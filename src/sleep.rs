// SPDX-License-Identifier: EUPL-1.2

//! Suspend and hibernate, through logind on the system bus.
//!
//! While a connection runs the agent holds a `delay` inhibitor lock. logind then announces
//! sleep with `PrepareForSleep(true)` and waits (up to `InhibitDelayMaxSec`) until the lock is
//! released, which the agent does once the tunnel is down. A tunnel left up over sleep would
//! come back dead, with openfortivpn not noticing.

use cosmic::iced::{
    Subscription,
    futures::{SinkExt, StreamExt, channel::mpsc::Sender},
    stream,
};
use tokio::sync::mpsc;
use zbus::zvariant::OwnedFd;

#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait Manager {
    fn inhibit(&self, what: &str, who: &str, why: &str, mode: &str) -> zbus::Result<OwnedFd>;

    #[zbus(signal)]
    fn prepare_for_sleep(&self, start: bool) -> zbus::Result<()>;
}

#[derive(Clone, Debug)]
pub enum SleepUpdate {
    /// Send `true` to hold the inhibitor lock, `false` to release it.
    Ready(mpsc::UnboundedSender<bool>),
    /// The system is about to sleep: disconnect, then release the lock.
    Suspending,
    Resumed,
    /// logind cannot be used; sleep is not handled.
    Failed(String),
}

pub fn subscription() -> Subscription<SleepUpdate> {
    Subscription::run(|| stream::channel(8, run))
}

async fn run(mut output: Sender<SleepUpdate>) {
    if let Err(err) = watch(&mut output).await {
        let _ = output.send(SleepUpdate::Failed(err.to_string())).await;
    }
}

async fn watch(output: &mut Sender<SleepUpdate>) -> zbus::Result<()> {
    let connection = zbus::Connection::system().await?;
    let manager = ManagerProxy::new(&connection).await?;
    let mut signals = manager.receive_prepare_for_sleep().await?;
    let (hold_tx, mut hold) = mpsc::unbounded_channel();
    if output.send(SleepUpdate::Ready(hold_tx)).await.is_err() {
        return Ok(());
    }

    // Dropping the descriptor releases the lock.
    let mut lock: Option<OwnedFd> = None;
    loop {
        tokio::select! {
            Some(wanted) = hold.recv() => {
                if wanted && lock.is_none() {
                    match manager
                        .inhibit("sleep", "OpenFortiVPN", "Disconnect the VPN before sleep", "delay")
                        .await
                    {
                        Ok(fd) => lock = Some(fd),
                        Err(err) => tracing::warn!(%err, "could not take the sleep inhibitor"),
                    }
                } else if !wanted && lock.take().is_some() {
                    tracing::info!("released the sleep inhibitor");
                }
            }
            Some(signal) = signals.next() => {
                let update = match signal.args() {
                    Ok(args) if args.start => SleepUpdate::Suspending,
                    Ok(_) => SleepUpdate::Resumed,
                    Err(err) => {
                        tracing::warn!(%err, "bad PrepareForSleep signal");
                        continue;
                    }
                };
                if output.send(update).await.is_err() {
                    return Ok(());
                }
            }
            else => return Ok(()),
        }
    }
}
