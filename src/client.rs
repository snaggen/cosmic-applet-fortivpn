// SPDX-License-Identifier: GPL-3.0-only

//! The applet's connection to the agent on the session bus.
//!
//! Reads the agent's state with `GetAll` (which also starts the agent through D-Bus
//! activation), then re-reads it on every `PropertiesChanged` and whenever the agent's bus
//! name changes owner.

use crate::bus::{AgentProxy, INTERFACE, NAME, PATH, Snapshot};
use cosmic::iced::{
    Subscription,
    futures::{SinkExt, StreamExt, channel::mpsc::Sender},
    stream,
};
use std::time::Duration;
use zbus::{
    Connection,
    fdo::{DBusProxy, PropertiesProxy},
    names::InterfaceName,
    proxy::CacheProperties,
};

/// Wait before reconnecting after the session bus failed.
const RETRY_DELAY: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub enum ClientUpdate {
    /// Proxy for calling the agent.
    Ready(AgentProxy<'static>),
    /// The agent's state, or `None` while it cannot be reached.
    Snapshot(Option<Box<Snapshot>>),
}

pub fn subscription() -> Subscription<ClientUpdate> {
    Subscription::run(|| stream::channel(16, run))
}

async fn run(mut output: Sender<ClientUpdate>) {
    loop {
        if let Err(err) = watch(&mut output).await {
            tracing::warn!(%err, "lost the session bus");
        }
        if output.send(ClientUpdate::Snapshot(None)).await.is_err() {
            return;
        }
        tokio::time::sleep(RETRY_DELAY).await;
    }
}

/// Follows the agent until the bus connection fails.
async fn watch(output: &mut Sender<ClientUpdate>) -> zbus::Result<()> {
    let connection = Connection::session().await?;
    let agent = AgentProxy::builder(&connection)
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let props = PropertiesProxy::builder(&connection)
        .destination(NAME)?
        .path(PATH)?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let dbus = DBusProxy::new(&connection).await?;

    let mut changes = props.receive_properties_changed().await?;
    let mut owners = dbus
        .receive_name_owner_changed_with_args(&[(0, NAME)])
        .await?;

    if output.send(ClientUpdate::Ready(agent)).await.is_err() {
        return Ok(());
    }
    // The first read starts the agent if it is not running.
    send_snapshot(&props, output).await;

    loop {
        tokio::select! {
            Some(_) = changes.next() => send_snapshot(&props, output).await,
            Some(_) = owners.next() => send_snapshot(&props, output).await,
            else => return Ok(()),
        }
    }
}

/// Reads all properties and sends them; `None` if the agent cannot be reached.
async fn send_snapshot(props: &PropertiesProxy<'_>, output: &mut Sender<ClientUpdate>) {
    let interface = InterfaceName::from_static_str_unchecked(INTERFACE);
    let snapshot = match props.get_all(interface).await {
        Ok(map) => Some(Box::new(Snapshot::from_properties(&map))),
        Err(err) => {
            tracing::warn!(%err, "could not read the agent's state");
            None
        }
    };
    let _ = output.send(ClientUpdate::Snapshot(snapshot)).await;
}
