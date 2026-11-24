// SPDX-License-Identifier: EUPL-1.2

//! Runs the root helper through pkexec and reports its events to the applet.
//!
//! The subscription first sends [`Update::Ready`] with a sender for [`TunnelCommand`]s.
//! A connect starts `pkexec <helper>`, writes the request line, and keeps the helper's stdin
//! open; a disconnect closes it, which makes the helper stop openfortivpn.

use cosmic::iced::{Subscription, futures::SinkExt, stream};
use cosmic_applet_fortivpn::{
    HELPER_NAME, LIBEXEC_DIR,
    protocol::{Event, Request},
};
use std::process::Stdio;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{ChildStdin, Command},
    sync::mpsc,
};

/// Most of pkexec's stderr kept for an error message.
const MAX_STDERR: u64 = 4096;

/// Requests from the applet to the tunnel task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelCommand {
    Connect(Request),
    Disconnect,
}

/// What the tunnel task reports.
#[derive(Clone, Debug)]
pub enum Update {
    /// The task is running and takes commands through this sender.
    Ready(mpsc::UnboundedSender<TunnelCommand>),
    /// An event from the helper.
    Event(Event),
    /// The helper process ended.
    Ended(Ended),
}

/// How the pkexec process ended. Only interesting when the helper reported nothing itself,
/// e.g. because pkexec refused to run it.
#[derive(Clone, Debug)]
pub struct Ended {
    /// Exit code of pkexec: the helper's own, or 126 (dialog dismissed) and 127 (not
    /// authorized, or the helper is missing) from pkexec itself.
    pub code: Option<i32>,
    /// What pkexec or the helper wrote to stderr, for the error message.
    pub stderr: String,
}

pub fn subscription() -> Subscription<Update> {
    Subscription::run(|| stream::channel(32, run))
}

async fn run(mut output: cosmic::iced::futures::channel::mpsc::Sender<Update>) {
    let (tx, mut commands) = mpsc::unbounded_channel();
    if output.send(Update::Ready(tx)).await.is_err() {
        return;
    }
    while let Some(command) = commands.recv().await {
        if let TunnelCommand::Connect(request) = command {
            let ended = run_helper(&request, &mut commands, &mut output).await;
            if output.send(Update::Ended(ended)).await.is_err() {
                return;
            }
        }
    }
}

/// Runs one helper process until it exits.
async fn run_helper(
    request: &Request,
    commands: &mut mpsc::UnboundedReceiver<TunnelCommand>,
    output: &mut cosmic::iced::futures::channel::mpsc::Sender<Update>,
) -> Ended {
    let helper = format!("{LIBEXEC_DIR}/{HELPER_NAME}");
    let mut child = match Command::new("pkexec")
        .arg(&helper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            return Ended {
                code: None,
                stderr: format!("pkexec: {err}"),
            };
        }
    };
    tracing::info!(?request, %helper, "started helper");

    let mut stdin = send_request(child.stdin.take(), request).await;
    let stderr = child.stderr.take().map(|stderr| {
        tokio::spawn(async move {
            let mut text = String::new();
            let _ = stderr.take(MAX_STDERR).read_to_string(&mut text).await;
            text
        })
    });

    if let Some(stdout) = child.stdout.take() {
        let mut lines = BufReader::new(stdout).lines();
        let mut commands_open = true;
        loop {
            tokio::select! {
                line = lines.next_line() => match line {
                    Ok(Some(line)) => {
                        if let Some(event) = Event::parse(&line)
                            && output.send(Update::Event(event)).await.is_err()
                        {
                            break;
                        }
                    }
                    Ok(None) | Err(_) => break,
                },
                command = commands.recv(), if commands_open => match command {
                    // Closing stdin tells the helper to disconnect.
                    Some(TunnelCommand::Disconnect) => stdin = None,
                    Some(TunnelCommand::Connect(_)) => {}
                    None => {
                        commands_open = false;
                        stdin = None;
                    }
                },
            }
        }
    }
    drop(stdin);

    let code = child.wait().await.ok().and_then(|status| status.code());
    let stderr = match stderr {
        Some(task) => task.await.unwrap_or_default(),
        None => String::new(),
    };
    Ended { code, stderr }
}

/// Writes the request line and returns the still open stdin.
async fn send_request(stdin: Option<ChildStdin>, request: &Request) -> Option<ChildStdin> {
    let mut stdin = stdin?;
    match stdin.write_all(request.to_line().as_bytes()).await {
        Ok(()) => Some(stdin),
        Err(err) => {
            // The helper exited early; its exit status and output say why.
            tracing::warn!(%err, "could not send the request to the helper");
            None
        }
    }
}
