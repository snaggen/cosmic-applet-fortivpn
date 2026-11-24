// SPDX-License-Identifier: GPL-3.0-only

//! The session-bus interface between the agent and the applets.
//!
//! The agent owns the tunnel and serves [`AgentInterface`] under [`NAME`]. Every applet
//! instance (one per panel output) is a client: it reads the state as properties, follows
//! `PropertiesChanged`, and calls `Connect`, `Disconnect` and `SetGateway`. D-Bus activation
//! starts the agent on first use.

use crate::state::{Failure, Status};
use cosmic::iced::{Subscription, futures::SinkExt, stream};
use cosmic_applet_fortivpn::gateway::Gateway;
use std::{collections::HashMap, time::SystemTime};
use tokio::sync::mpsc;
use zbus::{
    fdo::{RequestNameFlags, RequestNameReply},
    object_server::InterfaceRef,
    zvariant::OwnedValue,
};

/// Well-known bus name of the agent.
pub const NAME: &str = "io.github.snaggen.CosmicAppletFortivpn";
/// Object path of the agent.
pub const PATH: &str = "/io/github/snaggen/CosmicAppletFortivpn";
/// Interface name.
pub const INTERFACE: &str = "io.github.snaggen.CosmicAppletFortivpn1";

/// Connection state as published on the bus.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum State {
    #[default]
    Disconnected,
    Connecting,
    WaitingForLogin,
    Connected,
    Disconnecting,
    CertUntrusted,
    Failed,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Connecting => "connecting",
            Self::WaitingForLogin => "waiting-for-login",
            Self::Connected => "connected",
            Self::Disconnecting => "disconnecting",
            Self::CertUntrusted => "cert-untrusted",
            Self::Failed => "failed",
        }
    }

    /// Unknown values (from a newer agent) read as `Failed`.
    pub fn parse(s: &str) -> Self {
        match s {
            "disconnected" => Self::Disconnected,
            "connecting" => Self::Connecting,
            "waiting-for-login" => Self::WaitingForLogin,
            "connected" => Self::Connected,
            "disconnecting" => Self::Disconnecting,
            "cert-untrusted" => Self::CertUntrusted,
            _ => Self::Failed,
        }
    }
}

/// Everything an applet shows, as one value. Published by the agent as properties.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub state: State,
    /// Unix time the tunnel came up, 0 when not connected.
    pub connected_since: u64,
    /// `host:port`, empty when no gateway is configured.
    pub gateway: String,
    /// Why the gateway config could not be read, empty if it could.
    pub gateway_error: String,
    /// Failure code when `state` is `Failed`: see [`failure_code`].
    pub failure: String,
    pub failure_detail: String,
    /// A configure helper runs (waiting for the admin password).
    pub configuring: bool,
    pub configure_error: String,
}

impl Snapshot {
    pub fn new(
        status: &Status,
        gateway: &Result<Option<Gateway>, String>,
        configuring: bool,
        configure_error: Option<&str>,
    ) -> Self {
        let (failure, failure_detail) = match status {
            Status::Failed(failure) => failure_code(failure),
            _ => (String::new(), String::new()),
        };
        Self {
            state: match status {
                Status::Disconnected => State::Disconnected,
                Status::Checking | Status::Starting(_) | Status::Connecting => State::Connecting,
                Status::LoggingIn | Status::WaitingForLogin => State::WaitingForLogin,
                Status::Connected { .. } => State::Connected,
                Status::Disconnecting => State::Disconnecting,
                Status::CertUntrusted(_) => State::CertUntrusted,
                Status::Failed(_) => State::Failed,
            },
            connected_since: match status {
                Status::Connected { since } => unix_time(*since),
                _ => 0,
            },
            gateway: match gateway {
                Ok(Some(gateway)) => gateway.address(),
                _ => String::new(),
            },
            gateway_error: gateway.as_ref().err().cloned().unwrap_or_default(),
            failure,
            failure_detail,
            configuring,
            configure_error: configure_error.unwrap_or_default().to_owned(),
        }
    }

    /// Builds a snapshot from the agent's properties (`GetAll`). Missing or mistyped
    /// properties keep their defaults.
    pub fn from_properties(props: &HashMap<String, OwnedValue>) -> Self {
        let string = |key: &str| {
            props
                .get(key)
                .and_then(|v| String::try_from(v.clone()).ok())
                .unwrap_or_default()
        };
        Self {
            state: State::parse(&string("State")),
            connected_since: props
                .get("ConnectedSince")
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or_default(),
            gateway: string("Gateway"),
            gateway_error: string("GatewayError"),
            failure: string("Failure"),
            failure_detail: string("FailureDetail"),
            configuring: props
                .get("Configuring")
                .and_then(|v| bool::try_from(v).ok())
                .unwrap_or_default(),
            configure_error: string("ConfigureError"),
        }
    }
}

/// Failure code and detail for the bus; the applet translates the code.
fn failure_code(failure: &Failure) -> (String, String) {
    let (code, detail) = match failure {
        Failure::NotConfigured => ("not-configured", ""),
        Failure::Busy => ("busy", ""),
        Failure::AuthFailed => ("auth-failed", ""),
        Failure::NotAuthorized(why) => ("not-authorized", why.as_str()),
        Failure::Stopped => ("stopped", ""),
        Failure::Other(why) => ("other", why.as_str()),
    };
    (code.to_owned(), detail.to_owned())
}

/// Converts a monotonic instant to Unix time, for showing the uptime in another process.
fn unix_time(instant: std::time::Instant) -> u64 {
    let ago = instant.elapsed();
    SystemTime::now()
        .checked_sub(ago)
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

/// Requests from an applet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentCommand {
    Connect,
    Disconnect,
    SetGateway(String),
}

/// The agent's D-Bus object.
pub struct AgentInterface {
    commands: mpsc::UnboundedSender<AgentCommand>,
    snapshot: Snapshot,
}

#[zbus::interface(name = "io.github.snaggen.CosmicAppletFortivpn1")]
impl AgentInterface {
    fn connect(&self) {
        let _ = self.commands.send(AgentCommand::Connect);
    }

    fn disconnect(&self) {
        let _ = self.commands.send(AgentCommand::Disconnect);
    }

    /// Sets the gateway (`host:port`). The agent runs the configure helper, which asks for
    /// an admin password; the outcome shows in `Configuring` and `ConfigureError`.
    fn set_gateway(&self, address: String) -> zbus::fdo::Result<()> {
        address
            .parse::<Gateway>()
            .map_err(|err| zbus::fdo::Error::InvalidArgs(err.to_string()))?;
        let _ = self.commands.send(AgentCommand::SetGateway(address));
        Ok(())
    }

    #[zbus(property)]
    fn state(&self) -> &str {
        self.snapshot.state.as_str()
    }

    #[zbus(property)]
    fn connected_since(&self) -> u64 {
        self.snapshot.connected_since
    }

    #[zbus(property)]
    fn gateway(&self) -> &str {
        &self.snapshot.gateway
    }

    #[zbus(property)]
    fn gateway_error(&self) -> &str {
        &self.snapshot.gateway_error
    }

    #[zbus(property)]
    fn failure(&self) -> &str {
        &self.snapshot.failure
    }

    #[zbus(property)]
    fn failure_detail(&self) -> &str {
        &self.snapshot.failure_detail
    }

    #[zbus(property)]
    fn configuring(&self) -> bool {
        self.snapshot.configuring
    }

    #[zbus(property)]
    fn configure_error(&self) -> &str {
        &self.snapshot.configure_error
    }
}

/// Replaces the published snapshot and signals the properties that changed.
async fn publish(iface: &InterfaceRef<AgentInterface>, new: Snapshot) -> zbus::Result<()> {
    let mut guard = iface.get_mut().await;
    let old = std::mem::replace(&mut guard.snapshot, new);
    let new = &guard.snapshot;
    let emitter = iface.signal_emitter();
    if old.state != new.state {
        guard.state_changed(emitter).await?;
    }
    if old.connected_since != new.connected_since {
        guard.connected_since_changed(emitter).await?;
    }
    if old.gateway != new.gateway {
        guard.gateway_changed(emitter).await?;
    }
    if old.gateway_error != new.gateway_error {
        guard.gateway_error_changed(emitter).await?;
    }
    if old.failure != new.failure {
        guard.failure_changed(emitter).await?;
    }
    if old.failure_detail != new.failure_detail {
        guard.failure_detail_changed(emitter).await?;
    }
    if old.configuring != new.configuring {
        guard.configuring_changed(emitter).await?;
    }
    if old.configure_error != new.configure_error {
        guard.configure_error_changed(emitter).await?;
    }
    Ok(())
}

/// What the agent's bus task reports.
#[derive(Clone, Debug)]
pub enum BusUpdate {
    /// Serving under [`NAME`]; send snapshots to publish through this sender.
    Ready(mpsc::UnboundedSender<Snapshot>),
    Command(AgentCommand),
    /// Another agent owns the name: this one must exit.
    NameTaken,
    Failed(String),
}

/// Serves the agent interface for the agent's lifetime.
pub fn serve() -> Subscription<BusUpdate> {
    Subscription::run(|| stream::channel(32, run_server))
}

async fn run_server(mut output: cosmic::iced::futures::channel::mpsc::Sender<BusUpdate>) {
    let (commands_tx, mut commands) = mpsc::unbounded_channel();
    let (snapshots_tx, mut snapshots) = mpsc::unbounded_channel();
    let iface = AgentInterface {
        commands: commands_tx,
        snapshot: Snapshot::default(),
    };

    let connection = match zbus::connection::Builder::session()
        .and_then(|builder| builder.serve_at(PATH, iface))
    {
        Ok(builder) => builder.build().await,
        Err(err) => Err(err),
    };
    let connection = match connection {
        Ok(connection) => connection,
        Err(err) => {
            let _ = output.send(BusUpdate::Failed(err.to_string())).await;
            return;
        }
    };
    match connection
        .request_name_with_flags(NAME, RequestNameFlags::DoNotQueue.into())
        .await
    {
        Ok(RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner) => {}
        Ok(_) => {
            let _ = output.send(BusUpdate::NameTaken).await;
            return;
        }
        Err(err) => {
            let _ = output.send(BusUpdate::Failed(err.to_string())).await;
            return;
        }
    }
    let iface = match connection
        .object_server()
        .interface::<_, AgentInterface>(PATH)
        .await
    {
        Ok(iface) => iface,
        Err(err) => {
            let _ = output.send(BusUpdate::Failed(err.to_string())).await;
            return;
        }
    };
    if output.send(BusUpdate::Ready(snapshots_tx)).await.is_err() {
        return;
    }

    loop {
        tokio::select! {
            Some(command) = commands.recv() => {
                if output.send(BusUpdate::Command(command)).await.is_err() {
                    return;
                }
            }
            Some(snapshot) = snapshots.recv() => {
                if let Err(err) = publish(&iface, snapshot).await {
                    tracing::warn!(%err, "could not publish the state");
                }
            }
            else => return,
        }
    }
}

/// Client side, used by the applets.
#[zbus::proxy(
    interface = "io.github.snaggen.CosmicAppletFortivpn1",
    default_service = "io.github.snaggen.CosmicAppletFortivpn",
    default_path = "/io/github/snaggen/CosmicAppletFortivpn"
)]
pub trait Agent {
    fn connect(&self) -> zbus::Result<()>;
    fn disconnect(&self) -> zbus::Result<()>;
    fn set_gateway(&self, address: &str) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn state_names_round_trip() {
        for state in [
            State::Disconnected,
            State::Connecting,
            State::WaitingForLogin,
            State::Connected,
            State::Disconnecting,
            State::CertUntrusted,
            State::Failed,
        ] {
            assert_eq!(State::parse(state.as_str()), state);
        }
        assert_eq!(State::parse("something-new"), State::Failed);
    }

    #[test]
    fn snapshot_from_status() {
        let gateway = Ok(Some("vpn.example.com:443".parse().unwrap()));
        let snapshot = Snapshot::new(
            &Status::Failed(Failure::Other("boom".into())),
            &gateway,
            true,
            Some("denied"),
        );
        assert_eq!(snapshot.state, State::Failed);
        assert_eq!(snapshot.gateway, "vpn.example.com:443");
        assert_eq!(snapshot.failure, "other");
        assert_eq!(snapshot.failure_detail, "boom");
        assert!(snapshot.configuring);
        assert_eq!(snapshot.configure_error, "denied");

        let connected = Snapshot::new(
            &Status::Connected {
                since: Instant::now(),
            },
            &Ok(None),
            false,
            None,
        );
        assert_eq!(connected.state, State::Connected);
        assert!(connected.connected_since > 0);
        assert_eq!(connected.gateway, "");
    }

    #[test]
    fn snapshot_from_properties() {
        let props: HashMap<String, OwnedValue> = [
            (
                "State",
                OwnedValue::from(zbus::zvariant::Str::from("connected")),
            ),
            ("ConnectedSince", OwnedValue::from(42u64)),
            (
                "Gateway",
                OwnedValue::from(zbus::zvariant::Str::from("a.example:1")),
            ),
            ("Configuring", OwnedValue::from(true)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        let snapshot = Snapshot::from_properties(&props);
        assert_eq!(snapshot.state, State::Connected);
        assert_eq!(snapshot.connected_since, 42);
        assert_eq!(snapshot.gateway, "a.example:1");
        assert!(snapshot.configuring);
        assert_eq!(snapshot.failure, "");
    }
}
