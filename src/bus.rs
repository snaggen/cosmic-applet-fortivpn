// SPDX-License-Identifier: GPL-3.0-only

//! The session-bus interface between the agent and the applets.
//!
//! The agent owns the tunnel and serves [`AgentInterface`] under [`NAME`]. Every applet
//! instance (one per panel output) is a client: it reads the state as properties, follows
//! `PropertiesChanged`, and calls `Connect`, `Disconnect`, `SaveProfile` and the like. D-Bus activation
//! starts the agent on first use.

use crate::{
    state::{Failure, Status},
    stats::Traffic,
};
use cosmic::iced::{Subscription, futures::SinkExt, stream};
use cosmic_applet_fortivpn::{
    gateway::Gateway,
    profile::{self, LoginMethod, Profile, ProfileId},
};
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
    /// The tunnel went down and the agent reconnects by itself.
    Reconnecting,
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
            Self::Reconnecting => "reconnecting",
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
            "reconnecting" => Self::Reconnecting,
            _ => Self::Failed,
        }
    }
}

/// A profile as the applet shows it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProfileInfo {
    pub id: String,
    pub name: String,
    /// `saml` or `password`.
    pub method: String,
    /// `host:port`.
    pub address: String,
    /// SHA-256 digest of the certificate trusted although it does not validate, empty if
    /// none.
    pub trusted_cert: String,
}

/// How a profile travels on the bus: `(id, name, method, address, trusted_cert)`.
type ProfileTuple = (String, String, String, String, String);

impl ProfileInfo {
    fn from_profile(profile: &Profile) -> Self {
        Self {
            id: profile.id.to_string(),
            name: profile.name.clone(),
            method: profile.method.as_str().to_owned(),
            address: profile.gateway.address(),
            trusted_cert: profile
                .gateway
                .trusted_cert
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
        }
    }

    fn to_tuple(&self) -> ProfileTuple {
        (
            self.id.clone(),
            self.name.clone(),
            self.method.clone(),
            self.address.clone(),
            self.trusted_cert.clone(),
        )
    }

    fn from_tuple((id, name, method, address, trusted_cert): ProfileTuple) -> Self {
        Self {
            id,
            name,
            method,
            address,
            trusted_cert,
        }
    }
}

/// Everything an applet shows, as one value. Published by the agent as properties.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub state: State,
    /// Unix time the tunnel came up, 0 when not connected.
    pub connected_since: u64,
    /// The VPN accounts, sorted by name.
    pub profiles: Vec<ProfileInfo>,
    /// Id of the profile the state is about, empty if none.
    pub active: String,
    /// Why profiles could not be read, empty if they could.
    pub profiles_error: String,
    /// The tunnel's local IP address, empty when not connected.
    pub address: String,
    /// Traffic through the tunnel, zero when not connected.
    pub traffic: Traffic,
    /// Failure code when `state` is `Failed`: see [`failure_code`].
    pub failure: String,
    pub failure_detail: String,
    /// A configure helper runs (waiting for the admin password).
    pub configuring: bool,
    pub configure_error: String,
    /// The setting: reconnect by itself after the tunnel went down or after sleep.
    pub auto_reconnect: bool,
}

impl Snapshot {
    /// The state of the tunnel. The `with_*` methods add the rest.
    pub fn new(status: &Status) -> Self {
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
            failure,
            failure_detail,
            ..Self::default()
        }
    }

    /// Adds the profiles, why some could not be read, and the active one.
    pub fn with_profiles(
        mut self,
        profiles: &[Profile],
        error: Option<&str>,
        active: Option<&ProfileId>,
    ) -> Self {
        self.profiles = profiles.iter().map(ProfileInfo::from_profile).collect();
        self.profiles_error = error.unwrap_or_default().to_owned();
        self.active = active.map(ToString::to_string).unwrap_or_default();
        self
    }

    /// Adds whether the configure helper runs, and its last error.
    pub fn with_configure(mut self, configuring: bool, error: Option<&str>) -> Self {
        self.configuring = configuring;
        self.configure_error = error.unwrap_or_default().to_owned();
        self
    }

    /// Adds address and traffic, which are only published while connected.
    pub fn with_tunnel(mut self, address: Option<&str>, traffic: Traffic) -> Self {
        if self.state == State::Connected {
            self.address = address.unwrap_or_default().to_owned();
            self.traffic = traffic;
        }
        self
    }

    /// The active profile, if any.
    pub fn active_profile(&self) -> Option<&ProfileInfo> {
        self.profiles.iter().find(|p| p.id == self.active)
    }

    /// Adds the reconnect setting, and shows `Reconnecting` while a reconnect runs and the
    /// tunnel is not up.
    pub fn with_reconnect(mut self, reconnecting: bool, auto_reconnect: bool) -> Self {
        self.auto_reconnect = auto_reconnect;
        if reconnecting && self.state != State::Connected {
            self.state = State::Reconnecting;
        }
        self
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
        let number = |key: &str| {
            props
                .get(key)
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or_default()
        };
        Self {
            state: State::parse(&string("State")),
            connected_since: number("ConnectedSince"),
            profiles: props
                .get("Profiles")
                .and_then(|v| Vec::<ProfileTuple>::try_from(v.clone()).ok())
                .unwrap_or_default()
                .into_iter()
                .map(ProfileInfo::from_tuple)
                .collect(),
            active: string("ActiveProfile"),
            profiles_error: string("ProfilesError"),
            address: string("Address"),
            traffic: Traffic {
                received: number("Received"),
                sent: number("Sent"),
                receive_rate: number("ReceiveRate"),
                send_rate: number("SendRate"),
            },
            failure: string("Failure"),
            failure_detail: string("FailureDetail"),
            configuring: props
                .get("Configuring")
                .and_then(|v| bool::try_from(v).ok())
                .unwrap_or_default(),
            configure_error: string("ConfigureError"),
            auto_reconnect: props
                .get("AutoReconnect")
                .and_then(|v| bool::try_from(v).ok())
                .unwrap_or_default(),
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
        Failure::Lost => ("lost", ""),
        Failure::Unreachable(why) => ("unreachable", why.as_str()),
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
    Connect(ProfileId),
    Disconnect,
    SaveProfile {
        id: ProfileId,
        name: String,
        method: LoginMethod,
        address: String,
    },
    RemoveProfile(ProfileId),
    ForgetCert(ProfileId),
    SetAutoReconnect(bool),
}

fn invalid(err: impl std::fmt::Display) -> zbus::fdo::Error {
    zbus::fdo::Error::InvalidArgs(err.to_string())
}

/// The agent's D-Bus object.
pub struct AgentInterface {
    commands: mpsc::UnboundedSender<AgentCommand>,
    snapshot: Snapshot,
}

#[zbus::interface(name = "io.github.snaggen.CosmicAppletFortivpn1")]
impl AgentInterface {
    /// Connects the profile `id`, disconnecting another one first.
    fn connect(&self, id: String) -> zbus::fdo::Result<()> {
        let id = id.parse().map_err(invalid)?;
        let _ = self.commands.send(AgentCommand::Connect(id));
        Ok(())
    }

    fn disconnect(&self) {
        let _ = self.commands.send(AgentCommand::Disconnect);
    }

    /// Adds or changes a profile. The agent runs the configure helper, which asks for an
    /// admin password; the outcome shows in `Configuring` and `ConfigureError`.
    fn save_profile(
        &self,
        id: String,
        name: String,
        method: String,
        address: String,
    ) -> zbus::fdo::Result<()> {
        let id = id.parse().map_err(invalid)?;
        profile::validate_name(&name).map_err(invalid)?;
        let method = method.parse().map_err(invalid)?;
        address.parse::<Gateway>().map_err(invalid)?;
        let _ = self.commands.send(AgentCommand::SaveProfile {
            id,
            name,
            method,
            address,
        });
        Ok(())
    }

    /// Removes a profile (admin password).
    fn remove_profile(&self, id: String) -> zbus::fdo::Result<()> {
        let id = id.parse().map_err(invalid)?;
        let _ = self.commands.send(AgentCommand::RemoveProfile(id));
        Ok(())
    }

    /// Stops trusting a profile's certificate that does not validate (admin password).
    fn forget_cert(&self, id: String) -> zbus::fdo::Result<()> {
        let id = id.parse().map_err(invalid)?;
        let _ = self.commands.send(AgentCommand::ForgetCert(id));
        Ok(())
    }

    /// Turns reconnecting by itself on or off. A user setting: no password needed.
    fn set_auto_reconnect(&self, enabled: bool) {
        let _ = self.commands.send(AgentCommand::SetAutoReconnect(enabled));
    }

    #[zbus(property)]
    fn auto_reconnect(&self) -> bool {
        self.snapshot.auto_reconnect
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
    fn profiles(&self) -> Vec<ProfileTuple> {
        self.snapshot
            .profiles
            .iter()
            .map(ProfileInfo::to_tuple)
            .collect()
    }

    #[zbus(property)]
    fn active_profile(&self) -> &str {
        &self.snapshot.active
    }

    #[zbus(property)]
    fn profiles_error(&self) -> &str {
        &self.snapshot.profiles_error
    }

    #[zbus(property)]
    fn address(&self) -> &str {
        &self.snapshot.address
    }

    #[zbus(property)]
    fn received(&self) -> u64 {
        self.snapshot.traffic.received
    }

    #[zbus(property)]
    fn sent(&self) -> u64 {
        self.snapshot.traffic.sent
    }

    #[zbus(property)]
    fn receive_rate(&self) -> u64 {
        self.snapshot.traffic.receive_rate
    }

    #[zbus(property)]
    fn send_rate(&self) -> u64 {
        self.snapshot.traffic.send_rate
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
    if old.profiles != new.profiles {
        guard.profiles_changed(emitter).await?;
    }
    if old.active != new.active {
        guard.active_profile_changed(emitter).await?;
    }
    if old.profiles_error != new.profiles_error {
        guard.profiles_error_changed(emitter).await?;
    }
    if old.address != new.address {
        guard.address_changed(emitter).await?;
    }
    if old.traffic.received != new.traffic.received {
        guard.received_changed(emitter).await?;
    }
    if old.traffic.sent != new.traffic.sent {
        guard.sent_changed(emitter).await?;
    }
    if old.traffic.receive_rate != new.traffic.receive_rate {
        guard.receive_rate_changed(emitter).await?;
    }
    if old.traffic.send_rate != new.traffic.send_rate {
        guard.send_rate_changed(emitter).await?;
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
    if old.auto_reconnect != new.auto_reconnect {
        guard.auto_reconnect_changed(emitter).await?;
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
    fn connect(&self, id: &str) -> zbus::Result<()>;
    fn disconnect(&self) -> zbus::Result<()>;
    fn save_profile(&self, id: &str, name: &str, method: &str, address: &str) -> zbus::Result<()>;
    fn remove_profile(&self, id: &str) -> zbus::Result<()>;
    fn forget_cert(&self, id: &str) -> zbus::Result<()>;
    fn set_auto_reconnect(&self, enabled: bool) -> zbus::Result<()>;
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
            State::Reconnecting,
        ] {
            assert_eq!(State::parse(state.as_str()), state);
        }
        assert_eq!(State::parse("something-new"), State::Failed);
    }

    fn profile() -> Profile {
        Profile::parse_config(
            "ace".parse().unwrap(),
            "name = ACE\nmethod = saml\nhost = vpn.example.com\nport = 443\n",
        )
        .unwrap()
    }

    #[test]
    fn snapshot_from_status() {
        let profiles = [profile()];
        let snapshot = Snapshot::new(&Status::Failed(Failure::Other("boom".into())))
            .with_profiles(&profiles, None, Some(&profiles[0].id))
            .with_configure(true, Some("denied"))
            .with_tunnel(
                Some("192.0.2.1"),
                Traffic {
                    received: 1,
                    ..Traffic::default()
                },
            );
        assert_eq!(snapshot.state, State::Failed);
        assert_eq!(
            snapshot.active_profile().map(|p| p.address.as_str()),
            Some("vpn.example.com:443")
        );
        assert_eq!(snapshot.failure, "other");
        assert_eq!(snapshot.failure_detail, "boom");
        assert!(snapshot.configuring);
        assert_eq!(snapshot.configure_error, "denied");
        // Address and traffic only while connected.
        assert_eq!(snapshot.address, "");
        assert_eq!(snapshot.traffic, Traffic::default());

        let connected = Snapshot::new(&Status::Connected {
            since: Instant::now(),
        })
        .with_tunnel(
            Some("192.0.2.1"),
            Traffic {
                received: 7,
                ..Traffic::default()
            },
        );
        assert_eq!(connected.state, State::Connected);
        assert!(connected.connected_since > 0);
        assert_eq!(connected.address, "192.0.2.1");
        assert_eq!(connected.traffic.received, 7);
        assert_eq!(connected.active_profile(), None);
    }

    #[test]
    fn reconnecting_shows_until_connected() {
        let failed = Snapshot::new(&Status::Failed(Failure::Lost));
        let shown = failed.clone().with_reconnect(true, true);
        assert_eq!(shown.state, State::Reconnecting);
        assert!(shown.auto_reconnect);
        assert_eq!(
            failed.clone().with_reconnect(false, true).state,
            State::Failed
        );
        let connected = Snapshot::new(&Status::Connected {
            since: Instant::now(),
        });
        assert_eq!(connected.with_reconnect(true, true).state, State::Connected);
    }

    #[test]
    fn profiles_round_trip_through_properties() {
        let profiles = [profile()];
        let snapshot = Snapshot::new(&Status::Disconnected).with_profiles(&profiles, None, None);
        let iface_value: Vec<ProfileTuple> = snapshot
            .profiles
            .iter()
            .map(ProfileInfo::to_tuple)
            .collect();
        let props: HashMap<String, OwnedValue> = [(
            "Profiles".to_owned(),
            OwnedValue::try_from(zbus::zvariant::Value::from(iface_value)).unwrap(),
        )]
        .into_iter()
        .collect();
        assert_eq!(
            Snapshot::from_properties(&props).profiles,
            snapshot.profiles
        );
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
                "ActiveProfile",
                OwnedValue::from(zbus::zvariant::Str::from("ace")),
            ),
            ("Configuring", OwnedValue::from(true)),
            ("SendRate", OwnedValue::from(9u64)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        let snapshot = Snapshot::from_properties(&props);
        assert_eq!(snapshot.state, State::Connected);
        assert_eq!(snapshot.connected_since, 42);
        assert_eq!(snapshot.active, "ace");
        assert!(snapshot.configuring);
        assert_eq!(snapshot.traffic.send_rate, 9);
        assert_eq!(snapshot.failure, "");
    }
}
