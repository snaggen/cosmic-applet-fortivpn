// SPDX-License-Identifier: GPL-3.0-only

//! The agent: one process per user session that owns the tunnel and shows dialogs.
//!
//! Started through D-Bus activation (`cosmic-applet-fortivpn --agent`). It runs the root
//! helper, keeps the connection state, serves it to the applets over the session bus
//! ([`crate::bus`]), and opens a window in front of the user whenever they must act: to
//! trust a certificate, or to log in in the browser. It has no window otherwise.

use crate::{
    bus::{self, AgentCommand, BusUpdate, Snapshot},
    fl,
    liveness::{self, STALL_BEFORE_PROBE, STALL_WITHOUT_PROBE, Watch},
    login::{self, LoginResult},
    netwatch::{self, Change},
    notify::{self, Notification},
    reconnect::{self, Reconnect},
    sleep::{self, SleepUpdate},
    state::{Effect, Failure, Status},
    stats::{Counters, Meter, Traffic},
    tunnel::{self, TunnelCommand},
};
use cosmic::{
    ApplicationExt, Element, Task,
    app::Core,
    cosmic_config::{self, ConfigGet, ConfigSet},
    iced::{
        Length, Size, Subscription, task,
        widget::{column, row, space::horizontal as horizontal_space},
        window::{self, Id},
    },
    surface, theme,
    widget::{button, checkbox, container, header_bar, icon, scrollable, text},
};
use cosmic_applet_fortivpn::{
    CONFIGURE_NAME, LIBEXEC_DIR,
    certcheck::{self, CertCheck},
    gateway::{CertDigest, Gateway},
    openfortivpn::TunnelDetail,
    protocol::{Event, UntrustedCert},
};
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::sync::mpsc::UnboundedSender;

const APP_ID: &str = "io.github.snaggen.CosmicAppletFortivpn";

/// Version of the agent's settings in cosmic-config.
const CONFIG_VERSION: u64 = 1;
/// cosmic-config key: reconnect by itself (off by default).
const AUTO_RECONNECT: &str = "auto_reconnect";

/// Size of the certificate dialog. Wayland lets the compositor place it.
const CERT_DIALOG_SIZE: Size = Size::new(560.0, 520.0);
/// The login dialog only points at the browser, so it stays small.
const LOGIN_DIALOG_SIZE: Size = Size::new(440.0, 220.0);

/// How often the traffic counters are read while connected.
const TRAFFIC_INTERVAL: Duration = Duration::from_secs(1);

/// How long the certificate check may take. Without network, name resolution alone can take
/// minutes.
const CERT_CHECK_TIMEOUT: Duration = Duration::from_secs(15);

pub fn run() -> cosmic::iced::Result {
    let settings = cosmic::app::Settings::default()
        .no_main_window(true)
        .exit_on_close(false);
    cosmic::app::run::<Agent>(settings, ())
}

/// The dialog the agent shows, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Dialog {
    Cert(UntrustedCert),
    Login,
}

struct Agent {
    core: Core,
    status: Status,
    gateway: Result<Option<Gateway>, String>,
    tunnel: Option<UnboundedSender<TunnelCommand>>,
    /// Publishes snapshots on the bus, once it is served.
    bus: Option<UnboundedSender<Snapshot>>,
    published: Option<Snapshot>,
    /// A configure helper runs (waiting for the admin password).
    configuring: bool,
    configure_error: Option<String>,
    /// The open dialog window.
    dialog: Option<(Id, Dialog)>,
    /// The "always trust this certificate" checkbox.
    always_trust: bool,
    /// The certificate the user trusted in this session, for the login window. A certificate
    /// trusted once is only in a root-only file, so the agent keeps its own note of it.
    session_trust: Option<CertDigest>,
    /// The running login window, stopped when the wait for the login ends.
    login: Option<task::Handle>,
    /// The login window failed this time: the system browser and the login dialog stand in.
    browser_login: bool,
    /// What openfortivpn reported about the tunnel of this attempt.
    interface: Option<String>,
    address: Option<String>,
    meter: Meter,
    traffic: Traffic,
    /// The VPN's DNS servers, for probing whether the tunnel still works.
    nameservers: Vec<IpAddr>,
    watch: Watch,
    probing: bool,
    /// Holds or releases logind's sleep inhibitor.
    sleep_lock: Option<UnboundedSender<bool>>,
    holding_sleep: bool,
    /// The agent's settings, `None` if cosmic-config cannot be used.
    config: Option<cosmic_config::Config>,
    auto_reconnect: bool,
    /// A reconnect in progress (only with `auto_reconnect`).
    reconnect: Option<Reconnect>,
    /// Numbers reconnects, so a cancelled one's timer is ignored.
    reconnects: u64,
    /// The tunnel was up when the system went to sleep: reconnect after resume.
    connect_after_resume: bool,
    /// Numbers certificate checks, so a late result of a cancelled one is ignored.
    cert_checks: u64,
}

/// What a status change meant for reconnecting.
enum ReconnectStep {
    None,
    /// A reconnect runs or just started: the failure is not reported yet.
    Pending,
    /// All attempts failed.
    GaveUp,
}

#[derive(Clone, Debug)]
enum Message {
    Tunnel(tunnel::Update),
    Bus(BusUpdate),
    /// The configure helper finished; on success, whether to connect next.
    Configured(Result<(), String>, bool),
    LoginPageOpened(Result<(), String>),
    AlwaysTrust(bool),
    Trust,
    OpenLoginPage,
    /// Cancel in a dialog, or its window closed.
    Cancel,
    WindowClosed(Id),
    /// Drag on a dialog's header bar: move the window.
    Drag(Id),
    /// Certificate check `id` finished.
    CertChecked(u64, Result<CertCheck, String>),
    LoginFinished(LoginResult),
    /// Time to read the traffic counters.
    TrafficTick,
    /// Whether the tunnel answered a probe.
    Probed(bool),
    Sleep(SleepUpdate),
    /// Links, addresses or routes changed.
    Network(Change),
    /// Time for an attempt of reconnect `id`; `false` if the network did not come back.
    Reconnect {
        id: u64,
        network: bool,
    },
    Notified(Result<(), String>),
    /// The SAML id was handed to openfortivpn, or could not be.
    HandedOver(Result<(), String>),
}

impl cosmic::Application for Agent {
    type Executor = cosmic::SingleThreadExecutor;
    type Flags = ();
    type Message = Message;
    const APP_ID: &'static str = APP_ID;

    fn core(&self) -> &Core {
        &self.core
    }

    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }

    fn init(core: Core, _flags: Self::Flags) -> (Self, Task<cosmic::Action<Self::Message>>) {
        let mut agent = Self {
            core,
            status: Status::Disconnected,
            gateway: load_gateway(),
            tunnel: None,
            bus: None,
            published: None,
            configuring: false,
            configure_error: None,
            dialog: None,
            always_trust: true,
            session_trust: None,
            login: None,
            browser_login: false,
            interface: None,
            address: None,
            meter: Meter::default(),
            traffic: Traffic::default(),
            nameservers: Vec::new(),
            watch: Watch::default(),
            probing: false,
            sleep_lock: None,
            holding_sleep: false,
            config: None,
            auto_reconnect: false,
            reconnect: None,
            reconnects: 0,
            connect_after_resume: false,
            cert_checks: 0,
        };
        match cosmic_config::Config::new(APP_ID, CONFIG_VERSION) {
            Ok(config) => {
                agent.auto_reconnect = config.get(AUTO_RECONNECT).unwrap_or(false);
                agent.config = Some(config);
            }
            Err(err) => tracing::warn!(%err, "settings unavailable"),
        }
        (agent, Task::none())
    }

    fn subscription(&self) -> Subscription<Self::Message> {
        Subscription::batch([
            tunnel::subscription().map(Message::Tunnel),
            bus::serve().map(Message::Bus),
            window::close_events().map(Message::WindowClosed),
            self.traffic_ticks(),
            sleep::subscription().map(Message::Sleep),
            netwatch::subscription().map(Message::Network),
        ])
    }

    fn on_close_requested(&self, id: Id) -> Option<Message> {
        self.dialog
            .as_ref()
            .filter(|(dialog_id, _)| *dialog_id == id)
            .map(|_| Message::Cancel)
    }

    fn update(&mut self, message: Self::Message) -> Task<cosmic::Action<Self::Message>> {
        let before = self.status.clone();
        let task = self.handle(message);
        let mut follow_up = Task::none();
        if self.status != before {
            tracing::info!(status = ?self.status, "status changed");
            if !self.status.is_active() {
                self.forget_tunnel();
            }
            let (step, reconnect) = self.follow_reconnect(&before);
            let notification = match step {
                ReconnectStep::None => self.notify_failure(&before, None),
                ReconnectStep::Pending => Task::none(),
                ReconnectStep::GaveUp => {
                    self.notify_failure(&before, Some(fl!("notify-reconnect-failed")))
                }
            };
            follow_up = Task::batch([reconnect, notification]);
        }
        self.end_login_if_done();
        self.sync_sleep_lock();
        self.publish();
        Task::batch([task, self.sync_dialog(), follow_up])
    }

    /// The agent has no main window; this is never shown.
    fn view(&self) -> Element<'_, Self::Message> {
        text::body("").into()
    }

    fn view_window(&self, id: Id) -> Element<'_, Self::Message> {
        match &self.dialog {
            Some((dialog_id, Dialog::Cert(cert))) if *dialog_id == id => self.cert_dialog(id, cert),
            Some((dialog_id, Dialog::Login)) if *dialog_id == id => self.login_dialog(id),
            _ => text::body("").into(),
        }
    }
}

impl Agent {
    fn handle(&mut self, message: Message) -> Task<cosmic::Action<Message>> {
        match message {
            Message::Tunnel(update) => return self.on_tunnel(update),
            Message::Bus(update) => return self.on_bus(update),
            Message::Configured(result, connect_next) => {
                tracing::info!(?result, connect_next, "configure helper finished");
                self.configuring = false;
                self.gateway = load_gateway();
                match result {
                    Ok(()) if connect_next => {
                        self.configure_error = None;
                        let effect = self.status.connect_trusted();
                        return self.run(effect);
                    }
                    Ok(()) => self.configure_error = None,
                    // Empty: the user dismissed the password dialog.
                    Err(err) if err.is_empty() => self.configure_error = None,
                    Err(err) => self.configure_error = Some(err),
                }
            }
            Message::LoginPageOpened(Err(err)) => {
                tracing::warn!(%err, "could not open the login page");
            }
            Message::LoginPageOpened(Ok(())) => {}
            Message::AlwaysTrust(checked) => self.always_trust = checked,
            Message::Trust => return self.trust_cert(),
            Message::OpenLoginPage => return self.open_login_page(),
            Message::Cancel => {
                let effect = self.status.disconnect();
                return self.run(effect);
            }
            Message::Drag(id) => return window::drag(id),
            Message::CertChecked(id, result) => {
                // A check from an earlier, cancelled attempt says nothing about this one.
                if id != self.cert_checks {
                    return Task::none();
                }
                let result = match result {
                    Ok(CertCheck::Trusted) => Ok(None),
                    Ok(CertCheck::Untrusted(cert)) => Ok(Some(cert)),
                    Err(err) => {
                        tracing::warn!(%err, "could not check the gateway certificate");
                        Err(err)
                    }
                };
                let effect = self.status.on_cert_checked(result);
                return self.run(effect);
            }
            Message::LoginFinished(result) => {
                self.login = None;
                if let LoginResult::Failed(why) = &result {
                    tracing::warn!(%why, "login window failed, using the system browser");
                }
                let effect = self.status.on_login(result);
                return self.run(effect);
            }
            Message::TrafficTick => return self.read_traffic(),
            Message::Probed(alive) => return self.on_probed(alive),
            Message::Sleep(update) => return self.on_sleep(update),
            Message::Network(change) => return self.on_network_change(&change),
            Message::Reconnect { id, network } => return self.attempt_reconnect(id, network),
            Message::Notified(Err(err)) => tracing::warn!(%err, "could not show a notification"),
            Message::Notified(Ok(())) => {}
            Message::HandedOver(Ok(())) => {}
            Message::HandedOver(Err(why)) => {
                tracing::warn!(%why, "could not hand the login to openfortivpn");
                let effect = self.status.fail(Failure::Other(why));
                return self.run(effect);
            }
            Message::WindowClosed(id) => {
                if self
                    .dialog
                    .as_ref()
                    .is_some_and(|(dialog_id, _)| *dialog_id == id)
                {
                    self.dialog = None;
                }
            }
        }
        Task::none()
    }

    fn on_tunnel(&mut self, update: tunnel::Update) -> Task<cosmic::Action<Message>> {
        match update {
            tunnel::Update::Ready(sender) => self.tunnel = Some(sender),
            tunnel::Update::Event(event) => {
                if let Event::Log(line) = &event {
                    self.note_tunnel_detail(line);
                }
                let effect = self.status.on_event(event, Instant::now());
                return self.run(effect);
            }
            tunnel::Update::Ended(ended) => {
                tracing::info!(?ended, "helper ended");
                self.status.on_ended(&ended);
            }
        }
        Task::none()
    }

    fn on_bus(&mut self, update: BusUpdate) -> Task<cosmic::Action<Message>> {
        match update {
            BusUpdate::Ready(sender) => {
                tracing::info!(name = bus::NAME, "serving on the session bus");
                self.bus = Some(sender);
                // Publish the current state to the newly served object.
                self.published = None;
            }
            BusUpdate::Command(AgentCommand::Connect) => {
                self.cancel_reconnect();
                let effect = self.status.connect();
                return self.run(effect);
            }
            BusUpdate::Command(AgentCommand::Disconnect) => {
                self.cancel_reconnect();
                let effect = self.status.disconnect();
                return self.run(effect);
            }
            BusUpdate::Command(AgentCommand::SetAutoReconnect(enabled)) => {
                self.set_auto_reconnect(enabled);
            }
            BusUpdate::Command(AgentCommand::ForgetCert) => {
                return self.configure(vec!["forget-cert".into()], false);
            }
            BusUpdate::Command(AgentCommand::SetGateway(address)) => {
                self.session_trust = None;
                return self.configure(vec!["set-gateway".into(), address], false);
            }
            BusUpdate::NameTaken => {
                tracing::info!("another agent is running, exiting");
                return cosmic::iced::exit();
            }
            BusUpdate::Failed(err) => {
                // Without the bus no applet can reach the agent, and D-Bus activation
                // starts a new one on the next call.
                tracing::error!(%err, "session bus failed, exiting");
                return cosmic::iced::exit();
            }
        }
        Task::none()
    }

    /// Reads the traffic counters every [`TRAFFIC_INTERVAL`] while connected.
    fn traffic_ticks(&self) -> Subscription<Message> {
        if matches!(self.status, Status::Connected { .. }) && self.interface.is_some() {
            cosmic::iced::time::every(TRAFFIC_INTERVAL).map(|_| Message::TrafficTick)
        } else {
            Subscription::none()
        }
    }

    /// Reads the counters for the statistics and checks whether the tunnel stalls.
    fn read_traffic(&mut self) -> Task<cosmic::Action<Message>> {
        let Some(interface) = &self.interface else {
            return Task::none();
        };
        let counters = match Counters::read(interface) {
            Ok(counters) => counters,
            // The interface goes away when the tunnel drops; openfortivpn reports that.
            Err(err) => {
                tracing::debug!(%err, interface, "could not read the traffic counters");
                return Task::none();
            }
        };
        let now = Instant::now();
        self.traffic = self.meter.sample(now, counters);
        match self.watch.update(now, counters) {
            Some(stalled) if self.nameservers.is_empty() && stalled >= STALL_WITHOUT_PROBE => {
                tracing::warn!(?stalled, "tunnel stalled, no DNS server to probe");
                self.lose_tunnel()
            }
            Some(stalled) if stalled >= STALL_BEFORE_PROBE => self.probe(),
            _ => Task::none(),
        }
    }

    /// Probes the tunnel when the network under it changed: an idle tunnel would otherwise
    /// only be found dead when it is next used.
    fn on_network_change(&mut self, change: &Change) -> Task<cosmic::Action<Message>> {
        if !matches!(self.status, Status::Connected { .. }) {
            return Task::none();
        }
        let tunnel = self.interface.as_deref().and_then(interface_index);
        if !change.besides(tunnel) {
            return Task::none();
        }
        tracing::info!(?change, "network changed");
        self.probe()
    }

    /// Asks the VPN's DNS servers whether the tunnel still carries traffic.
    fn probe(&mut self) -> Task<cosmic::Action<Message>> {
        if self.probing || self.nameservers.is_empty() {
            return Task::none();
        }
        tracing::info!("probing the tunnel");
        self.probing = true;
        let servers = self.nameservers.clone();
        cosmic::task::future(async move { Message::Probed(liveness::probe(servers).await) })
    }

    fn on_probed(&mut self, alive: bool) -> Task<cosmic::Action<Message>> {
        self.probing = false;
        if alive {
            tracing::info!("tunnel answered the probe");
            self.watch.reset();
            Task::none()
        } else {
            tracing::warn!("tunnel did not answer the probe");
            self.lose_tunnel()
        }
    }

    /// The tunnel is dead: stop it and report it lost.
    fn lose_tunnel(&mut self) -> Task<cosmic::Action<Message>> {
        if !matches!(self.status, Status::Connected { .. }) {
            return Task::none();
        }
        let effect = self.status.fail(Failure::Lost);
        self.run(effect)
    }

    fn on_sleep(&mut self, update: SleepUpdate) -> Task<cosmic::Action<Message>> {
        match update {
            SleepUpdate::Ready(lock) => {
                self.sleep_lock = Some(lock);
                self.holding_sleep = false;
            }
            SleepUpdate::Suspending => {
                tracing::info!(status = ?self.status, "system is going to sleep");
                self.connect_after_resume = self.auto_reconnect
                    && (matches!(self.status, Status::Connected { .. })
                        || self.reconnect.is_some());
                self.cancel_reconnect();
                // The lock is released once the tunnel is down (sync_sleep_lock).
                let effect = self.status.disconnect();
                return self.run(effect);
            }
            SleepUpdate::Resumed => {
                tracing::info!(status = ?self.status, "system resumed");
                if std::mem::take(&mut self.connect_after_resume) {
                    return self.start_reconnect();
                }
                // Still up means the disconnect before sleep did not happen in time.
                if matches!(self.status, Status::Connected { .. }) {
                    return self.probe();
                }
            }
            SleepUpdate::Failed(err) => {
                tracing::warn!(%err, "logind unavailable, sleep is not handled");
            }
        }
        Task::none()
    }

    /// Holds logind's sleep inhibitor while a connection runs, so sleep waits for the
    /// disconnect.
    fn sync_sleep_lock(&mut self) {
        let wanted = self.status.is_active();
        if wanted == self.holding_sleep {
            return;
        }
        if let Some(lock) = &self.sleep_lock
            && lock.send(wanted).is_ok()
        {
            self.holding_sleep = wanted;
        }
    }

    /// Keeps the interface name and address that pppd logs.
    fn note_tunnel_detail(&mut self, line: &str) {
        match TunnelDetail::parse(line) {
            Some(TunnelDetail::Interface(name)) => self.interface = Some(name),
            Some(TunnelDetail::LocalAddress(address)) => self.address = Some(address),
            Some(TunnelDetail::Nameservers(servers)) => self.nameservers = servers,
            None => {}
        }
    }

    /// Clears what was known about the last tunnel.
    fn forget_tunnel(&mut self) {
        self.interface = None;
        self.address = None;
        self.meter = Meter::default();
        self.traffic = Traffic::default();
        self.nameservers.clear();
        self.watch = Watch::default();
        self.probing = false;
    }

    /// Decides what a status change means for reconnecting, and starts or continues it.
    fn follow_reconnect(
        &mut self,
        before: &Status,
    ) -> (ReconnectStep, Task<cosmic::Action<Message>>) {
        let was_connected = matches!(before, Status::Connected { .. });
        match &self.status {
            Status::Connected { .. } => {
                if self.reconnect.take().is_some() {
                    tracing::info!("reconnected");
                }
                (ReconnectStep::None, Task::none())
            }
            Status::Failed(Failure::Lost | Failure::Stopped)
                if was_connected && self.auto_reconnect =>
            {
                (ReconnectStep::Pending, self.start_reconnect())
            }
            Status::Failed(_) if self.reconnect.is_some() => match self.schedule_reconnect() {
                Some(task) => (ReconnectStep::Pending, task),
                None => (ReconnectStep::GaveUp, Task::none()),
            },
            // The user cancelled the attempt, or must decide about the certificate.
            Status::Disconnected | Status::CertUntrusted(_) => {
                self.cancel_reconnect();
                (ReconnectStep::None, Task::none())
            }
            _ => (ReconnectStep::None, Task::none()),
        }
    }

    fn start_reconnect(&mut self) -> Task<cosmic::Action<Message>> {
        self.reconnects += 1;
        tracing::info!("reconnecting");
        self.reconnect = Some(Reconnect::new(self.reconnects));
        self.schedule_reconnect().unwrap_or_else(Task::none)
    }

    /// Schedules the next attempt; `None` (and the reconnect ended) once all are used up.
    fn schedule_reconnect(&mut self) -> Option<Task<cosmic::Action<Message>>> {
        let reconnect = self.reconnect.as_mut()?;
        let Some(delay) = reconnect.next_delay() else {
            tracing::warn!("giving up reconnecting");
            self.reconnect = None;
            return None;
        };
        let id = reconnect.id;
        Some(cosmic::task::future(async move {
            Message::Reconnect {
                id,
                network: reconnect::wait(delay).await,
            }
        }))
    }

    fn attempt_reconnect(&mut self, id: u64, network: bool) -> Task<cosmic::Action<Message>> {
        if self.reconnect.as_ref().map(|r| r.id) != Some(id) {
            return Task::none();
        }
        if !network {
            tracing::info!("network did not come back");
            return self.schedule_reconnect().unwrap_or_else(|| {
                // The status stays as it is, so report giving up here.
                self.notify_failure(&self.status.clone(), Some(fl!("notify-reconnect-failed")))
            });
        }
        let effect = self.status.connect();
        self.run(effect)
    }

    fn cancel_reconnect(&mut self) {
        if self.reconnect.take().is_some() {
            tracing::info!("reconnect cancelled");
        }
    }

    fn set_auto_reconnect(&mut self, enabled: bool) {
        self.auto_reconnect = enabled;
        if !enabled {
            self.cancel_reconnect();
        }
        if let Some(config) = &self.config
            && let Err(err) = config.set(AUTO_RECONNECT, enabled)
        {
            tracing::warn!(%err, "could not save the settings");
        }
    }

    /// Notifies when the connection fails, since the popover is usually closed then. A
    /// disconnect the user asked for ends in `Disconnected`, not `Failed`. `summary` replaces
    /// the usual title.
    fn notify_failure(
        &self,
        before: &Status,
        summary: Option<String>,
    ) -> Task<cosmic::Action<Message>> {
        let Status::Failed(_) = &self.status else {
            return Task::none();
        };
        let snapshot = Snapshot::new(
            &self.status,
            &self.gateway,
            false,
            None,
            None,
            Traffic::default(),
        );
        let summary = summary.unwrap_or_else(|| {
            if matches!(before, Status::Connected { .. }) {
                fl!("notify-disconnected")
            } else {
                fl!("notify-failed")
            }
        });
        let notification = Notification {
            summary,
            body: crate::applet::failure_text(&snapshot),
        };
        cosmic::task::future(
            async move { Message::Notified(notify::show(notification, APP_ID).await) },
        )
    }

    /// Stops the login window once the login is no longer wanted (cancelled from an applet),
    /// and ends the browser fallback once openfortivpn no longer waits for the login.
    fn end_login_if_done(&mut self) {
        if self.status != Status::LoggingIn
            && let Some(login) = self.login.take()
        {
            login.abort();
        }
        if self.status != Status::WaitingForLogin {
            self.browser_login = false;
        }
    }

    /// Carries out what a state transition asks for.
    fn run(&mut self, effect: Effect) -> Task<cosmic::Action<Message>> {
        match effect {
            Effect::None => Task::none(),
            Effect::Send(command) => {
                let sent = self
                    .tunnel
                    .as_ref()
                    .is_some_and(|tunnel| tunnel.send(command).is_ok());
                if !sent {
                    tracing::error!("tunnel task is not running");
                    self.status =
                        Status::Failed(Failure::Other("tunnel task is not running".into()));
                }
                Task::none()
            }
            Effect::Login => self.run_login(),
            Effect::DeliverSamlId(id) => {
                cosmic::task::future(async move { Message::HandedOver(login::hand_over(id).await) })
            }
            Effect::OpenLoginPage => {
                self.browser_login = true;
                self.open_login_page()
            }
            Effect::CheckCert => self.check_cert(),
        }
    }

    /// Checks the gateway certificate on a blocking thread, for at most
    /// [`CERT_CHECK_TIMEOUT`].
    fn check_cert(&mut self) -> Task<cosmic::Action<Message>> {
        self.cert_checks += 1;
        let id = self.cert_checks;
        let Ok(Some(gateway)) = self.gateway.clone() else {
            // No gateway: let the helper report it.
            return cosmic::task::message(Message::CertChecked(id, Ok(CertCheck::Trusted)));
        };
        cosmic::task::future(async move {
            let check = tokio::task::spawn_blocking(move || certcheck::check(&gateway));
            // On timeout the blocking thread finishes on its own; its result is dropped.
            let result = match tokio::time::timeout(CERT_CHECK_TIMEOUT, check).await {
                Ok(joined) => joined.unwrap_or_else(|err| Err(err.to_string())),
                Err(_) => Err("no answer within 15 seconds".into()),
            };
            Message::CertChecked(id, result)
        })
    }

    fn open_login_page(&self) -> Task<cosmic::Action<Message>> {
        match &self.gateway {
            Ok(Some(gateway)) => {
                let url = gateway.saml_login_url();
                cosmic::task::future(async move { Message::LoginPageOpened(open_url(&url).await) })
            }
            _ => Task::none(),
        }
    }

    /// Trusts the certificate in the dialog, always or for this connection, then connects.
    fn trust_cert(&mut self) -> Task<cosmic::Action<Message>> {
        let Status::CertUntrusted(cert) = &self.status else {
            return Task::none();
        };
        let command = if self.always_trust {
            "trust-cert"
        } else {
            "trust-cert-once"
        };
        let args = vec![command.into(), cert.digest.to_string()];
        self.session_trust = Some(cert.digest.clone());
        self.configure(args, true)
    }

    /// Runs the login window, before openfortivpn starts. Aborting the task kills it
    /// (`kill_on_drop`).
    fn run_login(&mut self) -> Task<cosmic::Action<Message>> {
        let Ok(Some(gateway)) = &self.gateway else {
            let why = "no gateway".to_owned();
            return cosmic::task::message(Message::LoginFinished(LoginResult::Failed(why)));
        };
        let trusted = self
            .session_trust
            .clone()
            .or_else(|| gateway.trusted_cert.clone());
        let login = login::Login {
            url: gateway.saml_login_url(),
            host: gateway.host.clone(),
            trusted,
        };
        let (task, handle) =
            cosmic::task::future(async move { Message::LoginFinished(login::run(login).await) })
                .abortable();
        self.login = Some(handle);
        task
    }

    /// Runs the configure helper through pkexec, which asks for the admin password.
    fn configure(
        &mut self,
        args: Vec<String>,
        connect_next: bool,
    ) -> Task<cosmic::Action<Message>> {
        self.configuring = true;
        self.configure_error = None;
        cosmic::task::future(async move {
            Message::Configured(run_configure(&args).await, connect_next)
        })
    }

    /// Sends the current state to the bus if it changed.
    fn publish(&mut self) {
        let snapshot = Snapshot::new(
            &self.status,
            &self.gateway,
            self.configuring,
            self.configure_error.as_deref(),
            self.address.as_deref(),
            self.traffic,
        )
        .with_reconnect(self.reconnect.is_some(), self.auto_reconnect);
        if self.published.as_ref() == Some(&snapshot) {
            return;
        }
        if let Some(bus) = &self.bus
            && bus.send(snapshot.clone()).is_ok()
        {
            self.published = Some(snapshot);
        }
    }

    /// Opens, swaps or closes the dialog window to match the state.
    fn sync_dialog(&mut self) -> Task<cosmic::Action<Message>> {
        let wanted = match &self.status {
            Status::CertUntrusted(cert) => Some(Dialog::Cert(cert.clone())),
            // The login window speaks for itself; the dialog only points at the browser.
            Status::WaitingForLogin if self.browser_login => Some(Dialog::Login),
            _ => None,
        };
        if self.dialog.as_ref().map(|(_, dialog)| dialog) == wanted.as_ref() {
            return Task::none();
        }
        let close = match self.dialog.take() {
            Some((id, _)) => surface::surface_task(surface::action::destroy_window(id)),
            None => Task::none(),
        };
        let Some(dialog) = wanted else {
            return close;
        };
        if matches!(dialog, Dialog::Cert(_)) {
            self.always_trust = true;
        }
        let (title, size) = match &dialog {
            Dialog::Cert(_) => (fl!("cert-untrusted-title"), CERT_DIALOG_SIZE),
            Dialog::Login => (fl!("login-dialog-title"), LOGIN_DIALOG_SIZE),
        };
        let settings = window::Settings {
            size,
            resizable: false,
            decorations: false,
            exit_on_close_request: false,
            platform_specific: window::settings::PlatformSpecific {
                application_id: APP_ID.into(),
                ..Default::default()
            },
            ..Default::default()
        };
        // Through libcosmic rather than iced's `window::open`: libcosmic then tracks the
        // window and applies the theme's blur and corner radius when it opens. An untracked
        // window got a transparent background without blur until it was focused.
        // No blur: the frosted background let other windows' focus changes show through the
        // semi-transparent controls as flicker. The dialog draws an opaque background instead.
        let (id, open) = surface::action::app_window::<Self>(
            |_| surface::action::LiveSettings {
                blur: Some(false),
                ..Default::default()
            },
            move |_| settings.clone(),
            None,
        );
        self.dialog = Some((id, dialog));
        let title_task = self.set_window_title(title, id);
        Task::batch([close, surface::surface_task(open), title_task])
    }

    /// Asks whether to trust a certificate that does not validate.
    fn cert_dialog(&self, id: Id, cert: &UntrustedCert) -> Element<'_, Message> {
        let spacing = theme::active().cosmic().spacing;
        let host = match &self.gateway {
            Ok(Some(gateway)) => gateway.host.clone(),
            _ => String::new(),
        };
        let field =
            |label: String, value: String| column![text::caption_heading(label), text::body(value)];
        let mut details = column![
            text::body(fl!("cert-untrusted-body", host = host)),
            field(fl!("cert-subject"), cert.subject.clone()),
            field(fl!("cert-issuer"), cert.issuer.clone()),
            column![
                text::caption_heading(fl!("cert-fingerprint")),
                text::monotext(group_digest(cert.digest.as_str())),
            ],
            checkbox(self.always_trust)
                .label(fl!("always-trust"))
                .on_toggle(Message::AlwaysTrust),
        ]
        .spacing(spacing.space_s);
        if let Some(err) = &self.configure_error {
            details = details.push(text::body(err.clone()));
        }

        let mut trust = button::suggested(fl!("trust"));
        let mut cancel = button::standard(fl!("cancel"));
        if !self.configuring {
            trust = trust.on_press(Message::Trust);
            cancel = cancel.on_press(Message::Cancel);
        }
        dialog_layout(
            id,
            "dialog-warning-symbolic",
            fl!("cert-untrusted-title"),
            details.into(),
            vec![cancel.into(), trust.into()],
        )
    }

    /// Tells the user to log in in the browser; closes itself once the login arrived.
    fn login_dialog(&self, id: Id) -> Element<'_, Message> {
        let host = match &self.gateway {
            Ok(Some(gateway)) => gateway.host.clone(),
            _ => String::new(),
        };
        dialog_layout(
            id,
            "network-vpn-acquiring-symbolic",
            fl!("login-dialog-title"),
            text::body(fl!("login-dialog-body", host = host)).into(),
            vec![
                button::standard(fl!("cancel"))
                    .on_press(Message::Cancel)
                    .into(),
                button::suggested(fl!("open-login-page"))
                    .on_press(Message::OpenLoginPage)
                    .into(),
            ],
        )
    }
}

/// Lays out a dialog window: a header bar to move and close it, icon and scrollable content,
/// and the buttons at the bottom right. Unlike libcosmic's `dialog()`, the content scrolls, so
/// the buttons stay visible however long it gets (`dialog()` only scrolls the body text and
/// clips the rest).
fn dialog_layout<'a>(
    id: Id,
    icon_name: &'static str,
    title: String,
    content: Element<'a, Message>,
    buttons: Vec<Element<'a, Message>>,
) -> Element<'a, Message> {
    let spacing = theme::active().cosmic().spacing;
    let header = header_bar()
        .title(title)
        .on_drag(Message::Drag(id))
        .on_close(Message::Cancel);
    let mut button_row = row![horizontal_space()].spacing(spacing.space_xxs);
    for button in buttons {
        button_row = button_row.push(button);
    }
    let content = scrollable(container(content).padding([0, spacing.space_s, 0, 0]))
        .height(Length::Fill)
        .width(Length::Fill);
    let body = row![icon::from_name(icon_name).size(48), content]
        .spacing(spacing.space_s)
        .height(Length::Fill);
    let dialog = column![
        header,
        container(
            column![body, button_row]
                .spacing(spacing.space_m)
                .height(Length::Fill)
        )
        .padding([0, spacing.space_m, spacing.space_m, spacing.space_m])
        .width(Length::Fill)
        .height(Length::Fill),
    ];
    container(dialog)
        .class(cosmic::theme::Container::custom(opaque_background))
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// The theme's window background without its frosted-glass transparency.
fn opaque_background(theme: &cosmic::Theme) -> cosmic::iced::widget::container::Style {
    let cosmic = theme.cosmic();
    let background = cosmic.background(false);
    cosmic::iced::widget::container::Style {
        icon_color: Some(background.on.into()),
        text_color: Some(background.on.into()),
        background: Some(cosmic::iced::Background::Color(background.base.into())),
        border: cosmic::iced::Border {
            radius: cosmic.corner_radii.radius_s.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Splits a hex digest into groups of four, eight groups per line, so it can be compared by
/// eye and does not wrap at a width-dependent place.
fn group_digest(digest: &str) -> String {
    let groups: Vec<_> = digest
        .as_bytes()
        .chunks(4)
        .map(String::from_utf8_lossy)
        .collect();
    groups
        .chunks(8)
        .map(|line| line.join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

fn load_gateway() -> Result<Option<Gateway>, String> {
    Gateway::load().map_err(|err| err.to_string())
}

/// Opens a URL in the default browser.
async fn open_url(url: &str) -> Result<(), String> {
    let status = tokio::process::Command::new("xdg-open")
        .arg(url)
        .status()
        .await
        .map_err(|err| format!("xdg-open: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("xdg-open: {status}"))
    }
}

/// Runs `pkexec <configure helper> <args>`; the error is its stderr.
async fn run_configure(args: &[String]) -> Result<(), String> {
    let output = tokio::process::Command::new("pkexec")
        .arg(format!("{LIBEXEC_DIR}/{CONFIGURE_NAME}"))
        .args(args)
        .output()
        .await
        .map_err(|err| format!("pkexec: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    match output.status.code() {
        // Dismissed authentication dialog: not an error worth showing.
        Some(126) => Err(String::new()),
        _ if stderr.is_empty() => Err(format!("{}", output.status)),
        _ => Err(stderr),
    }
}

/// The kernel's index of a network interface (a name checked by `TunnelDetail`).
fn interface_index(name: &str) -> Option<u32> {
    let path = std::path::Path::new("/sys/class/net")
        .join(name)
        .join("ifindex");
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_grouped_by_four() {
        assert_eq!(group_digest("f2c93596abcd"), "f2c9 3596 abcd");
        assert_eq!(group_digest("f2c935"), "f2c9 35");
        let digest = "f2c935968edba48ab89c19f4291cf5449efc814665d179e32023f519dc89f1a1";
        assert_eq!(
            group_digest(digest),
            "f2c9 3596 8edb a48a b89c 19f4 291c f544\n9efc 8146 65d1 79e3 2023 f519 dc89 f1a1"
        );
    }
}
