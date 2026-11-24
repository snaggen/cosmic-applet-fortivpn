// SPDX-License-Identifier: GPL-3.0-only

//! The panel applet: panel icon and popover.

use crate::{
    fl,
    state::{Effect, Failure, Status},
    tunnel::{self, TunnelCommand},
};
use cosmic::{
    Element, Task,
    app::Core,
    applet::padded_control,
    iced::{
        Alignment, Length, Subscription,
        platform_specific::shell::wayland::commands::popup::destroy_popup,
        widget::{column, row, space::horizontal as horizontal_space},
        window::Id,
    },
    surface, theme,
    widget::{button, divider, icon, text, text_input},
};
use cosmic_applet_fortivpn::{CONFIGURE_NAME, LIBEXEC_DIR, gateway::Gateway};
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;

const APP_ID: &str = "io.github.snaggen.CosmicAppletFortivpn";

pub struct Applet {
    core: Core,
    /// The open popover, if any.
    popup: Option<Id>,
    status: Status,
    /// The configured gateway, or why it could not be read.
    gateway: Result<Option<Gateway>, String>,
    /// Gateway address being typed in the setup form.
    gateway_input: String,
    /// Commands to the tunnel task, once it runs.
    tunnel: Option<UnboundedSender<TunnelCommand>>,
    /// A configure helper is running (waiting for the admin password).
    configuring: bool,
    /// Why the last configure attempt failed.
    configure_error: Option<String>,
}

#[derive(Clone, Debug)]
pub enum Message {
    TogglePopup,
    PopupClosed(Id),
    Tunnel(tunnel::Update),
    Connect,
    Disconnect,
    GatewayInput(String),
    SaveGateway,
    TrustCert,
    /// The configure helper finished; on success, whether to connect next.
    Configured(Result<(), String>, bool),
    LoginPageOpened(Result<(), String>),
}

impl cosmic::Application for Applet {
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
        let applet = Self {
            core,
            popup: None,
            status: Status::Disconnected,
            gateway: load_gateway(),
            gateway_input: String::new(),
            tunnel: None,
            configuring: false,
            configure_error: None,
        };
        (applet, Task::none())
    }

    fn on_close_requested(&self, id: Id) -> Option<Message> {
        Some(Message::PopupClosed(id))
    }

    fn subscription(&self) -> Subscription<Self::Message> {
        tunnel::subscription().map(Message::Tunnel)
    }

    fn update(&mut self, message: Self::Message) -> Task<cosmic::Action<Self::Message>> {
        let before = self.status.clone();
        let task = self.handle(message);
        if self.status != before {
            tracing::info!(status = ?self.status, "status changed");
        }
        task
    }

    fn view(&self) -> Element<'_, Self::Message> {
        self.core
            .applet
            .icon_button(panel_icon(&self.status))
            .on_press_down(Message::TogglePopup)
            .into()
    }

    fn view_window(&self, _id: Id) -> Element<'_, Self::Message> {
        self.popover()
    }

    fn style(&self) -> Option<cosmic::iced::theme::Style> {
        Some(cosmic::applet::style())
    }
}

impl Applet {
    fn handle(&mut self, message: Message) -> Task<cosmic::Action<Message>> {
        match message {
            Message::TogglePopup => return self.toggle_popup(),
            Message::PopupClosed(id) => {
                if self.popup == Some(id) {
                    self.popup = None;
                }
            }
            Message::Tunnel(update) => return self.on_tunnel(update),
            Message::Connect => {
                tracing::info!(tunnel_ready = self.tunnel.is_some(), "connect clicked");
                let effect = self.status.connect();
                return self.run(effect);
            }
            Message::Disconnect => {
                let effect = self.status.disconnect();
                return self.run(effect);
            }
            Message::GatewayInput(input) => {
                self.gateway_input = input;
                self.configure_error = None;
            }
            Message::SaveGateway => return self.save_gateway(),
            Message::TrustCert => return self.trust_cert(),
            Message::Configured(result, connect_next) => {
                tracing::info!(?result, connect_next, "configure helper finished");
                self.configuring = false;
                self.gateway = load_gateway();
                match result {
                    Ok(()) if connect_next => {
                        let effect = self.status.connect();
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
        }
        Task::none()
    }

    fn popover(&self) -> Element<'_, Message> {
        let spacing = theme::active().cosmic().spacing;
        let mut content = column![padded_control(self.headline())];

        let body = match (&self.gateway, &self.status) {
            (Err(err), _) => Some(self.error_text(fl!("gateway-unreadable", reason = err.clone()))),
            (Ok(None), _) => Some(self.setup_form()),
            (Ok(Some(gateway)), Status::CertUntrusted(cert)) => {
                Some(self.cert_prompt(gateway, cert))
            }
            (Ok(Some(_)), Status::Failed(failure)) => Some(self.error_text(failure_text(failure))),
            (Ok(Some(_)), _) => None,
        };
        if let Some(body) = body {
            content = content
                .push(padded_control(divider::horizontal::default()))
                .push(padded_control(body));
        }
        if let Some(action) = self.action_button() {
            content = content
                .push(padded_control(divider::horizontal::default()))
                .push(padded_control(action));
        }

        let content = content.padding([spacing.space_xxs, 0]);
        self.core.applet.popup_container(content).into()
    }

    /// Closes the popover if open, otherwise opens it below the panel icon.
    fn toggle_popup(&mut self) -> Task<cosmic::Action<Message>> {
        if let Some(id) = self.popup.take() {
            return destroy_popup(id);
        }
        let Some(parent) = self.core.main_window_id() else {
            tracing::warn!("no main window to anchor the popover to");
            return Task::none();
        };
        surface::surface_task(surface::action::app_popup(
            |_: &Self| Default::default(),
            move |app: &mut Self| {
                let id = Id::unique();
                app.popup = Some(id);
                app.core
                    .applet
                    .get_popup_settings(parent, id, None, None, None)
            },
            None,
        ))
    }

    fn on_tunnel(&mut self, update: tunnel::Update) -> Task<cosmic::Action<Message>> {
        match update {
            tunnel::Update::Ready(sender) => {
                tracing::info!("tunnel task ready");
                self.tunnel = Some(sender);
            }
            tunnel::Update::Event(event) => {
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
            Effect::OpenLoginPage => match &self.gateway {
                Ok(Some(gateway)) => {
                    let url = gateway.saml_login_url();
                    cosmic::task::future(
                        async move { Message::LoginPageOpened(open_url(&url).await) },
                    )
                }
                _ => Task::none(),
            },
        }
    }

    fn save_gateway(&mut self) -> Task<cosmic::Action<Message>> {
        let input = self.gateway_input.trim().to_owned();
        if let Err(err) = input.parse::<Gateway>() {
            tracing::debug!(%err, %input, "invalid gateway");
            self.configure_error = Some(fl!("gateway-invalid"));
            return Task::none();
        }
        self.configure(vec!["set-gateway".into(), input], false)
    }

    fn trust_cert(&mut self) -> Task<cosmic::Action<Message>> {
        let Status::CertUntrusted(cert) = &self.status else {
            return Task::none();
        };
        let args = vec!["trust-cert".into(), cert.digest.to_string()];
        self.configure(args, true)
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

    /// Icon, "VPN", and the status with the gateway.
    fn headline(&self) -> Element<'_, Message> {
        let spacing = theme::active().cosmic().spacing;
        let mut details = column![
            text::heading(fl!("vpn")),
            text::caption(status_text(&self.status))
        ];
        if let Ok(Some(gateway)) = &self.gateway {
            details = details.push(text::caption(gateway.address()));
        }
        row![icon::from_name(panel_icon(&self.status)).size(24), details]
            .spacing(spacing.space_xs)
            .align_y(Alignment::Center)
            .into()
    }

    /// First-run form: the gateway address.
    fn setup_form(&self) -> Element<'_, Message> {
        let spacing = theme::active().cosmic().spacing;
        let mut input = text_input(fl!("gateway-placeholder"), &self.gateway_input)
            .label(fl!("gateway"))
            .width(Length::Fill);
        let mut save = button::suggested(fl!("save"));
        if !self.configuring {
            input = input
                .on_input(Message::GatewayInput)
                .on_submit(|_| Message::SaveGateway);
            save = save.on_press(Message::SaveGateway);
        }
        let mut form = column![text::body(fl!("gateway-missing")), input].spacing(spacing.space_xs);
        if let Some(err) = &self.configure_error {
            form = form.push(text::caption(err.clone()));
        }
        form.push(row![horizontal_space(), save]).into()
    }

    /// Trust-on-first-use prompt for a certificate that does not validate.
    fn cert_prompt(
        &self,
        gateway: &Gateway,
        cert: &cosmic_applet_fortivpn::protocol::UntrustedCert,
    ) -> Element<'_, Message> {
        let spacing = theme::active().cosmic().spacing;
        let field = |label: String, value: String| {
            column![text::caption_heading(label), text::caption(value)]
        };
        let mut prompt = column![
            text::heading(fl!("cert-untrusted-title")),
            text::body(fl!("cert-untrusted-body", host = gateway.host.clone())),
            field(fl!("cert-subject"), cert.subject.clone()),
            field(fl!("cert-issuer"), cert.issuer.clone()),
            column![
                text::caption_heading(fl!("cert-fingerprint")),
                text::monotext(group_digest(cert.digest.as_str())),
            ],
        ]
        .spacing(spacing.space_xs);
        if let Some(err) = &self.configure_error {
            prompt = prompt.push(text::caption(err.clone()));
        }
        prompt.into()
    }

    fn error_text(&self, message: String) -> Element<'_, Message> {
        text::body(message).into()
    }

    /// The main button for the current state.
    fn action_button(&self) -> Option<Element<'_, Message>> {
        if !matches!(self.gateway, Ok(Some(_))) {
            return None;
        }
        let spacing = theme::active().cosmic().spacing;
        let button: Element<'_, Message> = match &self.status {
            Status::Disconnected | Status::Failed(_) => button::suggested(fl!("connect"))
                .on_press(Message::Connect)
                .into(),
            Status::Connecting | Status::WaitingForLogin | Status::Connected { .. } => {
                button::standard(fl!("disconnect"))
                    .on_press(Message::Disconnect)
                    .into()
            }
            Status::Disconnecting => button::standard(fl!("disconnect")).into(),
            Status::CertUntrusted(_) => {
                let mut trust = button::suggested(fl!("trust-and-connect"));
                if !self.configuring {
                    trust = trust.on_press(Message::TrustCert);
                }
                row![
                    button::standard(fl!("cancel")).on_press(Message::Disconnect),
                    trust,
                ]
                .spacing(spacing.space_xs)
                .into()
            }
        };
        Some(
            row![horizontal_space(), button]
                .align_y(Alignment::Center)
                .into(),
        )
    }
}

fn panel_icon(status: &Status) -> &'static str {
    match status {
        Status::Disconnected => "network-vpn-disconnected-symbolic",
        Status::Connecting | Status::WaitingForLogin | Status::Disconnecting => {
            "network-vpn-acquiring-symbolic"
        }
        Status::Connected { .. } => "network-vpn-symbolic",
        Status::CertUntrusted(_) | Status::Failed(_) => "network-vpn-error-symbolic",
    }
}

fn status_text(status: &Status) -> String {
    match status {
        Status::Disconnected => fl!("status-disconnected"),
        Status::Connecting => fl!("status-connecting"),
        Status::WaitingForLogin => fl!("status-waiting-for-login"),
        Status::Connected { .. } => fl!("status-connected"),
        Status::Disconnecting => fl!("status-disconnecting"),
        Status::CertUntrusted(_) => fl!("status-cert-untrusted"),
        Status::Failed(_) => fl!("status-failed"),
    }
}

fn failure_text(failure: &Failure) -> String {
    match failure {
        Failure::NotConfigured => fl!("error-not-configured"),
        Failure::Busy => fl!("error-busy"),
        Failure::AuthFailed => fl!("error-auth-failed"),
        Failure::NotAuthorized(why) => fl!("error-not-authorized", reason = why.clone()),
        Failure::Stopped => fl!("error-stopped"),
        Failure::Other(why) => fl!("error-other", reason = why.clone()),
    }
}

/// Splits a hex digest into groups of four, so it can be compared by eye and wraps.
fn group_digest(digest: &str) -> String {
    digest
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk))
        .collect::<Vec<_>>()
        .join(" ")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_grouped_by_four() {
        assert_eq!(group_digest("f2c93596abcd"), "f2c9 3596 abcd");
        assert_eq!(group_digest("f2c935"), "f2c9 35");
    }
}
