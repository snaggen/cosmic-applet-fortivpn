// SPDX-License-Identifier: GPL-3.0-only

//! The panel applet: panel icon and popover.
//!
//! The panel runs one applet per output, so the applet only shows the agent's state and
//! forwards the user's clicks to it ([`crate::client`]). The agent owns the tunnel.

use crate::{
    bus::{AgentProxy, Snapshot, State},
    client::{self, ClientUpdate},
    fl,
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
use cosmic_applet_fortivpn::gateway::Gateway;

const APP_ID: &str = "io.github.snaggen.CosmicAppletFortivpn";

pub struct Applet {
    core: Core,
    /// The open popover, if any.
    popup: Option<Id>,
    agent: Option<AgentProxy<'static>>,
    /// The agent's state; `None` until read, or while the agent cannot be reached.
    snapshot: Option<Snapshot>,
    /// Gateway address being typed in the setup form.
    gateway_input: String,
    /// The typed address is not `host:port`.
    gateway_invalid: bool,
}

#[derive(Clone, Debug)]
pub enum Message {
    TogglePopup,
    PopupClosed(Id),
    Client(ClientUpdate),
    Connect,
    Disconnect,
    GatewayInput(String),
    SaveGateway,
    /// A call to the agent finished.
    Called(Result<(), String>),
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
            agent: None,
            snapshot: None,
            gateway_input: String::new(),
            gateway_invalid: false,
        };
        (applet, Task::none())
    }

    fn on_close_requested(&self, id: Id) -> Option<Message> {
        Some(Message::PopupClosed(id))
    }

    fn subscription(&self) -> Subscription<Self::Message> {
        client::subscription().map(Message::Client)
    }

    fn update(&mut self, message: Self::Message) -> Task<cosmic::Action<Self::Message>> {
        match message {
            Message::TogglePopup => return self.toggle_popup(),
            Message::PopupClosed(id) => {
                if self.popup == Some(id) {
                    self.popup = None;
                }
            }
            Message::Client(ClientUpdate::Ready(agent)) => self.agent = Some(agent),
            Message::Client(ClientUpdate::Snapshot(snapshot)) => {
                if snapshot.as_ref().map(|s| s.state) != self.snapshot.as_ref().map(|s| s.state) {
                    tracing::info!(state = ?snapshot.as_ref().map(|s| s.state), "agent state");
                }
                self.snapshot = snapshot;
            }
            Message::Connect => return self.call(|agent| async move { agent.connect().await }),
            Message::Disconnect => {
                return self.call(|agent| async move { agent.disconnect().await });
            }
            Message::GatewayInput(input) => {
                self.gateway_input = input;
                self.gateway_invalid = false;
            }
            Message::SaveGateway => {
                let address = self.gateway_input.trim().to_owned();
                if address.parse::<Gateway>().is_err() {
                    self.gateway_invalid = true;
                    return Task::none();
                }
                return self.call(move |agent| async move { agent.set_gateway(&address).await });
            }
            Message::Called(Err(err)) => tracing::warn!(%err, "call to the agent failed"),
            Message::Called(Ok(())) => {}
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Self::Message> {
        self.core
            .applet
            .icon_button(panel_icon(self.snapshot.as_ref()))
            .on_press_down(Message::TogglePopup)
            .into()
    }

    fn view_window(&self, _id: Id) -> Element<'_, Self::Message> {
        let spacing = theme::active().cosmic().spacing;
        let mut content = column![padded_control(self.headline())];
        if let Some(body) = self.body() {
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

    fn style(&self) -> Option<cosmic::iced::theme::Style> {
        Some(cosmic::applet::style())
    }
}

impl Applet {
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

    /// Calls the agent. The result shows up as a state change, so only errors are logged.
    fn call<F, Fut>(&self, f: F) -> Task<cosmic::Action<Message>>
    where
        F: FnOnce(AgentProxy<'static>) -> Fut + Send + 'static,
        Fut: Future<Output = zbus::Result<()>> + Send + 'static,
    {
        let Some(agent) = self.agent.clone() else {
            tracing::warn!("not connected to the session bus yet");
            return Task::none();
        };
        cosmic::task::future(async move {
            Message::Called(f(agent).await.map_err(|err| err.to_string()))
        })
    }

    /// Icon, "VPN", the state, and the gateway.
    fn headline(&self) -> Element<'_, Message> {
        let spacing = theme::active().cosmic().spacing;
        let mut details = column![
            text::heading(fl!("vpn")),
            text::caption(status_text(self.snapshot.as_ref()))
        ];
        if let Some(snapshot) = &self.snapshot
            && !snapshot.gateway.is_empty()
        {
            details = details.push(text::caption(snapshot.gateway.clone()));
        }
        row![
            icon::from_name(panel_icon(self.snapshot.as_ref())).size(24),
            details
        ]
        .spacing(spacing.space_xs)
        .align_y(Alignment::Center)
        .into()
    }

    /// Setup form, or an explanation of the current problem.
    fn body(&self) -> Option<Element<'_, Message>> {
        let Some(snapshot) = &self.snapshot else {
            return Some(text::body(fl!("agent-unavailable")).into());
        };
        if !snapshot.gateway_error.is_empty() {
            let reason = snapshot.gateway_error.clone();
            return Some(text::body(fl!("gateway-unreadable", reason = reason)).into());
        }
        if snapshot.gateway.is_empty() {
            return Some(self.setup_form(snapshot));
        }
        match snapshot.state {
            State::Failed => Some(text::body(failure_text(snapshot)).into()),
            State::CertUntrusted => Some(text::body(fl!("cert-untrusted-hint")).into()),
            State::WaitingForLogin => Some(text::body(fl!("waiting-for-login-hint")).into()),
            _ => None,
        }
    }

    /// First-run form: the gateway address.
    fn setup_form(&self, snapshot: &Snapshot) -> Element<'_, Message> {
        let spacing = theme::active().cosmic().spacing;
        let mut input = text_input(fl!("gateway-placeholder"), &self.gateway_input)
            .label(fl!("gateway"))
            .width(Length::Fill);
        let mut save = button::suggested(fl!("save"));
        if !snapshot.configuring {
            input = input
                .on_input(Message::GatewayInput)
                .on_submit(|_| Message::SaveGateway);
            save = save.on_press(Message::SaveGateway);
        }
        let mut form = column![text::body(fl!("gateway-missing")), input].spacing(spacing.space_xs);
        if self.gateway_invalid {
            form = form.push(text::caption(fl!("gateway-invalid")));
        } else if !snapshot.configure_error.is_empty() {
            form = form.push(text::caption(snapshot.configure_error.clone()));
        }
        form.push(row![horizontal_space(), save]).into()
    }

    /// Connect or disconnect, depending on the state.
    fn action_button(&self) -> Option<Element<'_, Message>> {
        let snapshot = self.snapshot.as_ref()?;
        if snapshot.gateway.is_empty() {
            return None;
        }
        let button: Element<'_, Message> = match snapshot.state {
            State::Disconnected | State::Failed => button::suggested(fl!("connect"))
                .on_press(Message::Connect)
                .into(),
            State::Connecting
            | State::WaitingForLogin
            | State::Connected
            | State::CertUntrusted => button::standard(fl!("disconnect"))
                .on_press(Message::Disconnect)
                .into(),
            State::Disconnecting => button::standard(fl!("disconnect")).into(),
        };
        Some(
            row![horizontal_space(), button]
                .align_y(Alignment::Center)
                .into(),
        )
    }
}

fn panel_icon(snapshot: Option<&Snapshot>) -> &'static str {
    match snapshot.map(|s| s.state) {
        Some(State::Disconnected) => "network-vpn-disconnected-symbolic",
        Some(State::Connecting | State::WaitingForLogin | State::Disconnecting) => {
            "network-vpn-acquiring-symbolic"
        }
        Some(State::Connected) => "network-vpn-symbolic",
        Some(State::CertUntrusted | State::Failed) | None => "network-vpn-error-symbolic",
    }
}

fn status_text(snapshot: Option<&Snapshot>) -> String {
    match snapshot.map(|s| s.state) {
        None => fl!("status-unavailable"),
        Some(State::Disconnected) => fl!("status-disconnected"),
        Some(State::Connecting) => fl!("status-connecting"),
        Some(State::WaitingForLogin) => fl!("status-waiting-for-login"),
        Some(State::Connected) => fl!("status-connected"),
        Some(State::Disconnecting) => fl!("status-disconnecting"),
        Some(State::CertUntrusted) => fl!("status-cert-untrusted"),
        Some(State::Failed) => fl!("status-failed"),
    }
}

fn failure_text(snapshot: &Snapshot) -> String {
    let reason = snapshot.failure_detail.clone();
    match snapshot.failure.as_str() {
        "not-configured" => fl!("error-not-configured"),
        "busy" => fl!("error-busy"),
        "auth-failed" => fl!("error-auth-failed"),
        "not-authorized" => fl!("error-not-authorized", reason = reason),
        "stopped" => fl!("error-stopped"),
        _ => fl!("error-other", reason = reason),
    }
}
