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
    applet::{menu_button, padded_control},
    iced::{
        Alignment, Length, Subscription,
        platform_specific::shell::wayland::commands::popup::destroy_popup,
        widget::{column, row, space::horizontal as horizontal_space},
        window::Id,
    },
    surface, theme,
    widget::{button, divider, icon, text, text_input, toggler},
};
use cosmic_applet_fortivpn::gateway::Gateway;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    /// The settings section of the popover is expanded.
    settings_open: bool,
    /// The gateway is being changed in the settings.
    editing_gateway: bool,
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
    ToggleSettings,
    EditGateway,
    CancelEditGateway,
    ForgetCert,
    SetAutoReconnect(bool),
    /// Redraw, for the uptime.
    Tick,
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
            settings_open: false,
            editing_gateway: false,
        };
        (applet, Task::none())
    }

    fn on_close_requested(&self, id: Id) -> Option<Message> {
        Some(Message::PopupClosed(id))
    }

    fn subscription(&self) -> Subscription<Self::Message> {
        // The uptime moves every second, also when no traffic changes the state.
        let connected = self.snapshot.as_ref().map(|s| s.state) == Some(State::Connected);
        let ticks = if self.popup.is_some() && connected {
            cosmic::iced::time::every(Duration::from_secs(1)).map(|_| Message::Tick)
        } else {
            Subscription::none()
        };
        Subscription::batch([client::subscription().map(Message::Client), ticks])
    }

    fn update(&mut self, message: Self::Message) -> Task<cosmic::Action<Self::Message>> {
        match message {
            Message::TogglePopup => return self.toggle_popup(),
            Message::PopupClosed(id) => {
                if self.popup == Some(id) {
                    self.popup = None;
                    self.settings_open = false;
                    self.editing_gateway = false;
                }
            }
            Message::Client(ClientUpdate::Ready(agent)) => self.agent = Some(agent),
            Message::Client(ClientUpdate::Snapshot(snapshot)) => {
                if snapshot.as_ref().map(|s| s.state) != self.snapshot.as_ref().map(|s| s.state) {
                    tracing::info!(state = ?snapshot.as_ref().map(|s| s.state), "agent state");
                }
                self.snapshot = snapshot.map(|snapshot| *snapshot);
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
                self.editing_gateway = false;
                return self.call(move |agent| async move { agent.set_gateway(&address).await });
            }
            Message::ToggleSettings => {
                self.settings_open = !self.settings_open;
                self.editing_gateway = false;
            }
            Message::EditGateway => {
                self.editing_gateway = true;
                self.gateway_invalid = false;
                self.gateway_input = self
                    .snapshot
                    .as_ref()
                    .map(|s| s.gateway.clone())
                    .unwrap_or_default();
            }
            Message::CancelEditGateway => self.editing_gateway = false,
            Message::ForgetCert => {
                return self.call(|agent| async move { agent.forget_cert().await });
            }
            Message::SetAutoReconnect(enabled) => {
                return self
                    .call(move |agent| async move { agent.set_auto_reconnect(enabled).await });
            }
            Message::Tick => {}
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
        if let Some(settings) = self.settings() {
            content = content
                .push(padded_control(divider::horizontal::default()))
                .push(settings);
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

    /// Icon, "OpenFortiVPN", the state, and the gateway.
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
            return Some(self.gateway_form(snapshot, fl!("gateway-missing"), false));
        }
        match snapshot.state {
            State::Connected => Some(self.tunnel_details(snapshot)),
            State::Failed => Some(text::body(failure_text(snapshot)).into()),
            State::CertUntrusted => Some(text::body(fl!("cert-untrusted-hint")).into()),
            _ => None,
        }
    }

    /// Address, uptime and traffic of the tunnel.
    fn tunnel_details(&self, snapshot: &Snapshot) -> Element<'_, Message> {
        let spacing = theme::active().cosmic().spacing;
        let separator = fl!("decimal-separator");
        let uptime = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |now| now.as_secs())
            .saturating_sub(snapshot.connected_since);
        let traffic = snapshot.traffic;
        let amount = |total: u64, rate: u64| {
            format!(
                "{}  ({}/s)",
                format_bytes(total, &separator),
                format_bytes(rate, &separator)
            )
        };
        let mut rows = column![].spacing(spacing.space_xxxs);
        if !snapshot.address.is_empty() {
            rows = rows.push(detail_row(fl!("address"), snapshot.address.clone()));
        }
        rows.push(detail_row(fl!("uptime"), format_duration(uptime)))
            .push(detail_row(
                fl!("received"),
                amount(traffic.received, traffic.receive_rate),
            ))
            .push(detail_row(
                fl!("sent"),
                amount(traffic.sent, traffic.send_rate),
            ))
            .into()
    }

    /// Expandable settings: the gateway and the trusted certificate. Changes need an admin
    /// password and are only offered while no connection runs.
    fn settings(&self) -> Option<Element<'_, Message>> {
        let snapshot = self.snapshot.as_ref()?;
        if snapshot.gateway.is_empty() {
            return None;
        }
        let spacing = theme::active().cosmic().spacing;
        let toggle = menu_button(
            row![
                text::body(fl!("settings")),
                horizontal_space(),
                icon::from_name(if self.settings_open {
                    "go-up-symbolic"
                } else {
                    "go-down-symbolic"
                })
                .size(16)
            ]
            .align_y(Alignment::Center),
        )
        .on_press(Message::ToggleSettings);
        if !self.settings_open {
            return Some(toggle.into());
        }

        let idle =
            matches!(snapshot.state, State::Disconnected | State::Failed) && !snapshot.configuring;
        let gateway: Element<'_, Message> = if self.editing_gateway {
            self.gateway_form(snapshot, fl!("gateway-change"), true)
        } else {
            let mut change = button::text(fl!("change"));
            if idle {
                change = change.on_press(Message::EditGateway);
            }
            setting_row(fl!("gateway"), snapshot.gateway.clone(), change.into())
        };
        let cert: Element<'_, Message> = if snapshot.trusted_cert.is_empty() {
            setting_row(
                fl!("certificate"),
                fl!("certificate-system"),
                horizontal_space().into(),
            )
        } else {
            let mut forget = button::text(fl!("forget"));
            if idle {
                forget = forget.on_press(Message::ForgetCert);
            }
            setting_row(
                fl!("certificate-trusted"),
                format_fingerprint(&snapshot.trusted_cert),
                forget.into(),
            )
        };
        let reconnect = toggler(snapshot.auto_reconnect)
            .label(fl!("auto-reconnect"))
            .on_toggle(Message::SetAutoReconnect)
            .width(Length::Fill);
        let mut section = column![gateway, cert, reconnect].spacing(spacing.space_xs);
        if !self.editing_gateway && !snapshot.configure_error.is_empty() {
            section = section.push(text::caption(snapshot.configure_error.clone()));
        }
        Some(column![toggle, padded_control(section)].into())
    }

    /// The gateway address form: on first run, or to change it from the settings.
    fn gateway_form(
        &self,
        snapshot: &Snapshot,
        intro: String,
        cancellable: bool,
    ) -> Element<'_, Message> {
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
        let mut form = column![text::body(intro), input].spacing(spacing.space_xs);
        if self.gateway_invalid {
            form = form.push(text::caption(fl!("gateway-invalid")));
        } else if !snapshot.configure_error.is_empty() {
            form = form.push(text::caption(snapshot.configure_error.clone()));
        }
        let mut buttons = row![horizontal_space()].spacing(spacing.space_xs);
        if cancellable {
            buttons =
                buttons.push(button::standard(fl!("cancel")).on_press(Message::CancelEditGateway));
        }
        form.push(buttons.push(save)).into()
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
            | State::CertUntrusted
            | State::Reconnecting => button::standard(fl!("disconnect"))
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
        Some(
            State::Connecting | State::WaitingForLogin | State::Disconnecting | State::Reconnecting,
        ) => "network-vpn-acquiring-symbolic",
        Some(State::Connected) => "network-vpn-symbolic",
        Some(State::CertUntrusted | State::Failed) | None => "network-vpn-error-symbolic",
    }
}

fn status_text(snapshot: Option<&Snapshot>) -> String {
    match snapshot.map(|s| s.state) {
        None => fl!("status-unavailable"),
        Some(State::Disconnected) => fl!("status-disconnected"),
        // The login window or the browser dialog shows when the login needs the user;
        // otherwise it runs unseen, so the applet only says it is connecting.
        Some(State::Connecting | State::WaitingForLogin) => fl!("status-connecting"),
        Some(State::Connected) => fl!("status-connected"),
        Some(State::Disconnecting) => fl!("status-disconnecting"),
        Some(State::Reconnecting) => fl!("status-reconnecting"),
        Some(State::CertUntrusted) => fl!("status-cert-untrusted"),
        // A tunnel that went down is interrupted, not a failed attempt.
        Some(State::Failed) => match snapshot.map(|s| s.failure.as_str()) {
            Some("lost" | "stopped") => fl!("status-interrupted"),
            _ => fl!("status-failed"),
        },
    }
}

/// The failure in `snapshot`, translated. Also the agent's notification text.
pub(crate) fn failure_text(snapshot: &Snapshot) -> String {
    let reason = snapshot.failure_detail.clone();
    match snapshot.failure.as_str() {
        "not-configured" => fl!("error-not-configured"),
        "busy" => fl!("error-busy"),
        "auth-failed" => fl!("error-auth-failed"),
        "not-authorized" => fl!("error-not-authorized", reason = reason),
        "stopped" => fl!("error-stopped"),
        "lost" => fl!("error-lost"),
        _ => fl!("error-other", reason = reason),
    }
}

/// A label and its value on one line.
fn detail_row<'a>(label: String, value: String) -> Element<'a, Message> {
    row![text::body(label), horizontal_space(), text::body(value)]
        .align_y(Alignment::Center)
        .into()
}

/// A setting: label and value stacked, with its button on the right.
fn setting_row<'a>(
    label: String,
    value: String,
    action: Element<'a, Message>,
) -> Element<'a, Message> {
    row![
        column![text::caption(label), text::body(value)].width(Length::Fill),
        action
    ]
    .align_y(Alignment::Center)
    .into()
}

/// Bytes with an SI unit: one decimal below 100 of a unit, none above.
fn format_bytes(bytes: u64, decimal_separator: &str) -> String {
    const UNITS: [&str; 5] = ["kB", "MB", "GB", "TB", "PB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1000.0;
    let mut unit = UNITS[0];
    for next in &UNITS[1..] {
        if value < 1000.0 {
            break;
        }
        value /= 1000.0;
        unit = next;
    }
    let number = if value < 100.0 {
        format!("{value:.1}").replace('.', decimal_separator)
    } else {
        format!("{value:.0}")
    };
    format!("{number} {unit}")
}

/// `H:MM:SS`; hours keep counting past a day.
fn format_duration(secs: u64) -> String {
    format!("{}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

/// The SHA-256 digest in groups of four, so it can be compared with what IT gives out.
fn format_fingerprint(hex: &str) -> String {
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes() {
        assert_eq!(format_bytes(0, "."), "0 B");
        assert_eq!(format_bytes(999, "."), "999 B");
        assert_eq!(format_bytes(1000, "."), "1.0 kB");
        assert_eq!(format_bytes(12_345, ","), "12,3 kB");
        assert_eq!(format_bytes(123_456, "."), "123 kB");
        assert_eq!(format_bytes(999_999, "."), "1000 kB");
        assert_eq!(format_bytes(1_500_000, "."), "1.5 MB");
        assert_eq!(format_bytes(2_000_000_000, "."), "2.0 GB");
        assert_eq!(format_bytes(u64::MAX, "."), "18447 PB");
    }

    #[test]
    fn durations() {
        assert_eq!(format_duration(0), "0:00:00");
        assert_eq!(format_duration(61), "0:01:01");
        assert_eq!(format_duration(3_723), "1:02:03");
        assert_eq!(format_duration(90_000), "25:00:00");
    }

    #[test]
    fn fingerprints() {
        assert_eq!(format_fingerprint("f2c93596"), "f2c9 3596");
        assert_eq!(format_fingerprint("abcdef"), "abcd ef");
        assert_eq!(format_fingerprint(""), "");
    }
}
