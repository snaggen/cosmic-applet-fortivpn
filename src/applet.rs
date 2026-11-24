// SPDX-License-Identifier: GPL-3.0-only

//! The panel applet: panel icon and popover.
//!
//! The panel runs one applet per output, so the applet only shows the agent's state and
//! forwards the user's clicks to it ([`crate::client`]). The agent owns the tunnel.
//!
//! The popover lists the VPN accounts (profiles), each with its own connect button; one
//! tunnel runs at a time, so connecting one disconnects another. Below it, expandable
//! settings add, change and remove accounts.

use crate::{
    bus::{AgentProxy, ProfileInfo, Snapshot, State},
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
use cosmic_applet_fortivpn::{
    gateway::Gateway,
    profile::{self, LoginMethod, ProfileId},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const APP_ID: &str = "io.github.snaggen.CosmicAppletFortivpn";

pub struct Applet {
    core: Core,
    /// The open popover, if any.
    popup: Option<Id>,
    agent: Option<AgentProxy<'static>>,
    /// The agent's state; `None` until read, or while the agent cannot be reached.
    snapshot: Option<Snapshot>,
    /// The settings section of the popover is expanded.
    settings_open: bool,
    /// A profile being added or changed.
    editing: Option<ProfileForm>,
}

/// The form for adding or changing a profile.
#[derive(Clone, Debug, Default)]
struct ProfileForm {
    /// `None` for a new profile; its id is made from the name.
    id: Option<String>,
    name: String,
    address: String,
    password_login: bool,
    /// Why the form cannot be saved.
    error: Option<String>,
}

/// The form before anything was typed.
static EMPTY_FORM: ProfileForm = ProfileForm {
    id: None,
    name: String::new(),
    address: String::new(),
    password_login: false,
    error: None,
};

#[derive(Clone, Debug)]
pub enum Message {
    TogglePopup,
    PopupClosed(Id),
    Client(ClientUpdate),
    Connect(String),
    Disconnect,
    ToggleSettings,
    /// Open the form: for a profile, or `None` for a new one.
    EditProfile(Option<String>),
    EditName(String),
    EditAddress(String),
    EditPasswordLogin(bool),
    SaveProfile,
    CancelEdit,
    RemoveProfile(String),
    ForgetCert(String),
    SetAutoReconnect(bool),
    /// A call to the agent finished.
    Called(Result<(), String>),
    /// Redraw, for the uptime.
    Tick,
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
            settings_open: false,
            editing: None,
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
                    self.editing = None;
                }
            }
            Message::Client(ClientUpdate::Ready(agent)) => self.agent = Some(agent),
            Message::Client(ClientUpdate::Snapshot(snapshot)) => {
                if snapshot.as_ref().map(|s| s.state) != self.snapshot.as_ref().map(|s| s.state) {
                    tracing::info!(state = ?snapshot.as_ref().map(|s| s.state), "agent state");
                }
                self.snapshot = snapshot.map(|snapshot| *snapshot);
            }
            Message::Connect(id) => {
                return self.call(move |agent| async move { agent.connect(&id).await });
            }
            Message::Disconnect => {
                return self.call(|agent| async move { agent.disconnect().await });
            }
            Message::ToggleSettings => {
                self.settings_open = !self.settings_open;
                self.editing = None;
            }
            Message::EditProfile(id) => self.editing = Some(self.form_for(id)),
            Message::EditName(name) => self.edit(|form| form.name = name),
            Message::EditAddress(address) => self.edit(|form| form.address = address),
            Message::EditPasswordLogin(on) => self.edit(|form| form.password_login = on),
            Message::CancelEdit => self.editing = None,
            Message::SaveProfile => return self.save_profile(),
            Message::RemoveProfile(id) => {
                return self.call(move |agent| async move { agent.remove_profile(&id).await });
            }
            Message::ForgetCert(id) => {
                return self.call(move |agent| async move { agent.forget_cert(&id).await });
            }
            Message::SetAutoReconnect(enabled) => {
                return self
                    .call(move |agent| async move { agent.set_auto_reconnect(enabled).await });
            }
            Message::Called(Err(err)) => tracing::warn!(%err, "call to the agent failed"),
            Message::Called(Ok(())) => {}
            Message::Tick => {}
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
        let divider = || padded_control(divider::horizontal::default());
        let mut content = column![padded_control(self.headline())];
        match &self.snapshot {
            None => {
                content = content
                    .push(divider())
                    .push(padded_control(text::body(fl!("agent-unavailable"))));
            }
            Some(snapshot) if snapshot.profiles.is_empty() => {
                // First run: nothing to list yet, so the form is the popover.
                let form = self.editing.as_ref().unwrap_or(&EMPTY_FORM);
                content = content
                    .push(divider())
                    .push(padded_control(self.profile_form(snapshot, form, true)));
            }
            Some(snapshot) => {
                content = content.push(divider()).push(self.profile_list(snapshot));
                if let Some(body) = self.body(snapshot) {
                    content = content.push(divider()).push(padded_control(body));
                }
                content = content.push(divider()).push(self.settings(snapshot));
            }
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

    fn edit(&mut self, change: impl FnOnce(&mut ProfileForm)) {
        let form = self.editing.get_or_insert_with(ProfileForm::default);
        change(form);
        form.error = None;
    }

    /// The form filled in from a profile, or empty for a new one.
    fn form_for(&self, id: Option<String>) -> ProfileForm {
        let profile = id.as_ref().and_then(|id| {
            self.snapshot
                .as_ref()?
                .profiles
                .iter()
                .find(|p| &p.id == id)
        });
        match profile {
            Some(p) => ProfileForm {
                id: Some(p.id.clone()),
                name: p.name.clone(),
                address: p.address.clone(),
                password_login: p.method == LoginMethod::Password.as_str(),
                error: None,
            },
            None => ProfileForm::default(),
        }
    }

    /// Checks the form and asks the agent to save it (admin password).
    fn save_profile(&mut self) -> Task<cosmic::Action<Message>> {
        let Some(form) = self.editing.as_mut() else {
            return Task::none();
        };
        let name = form.name.trim().to_owned();
        let address = form.address.trim().to_owned();
        if profile::validate_name(&name).is_err() {
            form.error = Some(fl!("profile-name-invalid"));
            return Task::none();
        }
        if address.parse::<Gateway>().is_err() {
            form.error = Some(fl!("gateway-invalid"));
            return Task::none();
        }
        let existing: Vec<String> = self
            .snapshot
            .as_ref()
            .map(|s| s.profiles.iter().map(|p| p.id.clone()).collect())
            .unwrap_or_default();
        let id = match &form.id {
            Some(id) => id.clone(),
            None => match new_profile_id(&name, &existing) {
                Some(id) => id,
                None => {
                    form.error = Some(fl!("profile-name-invalid"));
                    return Task::none();
                }
            },
        };
        let method = if form.password_login {
            LoginMethod::Password
        } else {
            LoginMethod::Saml
        };
        self.editing = None;
        self.call(move |agent| async move {
            agent
                .save_profile(&id, &name, method.as_str(), &address)
                .await
        })
    }

    /// Icon, "OpenFortiVPN", and the state of the active profile.
    fn headline(&self) -> Element<'_, Message> {
        let spacing = theme::active().cosmic().spacing;
        let mut details = column![
            text::heading(fl!("vpn")),
            text::caption(status_text(self.snapshot.as_ref()))
        ];
        if let Some(profile) = self.snapshot.as_ref().and_then(Snapshot::active_profile)
            && self.snapshot.as_ref().map(|s| s.state) != Some(State::Disconnected)
        {
            details = details.push(text::caption(profile.name.clone()));
        }
        row![
            icon::from_name(panel_icon(self.snapshot.as_ref())).size(24),
            details
        ]
        .spacing(spacing.space_xs)
        .align_y(Alignment::Center)
        .into()
    }

    /// The profiles, each with its connect or disconnect button.
    fn profile_list<'a>(&'a self, snapshot: &'a Snapshot) -> Element<'a, Message> {
        let spacing = theme::active().cosmic().spacing;
        let mut list = column![].spacing(spacing.space_xs);
        for profile in &snapshot.profiles {
            let active = profile.id == snapshot.active;
            let busy = active
                && matches!(
                    snapshot.state,
                    State::Connecting
                        | State::WaitingForLogin
                        | State::Connected
                        | State::CertUntrusted
                        | State::Reconnecting
                );
            let action: Element<'_, Message> = if busy {
                button::standard(fl!("disconnect"))
                    .on_press(Message::Disconnect)
                    .into()
            } else if active && snapshot.state == State::Disconnecting {
                button::standard(fl!("disconnect")).into()
            } else {
                button::suggested(fl!("connect"))
                    .on_press(Message::Connect(profile.id.clone()))
                    .into()
            };
            list = list.push(
                row![
                    column![
                        text::body(profile.name.clone()),
                        text::caption(profile.address.clone())
                    ]
                    .width(Length::Fill),
                    action
                ]
                .align_y(Alignment::Center),
            );
        }
        padded_control(list).into()
    }

    /// What the active profile's state needs explained: the tunnel's details, or a problem.
    fn body<'a>(&'a self, snapshot: &'a Snapshot) -> Option<Element<'a, Message>> {
        if !snapshot.profiles_error.is_empty() {
            let reason = snapshot.profiles_error.clone();
            return Some(text::body(fl!("gateway-unreadable", reason = reason)).into());
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

    /// Expandable settings: the profiles with their certificates, adding one, and
    /// reconnecting. Changes to profiles need an admin password; a profile in use cannot be
    /// changed or removed.
    fn settings<'a>(&'a self, snapshot: &'a Snapshot) -> Element<'a, Message> {
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
            return toggle.into();
        }

        let mut section = column![].spacing(spacing.space_s);
        if let Some(form) = &self.editing {
            section = section.push(self.profile_form(snapshot, form, false));
        } else {
            for profile in &snapshot.profiles {
                section = section.push(self.profile_settings(snapshot, profile));
            }
            let mut add = button::text(fl!("add-profile"));
            if !snapshot.configuring {
                add = add.on_press(Message::EditProfile(None));
            }
            section = section.push(add);
            if !snapshot.configure_error.is_empty() {
                section = section.push(text::caption(snapshot.configure_error.clone()));
            }
        }
        let reconnect = toggler(snapshot.auto_reconnect)
            .label(fl!("auto-reconnect"))
            .on_toggle(Message::SetAutoReconnect)
            .width(Length::Fill);
        section = section.push(reconnect);
        column![toggle, padded_control(section)].into()
    }

    /// One profile in the settings: change, remove, and its trusted certificate.
    fn profile_settings(&self, snapshot: &Snapshot, profile: &ProfileInfo) -> Element<'_, Message> {
        let spacing = theme::active().cosmic().spacing;
        let in_use = profile.id == snapshot.active
            && !matches!(snapshot.state, State::Disconnected | State::Failed);
        let idle = !in_use && !snapshot.configuring;
        let mut change = button::text(fl!("change"));
        let mut remove = button::text(fl!("remove"));
        if idle {
            change = change.on_press(Message::EditProfile(Some(profile.id.clone())));
            remove = remove.on_press(Message::RemoveProfile(profile.id.clone()));
        }
        let method = if profile.method == LoginMethod::Password.as_str() {
            fl!("method-password")
        } else {
            fl!("method-saml")
        };
        let mut block = column![
            row![
                column![
                    text::body(profile.name.clone()),
                    text::caption(format!("{} · {method}", profile.address))
                ]
                .width(Length::Fill),
                change,
                remove
            ]
            .align_y(Alignment::Center)
        ]
        .spacing(spacing.space_xxs);
        if !profile.trusted_cert.is_empty() {
            let mut forget = button::text(fl!("forget"));
            if idle {
                forget = forget.on_press(Message::ForgetCert(profile.id.clone()));
            }
            block = block.push(setting_row(
                fl!("certificate-trusted"),
                format_fingerprint(&profile.trusted_cert),
                forget.into(),
            ));
        }
        block.into()
    }

    /// The form for a profile: on first run, or to add or change one from the settings.
    fn profile_form<'a>(
        &'a self,
        snapshot: &'a Snapshot,
        form: &'a ProfileForm,
        first_run: bool,
    ) -> Element<'a, Message> {
        let spacing = theme::active().cosmic().spacing;
        let intro = if first_run {
            fl!("gateway-missing")
        } else if form.id.is_some() {
            fl!("gateway-change")
        } else {
            fl!("profile-add-intro")
        };
        let mut name = text_input(fl!("profile-name-placeholder"), &form.name)
            .label(fl!("profile-name"))
            .width(Length::Fill);
        let mut address = text_input(fl!("gateway-placeholder"), &form.address)
            .label(fl!("gateway"))
            .width(Length::Fill);
        let mut password = toggler(form.password_login)
            .label(fl!("password-login"))
            .width(Length::Fill);
        let mut save = button::suggested(fl!("save"));
        if !snapshot.configuring {
            name = name
                .on_input(Message::EditName)
                .on_submit(|_| Message::SaveProfile);
            address = address
                .on_input(Message::EditAddress)
                .on_submit(|_| Message::SaveProfile);
            password = password.on_toggle(Message::EditPasswordLogin);
            save = save.on_press(Message::SaveProfile);
        }
        let mut column =
            column![text::body(intro), name, address, password].spacing(spacing.space_xs);
        if let Some(err) = &form.error {
            column = column.push(text::caption(err.clone()));
        } else if !snapshot.configure_error.is_empty() {
            column = column.push(text::caption(snapshot.configure_error.clone()));
        }
        let mut buttons = row![horizontal_space()].spacing(spacing.space_xs);
        if !first_run {
            buttons = buttons.push(button::standard(fl!("cancel")).on_press(Message::CancelEdit));
        }
        column.push(buttons.push(save)).into()
    }
}

/// An id for a new profile from its name, not taken by another profile.
fn new_profile_id(name: &str, existing: &[String]) -> Option<String> {
    let base = ProfileId::from_name(name)?.to_string();
    if !existing.contains(&base) {
        return Some(base);
    }
    (2..100)
        .map(|n| {
            // Room for the suffix within the 32-character limit.
            let stem: String = base.chars().take(28).collect();
            format!("{}-{n}", stem.trim_end_matches('-'))
        })
        .find(|id| !existing.contains(id) && id.parse::<ProfileId>().is_ok())
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
        "unreachable" => fl!("error-unreachable", reason = reason),
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
    fn new_profile_ids_are_unique() {
        assert_eq!(new_profile_id("ACE Media", &[]), Some("ace-media".into()));
        assert_eq!(
            new_profile_id("ACE", &["ace".into(), "ace-2".into()]),
            Some("ace-3".into())
        );
        let long = "x".repeat(40);
        let taken = vec!["x".repeat(32)];
        let id = new_profile_id(&long, &taken).unwrap();
        assert!(id.len() <= 32 && id.ends_with("-2"), "{id}");
        assert_eq!(new_profile_id("???", &[]), None);
    }

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
