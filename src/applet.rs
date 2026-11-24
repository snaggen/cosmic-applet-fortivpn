// SPDX-License-Identifier: GPL-3.0-only

//! The panel applet: panel icon and popover.

use crate::fl;
use cosmic::{
    Element, Task,
    app::Core,
    applet::padded_control,
    iced::{
        Alignment,
        platform_specific::shell::wayland::commands::popup::destroy_popup,
        widget::{column, row},
        window::Id,
    },
    surface, theme,
    widget::{icon, text},
};

const APP_ID: &str = "io.github.snaggen.CosmicAppletFortivpn";

/// Panel icon while no tunnel is up.
const ICON_DISCONNECTED: &str = "network-vpn-disconnected-symbolic";

pub struct Applet {
    core: Core,
    /// The open popover, if any.
    popup: Option<Id>,
}

#[derive(Clone, Debug)]
pub enum Message {
    TogglePopup,
    PopupClosed(Id),
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
        (Self { core, popup: None }, Task::none())
    }

    fn on_close_requested(&self, id: Id) -> Option<Message> {
        Some(Message::PopupClosed(id))
    }

    fn update(&mut self, message: Self::Message) -> Task<cosmic::Action<Self::Message>> {
        match message {
            Message::TogglePopup => return self.toggle_popup(),
            Message::PopupClosed(id) => {
                if self.popup == Some(id) {
                    self.popup = None;
                }
            }
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Self::Message> {
        self.core
            .applet
            .icon_button(ICON_DISCONNECTED)
            .on_press_down(Message::TogglePopup)
            .into()
    }

    fn view_window(&self, _id: Id) -> Element<'_, Self::Message> {
        let spacing = theme::active().cosmic().spacing;

        let headline = row![
            icon::from_name(ICON_DISCONNECTED).size(24),
            column![
                text::heading(fl!("vpn")),
                text::caption(fl!("status-disconnected")),
            ],
        ]
        .spacing(spacing.space_xs)
        .align_y(Alignment::Center);

        let content = column![padded_control(headline)].padding([spacing.space_xxs, 0]);

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
}
