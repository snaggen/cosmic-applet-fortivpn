// SPDX-License-Identifier: GPL-3.0-only

//! Desktop notifications through `org.freedesktop.Notifications`.

use std::collections::HashMap;
use zbus::zvariant::Value;

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;
}

/// A notification to show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    pub summary: String,
    pub body: String,
}

/// Shows `notification`. `desktop_entry` names the app (for its name and icon in the
/// notification centre).
pub async fn show(notification: Notification, desktop_entry: &str) -> Result<(), String> {
    let send = async {
        let connection = zbus::Connection::session().await?;
        let proxy = NotificationsProxy::new(&connection).await?;
        let hints = HashMap::from([
            ("desktop-entry", Value::from(desktop_entry)),
            // Normal urgency: it reports a change, nothing needs an answer.
            ("urgency", Value::from(1u8)),
        ]);
        proxy
            .notify(
                "OpenFortiVPN",
                0,
                "network-vpn-error-symbolic",
                &notification.summary,
                &notification.body,
                &[],
                hints,
                // The server's default timeout.
                -1,
            )
            .await
    };
    send.await.map(|_| ()).map_err(|err| err.to_string())
}
