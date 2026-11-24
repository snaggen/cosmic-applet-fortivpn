// SPDX-License-Identifier: GPL-3.0-only

//! The connection state machine, kept free of UI code so it can be tested.

use crate::{
    login::LoginResult,
    tunnel::{Ended, TunnelCommand},
};
use cosmic_applet_fortivpn::{
    protocol::{Event, HelperError, UntrustedCert},
    saml::SamlId,
};
use std::time::Instant;

/// pkexec's exit code when the user dismissed the authentication dialog.
const PKEXEC_DISMISSED: i32 = 126;
/// pkexec's exit code when not authorized, or the program could not be run.
const PKEXEC_NOT_AUTHORIZED: i32 = 127;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Disconnected,
    /// The agent checks the gateway certificate before anything else, so an untrusted
    /// certificate is asked about before the user logs in, not after.
    Checking,
    /// The login window is open. openfortivpn is not started yet: it waits only 50 seconds
    /// for the login.
    LoggingIn,
    /// The helper is starting openfortivpn, which then gets this id from the login.
    Starting(SamlId),
    /// The helper is starting openfortivpn, or openfortivpn has the login and sets up the
    /// tunnel.
    Connecting,
    /// openfortivpn waits for the SAML login: the id is being handed over, or the login runs
    /// in the system browser.
    WaitingForLogin,
    Connected {
        since: Instant,
    },
    Disconnecting,
    /// The gateway certificate needs the user's decision.
    CertUntrusted(UntrustedCert),
    Failed(Failure),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    NotConfigured,
    Busy,
    AuthFailed,
    NotAuthorized(String),
    /// The tunnel or the helper stopped without being asked to.
    Stopped,
    /// The tunnel stopped carrying traffic (the network under it went away).
    Lost,
    /// The gateway could not be reached before connecting.
    Unreachable(String),
    Other(String),
}

/// What the applet must do after a transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    None,
    Send(TunnelCommand),
    /// Start the helper for the active profile; the agent builds the request (login,
    /// credentials, intermediate certificate).
    StartHelper,
    /// Log in (the login window, or credentials for a password profile), then report with
    /// [`Status::on_login`].
    Login,
    /// Hand openfortivpn the id from the login window (on its SAML listener).
    DeliverSamlId(SamlId),
    /// The login window failed: open the login page in the system browser.
    OpenLoginPage,
    /// Check the gateway certificate, then report with [`Status::on_cert_checked`].
    CheckCert,
}

impl Status {
    /// Whether a helper process is running.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Starting(_)
                | Self::Connecting
                | Self::WaitingForLogin
                | Self::Connected { .. }
                | Self::Disconnecting
        )
    }

    /// Starts a connection: first the certificate check.
    pub fn connect(&mut self) -> Effect {
        if self.is_active() || matches!(self, Self::Checking | Self::LoggingIn) {
            return Effect::None;
        }
        *self = Self::Checking;
        Effect::CheckCert
    }

    /// Logs in without a certificate check, after the user trusted the certificate. A
    /// certificate trusted once is only known to the helper, so a new check would ask again.
    pub fn connect_trusted(&mut self) -> Effect {
        if self.is_active() || *self == Self::LoggingIn {
            return Effect::None;
        }
        self.login()
    }

    /// The certificate check finished: `Ok(None)` if trusted, `Ok(Some(_))` with the
    /// certificate to ask about, `Err` if the gateway could not be reached. Connecting without
    /// a reachable gateway would only open the login window on an error page.
    pub fn on_cert_checked(&mut self, result: Result<Option<UntrustedCert>, String>) -> Effect {
        if *self != Self::Checking {
            return Effect::None;
        }
        match result {
            Ok(None) => self.login(),
            Ok(Some(cert)) => {
                *self = Self::CertUntrusted(cert);
                Effect::None
            }
            Err(why) => {
                *self = Self::Failed(Failure::Unreachable(why));
                Effect::None
            }
        }
    }

    fn login(&mut self) -> Effect {
        *self = Self::LoggingIn;
        Effect::Login
    }

    /// The login ended. With a SAML id, openfortivpn starts and gets it once listening; with
    /// credentials, openfortivpn logs in with them; if the window failed, openfortivpn starts
    /// and the login runs in the system browser.
    pub fn on_login(&mut self, result: LoginResult) -> Effect {
        if *self != Self::LoggingIn {
            return Effect::None;
        }
        *self = match result {
            LoginResult::Done(id) => Self::Starting(id),
            LoginResult::Password | LoginResult::Failed(_) => Self::Connecting,
            LoginResult::Cancelled => {
                *self = Self::Disconnected;
                return Effect::None;
            }
        };
        Effect::StartHelper
    }

    /// The agent found the connection broken: give up and stop the helper.
    pub fn fail(&mut self, failure: Failure) -> Effect {
        if !self.is_active() {
            return Effect::None;
        }
        *self = Self::Failed(failure);
        Effect::Send(TunnelCommand::Disconnect)
    }

    pub fn disconnect(&mut self) -> Effect {
        match self {
            Self::Starting(_)
            | Self::Connecting
            | Self::WaitingForLogin
            | Self::Connected { .. } => {
                *self = Self::Disconnecting;
                Effect::Send(TunnelCommand::Disconnect)
            }
            Self::Checking | Self::LoggingIn | Self::CertUntrusted(_) | Self::Failed(_) => {
                *self = Self::Disconnected;
                Effect::None
            }
            Self::Disconnected | Self::Disconnecting => Effect::None,
        }
    }

    /// Applies an event from the helper.
    pub fn on_event(&mut self, event: Event, now: Instant) -> Effect {
        match event {
            Event::SamlReady if self.is_active() => {
                let previous = std::mem::replace(self, Self::WaitingForLogin);
                return match previous {
                    Self::Starting(id) => Effect::DeliverSamlId(id),
                    _ => Effect::OpenLoginPage,
                };
            }
            // The login is done; the login dialog closes while the tunnel comes up.
            Event::SamlReceived if *self == Self::WaitingForLogin => *self = Self::Connecting,
            Event::Up if self.is_active() => *self = Self::Connected { since: now },
            Event::CertUntrusted(cert) => *self = Self::CertUntrusted(cert),
            Event::AuthFailed => *self = Self::Failed(Failure::AuthFailed),
            Event::Error(err) => *self = Self::Failed(failure_from(err)),
            Event::Exited(_) => self.on_exit(),
            Event::Log(line) => tracing::info!(%line, "openfortivpn"),
            Event::SamlReady | Event::SamlReceived | Event::Up => {}
        }
        Effect::None
    }

    /// openfortivpn ended. Expected only after a disconnect; an earlier failure stays shown.
    fn on_exit(&mut self) {
        match self {
            Self::Disconnecting => *self = Self::Disconnected,
            Self::Starting(_)
            | Self::Connecting
            | Self::WaitingForLogin
            | Self::Connected { .. } => {
                *self = Self::Failed(Failure::Stopped);
            }
            Self::Disconnected
            | Self::Checking
            | Self::LoggingIn
            | Self::CertUntrusted(_)
            | Self::Failed(_) => {}
        }
    }

    /// The pkexec process ended. Decides the state only if the helper reported no exit.
    pub fn on_ended(&mut self, ended: &Ended) {
        if !self.is_active() {
            return;
        }
        *self = match (&*self, ended.code) {
            (Self::Disconnecting, _) | (_, Some(PKEXEC_DISMISSED)) => Self::Disconnected,
            (_, Some(PKEXEC_NOT_AUTHORIZED)) => {
                Self::Failed(Failure::NotAuthorized(ended.stderr.trim().to_owned()))
            }
            _ if ended.stderr.trim().is_empty() => Self::Failed(Failure::Stopped),
            _ => Self::Failed(Failure::Other(ended.stderr.trim().to_owned())),
        };
    }
}

fn failure_from(err: HelperError) -> Failure {
    match err {
        HelperError::NotConfigured => Failure::NotConfigured,
        HelperError::Busy => Failure::Busy,
        HelperError::BadRequest => Failure::Other("the helper rejected the request".into()),
        HelperError::Failed(why) => Failure::Other(why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ended(code: i32, stderr: &str) -> Ended {
        Ended {
            code: Some(code),
            stderr: stderr.into(),
        }
    }

    fn cert() -> UntrustedCert {
        UntrustedCert {
            digest: "f2c935968edba48ab89c19f4291cf5449efc814665d179e32023f519dc89f1a1"
                .parse()
                .unwrap(),
            subject: "CN=vpn.example.com".into(),
            issuer: "CN=Some CA".into(),
        }
    }

    fn id() -> SamlId {
        SamlId::parse("abc123").unwrap()
    }

    #[test]
    fn saml_connect_and_disconnect() {
        let now = Instant::now();
        let mut status = Status::Disconnected;
        assert_eq!(status.connect(), Effect::CheckCert);
        assert_eq!(status, Status::Checking);
        assert_eq!(status.on_cert_checked(Ok(None)), Effect::Login);
        assert_eq!(status, Status::LoggingIn);
        assert!(!status.is_active());
        assert_eq!(
            status.on_login(LoginResult::Done(id())),
            Effect::StartHelper
        );
        assert_eq!(status, Status::Starting(id()));
        assert_eq!(
            status.on_event(Event::SamlReady, now),
            Effect::DeliverSamlId(id())
        );
        assert_eq!(status, Status::WaitingForLogin);
        status.on_event(Event::SamlReceived, now);
        assert_eq!(status, Status::Connecting);
        status.on_event(Event::Up, now);
        assert_eq!(status, Status::Connected { since: now });
        assert_eq!(status.disconnect(), Effect::Send(TunnelCommand::Disconnect));
        assert_eq!(status, Status::Disconnecting);
        status.on_event(Event::Exited(Some(0)), now);
        assert_eq!(status, Status::Disconnected);
        status.on_ended(&ended(0, ""));
        assert_eq!(status, Status::Disconnected);
    }

    #[test]
    fn failed_login_window_falls_back_to_the_browser() {
        let now = Instant::now();
        let mut status = Status::LoggingIn;
        assert_eq!(
            status.on_login(LoginResult::Failed("no window".into())),
            Effect::StartHelper
        );
        assert_eq!(status, Status::Connecting);
        assert_eq!(
            status.on_event(Event::SamlReady, now),
            Effect::OpenLoginPage
        );
        assert_eq!(status, Status::WaitingForLogin);
    }

    #[test]
    fn password_login_starts_the_helper() {
        let mut status = Status::LoggingIn;
        assert_eq!(status.on_login(LoginResult::Password), Effect::StartHelper);
        assert_eq!(status, Status::Connecting);
    }

    #[test]
    fn cancelled_login_starts_nothing() {
        let mut status = Status::LoggingIn;
        assert_eq!(status.on_login(LoginResult::Cancelled), Effect::None);
        assert_eq!(status, Status::Disconnected);
    }

    #[test]
    fn late_login_result_is_ignored() {
        let mut status = Status::LoggingIn;
        assert_eq!(status.disconnect(), Effect::None);
        assert_eq!(status, Status::Disconnected);
        assert_eq!(status.on_login(LoginResult::Done(id())), Effect::None);
        assert_eq!(status, Status::Disconnected);
    }

    #[test]
    fn failed_handover_stops_the_helper() {
        let mut status = Status::WaitingForLogin;
        assert_eq!(
            status.fail(Failure::Other("refused".into())),
            Effect::Send(TunnelCommand::Disconnect)
        );
        assert_eq!(status, Status::Failed(Failure::Other("refused".into())));
        // The helper's exit keeps the failure shown.
        status.on_event(Event::Exited(Some(1)), Instant::now());
        assert_eq!(status, Status::Failed(Failure::Other("refused".into())));
        assert_eq!(Status::Disconnected.fail(Failure::Lost), Effect::None);
    }

    #[test]
    fn saml_received_only_ends_the_wait_for_login() {
        let now = Instant::now();
        let mut status = Status::Disconnected;
        status.on_event(Event::SamlReceived, now);
        assert_eq!(status, Status::Disconnected);
        let mut status = Status::Connected { since: now };
        status.on_event(Event::SamlReceived, now);
        assert_eq!(status, Status::Connected { since: now });
    }

    #[test]
    fn untrusted_cert_is_asked_before_the_login() {
        let mut status = Status::Disconnected;
        status.connect();
        assert_eq!(status.on_cert_checked(Ok(Some(cert()))), Effect::None);
        assert_eq!(status, Status::CertUntrusted(cert()));
        // After the user trusts it, the login starts without another check.
        assert_eq!(status.connect_trusted(), Effect::Login);
        assert_eq!(status, Status::LoggingIn);
        assert_eq!(status.connect(), Effect::None);
    }

    #[test]
    fn unreachable_gateway_fails_before_the_login() {
        let mut status = Status::Disconnected;
        status.connect();
        assert_eq!(
            status.on_cert_checked(Err("timed out".into())),
            Effect::None
        );
        assert_eq!(
            status,
            Status::Failed(Failure::Unreachable("timed out".into()))
        );
    }

    #[test]
    fn cancel_during_the_check_ignores_its_result() {
        let mut status = Status::Disconnected;
        status.connect();
        assert_eq!(status.disconnect(), Effect::None);
        assert_eq!(status, Status::Disconnected);
        assert_eq!(status.on_cert_checked(Ok(None)), Effect::None);
        assert_eq!(status, Status::Disconnected);
    }

    #[test]
    fn connect_is_ignored_while_active() {
        let mut status = Status::Connecting;
        assert_eq!(status.connect(), Effect::None);
    }

    #[test]
    fn dropped_tunnel_is_a_failure() {
        let now = Instant::now();
        let mut status = Status::Connected { since: now };
        status.on_event(Event::Exited(Some(1)), now);
        assert_eq!(status, Status::Failed(Failure::Stopped));
        status.on_ended(&ended(0, ""));
        assert_eq!(status, Status::Failed(Failure::Stopped));
    }

    #[test]
    fn untrusted_cert_survives_the_exit_that_follows() {
        let now = Instant::now();
        let mut status = Status::WaitingForLogin;
        status.on_event(Event::CertUntrusted(cert()), now);
        status.on_event(Event::CertUntrusted(cert()), now);
        status.on_event(Event::Exited(None), now);
        status.on_ended(&ended(0, ""));
        assert_eq!(status, Status::CertUntrusted(cert()));
        assert_eq!(status.disconnect(), Effect::None);
        assert_eq!(status, Status::Disconnected);
    }

    #[test]
    fn helper_errors() {
        let now = Instant::now();
        let mut status = Status::Connecting;
        status.on_event(Event::Error(HelperError::Busy), now);
        assert_eq!(status, Status::Failed(Failure::Busy));

        let mut status = Status::Connecting;
        status.on_event(Event::AuthFailed, now);
        assert_eq!(status, Status::Failed(Failure::AuthFailed));
    }

    #[test]
    fn pkexec_refusals() {
        let mut status = Status::Connecting;
        status.on_ended(&ended(126, ""));
        assert_eq!(status, Status::Disconnected);

        let mut status = Status::Connecting;
        status.on_ended(&ended(
            127,
            "Error executing command as another user: Not authorized\n",
        ));
        assert_eq!(
            status,
            Status::Failed(Failure::NotAuthorized(
                "Error executing command as another user: Not authorized".into()
            ))
        );

        let mut status = Status::Connecting;
        status.on_ended(&ended(1, ""));
        assert_eq!(status, Status::Failed(Failure::Stopped));
    }

    #[test]
    fn late_events_do_not_revive_a_finished_attempt() {
        let now = Instant::now();
        let mut status = Status::Disconnected;
        status.on_event(Event::Up, now);
        status.on_event(Event::SamlReady, now);
        assert_eq!(status, Status::Disconnected);
    }
}
