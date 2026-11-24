// SPDX-License-Identifier: GPL-3.0-only

//! The line protocol between the applet and the helper that runs openfortivpn.
//!
//! The applet writes one [`Request`] line to the helper's stdin and keeps stdin open; closing
//! it disconnects. The helper writes one [`Event`] per line to stdout, fields separated by tabs.
//!
//! ```
//! use cosmic_applet_fortivpn::protocol::{Event, Request};
//!
//! assert_eq!(Request::parse("saml-login"), Ok(Request::SamlLogin));
//! assert_eq!(Event::parse(&Event::Up.to_line()), Some(Event::Up));
//! ```

use crate::gateway::CertDigest;
use std::fmt;

/// Longest cookie accepted. openfortivpn reads the cookie with a single `read()` of at most
/// 4096 bytes, so a longer one would be cut off.
pub const MAX_COOKIE_LEN: usize = 4000;

/// How the helper should log in. The only input the helper takes from the applet.
#[derive(Clone, PartialEq, Eq)]
pub enum Request {
    /// Let openfortivpn receive the SAML redirect on `127.0.0.1:8020` (`--saml-login`).
    SamlLogin,
    /// Use an `SVPNCOOKIE` obtained elsewhere (`--cookie-on-stdin`).
    Cookie(String),
}

/// Never shows the cookie, so a request can be logged safely.
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SamlLogin => write!(f, "SamlLogin"),
            Self::Cookie(_) => write!(f, "Cookie(<redacted>)"),
        }
    }
}

/// Why a request line was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestError {
    Unknown,
    InvalidCookie,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown request"),
            Self::InvalidCookie => write!(f, "invalid cookie"),
        }
    }
}

impl Request {
    /// Parses a request line (without the newline).
    pub fn parse(line: &str) -> Result<Self, RequestError> {
        match line.split_once(' ') {
            None if line == "saml-login" => Ok(Self::SamlLogin),
            Some(("cookie", cookie)) if is_valid_cookie(cookie) => Ok(Self::Cookie(cookie.into())),
            Some(("cookie", _)) => Err(RequestError::InvalidCookie),
            _ => Err(RequestError::Unknown),
        }
    }

    /// Formats the request line, newline included.
    pub fn to_line(&self) -> String {
        match self {
            Self::SamlLogin => "saml-login\n".into(),
            Self::Cookie(cookie) => format!("cookie {cookie}\n"),
        }
    }
}

/// Printable ASCII without whitespace or characters that would end the cookie in a header.
fn is_valid_cookie(cookie: &str) -> bool {
    (1..=MAX_COOKIE_LEN).contains(&cookie.len())
        && cookie
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b';' | b',' | b'"' | b'\\'))
}

/// The gateway certificate openfortivpn refused, for the user to decide on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UntrustedCert {
    pub digest: CertDigest,
    /// Subject name parts, e.g. `CN=vpn.example.com`, joined with ", ".
    pub subject: String,
    /// Issuer name parts, joined with ", ".
    pub issuer: String,
}

/// Errors the helper reports before or instead of running openfortivpn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelperError {
    /// No gateway config, or it could not be read.
    NotConfigured,
    /// Another helper already runs a tunnel.
    Busy,
    /// The request line was missing or invalid.
    BadRequest,
    /// openfortivpn could not be started, or something else failed.
    Failed(String),
}

/// What the helper reports on stdout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// openfortivpn waits for the SAML redirect; the applet opens the login page now.
    SamlReady,
    /// The browser delivered the SAML login to openfortivpn; the login page is done.
    SamlReceived,
    /// The tunnel is up.
    Up,
    /// The gateway certificate does not validate and is not trusted.
    CertUntrusted(UntrustedCert),
    /// The gateway rejected the login.
    AuthFailed,
    /// Any other openfortivpn output line, for the applet's debug log.
    Log(String),
    Error(HelperError),
    /// openfortivpn ended. The exit code, or `None` if it was killed by a signal.
    Exited(Option<i32>),
}

impl Event {
    /// Formats the event as one line, newline included. Tabs and control characters inside
    /// fields are replaced by spaces, so a field can never start a new field or line.
    pub fn to_line(&self) -> String {
        let fields: Vec<String> = match self {
            Self::SamlReady => vec!["saml-ready".into()],
            Self::SamlReceived => vec!["saml-received".into()],
            Self::Up => vec!["up".into()],
            Self::CertUntrusted(cert) => vec![
                "cert-untrusted".into(),
                cert.digest.to_string(),
                cert.subject.clone(),
                cert.issuer.clone(),
            ],
            Self::AuthFailed => vec!["auth-failed".into()],
            Self::Log(text) => vec!["log".into(), text.clone()],
            Self::Error(HelperError::NotConfigured) => {
                vec!["error".into(), "not-configured".into()]
            }
            Self::Error(HelperError::Busy) => vec!["error".into(), "busy".into()],
            Self::Error(HelperError::BadRequest) => vec!["error".into(), "bad-request".into()],
            Self::Error(HelperError::Failed(why)) => {
                vec!["error".into(), "failed".into(), why.clone()]
            }
            Self::Exited(code) => vec![
                "exited".into(),
                code.map_or_else(|| "signal".into(), |c| c.to_string()),
            ],
        };
        let mut line = fields
            .iter()
            .map(|f| sanitize(f))
            .collect::<Vec<_>>()
            .join("\t");
        line.push('\n');
        line
    }

    /// Parses an event line; a trailing newline is ignored. `None` for anything unknown, so
    /// the applet can skip lines from a newer helper.
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim_end_matches(['\n', '\r']);
        let fields: Vec<&str> = line.split('\t').collect();
        let event = match fields.as_slice() {
            ["saml-ready"] => Self::SamlReady,
            ["saml-received"] => Self::SamlReceived,
            ["up"] => Self::Up,
            ["cert-untrusted", digest, subject, issuer] => Self::CertUntrusted(UntrustedCert {
                digest: digest.parse().ok()?,
                subject: (*subject).into(),
                issuer: (*issuer).into(),
            }),
            ["auth-failed"] => Self::AuthFailed,
            ["log", text] => Self::Log((*text).into()),
            ["error", "not-configured"] => Self::Error(HelperError::NotConfigured),
            ["error", "busy"] => Self::Error(HelperError::Busy),
            ["error", "bad-request"] => Self::Error(HelperError::BadRequest),
            ["error", "failed", why] => Self::Error(HelperError::Failed((*why).into())),
            ["exited", "signal"] => Self::Exited(None),
            ["exited", code] => Self::Exited(Some(code.parse().ok()?)),
            _ => return None,
        };
        Some(event)
    }
}

fn sanitize(field: &str) -> String {
    field
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "f2c935968edba48ab89c19f4291cf5449efc814665d179e32023f519dc89f1a1";

    #[test]
    fn request_round_trips() {
        for request in [Request::SamlLogin, Request::Cookie("abc+/=123".into())] {
            let line = request.to_line();
            assert_eq!(Request::parse(line.trim_end_matches('\n')), Ok(request));
        }
    }

    #[test]
    fn request_rejects_bad_input() {
        assert_eq!(Request::parse(""), Err(RequestError::Unknown));
        assert_eq!(Request::parse("saml-login x"), Err(RequestError::Unknown));
        assert_eq!(
            Request::parse("--pppd-plugin x"),
            Err(RequestError::Unknown)
        );
        assert_eq!(Request::parse("cookie "), Err(RequestError::InvalidCookie));
        assert_eq!(
            Request::parse("cookie a b"),
            Err(RequestError::InvalidCookie)
        );
        assert_eq!(
            Request::parse("cookie a;b"),
            Err(RequestError::InvalidCookie)
        );
        let too_long = format!("cookie {}", "a".repeat(MAX_COOKIE_LEN + 1));
        assert_eq!(Request::parse(&too_long), Err(RequestError::InvalidCookie));
        let longest = format!("cookie {}", "a".repeat(MAX_COOKIE_LEN));
        assert!(Request::parse(&longest).is_ok());
    }

    #[test]
    fn request_debug_hides_cookie() {
        let debug = format!("{:?}", Request::Cookie("secret".into()));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn events_round_trip() {
        let events = [
            Event::SamlReady,
            Event::SamlReceived,
            Event::Up,
            Event::CertUntrusted(UntrustedCert {
                digest: DIGEST.parse().unwrap(),
                subject: "CN=vpn.example.com".into(),
                issuer: "C=GB, O=Sectigo Limited".into(),
            }),
            Event::AuthFailed,
            Event::Log("INFO:   Something".into()),
            Event::Error(HelperError::NotConfigured),
            Event::Error(HelperError::Busy),
            Event::Error(HelperError::BadRequest),
            Event::Error(HelperError::Failed("no such file".into())),
            Event::Exited(Some(0)),
            Event::Exited(Some(1)),
            Event::Exited(None),
        ];
        for event in events {
            let line = event.to_line();
            assert_eq!(line.matches('\n').count(), 1);
            assert_eq!(Event::parse(line.trim_end_matches('\n')), Some(event));
        }
    }

    #[test]
    fn event_fields_cannot_inject_lines_or_fields() {
        let line = Event::Log("a\tb\nup".into()).to_line();
        assert_eq!(line, "log\ta b up\n");
        assert_eq!(
            Event::parse("log\ta b up"),
            Some(Event::Log("a b up".into()))
        );
    }

    #[test]
    fn unknown_events_are_skipped() {
        assert_eq!(Event::parse("something-new\tx"), None);
        assert_eq!(Event::parse("exited\tx"), None);
        assert_eq!(Event::parse("cert-untrusted\tnot-hex\ta\tb"), None);
    }
}
