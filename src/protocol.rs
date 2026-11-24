// SPDX-License-Identifier: GPL-3.0-only

//! The line protocol between the applet and the helper that runs openfortivpn.
//!
//! The applet writes one [`Request`] line to the helper's stdin and keeps stdin open; closing
//! it disconnects. The helper writes one [`Event`] per line to stdout, fields separated by tabs.
//!
//! ```
//! use cosmic_applet_fortivpn::protocol::Event;
//!
//! assert_eq!(Event::parse(&Event::Up.to_line()), Some(Event::Up));
//! ```

use crate::{gateway::CertDigest, profile::ProfileId};
use std::fmt;

/// Longest username and password accepted, in bytes: openfortivpn's own limits
/// (`USERNAME_SIZE`, `PASSWORD_SIZE`), beyond which it would cut them off.
const MAX_USERNAME_LEN: usize = 64;
const MAX_PASSWORD_LEN: usize = 256;
/// Longest one-time code accepted.
const MAX_OTP_LEN: usize = 16;
/// Largest intermediate certificate accepted (DER).
pub const MAX_INTERMEDIATE_LEN: usize = 3000;

/// What the helper should do. The only input the helper takes from the agent: which profile
/// (an admin set up everything else about it), the login, and maybe a certificate the agent
/// fetched to complete the gateway's chain, which the helper verifies itself.
///
/// One line: the login kind, then tab-separated `key=value` fields.
///
/// ```
/// use cosmic_applet_fortivpn::protocol::{Login, Request};
///
/// let request = Request {
///     profile: "ace".parse().unwrap(),
///     login: Login::Saml,
///     intermediate: None,
/// };
/// assert_eq!(request.to_line(), "saml-login\tprofile=ace\n");
/// assert_eq!(Request::parse("saml-login\tprofile=ace"), Ok(request));
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    pub profile: ProfileId,
    pub login: Login,
    /// The intermediate certificate the gateway does not send (DER), fetched through AIA.
    pub intermediate: Option<Vec<u8>>,
}

/// How to log in.
#[derive(Clone, PartialEq, Eq)]
pub enum Login {
    /// Let openfortivpn receive the SAML redirect on `127.0.0.1:8020` (`--saml-login`).
    Saml,
    /// Username and password, written to openfortivpn's root-only config file.
    Password(Credentials),
}

/// A username and password, maybe with a one-time code.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub otp: Option<String>,
}

/// Never shows the password or code, so a request can be logged safely.
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let login = match &self.login {
            Login::Saml => "Saml",
            Login::Password(_) => "Password(<redacted>)",
        };
        f.debug_struct("Request")
            .field("profile", &self.profile)
            .field("login", &format_args!("{login}"))
            .field("intermediate", &self.intermediate.as_ref().map(Vec::len))
            .finish()
    }
}

/// Why a request line was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestError {
    Unknown,
    /// A field is missing, repeated, unknown or invalid; names the key.
    Field(&'static str),
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown request"),
            Self::Field(key) => write!(f, "invalid request field {key}"),
        }
    }
}

impl Credentials {
    /// Whether the credentials can be sent: no control characters (they would end a field or
    /// a config line), no surrounding spaces (openfortivpn's config parser drops them), bounded
    /// length, and a code of digits and letters only.
    pub fn check(&self) -> Result<(), RequestError> {
        if !is_valid_credential(&self.username, MAX_USERNAME_LEN) {
            return Err(RequestError::Field("user"));
        }
        if !is_valid_credential(&self.password, MAX_PASSWORD_LEN) {
            return Err(RequestError::Field("pass"));
        }
        if let Some(otp) = &self.otp
            && !is_valid_otp(otp)
        {
            return Err(RequestError::Field("otp"));
        }
        Ok(())
    }
}

impl Request {
    /// Parses a request line (without the newline).
    pub fn parse(line: &str) -> Result<Self, RequestError> {
        let mut fields = line.split('\t');
        let kind = fields.next().unwrap_or_default();
        let (mut profile, mut user, mut pass, mut otp, mut ca) = (None, None, None, None, None);
        for field in fields {
            let (key, value) = field.split_once('=').ok_or(RequestError::Unknown)?;
            let slot = match key {
                "profile" => &mut profile,
                "user" => &mut user,
                "pass" => &mut pass,
                "otp" => &mut otp,
                "ca" => &mut ca,
                _ => return Err(RequestError::Unknown),
            };
            if slot.replace(value).is_some() {
                return Err(RequestError::Unknown);
            }
        }
        let profile = profile
            .ok_or(RequestError::Field("profile"))?
            .parse()
            .map_err(|_| RequestError::Field("profile"))?;
        let intermediate = ca
            .map(|hex| {
                decode_hex(hex).filter(|der| (1..=MAX_INTERMEDIATE_LEN).contains(&der.len()))
            })
            .map(|der| der.ok_or(RequestError::Field("ca")))
            .transpose()?;
        let login = match kind {
            "saml-login" if user.is_none() && pass.is_none() && otp.is_none() => Login::Saml,
            "password" => {
                let credentials = Credentials {
                    username: user.ok_or(RequestError::Field("user"))?.to_owned(),
                    password: pass.ok_or(RequestError::Field("pass"))?.to_owned(),
                    otp: otp.map(str::to_owned),
                };
                credentials.check()?;
                Login::Password(credentials)
            }
            _ => return Err(RequestError::Unknown),
        };
        Ok(Self {
            profile,
            login,
            intermediate,
        })
    }

    /// Formats the request line, newline included. Credentials must have passed
    /// [`Credentials::check`].
    pub fn to_line(&self) -> String {
        let mut line = match &self.login {
            Login::Saml => format!("saml-login\tprofile={}", self.profile),
            Login::Password(c) => {
                let mut line = format!(
                    "password\tprofile={}\tuser={}\tpass={}",
                    self.profile, c.username, c.password
                );
                if let Some(otp) = &c.otp {
                    line.push_str(&format!("\totp={otp}"));
                }
                line
            }
        };
        if let Some(der) = &self.intermediate {
            line.push_str("\tca=");
            line.push_str(&encode_hex(der));
        }
        line.push('\n');
        line
    }
}

fn is_valid_credential(value: &str, max_len: usize) -> bool {
    (1..=max_len).contains(&value.len())
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn is_valid_otp(otp: &str) -> bool {
    (1..=MAX_OTP_LEN).contains(&otp.len()) && otp.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    hex.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
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

    fn profile() -> ProfileId {
        "ace".parse().unwrap()
    }

    fn password(otp: Option<&str>) -> Login {
        Login::Password(Credentials {
            username: "anna@example.com".into(),
            password: "p=ss wörd#1".into(),
            otp: otp.map(str::to_owned),
        })
    }

    #[test]
    fn request_round_trips() {
        for (login, intermediate) in [
            (Login::Saml, None),
            (Login::Saml, Some(vec![0x30, 0x82, 0xff])),
            (password(None), None),
            (password(Some("123456")), Some(vec![1, 2, 3])),
        ] {
            let request = Request {
                profile: profile(),
                login,
                intermediate,
            };
            let line = request.to_line();
            assert_eq!(Request::parse(line.trim_end_matches('\n')), Ok(request));
        }
    }

    #[test]
    fn request_rejects_bad_input() {
        let bad = |line: &str| Request::parse(line).is_err();
        assert!(bad(""));
        assert!(bad("saml-login"), "profile is required");
        assert!(bad("saml-login\tprofile=../x"));
        assert!(
            bad("saml-login\tprofile=ace\tprofile=ace"),
            "repeated field"
        );
        assert!(
            bad("saml-login\tprofile=ace\tpppd-plugin=x"),
            "unknown field"
        );
        assert!(
            bad("saml-login\tprofile=ace\tpass=x"),
            "no password for SAML"
        );
        assert!(bad("cookie\tprofile=ace"));
        assert!(bad("--pppd-plugin x"));
        assert!(bad("password\tprofile=ace\tuser=a"), "password is required");
        assert!(
            bad("password\tprofile=ace\tuser=a\tpass= x"),
            "surrounding space"
        );
        assert!(bad("password\tprofile=ace\tuser=a\tpass=x\totp=12 34"));
        assert!(bad(
            "password\tprofile=ace\tuser=a\tpass=x\totp=12345678901234567"
        ));
        let long = "a".repeat(MAX_PASSWORD_LEN + 1);
        assert!(bad(&format!("password\tprofile=ace\tuser=a\tpass={long}")));
        let long = "a".repeat(MAX_USERNAME_LEN + 1);
        assert!(bad(&format!("password\tprofile=ace\tuser={long}\tpass=x")));
        assert!(bad("saml-login\tprofile=ace\tca=abc"), "odd hex");
        assert!(bad("saml-login\tprofile=ace\tca=zz"), "not hex");
        assert!(bad("saml-login\tprofile=ace\tca="), "empty certificate");
        let huge = "00".repeat(MAX_INTERMEDIATE_LEN + 1);
        assert!(bad(&format!("saml-login\tprofile=ace\tca={huge}")));
    }

    #[test]
    fn request_debug_hides_secrets() {
        let request = Request {
            profile: profile(),
            login: password(Some("987654")),
            intermediate: None,
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("wörd"));
        assert!(!debug.contains("987654"));
        assert!(debug.contains("ace"));
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
