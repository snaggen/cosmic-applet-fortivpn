// SPDX-License-Identifier: EUPL-1.2

//! The gateway config: which VPN gateway to use and which certificate to trust.
//!
//! It lives in a root-owned, world-readable file, so the applet can read it but only an admin
//! (through the configure helper) can change it. See `PLAN.md`, "Privilege boundary".
//!
//! ```
//! use cosmic_applet_fortivpn::gateway::Gateway;
//!
//! let gw: Gateway = "vpn.example.com:10443".parse().unwrap();
//! assert_eq!(gw.port, 10443);
//! assert_eq!(Gateway::parse_config(&gw.to_config()).unwrap(), gw);
//! ```

use std::{fmt, str::FromStr};

/// Path of the gateway config.
pub const CONFIG_PATH: &str = "/etc/cosmic-applet-fortivpn/gateway.conf";

/// A VPN gateway and, optionally, the certificate the user chose to trust for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gateway {
    pub host: String,
    pub port: u16,
    /// SHA-256 digest of the gateway certificate, accepted although it does not validate.
    pub trusted_cert: Option<CertDigest>,
}

/// Why a gateway or its config was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidHost,
    InvalidPort,
    InvalidCertDigest,
    MissingHost,
    MissingPort,
    UnknownKey(String),
    MalformedLine(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHost => write!(f, "invalid host name"),
            Self::InvalidPort => write!(f, "invalid port"),
            Self::InvalidCertDigest => write!(f, "invalid certificate digest"),
            Self::MissingHost => write!(f, "host is missing"),
            Self::MissingPort => write!(f, "port is missing"),
            Self::UnknownKey(key) => write!(f, "unknown key: {key}"),
            Self::MalformedLine(line) => write!(f, "malformed line: {line}"),
        }
    }
}

impl std::error::Error for Error {}

impl Gateway {
    /// Parses the config file format: `key = value` lines, `#` comments.
    pub fn parse_config(text: &str) -> Result<Self, Error> {
        let mut host = None;
        let mut port = None;
        let mut trusted_cert = None;
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| Error::MalformedLine(line.to_owned()))?;
            let value = value.trim();
            match key.trim() {
                "host" => host = Some(parse_host(value)?),
                "port" => port = Some(parse_port(value)?),
                "trusted-cert" => trusted_cert = Some(value.parse()?),
                other => return Err(Error::UnknownKey(other.to_owned())),
            }
        }
        Ok(Self {
            host: host.ok_or(Error::MissingHost)?,
            port: port.ok_or(Error::MissingPort)?,
            trusted_cert,
        })
    }

    /// Formats the config file.
    pub fn to_config(&self) -> String {
        let mut text = format!("host = {}\nport = {}\n", self.host, self.port);
        if let Some(cert) = &self.trusted_cert {
            text.push_str(&format!("trusted-cert = {cert}\n"));
        }
        text
    }

    /// Reads the config from [`CONFIG_PATH`]. `Ok(None)` if no gateway is configured yet.
    pub fn load() -> std::io::Result<Option<Self>> {
        match std::fs::read_to_string(CONFIG_PATH) {
            Ok(text) => Self::parse_config(&text)
                .map(Some)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// The page that starts the SAML login and redirects back to openfortivpn.
    pub fn saml_login_url(&self) -> String {
        format!(
            "https://{}:{}/remote/saml/start?redirect=1",
            self.host, self.port
        )
    }

    /// `host:port`, as the user enters it.
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Parses `host:port`, with no trusted certificate.
impl FromStr for Gateway {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let (host, port) = s.trim().rsplit_once(':').ok_or(Error::MissingPort)?;
        Ok(Self {
            host: parse_host(host)?,
            port: parse_port(port)?,
            trusted_cert: None,
        })
    }
}

/// A DNS name or IPv4 address. Restricted to a safe charset, since the host ends up in a
/// config file read by a root process and in a URL opened in the browser.
fn parse_host(s: &str) -> Result<String, Error> {
    let valid = !s.is_empty()
        && s.len() <= 253
        && !s.starts_with(['-', '.'])
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if valid {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(Error::InvalidHost)
    }
}

fn parse_port(s: &str) -> Result<u16, Error> {
    match s.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(Error::InvalidPort),
    }
}

/// A SHA-256 certificate digest as openfortivpn prints it: 64 lowercase hex digits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertDigest(String);

impl CertDigest {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The digest of a SHA-256 hash, in openfortivpn's lowercase hex form.
    pub fn from_sha256(hash: [u8; 32]) -> Self {
        Self(hash.iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

impl FromStr for CertDigest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let s = s.trim();
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Ok(Self(s.to_ascii_lowercase()))
        } else {
            Err(Error::InvalidCertDigest)
        }
    }
}

impl fmt::Display for CertDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "f2c935968edba48ab89c19f4291cf5449efc814665d179e32023f519dc89f1a1";

    #[test]
    fn parses_host_and_port() {
        let gw: Gateway = "VPN.Example.com:10443".parse().unwrap();
        assert_eq!(gw.host, "vpn.example.com");
        assert_eq!(gw.port, 10443);
        assert_eq!(gw.trusted_cert, None);
        assert_eq!(gw.address(), "vpn.example.com:10443");
    }

    #[test]
    fn rejects_bad_addresses() {
        for bad in [
            "",
            "vpn.example.com",
            ":443",
            "vpn.example.com:0",
            "vpn.example.com:70000",
            "-c/etc/passwd:443",
            "vpn example.com:443",
            "vpn.example.com/path:443",
            "vpn.example.com\nhost = evil:443",
        ] {
            assert!(bad.parse::<Gateway>().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn config_round_trips() {
        let gw = Gateway {
            host: "vpn.example.com".into(),
            port: 443,
            trusted_cert: Some(DIGEST.parse().unwrap()),
        };
        let text = gw.to_config();
        assert_eq!(
            text,
            format!("host = vpn.example.com\nport = 443\ntrusted-cert = {DIGEST}\n")
        );
        assert_eq!(Gateway::parse_config(&text).unwrap(), gw);
    }

    #[test]
    fn config_skips_comments_and_rejects_unknown_keys() {
        let text = "# comment\n\nhost = a.example\nport = 1\n";
        assert_eq!(Gateway::parse_config(text).unwrap().host, "a.example");
        assert_eq!(
            Gateway::parse_config("host = a\nport = 1\npppd-plugin = x.so\n"),
            Err(Error::UnknownKey("pppd-plugin".into()))
        );
        assert_eq!(Gateway::parse_config("port = 1"), Err(Error::MissingHost));
        assert_eq!(Gateway::parse_config("host = a"), Err(Error::MissingPort));
    }

    #[test]
    fn digest_is_64_hex_digits() {
        assert_eq!(
            DIGEST
                .to_uppercase()
                .parse::<CertDigest>()
                .unwrap()
                .as_str(),
            DIGEST
        );
        assert!("abc".parse::<CertDigest>().is_err());
        assert!(format!("{DIGEST}0").parse::<CertDigest>().is_err());
        assert!(DIGEST.replace('f', "g").parse::<CertDigest>().is_err());
    }

    #[test]
    fn saml_url() {
        let gw: Gateway = "vpn.example.com:10443".parse().unwrap();
        assert_eq!(
            gw.saml_login_url(),
            "https://vpn.example.com:10443/remote/saml/start?redirect=1"
        );
    }
}
