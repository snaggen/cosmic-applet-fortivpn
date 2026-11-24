// SPDX-License-Identifier: EUPL-1.2

//! Running openfortivpn: its config file, and turning its output into [`Event`]s.
//!
//! ```
//! use cosmic_applet_fortivpn::{openfortivpn::OutputParser, protocol::Event};
//!
//! let mut parser = OutputParser::default();
//! assert_eq!(parser.parse_line("INFO:   Tunnel is up and running."), Some(Event::Up));
//! ```

use crate::{
    gateway::{CertDigest, Gateway},
    protocol::{Credentials, Event, UntrustedCert},
};

/// Path of the openfortivpn binary. Absolute, since the helper runs with a cleared PATH.
pub const OPENFORTIVPN: &str = "/usr/bin/openfortivpn";

/// The config file passed with `-c`. Passing our own file keeps openfortivpn from reading
/// `/etc/openfortivpn/config`, so nothing but the profile decides how it runs.
/// `session_trust` are certificates trusted for this connection only; openfortivpn accepts
/// several `trusted-cert` lines. `credentials` must have passed [`Credentials::check`]: no
/// line breaks, no surrounding spaces (openfortivpn splits at the first `=` and trims).
pub fn config_file(
    gateway: &Gateway,
    session_trust: &[CertDigest],
    credentials: Option<&Credentials>,
) -> String {
    let mut text = format!(
        "host = {}\nport = {}\npersistent = 0\n",
        gateway.host, gateway.port
    );
    for cert in gateway.trusted_cert.iter().chain(session_trust) {
        text.push_str(&format!("trusted-cert = {cert}\n"));
    }
    if let Some(credentials) = credentials {
        text.push_str(&format!(
            "username = {}\npassword = {}\n",
            credentials.username, credentials.password
        ));
        if let Some(otp) = &credentials.otp {
            text.push_str(&format!("otp = {otp}\n"));
        }
    }
    text
}

/// Where in openfortivpn's multi-line certificate error the parser is.
#[derive(Debug, Default)]
enum CertSection {
    #[default]
    None,
    Header,
    Subject,
    Issuer,
    Digest,
}

/// Turns openfortivpn's output lines into events. Keeps state across lines, since the
/// certificate error spans several of them.
#[derive(Debug, Default)]
pub struct OutputParser {
    section: CertSection,
    subject: Vec<String>,
    issuer: Vec<String>,
}

impl OutputParser {
    /// Parses one output line. Returns `None` for lines that are part of a larger message
    /// still being collected.
    pub fn parse_line(&mut self, line: &str) -> Option<Event> {
        let text = strip_level(line);

        if text.starts_with("Gateway certificate validation failed, and the certificate") {
            *self = Self {
                section: CertSection::Header,
                ..Self::default()
            };
            return None;
        }
        if !matches!(self.section, CertSection::None) {
            return self.parse_cert_line(text);
        }

        let event = if text.starts_with("Listening for SAML login") {
            Event::SamlReady
        } else if text.starts_with("Processing HTTP SAML request") {
            Event::SamlReceived
        } else if text.starts_with("Tunnel is up and running") {
            Event::Up
        } else if text.starts_with("Could not authenticate to gateway") {
            Event::AuthFailed
        } else {
            Event::Log(line.trim_end().to_owned())
        };
        Some(event)
    }

    /// One line of the certificate error. Its layout, from openfortivpn's `tunnel.c`:
    ///
    /// ```text
    /// ERROR:  Gateway certificate:
    /// ERROR:      subject:
    /// ERROR:          CN=vpn.example.com
    /// ERROR:      issuer:
    /// ERROR:          C=GB
    /// ERROR:      sha256 digest:
    /// ERROR:          f2c9…f1a1
    /// ```
    fn parse_cert_line(&mut self, text: &str) -> Option<Event> {
        match text.trim() {
            "subject:" => self.section = CertSection::Subject,
            "issuer:" => self.section = CertSection::Issuer,
            "sha256 digest:" => self.section = CertSection::Digest,
            value => match self.section {
                CertSection::Subject => self.subject.push(value.to_owned()),
                CertSection::Issuer => self.issuer.push(value.to_owned()),
                CertSection::Digest => {
                    let event = value.parse().ok().map(|digest| {
                        Event::CertUntrusted(UntrustedCert {
                            digest,
                            subject: self.subject.join(", "),
                            issuer: self.issuer.join(", "),
                        })
                    });
                    *self = Self::default();
                    return event;
                }
                CertSection::Header | CertSection::None => {}
            },
        }
        None
    }
}

/// Facts about the tunnel that openfortivpn (through pppd) logs while it comes up. The helper
/// passes these lines on as [`Event::Log`]; the agent picks them out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelDetail {
    /// The network interface, e.g. `ppp0`.
    Interface(String),
    /// The tunnel's local IP address.
    LocalAddress(String),
    /// The VPN's DNS servers, reached through the tunnel.
    Nameservers(Vec<std::net::IpAddr>),
}

impl TunnelDetail {
    /// Recognises pppd's `Using interface ppp0` and `local  IP address 192.0.2.1`, and
    /// openfortivpn's `Got addresses: [192.0.2.1], ns [192.0.2.53]`.
    ///
    /// ```
    /// use cosmic_applet_fortivpn::openfortivpn::TunnelDetail;
    ///
    /// assert_eq!(
    ///     TunnelDetail::parse("Using interface ppp0"),
    ///     Some(TunnelDetail::Interface("ppp0".into()))
    /// );
    /// assert_eq!(
    ///     TunnelDetail::parse("local  IP address 192.0.2.1"),
    ///     Some(TunnelDetail::LocalAddress("192.0.2.1".into()))
    /// );
    /// ```
    pub fn parse(line: &str) -> Option<Self> {
        let text = strip_level(line);
        if let Some(name) = text.strip_prefix("Using interface ") {
            let name = name.trim();
            // The name becomes part of a /sys path, so only plain interface names pass.
            let valid = !name.is_empty()
                && name.len() <= 15
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            return valid.then(|| Self::Interface(name.to_owned()));
        }
        if let Some(rest) = text.strip_prefix("Got addresses: ") {
            let list = rest.split_once("ns [")?.1.split(']').next()?;
            let servers: Vec<_> = list
                .split(',')
                .filter_map(|server| server.trim().parse().ok())
                .collect();
            return (!servers.is_empty()).then_some(Self::Nameservers(servers));
        }
        let address = text.strip_prefix("local")?.trim_start();
        let address = address.strip_prefix("IP address")?.trim();
        address
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| Self::LocalAddress(ip.to_string()))
    }
}

/// Strips openfortivpn's `LEVEL:` prefix and the padding after it.
fn strip_level(line: &str) -> &str {
    let line = line.trim_end();
    match line.split_once(':') {
        Some(("DEBUG" | "INFO" | "WARN" | "ERROR", rest)) => rest.trim_start(),
        _ => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "f2c935968edba48ab89c19f4291cf5449efc814665d179e32023f519dc89f1a1";

    fn parse_all(output: &str) -> Vec<Event> {
        let mut parser = OutputParser::default();
        output
            .lines()
            .filter_map(|line| parser.parse_line(line))
            .collect()
    }

    #[test]
    fn config_file_has_only_gateway_settings() {
        let mut gw: Gateway = "vpn.example.com:10443".parse().unwrap();
        assert_eq!(
            config_file(&gw, &[], None),
            "host = vpn.example.com\nport = 10443\npersistent = 0\n"
        );
        gw.trusted_cert = Some(DIGEST.parse().unwrap());
        assert!(config_file(&gw, &[], None).ends_with(&format!("trusted-cert = {DIGEST}\n")));
    }

    #[test]
    fn config_file_adds_credentials() {
        let gw: Gateway = "vpn.example.com:443".parse().unwrap();
        let credentials = Credentials {
            username: "anna".into(),
            password: "a#b=c".into(),
            otp: Some("123456".into()),
        };
        let text = config_file(&gw, &[], Some(&credentials));
        assert!(text.ends_with("username = anna\npassword = a#b=c\notp = 123456\n"));
    }

    #[test]
    fn config_file_adds_session_trust() {
        let mut gw: Gateway = "vpn.example.com:10443".parse().unwrap();
        let once: CertDigest = "a".repeat(64).parse().unwrap();
        assert!(
            config_file(&gw, std::slice::from_ref(&once), None)
                .ends_with(&format!("trusted-cert = {once}\n"))
        );
        gw.trusted_cert = Some(DIGEST.parse().unwrap());
        let text = config_file(&gw, std::slice::from_ref(&once), None);
        assert_eq!(text.matches("trusted-cert = ").count(), 2);
    }

    #[test]
    fn saml_login_and_tunnel_up() {
        let output = "\
INFO:   Listening for SAML login on port 8020
INFO:   Authenticate at 'https://vpn.example.com:10443/remote/saml/start?redirect=1'
INFO:   Processing HTTP SAML request
INFO:   Interface ppp0 is UP.
INFO:   Tunnel is up and running.
";
        assert_eq!(
            parse_all(output),
            vec![
                Event::SamlReady,
                Event::Log(
                    "INFO:   Authenticate at 'https://vpn.example.com:10443/remote/saml/start?redirect=1'"
                        .into()
                ),
                Event::SamlReceived,
                Event::Log("INFO:   Interface ppp0 is UP.".into()),
                Event::Up,
            ]
        );
    }

    /// Output captured from the gateway test (2026-11-24), which does not send its
    /// intermediate certificate. openfortivpn printed the block twice.
    #[test]
    fn untrusted_certificate() {
        let block = format!(
            "\
ERROR:  Gateway certificate validation failed, and the certificate digest is not in the local whitelist. If you trust it, rerun with:
ERROR:      --trusted-cert {DIGEST}
ERROR:  or add this line to your configuration file:
ERROR:      trusted-cert = {DIGEST}
ERROR:  Gateway certificate:
ERROR:      subject:
ERROR:          CN=vpn.example.com
ERROR:      issuer:
ERROR:          C=GB
ERROR:          O=Sectigo Limited
ERROR:          CN=Sectigo Public Server Authentication CA DV R36
ERROR:      sha256 digest:
ERROR:          {DIGEST}
"
        );
        let output = format!(
            "DEBUG:  Gateway certificate validation failed.\n{block}{block}INFO:   Closed connection to gateway.\n"
        );
        let expected = Event::CertUntrusted(UntrustedCert {
            digest: DIGEST.parse().unwrap(),
            subject: "CN=vpn.example.com".into(),
            issuer: "C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV R36"
                .into(),
        });
        assert_eq!(
            parse_all(&output),
            vec![
                Event::Log("DEBUG:  Gateway certificate validation failed.".into()),
                expected.clone(),
                expected,
                Event::Log("INFO:   Closed connection to gateway.".into()),
            ]
        );
    }

    #[test]
    fn auth_failure() {
        let output = "ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc.\n";
        assert_eq!(parse_all(output), vec![Event::AuthFailed]);
    }

    #[test]
    fn tunnel_details() {
        assert_eq!(
            TunnelDetail::parse("Using interface ppp0"),
            Some(TunnelDetail::Interface("ppp0".into()))
        );
        assert_eq!(
            TunnelDetail::parse("local  IP address 192.168.77.13"),
            Some(TunnelDetail::LocalAddress("192.168.77.13".into()))
        );
        assert_eq!(
            TunnelDetail::parse("remote IP address 125.63.190.187"),
            None
        );
        assert_eq!(TunnelDetail::parse("Using interface ../../etc"), None);
        assert_eq!(TunnelDetail::parse("Using interface "), None);
        assert_eq!(TunnelDetail::parse("local  IP address nonsense"), None);
        assert_eq!(
            TunnelDetail::parse("INFO:   Tunnel is up and running."),
            None
        );
        assert_eq!(
            TunnelDetail::parse(
                "INFO:   Got addresses: [192.168.77.13], ns [172.26.0.11, 172.28.0.11]"
            ),
            Some(TunnelDetail::Nameservers(vec![
                "172.26.0.11".parse().unwrap(),
                "172.28.0.11".parse().unwrap()
            ]))
        );
        assert_eq!(
            TunnelDetail::parse("INFO:   Got addresses: [192.168.77.13], ns [0.0.0.0x]"),
            None
        );
    }

    #[test]
    fn lines_without_level_are_logged() {
        let output = "Dropped protocol specifier '.openfortivpn' from 'ppp0.openfortivpn'.\n";
        assert_eq!(
            parse_all(output),
            vec![Event::Log(
                "Dropped protocol specifier '.openfortivpn' from 'ppp0.openfortivpn'.".into()
            )]
        );
    }
}
