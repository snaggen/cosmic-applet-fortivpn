// SPDX-License-Identifier: GPL-3.0-only

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
    protocol::{Event, UntrustedCert},
};

/// Path of the openfortivpn binary. Absolute, since the helper runs with a cleared PATH.
pub const OPENFORTIVPN: &str = "/usr/bin/openfortivpn";

/// The config file passed with `-c`. Passing our own file keeps openfortivpn from reading
/// `/etc/openfortivpn/config`, so nothing but the gateway config decides how it runs.
/// `session_trust` is a certificate trusted for this connection only; openfortivpn accepts
/// several `trusted-cert` lines.
pub fn config_file(gateway: &Gateway, session_trust: Option<&CertDigest>) -> String {
    let mut text = format!(
        "host = {}\nport = {}\npersistent = 0\n",
        gateway.host, gateway.port
    );
    for cert in gateway.trusted_cert.iter().chain(session_trust) {
        text.push_str(&format!("trusted-cert = {cert}\n"));
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
            config_file(&gw, None),
            "host = vpn.example.com\nport = 10443\npersistent = 0\n"
        );
        gw.trusted_cert = Some(DIGEST.parse().unwrap());
        assert!(config_file(&gw, None).ends_with(&format!("trusted-cert = {DIGEST}\n")));
    }

    #[test]
    fn config_file_adds_session_trust() {
        let mut gw: Gateway = "vpn.example.com:10443".parse().unwrap();
        let once: CertDigest = "a".repeat(64).parse().unwrap();
        assert!(config_file(&gw, Some(&once)).ends_with(&format!("trusted-cert = {once}\n")));
        gw.trusted_cert = Some(DIGEST.parse().unwrap());
        let text = config_file(&gw, Some(&once));
        assert_eq!(text.matches("trusted-cert = ").count(), 2);
    }

    #[test]
    fn saml_login_and_tunnel_up() {
        let output = "\
INFO:   Listening for SAML login on port 8020
INFO:   Authenticate at 'https://vpn.example.com:10443/remote/saml/start?redirect=1'
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
