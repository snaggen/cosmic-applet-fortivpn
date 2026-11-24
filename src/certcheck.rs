// SPDX-License-Identifier: GPL-3.0-only

//! Checks the gateway certificate before logging in.
//!
//! openfortivpn only contacts the gateway after the SAML login, so a certificate it does not
//! trust would cost the user a login. The agent runs this check first and asks about the
//! certificate up front. It mirrors openfortivpn's rule: trusted if it validates against the
//! system roots for the host name, or if its SHA-256 digest is the pinned one.
//!
//! ```no_run
//! use cosmic_applet_fortivpn::{certcheck::{check, CertCheck}, gateway::Gateway};
//!
//! let gateway: Gateway = "vpn.example.com:443".parse().unwrap();
//! match check(&gateway) {
//!     Ok(CertCheck::Trusted) => println!("trusted"),
//!     Ok(CertCheck::Untrusted(cert)) => println!("ask about {}", cert.digest),
//!     Err(err) => println!("could not check: {err}"),
//! }
//! ```

use crate::{
    gateway::{CertDigest, Gateway},
    protocol::UntrustedCert,
};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::{
    net::{TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::Duration,
};
use x509_parser::{
    objects::{oid_registry, oid2abbrev},
    x509::X509Name,
};

/// Timeout for connecting and for each read or write of the handshake.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The outcome of a certificate check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertCheck {
    Trusted,
    Untrusted(UntrustedCert),
}

/// Connects to the gateway and checks its certificate. Blocking; at most a few round trips.
pub fn check(gateway: &Gateway) -> Result<CertCheck, String> {
    let seen = fetch_certificate(gateway)?;
    Ok(decide(gateway, &seen.der, seen.valid))
}

/// Decides on a certificate the server presented.
fn decide(gateway: &Gateway, der: &[u8], valid: bool) -> CertCheck {
    if valid {
        return CertCheck::Trusted;
    }
    let digest = sha256_digest(der);
    if gateway.trusted_cert.as_ref() == Some(&digest) {
        return CertCheck::Trusted;
    }
    let (subject, issuer) = names(der);
    CertCheck::Untrusted(UntrustedCert {
        digest,
        subject,
        issuer,
    })
}

/// The SHA-256 digest of a DER certificate, as openfortivpn computes it for `trusted-cert`.
fn sha256_digest(der: &[u8]) -> CertDigest {
    CertDigest::from_sha256(Sha256::digest(der).into())
}

/// Subject and issuer as `C=GB, O=…, CN=…`, in certificate order like openfortivpn shows them.
fn names(der: &[u8]) -> (String, String) {
    match x509_parser::parse_x509_certificate(der) {
        Ok((_, cert)) => (format_name(cert.subject()), format_name(cert.issuer())),
        Err(_) => (String::new(), String::new()),
    }
}

fn format_name(name: &X509Name<'_>) -> String {
    name.iter()
        .flat_map(|rdn| rdn.iter())
        .map(|attr| {
            let key = oid2abbrev(attr.attr_type(), oid_registry())
                .map(str::to_owned)
                .unwrap_or_else(|_| attr.attr_type().to_id_string());
            let value = attr.as_str().unwrap_or("?");
            format!("{key}={value}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The leaf certificate the server sent, and whether it validated.
struct Seen {
    der: Vec<u8>,
    valid: bool,
}

/// Starts a TLS handshake only far enough to see and judge the server certificate.
fn fetch_certificate(gateway: &Gateway) -> Result<Seen, String> {
    let recorder = Arc::new(Recorder::new()?);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| err.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(gateway.host.clone()).map_err(|err| err.to_string())?;
    let mut conn = ClientConnection::new(Arc::new(config), name).map_err(|err| err.to_string())?;

    let address = format!("{}:{}", gateway.host, gateway.port);
    let mut socket = connect(&address)?;
    // The recorder rejects every certificate after looking at it, so the handshake always
    // ends in an error once the certificate has been seen.
    while conn.is_handshaking() {
        if conn.complete_io(&mut socket).is_err() {
            break;
        }
    }
    recorder
        .take()
        .ok_or_else(|| format!("{address}: no certificate received"))
}

fn connect(address: &str) -> Result<TcpStream, String> {
    let addrs = address
        .to_socket_addrs()
        .map_err(|err| format!("{address}: {err}"))?;
    let mut last_err = format!("{address}: no address");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, TIMEOUT) {
            Ok(socket) => {
                socket
                    .set_read_timeout(Some(TIMEOUT))
                    .and_then(|()| socket.set_write_timeout(Some(TIMEOUT)))
                    .map_err(|err| format!("{address}: {err}"))?;
                return Ok(socket);
            }
            Err(err) => last_err = format!("{address}: {err}"),
        }
    }
    Err(last_err)
}

/// A verifier that records the leaf certificate and whether the system roots accept it,
/// then stops the handshake.
#[derive(Debug)]
struct Recorder {
    webpki: Arc<WebPkiServerVerifier>,
    seen: Mutex<Option<Seen>>,
}

impl std::fmt::Debug for Seen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Seen").field("valid", &self.valid).finish()
    }
}

impl Recorder {
    fn new() -> Result<Self, String> {
        let mut roots = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        let (added, _) = roots.add_parsable_certificates(native.certs);
        if added == 0 {
            return Err("no system root certificates found".into());
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|err| err.to_string())?;
        Ok(Self {
            webpki,
            seen: Mutex::new(None),
        })
    }

    fn take(&self) -> Option<Seen> {
        self.seen.lock().ok()?.take()
    }
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let valid = self
            .webpki
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .is_ok();
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(Seen {
                der: end_entity.to_vec(),
                valid,
            });
        }
        Err(rustls::Error::General("certificate recorded".into()))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed test certificate (`CN=vpn.example.com`, issuer the same).
    const TEST_CERT_DER: &[u8] = include_bytes!("../tests/data/self-signed.der");

    fn gateway() -> Gateway {
        "vpn.example.com:443".parse().unwrap()
    }

    #[test]
    fn valid_certificate_is_trusted() {
        assert_eq!(decide(&gateway(), TEST_CERT_DER, true), CertCheck::Trusted);
    }

    #[test]
    fn invalid_certificate_is_untrusted_unless_pinned() {
        let CertCheck::Untrusted(cert) = decide(&gateway(), TEST_CERT_DER, false) else {
            panic!("expected untrusted");
        };
        assert_eq!(cert.subject, "C=SE, O=Test, CN=vpn.example.com");
        assert_eq!(cert.issuer, "C=SE, O=Test, CN=vpn.example.com");
        assert_eq!(cert.digest, sha256_digest(TEST_CERT_DER));

        let mut pinned = gateway();
        pinned.trusted_cert = Some(cert.digest);
        assert_eq!(decide(&pinned, TEST_CERT_DER, false), CertCheck::Trusted);
    }

    /// Network: `cargo test -- --ignored`. A server with a complete chain validates.
    #[test]
    #[ignore]
    fn live_complete_chain_is_trusted() {
        let gateway: Gateway = "badssl.com:443".parse().unwrap();
        assert_eq!(check(&gateway), Ok(CertCheck::Trusted));
    }

    /// Network. A server that leaves out its intermediate, like the gateway this was built
    /// for, does not validate.
    #[test]
    #[ignore]
    fn live_incomplete_chain_is_untrusted() {
        let gateway: Gateway = "incomplete-chain.badssl.com:443".parse().unwrap();
        let Ok(CertCheck::Untrusted(cert)) = check(&gateway) else {
            panic!("expected untrusted");
        };
        assert!(cert.subject.contains("CN=*.badssl.com"), "{}", cert.subject);
    }

    #[test]
    fn digest_matches_openssl() {
        // `openssl x509 -in self-signed.der -inform der -noout -fingerprint -sha256`
        let expected = include_str!("../tests/data/self-signed.sha256").trim();
        assert_eq!(sha256_digest(TEST_CERT_DER).as_str(), expected);
    }
}
