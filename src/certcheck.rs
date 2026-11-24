// SPDX-License-Identifier: GPL-3.0-only

//! Checks the gateway certificate before logging in.
//!
//! openfortivpn only contacts the gateway after the SAML login, so a certificate it does not
//! trust would cost the user a login. The agent runs this check first and asks about the
//! certificate up front. It mirrors openfortivpn's rule: trusted if it validates against the
//! system roots for the host name, or if its SHA-256 digest is the pinned one.
//!
//! Gateways often send only their own certificate, without the intermediate CA, which only
//! browsers cope with. The check then fetches the intermediate from the address in the
//! certificate's Authority Information Access (`caIssuers`) and validates again
//! ([`CertCheck::Completed`]). The root helper repeats that validation itself
//! ([`verify_with_intermediate`]) before it trusts the certificate for the connection, so no
//! prompt is needed and certificate renewals keep working.
//!
//! ```no_run
//! use cosmic_applet_fortivpn::{certcheck::{check, CertCheck}, gateway::Gateway};
//!
//! let gateway: Gateway = "vpn.example.com:443".parse().unwrap();
//! match check(&gateway) {
//!     Ok(CertCheck::Trusted) => println!("trusted"),
//!     Ok(CertCheck::Completed { .. }) => println!("trusted with the fetched intermediate"),
//!     Ok(CertCheck::Untrusted(cert)) => println!("ask about {}", cert.digest),
//!     Err(err) => println!("could not check: {err}"),
//! }
//! ```

use crate::{
    gateway::{CertDigest, Gateway},
    protocol::{MAX_INTERMEDIATE_LEN, UntrustedCert},
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
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::Duration,
};
use x509_parser::{
    certificate::X509Certificate,
    extensions::{GeneralName, ParsedExtension},
    objects::{oid_registry, oid2abbrev},
    pem::parse_x509_pem,
    prelude::FromDer,
    x509::X509Name,
};

/// Largest HTTP response accepted when fetching an intermediate certificate.
const MAX_FETCH_LEN: u64 = 64 * 1024;

/// Timeout for connecting and for each read or write of the handshake.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The outcome of a certificate check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertCheck {
    Trusted,
    /// Valid once the intermediate fetched through AIA is added. `leaf` is the gateway
    /// certificate's digest, for the login window, which lacks the intermediate as well.
    Completed {
        intermediate: Vec<u8>,
        leaf: CertDigest,
    },
    Untrusted(UntrustedCert),
}

/// Connects to the gateway and checks its certificate. Blocking; a few round trips, plus one
/// HTTP request when the chain must be completed.
pub fn check(gateway: &Gateway) -> Result<CertCheck, String> {
    let seen = fetch_certificate(gateway)?;
    let decision = decide(gateway, &seen.der, seen.valid);
    if !matches!(decision, CertCheck::Untrusted(_)) {
        return Ok(decision);
    }
    match complete_chain(gateway, &seen) {
        Ok(Some(intermediate)) => Ok(CertCheck::Completed {
            intermediate,
            leaf: sha256_digest(&seen.der),
        }),
        Ok(None) => Ok(decision),
        Err(err) => {
            tracing::info!(%err, "could not complete the certificate chain");
            Ok(decision)
        }
    }
}

/// For the root helper: whether the gateway's certificate validates with `intermediate`
/// added, checked against the system roots from scratch. Returns the certificate's digest to
/// trust for this connection. `intermediate` comes from the caller, but it can only help a
/// chain that ends at a system root, so it cannot make an untrusted certificate pass.
pub fn verify_with_intermediate(
    gateway: &Gateway,
    intermediate: &[u8],
) -> Result<Option<CertDigest>, String> {
    let seen = fetch_certificate(gateway)?;
    if seen.valid {
        return Ok(None);
    }
    Ok(validates_with(gateway, &seen, intermediate)?.then(|| sha256_digest(&seen.der)))
}

/// Fetches the intermediate named in the certificate's AIA and returns it if the chain then
/// validates.
fn complete_chain(gateway: &Gateway, seen: &Seen) -> Result<Option<Vec<u8>>, String> {
    let Some(url) = ca_issuers_url(&seen.der) else {
        return Ok(None);
    };
    let intermediate = fetch_issuer(&url)?;
    Ok(validates_with(gateway, seen, &intermediate)?.then_some(intermediate))
}

/// Validates the leaf against the system roots, with the intermediates it sent plus `extra`.
fn validates_with(gateway: &Gateway, seen: &Seen, extra: &[u8]) -> Result<bool, String> {
    let verifier = webpki_verifier()?;
    let mut intermediates: Vec<CertificateDer<'_>> = seen
        .intermediates
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    intermediates.push(CertificateDer::from(extra));
    let name = ServerName::try_from(gateway.host.as_str()).map_err(|err| err.to_string())?;
    Ok(verifier
        .verify_server_cert(
            &CertificateDer::from(seen.der.as_slice()),
            &intermediates,
            &name,
            &[],
            UnixTime::now(),
        )
        .is_ok())
}

/// The `caIssuers` URL from the certificate's Authority Information Access, if plain HTTP
/// (as RFC 5280 recommends; an HTTPS one would need a chain of its own).
fn ca_issuers_url(der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    cert.extensions().iter().find_map(|ext| {
        let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() else {
            return None;
        };
        aia.accessdescs.iter().find_map(|desc| {
            if desc.access_method
                != x509_parser::oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS
            {
                return None;
            }
            match &desc.access_location {
                GeneralName::URI(uri) if uri.starts_with("http://") => Some((*uri).to_owned()),
                _ => None,
            }
        })
    })
}

/// Fetches a certificate over plain HTTP (DER or PEM). HTTP/1.0, so no chunked encoding.
fn fetch_issuer(url: &str) -> Result<Vec<u8>, String> {
    let (host, port, path) =
        split_http_url(url).ok_or_else(|| format!("{url}: unsupported URL"))?;
    let mut socket = connect(&format!("{host}:{port}"))?;
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: cosmic-applet-fortivpn\r\n\r\n"
    );
    socket
        .write_all(request.as_bytes())
        .map_err(|err| format!("{url}: {err}"))?;
    let mut response = Vec::new();
    socket
        .take(MAX_FETCH_LEN)
        .read_to_end(&mut response)
        .map_err(|err| format!("{url}: {err}"))?;
    let body = http_body(&response).ok_or_else(|| format!("{url}: bad HTTP response"))?;
    certificate_from(body).ok_or_else(|| format!("{url}: not a certificate"))
}

/// Splits `http://host[:port]/path`.
fn split_http_url(url: &str) -> Option<(&str, u16, &str)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (authority, 80),
    };
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    let path_ok = path.bytes().all(|b| b.is_ascii_graphic());
    (host_ok && path_ok).then_some((host, port, path))
}

/// The body of a `200` response.
fn http_body(response: &[u8]) -> Option<&[u8]> {
    let end = response.windows(4).position(|w| w == b"\r\n\r\n")?;
    let status = response.get(..end)?.split(|&b| b == b'\n').next()?;
    let status = std::str::from_utf8(status).ok()?;
    let mut parts = status.split_whitespace();
    let ok = parts.next()?.starts_with("HTTP/1.") && parts.next()? == "200";
    ok.then(|| response.get(end + 4..)).flatten()
}

/// A DER certificate from a DER or PEM body, if it parses.
fn certificate_from(body: &[u8]) -> Option<Vec<u8>> {
    let der = if body.starts_with(b"-----BEGIN") {
        parse_x509_pem(body).ok()?.1.contents
    } else {
        body.to_vec()
    };
    let parses = X509Certificate::from_der(&der).is_ok();
    (parses && der.len() <= MAX_INTERMEDIATE_LEN).then_some(der)
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

/// The leaf certificate the server sent, the intermediates it sent with it, and whether it
/// validated.
struct Seen {
    der: Vec<u8>,
    intermediates: Vec<Vec<u8>>,
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

/// A verifier against the system roots.
fn webpki_verifier() -> Result<Arc<WebPkiServerVerifier>, String> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    let (added, _) = roots.add_parsable_certificates(native.certs);
    if added == 0 {
        return Err("no system root certificates found".into());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|err| err.to_string())
}

impl Recorder {
    fn new() -> Result<Self, String> {
        Ok(Self {
            webpki: webpki_verifier()?,
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
                intermediates: intermediates.iter().map(|der| der.to_vec()).collect(),
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
    fn http_urls() {
        assert_eq!(
            split_http_url("http://crt.sectigo.com/Sectigo.crt"),
            Some(("crt.sectigo.com", 80, "/Sectigo.crt"))
        );
        assert_eq!(
            split_http_url("http://ca.example:8080/x"),
            Some(("ca.example", 8080, "/x"))
        );
        assert_eq!(
            split_http_url("http://ca.example"),
            Some(("ca.example", 80, "/"))
        );
        assert_eq!(split_http_url("https://ca.example/x"), None);
        assert_eq!(split_http_url("http://ca.example/a b"), None);
        assert_eq!(split_http_url("http://ca.example\r\nX: y/"), None);
    }

    #[test]
    fn http_responses() {
        assert_eq!(
            http_body(b"HTTP/1.1 200 OK\r\nContent-Type: x\r\n\r\nbody"),
            Some(&b"body"[..])
        );
        assert_eq!(http_body(b"HTTP/1.1 404 Not Found\r\n\r\nbody"), None);
        assert_eq!(http_body(b"HTTP/1.1 200 OK\r\n"), None);
    }

    #[test]
    fn certificates_from_der_and_pem() {
        assert_eq!(
            certificate_from(TEST_CERT_DER).as_deref(),
            Some(TEST_CERT_DER)
        );
        let pem = pem_of(TEST_CERT_DER);
        assert_eq!(
            certificate_from(pem.as_bytes()).as_deref(),
            Some(TEST_CERT_DER)
        );
        assert_eq!(certificate_from(b"<html>"), None);
    }

    /// PEM armour around DER, for the test.
    fn pem_of(der: &[u8]) -> String {
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut b64 = String::new();
        for chunk in der.chunks(3) {
            let n =
                chunk.iter().fold(0u32, |n, b| n << 8 | u32::from(*b)) << (8 * (3 - chunk.len()));
            for i in 0..4 {
                if i <= chunk.len() {
                    b64.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    b64.push('=');
                }
            }
        }
        let lines: Vec<_> = b64
            .as_bytes()
            .chunks(64)
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .collect();
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            lines.join("\n")
        )
    }

    #[test]
    fn self_signed_certificate_has_no_aia() {
        assert_eq!(ca_issuers_url(TEST_CERT_DER), None);
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
    /// for, validates once the intermediate is fetched through AIA; the helper's own check
    /// agrees and trusts that certificate.
    #[test]
    #[ignore]
    fn live_incomplete_chain_is_completed() {
        let gateway: Gateway = "incomplete-chain.badssl.com:443".parse().unwrap();
        let Ok(CertCheck::Completed { intermediate, leaf }) = check(&gateway) else {
            panic!("expected a completed chain");
        };
        assert_eq!(
            verify_with_intermediate(&gateway, &intermediate),
            Ok(Some(leaf))
        );
        // Some other certificate does not complete the chain.
        assert_eq!(verify_with_intermediate(&gateway, TEST_CERT_DER), Ok(None));
    }

    /// Network. A self-signed certificate has nothing to complete.
    #[test]
    #[ignore]
    fn live_self_signed_is_untrusted() {
        let gateway: Gateway = "self-signed.badssl.com:443".parse().unwrap();
        assert!(matches!(check(&gateway), Ok(CertCheck::Untrusted(_))));
    }

    #[test]
    fn digest_matches_openssl() {
        // `openssl x509 -in self-signed.der -inform der -noout -fingerprint -sha256`
        let expected = include_str!("../tests/data/self-signed.sha256").trim();
        assert_eq!(sha256_digest(TEST_CERT_DER).as_str(), expected);
    }
}
