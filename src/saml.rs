// SPDX-License-Identifier: EUPL-1.2

//! The SAML session id that ends a login, and handing it to openfortivpn.
//!
//! At the end of the SAML login the gateway redirects the browser to openfortivpn's listener,
//! `http://127.0.0.1:8020/?id=<id>`. openfortivpn (`--saml-login`) only listens for 50 seconds,
//! too short for a login with a second factor. So the login window stops at that redirect and
//! keeps the id; openfortivpn is started afterwards and gets the id as if the browser had
//! followed the redirect.
//!
//! ```
//! use cosmic_applet_fortivpn::saml::SamlId;
//!
//! let id = SamlId::from_redirect("http://127.0.0.1:8020/?id=abc123").unwrap();
//! assert_eq!(id.as_str(), "abc123");
//! assert!(id.request().starts_with("GET /?id=abc123 HTTP/1.1\r\n"));
//! assert_eq!(SamlId::from_redirect("https://vpn.example.com/?id=abc123"), None);
//! ```

use std::fmt;

/// Where openfortivpn listens for the redirect (its default `saml-port`).
pub const LISTENER_ADDR: &str = "127.0.0.1:8020";

/// Start of the redirect URL to the listener.
pub const LISTENER_URL: &str = "http://127.0.0.1:8020/";

/// Longest id accepted. openfortivpn reads the whole request with one `read()` of at most
/// 1023 bytes, so the request line must stay well below that.
const MAX_ID_LEN: usize = 512;

/// A SAML session id: the gateway's one-time ticket that openfortivpn exchanges for the tunnel
/// cookie. Kept out of `Debug` output since it works like a password until used.
#[derive(Clone, PartialEq, Eq)]
pub struct SamlId(String);

impl SamlId {
    /// Parses an id, accepting what openfortivpn accepts: ASCII letters, digits and `-`. That
    /// also keeps it from changing the request it is put into.
    pub fn parse(id: &str) -> Option<Self> {
        let valid = !id.is_empty()
            && id.len() <= MAX_ID_LEN
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        valid.then(|| Self(id.to_owned()))
    }

    /// The id from a redirect to openfortivpn's listener, `None` for any other URL.
    pub fn from_redirect(url: &str) -> Option<Self> {
        let query = url.strip_prefix(LISTENER_URL)?.strip_prefix('?')?;
        let query = query.split('#').next()?;
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix("id="))
            .and_then(Self::parse)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The HTTP request the browser would send to the listener.
    pub fn request(&self) -> String {
        format!(
            "GET /?id={} HTTP/1.1\r\nHost: {LISTENER_ADDR}\r\nConnection: close\r\n\r\n",
            self.0
        )
    }
}

impl fmt::Debug for SamlId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SamlId(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_from_redirects() {
        let id = |url: &str| SamlId::from_redirect(url).map(|id| id.as_str().to_owned());
        assert_eq!(
            id("http://127.0.0.1:8020/?id=A1b2-C3d4"),
            Some("A1b2-C3d4".into())
        );
        assert_eq!(
            id("http://127.0.0.1:8020/?x=1&id=abc#frag"),
            Some("abc".into())
        );
        assert_eq!(id("http://127.0.0.1:8020/?x=1"), None);
        assert_eq!(id("http://127.0.0.1:8020/"), None);
        assert_eq!(id("http://127.0.0.1:8021/?id=abc"), None);
        assert_eq!(id("http://127.0.0.1:8020/?id="), None);
    }

    #[test]
    fn ids_cannot_inject_into_the_request() {
        assert_eq!(SamlId::parse("abc HTTP/1.1\r\nX: y"), None);
        assert_eq!(SamlId::parse("a&b"), None);
        assert_eq!(SamlId::parse("a%20b"), None);
        assert_eq!(SamlId::parse(&"a".repeat(MAX_ID_LEN + 1)), None);
        assert!(SamlId::parse(&"a".repeat(MAX_ID_LEN)).is_some());
    }

    #[test]
    fn request_fits_openfortivpns_read() {
        let id = SamlId::parse(&"a".repeat(MAX_ID_LEN)).unwrap();
        assert!(id.request().len() < 1023);
    }

    #[test]
    fn debug_hides_the_id() {
        let id = SamlId::parse("secret").unwrap();
        assert!(!format!("{id:?}").contains("secret"));
    }
}
