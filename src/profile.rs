// SPDX-License-Identifier: GPL-3.0-only

//! VPN accounts (profiles): one gateway each, with a name and a login method.
//!
//! Profiles are root-owned files, `/etc/cosmic-applet-fortivpn/profiles/<id>.conf`, written
//! only by the configure helper (admin password). The helper that runs openfortivpn takes a
//! profile id from the caller and reads everything else from that file, so a caller only picks
//! among the profiles an admin set up.
//!
//! ```
//! use cosmic_applet_fortivpn::profile::{LoginMethod, Profile};
//!
//! let profile = Profile::parse_config(
//!     "ace".parse().unwrap(),
//!     "name = ACE\nmethod = saml\nhost = vpn.example.com\nport = 10443\n",
//! )
//! .unwrap();
//! assert_eq!(profile.name, "ACE");
//! assert_eq!(profile.method, LoginMethod::Saml);
//! assert_eq!(profile.gateway.address(), "vpn.example.com:10443");
//! ```

use crate::gateway::{self, Gateway};
use std::{
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};

/// Directory of the profile files.
pub const PROFILES_DIR: &str = "/etc/cosmic-applet-fortivpn/profiles";

/// Id of the profile the single gateway config of earlier versions becomes.
pub const LEGACY_ID: &str = "default";

/// Longest profile id and name.
const MAX_ID_LEN: usize = 32;
const MAX_NAME_LEN: usize = 64;

/// A profile id: `[a-z0-9-]`, at most 32 characters, not starting with `-`. Safe as a file
/// name and as a field in the helper's request line.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileId(String);

impl ProfileId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// An id made from a display name: lower case, other characters as `-`.
    ///
    /// ```
    /// use cosmic_applet_fortivpn::profile::ProfileId;
    ///
    /// assert_eq!(ProfileId::from_name("ACE Media (AU)").unwrap().as_str(), "ace-media-au");
    /// assert!(ProfileId::from_name("!!!").is_none());
    /// ```
    pub fn from_name(name: &str) -> Option<Self> {
        let mut id = String::new();
        for c in name.chars().flat_map(char::to_lowercase) {
            if c.is_ascii_alphanumeric() {
                id.push(c);
            } else if !id.is_empty() && !id.ends_with('-') {
                id.push('-');
            }
        }
        let id = id.trim_end_matches('-');
        let id: String = id.chars().take(MAX_ID_LEN).collect();
        id.trim_end_matches('-').parse().ok()
    }

    /// The profile's file.
    pub fn path(&self) -> PathBuf {
        Path::new(PROFILES_DIR).join(format!("{}.conf", self.0))
    }
}

impl FromStr for ProfileId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let valid = (1..=MAX_ID_LEN).contains(&s.len())
            && !s.starts_with('-')
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        valid
            .then(|| Self(s.to_owned()))
            .ok_or_else(|| Error::InvalidId(s.to_owned()))
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How the profile logs in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LoginMethod {
    /// SAML single sign-on in the login window.
    #[default]
    Saml,
    /// Username and password, maybe with a one-time code.
    Password,
}

impl LoginMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Saml => "saml",
            Self::Password => "password",
        }
    }
}

impl FromStr for LoginMethod {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "saml" => Ok(Self::Saml),
            "password" => Ok(Self::Password),
            other => Err(Error::InvalidMethod(other.to_owned())),
        }
    }
}

/// A VPN account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub id: ProfileId,
    /// Shown to the user.
    pub name: String,
    pub method: LoginMethod,
    pub gateway: Gateway,
}

/// Why a profile was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidId(String),
    InvalidName,
    InvalidMethod(String),
    Gateway(gateway::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId(id) => write!(f, "invalid profile id {id:?}: use a-z, 0-9 and -"),
            Self::InvalidName => write!(f, "invalid profile name"),
            Self::InvalidMethod(method) => {
                write!(f, "unknown login method {method:?}: saml or password")
            }
            Self::Gateway(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl From<gateway::Error> for Error {
    fn from(err: gateway::Error) -> Self {
        Self::Gateway(err)
    }
}

/// A display name: printable, one line, at most 64 characters.
pub fn validate_name(name: &str) -> Result<(), Error> {
    let name_ok = !name.trim().is_empty()
        && name.chars().count() <= MAX_NAME_LEN
        && !name.chars().any(char::is_control);
    name_ok.then_some(()).ok_or(Error::InvalidName)
}

impl Profile {
    /// Parses a profile file: `name` and `method` lines, the rest as [`Gateway::parse_config`].
    /// A missing name is the gateway host; a missing method is SAML.
    pub fn parse_config(id: ProfileId, text: &str) -> Result<Self, Error> {
        let mut name = None;
        let mut method = LoginMethod::default();
        let mut gateway_lines = String::new();
        for line in text.lines() {
            match line.split_once('=').map(|(k, v)| (k.trim(), v.trim())) {
                Some(("name", value)) => {
                    validate_name(value)?;
                    name = Some(value.to_owned());
                }
                Some(("method", value)) => method = value.parse()?,
                _ => {
                    gateway_lines.push_str(line);
                    gateway_lines.push('\n');
                }
            }
        }
        let gateway = Gateway::parse_config(&gateway_lines)?;
        Ok(Self {
            name: name.unwrap_or_else(|| gateway.host.clone()),
            id,
            method,
            gateway,
        })
    }

    pub fn to_config(&self) -> String {
        format!(
            "name = {}\nmethod = {}\n{}",
            self.name,
            self.method.as_str(),
            self.gateway.to_config()
        )
    }

    /// Reads one profile. The legacy `gateway.conf` stands in for [`LEGACY_ID`] until the
    /// configure helper moves it.
    pub fn load(id: &ProfileId) -> std::io::Result<Option<Self>> {
        let invalid = |err: Error| std::io::Error::new(std::io::ErrorKind::InvalidData, err);
        match std::fs::read_to_string(id.path()) {
            Ok(text) => Self::parse_config(id.clone(), &text)
                .map(Some)
                .map_err(invalid),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if id.as_str() != LEGACY_ID {
                    return Ok(None);
                }
                Ok(Gateway::load()?.map(Self::from_legacy))
            }
            Err(err) => Err(err),
        }
    }

    /// The single gateway of earlier versions as a profile.
    pub fn from_legacy(gateway: Gateway) -> Self {
        Self {
            // Safe: LEGACY_ID is a valid id.
            id: ProfileId(LEGACY_ID.to_owned()),
            name: gateway.host.clone(),
            method: LoginMethod::Saml,
            gateway,
        }
    }

    /// All profiles, sorted by name. A file that cannot be read is reported in the second
    /// list instead of hiding the others.
    pub fn load_all() -> (Vec<Self>, Vec<String>) {
        let mut profiles = Vec::new();
        let mut errors = Vec::new();
        match std::fs::read_dir(PROFILES_DIR) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let Some(id) = profile_id_of(&path) else {
                        continue;
                    };
                    match Self::load(&id) {
                        Ok(Some(profile)) => profiles.push(profile),
                        Ok(None) => {}
                        Err(err) => errors.push(format!("{}: {err}", path.display())),
                    }
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => errors.push(format!("{PROFILES_DIR}: {err}")),
        }
        if !profiles.iter().any(|p| p.id.as_str() == LEGACY_ID) {
            match Gateway::load() {
                Ok(Some(gateway)) => profiles.push(Self::from_legacy(gateway)),
                Ok(None) => {}
                Err(err) => errors.push(format!("{}: {err}", gateway::CONFIG_PATH)),
            }
        }
        profiles.sort_by_key(|p| p.name.to_lowercase());
        (profiles, errors)
    }
}

/// The id of a `<id>.conf` file, if the name is a valid id.
fn profile_id_of(path: &Path) -> Option<ProfileId> {
    if path.extension()? != "conf" {
        return None;
    }
    path.file_stem()?.to_str()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> ProfileId {
        s.parse().unwrap()
    }

    #[test]
    fn ids() {
        assert!("ace".parse::<ProfileId>().is_ok());
        assert!("customer-2".parse::<ProfileId>().is_ok());
        assert!("".parse::<ProfileId>().is_err());
        assert!("-x".parse::<ProfileId>().is_err());
        assert!("Ace".parse::<ProfileId>().is_err());
        assert!("../etc".parse::<ProfileId>().is_err());
        assert!("a b".parse::<ProfileId>().is_err());
        assert!("a".repeat(33).parse::<ProfileId>().is_err());
        assert_eq!(id("ace").path(), Path::new(PROFILES_DIR).join("ace.conf"));
    }

    #[test]
    fn ids_from_names() {
        assert_eq!(ProfileId::from_name("ACE").unwrap(), id("ace"));
        assert_eq!(
            ProfileId::from_name("  Kund AB / Prod ").unwrap(),
            id("kund-ab-prod")
        );
        assert_eq!(ProfileId::from_name("Åre").unwrap(), id("re"));
        assert_eq!(
            ProfileId::from_name(&"x".repeat(40))
                .unwrap()
                .as_str()
                .len(),
            32
        );
    }

    #[test]
    fn profile_round_trip() {
        let text = "name = Kund AB\nmethod = password\nhost = vpn.example.com\nport = 443\n";
        let profile = Profile::parse_config(id("kund"), text).unwrap();
        assert_eq!(profile.method, LoginMethod::Password);
        assert_eq!(
            Profile::parse_config(id("kund"), &profile.to_config()).unwrap(),
            profile
        );
    }

    #[test]
    fn defaults_and_errors() {
        let profile = Profile::parse_config(id("x"), "host = a.example\nport = 1\n").unwrap();
        assert_eq!(profile.name, "a.example");
        assert_eq!(profile.method, LoginMethod::Saml);
        assert!(Profile::parse_config(id("x"), "method = kerberos\nhost = a\nport = 1").is_err());
        assert!(Profile::parse_config(id("x"), "name = \u{7}\nhost = a\nport = 1").is_err());
        assert!(Profile::parse_config(id("x"), "name = X\n").is_err());
    }

    #[test]
    fn profile_files() {
        assert_eq!(profile_id_of(Path::new("/x/ace.conf")), Some(id("ace")));
        assert_eq!(profile_id_of(Path::new("/x/ace.conf~")), None);
        assert_eq!(profile_id_of(Path::new("/x/ACE.conf")), None);
    }
}
