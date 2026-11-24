// SPDX-License-Identifier: GPL-3.0-only

//! Writes the root-owned VPN profiles. Started by the agent through pkexec; polkit asks for an
//! admin password, since a profile decides where the VPN connects and which certificate counts
//! as trusted.
//!
//! ```text
//! cosmic-applet-fortivpn-configure save-profile <id> <name> <saml|password> <host:port>
//! cosmic-applet-fortivpn-configure remove-profile <id>
//! cosmic-applet-fortivpn-configure trust-cert <id> <sha256 digest>
//! cosmic-applet-fortivpn-configure forget-cert <id>
//! cosmic-applet-fortivpn-configure trust-cert-once <id> <sha256 digest>
//! ```
//!
//! Changing a profile's gateway forgets its trusted certificate, which belonged to the old one.
//! `trust-cert-once` trusts a certificate for the next connection of that profile only: the
//! helper reads it from the runtime directory and removes it when that connection ends.
//!
//! The single `gateway.conf` of earlier versions is moved to the profile `default` on the
//! first run.
//!
//! This runs as root: it must not panic.

use cosmic_applet_fortivpn::{
    RUN_DIR, SESSION_TRUST_PATH,
    gateway::{self, CertDigest, Gateway},
    profile::{self, LoginMethod, PROFILES_DIR, Profile, ProfileId},
};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    process::ExitCode,
};

const USAGE: &str = "usage: cosmic-applet-fortivpn-configure \
    save-profile <id> <name> <saml|password> <host:port> | remove-profile <id> | \
    trust-cert <id> <sha256> | forget-cert <id> | trust-cert-once <id> <sha256>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("cosmic-applet-fortivpn-configure: {err}");
            ExitCode::FAILURE
        }
    }
}

/// What a command does to the profiles.
#[derive(Debug, PartialEq, Eq)]
enum Change {
    Write(Profile),
    Remove(ProfileId),
    TrustOnce(ProfileId, CertDigest),
}

fn run(args: &[String]) -> Result<(), String> {
    if !rustix::process::geteuid().is_root() {
        return Err("must run as root, through pkexec".into());
    }
    migrate_legacy()?;
    let id = args
        .get(1)
        .ok_or(USAGE)?
        .parse::<ProfileId>()
        .map_err(|err| err.to_string())?;
    let current = Profile::load(&id).map_err(|err| format!("{}: {err}", id.path().display()))?;
    match plan(current, &id, args)? {
        Change::Write(profile) => {
            write_profile(&profile)?;
            clear_session_trust()
        }
        Change::Remove(id) => {
            match fs::remove_file(id.path()) {
                Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                    return Err(format!("{}: {err}", id.path().display()));
                }
                _ => {}
            }
            clear_session_trust()
        }
        Change::TrustOnce(id, digest) => write_session_trust(&id, &digest),
    }
}

/// Decides what a command changes, from the profile as it is now.
fn plan(current: Option<Profile>, id: &ProfileId, args: &[String]) -> Result<Change, String> {
    let existing = || current.clone().ok_or_else(|| format!("no profile {id}"));
    let digest = |s: &String| s.parse::<CertDigest>().map_err(|err| format!("{s}: {err}"));
    match args {
        [cmd, _, name, method, address] if cmd == "save-profile" => {
            profile::validate_name(name).map_err(|err| err.to_string())?;
            let method: LoginMethod = method
                .parse()
                .map_err(|err: profile::Error| err.to_string())?;
            let mut gateway: Gateway =
                address.parse().map_err(|err| format!("{address}: {err}"))?;
            // Keep the trusted certificate only if the gateway stays the same.
            if let Some(current) = &current
                && current.gateway.host == gateway.host
                && current.gateway.port == gateway.port
            {
                gateway.trusted_cert = current.gateway.trusted_cert.clone();
            }
            Ok(Change::Write(Profile {
                id: id.clone(),
                name: name.clone(),
                method,
                gateway,
            }))
        }
        [cmd, _] if cmd == "remove-profile" => {
            existing()?;
            Ok(Change::Remove(id.clone()))
        }
        [cmd, _, sha] if cmd == "trust-cert" => {
            let mut profile = existing()?;
            profile.gateway.trusted_cert = Some(digest(sha)?);
            Ok(Change::Write(profile))
        }
        [cmd, _] if cmd == "forget-cert" => {
            let mut profile = existing()?;
            profile.gateway.trusted_cert = None;
            Ok(Change::Write(profile))
        }
        [cmd, _, sha] if cmd == "trust-cert-once" => {
            existing()?;
            Ok(Change::TrustOnce(id.clone(), digest(sha)?))
        }
        _ => Err(USAGE.into()),
    }
}

/// Moves the legacy `gateway.conf` to the profile `default`, unless that exists already.
fn migrate_legacy() -> Result<(), String> {
    let legacy = Path::new(gateway::CONFIG_PATH);
    let Some(gateway) = Gateway::load().map_err(|err| format!("{}: {err}", legacy.display()))?
    else {
        return Ok(());
    };
    let profile = Profile::from_legacy(gateway);
    if !profile.id.path().exists() {
        write_profile(&profile)?;
    }
    fs::remove_file(legacy).map_err(|err| format!("{}: {err}", legacy.display()))
}

/// Replaces a profile file atomically. World-readable, so the agent can list the profiles;
/// it holds no secrets.
fn write_profile(profile: &Profile) -> Result<(), String> {
    let path = profile.id.path();
    let tmp = Path::new(PROFILES_DIR).join(format!(".{}.tmp", profile.id));
    let failed = |err: std::io::Error| format!("{}: {err}", path.display());

    DirBuilder::new()
        .mode(0o755)
        .recursive(true)
        .create(PROFILES_DIR)
        .map_err(failed)?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o644)
        .open(&tmp)
        .map_err(failed)?;
    file.write_all(profile.to_config().as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(failed)?;
    fs::rename(&tmp, &path).map_err(failed)
}

/// Trusts a certificate for the next connection of a profile: root-only, in the helper's
/// runtime dir.
fn write_session_trust(id: &ProfileId, digest: &CertDigest) -> Result<(), String> {
    let failed = |err: std::io::Error| format!("{SESSION_TRUST_PATH}: {err}");
    DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(RUN_DIR)
        .map_err(failed)?;
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(SESSION_TRUST_PATH)
        .and_then(|mut file| file.write_all(format!("{id} {digest}\n").as_bytes()))
        .map_err(failed)
}

/// A certificate trusted once belonged to the profiles as they were.
fn clear_session_trust() -> Result<(), String> {
    match fs::remove_file(SESSION_TRUST_PATH) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("{SESSION_TRUST_PATH}: {err}"))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "f2c935968edba48ab89c19f4291cf5449efc814665d179e32023f519dc89f1a1";

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn id() -> ProfileId {
        "ace".parse().unwrap()
    }

    fn trusted(address: &str) -> Profile {
        let mut gateway: Gateway = address.parse().unwrap();
        gateway.trusted_cert = Some(DIGEST.parse().unwrap());
        Profile {
            id: id(),
            name: "ACE".into(),
            method: LoginMethod::Saml,
            gateway,
        }
    }

    fn written(change: Change) -> Profile {
        match change {
            Change::Write(profile) => profile,
            other => panic!("expected a write, got {other:?}"),
        }
    }

    #[test]
    fn save_keeps_cert_only_for_same_gateway() {
        let current = Some(trusted("a.example:443"));
        let same = written(
            plan(
                current.clone(),
                &id(),
                &args(&[
                    "save-profile",
                    "ace",
                    "ACE Media",
                    "password",
                    "a.example:443",
                ]),
            )
            .unwrap(),
        );
        assert!(same.gateway.trusted_cert.is_some());
        assert_eq!(same.name, "ACE Media");
        assert_eq!(same.method, LoginMethod::Password);
        let other = written(
            plan(
                current,
                &id(),
                &args(&["save-profile", "ace", "ACE", "saml", "b.example:443"]),
            )
            .unwrap(),
        );
        assert_eq!(other.gateway.host, "b.example");
        assert_eq!(other.gateway.trusted_cert, None);
    }

    #[test]
    fn trust_and_forget_cert() {
        let mut current = trusted("a.example:443");
        current.gateway.trusted_cert = None;
        let profile =
            written(plan(Some(current), &id(), &args(&["trust-cert", "ace", DIGEST])).unwrap());
        assert_eq!(
            profile.gateway.trusted_cert.as_ref().map(|d| d.as_str()),
            Some(DIGEST)
        );
        let profile = written(plan(Some(profile), &id(), &args(&["forget-cert", "ace"])).unwrap());
        assert_eq!(profile.gateway.trusted_cert, None);
    }

    #[test]
    fn remove_and_trust_once() {
        let current = Some(trusted("a.example:443"));
        assert_eq!(
            plan(current.clone(), &id(), &args(&["remove-profile", "ace"])),
            Ok(Change::Remove(id()))
        );
        assert_eq!(
            plan(current, &id(), &args(&["trust-cert-once", "ace", DIGEST])),
            Ok(Change::TrustOnce(id(), DIGEST.parse().unwrap()))
        );
    }

    #[test]
    fn rejects_bad_input() {
        let bad =
            |current: Option<Profile>, list: &[&str]| plan(current, &id(), &args(list)).is_err();
        assert!(bad(None, &["trust-cert", "ace", DIGEST]), "no such profile");
        assert!(bad(None, &["remove-profile", "ace"]));
        assert!(bad(
            None,
            &["save-profile", "ace", "N", "saml", "bad host:443"]
        ));
        assert!(bad(
            None,
            &["save-profile", "ace", "N", "kerberos", "a.example:1"]
        ));
        assert!(bad(
            None,
            &["save-profile", "ace", "\u{7}", "saml", "a.example:1"]
        ));
        assert!(bad(
            Some(trusted("a.example:1")),
            &["trust-cert", "ace", "xyz"]
        ));
        assert!(bad(None, &[]));
        assert!(bad(None, &["set-gateway", "a.example:1"]));
    }

    #[test]
    fn legacy_id_is_valid() {
        assert!(profile::LEGACY_ID.parse::<ProfileId>().is_ok());
    }
}
