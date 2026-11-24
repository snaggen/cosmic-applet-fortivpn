// SPDX-License-Identifier: GPL-3.0-only

//! Writes the root-owned gateway config. Started by the applet through pkexec; the polkit
//! policy requires admin authentication for it.
//!
//! ```text
//! cosmic-applet-fortivpn-configure set-gateway <host:port>
//! cosmic-applet-fortivpn-configure trust-cert <sha256 digest>
//! cosmic-applet-fortivpn-configure forget-cert
//! ```
//!
//! Changing the gateway forgets the trusted certificate, which belonged to the old one.

use cosmic_applet_fortivpn::gateway::{self, CertDigest, Gateway};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    process::ExitCode,
};

const USAGE: &str = "usage: cosmic-applet-fortivpn-configure \
    set-gateway <host:port> | trust-cert <sha256> | forget-cert";

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

fn run(args: &[String]) -> Result<(), String> {
    if !rustix::process::geteuid().is_root() {
        return Err("must run as root, through pkexec".into());
    }
    let current = Gateway::load().map_err(|err| format!("{}: {err}", gateway::CONFIG_PATH))?;
    let updated = apply(current, args)?;
    write_config(&updated)
}

/// Applies one command to the current config.
fn apply(current: Option<Gateway>, args: &[String]) -> Result<Gateway, String> {
    match args {
        [cmd, address] if cmd == "set-gateway" => {
            let mut new: Gateway = address.parse().map_err(|err| format!("{address}: {err}"))?;
            // Keep the trusted certificate only if the gateway stays the same.
            if let Some(current) = current
                && current.host == new.host
                && current.port == new.port
            {
                new.trusted_cert = current.trusted_cert;
            }
            Ok(new)
        }
        [cmd, digest] if cmd == "trust-cert" => {
            let digest: CertDigest = digest.parse().map_err(|err| format!("{digest}: {err}"))?;
            let mut gateway = current.ok_or("no gateway configured")?;
            gateway.trusted_cert = Some(digest);
            Ok(gateway)
        }
        [cmd] if cmd == "forget-cert" => {
            let mut gateway = current.ok_or("no gateway configured")?;
            gateway.trusted_cert = None;
            Ok(gateway)
        }
        _ => Err(USAGE.into()),
    }
}

/// Replaces the config atomically: world-readable, so the applet can read it.
fn write_config(gateway: &Gateway) -> Result<(), String> {
    let path = Path::new(gateway::CONFIG_PATH);
    let dir = path.parent().ok_or("config path has no directory")?;
    let tmp = dir.join(".gateway.conf.tmp");
    let failed = |err: std::io::Error| format!("{}: {err}", path.display());

    DirBuilder::new()
        .mode(0o755)
        .recursive(true)
        .create(dir)
        .map_err(failed)?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o644)
        .open(&tmp)
        .map_err(failed)?;
    file.write_all(gateway.to_config().as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(failed)?;
    fs::rename(&tmp, path).map_err(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "f2c935968edba48ab89c19f4291cf5449efc814665d179e32023f519dc89f1a1";

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn trusted(address: &str) -> Gateway {
        let mut gateway: Gateway = address.parse().unwrap();
        gateway.trusted_cert = Some(DIGEST.parse().unwrap());
        gateway
    }

    #[test]
    fn set_gateway_keeps_cert_only_for_same_gateway() {
        let current = Some(trusted("a.example:443"));
        let same = apply(current.clone(), &args(&["set-gateway", "a.example:443"])).unwrap();
        assert!(same.trusted_cert.is_some());
        let other = apply(current, &args(&["set-gateway", "b.example:443"])).unwrap();
        assert_eq!(other.host, "b.example");
        assert_eq!(other.trusted_cert, None);
    }

    #[test]
    fn trust_and_forget_cert() {
        let current = Some("a.example:443".parse().unwrap());
        let gw = apply(current, &args(&["trust-cert", DIGEST])).unwrap();
        assert_eq!(gw.trusted_cert.as_ref().map(|d| d.as_str()), Some(DIGEST));
        let gw = apply(Some(gw), &args(&["forget-cert"])).unwrap();
        assert_eq!(gw.trusted_cert, None);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(apply(None, &args(&["trust-cert", DIGEST])).is_err());
        assert!(apply(None, &args(&["set-gateway", "bad host:443"])).is_err());
        assert!(apply(None, &args(&["trust-cert", "xyz"])).is_err());
        assert!(apply(None, &args(&[])).is_err());
        assert!(apply(None, &args(&["set-gateway"])).is_err());
    }
}
