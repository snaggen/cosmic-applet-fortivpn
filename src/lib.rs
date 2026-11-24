// SPDX-License-Identifier: GPL-3.0-only

//! Code shared by the applet and its privileged helpers.
//!
//! The applet runs as the user. Two small helpers run as root through pkexec:
//!
//! - `cosmic-applet-fortivpn-helper` runs openfortivpn. It reads one [`protocol::Request`]
//!   from stdin, reports [`protocol::Event`]s on stdout, and disconnects when stdin closes.
//! - `cosmic-applet-fortivpn-configure` writes the root-owned [`gateway::Gateway`] config.
//!
//! The helper takes nothing from the caller but the login (a cookie or SAML login), so the
//! gateway and the trusted certificate are only ever changed by an admin.

pub mod certcheck;
pub mod gateway;
pub mod openfortivpn;
pub mod protocol;
pub mod saml;

/// Directory of the root-only helpers. Must match where `just install-helper` puts them and
/// the paths in the polkit policy.
pub const LIBEXEC_DIR: &str = match option_env!("FORTIVPN_LIBEXECDIR") {
    Some(dir) => dir,
    None => "/usr/local/libexec",
};

/// File name of the helper that runs openfortivpn.
pub const HELPER_NAME: &str = "cosmic-applet-fortivpn-helper";

/// File name of the helper that writes the gateway config.
pub const CONFIGURE_NAME: &str = "cosmic-applet-fortivpn-configure";

/// Runtime directory of the root helpers (mode 0700). Only root can write `/run`.
pub const RUN_DIR: &str = "/run/cosmic-applet-fortivpn";

/// A certificate digest trusted for the next connection only, written by
/// `configure trust-cert-once` and removed by the helper when that connection ends.
pub const SESSION_TRUST_PATH: &str = "/run/cosmic-applet-fortivpn/session-trust";
