// SPDX-License-Identifier: GPL-3.0-only

//! COSMIC panel applet for a Fortinet SSL VPN.
//!
//! One binary, two roles: without arguments it is the panel applet (one per panel output);
//! with `--agent` it is the per-session agent that owns the tunnel and shows dialogs,
//! started by D-Bus activation.

mod agent;
mod applet;
mod bus;
mod client;
mod liveness;
mod localize;
mod login;
mod notify;
mod sleep;
mod state;
mod stats;
mod tunnel;

/// Log filter when `RUST_LOG` is unset. State changes in the journal are what makes a problem
/// in the panel traceable.
const DEFAULT_LOG_FILTER: &str = "warn,cosmic_applet_fortivpn=info";

fn main() -> cosmic::iced::Result {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(DEFAULT_LOG_FILTER));
    // stderr, not the default stdout: the panel passes only an applet's stderr to the journal.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    localize::localize();

    if std::env::args().nth(1).as_deref() == Some("--agent") {
        agent::run()
    } else {
        cosmic::applet::run::<applet::Applet>(())
    }
}
