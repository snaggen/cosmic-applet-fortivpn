// SPDX-License-Identifier: GPL-3.0-only

//! COSMIC panel applet for a Fortinet SSL VPN.

mod applet;
mod localize;
mod state;
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

    cosmic::applet::run::<applet::Applet>(())
}
