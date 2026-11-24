// SPDX-License-Identifier: GPL-3.0-only

//! The SAML login window: a WebKitGTK view that takes the user through the gateway's SAML
//! login, in place of the system browser. Started by the agent; a separate process keeps GTK's
//! main loop and WebKit out of the agent.
//!
//! ```text
//! cosmic-applet-fortivpn-login --url https://<gw>:<port>/remote/saml/start?redirect=1
//!     --host <gateway host> --data-dir <dir> [--trusted-cert <sha256>]
//! ```
//!
//! At the end of the login the gateway redirects to openfortivpn's listener,
//! `http://127.0.0.1:8020/?id=<id>`. The window does not follow that redirect: it prints the id
//! on stdout and exits, and the agent starts openfortivpn and hands it the id (see
//! [`cosmic_applet_fortivpn::saml`]). openfortivpn only waits 50 seconds for the redirect, too
//! short for a login with a second factor, so it cannot already be listening during the login.
//!
//! Exit 0 with the id on stdout, 2 if the user closed the window, 1 on any other failure,
//! explained on stderr.
//!
//! The profile in `--data-dir` keeps the IdP session (cookies) between runs, so while it is
//! valid the login completes without the user doing anything. The window therefore starts
//! hidden and only appears once a page has finished loading and no other load followed within
//! [`SETTLE`]: the IdP waits for input. It has a fixed size, which makes tiling compositors
//! (cosmic-comp) float it instead of re-tiling the workspace.
//!
//! The gateway may not send its full certificate chain. WebKit then refuses it like
//! openfortivpn does; the login accepts it only for the gateway host and only if its SHA-256
//! digest is the one passed with `--trusted-cert`.

use cosmic_applet_fortivpn::{
    gateway::CertDigest,
    saml::{self, SamlId},
};
use gtk::prelude::*;
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    path::{Path, PathBuf},
    process::ExitCode,
    rc::Rc,
    time::Duration,
};
use webkit2gtk::{
    CookieManagerExt, CookiePersistentStorage, LoadEvent, NavigationPolicyDecision,
    NavigationPolicyDecisionExt, PolicyDecisionExt, URIRequestExt, WebContext, WebContextExt,
    WebView, WebViewExt, WebsiteDataManager, WebsiteDataManagerExt, glib,
};

/// Show the window when a loaded page stays this long: the IdP wants input. A silent login
/// moves on to the next page within milliseconds (auto-submitted forms).
const SETTLE: Duration = Duration::from_millis(1500);

/// Fixed window size; see the module docs on floating.
const WINDOW_SIZE: (i32, i32) = (520, 680);

/// Exit code when the user closed the window.
const EXIT_CANCELLED: u8 = 2;

/// How the login ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Running,
    LoggedIn,
    Cancelled,
}

struct Args {
    url: String,
    host: String,
    data_dir: PathBuf,
    trusted_cert: Option<CertDigest>,
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(err) => {
            eprintln!("cosmic-applet-fortivpn-login: {err}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(err) = gtk::init() {
        eprintln!("cosmic-applet-fortivpn-login: GTK: {err}");
        return ExitCode::FAILURE;
    }
    match run(&args) {
        Outcome::LoggedIn => ExitCode::SUCCESS,
        Outcome::Cancelled => ExitCode::from(EXIT_CANCELLED),
        Outcome::Running => ExitCode::FAILURE,
    }
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut url = None;
    let mut host = None;
    let mut data_dir = None;
    let mut trusted_cert = None;
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--url" => url = Some(value),
            "--host" => host = Some(value),
            "--data-dir" => data_dir = Some(PathBuf::from(value)),
            "--trusted-cert" => {
                trusted_cert = Some(value.parse().map_err(|err| format!("{value}: {err}"))?);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        url: url.ok_or("--url is required")?,
        host: host.ok_or("--host is required")?,
        data_dir: data_dir.ok_or("--data-dir is required")?,
        trusted_cert,
    })
}

/// Runs the login until the redirect to openfortivpn's listener or until the window is closed.
fn run(args: &Args) -> Outcome {
    let context = web_context(&args.data_dir);
    let view = WebView::with_context(&context);
    let outcome = Rc::new(Cell::new(Outcome::Running));

    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title(&args.host);
    window.set_default_size(WINDOW_SIZE.0, WINDOW_SIZE.1);
    window.set_size_request(WINDOW_SIZE.0, WINDOW_SIZE.1);
    window.set_resizable(false);
    window.add(&view);
    {
        let outcome = outcome.clone();
        window.connect_delete_event(move |_, _| {
            outcome.set(Outcome::Cancelled);
            gtk::main_quit();
            glib::Propagation::Proceed
        });
    }

    accept_pinned_certificate(&view, &context, &args.host, args.trusted_cert.clone());
    log_loads(&view);
    stop_at_listener(&view, outcome.clone());
    show_when_settled(&view, &window, outcome.clone());

    view.load_uri(&args.url);
    gtk::main();
    outcome.get()
}

/// A web context with its data in `data_dir`, so the IdP session survives restarts.
fn web_context(data_dir: &Path) -> WebContext {
    let path = |name: &str| data_dir.join(name).to_string_lossy().into_owned();
    let manager = WebsiteDataManager::builder()
        .base_data_directory(path("data"))
        .base_cache_directory(path("cache"))
        .build();
    let context = WebContext::with_website_data_manager(&manager);
    let cookies = manager
        .cookie_manager()
        .or_else(|| context.cookie_manager());
    let cookies = match cookies {
        Some(cookies) => cookies,
        // Deliberate startup failure: WebKit always has a cookie manager; without one the IdP
        // session would not persist and every connect would need a full login.
        None => {
            eprintln!("cosmic-applet-fortivpn-login: no cookie manager");
            std::process::exit(1);
        }
    };
    cookies.set_persistent_storage(&path("cookies.sqlite"), CookiePersistentStorage::Sqlite);
    context
}

/// Accepts a certificate that fails validation only for the gateway and only if it is the
/// pinned one, then reloads. Everything else fails as usual.
fn accept_pinned_certificate(
    view: &WebView,
    context: &WebContext,
    host: &str,
    trusted: Option<CertDigest>,
) {
    let Some(trusted) = trusted else {
        return;
    };
    let context = context.clone();
    let host = host.to_owned();
    view.connect_load_failed_with_tls_errors(move |view, uri, cert, _errors| {
        if host_of(uri) != Some(host.as_str()) {
            return false;
        }
        let Some(der) = cert.certificate() else {
            return false;
        };
        if CertDigest::from_sha256(Sha256::digest(&der).into()) != trusted {
            eprintln!("cosmic-applet-fortivpn-login: certificate of {host} is not the trusted one");
            return false;
        }
        context.allow_tls_certificate_for_host(cert, &host);
        view.load_uri(uri);
        true
    });
}

/// Shows the window once a finished page is not followed by another load within [`SETTLE`].
/// While the IdP session is valid the login runs through without ever settling, so the window
/// never appears.
fn show_when_settled(view: &WebView, window: &gtk::Window, outcome: Rc<Cell<Outcome>>) {
    // Counts load starts; a timer only shows the window if no load started after its page.
    let loads = Rc::new(Cell::new(0u64));
    let window = window.clone();
    view.connect_load_changed(move |_, event| match event {
        LoadEvent::Started => loads.set(loads.get() + 1),
        LoadEvent::Finished => {
            let seen = loads.get();
            let loads = loads.clone();
            let window = window.clone();
            let outcome = outcome.clone();
            glib::timeout_add_local_once(SETTLE, move || {
                if loads.get() == seen && outcome.get() == Outcome::Running && !window.is_visible()
                {
                    window.show_all();
                    window.present();
                }
            });
        }
        _ => {}
    });
}

/// Logs each loaded page, without the query: it can carry SAML tokens.
fn log_loads(view: &WebView) {
    view.connect_load_changed(|view, event| {
        let uri = view.uri().map(|u| u.to_string()).unwrap_or_default();
        if event == LoadEvent::Finished && !uri.is_empty() {
            let page = uri.split(['?', '#']).next().unwrap_or_default();
            eprintln!("cosmic-applet-fortivpn-login: loaded {page}");
        }
    });
}

/// Stops the navigation to openfortivpn's listener and ends the login with its id on stdout.
fn stop_at_listener(view: &WebView, outcome: Rc<Cell<Outcome>>) {
    view.connect_decide_policy(move |_, decision, _| {
        let Some(navigation) = decision.downcast_ref::<NavigationPolicyDecision>() else {
            return false;
        };
        let uri = navigation
            .navigation_action()
            .and_then(|action| action.request())
            .and_then(|request| request.uri())
            .map(|uri| uri.to_string())
            .unwrap_or_default();
        if !uri.starts_with(saml::LISTENER_URL) {
            return false;
        }
        decision.ignore();
        if outcome.get() == Outcome::Running {
            match SamlId::from_redirect(&uri) {
                Some(id) => {
                    println!("{}", id.as_str());
                    outcome.set(Outcome::LoggedIn);
                }
                None => eprintln!("cosmic-applet-fortivpn-login: redirect without a valid id"),
            }
            gtk::main_quit();
        }
        true
    });
}

/// The host part of an `https://host[:port]/…` URL.
fn host_of(uri: &str) -> Option<&str> {
    let rest = uri.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host);
    Some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_https_urls() {
        assert_eq!(
            host_of("https://vpn.example.com:10443/remote/saml/start"),
            Some("vpn.example.com")
        );
        assert_eq!(
            host_of("https://login.microsoftonline.com/x?y"),
            Some("login.microsoftonline.com")
        );
        assert_eq!(host_of("https://a.example"), Some("a.example"));
        assert_eq!(host_of("http://vpn.example.com/"), None);
    }

    #[test]
    fn args() {
        let args = |list: &[&str]| parse_args(list.iter().map(|s| s.to_string()));
        let parsed = args(&[
            "--url",
            "https://a.example/",
            "--host",
            "a.example",
            "--data-dir",
            "/tmp/x",
        ])
        .unwrap();
        assert_eq!(parsed.host, "a.example");
        assert!(parsed.trusted_cert.is_none());
        assert!(args(&["--url", "u", "--host", "h"]).is_err());
        assert!(args(&["--url"]).is_err());
        assert!(args(&["--bogus", "x"]).is_err());
        assert!(
            args(&[
                "--url",
                "u",
                "--host",
                "h",
                "--data-dir",
                "d",
                "--trusted-cert",
                "nothex"
            ])
            .is_err()
        );
    }
}
