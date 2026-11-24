// SPDX-License-Identifier: GPL-3.0-only

//! Runs openfortivpn as root on behalf of the applet. Started by the applet through pkexec.
//!
//! Reads one request line from stdin (the only input taken from the caller: a profile id, the
//! login, maybe an intermediate certificate), runs openfortivpn against that root-owned
//! profile, and reports events on stdout. When stdin
//! closes, because the applet disconnects or exits, openfortivpn is stopped with SIGTERM so it
//! can restore routes and DNS. Its last step, logging out at the gateway, can hang when the
//! network is gone; once the rest is done it gets [`LOGOUT_GRACE`], then SIGKILL.
//!
//! This runs as root: it must not panic, and it never passes caller input to openfortivpn
//! other than validated credentials. An intermediate certificate from the caller is only used
//! after the helper validated the gateway's chain with it against the system roots itself.

use cosmic_applet_fortivpn::{
    RUN_DIR, SESSION_TRUST_PATH, certcheck,
    gateway::{CertDigest, Gateway},
    openfortivpn::{self, OutputParser},
    profile::{LoginMethod, Profile, ProfileId},
    protocol::{Credentials, Event, HelperError, Login, Request},
};
use rustix::{
    fs::{FlockOperation, flock},
    process::{Pid, Signal, kill_process},
};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

/// Upper bound for the request line: credentials, and an intermediate certificate in hex.
const MAX_REQUEST_LEN: u64 = 8192;

/// How long openfortivpn may take to log out at the gateway after it restored routes and DNS.
const LOGOUT_GRACE: Duration = Duration::from_secs(3);

/// How long openfortivpn may take to stop at all after SIGTERM.
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// openfortivpn's line once routes, DNS and the tunnel are cleaned up; only the logout at the
/// gateway follows.
const CLEANED_UP: &str = "Closed connection to gateway";

/// What the main loop waits for.
enum Input {
    /// A line from openfortivpn's stdout or stderr.
    Line(String),
    /// One of openfortivpn's output streams ended.
    OutputClosed,
    /// The applet closed our stdin: disconnect.
    StdinClosed,
}

fn main() -> ExitCode {
    let mut events = Events(io::stdout());
    match run(&mut events) {
        Ok(code) => {
            events.send(&Event::Exited(code));
            ExitCode::SUCCESS
        }
        Err(err) => {
            events.send(&Event::Error(err));
            ExitCode::FAILURE
        }
    }
}

/// Writes events to stdout, one line each.
struct Events(io::Stdout);

impl Events {
    /// Sends an event. A failed write means the applet is gone; the closed stdin that comes
    /// with it stops the tunnel, so the error needs no handling here.
    fn send(&mut self, event: &Event) {
        let _ = self
            .0
            .write_all(event.to_line().as_bytes())
            .and_then(|()| self.0.flush());
    }
}

fn run(events: &mut Events) -> Result<Option<i32>, HelperError> {
    if !rustix::process::geteuid().is_root() {
        return Err(HelperError::Failed(
            "must run as root, through pkexec".into(),
        ));
    }
    let mut stdin = BufReader::new(io::stdin());
    let request = read_request(&mut stdin)?;
    let profile = match Profile::load(&request.profile) {
        Ok(Some(profile)) => profile,
        Ok(None) => return Err(HelperError::NotConfigured),
        Err(err) => {
            return Err(HelperError::Failed(format!(
                "profile {}: {err}",
                request.profile
            )));
        }
    };
    let credentials = match (&request.login, profile.method) {
        (Login::Saml, LoginMethod::Saml) => None,
        (Login::Password(credentials), LoginMethod::Password) => Some(credentials),
        // The profile, set up by an admin, decides how it logs in.
        _ => return Err(HelperError::BadRequest),
    };

    let _lock = lock()?;
    let mut trusted: Vec<CertDigest> = read_session_trust(&profile.id).into_iter().collect();
    if let Some(intermediate) = &request.intermediate {
        trusted.extend(verify_intermediate(&profile.gateway, intermediate, events));
    }
    let config = ConfigFile::write(&profile.gateway, &trusted, credentials)?;
    let mut child = spawn(&config.path, &request.login)?;

    let (tx, rx) = mpsc::channel();
    forward_lines(child.stdout.take(), tx.clone());
    forward_lines(child.stderr.take(), tx.clone());
    watch_stdin(stdin, tx);

    supervise(&mut child, &rx, events);

    let status = child
        .wait()
        .map_err(|err| HelperError::Failed(format!("waiting for openfortivpn: {err}")))?;
    Ok(status.code())
}

/// Reads and validates the request line.
fn read_request(stdin: &mut impl BufRead) -> Result<Request, HelperError> {
    let mut line = String::new();
    stdin
        .take(MAX_REQUEST_LEN)
        .read_line(&mut line)
        .map_err(|_| HelperError::BadRequest)?;
    let line = line.strip_suffix('\n').ok_or(HelperError::BadRequest)?;
    Request::parse(line).map_err(|_| HelperError::BadRequest)
}

/// Takes the lock that allows only one tunnel at a time. Held until the returned file drops.
fn lock() -> Result<File, HelperError> {
    let failed = |err: io::Error| HelperError::Failed(format!("{RUN_DIR}: {err}"));
    DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(RUN_DIR)
        .map_err(failed)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(Path::new(RUN_DIR).join("lock"))
        .map_err(failed)?;
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(file),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(HelperError::Busy),
        Err(err) => Err(failed(err.into())),
    }
}

/// Validates the gateway's chain with the caller's intermediate against the system roots, and
/// if it holds, returns the gateway certificate's digest to trust for this connection.
fn verify_intermediate(
    gateway: &Gateway,
    intermediate: &[u8],
    events: &mut Events,
) -> Option<CertDigest> {
    match certcheck::verify_with_intermediate(gateway, intermediate) {
        Ok(Some(digest)) => {
            events.send(&Event::Log("certificate chain completed".into()));
            Some(digest)
        }
        Ok(None) => {
            events.send(&Event::Log("intermediate certificate not used".into()));
            None
        }
        Err(err) => {
            events.send(&Event::Log(format!("intermediate certificate: {err}")));
            None
        }
    }
}

/// openfortivpn's config file, removed again on drop together with the session trust,
/// which is valid for this one connection. Holds the password for a password login: it lives
/// in the root-only runtime directory, and only while the connection runs.
struct ConfigFile {
    path: PathBuf,
}

impl ConfigFile {
    fn write(
        gateway: &Gateway,
        trusted: &[CertDigest],
        credentials: Option<&Credentials>,
    ) -> Result<Self, HelperError> {
        let path = Path::new(RUN_DIR).join("openfortivpn.conf");
        let text = openfortivpn::config_file(gateway, trusted, credentials);
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut file| file.write_all(text.as_bytes()))
            .map_err(|err| HelperError::Failed(format!("{}: {err}", path.display())))?;
        Ok(Self { path })
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(SESSION_TRUST_PATH);
    }
}

/// The certificate an admin trusted for this profile's next connection only, if any. Written
/// by `configure trust-cert-once` as `<profile> <digest>`; an unreadable or invalid file, or
/// one for another profile, trusts nothing.
fn read_session_trust(profile: &ProfileId) -> Option<CertDigest> {
    parse_session_trust(&fs::read_to_string(SESSION_TRUST_PATH).ok()?, profile)
}

fn parse_session_trust(text: &str, profile: &ProfileId) -> Option<CertDigest> {
    let (id, digest) = text.trim().split_once(' ')?;
    (id == profile.as_str()).then(|| digest.parse().ok())?
}

/// Starts openfortivpn with our config file and a clean environment. A password login needs
/// no option: the credentials are in the config file.
fn spawn(config: &Path, login: &Login) -> Result<Child, HelperError> {
    let mut command = Command::new(openfortivpn::OPENFORTIVPN);
    command.arg("-c").arg(config);
    if let Login::Saml = login {
        command.arg("--saml-login");
    }
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| HelperError::Failed(format!("{}: {err}", openfortivpn::OPENFORTIVPN)))
}

/// Forwards lines from one of openfortivpn's output streams until it closes.
fn forward_lines(stream: Option<impl Read + Send + 'static>, tx: mpsc::Sender<Input>) {
    let Some(stream) = stream else {
        let _ = tx.send(Input::OutputClosed);
        return;
    };
    thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let line = String::from_utf8_lossy(&buf).into_owned();
                    if tx.send(Input::Line(line)).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = tx.send(Input::OutputClosed);
    });
}

/// Reports when our stdin closes. Anything the applet writes after the request is ignored.
fn watch_stdin(mut stdin: impl Read + Send + 'static, tx: mpsc::Sender<Input>) {
    thread::spawn(move || {
        let _ = io::copy(&mut stdin, &mut io::sink());
        let _ = tx.send(Input::StdinClosed);
    });
}

/// Relays openfortivpn's output as events until both its streams close. Stops it when the
/// applet disconnects, or when it is stuck after an error it does not exit on by itself.
fn supervise(child: &mut Child, rx: &mpsc::Receiver<Input>, events: &mut Events) {
    let mut parser = OutputParser::default();
    let mut stop = Stop::default();
    let mut open_streams = 2;

    while open_streams > 0 {
        let input = match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(input) => input,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if stop.kill_due(Instant::now()) {
                    let _ = kill_process(Pid::from_child(child), Signal::KILL);
                }
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        match input {
            Input::Line(line) => {
                stop.saw_line(&line, Instant::now());
                let Some(event) = parser.parse_line(&line) else {
                    continue;
                };
                let fatal = matches!(event, Event::CertUntrusted(_) | Event::AuthFailed);
                events.send(&event);
                if fatal && stop.ask(Instant::now()) {
                    let _ = kill_process(Pid::from_child(child), Signal::TERM);
                }
            }
            Input::OutputClosed => open_streams -= 1,
            Input::StdinClosed => {
                if stop.ask(Instant::now()) {
                    let _ = kill_process(Pid::from_child(child), Signal::TERM);
                }
            }
        }
    }
}

/// Stopping openfortivpn: SIGTERM first, SIGKILL if it hangs after that.
#[derive(Debug, Default)]
struct Stop {
    asked_at: Option<Instant>,
    cleaned_up_at: Option<Instant>,
    killed: bool,
}

impl Stop {
    /// Records the request to stop; `true` the first time, when SIGTERM is to be sent.
    fn ask(&mut self, now: Instant) -> bool {
        if self.asked_at.is_some() {
            return false;
        }
        self.asked_at = Some(now);
        true
    }

    /// Notes openfortivpn's line saying it cleaned up.
    fn saw_line(&mut self, line: &str, now: Instant) {
        if self.asked_at.is_some() && self.cleaned_up_at.is_none() && line.contains(CLEANED_UP) {
            self.cleaned_up_at = Some(now);
        }
    }

    /// Whether to send SIGKILL now: the logout hangs after the cleanup, or the whole stop takes
    /// too long. Answers `true` once.
    fn kill_due(&mut self, now: Instant) -> bool {
        let Some(asked) = self.asked_at else {
            return false;
        };
        let logout_hangs = self
            .cleaned_up_at
            .is_some_and(|cleaned| now.saturating_duration_since(cleaned) >= LOGOUT_GRACE);
        let too_long = now.saturating_duration_since(asked) >= STOP_TIMEOUT;
        if self.killed || !(logout_hangs || too_long) {
            return false;
        }
        self.killed = true;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_after_a_hanging_logout() {
        let t0 = Instant::now();
        let s = |n| t0 + Duration::from_secs(n);
        let mut stop = Stop::default();
        // Lines before the stop was asked for do not count.
        stop.saw_line("INFO:   Closed connection to gateway.", s(0));
        assert!(stop.ask(s(1)));
        assert!(!stop.ask(s(1)), "SIGTERM only once");
        assert!(!stop.kill_due(s(10)));
        stop.saw_line("INFO:   Closed connection to gateway.\n", s(10));
        assert!(!stop.kill_due(s(12)));
        assert!(stop.kill_due(s(13)));
        assert!(!stop.kill_due(s(14)), "SIGKILL only once");
    }

    #[test]
    fn kill_when_stopping_takes_too_long() {
        let t0 = Instant::now();
        let mut stop = Stop::default();
        assert!(
            !stop.kill_due(t0 + STOP_TIMEOUT),
            "nothing to kill before a stop"
        );
        stop.ask(t0);
        assert!(!stop.kill_due(t0 + STOP_TIMEOUT - Duration::from_secs(1)));
        assert!(stop.kill_due(t0 + STOP_TIMEOUT));
    }

    #[test]
    fn session_trust_only_for_its_profile() {
        const DIGEST: &str = "f2c935968edba48ab89c19f4291cf5449efc814665d179e32023f519dc89f1a1";
        let ace: ProfileId = "ace".parse().unwrap();
        let other: ProfileId = "other".parse().unwrap();
        let text = format!("ace {DIGEST}\n");
        assert_eq!(
            parse_session_trust(&text, &ace).map(|d| d.to_string()),
            Some(DIGEST.to_owned())
        );
        assert_eq!(parse_session_trust(&text, &other), None);
        assert_eq!(
            parse_session_trust(DIGEST, &ace),
            None,
            "old format trusts nothing"
        );
        assert_eq!(parse_session_trust("ace nothex", &ace), None);
    }

    #[test]
    fn request_line_must_be_complete_and_valid() {
        let read = |input: &str| read_request(&mut BufReader::new(input.as_bytes()));
        let saml = Request {
            profile: "ace".parse().unwrap(),
            login: Login::Saml,
            intermediate: None,
        };
        assert_eq!(read("saml-login\tprofile=ace\n"), Ok(saml.clone()));
        assert_eq!(read("saml-login\tprofile=ace\nrest"), Ok(saml));
        assert_eq!(
            read("saml-login\tprofile=ace"),
            Err(HelperError::BadRequest)
        );
        assert_eq!(read(""), Err(HelperError::BadRequest));
        assert_eq!(read("-c /tmp/x\n"), Err(HelperError::BadRequest));
        let endless = "a".repeat(MAX_REQUEST_LEN as usize + 10);
        assert_eq!(read(&endless), Err(HelperError::BadRequest));
    }
}
