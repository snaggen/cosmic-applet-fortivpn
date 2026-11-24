// SPDX-License-Identifier: GPL-3.0-only

//! Runs openfortivpn as root on behalf of the applet. Started by the applet through pkexec.
//!
//! Reads one request line from stdin (the only input taken from the caller), runs openfortivpn
//! against the gateway in the root-owned config, and reports events on stdout. When stdin
//! closes, because the applet disconnects or exits, openfortivpn is stopped with SIGTERM so it
//! can restore routes and DNS.
//!
//! This runs as root: it must not panic, and it never passes caller input to openfortivpn
//! other than the validated cookie.

use cosmic_applet_fortivpn::{
    gateway::Gateway,
    openfortivpn::{self, OutputParser},
    protocol::{Event, HelperError, Request},
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
    process::{Child, ChildStdin, Command, ExitCode, Stdio},
    sync::mpsc,
    thread,
};

/// Runtime directory for the lock and openfortivpn's config. Only root can write `/run`.
const RUN_DIR: &str = "/run/cosmic-applet-fortivpn";

/// Upper bound for the request line; a cookie is at most 4000 bytes.
const MAX_REQUEST_LEN: u64 = 8192;

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
    let gateway = match Gateway::load() {
        Ok(Some(gateway)) => gateway,
        Ok(None) => return Err(HelperError::NotConfigured),
        Err(err) => return Err(HelperError::Failed(format!("gateway config: {err}"))),
    };

    let mut stdin = BufReader::new(io::stdin());
    let request = read_request(&mut stdin)?;

    let _lock = lock()?;
    let config = ConfigFile::write(&gateway)?;
    let mut child = spawn(&config.path, &request)?;
    if let Request::Cookie(cookie) = &request {
        send_cookie(child.stdin.take(), cookie)?;
    }

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

/// openfortivpn's config file, removed again on drop.
struct ConfigFile {
    path: PathBuf,
}

impl ConfigFile {
    fn write(gateway: &Gateway) -> Result<Self, HelperError> {
        let path = Path::new(RUN_DIR).join("openfortivpn.conf");
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut file| file.write_all(openfortivpn::config_file(gateway).as_bytes()))
            .map_err(|err| HelperError::Failed(format!("{}: {err}", path.display())))?;
        Ok(Self { path })
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Starts openfortivpn with our config file and a clean environment.
fn spawn(config: &Path, request: &Request) -> Result<Child, HelperError> {
    let (login_arg, stdin) = match request {
        Request::SamlLogin => ("--saml-login", Stdio::null()),
        Request::Cookie(_) => ("--cookie-on-stdin", Stdio::piped()),
    };
    Command::new(openfortivpn::OPENFORTIVPN)
        .arg("-c")
        .arg(config)
        .arg(login_arg)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| HelperError::Failed(format!("{}: {err}", openfortivpn::OPENFORTIVPN)))
}

/// Writes the cookie in one write and closes the pipe. openfortivpn reads it with a single
/// `read()` and keeps any trailing newline, so none is sent. Writes of up to 4096 bytes to a
/// pipe are atomic, and cookies are at most 4000.
fn send_cookie(stdin: Option<ChildStdin>, cookie: &str) -> Result<(), HelperError> {
    let mut stdin = stdin.ok_or_else(|| HelperError::Failed("no stdin for openfortivpn".into()))?;
    stdin
        .write_all(cookie.as_bytes())
        .map_err(|err| HelperError::Failed(format!("sending the cookie: {err}")))
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
    let mut open_streams = 2;
    let mut terminated = false;
    let mut terminate = |child: &Child| {
        if !terminated {
            terminated = true;
            let _ = kill_process(Pid::from_child(child), Signal::TERM);
        }
    };

    while open_streams > 0 {
        match rx.recv() {
            Ok(Input::Line(line)) => {
                let Some(event) = parser.parse_line(&line) else {
                    continue;
                };
                let fatal = matches!(event, Event::CertUntrusted(_) | Event::AuthFailed);
                events.send(&event);
                if fatal {
                    terminate(child);
                }
            }
            Ok(Input::OutputClosed) => open_streams -= 1,
            Ok(Input::StdinClosed) => terminate(child),
            Err(mpsc::RecvError) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_line_must_be_complete_and_valid() {
        let read = |input: &str| read_request(&mut BufReader::new(input.as_bytes()));
        assert_eq!(read("saml-login\n"), Ok(Request::SamlLogin));
        assert_eq!(read("cookie abc\nrest"), Ok(Request::Cookie("abc".into())));
        assert_eq!(read("saml-login"), Err(HelperError::BadRequest));
        assert_eq!(read(""), Err(HelperError::BadRequest));
        assert_eq!(read("-c /tmp/x\n"), Err(HelperError::BadRequest));
        let endless = "a".repeat(MAX_REQUEST_LEN as usize + 10);
        assert_eq!(read(&endless), Err(HelperError::BadRequest));
    }
}
