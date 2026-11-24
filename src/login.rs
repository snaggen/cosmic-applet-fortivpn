// SPDX-License-Identifier: GPL-3.0-only

//! Runs the login window (`cosmic-applet-fortivpn-login`) for the agent, in place of the
//! system browser. It ends with the SAML session id, which the agent hands to openfortivpn.
//!
//! The login binary is installed next to this one. It keeps a WebKit profile per VPN profile
//! in `$XDG_DATA_HOME/cosmic-applet-fortivpn/webview/<profile>`, so the IdP session survives
//! restarts and the sessions of different customers stay apart.

use cosmic_applet_fortivpn::{
    gateway::CertDigest,
    profile::{LEGACY_ID, ProfileId},
    saml::{self, SamlId},
};
use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    process::{Output, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// File name of the login binary.
const LOGIN_NAME: &str = "cosmic-applet-fortivpn-login";

/// Exit code of the login binary when the user closed the window.
const EXIT_CANCELLED: i32 = 2;

/// How the login window ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginResult {
    /// The login is done; openfortivpn needs this id.
    Done(SamlId),
    /// The user closed the window, or the password dialog.
    Cancelled,
    /// Not from the window: the credentials for a password profile are ready (the agent holds
    /// them).
    Password,
    /// The window could not run or failed; the system browser takes over.
    Failed(String),
}

/// What the login window needs.
#[derive(Clone, Debug)]
pub struct Login {
    pub url: String,
    pub host: String,
    /// Whose WebKit profile to use.
    pub profile: ProfileId,
    /// A certificate the user trusted although it does not validate.
    pub trusted: Option<CertDigest>,
}

/// Runs the login window until the login is done, it is closed, or it fails.
/// Dropping the future kills the window.
pub async fn run(login: Login) -> LoginResult {
    let binary = match login_binary() {
        Ok(binary) => binary,
        Err(why) => return LoginResult::Failed(why),
    };
    let data_dir = match data_dir(&login.profile) {
        Ok(dir) => dir,
        Err(why) => return LoginResult::Failed(why),
    };

    let mut command = tokio::process::Command::new(&binary);
    command
        .arg("--url")
        .arg(&login.url)
        .arg("--host")
        .arg(&login.host)
        .arg("--data-dir")
        .arg(&data_dir);
    if let Some(trusted) = &login.trusted {
        command.arg("--trusted-cert").arg(trusted.as_str());
    }
    command
        // A socket the panel handed an applet must not reach the login window.
        .env_remove("WAYLAND_SOCKET")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);

    // spawn + wait_with_output, not output(): output() captures stderr too, which would hide
    // the window's log.
    let output = match command.spawn() {
        Ok(child) => child.wait_with_output().await,
        Err(err) => Err(err),
    };
    match output {
        Ok(output) => result_from(&output),
        Err(err) => LoginResult::Failed(format!("{}: {err}", binary.display())),
    }
}

/// How long openfortivpn may take to answer the handed-over id.
const HAND_OVER_TIMEOUT: Duration = Duration::from_secs(10);

/// Hands the id to openfortivpn's SAML listener the way the browser would have: one request,
/// then openfortivpn answers with a status page and closes the connection.
pub async fn hand_over(id: SamlId) -> Result<(), String> {
    let exchange = async {
        let mut stream = TcpStream::connect(saml::LISTENER_ADDR).await?;
        // One write: openfortivpn reads the request with a single read().
        stream.write_all(id.request().as_bytes()).await?;
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await?;
        Ok::<_, std::io::Error>(reply)
    };
    let reply = tokio::time::timeout(HAND_OVER_TIMEOUT, exchange)
        .await
        .map_err(|_| "openfortivpn did not answer the SAML login".to_owned())?
        .map_err(|err| format!("openfortivpn's SAML listener: {err}"))?;
    if reply.starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        Err("openfortivpn's SAML listener gave no answer".into())
    }
}

/// Interprets how the login binary ended: exit 0 with the id on stdout.
fn result_from(output: &Output) -> LoginResult {
    match output.status.code() {
        Some(0) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            match SamlId::parse(stdout.trim()) {
                Some(id) => LoginResult::Done(id),
                None => LoginResult::Failed("login window gave no valid SAML id".into()),
            }
        }
        Some(EXIT_CANCELLED) => LoginResult::Cancelled,
        _ => LoginResult::Failed(format!("login window: {}", output.status)),
    }
}

/// The login binary next to the running one.
fn login_binary() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|err| format!("current executable: {err}"))?;
    let dir = exe.parent().ok_or("current executable has no directory")?;
    let binary = dir.join(LOGIN_NAME);
    if binary.is_file() {
        Ok(binary)
    } else {
        Err(format!("{} is not installed", binary.display()))
    }
}

/// The WebKit profile directory of a VPN profile, created private to the user: the IdP
/// session in it works like a password for weeks.
fn data_dir(profile: &ProfileId) -> Result<PathBuf, String> {
    let base = match std::env::var_os("XDG_DATA_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join(".local/share"))
            .ok_or("neither XDG_DATA_HOME nor HOME is set")?,
    };
    let webview = base.join("cosmic-applet-fortivpn").join("webview");
    let dir = webview.join(profile.as_str());
    let private = |dir: &PathBuf| -> Result<(), String> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|err| format!("{}: {err}", dir.display()))?;
        // The mode above only applies to directories created now; tighten one made earlier.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("{}: {err}", dir.display()))
    };
    private(&webview)?;
    if profile.as_str() == LEGACY_ID {
        move_single_profile(&webview, &dir);
    }
    private(&dir)?;
    Ok(dir)
}

/// Before profiles there was one WebKit profile directly in `webview`. It belonged to the
/// gateway that became the profile `default`, so it moves there, keeping the IdP session.
fn move_single_profile(webview: &std::path::Path, dir: &std::path::Path) {
    if dir.exists() || !webview.join("cookies.sqlite").exists() {
        return;
    }
    if let Err(err) = std::fs::create_dir(dir) {
        tracing::warn!(%err, "could not move the old login profile");
        return;
    }
    for name in ["cookies.sqlite", "data", "cache"] {
        let from = webview.join(name);
        if from.exists()
            && let Err(err) = std::fs::rename(&from, dir.join(name))
        {
            tracing::warn!(%err, name, "could not move the old login profile");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::process::ExitStatusExt, process::ExitStatus};

    fn output(code: i32, stdout: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn exit_codes() {
        assert_eq!(
            result_from(&output(0, "abc123\n")),
            LoginResult::Done(SamlId::parse("abc123").unwrap())
        );
        assert!(matches!(
            result_from(&output(0, "")),
            LoginResult::Failed(_)
        ));
        assert!(matches!(
            result_from(&output(0, "a b")),
            LoginResult::Failed(_)
        ));
        assert_eq!(result_from(&output(2, "")), LoginResult::Cancelled);
        assert!(matches!(
            result_from(&output(1, "abc")),
            LoginResult::Failed(_)
        ));
    }
}
