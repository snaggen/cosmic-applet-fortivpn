// SPDX-License-Identifier: EUPL-1.2

//! Reconnecting by itself, when the user turned it on: after a lost tunnel, and after resume
//! when the tunnel was up before sleep. Off by default.
//!
//! Each attempt waits for the network first (NetworkManager's global connectivity), so an
//! attempt does not fail, or open the login window on an error page, just because the network
//! is not back yet.

use std::time::Duration;

/// Attempts before giving up.
pub const MAX_ATTEMPTS: u32 = 3;

/// Before the first attempt: lets the old helper finish (its logout may take a few seconds).
const FIRST_DELAY: Duration = Duration::from_secs(5);
/// Between attempts.
const RETRY_DELAY: Duration = Duration::from_secs(15);
/// How long an attempt waits for the network.
const NETWORK_TIMEOUT: Duration = Duration::from_secs(120);
/// How often NetworkManager's state is read while waiting.
const NETWORK_POLL: Duration = Duration::from_secs(2);

/// NetworkManager's `NM_STATE_CONNECTED_GLOBAL`.
const NM_CONNECTED_GLOBAL: u32 = 70;

/// A reconnect in progress.
#[derive(Debug, PartialEq, Eq)]
pub struct Reconnect {
    /// Tells this reconnect's timers from those of an earlier, cancelled one.
    pub id: u64,
    attempts: u32,
}

impl Reconnect {
    pub fn new(id: u64) -> Self {
        Self { id, attempts: 0 }
    }

    /// The wait before the next attempt, or `None` once all attempts are used up.
    pub fn next_delay(&mut self) -> Option<Duration> {
        if self.attempts >= MAX_ATTEMPTS {
            return None;
        }
        let delay = if self.attempts == 0 {
            FIRST_DELAY
        } else {
            RETRY_DELAY
        };
        self.attempts += 1;
        Some(delay)
    }
}

/// Sleeps `delay`, then waits for the network. `false` if it did not come back in time.
pub async fn wait(delay: Duration) -> bool {
    tokio::time::sleep(delay).await;
    let deadline = tokio::time::Instant::now() + NETWORK_TIMEOUT;
    loop {
        match network_state().await {
            Ok(state) if state >= NM_CONNECTED_GLOBAL => return true,
            Ok(_) => {}
            // Without NetworkManager there is nothing to wait for: just try.
            Err(err) => {
                tracing::debug!(%err, "no NetworkManager state");
                return true;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(NETWORK_POLL).await;
    }
}

#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager"
)]
trait NetworkManager {
    #[zbus(property)]
    fn state(&self) -> zbus::Result<u32>;
}

async fn network_state() -> zbus::Result<u32> {
    let connection = zbus::Connection::system().await?;
    NetworkManagerProxy::new(&connection).await?.state().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_are_limited() {
        let mut reconnect = Reconnect::new(1);
        assert_eq!(reconnect.next_delay(), Some(FIRST_DELAY));
        assert_eq!(reconnect.next_delay(), Some(RETRY_DELAY));
        assert_eq!(reconnect.next_delay(), Some(RETRY_DELAY));
        assert_eq!(reconnect.next_delay(), None);
    }
}
