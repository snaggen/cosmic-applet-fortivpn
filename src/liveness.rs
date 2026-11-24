// SPDX-License-Identifier: EUPL-1.2

//! Noticing a dead tunnel. openfortivpn has no keepalive: when the network under the tunnel
//! goes away, its TLS connection just stalls and it keeps reporting nothing.
//!
//! A stall shows as data going into the tunnel while nothing comes back. That alone is not
//! proof (one-way UDP, a host behind the VPN that does not answer), so it only triggers a
//! [`probe`]: a DNS query to the VPN's own DNS server, which always answers through a working
//! tunnel.

use crate::stats::Counters;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::net::UdpSocket;

/// How long data may go out without anything coming back before the tunnel is probed.
pub const STALL_BEFORE_PROBE: Duration = Duration::from_secs(15);

/// Without DNS servers to probe, a stall this long counts as a dead tunnel.
pub const STALL_WITHOUT_PROBE: Duration = Duration::from_secs(60);

/// How long to wait for each DNS answer.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Rounds over all servers before giving up.
const PROBE_ROUNDS: usize = 3;

/// Follows the counters and tells how long the tunnel has been stalled.
#[derive(Debug, Default)]
pub struct Watch {
    last: Option<Counters>,
    /// Since when data has gone out with nothing received.
    stalled_since: Option<Instant>,
}

impl Watch {
    /// Adds a sample; returns how long the tunnel has been stalled, if it is.
    pub fn update(&mut self, now: Instant, counters: Counters) -> Option<Duration> {
        if let Some(last) = self.last {
            if counters.received != last.received {
                self.stalled_since = None;
            } else if counters.sent != last.sent && self.stalled_since.is_none() {
                self.stalled_since = Some(now);
            }
        }
        self.last = Some(counters);
        self.stalled_since
            .map(|since| now.saturating_duration_since(since))
    }

    /// The tunnel proved alive: start over.
    pub fn reset(&mut self) {
        self.stalled_since = None;
    }
}

/// Whether any of the VPN's DNS servers answers. Any answer counts, even an error: it came
/// back through the tunnel.
pub async fn probe(servers: Vec<IpAddr>) -> bool {
    for _ in 0..PROBE_ROUNDS {
        for server in &servers {
            if ask(*server).await.unwrap_or(false) {
                return true;
            }
        }
    }
    false
}

/// Sends one query to `server`; `Ok(true)` if it answered in time.
async fn ask(server: IpAddr) -> std::io::Result<bool> {
    let local: SocketAddr = match server {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect((server, 53)).await?;
    let id = query_id();
    socket.send(&query(id)).await?;
    let mut buf = [0u8; 512];
    let answered = async {
        loop {
            let len = socket.recv(&mut buf).await?;
            if buf.get(..len).is_some_and(|reply| is_answer(reply, id)) {
                return Ok::<_, std::io::Error>(());
            }
        }
    };
    Ok(tokio::time::timeout(PROBE_TIMEOUT, answered)
        .await
        .is_ok_and(|r| r.is_ok()))
}

/// A query id that differs between probes. Not secret: an answer only says the server is
/// reachable.
fn query_id() -> u16 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos() as u16)
}

/// A DNS query for the root's NS records: small, and any server answers it somehow.
fn query(id: u16) -> [u8; 17] {
    let [hi, lo] = id.to_be_bytes();
    [
        hi, lo, // id
        0x01, 0x00, // standard query, recursion desired
        0x00, 0x01, // one question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // no answer, authority or additional records
        0x00, // the root name
        0x00, 0x02, // type NS
        0x00, 0x01, // class IN
    ]
}

/// Whether `reply` is a response to the query with `id`.
fn is_answer(reply: &[u8], id: u16) -> bool {
    match reply {
        [hi, lo, flags, ..] if reply.len() >= 12 => {
            u16::from_be_bytes([*hi, *lo]) == id && flags & 0x80 != 0
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counters(received: u64, sent: u64) -> Counters {
        Counters { received, sent }
    }

    #[test]
    fn stall_starts_when_only_sending() {
        let t0 = Instant::now();
        let s = |n| t0 + Duration::from_secs(n);
        let mut watch = Watch::default();
        assert_eq!(watch.update(s(0), counters(100, 100)), None);
        // Idle: nothing in either direction is no stall.
        assert_eq!(watch.update(s(1), counters(100, 100)), None);
        // Sending without receiving starts the stall.
        assert_eq!(watch.update(s(2), counters(100, 200)), Some(Duration::ZERO));
        assert_eq!(
            watch.update(s(20), counters(100, 300)),
            Some(Duration::from_secs(18))
        );
        // Anything received ends it.
        assert_eq!(watch.update(s(21), counters(150, 300)), None);
    }

    #[test]
    fn reset_restarts_the_clock() {
        let t0 = Instant::now();
        let s = |n| t0 + Duration::from_secs(n);
        let mut watch = Watch::default();
        watch.update(s(0), counters(0, 0));
        watch.update(s(1), counters(0, 10));
        watch.reset();
        assert_eq!(watch.update(s(30), counters(0, 10)), None);
        assert_eq!(watch.update(s(31), counters(0, 20)), Some(Duration::ZERO));
    }

    #[test]
    fn query_and_answer() {
        let q = query(0xabcd);
        assert_eq!(&q[..2], &[0xab, 0xcd]);
        let mut reply = q.to_vec();
        assert!(!is_answer(&reply, 0xabcd), "a query is not an answer");
        reply[2] |= 0x80;
        assert!(is_answer(&reply, 0xabcd));
        assert!(!is_answer(&reply, 0x1234));
        assert!(!is_answer(&reply[..5], 0xabcd));
    }

    #[tokio::test]
    async fn unanswered_probe_fails() {
        // Nothing listens on the discard port of loopback, so no DNS answer comes back.
        assert!(!ask("127.0.0.1".parse().unwrap()).await.unwrap_or(false));
    }
}
