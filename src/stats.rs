// SPDX-License-Identifier: EUPL-1.2

//! Traffic through the tunnel, from the interface counters in `/sys/class/net`.

use std::{path::Path, time::Instant};

/// Totals and current rates, in bytes and bytes per second.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    pub received: u64,
    pub sent: u64,
    pub receive_rate: u64,
    pub send_rate: u64,
}

/// The interface's byte counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counters {
    pub received: u64,
    pub sent: u64,
}

impl Counters {
    /// Reads the counters of `interface` (a name checked by
    /// [`cosmic_applet_fortivpn::openfortivpn::TunnelDetail`]).
    pub fn read(interface: &str) -> std::io::Result<Self> {
        let dir = Path::new("/sys/class/net")
            .join(interface)
            .join("statistics");
        let read = |name: &str| -> std::io::Result<u64> {
            std::fs::read_to_string(dir.join(name))?
                .trim()
                .parse()
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
        };
        Ok(Self {
            received: read("rx_bytes")?,
            sent: read("tx_bytes")?,
        })
    }
}

/// Turns counter samples into [`Traffic`].
#[derive(Debug, Default)]
pub struct Meter {
    last: Option<(Instant, Counters)>,
}

impl Meter {
    /// Adds a sample; the rate is over the time since the previous one.
    pub fn sample(&mut self, now: Instant, counters: Counters) -> Traffic {
        let (receive_rate, send_rate) = match self.last {
            Some((then, last)) => {
                let secs = now.saturating_duration_since(then).as_secs_f64();
                // A counter that went down (interface re-created) restarts the rate.
                let rate = |new: u64, old: u64| {
                    if secs > 0.0 {
                        (new.saturating_sub(old) as f64 / secs).round() as u64
                    } else {
                        0
                    }
                };
                (
                    rate(counters.received, last.received),
                    rate(counters.sent, last.sent),
                )
            }
            None => (0, 0),
        };
        self.last = Some((now, counters));
        Traffic {
            received: counters.received,
            sent: counters.sent,
            receive_rate,
            send_rate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rates_over_the_interval() {
        let t0 = Instant::now();
        let mut meter = Meter::default();
        let first = meter.sample(
            t0,
            Counters {
                received: 500,
                sent: 100,
            },
        );
        assert_eq!(
            first,
            Traffic {
                received: 500,
                sent: 100,
                receive_rate: 0,
                send_rate: 0
            }
        );
        let second = meter.sample(
            t0 + Duration::from_secs(2),
            Counters {
                received: 2500,
                sent: 300,
            },
        );
        assert_eq!(second.receive_rate, 1000);
        assert_eq!(second.send_rate, 100);
        assert_eq!(second.received, 2500);
    }

    #[test]
    fn counter_reset_gives_zero_rate() {
        let t0 = Instant::now();
        let mut meter = Meter::default();
        meter.sample(
            t0,
            Counters {
                received: 5000,
                sent: 5000,
            },
        );
        let traffic = meter.sample(
            t0 + Duration::from_secs(1),
            Counters {
                received: 10,
                sent: 10,
            },
        );
        assert_eq!(traffic.receive_rate, 0);
        assert_eq!(traffic.send_rate, 0);
    }

    #[test]
    fn reads_loopback_counters() {
        // `lo` exists everywhere and has statistics.
        assert!(Counters::read("lo").is_ok());
        assert!(Counters::read("no-such-if0").is_err());
    }
}
