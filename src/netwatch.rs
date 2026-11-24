// SPDX-License-Identifier: EUPL-1.2

//! Watching the network through netlink: links, addresses and routes.
//!
//! A tunnel only notices that the network under it changed when traffic stalls (see
//! [`crate::liveness`]), and an idle tunnel never does. So the agent listens for the kernel's
//! link, address and route changes and probes the tunnel right away. Changes come in bursts
//! (NetworkManager reconfiguring an interface), so they are gathered for [`QUIET`] and reported
//! once, with the interfaces they concern.

use cosmic::iced::{
    Subscription,
    futures::{SinkExt, channel::mpsc::Sender},
    stream,
};
use rustix::net::{
    AddressFamily, RecvFlags, SocketFlags, SocketType, bind, netlink, recv, socket_with,
};
use std::{collections::BTreeSet, io, os::fd::OwnedFd, time::Duration};
use tokio::io::unix::AsyncFd;

/// Changes closer together than this are reported as one.
const QUIET: Duration = Duration::from_secs(2);

// Multicast groups (`RTMGRP_*` in linux/rtnetlink.h).
const RTMGRP_LINK: u32 = 0x1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
const RTMGRP_IPV6_ROUTE: u32 = 0x400;

// Message types (`RTM_*`).
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;

/// Length of `struct nlmsghdr`.
const NLMSG_HDRLEN: usize = 16;
/// Length of `struct rtmsg`, after which a route message's attributes start.
const RTMSG_LEN: usize = 12;
/// `RTA_OIF`: a route's output interface.
const RTA_OIF: u16 = 4;

/// The network changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Change {
    /// Interfaces the changes concern.
    pub interfaces: BTreeSet<u32>,
    /// Some change named no interface (a route without one, or lost messages).
    pub unknown: bool,
}

impl Change {
    /// Whether anything changed besides the interface `ignored` (the tunnel's own).
    pub fn besides(&self, ignored: Option<u32>) -> bool {
        self.unknown || self.interfaces.iter().any(|index| Some(*index) != ignored)
    }
}

pub fn subscription() -> Subscription<Change> {
    Subscription::run(|| stream::channel(4, run))
}

async fn run(mut output: Sender<Change>) {
    if let Err(err) = watch(&mut output).await {
        tracing::warn!(%err, "not watching the network");
    }
}

async fn watch(output: &mut Sender<Change>) -> io::Result<()> {
    let socket = AsyncFd::new(open()?)?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // Wait for the first change, then gather until it is quiet.
        let mut change = Change::default();
        read(&socket, &mut buf, &mut change).await?;
        while let Ok(result) =
            tokio::time::timeout(QUIET, read(&socket, &mut buf, &mut change)).await
        {
            result?;
        }
        if output.send(change).await.is_err() {
            return Ok(());
        }
    }
}

/// A netlink socket subscribed to link, address and route changes.
fn open() -> io::Result<OwnedFd> {
    let fd = socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        // NETLINK_ROUTE is protocol 0, the default, which rustix spells as no protocol.
        None,
    )?;
    let groups = RTMGRP_LINK
        | RTMGRP_IPV4_IFADDR
        | RTMGRP_IPV4_ROUTE
        | RTMGRP_IPV6_IFADDR
        | RTMGRP_IPV6_ROUTE;
    bind(&fd, &netlink::SocketAddrNetlink::new(0, groups))?;
    Ok(fd)
}

/// Reads one datagram and adds what it says to `change`.
async fn read(socket: &AsyncFd<OwnedFd>, buf: &mut [u8], change: &mut Change) -> io::Result<()> {
    loop {
        let mut guard = socket.readable().await?;
        match guard
            .try_io(|fd| recv(fd.get_ref(), &mut *buf, RecvFlags::empty()).map_err(io::Error::from))
        {
            Ok(Ok((len, _))) => {
                for interface in interfaces(buf.get(..len).unwrap_or_default()) {
                    match interface {
                        Some(index) => {
                            change.interfaces.insert(index);
                        }
                        None => change.unknown = true,
                    }
                }
                return Ok(());
            }
            // The kernel dropped messages (ENOBUFS): something changed, but not known what.
            Ok(Err(err))
                if err.raw_os_error() == Some(rustix::io::Errno::NOBUFS.raw_os_error()) =>
            {
                change.unknown = true;
                return Ok(());
            }
            Ok(Err(err)) => return Err(err),
            Err(_would_block) => continue,
        }
    }
}

/// The interface of each link, address or route message in a datagram; `None` where a
/// message names none.
fn interfaces(datagram: &[u8]) -> Vec<Option<u32>> {
    let mut found = Vec::new();
    let mut rest = datagram;
    while let Some(len) = rest.get(0..4).map(|b| u32_at(b, 0) as usize) {
        if len < NLMSG_HDRLEN || len > rest.len() {
            break;
        }
        let kind = rest
            .get(4..6)
            .map_or(0, |b| u16::from_ne_bytes([b[0], b[1]]));
        let payload = rest.get(NLMSG_HDRLEN..len).unwrap_or_default();
        match kind {
            // ifinfomsg and ifaddrmsg: the index follows 4 bytes of family, type, etc.
            RTM_NEWLINK | RTM_DELLINK | RTM_NEWADDR | RTM_DELADDR => {
                found.push(payload.get(4..8).map(|b| u32_at(b, 0)));
            }
            RTM_NEWROUTE | RTM_DELROUTE => found.push(route_interface(payload)),
            _ => {}
        }
        rest = rest.get(align(len)..).unwrap_or_default();
    }
    found
}

/// A route's output interface, from its `RTA_OIF` attribute.
fn route_interface(payload: &[u8]) -> Option<u32> {
    let mut attrs = payload.get(RTMSG_LEN..)?;
    while let Some(header) = attrs.get(0..4) {
        let len = u16::from_ne_bytes([header[0], header[1]]) as usize;
        let kind = u16::from_ne_bytes([header[2], header[3]]);
        if len < 4 {
            return None;
        }
        if kind == RTA_OIF {
            return attrs.get(4..8).map(|b| u32_at(b, 0));
        }
        attrs = attrs.get(align(len)..)?;
    }
    None
}

/// A native-endian u32 at `offset`; `bytes` holds at least `offset + 4` bytes.
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    let mut word = [0u8; 4];
    if let Some(slice) = bytes.get(offset..offset + 4) {
        word.copy_from_slice(slice);
    }
    u32::from_ne_bytes(word)
}

/// Netlink's 4-byte alignment.
fn align(len: usize) -> usize {
    (len + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A netlink message of `kind` with `payload`, padded.
    fn message(kind: u16, payload: &[u8]) -> Vec<u8> {
        let len = (NLMSG_HDRLEN + payload.len()) as u32;
        let mut msg = Vec::new();
        msg.extend_from_slice(&len.to_ne_bytes());
        msg.extend_from_slice(&kind.to_ne_bytes());
        msg.extend_from_slice(&[0; 10]); // flags, seq, pid
        msg.extend_from_slice(payload);
        msg.resize(align(msg.len()), 0);
        msg
    }

    fn attr(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        a.extend_from_slice(&kind.to_ne_bytes());
        a.extend_from_slice(data);
        a.resize(align(a.len()), 0);
        a
    }

    #[test]
    fn link_address_and_route_messages() {
        let mut ifinfo = vec![0u8; 16];
        ifinfo[4..8].copy_from_slice(&3u32.to_ne_bytes());
        let mut ifaddr = vec![0u8; 8];
        ifaddr[4..8].copy_from_slice(&7u32.to_ne_bytes());
        let mut route = vec![0u8; RTMSG_LEN];
        route.extend(attr(1, &[10, 0, 0, 0])); // RTA_DST
        route.extend(attr(RTA_OIF, &9u32.to_ne_bytes()));
        let route_without_oif = vec![0u8; RTMSG_LEN];

        let mut datagram = message(RTM_DELLINK, &ifinfo);
        datagram.extend(message(RTM_NEWADDR, &ifaddr));
        datagram.extend(message(RTM_NEWROUTE, &route));
        datagram.extend(message(RTM_DELROUTE, &route_without_oif));
        datagram.extend(message(3, &[])); // NLMSG_DONE: ignored

        assert_eq!(interfaces(&datagram), vec![Some(3), Some(7), Some(9), None]);
    }

    #[test]
    fn truncated_messages_are_not_read_past() {
        let msg = message(RTM_NEWLINK, &[0u8; 16]);
        assert_eq!(interfaces(&msg[..10]), Vec::<Option<u32>>::new());
        // A length field larger than the datagram stops the parse.
        let mut bad = msg.clone();
        bad[0..4].copy_from_slice(&1000u32.to_ne_bytes());
        assert_eq!(interfaces(&bad), Vec::<Option<u32>>::new());
        // A link message too short for the index names no interface.
        assert_eq!(interfaces(&message(RTM_NEWLINK, &[0u8; 2])), vec![None]);
    }

    #[test]
    fn changes_besides_the_tunnel() {
        let tunnel_only = Change {
            interfaces: [5].into(),
            unknown: false,
        };
        assert!(!tunnel_only.besides(Some(5)));
        assert!(tunnel_only.besides(None));
        let more = Change {
            interfaces: [2, 5].into(),
            unknown: false,
        };
        assert!(more.besides(Some(5)));
        let unknown = Change {
            interfaces: [5].into(),
            unknown: true,
        };
        assert!(unknown.besides(Some(5)));
    }

    #[test]
    fn opens_a_netlink_socket() {
        // Joining these groups needs no privileges.
        assert!(open().is_ok());
    }
}
