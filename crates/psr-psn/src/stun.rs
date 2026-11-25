// SPDX-License-Identifier: AGPL-3.0-only
//! Our public address, from a STUN binding request (RFC 5389), for the holepunch offer. Ported from chiaki-ng
//! `stun_get_external_address_from_server` in `lib/src/remote/stun.h` (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! **Differences from chiaki-ng:**
//! - **The server list is fixed.** chiaki-ng also downloads a list of public STUN servers from a GitHub file
//!   at run time; here only its built-in servers are asked, so no third party decides where the probe goes.
//! - **The reply must come from the server asked.** chiaki-ng takes the first datagram the socket receives;
//!   here datagrams from any other address are passed over, as are malformed replies, until the timeout.
//! - **Each name lookup and each send can fail alone.** A server whose name does not resolve within
//!   [`RESOLVE_TIMEOUT`], or that cannot be sent to, is skipped for the next.
//! - **IPv4 only, one answer.** chiaki-ng asks up to four servers to measure how the NAT allocates ports, for
//!   port guessing; that is not ported yet (`docs/PSN.md`, 9b-2b).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use crate::PsnError;

/// chiaki-ng `STUN_SERVERS`, the Moonlight server first, as chiaki-ng keeps it; one port per Google host.
pub const SERVERS: &[(&str, u16)] = &[
    ("stun.moonlight-stream.org", 3478),
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
    ("stun3.l.google.com", 19302),
];
/// How long each server has to answer. chiaki-ng waits 5 s; several servers are tried here instead.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(2);

const HEADER: usize = 20;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const MAGIC_COOKIE: u32 = 0x2112_a442;
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FAMILY_IPV4: u8 = 0x01;

/// A binding request with this transaction ID: a header with no attributes.
pub fn binding_request(txid: &[u8; 12]) -> [u8; HEADER] {
    let mut r = [0u8; HEADER];
    r[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    r[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    r[8..20].copy_from_slice(txid);
    r
}

/// The address a binding response reports for us, or `None` if it is not a well-formed response to `txid`
/// with an IPv4 address a probe could be sent to. `XOR-MAPPED-ADDRESS` is preferred to `MAPPED-ADDRESS`.
pub fn parse_binding_response(resp: &[u8], txid: &[u8; 12]) -> Option<SocketAddrV4> {
    let be16 = |i: usize| u16::from_be_bytes([resp[i], resp[i + 1]]);
    if resp.len() < HEADER
        || be16(0) != BINDING_RESPONSE
        || usize::from(be16(2)) + HEADER != resp.len()
        || resp[4..8] != MAGIC_COOKIE.to_be_bytes()
        || resp[8..20] != *txid
    {
        return None;
    }
    let (mut pos, mut plain, mut xored) = (HEADER, None, None);
    while pos + 4 <= resp.len() {
        let (kind, len) = (be16(pos), usize::from(be16(pos + 2)));
        let value = resp.get(pos + 4..pos + 4 + len)?;
        if kind == MAPPED_ADDRESS || kind == XOR_MAPPED_ADDRESS {
            let addr = ipv4_attribute(value, kind == XOR_MAPPED_ADDRESS)?;
            if kind == XOR_MAPPED_ADDRESS { xored = Some(addr) } else { plain = Some(addr) }
        }
        // Attribute values are padded to a multiple of four bytes.
        pos += 4 + len.next_multiple_of(4);
    }
    let addr = xored.or(plain)?;
    let ip = std::net::IpAddr::V4(*addr.ip());
    (crate::holepunch::probe_address(ip) && addr.port() != 0).then_some(addr)
}

/// A `MAPPED-ADDRESS` or `XOR-MAPPED-ADDRESS` value holding an IPv4 address.
fn ipv4_attribute(v: &[u8], xored: bool) -> Option<SocketAddrV4> {
    if v.len() != 8 || v[1] != FAMILY_IPV4 {
        return None;
    }
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let mask = |i: usize| if xored { cookie[i] } else { 0 };
    let port = u16::from_be_bytes([v[2] ^ mask(0), v[3] ^ mask(1)]);
    let ip = Ipv4Addr::new(v[4] ^ mask(0), v[5] ^ mask(1), v[6] ^ mask(2), v[7] ^ mask(3));
    Some(SocketAddrV4::new(ip, port))
}

/// Asks one server, from `sock`, for the address it sees us at: `None` if no well-formed answer comes from it
/// within [`REPLY_TIMEOUT`].
pub fn ask(sock: &UdpSocket, server: SocketAddrV4) -> Result<Option<SocketAddrV4>, PsnError> {
    let txid: [u8; 12] = crate::holepunch::random()?;
    let io = |e: std::io::Error| PsnError::Network(format!("STUN: {e}"));
    // A server that cannot be sent to is skipped, not fatal: another may be reachable.
    if sock.send_to(&binding_request(&txid), server).is_err() {
        return Ok(None);
    }
    let deadline = Instant::now() + REPLY_TIMEOUT;
    let mut buf = [0u8; 512];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(None);
        }
        match psr_lan::udp::recv_from_within(sock, &mut buf, left) {
            Ok(None) => {}
            Ok(Some((n, SocketAddr::V4(from)))) if from == server => {
                if let Some(addr) = parse_binding_response(&buf[..n], &txid) {
                    return Ok(Some(addr));
                }
            }
            Ok(Some(_)) => {}
            Err(e) if is_transient(&e) => {}
            Err(e) => return Err(io(e)),
        }
    }
}

/// Errors a UDP receive gives that only mean "nothing usable yet": a timeout, and on Windows the
/// `WSAECONNRESET` an ICMP "port unreachable" from an earlier send turns into.
pub(crate) fn is_transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(e.kind(), WouldBlock | TimedOut | ConnectionReset | Interrupted)
}

/// How long a STUN server's name has to resolve. The system resolver has no timeout of its own to set.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// The first IPv4 address of `host`, looked up on a thread so a stalled resolver costs at most
/// [`RESOLVE_TIMEOUT`] (the thread is left to finish on its own).
fn resolve_v4(host: &'static str, port: u16) -> Option<SocketAddrV4> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let found = (host, port).to_socket_addrs().ok().and_then(|mut a| {
            a.find_map(|s| match s {
                SocketAddr::V4(v4) => Some(v4),
                SocketAddr::V6(_) => None,
            })
        });
        // The receiver may have given up already; there is nothing to do then.
        let _ = tx.send(found);
    });
    rx.recv_timeout(RESOLVE_TIMEOUT).ok().flatten()
}

/// Our public address as the first server in [`SERVERS`] to answer sees it, from `sock`, and that server's
/// address. An error if none answers.
pub fn external_address(sock: &UdpSocket) -> Result<(SocketAddrV4, SocketAddrV4), PsnError> {
    for &(host, port) in SERVERS {
        // A name that does not resolve to IPv4 in time is skipped, as chiaki-ng skips a server it cannot reach.
        let Some(server) = resolve_v4(host, port) else { continue };
        if let Some(addr) = ask(sock, server)? {
            return Ok((addr, server));
        }
    }
    Err(PsnError::Timeout("an answer from a STUN server"))
}
