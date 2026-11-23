// SPDX-License-Identifier: AGPL-3.0-only
//! Finding consoles on the home network and waking them. Ported from chiaki-ng `lib/src/discovery.c`
//! (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! A search is one UDP datagram, broadcast to the console's discovery port; a console answers with an
//! HTTP-shaped reply. A wake-up is one datagram sent straight to the console, carrying the credential
//! from registration (step 5).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use psr_crypto::Target;

use crate::LanError;
use crate::http;

pub const PORT_PS4: u16 = 987;
pub const PROTOCOL_VERSION_PS4: &str = "00020020";
pub const PORT_PS5: u16 = 9302;
pub const PROTOCOL_VERSION_PS5: &str = "00030010";
/// chiaki-ng binds the first free port in 9303..=9319, then any port.
pub const LOCAL_PORTS: std::ops::RangeInclusive<u16> = 9303..=9319;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Console {
    Ps4,
    Ps5,
}

impl Console {
    pub const fn port(self) -> u16 {
        match self {
            Console::Ps4 => PORT_PS4,
            Console::Ps5 => PORT_PS5,
        }
    }

    pub const fn protocol_version(self) -> &'static str {
        match self {
            Console::Ps4 => PROTOCOL_VERSION_PS4,
            Console::Ps5 => PROTOCOL_VERSION_PS5,
        }
    }
}

/// chiaki-ng sends each packet with its terminating NUL byte (`len + 1`), so this does too.
fn with_nul(s: String) -> Vec<u8> {
    let mut v = s.into_bytes();
    v.push(0);
    v
}

/// chiaki-ng `chiaki_discovery_packet_fmt`, `SRCH`.
pub fn search_packet(console: Console) -> Vec<u8> {
    with_nul(format!("SRCH * HTTP/1.1\ndevice-discovery-protocol-version:{}\n", console.protocol_version()))
}

/// chiaki-ng `chiaki_discovery_packet_fmt`, `WAKEUP`. `credential` is the registration key read as a
/// hexadecimal number.
pub fn wakeup_packet(console: Console, credential: u64) -> Vec<u8> {
    with_nul(format!(
        "WAKEUP * HTTP/1.1\nclient-type:vr\nauth-type:R\nmodel:w\napp-type:r\nuser-credential:{credential}\ndevice-discovery-protocol-version:{}\n",
        console.protocol_version()
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    Unknown,
    Ready,
    Standby,
}

/// A console's reply to a search (chiaki-ng `ChiakiDiscoveryHost`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub addr: IpAddr,
    pub state: HostState,
    pub host_request_port: u16,
    pub system_version: Option<String>,
    pub device_discovery_protocol_version: Option<String>,
    pub host_name: Option<String>,
    pub host_type: Option<String>,
    pub host_id: Option<String>,
    pub running_app_titleid: Option<String>,
    pub running_app_name: Option<String>,
}

impl Host {
    /// chiaki-ng `chiaki_discovery_srch_response_parse`. 200 means on, 620 means in rest mode.
    pub fn parse(addr: IpAddr, reply: &[u8]) -> Result<Self, LanError> {
        let r = http::parse_response(reply)?;
        let get = |k: &str| r.header(k).map(str::to_string);
        Ok(Self {
            addr,
            state: match r.code {
                200 => HostState::Ready,
                620 => HostState::Standby,
                _ => HostState::Unknown,
            },
            host_request_port: r.header("host-request-port").and_then(parse_c_ulong).unwrap_or(0),
            system_version: get("system-version"),
            device_discovery_protocol_version: get("device-discovery-protocol-version"),
            host_name: get("host-name"),
            host_type: get("host-type"),
            host_id: get("host-id"),
            running_app_titleid: get("running-app-titleid"),
            running_app_name: get("running-app-name"),
        })
    }

    /// chiaki-ng `chiaki_discovery_host_is_ps5`: the PS5 answers with its own protocol version.
    pub fn is_ps5(&self) -> bool {
        self.device_discovery_protocol_version.as_deref() == Some(PROTOCOL_VERSION_PS5)
    }

    /// chiaki-ng `chiaki_discovery_host_system_version_target`.
    pub fn target(&self) -> Target {
        let version = self.system_version.as_deref().map(atoi).unwrap_or(0);
        let ps5 = self.is_ps5();
        match version {
            v if v >= 8_050_001 && ps5 => Target::Ps5V1,
            v if v >= 8_050_000 && ps5 => Target::Ps5Unknown,
            v if v >= 8_000_000 => Target::Ps4V10,
            v if v >= 7_000_000 => Target::Ps4V9,
            v if v > 0 => Target::Ps4V8,
            _ => Target::Ps4Unknown,
        }
    }
}

/// C `atoi`: leading digits, ignoring what follows, 0 if none.
fn atoi(s: &str) -> i64 {
    let digits: String = s.trim_start().chars().take_while(char::is_ascii_digit).collect();
    digits.parse().unwrap_or(0)
}

/// C `strtoul(s, NULL, 0)` for a u16: decimal, `0x` hex or leading-zero octal.
fn parse_c_ulong(s: &str) -> Option<u16> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).ok()
    } else if s.len() > 1 && s.starts_with('0') {
        u16::from_str_radix(&s[1..], 8).ok()
    } else {
        s.parse().ok()
    }
}

fn bind_discovery_socket() -> Result<UdpSocket, LanError> {
    let any = Ipv4Addr::UNSPECIFIED;
    let socket = LOCAL_PORTS
        .clone()
        .find_map(|p| UdpSocket::bind((any, p)).ok())
        .map_or_else(|| UdpSocket::bind((any, 0)), Ok)
        .map_err(LanError::Io)?;
    socket.set_broadcast(true).map_err(LanError::Io)?;
    Ok(socket)
}

/// Broadcasts a search for both console families and collects replies until `wait` has passed. A reply
/// that doesn't parse is skipped, as in chiaki-ng. Searching is IPv4: IPv6 has no broadcast address,
/// and the consoles answer chiaki-ng's IPv4 broadcast.
pub fn search(broadcast: Ipv4Addr, wait: Duration) -> Result<Vec<Host>, LanError> {
    let socket = bind_discovery_socket()?;
    for console in [Console::Ps5, Console::Ps4] {
        socket.send_to(&search_packet(console), (broadcast, console.port())).map_err(LanError::Io)?;
    }
    let deadline = Instant::now() + wait;
    let mut hosts: Vec<Host> = Vec::new();
    let mut buf = [0u8; 512];
    while let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) {
        socket.set_read_timeout(Some(left)).map_err(LanError::Io)?;
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                if let Ok(host) = Host::parse(from.ip(), &buf[..n])
                    && !hosts.iter().any(|h| h.addr == host.addr)
                {
                    hosts.push(host);
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
            // Windows reports an ICMP "port unreachable" for an earlier send (say, the PS4 search to a
            // network with no PS4) as WSAECONNRESET on the next receive. It says nothing about the
            // replies still to come, so keep listening.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(e) => return Err(LanError::Io(e)),
        }
    }
    Ok(hosts)
}

/// chiaki-ng `chiaki_discovery_wakeup`: sends one wake-up datagram straight to the console.
pub fn wake(addr: IpAddr, console: Console, credential: u64) -> Result<(), LanError> {
    let socket = bind_discovery_socket()?;
    socket.send_to(&wakeup_packet(console, credential), SocketAddr::new(addr, console.port())).map_err(LanError::Io)?;
    Ok(())
}
