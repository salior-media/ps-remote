// SPDX-License-Identifier: AGPL-3.0-only
//! Registration ("Link Device"): pairing this client with a console using the PIN it shows. Ported from
//! chiaki-ng `lib/src/regist.c` (LicenseRef-AGPL-3.0-only-OpenSSL), home-network path. Over PSN the same
//! request goes through the punched hole instead (`psr-psn`'s `regist`), built by [`request_payload_psn`]
//! and [`request_header_host`].
//!
//! 1. UDP `SRC3` (PS5) or `SRC2` (PS4) to port 9295, wait for `RES3`/`RES2`.
//! 2. After 100 ms (the PS4 refuses requests that come sooner), TCP to the same address, port 9295.
//! 3. An HTTP POST header, then a payload: 0x1e0 filler bytes carrying the "aeropause" key, then the
//!    inner header (client type and account ID), encrypted with the PIN-derived cipher.
//! 4. The reply's body, decrypted with the same cipher, holds the registration key, the RP key and the
//!    console's MAC address.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use base64::Engine;
use psr_crypto::Target;
use psr_crypto::rpcrypt::{self, RpCrypt};

use crate::LanError;
use crate::http;

pub const REGIST_PORT: u16 = 9295;
pub const PSN_ACCOUNT_ID_SIZE: usize = 8;
const SEARCH_TIMEOUT: Duration = Duration::from_millis(3000);
const RESPONSE_TIMEOUT: Duration = Duration::from_millis(3000);
const SEARCH_TO_REQUEST_DELAY: Duration = Duration::from_millis(100);
const INNER_HEADER_OFF: usize = 0x1e0;
/// chiaki-ng's `client_type` for PS4 10+ and PS5.
const CLIENT_TYPE: &str = "dabfa2ec873de5839bee8d3f4c0239c4282c07c25c6077a2931afcf0adc0d34f";
const CLIENT_TYPE_PS4_PRE10: &str = "Windows";
/// chiaki-ng sends this fixed address as the `HOST` header on the home network.
const REGIST_LOCAL_ADDR: &str = "10.0.2.15";
const RESPONSE_BUF_SIZE: usize = 1500;

/// Who is registering: the PSN online ID (PS4 before 7.0) or the 8-byte account ID (everything later).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    OnlineId(String),
    AccountId([u8; PSN_ACCOUNT_ID_SIZE]),
}

impl Identity {
    /// The account ID in the base64 form chiaki-ng's script prints and the console expects.
    pub fn account_id_from_base64(b64: &str) -> Result<Self, LanError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|_| LanError::BadAccountId)?;
        bytes.try_into().map(Identity::AccountId).map_err(|_| LanError::BadAccountId)
    }
}

/// chiaki-ng `chiaki_rp_version_string`.
pub fn rp_version(target: Target) -> Option<&'static str> {
    match target {
        Target::Ps4V8 => Some("8.0"),
        Target::Ps4V9 => Some("9.0"),
        Target::Ps4V10 => Some("10.0"),
        Target::Ps5V1 => Some("1.0"),
        _ => None,
    }
}

fn request_path(target: Target) -> &'static str {
    match target {
        Target::Ps5Unknown | Target::Ps5V1 => "/sie/ps5/rp/sess/rgst",
        Target::Ps4V8 | Target::Ps4V9 => "/sce/rp/regist",
        _ => "/sie/ps4/rp/sess/rgst",
    }
}

/// chiaki-ng `chiaki_regist_request_payload_format`: the payload and the cipher that will also decrypt
/// the reply. `ambassador` is 16 random bytes for a real registration.
pub fn request_payload(
    target: Target,
    ambassador: &rpcrypt::Key,
    identity: &Identity,
    pin: u32,
) -> Result<(Vec<u8>, RpCrypt), LanError> {
    // chiaki-ng: "can be random". Filling with 'A' fixes the key offsets below; it is what chiaki-ng does.
    let mut buf = vec![b'A'; INNER_HEADER_OFF];
    let crypt;
    if target.code() < Target::Ps4V10.code() {
        crypt = RpCrypt::regist_ps4_pre10(ambassador, pin);
        buf[0x11c..0x12c].copy_from_slice(&rpcrypt::aeropause_ps4_pre10(crypt.ambassador()));
    } else {
        let key_0_off = usize::from(buf[0x18d] & 0x1f);
        let key_1_off = usize::from(buf[0] >> 3);
        crypt = RpCrypt::regist(target, ambassador, key_0_off, pin)?;
        let aeropause = rpcrypt::aeropause(target, key_1_off, crypt.ambassador())?;
        place_aeropause(&mut buf, &aeropause);
        // chiaki-ng drops the online ID from PS4 10 on, so it needs the account ID.
        if let Identity::OnlineId(_) = identity {
            return Err(LanError::NeedsAccountId(target));
        }
    }
    Ok((finish_payload(buf, target, &crypt, identity), crypt))
}

/// The "aeropause" key where chiaki-ng puts it for PS4 10 and later: its second half, then its first.
fn place_aeropause(buf: &mut [u8], aeropause: &rpcrypt::Key) {
    buf[0xc7..0xcf].copy_from_slice(&aeropause[8..]);
    buf[0x191..0x199].copy_from_slice(&aeropause[..8]);
}

/// chiaki-ng `chiaki_regist_request_payload_format` with `holepunch_info`: registering over PSN, where no
/// PIN is shown and the cipher comes from the session's `customData1`, `data1` and `data2` instead. PS4 10
/// and later, and the PS5, only (chiaki-ng takes the PIN path for older PS4s whatever is given).
pub fn request_payload_psn(
    target: Target,
    ambassador: &rpcrypt::Key,
    account_id: &[u8; PSN_ACCOUNT_ID_SIZE],
    custom_data1: &rpcrypt::Key,
    data1: &rpcrypt::Key,
    data2: &rpcrypt::Key,
) -> Result<(Vec<u8>, RpCrypt), LanError> {
    if target.code() < Target::Ps4V10.code() {
        return Err(LanError::NoPsnRegist(target));
    }
    let mut buf = vec![b'A'; INNER_HEADER_OFF];
    let key_0_off = usize::from(buf[0x18d] & 0x1f);
    let key_1_off = usize::from(buf[0] >> 3);
    let crypt = RpCrypt::regist_psn(target, ambassador, key_0_off, custom_data1, data1, data2)?;
    place_aeropause(&mut buf, &rpcrypt::aeropause_psn(target, key_1_off, crypt.ambassador())?);
    Ok((finish_payload(buf, target, &crypt, &Identity::AccountId(*account_id)), crypt))
}

/// The filler and keys, then the inner header encrypted.
fn finish_payload(mut buf: Vec<u8>, target: Target, crypt: &RpCrypt, identity: &Identity) -> Vec<u8> {
    let inner = match identity {
        Identity::OnlineId(id) => format!("Client-Type: Windows\r\nNp-Online-Id: {id}\r\n"),
        Identity::AccountId(id) => {
            let client = if target.code() < Target::Ps4V10.code() { CLIENT_TYPE_PS4_PRE10 } else { CLIENT_TYPE };
            let b64 = base64::engine::general_purpose::STANDARD.encode(id);
            format!("Client-Type: {client}\r\nNp-AccountId: {b64}\r\n")
        }
    };
    buf.extend_from_slice(&crypt.encrypt(0, inner.as_bytes()));
    buf
}

/// chiaki-ng `request_header_format`. The doubled ` HTTP/1.1` on the first line is chiaki-ng's, and is
/// kept byte for byte: it is what the console has been accepting.
pub fn request_header(target: Target, payload_len: usize) -> Result<String, LanError> {
    request_header_host(target, payload_len, REGIST_LOCAL_ADDR)
}

/// [`request_header`] with another `HOST`: over PSN chiaki-ng sends this client's local address there.
pub fn request_header_host(target: Target, payload_len: usize, host: &str) -> Result<String, LanError> {
    let mut h = format!(
        "POST {} HTTP/1.1\r\n HTTP/1.1\r\nHOST: {host}\r\nUser-Agent: remoteplay Windows\r\nConnection: close\r\nContent-Length: {payload_len}\r\n",
        request_path(target)
    );
    if target.code() >= Target::Ps4V9.code() {
        let v = rp_version(target).ok_or(LanError::NoRpVersion(target))?;
        h.push_str(&format!("RP-Version: {v}\r\n"));
    }
    h.push_str("\r\n");
    Ok(h)
}

/// What a console hands back on a successful registration (chiaki-ng `ChiakiRegisteredHost`). The
/// registration key and RP key are credentials: keep them out of logs and repositories.
#[derive(Clone, PartialEq, Eq)]
pub struct RegisteredHost {
    pub target: Target,
    pub ap_ssid: Option<String>,
    pub ap_bssid: Option<String>,
    pub ap_key: Option<String>,
    pub ap_name: Option<String>,
    pub server_mac: [u8; 6],
    pub server_nickname: Option<String>,
    /// Up to 16 bytes, zero-padded, as chiaki-ng stores it.
    pub rp_regist_key: [u8; 16],
    pub rp_key_type: u32,
    pub rp_key: [u8; 16],
}

impl std::fmt::Debug for RegisteredHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredHost")
            .field("target", &self.target)
            .field("server_nickname", &self.server_nickname)
            .field("rp_key_type", &self.rp_key_type)
            .field("rp_regist_key", &"<redacted>")
            .field("rp_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl RegisteredHost {
    /// The wake-up credential: chiaki-ng reads the registration key's text as a hexadecimal number.
    pub fn wakeup_credential(&self) -> Option<u64> {
        let end = self.rp_regist_key.iter().position(|&b| b == 0).unwrap_or(16);
        let text = std::str::from_utf8(&self.rp_regist_key[..end]).ok()?;
        u64::from_str_radix(text, 16).ok()
    }
}

/// C `parse_hex` into a fixed buffer: even length, hex digits, at most `N` bytes.
fn parse_hex<const N: usize>(hex: &str) -> Option<([u8; N], usize)> {
    if !hex.len().is_multiple_of(2) || hex.len() / 2 > N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some((out, hex.len() / 2))
}

fn strtoul(s: &str) -> u32 {
    let s = s.trim();
    s.strip_prefix("0x").map_or_else(|| s.parse().ok(), |h| u32::from_str_radix(h, 16).ok()).unwrap_or(0)
}

/// chiaki-ng `regist_parse_response_payload`, given the decrypted body. The registration key, RP key
/// and MAC address are all required.
pub fn parse_response_payload(target: Target, body: &[u8]) -> Result<RegisteredHost, LanError> {
    let headers = http::parse_headers(body)?;
    let ps5 = target.is_ps5();
    let get = |k: &str| headers.iter().find(|(hk, _)| hk == k).map(|(_, v)| v.clone());
    let fit = |k: &str, max: usize| get(k).filter(|v| v.len() < max);
    let regist_key = get(if ps5 { "PS5-RegistKey" } else { "PS4-RegistKey" })
        .and_then(|v| parse_hex::<16>(&v))
        .map(|(k, _)| k)
        .ok_or(LanError::MissingField("RegistKey"))?;
    let rp_key = get("RP-Key")
        .and_then(|v| parse_hex::<16>(&v))
        .filter(|(_, n)| *n == 16)
        .map(|(k, _)| k)
        .ok_or(LanError::MissingField("RP-Key"))?;
    let server_mac = get(if ps5 { "PS5-Mac" } else { "PS4-Mac" })
        .and_then(|v| parse_hex::<6>(&v))
        .filter(|(_, n)| *n == 6)
        .map(|(k, _)| k)
        .ok_or(LanError::MissingField("Mac"))?;
    Ok(RegisteredHost {
        target,
        ap_ssid: fit("AP-Ssid", 0x30),
        ap_bssid: fit("AP-Bssid", 0x20),
        ap_key: fit("AP-Key", 0x50),
        ap_name: fit("AP-Name", 0x20),
        server_mac,
        server_nickname: fit(if ps5 { "PS5-Nickname" } else { "PS4-Nickname" }, 0x20),
        rp_regist_key: regist_key,
        rp_key_type: get("RP-KeyType").map_or(0, |v| strtoul(&v)),
        rp_key,
    })
}

/// chiaki-ng `regist_recv_response`, after the bytes have arrived: checks the status, finds the body by
/// its `Content-Length`, decrypts it and parses it.
pub fn parse_response(target: Target, crypt: &RpCrypt, response: &[u8]) -> Result<RegisteredHost, LanError> {
    let header_len = http::header_end(response).ok_or(LanError::NotHttp)?;
    let head = http::parse_response(&response[..header_len])?;
    if head.code != 200 {
        let reason = head.header("RP-Application-Reason").and_then(|r| u32::from_str_radix(r.trim_start_matches("0x"), 16).ok());
        return Err(LanError::Refused { code: head.code, reason });
    }
    let content_len: usize =
        head.header("Content-Length").and_then(|v| v.trim().parse().ok()).filter(|&n| n > 0).ok_or(LanError::MissingField("Content-Length"))?;
    let body = header_len.checked_add(content_len).and_then(|end| response.get(header_len..end)).ok_or(LanError::Truncated)?;
    parse_response_payload(target, &crypt.decrypt(0, body))
}

fn io(e: std::io::Error) -> LanError {
    LanError::Io(e)
}

/// UDP search on the registration port: the console answers `RES3`/`RES2` from the address to register
/// with.
fn search(host: IpAddr, target: Target) -> Result<SocketAddr, LanError> {
    let (src, res): (&[u8], &[u8]) = if target.is_ps5() { (b"SRC3\0", b"RES3") } else { (b"SRC2\0", b"RES2") };
    let any: IpAddr = if host.is_ipv4() { std::net::Ipv4Addr::UNSPECIFIED.into() } else { std::net::Ipv6Addr::UNSPECIFIED.into() };
    let socket = UdpSocket::bind((any, 0)).map_err(io)?;
    socket.connect((host, REGIST_PORT)).map_err(io)?;
    socket.send(src).map_err(io)?;
    let deadline = Instant::now() + SEARCH_TIMEOUT;
    let mut buf = [0u8; 0x100];
    loop {
        let left = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(LanError::Timeout("search"))?;
        match crate::udp::recv_from_within(&socket, &mut buf, left) {
            Ok(None) => return Err(LanError::Timeout("search")),
            Ok(Some((n, from))) if buf[..n].starts_with(res) => return Ok(SocketAddr::new(from.ip(), REGIST_PORT)),
            Ok(Some(_)) => continue,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Err(LanError::Timeout("search"));
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset || e.kind() == std::io::ErrorKind::ConnectionRefused => {
                return Err(LanError::NotListening);
            }
            Err(e) => return Err(io(e)),
        }
    }
}

/// Registers with the console at `host` on the home network. The console must be showing its
/// *Link Device* screen with `pin`.
pub fn register(host: IpAddr, target: Target, identity: &Identity, pin: u32) -> Result<RegisteredHost, LanError> {
    let mut ambassador = [0u8; 16];
    getrandom::fill(&mut ambassador).map_err(|e| LanError::Random(e.to_string()))?;
    let (payload, crypt) = request_payload(target, &ambassador, identity, pin)?;
    let header = request_header(target, payload.len())?;
    let addr = search(host, target)?;
    std::thread::sleep(SEARCH_TO_REQUEST_DELAY);
    let mut stream = TcpStream::connect_timeout(&addr, RESPONSE_TIMEOUT).map_err(io)?;
    stream.set_write_timeout(Some(RESPONSE_TIMEOUT)).map_err(io)?;
    stream.write_all(header.as_bytes()).map_err(io)?;
    stream.write_all(&payload).map_err(io)?;
    let response = read_response(&mut stream)?;
    parse_response(target, &crypt, &response)
}

/// Reads until the header and its `Content-Length` body are in, within the timeout and 1500 bytes
/// (chiaki-ng's buffer).
fn read_response(stream: &mut TcpStream) -> Result<Vec<u8>, LanError> {
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    let mut buf = Vec::with_capacity(RESPONSE_BUF_SIZE);
    let mut chunk = [0u8; 512];
    loop {
        if let Some(end) = http::header_end(&buf) {
            let len = http::parse_response(&buf[..end])
                .ok()
                .and_then(|r| r.header("Content-Length").and_then(|v| v.trim().parse::<usize>().ok()))
                .unwrap_or(0);
            if buf.len() >= end + len {
                return Ok(buf);
            }
        }
        if buf.len() >= RESPONSE_BUF_SIZE {
            return Err(LanError::Truncated);
        }
        let left = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(LanError::Timeout("response"))?;
        stream.set_read_timeout(Some(left)).map_err(io)?;
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(buf),
            Ok(n) => buf.extend_from_slice(&chunk[..n.min(RESPONSE_BUF_SIZE - buf.len())]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Err(LanError::Timeout("response"));
            }
            Err(e) => return Err(io(e)),
        }
    }
}
