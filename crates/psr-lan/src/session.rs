// SPDX-License-Identifier: AGPL-3.0-only
//! Starting a Remote Play session on the home network: the session request that returns a nonce, then the
//! ctrl channel up to the console's session ID. Ported from chiaki-ng `lib/src/session.c`
//! (LicenseRef-AGPL-3.0-only-OpenSSL), the part of `session_thread_func` before Senkusha and the stream
//! connection, which are the next parts of step 6 in `docs/PORT-MAP.md`.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use base64::Engine;
use psr_crypto::Target;
use psr_crypto::rpcrypt::RpCrypt;

use crate::LanError;
use crate::ctrl::{self, CtrlCipher, CtrlEvent, Framer, MessageType};
use crate::http;
use crate::regist::{RegisteredHost, rp_version};

pub const SESSION_PORT: u16 = 9295;
/// chiaki-ng `SESSION_EXPECT_TIMEOUT_MS` and `CTRL_EXPECT_TIMEOUT`.
const EXPECT_TIMEOUT: Duration = Duration::from_secs(5);
/// chiaki-ng `SESSION_EXPECT_CTRL_START_MS`: how long the console has to send its session ID.
const CTRL_START_TIMEOUT: Duration = Duration::from_secs(10);
/// A heartbeat request this soon after the last reply is not answered again, so a flood of them cannot fill
/// RUDP's send buffer (the security review of step 9c-2). The console asks every few seconds.
const HEARTBEAT_MIN_GAP: Duration = Duration::from_secs(1);
/// How many other ctrl messages [`Session::switch_to_stream`] keeps while it waits.
pub const SWITCH_EVENTS_MAX: usize = 64;
/// chiaki-ng: "PS4 doesn't always react right away, sleep a bit".
const BEFORE_CTRL_DELAY: Duration = Duration::from_millis(10);
/// chiaki-ng reads both HTTP replies into a 512-byte buffer.
const HEAD_BUF_SIZE: usize = 512;

/// chiaki-ng `CHIAKI_RP_APPLICATION_REASON_*`.
pub mod reason {
    pub const REGIST_FAILED: u32 = 0x8010_8b09;
    pub const INVALID_PSN_ID: u32 = 0x8010_8b02;
    pub const IN_USE: u32 = 0x8010_8b10;
    pub const CRASH: u32 = 0x8010_8b15;
    pub const RP_VERSION: u32 = 0x8010_8b11;
    pub const UNKNOWN: u32 = 0x8010_8bff;
}

/// chiaki-ng `chiaki_rp_application_reason_string`.
pub fn reason_text(reason: Option<u32>) -> &'static str {
    match reason {
        Some(reason::REGIST_FAILED) => "registration failed, probably an invalid PIN",
        Some(reason::INVALID_PSN_ID) => "invalid PSN ID",
        Some(reason::IN_USE) => "Remote Play is already in use",
        Some(reason::CRASH) => "Remote Play on the console crashed",
        Some(reason::RP_VERSION) => "RP-Version mismatch",
        _ => "unknown reason",
    }
}

/// The video codec asked for. ps-remote asks for H.264, which browsers take over WebRTC as it is
/// (`docs/PORT-MAP.md` §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Codec {
    #[default]
    H264,
    H265,
    H265Hdr,
}

impl Codec {
    /// The value of `RP-StreamingType` (chiaki-ng `ctrl_connect`).
    pub const fn streaming_type(self) -> u32 {
        match self {
            Self::H264 => 1,
            Self::H265 => 2,
            Self::H265Hdr => 3,
        }
    }
}

/// chiaki-ng `chiaki_session_init`'s device ID: a fixed 10-byte prefix, 16 random bytes, 6 zero bytes.
pub fn did(random: &[u8; 16]) -> [u8; 32] {
    const PREFIX: [u8; 10] = [0x00, 0x18, 0x00, 0x00, 0x00, 0x07, 0x00, 0x40, 0x00, 0x80];
    let mut did = [0u8; 32];
    did[..10].copy_from_slice(&PREFIX);
    did[10..26].copy_from_slice(random);
    did
}

fn request_path(target: Target) -> &'static str {
    match target {
        Target::Ps4V8 | Target::Ps4V9 => "/sce/rp/session",
        t if t.is_ps5() => "/sie/ps5/rp/sess/init",
        _ => "/sie/ps4/rp/sess/init",
    }
}

/// chiaki-ng `session_thread_request_session`'s request. The registration key is sent as hex of its bytes
/// up to the first zero byte.
///
/// **Difference from chiaki-ng:** its `nibble_char` writes `'a' + v` for nibbles 10 to 15, so it would send
/// `k` to `p` instead of `a` to `f`. Real registration keys are the text of a hex number, whose bytes have
/// no such nibble, so the two agree on every key a console hands out; this port writes correct hex.
pub fn session_request(target: Target, host: &str, regist_key: &[u8; 16]) -> Result<String, LanError> {
    session_request_port(target, host, SESSION_PORT, regist_key)
}

/// [`session_request`] naming another port in `Host`: over PSN chiaki-ng names the console's end of the
/// punched control hole.
pub fn session_request_port(target: Target, host: &str, port: u16, regist_key: &[u8; 16]) -> Result<String, LanError> {
    let version = rp_version(target).ok_or(LanError::NoRpVersion(target))?;
    let end = regist_key.iter().position(|&b| b == 0).unwrap_or(regist_key.len());
    let key: String = regist_key[..end].iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "GET {} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: remoteplay Windows\r\nConnection: close\r\n\
         Content-Length: 0\r\nRP-Registkey: {key}\r\nRp-Version: {version}\r\n\r\n",
        request_path(target)
    ))
}

/// chiaki-ng `parse_session_response`: a 200 reply with a 16-byte base64 `RP-Nonce` starts a session.
pub fn parse_session_response(head: &[u8]) -> Result<[u8; 16], LanError> {
    let response = http::parse_response(head)?;
    let nonce = response.header("RP-Nonce");
    if response.code == 200
        && let Some(nonce) = nonce
    {
        let raw = base64::engine::general_purpose::STANDARD.decode(nonce.trim()).map_err(|_| LanError::BadNonce)?;
        return raw.try_into().map_err(|_| LanError::BadNonce);
    }
    let reason = response
        .header("RP-Application-Reason")
        .and_then(|r| u32::from_str_radix(r.trim().trim_start_matches("0x"), 16).ok());
    // chiaki-ng matches this one header without regard to case.
    let rp_version =
        response.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("RP-Version")).map(|(_, v)| v.clone());
    Err(LanError::SessionRefused { code: response.code, reason, rp_version })
}

/// chiaki-ng `chiaki_rp_version_parse`.
fn parse_rp_version(version: &str, ps5: bool) -> Option<Target> {
    match (ps5, version) {
        (true, "1.0") => Some(Target::Ps5V1),
        (false, "8.0") => Some(Target::Ps4V8),
        (false, "9.0") => Some(Target::Ps4V9),
        (false, "10.0") => Some(Target::Ps4V10),
        _ => None,
    }
}

/// When a refusal names a different RP-Version that this port knows, the target to ask again with
/// (chiaki-ng's version-mismatch retry).
pub fn retry_target(err: &LanError, current: Target) -> Option<Target> {
    let LanError::SessionRefused { reason: Some(r), rp_version: Some(version), .. } = err else { return None };
    if (*r != reason::RP_VERSION && *r != reason::UNKNOWN) || Some(version.as_str()) == rp_version(current) {
        return None;
    }
    match parse_rp_version(version, current.is_ps5()) {
        Some(t) => Some(t),
        // chiaki-ng: "Reported Server RP-Version is 5.0. This is probably nonsense, let's try with 9.0".
        None if !current.is_ps5() && version == "5.0" => Some(Target::Ps4V9),
        None => None,
    }
}

fn io(e: std::io::Error) -> LanError {
    LanError::Io(e)
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

/// Reads an HTTP header, returning it and whatever arrived after it.
fn read_head(stream: &mut TcpStream, what: &'static str) -> Result<(Vec<u8>, Vec<u8>), LanError> {
    let deadline = Instant::now() + EXPECT_TIMEOUT;
    let mut buf = Vec::with_capacity(HEAD_BUF_SIZE);
    let mut chunk = [0u8; HEAD_BUF_SIZE];
    loop {
        if let Some(end) = http::header_end(&buf) {
            let rest = buf.split_off(end);
            return Ok((buf, rest));
        }
        if buf.len() >= HEAD_BUF_SIZE {
            return Err(LanError::Truncated);
        }
        let left =
            deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(LanError::Timeout(what))?;
        stream.set_read_timeout(Some(left)).map_err(io)?;
        match stream.read(&mut chunk[..HEAD_BUF_SIZE - buf.len()]) {
            Ok(0) => return Err(LanError::CtrlClosed),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if is_timeout(&e) => return Err(LanError::Timeout(what)),
            Err(e) => return Err(io(e)),
        }
    }
}

fn connect(addr: SocketAddr) -> Result<TcpStream, LanError> {
    let stream = TcpStream::connect_timeout(&addr, EXPECT_TIMEOUT).map_err(io)?;
    stream.set_write_timeout(Some(EXPECT_TIMEOUT)).map_err(io)?;
    Ok(stream)
}

/// One session request (chiaki-ng `session_thread_request_session`, home-network path).
fn request_nonce(addr: SocketAddr, target: Target, regist_key: &[u8; 16]) -> Result<[u8; 16], LanError> {
    let mut stream = connect(addr)?;
    stream.write_all(session_request(target, &addr.ip().to_string(), regist_key)?.as_bytes()).map_err(io)?;
    let (head, _) = read_head(&mut stream, "session reply")?;
    parse_session_response(&head)
}

/// chiaki-ng `ctrl_message_set_fallback_session_id`: used when the console's session ID never arrives or
/// is malformed. The seconds of a clock, then 48 random bytes in base64.
pub fn fallback_session_id(seconds: u64, random: &[u8; 48]) -> String {
    format!("{seconds}{}", base64::engine::general_purpose::STANDARD.encode(random))
}

/// A started session: the ctrl channel is open and the console has handed out its session ID. Keep calling
/// [`Session::poll`]: it answers the console's heartbeats, and the console ends the session when they stop.
pub struct Session {
    target: Target,
    link: Box<dyn CtrlLink>,
    cipher: CtrlCipher,
    framer: Framer,
    session_id: String,
    session_id_was_fallback: bool,
    server_type: Option<u8>,
    prohibit: bool,
    /// Over RUDP chiaki-ng also sends a heartbeat reply on its own this often, once the console has asked
    /// for one (`CTRL_RUDP_HEARTBEAT_REP_INTERVAL_MS`).
    heartbeat_every: Option<Duration>,
    last_heartbeat: Option<Instant>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("target", &self.target)
            .field("server_type", &self.server_type)
            .field("session_id_was_fallback", &self.session_id_was_fallback)
            .finish_non_exhaustive()
    }
}

/// Starts a session with a linked console at `host` on the home network.
pub fn start(host: IpAddr, console: &RegisteredHost, codec: Codec) -> Result<Session, LanError> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|e| LanError::Random(e.to_string()))?;
    start_at(SocketAddr::new(host, SESSION_PORT), console, codec, &did(&random))
}

/// [`start`] at any address, with a given device ID. The `Host` headers still name port 9295, as
/// chiaki-ng's do.
pub fn start_at(addr: SocketAddr, console: &RegisteredHost, codec: Codec, did: &[u8; 32]) -> Result<Session, LanError> {
    let mut target = console.target;
    // chiaki-ng asks up to three times, following the console's RP-Version each time it names a new one.
    let mut nonce = request_nonce(addr, target, &console.rp_regist_key);
    for _ in 0..2 {
        let Some(next) = nonce.as_ref().err().and_then(|e| retry_target(e, target)) else { break };
        target = next;
        nonce = request_nonce(addr, target, &console.rp_regist_key);
    }
    let nonce = nonce?;
    let mut cipher = CtrlCipher::new(RpCrypt::auth(target, &nonce, &console.rp_key)?);
    std::thread::sleep(BEFORE_CTRL_DELAY);

    let host = addr.ip().to_string();
    let request = ctrl::ctrl_request(target, &host, &mut cipher, &console.rp_regist_key, did, codec)?;
    // chiaki-ng resends once, on a fresh connection, when the first reply times out.
    let mut stream = connect(addr)?;
    stream.write_all(request.as_bytes()).map_err(io)?;
    let (head, rest) = match read_head(&mut stream, "ctrl reply") {
        Err(LanError::Timeout(_)) => {
            stream = connect(addr)?;
            stream.write_all(request.as_bytes()).map_err(io)?;
            read_head(&mut stream, "ctrl reply")?
        }
        other => other?,
    };
    let response = ctrl::parse_ctrl_response(&head, &mut cipher)?;
    Session::over(Box::new(TcpLink(stream)), target, cipher, &rest, response, None)
}

/// How ctrl frames travel: a TCP connection at home, the punched hole's RUDP over PSN (`psr-psn`).
pub trait CtrlLink: Send {
    /// Sends ctrl frames, as [`CtrlCipher::seal`] makes them.
    fn write(&mut self, frames: &[u8]) -> Result<(), LanError>;
    /// What arrives within `timeout`, as ctrl frame bytes: nothing if it ran out first. The console
    /// closing the channel is [`LanError::CtrlClosed`].
    fn read(&mut self, timeout: Duration) -> Result<Vec<u8>, LanError>;
    /// Asks the console to move to the stream connection, where the link has a message for it: RUDP's over
    /// PSN (chiaki-ng `chiaki_rudp_send_switch_to_stream_connection_message`). Nothing at home.
    fn switch_to_stream(&mut self) -> Result<bool, LanError> {
        Ok(false)
    }
}

/// The home network's ctrl connection.
struct TcpLink(TcpStream);

impl CtrlLink for TcpLink {
    fn write(&mut self, frames: &[u8]) -> Result<(), LanError> {
        self.0.write_all(frames).map_err(io)
    }

    fn read(&mut self, timeout: Duration) -> Result<Vec<u8>, LanError> {
        let mut chunk = [0u8; ctrl::MAX_FRAME];
        self.0.set_read_timeout(Some(timeout.max(Duration::from_millis(1)))).map_err(io)?;
        match self.0.read(&mut chunk) {
            Ok(0) => Err(LanError::CtrlClosed),
            Ok(n) => Ok(chunk[..n].to_vec()),
            Err(e) if is_timeout(&e) => Ok(Vec::new()),
            Err(e) => Err(io(e)),
        }
    }
}

impl Session {
    /// The rest of chiaki-ng's ctrl start once the ctrl request has its answer, on any link: `rest` is what
    /// arrived after the answer's header. Waits for the console's session ID, then enables the features.
    pub fn over(
        link: Box<dyn CtrlLink>,
        target: Target,
        cipher: CtrlCipher,
        rest: &[u8],
        response: ctrl::CtrlResponse,
        heartbeat_every: Option<Duration>,
    ) -> Result<Session, LanError> {
        let mut framer = Framer::default();
        framer.push(rest)?;
        let mut session = Session {
            target,
            link,
            cipher,
            framer,
            session_id: String::new(),
            session_id_was_fallback: false,
            server_type: response.server_type,
            prohibit: response.prohibit,
            heartbeat_every,
            last_heartbeat: None,
        };
        session.await_session_id()?;
        session.enable_features()?;
        Ok(session)
    }

    pub fn target(&self) -> Target {
        self.target
    }

    /// The auth cipher made from the session's nonce.
    pub fn rpcrypt(&self) -> &RpCrypt {
        self.cipher.crypt()
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Whether chiaki-ng's fallback session ID is in use, because the console's was missing or not in
    /// the form chiaki-ng accepts (current PS5 firmware sends a shorter one, see
    /// [`ctrl::parse_session_id`]).
    pub fn session_id_was_fallback(&self) -> bool {
        self.session_id_was_fallback
    }

    /// 0 is a PS4, 1 a PS4 Pro, 2 a PS5, when the console said.
    pub fn server_type(&self) -> Option<u8> {
        self.server_type
    }

    pub fn prohibit(&self) -> bool {
        self.prohibit
    }

    /// Sends one ctrl message.
    pub fn send(&mut self, message_type: u16, payload: &[u8]) -> Result<(), LanError> {
        let frame = self.cipher.seal(message_type, payload);
        self.link.write(&frame)
    }

    fn send_heartbeat(&mut self) -> Result<(), LanError> {
        self.send(MessageType::HeartbeatRep.code(), &[])?;
        self.last_heartbeat = Some(Instant::now());
        Ok(())
    }

    /// The heartbeat reply chiaki-ng sends unasked over RUDP, when one is due.
    fn heartbeat_if_due(&mut self) -> Result<(), LanError> {
        if let (Some(every), Some(last)) = (self.heartbeat_every, self.last_heartbeat)
            && last.elapsed() >= every
        {
            self.send_heartbeat()?;
        }
        Ok(())
    }

    fn await_session_id(&mut self) -> Result<(), LanError> {
        let deadline = Instant::now() + CTRL_START_TIMEOUT;
        loop {
            for e in self.drain()? {
                match e {
                    CtrlEvent::SessionId(id) => return self.set_session_id(id),
                    // Answering a login PIN is not ported yet: it is only asked on consoles whose user
                    // has a passcode for Remote Play.
                    CtrlEvent::LoginPinRequested => return Err(LanError::LoginPinRequired),
                    _ => {}
                }
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) else {
                return self.set_session_id(None);
            };
            self.read_some(left)?;
        }
    }

    fn set_session_id(&mut self, id: Option<String>) -> Result<(), LanError> {
        match id {
            Some(id) => self.session_id = id,
            None => {
                let mut random = [0u8; 48];
                getrandom::fill(&mut random).map_err(|e| LanError::Random(e.to_string()))?;
                let seconds =
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
                self.session_id = fallback_session_id(seconds, &random);
                self.session_id_was_fallback = true;
            }
        }
        Ok(())
    }

    /// chiaki-ng `ctrl_enable_features`, with DualSense features and the keyboard off: the microphone
    /// message twice, then display devices.
    fn enable_features(&mut self) -> Result<(), LanError> {
        // chiaki-ng `ctrl_message_toggle_microphone(ctrl, false)`: {0, 1, 1, 89}, the third byte cleared
        // only when muting.
        self.send(MessageType::MicToggle.code(), &[0, 1, 1, 89])?;
        self.send(MessageType::MicToggle.code(), &[0, 1, 1, 89])?;
        self.send(MessageType::DisplayDevices.code(), &[0; 4])
    }

    /// chiaki-ng's step before the stream connection over PSN: the link's switch message, then the console's
    /// `SwitchToStreamConnection` within `timeout`. The other messages that come meanwhile are returned. At
    /// home, where the link has no such message, nothing is sent and nothing waited for.
    pub fn switch_to_stream(&mut self, timeout: Duration) -> Result<Vec<CtrlEvent>, LanError> {
        if !self.link.switch_to_stream()? {
            return Ok(Vec::new());
        }
        let deadline = Instant::now() + timeout;
        let mut others = Vec::new();
        loop {
            self.heartbeat_if_due()?;
            for e in self.drain()? {
                if e == CtrlEvent::SwitchToStreamConnection {
                    return Ok(others);
                }
                // Kept for the caller up to a bound, so a flood in the wait cannot grow it without end.
                if others.len() < SWITCH_EVENTS_MAX {
                    others.push(e);
                }
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) else {
                return Err(LanError::Timeout("switch to stream connection ack"));
            };
            // Woken for the next unasked heartbeat too, as `poll` is.
            let until_heartbeat = match (self.heartbeat_every, self.last_heartbeat) {
                (Some(every), Some(last)) => every.saturating_sub(last.elapsed()),
                _ => left,
            };
            self.read_some(left.min(until_heartbeat).max(Duration::from_millis(1)))?;
        }
    }

    /// Reads what has arrived within `timeout` and returns the messages, having already answered any
    /// heartbeat request.
    pub fn poll(&mut self, timeout: Duration) -> Result<Vec<CtrlEvent>, LanError> {
        self.heartbeat_if_due()?;
        let mut events = self.drain()?;
        if events.is_empty() {
            // Wake for the next unasked heartbeat, if it comes before the timeout.
            let until_heartbeat = match (self.heartbeat_every, self.last_heartbeat) {
                (Some(every), Some(last)) => every.saturating_sub(last.elapsed()),
                _ => timeout,
            };
            self.read_some(timeout.min(until_heartbeat))?;
            events = self.drain()?;
        }
        self.heartbeat_if_due()?;
        Ok(events)
    }

    fn read_some(&mut self, timeout: Duration) -> Result<(), LanError> {
        let bytes = self.link.read(timeout)?;
        self.framer.push(&bytes)
    }

    fn drain(&mut self) -> Result<Vec<CtrlEvent>, LanError> {
        let mut events = Vec::new();
        while let Some((ty, payload)) = self.framer.next_frame() {
            // A session ID is never empty; an empty one uses no counter, so anyone could send it to cut short
            // the wait for the console's. Passed over (the security review of step 9c-2).
            if ty == MessageType::SessionId.code() && payload.is_empty() {
                continue;
            }
            let event = ctrl::event(ty, &self.cipher.open(&payload));
            if event == CtrlEvent::HeartbeatRequested
                && self.last_heartbeat.is_none_or(|last| last.elapsed() >= HEARTBEAT_MIN_GAP)
            {
                self.send_heartbeat()?;
            }
            events.push(event);
        }
        Ok(events)
    }
}
