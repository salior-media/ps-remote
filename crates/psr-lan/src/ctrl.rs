// SPDX-License-Identifier: AGPL-3.0-only
//! The ctrl channel: a TCP connection to the console that stays open for the whole session, carrying
//! small encrypted messages (session ID, heartbeats, login PIN, display state). Ported from chiaki-ng
//! `lib/src/ctrl.c` (LicenseRef-AGPL-3.0-only-OpenSSL), home-network path only: the PSN (RUDP) path is a
//! later step of `docs/PORT-MAP.md`.

use base64::Engine;
use psr_crypto::Target;
use psr_crypto::rpcrypt::RpCrypt;

use crate::LanError;
use crate::http;
use crate::regist::rp_version;
use crate::session::{Codec, SESSION_PORT};

/// chiaki-ng's `SESSION_OSTYPE`, sent NUL-terminated.
const OS_TYPE: &[u8] = b"Win10.0.0\0";
/// chiaki-ng's ctrl receive buffer: a frame, header included, must fit.
pub const MAX_FRAME: usize = 512;
const HEADER: usize = 8;

/// chiaki-ng `CtrlMessageType`, the ones this port sends or reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    DisplayA,
    LoginPinReq,
    Login,
    EnableDualsenseFeatures,
    DisplayB,
    SessionId,
    SwitchToStreamConnection,
    MicToggle,
    HeartbeatReq,
    HeartbeatRep,
    DisplayDevices,
    LoginPinRep,
}

impl MessageType {
    pub const fn code(self) -> u16 {
        match self {
            Self::DisplayA => 0x1,
            Self::LoginPinReq => 0x4,
            Self::Login => 0x5,
            Self::EnableDualsenseFeatures => 0x13,
            Self::DisplayB => 0x16,
            Self::SessionId => 0x33,
            Self::SwitchToStreamConnection => 0x34,
            Self::MicToggle => 0x36,
            Self::HeartbeatReq => 0xfe,
            Self::HeartbeatRep => 0x1fe,
            Self::DisplayDevices => 0x910,
            Self::LoginPinRep => 0x8004,
        }
    }
}

/// The session's auth cipher with the two message counters chiaki-ng keeps beside it. Each side counts
/// the payloads it encrypts; an empty payload is sent bare and uses no counter.
#[derive(Debug, Clone)]
pub struct CtrlCipher {
    crypt: RpCrypt,
    local: u64,
    remote: u64,
}

impl CtrlCipher {
    pub fn new(crypt: RpCrypt) -> Self {
        Self { crypt, local: 0, remote: 0 }
    }

    /// The session's auth cipher, which chiaki-ng also uses for the launch spec.
    pub fn crypt(&self) -> &RpCrypt {
        &self.crypt
    }

    pub fn local(&self) -> u64 {
        self.local
    }

    pub fn remote(&self) -> u64 {
        self.remote
    }

    pub fn set_local(&mut self, counter: u64) {
        self.local = counter;
    }

    pub fn set_remote(&mut self, counter: u64) {
        self.remote = counter;
    }

    /// Encrypts one request field at the next local counter.
    fn field(&mut self, plain: &[u8]) -> String {
        let enc = self.crypt.encrypt(self.local, plain);
        self.local += 1;
        base64::engine::general_purpose::STANDARD.encode(enc)
    }

    /// chiaki-ng `ctrl_message_send`: an 8-byte header (payload length and type, big-endian, then two zero
    /// bytes) and the encrypted payload.
    pub fn seal(&mut self, message_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(HEADER + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&message_type.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        if !payload.is_empty() {
            frame.extend(self.crypt.encrypt(self.local, payload));
            self.local += 1;
        }
        frame
    }

    /// chiaki-ng `ctrl_message_received`: decrypts a received payload at the next remote counter.
    pub fn open(&mut self, payload: &[u8]) -> Vec<u8> {
        if payload.is_empty() {
            return Vec::new();
        }
        let plain = self.crypt.decrypt(self.remote, payload);
        self.remote += 1;
        plain
    }
}

fn request_path(target: Target) -> &'static str {
    match target {
        Target::Ps4V8 | Target::Ps4V9 => "/sce/rp/session/ctrl",
        t if t.is_ps5() => "/sie/ps5/rp/sess/ctrl",
        _ => "/sie/ps4/rp/sess/ctrl",
    }
}

/// chiaki-ng `ctrl_connect`'s request. Its fields are encrypted in order at local counters 0, 1, 2,
/// then 3 for the start bitrate (PS4 10 and later) and the next one for the streaming type (PS5).
pub fn ctrl_request(
    target: Target,
    host: &str,
    cipher: &mut CtrlCipher,
    regist_key: &[u8; 16],
    did: &[u8; 32],
    codec: Codec,
) -> Result<String, LanError> {
    let version = rp_version(target).ok_or(LanError::NoRpVersion(target))?;
    let auth = cipher.field(regist_key);
    let did = cipher.field(did);
    let os_type = cipher.field(OS_TYPE);
    let mut r = format!(
        "GET {} HTTP/1.1\r\nHost: {host}:{SESSION_PORT}\r\nUser-Agent: remoteplay Windows\r\nConnection: keep-alive\r\n\
         Content-Length: 0\r\nRP-Auth: {auth}\r\nRP-Version: {version}\r\nRP-Did: {did}\r\nRP-ControllerType: 3\r\n\
         RP-ClientType: 11\r\nRP-OSType: {os_type}\r\nRP-ConPath: 1\r\n",
        request_path(target)
    );
    if target.is_ps5() {
        // chiaki-ng: without it a PS5 sends some adaptive trigger effects in a form the controller
        // doesn't apply.
        r.push_str("RP-PadProcNo: 3\r\n");
    }
    if target.code() >= Target::Ps4V10.code() {
        r.push_str(&format!("RP-StartBitrate: {}\r\n", cipher.field(&[0; 4])));
    }
    if target.is_ps5() {
        r.push_str(&format!("RP-StreamingType: {}\r\n", cipher.field(&codec.streaming_type().to_le_bytes())));
    }
    r.push_str("\r\n");
    Ok(r)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtrlResponse {
    /// 0 is a PS4, 1 a PS4 Pro, 2 a PS5.
    pub server_type: Option<u8>,
    /// The console says what it is showing may not be streamed.
    pub prohibit: bool,
}

/// chiaki-ng `parse_ctrl_response` and what `ctrl_connect` does with it. `RP-Server-Type` takes a remote
/// counter only when it is present and 16 bytes long, as in chiaki-ng.
pub fn parse_ctrl_response(head: &[u8], cipher: &mut CtrlCipher) -> Result<CtrlResponse, LanError> {
    let response = http::parse_response(head)?;
    if response.code != 200 {
        return Err(LanError::CtrlRefused(response.code));
    }
    let server_type = match response.header("RP-Server-Type") {
        Some(v) => {
            let raw = base64::engine::general_purpose::STANDARD.decode(v.trim()).map_err(|_| LanError::BadHeader(http::name_only("RP-Server-Type")))?;
            (raw.len() == 16).then(|| cipher.open(&raw)[0])
        }
        None => None,
    };
    let prohibit = response.header("RP-Prohibit").is_some_and(|v| v.trim().parse::<i64>().ok() == Some(1));
    Ok(CtrlResponse { server_type, prohibit })
}

/// Splits the ctrl byte stream into frames.
#[derive(Debug, Default)]
pub struct Framer {
    buf: Vec<u8>,
}

impl Framer {
    /// Adds received bytes. Fails, as chiaki-ng does, once a frame is announced that would not fit its
    /// 512-byte buffer.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), LanError> {
        self.buf.extend_from_slice(bytes);
        let mut at = 0;
        while self.buf.len() >= at + HEADER {
            let len = u32::from_be_bytes(self.buf[at..at + 4].try_into().expect("4 bytes")) as usize;
            if HEADER + len > MAX_FRAME {
                return Err(LanError::CtrlOverflow);
            }
            at += HEADER + len;
        }
        Ok(())
    }

    fn announced(&self) -> usize {
        u32::from_be_bytes(self.buf[..4].try_into().expect("4 bytes")) as usize
    }

    /// The next whole frame's type and still-encrypted payload.
    pub fn next_frame(&mut self) -> Option<(u16, Vec<u8>)> {
        if self.buf.len() < HEADER || self.buf.len() < HEADER + self.announced() {
            return None;
        }
        let len = self.announced();
        let ty = u16::from_be_bytes([self.buf[4], self.buf[5]]);
        let payload = self.buf[HEADER..HEADER + len].to_vec();
        self.buf.drain(..HEADER + len);
        Some((ty, payload))
    }
}

/// chiaki-ng `ctrl_message_received_session_id`: one byte it skips, then 24 to 78 letters and digits.
///
/// The byte is the ID's length: 0x4a (74) in the form these rules were written for. A PS5 on
/// firmware of November 2026 sends a 16-character ID (length byte 0x10), which these rules refuse, so
/// chiaki-ng and this port both use [`crate::session::fallback_session_id`], which is again 74
/// characters long. That is kept, since it is the path chiaki-ng streams with.
pub fn parse_session_id(payload: &[u8]) -> Option<String> {
    let (_, id) = payload.split_first()?;
    if id.len() < 24 || id.len() >= 79 || !id.iter().all(u8::is_ascii_alphanumeric) {
        return None;
    }
    String::from_utf8(id.to_vec()).ok()
}

/// What a decrypted ctrl message means to the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtrlEvent {
    /// `None` when the console's session ID was malformed; chiaki-ng then makes up a fallback.
    SessionId(Option<String>),
    HeartbeatRequested,
    LoginPinRequested,
    /// The console's verdict on a login PIN.
    LoginResult { pin_incorrect: bool },
    SwitchToStreamConnection,
    /// chiaki-ng's "display A/B" messages: the console showing something it will not stream.
    Display { message_type: u16, payload: Vec<u8> },
    Other { message_type: u16, payload: Vec<u8> },
}

/// Classifies a decrypted message (chiaki-ng's `ctrl_message_received` switch).
pub fn event(message_type: u16, payload: &[u8]) -> CtrlEvent {
    let code = |t: MessageType| t.code();
    match message_type {
        t if t == code(MessageType::SessionId) => CtrlEvent::SessionId(parse_session_id(payload)),
        t if t == code(MessageType::HeartbeatReq) => CtrlEvent::HeartbeatRequested,
        t if t == code(MessageType::LoginPinReq) => CtrlEvent::LoginPinRequested,
        t if t == code(MessageType::Login) => CtrlEvent::LoginResult { pin_incorrect: payload.first() == Some(&1) },
        t if t == code(MessageType::SwitchToStreamConnection) => CtrlEvent::SwitchToStreamConnection,
        t if t == code(MessageType::DisplayA) || t == code(MessageType::DisplayB) => {
            CtrlEvent::Display { message_type, payload: payload.to_vec() }
        }
        _ => CtrlEvent::Other { message_type, payload: payload.to_vec() },
    }
}
