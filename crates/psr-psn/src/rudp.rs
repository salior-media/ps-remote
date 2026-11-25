// SPDX-License-Identifier: AGPL-3.0-only
//! RUDP: the console's reliable-datagram framing over the punched control hole, which carries registration,
//! the session request and ctrl when playing over PSN. Ported from chiaki-ng `lib/src/remote/rudp.c`
//! (LicenseRef-AGPL-3.0-only-OpenSSL). Step 9c-1 needs the handshake and the HTTP exchange; ctrl messages and
//! the send buffer come with the ctrl in 9c-2.
//!
//! A message is an 8-byte header — `0xC000 | (8 + data length)`, the constant `0x244F244F`, the type — then
//! its data. A datagram may chain a second message after the first's data. Most types' data starts with
//! the sender's 16-bit counter; the counter after the console's is what an answer names as its "remote
//! counter".
//!
//! 1. INIT_REQUEST, answered by INIT_RESPONSE, whose data from byte 8 on is a cookie.
//! 2. COOKIE_REQUEST carrying that cookie, answered by COOKIE_RESPONSE.
//! 3. For an HTTP request: a SESSION_MESSAGE with the request in a chained CTRL_MESSAGE, answered by a
//!    CTRL_MESSAGE with the response; then an ACK, answered by FINISH.
//!
//! **Differences from chiaki-ng.**
//! - **A wrong message does not cost a try.** chiaki-ng resends as soon as one datagram is not the answer;
//!   here each try listens for its whole second, passing over what is not the answer, so a stray datagram
//!   (a late holepunch request, say) cannot use up the tries.
//! - **A datagram too short to be RUDP is passed over**, where chiaki-ng ends the exchange.
//! - **The answer's minimum length is checked before it is taken**, not after, so a short one is passed over
//!   like any other wrong message.
//! - **A message's header must be well formed** (the security review's finding): its length word must start
//!   with `0xC` and the constant must follow, or it and the rest of its datagram are passed over. chiaki-ng
//!   reads any eight bytes as a header, so a late holepunch or STUN datagram whose seventh byte happened to be
//!   right would count as the answer. Every message the console sent in the live runs had both.
//! - **A request too long for one message is refused** rather than sent with its 12-bit length cut short.
//! - **A connection reset is waited out**, 10 ms at a time, where the loop would otherwise spin until the try
//!   ends (Windows reports an ICMP port-unreachable on the next receive).

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use crate::{PsnError, holepunch, stun};

pub const CONSTANT: u32 = 0x244F_244F;
pub const HEADER_LEN: usize = 8;
/// chiaki-ng `RUDP_EXPECT_TIMEOUT_MS`: how long each try listens.
pub const EXPECT_TIMEOUT: Duration = Duration::from_secs(1);
/// chiaki-ng passes 3 to every `chiaki_rudp_send_recv`.
pub const TRIES: usize = 3;
/// chiaki-ng's receive buffer.
pub const RECV_LEN: usize = 1500;
/// The 12-bit length covers the header and the data.
pub const MAX_DATA: usize = 0x0FFF - HEADER_LEN;
/// The top four bits of every header's length word.
const LEN_TAG: u16 = 0xC000;
/// How long to wait after a connection reset before receiving again.
const RESET_PAUSE: Duration = Duration::from_millis(10);

pub const INIT_REQUEST: u16 = 0x8030;
pub const INIT_RESPONSE: u16 = 0xD000;
pub const COOKIE_REQUEST: u16 = 0x9030;
pub const COOKIE_RESPONSE: u16 = 0xA030;
pub const SESSION_MESSAGE: u16 = 0x2030;
pub const STREAM_CONNECTION_SWITCH_ACK: u16 = 0x242E;
pub const ACK: u16 = 0x2430;
pub const CTRL_MESSAGE: u16 = 0x0230;
pub const OFFSET8: u16 = 0x1230;
pub const OFFSET10: u16 = 0x2630;
pub const FINISH: u16 = 0xC000;

/// The bytes after the counter in INIT and COOKIE requests, and after the header word.
const AFTER_COUNTER: [u8; 6] = [0x0B, 0x01, 0x01, 0x00, 0x01, 0x00];
const AFTER_HEADER: [u8; 2] = [0x05, 0x82];
const AFTER_ACK_COUNTERS: [u8; 2] = [0x00, 0x92];

/// One message of a datagram. Its `Debug` shows the type and the data's length, not the data, which may be
/// a registration's ciphertext or, later, ctrl's.
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    pub kind: u16,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Message")
            .field("kind", &format_args!("{:#06x}", self.kind))
            .field("len", &self.data.len())
            .finish()
    }
}

impl Message {
    /// chiaki-ng `subtype`: the type's first byte, which is what answers are recognised by.
    pub fn subtype(&self) -> u8 {
        self.kind.to_be_bytes()[0]
    }

    /// chiaki-ng `remote_counter`: the sender's counter, plus one, when the data has one.
    pub fn remote_counter(&self) -> Option<u16> {
        self.data.get(..2).map(|c| u16::from_be_bytes([c[0], c[1]]).wrapping_add(1))
    }
}

/// chiaki-ng `rudp_message_serialize`: each message's header and data, in order (the second chained after
/// the first). The header's length covers its own message only.
///
/// # Panics
/// If a message's data is longer than [`MAX_DATA`]: its length would not fit. [`Rudp::http`] refuses such a
/// request before it gets here.
pub fn serialize(messages: &[(u16, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (kind, data) in messages {
        assert!(data.len() <= MAX_DATA, "an RUDP message's data is at most {MAX_DATA} bytes");
        let len = u16::try_from(HEADER_LEN + data.len()).unwrap_or(0x0FFF);
        out.extend((LEN_TAG | len).to_be_bytes());
        out.extend(CONSTANT.to_be_bytes());
        out.extend(kind.to_be_bytes());
        out.extend(*data);
    }
    out
}

/// chiaki-ng `chiaki_rudp_message_parse`: the chain of messages in a datagram. A length that runs past the
/// datagram is cut to what is there; bytes after the last message too few for a header are ignored. A header
/// without the `0xC` tag and the constant ends the chain there (see the module notes).
pub fn parse(datagram: &[u8]) -> Vec<Message> {
    let mut out = Vec::new();
    let mut rest = datagram;
    while rest.len() >= HEADER_LEN {
        let word = u16::from_be_bytes([rest[0], rest[1]]);
        if word & 0xF000 != LEN_TAG || rest[2..6] != CONSTANT.to_be_bytes() {
            break;
        }
        let len = usize::from(word & 0x0FFF);
        let kind = u16::from_be_bytes([rest[6], rest[7]]);
        let data_len = len.saturating_sub(HEADER_LEN).min(rest.len() - HEADER_LEN);
        out.push(Message { kind, data: rest[HEADER_LEN..HEADER_LEN + data_len].to_vec() });
        rest = &rest[HEADER_LEN + data_len..];
    }
    out
}

/// chiaki-ng `chiaki_rudp_send_init_message`.
pub fn init_request(counter: u16, header: u32) -> Vec<u8> {
    serialize(&[(INIT_REQUEST, &handshake_data(counter, header, &[]))])
}

/// chiaki-ng `chiaki_rudp_send_cookie_message`: the cookie is INIT_RESPONSE's data from byte 8 on.
pub fn cookie_request(counter: u16, header: u32, cookie: &[u8]) -> Vec<u8> {
    serialize(&[(COOKIE_REQUEST, &handshake_data(counter, header, cookie))])
}

fn handshake_data(counter: u16, header: u32, tail: &[u8]) -> Vec<u8> {
    let mut d = counter.to_be_bytes().to_vec();
    d.extend(AFTER_COUNTER);
    d.extend(header.to_be_bytes());
    d.extend(AFTER_HEADER);
    d.extend(tail);
    d
}

/// chiaki-ng `chiaki_rudp_send_session_message`: a SESSION_MESSAGE naming the console's counter, with the
/// payload in a chained CTRL_MESSAGE. Both carry the same counter of ours.
pub fn session_message(counter: u16, remote_counter: u16, payload: &[u8]) -> Vec<u8> {
    let mut outer = counter.to_be_bytes().to_vec();
    outer.extend(remote_counter.to_be_bytes());
    let mut inner = counter.to_be_bytes().to_vec();
    inner.extend(payload);
    serialize(&[(SESSION_MESSAGE, &outer), (CTRL_MESSAGE, &inner)])
}

/// chiaki-ng `chiaki_rudp_send_ack_message`.
pub fn ack(counter: u16, remote_counter: u16) -> Vec<u8> {
    let mut d = counter.to_be_bytes().to_vec();
    d.extend(remote_counter.to_be_bytes());
    d.extend(AFTER_ACK_COUNTERS);
    serialize(&[(ACK, &d)])
}

/// The answer a request waits for, by chiaki-ng's subtype checks in `chiaki_rudp_send_recv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    InitResponse,
    CookieResponse,
    /// CTRL_MESSAGE, and the OFFSET8 and OFFSET10 kinds, whose subtypes end in 2 or 6 the same way.
    Ctrl,
    Finish,
}

impl Expect {
    pub fn matches(self, m: &Message) -> bool {
        let s = m.subtype();
        match self {
            Expect::InitResponse => s == 0xD0,
            Expect::CookieResponse => s == 0xA0,
            Expect::Ctrl => matches!(s & 0x0F, 0x2 | 0x6),
            Expect::Finish => s == 0xC0,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Expect::InitResponse => "the console's RUDP INIT response",
            Expect::CookieResponse => "the console's RUDP COOKIE response",
            Expect::Ctrl => "the console's RUDP answer",
            Expect::Finish => "the console's RUDP FINISH",
        }
    }
}

/// What to send on each try.
enum Send<'a> {
    Init,
    Cookie(&'a [u8]),
    Session { remote_counter: u16, payload: &'a [u8] },
    Ack { remote_counter: u16 },
}

/// chiaki-ng `RudpInstance`, without the send buffer (9c-2): the connected hole, our counter and the random
/// header word INIT and COOKIE carry.
pub struct Rudp {
    sock: UdpSocket,
    counter: u16,
    header: u32,
}

impl std::fmt::Debug for Rudp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rudp").field("counter", &self.counter).finish_non_exhaustive()
    }
}

impl Rudp {
    /// chiaki-ng `chiaki_rudp_init` and `chiaki_rudp_reset_counter_header`. `sock` must be connected to
    /// the console, as a punched hole is: nothing else's datagrams then reach it.
    pub fn new(sock: UdpSocket) -> Result<Self, PsnError> {
        let r = u32::from_be_bytes(holepunch::random()?);
        let h = u32::from_be_bytes(holepunch::random()?);
        // `% 0x5E00 + 0x1FF` stays below 0x5FFF, so it fits.
        let counter = u16::try_from(r % 0x5E00 + 0x1FF).unwrap_or(0x1FF);
        Ok(Self::with(sock, counter, h.wrapping_add(0x8000)))
    }

    /// Given counter and header word, for tests.
    pub fn with(sock: UdpSocket, counter: u16, header: u32) -> Self {
        Rudp { sock, counter, header }
    }

    pub fn counter(&self) -> u16 {
        self.counter
    }

    /// chiaki-ng `get_then_increase_counter`.
    fn next_counter(&mut self) -> u16 {
        let c = self.counter;
        self.counter = self.counter.wrapping_add(1);
        c
    }

    fn build(&mut self, send: &Send) -> Vec<u8> {
        match *send {
            Send::Init => {
                let c = self.next_counter();
                init_request(c, self.header)
            }
            Send::Cookie(cookie) => {
                let c = self.next_counter();
                cookie_request(c, self.header, cookie)
            }
            Send::Session { remote_counter, payload } => {
                let c = self.next_counter();
                session_message(c, remote_counter, payload)
            }
            // chiaki-ng: an ACK carries the counter without taking it.
            Send::Ack { remote_counter } => ack(self.counter, remote_counter),
        }
    }

    /// chiaki-ng `chiaki_rudp_send_recv`: up to [`TRIES`] times, send and listen [`EXPECT_TIMEOUT`] for the
    /// first message of the chain that is `expect` and has at least `min_data` bytes of data.
    fn send_recv(&mut self, send: Send, expect: Expect, min_data: usize) -> Result<Message, PsnError> {
        let mut buf = [0u8; RECV_LEN];
        for _ in 0..TRIES {
            let datagram = self.build(&send);
            // As chiaki-ng: a send that fails is a try that gets no answer.
            let _ = self.sock.send(&datagram);
            let deadline = Instant::now() + EXPECT_TIMEOUT;
            loop {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                self.sock.set_read_timeout(Some((deadline - now).max(Duration::from_millis(1)))).map_err(io)?;
                let n = match self.sock.recv(&mut buf) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                        std::thread::sleep(RESET_PAUSE);
                        continue;
                    }
                    Err(e) if stun::is_transient(&e) => continue,
                    Err(e) => return Err(io(e)),
                };
                if let Some(m) = parse(&buf[..n]).into_iter().find(|m| expect.matches(m) && m.data.len() >= min_data) {
                    return Ok(m);
                }
            }
        }
        Err(PsnError::Timeout(expect.name()))
    }

    /// Steps 1 and 2: INIT, then COOKIE. The console's counter to answer next.
    pub fn handshake(&mut self) -> Result<u16, PsnError> {
        let init = self.send_recv(Send::Init, Expect::InitResponse, 8)?;
        let cookie = init.data[8..].to_vec();
        let answer = self.send_recv(Send::Cookie(&cookie), Expect::CookieResponse, 2)?;
        answer.remote_counter().ok_or(PsnError::MissingField("RUDP counter"))
    }

    /// Step 3's request and response (chiaki-ng `chiaki_send_recv_http_header_psn`): the whole response, which
    /// must hold a complete HTTP header. `remote_counter` becomes the console's next.
    pub fn http(&mut self, remote_counter: &mut u16, request: &[u8]) -> Result<Vec<u8>, PsnError> {
        // The chained CTRL_MESSAGE carries our counter, then the request.
        if request.len() + 2 > MAX_DATA {
            return Err(PsnError::Rudp("the request is too long for one RUDP message"));
        }
        let send = Send::Session { remote_counter: *remote_counter, payload: request };
        let m = self.send_recv(send, Expect::Ctrl, 2)?;
        *remote_counter = m.remote_counter().ok_or(PsnError::MissingField("RUDP counter"))?;
        let body = m.data[2..].to_vec();
        if body.is_empty() {
            return Err(PsnError::Rudp("the console answered with nothing"));
        }
        if psr_lan::http::header_end(&body).is_none() {
            return Err(PsnError::Rudp("the console's answer has no complete HTTP header"));
        }
        Ok(body)
    }

    /// Step 3's end: ACK the response and wait for FINISH. chiaki-ng logs a failure here and carries on.
    pub fn finish(&mut self, remote_counter: u16) -> Result<(), PsnError> {
        self.send_recv(Send::Ack { remote_counter }, Expect::Finish, 0).map(drop)
    }
}

fn io(e: std::io::Error) -> PsnError {
    PsnError::Network(e.to_string())
}
