// SPDX-License-Identifier: AGPL-3.0-only
//! RUDP: the console's reliable-datagram framing over the punched control hole, which carries registration,
//! the session request and ctrl when playing over PSN. Ported from chiaki-ng `lib/src/remote/rudp.c`
//! (LicenseRef-AGPL-3.0-only-OpenSSL), and its send buffer from `rudpsendbuffer.c`. Step 9c-1 uses the
//! handshake and the HTTP exchange; 9c-2 carries ctrl over it ([`Rudp`] is a `psr_lan` ctrl link), with what
//! chiaki-ng's `ctrl.c` does with each message that arrives ([`incoming`]).
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
//! - **One ACK per datagram.** chiaki-ng's ctrl loop sends an ACK for every message of a chain that asks for
//!   one, each naming the same counter; here the first is sent and the repeats are not.
//! - **A datagram whose counter is not new is not read again** (the security review's finding). It is still
//!   acknowledged, so the console stops resending it, but its frames are passed over: read twice, a frame
//!   would advance the ctrl cipher's counter and garble every message after it.
//! - **A frame too long for ctrl's 512 bytes is passed over** with its datagram's other frames kept, where it
//!   would end ctrl.
//! - **A message given up on is reported**: after [`RESEND_TRIES_MAX`] resends unacknowledged, reading ctrl
//!   fails, where chiaki-ng drops the message and carries on as though the console were there.
//! - **The send buffer is resent from the ctrl loop**, when it reads, not from a thread of its own. The ctrl
//!   loop reads in steps of at most [`RESEND_WAKE`], chiaki-ng's resend thread's wake-up, so the timing is
//!   the same while ctrl is polled.

use std::net::UdpSocket;

use psr_lan::LanError;
use psr_lan::ctrl::MAX_FRAME;
use psr_lan::session::CtrlLink;
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
    sent: SendBuffer,
    /// The console's counter on the last datagram whose frames were read.
    last_read: Option<u16>,
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
        Rudp { sock, counter, header, sent: SendBuffer::default(), last_read: None }
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

/// chiaki-ng `RUDP_DATA_RESEND_TIMEOUT_MS`: a ctrl message not acknowledged in this time is sent again.
pub const RESEND_TIMEOUT: Duration = Duration::from_millis(400);
/// chiaki-ng `RUDP_DATA_RESEND_WAKEUP_TIMEOUT_MS`.
pub const RESEND_WAKE: Duration = Duration::from_millis(200);
/// chiaki-ng `RUDP_DATA_RESEND_TRIES_MAX`: after this many resends a message is given up on.
pub const RESEND_TRIES_MAX: u32 = 25;
/// chiaki-ng `RUDP_SEND_BUFFER_SIZE`: messages waiting for their acknowledgment at once.
pub const SEND_BUFFER_SIZE: usize = 16;

/// chiaki-ng `chiaki_rudp_send_ctrl_message`: our counter, then the ctrl frames.
pub fn ctrl_message(counter: u16, frames: &[u8]) -> Vec<u8> {
    serialize(&[(CTRL_MESSAGE, &[&counter.to_be_bytes()[..], frames].concat())])
}

/// chiaki-ng `chiaki_seq_num_16_lt`: `a` comes before `b`, counting round the wrap.
pub fn seq_lt(a: u16, b: u16) -> bool {
    (1..0x8000).contains(&b.wrapping_sub(a))
}

struct Pending {
    seq: u16,
    tries: u32,
    last_send: Instant,
    datagram: Vec<u8>,
}

/// chiaki-ng `ChiakiRudpSendBuffer`: our ctrl messages until the console acknowledges them, each under the
/// counter after its own, which is what the console's acknowledgment names.
#[derive(Default)]
pub struct SendBuffer {
    pending: Vec<Pending>,
}

impl SendBuffer {
    /// chiaki-ng `chiaki_rudp_send_buffer_push`: refused when full or when `seq` is already waiting.
    pub fn push(&mut self, seq: u16, datagram: Vec<u8>, now: Instant) -> Result<(), PsnError> {
        if self.pending.len() >= SEND_BUFFER_SIZE {
            return Err(PsnError::Rudp("too many ctrl messages wait for the console's acknowledgment"));
        }
        if self.pending.iter().any(|p| p.seq == seq) {
            return Err(PsnError::Rudp("a ctrl message with that counter already waits"));
        }
        self.pending.push(Pending { seq, tries: 0, last_send: now, datagram });
        Ok(())
    }

    /// chiaki-ng `chiaki_rudp_send_buffer_ack`: `seq` and everything before it are done with.
    pub fn ack(&mut self, seq: u16) {
        self.pending.retain(|p| p.seq != seq && !seq_lt(p.seq, seq));
    }

    /// chiaki-ng `rudp_send_buffer_resend`: what to send again now, and whether a message was given up on. A
    /// message resent [`RESEND_TRIES_MAX`] times is dropped, with everything before it, as chiaki-ng does.
    pub fn due(&mut self, now: Instant) -> (Vec<Vec<u8>>, bool) {
        let gave_up = if let Some(seq) = self
            .pending
            .iter()
            .filter(|p| now.duration_since(p.last_send) > RESEND_TIMEOUT && p.tries >= RESEND_TRIES_MAX)
            .map(|p| p.seq)
            .next_back()
        {
            self.ack(seq);
            true
        } else {
            false
        };
        let mut out = Vec::new();
        for p in self.pending.iter_mut().filter(|p| now.duration_since(p.last_send) > RESEND_TIMEOUT) {
            p.tries += 1;
            p.last_send = now;
            out.push(p.datagram.clone());
        }
        (out, gave_up)
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

/// What one datagram means to ctrl (chiaki-ng `ctrl_thread_func`, the RUDP branch). Its `Debug` shows the
/// frames' length, not their bytes.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct Incoming {
    /// The console's counter on the first message, which says whether the datagram is new.
    pub counter: Option<u16>,
    /// Our messages the console acknowledges, by the counter each names.
    pub acked: Vec<u16>,
    /// The counter to acknowledge, when a message asks for it: the first message's, plus one.
    pub ack: Option<u16>,
    /// Ctrl frames, header and payload, in order.
    pub frames: Vec<u8>,
    /// The console sent FINISH: ctrl is over.
    pub finished: bool,
}

impl std::fmt::Debug for Incoming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Incoming")
            .field("counter", &self.counter)
            .field("acked", &self.acked)
            .field("ack", &self.ack)
            .field("frames_len", &self.frames.len())
            .field("finished", &self.finished)
            .finish()
    }
}

/// chiaki-ng `rudp_packet_type_data_offset`, where the ctrl frame starts in a message of this subtype.
fn frame_offset(subtype: u8) -> usize {
    match subtype {
        0x12 => 8,
        0x26 => 6,
        _ => 2,
    }
}

/// chiaki-ng's ctrl loop over each message of a chain. A message whose data is shorter than its two
/// counters is passed over (FINISH apart). A frame is taken only when its header's length is exactly the
/// rest of the message, as chiaki-ng checks.
pub fn incoming(messages: &[Message]) -> Incoming {
    let mut r = Incoming {
        counter: messages.first().and_then(Message::remote_counter).map(|c| c.wrapping_sub(1)),
        ..Incoming::default()
    };
    let ack_to = messages.first().and_then(Message::remote_counter).unwrap_or(0);
    let take = |m: &Message, offset: usize, r: &mut Incoming| {
        r.ack = Some(ack_to);
        let Some(frame) = m.data.get(offset..).filter(|f| f.len() >= 8) else { return };
        let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        // chiaki-ng's length check, and ctrl's buffer size, which a longer frame would overflow.
        if frame.len() <= MAX_FRAME && usize::try_from(len).is_ok_and(|l| l == frame.len() - 8) {
            r.frames.extend_from_slice(frame);
        }
    };
    for m in messages {
        let s = m.subtype();
        if m.data.len() < 4 && s != 0xC0 {
            continue;
        }
        let acked = || u16::from_be_bytes([m.data[2], m.data[3]]);
        match s {
            0x12 | 0x26 | 0x36 => {
                r.acked.push(acked());
                take(m, frame_offset(s), &mut r);
            }
            0x02 => take(m, frame_offset(s), &mut r),
            0x24 => r.acked.push(acked()),
            0xC0 => r.finished = true,
            // chiaki-ng: an unknown kind is acknowledged, retires nothing, and may carry a frame at 4.
            _ => take(m, 4, &mut r),
        }
    }
    r
}

impl Rudp {
    /// chiaki-ng `chiaki_rudp_send_ack_message`, on its own.
    pub fn send_ack(&mut self, remote_counter: u16) -> Result<(), PsnError> {
        self.sock.send(&ack(self.counter, remote_counter)).map(drop).map_err(io)
    }

    /// chiaki-ng `chiaki_rudp_send_ctrl_message`: sent now, and again until the console acknowledges it.
    pub fn send_ctrl(&mut self, frames: &[u8]) -> Result<(), PsnError> {
        if frames.len() + 2 > MAX_DATA {
            return Err(PsnError::Rudp("the ctrl message is too long for one RUDP message"));
        }
        // Checked before the counter is taken and the message sent, so a refusal leaves nothing half done.
        if self.sent.len() >= SEND_BUFFER_SIZE {
            return Err(PsnError::Rudp("too many ctrl messages wait for the console's acknowledgment"));
        }
        let counter = self.next_counter();
        let datagram = ctrl_message(counter, frames);
        self.sock.send(&datagram).map_err(io)?;
        self.sent.push(self.counter, datagram, Instant::now())
    }

    /// Our ctrl messages still waiting for the console's acknowledgment.
    pub fn unacknowledged(&self) -> usize {
        self.sent.len()
    }

    /// Ctrl frames that arrive within `timeout`, acknowledging what asks for it, taking the console's
    /// acknowledgments, and resending what is due while it waits. Empty if nothing came.
    pub fn read_ctrl(&mut self, timeout: Duration) -> Result<Vec<u8>, PsnError> {
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; RECV_LEN];
        loop {
            let now = Instant::now();
            let (resends, gave_up) = self.sent.due(now);
            if gave_up {
                return Err(PsnError::Rudp("the console stopped acknowledging our ctrl messages"));
            }
            for datagram in resends {
                // A resend that fails is tried again at the next.
                let _ = self.sock.send(&datagram);
            }
            if now >= deadline {
                return Ok(Vec::new());
            }
            let wait = (deadline - now).min(RESEND_WAKE).max(Duration::from_millis(1));
            self.sock.set_read_timeout(Some(wait)).map_err(io)?;
            let n = match self.sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                    std::thread::sleep(RESET_PAUSE);
                    continue;
                }
                Err(e) if stun::is_transient(&e) => continue,
                Err(e) => return Err(io(e)),
            };
            let got = incoming(&parse(&buf[..n]));
            for seq in &got.acked {
                self.sent.ack(*seq);
            }
            if let Some(remote) = got.ack {
                // As a resend: an ACK that cannot go out now is sent again when the console resends.
                let _ = self.send_ack(remote);
            }
            if got.finished {
                return Err(PsnError::Finished);
            }
            if got.frames.is_empty() {
                continue;
            }
            // Read once only (see the module notes); a datagram with no counter cannot be told apart, so it is
            // read as chiaki-ng reads it.
            if let Some(c) = got.counter {
                if self.last_read.is_some_and(|last| !seq_lt(last, c)) {
                    continue;
                }
                self.last_read = Some(c);
            }
            return Ok(got.frames);
        }
    }
}

/// Ctrl over the hole: [`psr_lan::session::Session`] runs on this as it does on TCP at home.
impl CtrlLink for Rudp {
    fn write(&mut self, frames: &[u8]) -> Result<(), LanError> {
        self.send_ctrl(frames).map_err(lan)
    }

    fn read(&mut self, timeout: Duration) -> Result<Vec<u8>, LanError> {
        match self.read_ctrl(timeout) {
            Err(PsnError::Finished) => Err(LanError::CtrlClosed),
            other => other.map_err(lan),
        }
    }
}

fn lan(e: PsnError) -> LanError {
    LanError::Io(std::io::Error::other(e.to_string()))
}

fn io(e: std::io::Error) -> PsnError {
    PsnError::Network(e.to_string())
}
