// SPDX-License-Identifier: AGPL-3.0-only
//! A Takion connection's state without a socket: the INIT / COOKIE handshake datagrams, reliable data
//! messages with their sequence numbers and key positions, and the receive side that checks MACs, puts
//! data back in order and says what to acknowledge. Ported from chiaki-ng `lib/src/takion.c`
//! (LicenseRef-AGPL-3.0-only-OpenSSL): `takion_handshake`, `chiaki_takion_send_message_data(_cont)`,
//! `chiaki_takion_send_message_data_ack`, `takion_handle_packet` and `takion_flush_data_queue`.
//! The socket loop that drives it lives with the stream connection in psr-lan.

use psr_crypto::gkcrypt::{BLOCK_SIZE, GkCrypt, KeyState};

use crate::TakionError;
use crate::message::{self, ChunkType, MESSAGE_HEADER_SIZE};
use crate::packet::{self, PacketType};
use crate::reorder::ReorderQueue;

/// chiaki-ng `TAKION_A_RWND`, `TAKION_OUTBOUND_STREAMS`, `TAKION_INBOUND_STREAMS`.
pub const A_RWND: u32 = 0x19000;
pub const OUTBOUND_STREAMS: u16 = 0x64;
pub const INBOUND_STREAMS: u16 = 0x64;
pub const COOKIE_SIZE: usize = 0x20;
/// chiaki-ng `TAKION_REORDER_QUEUE_SIZE_EXP`: 16 entries.
const DATA_QUEUE_SIZE_EXP: u32 = 4;
/// The data header in front of a first (or only) chunk: sequence number, channel, two zero bytes, and the
/// data type. A continuation chunk has no data type byte.
const DATA_HEADER: usize = 9;

/// chiaki-ng `ChiakiTakionMessageDataType`.
pub mod data_type {
    pub const PROTOBUF: u8 = 0;
    pub const RUMBLE: u8 = 7;
    pub const PAD_INFO: u8 = 9;
    pub const TRIGGER_EFFECTS: u8 = 11;
}

fn control(tag_remote: u32, key_pos: u64, chunk: ChunkType, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(1 + MESSAGE_HEADER_SIZE + payload.len());
    d.push(PacketType::Control.code());
    d.extend_from_slice(&message::header(tag_remote, key_pos, chunk, flags, payload.len() as u16));
    d.extend_from_slice(payload);
    d
}

/// chiaki-ng `takion_send_message_init`. Sent before the console's tag is known, so with tag 0.
pub fn init_datagram(tag_local: u32, initial_seq_num: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity(0x10);
    p.extend_from_slice(&tag_local.to_be_bytes());
    p.extend_from_slice(&A_RWND.to_be_bytes());
    p.extend_from_slice(&OUTBOUND_STREAMS.to_be_bytes());
    p.extend_from_slice(&INBOUND_STREAMS.to_be_bytes());
    p.extend_from_slice(&initial_seq_num.to_be_bytes());
    control(0, 0, ChunkType::Init, 0, &p)
}

/// chiaki-ng `takion_send_message_cookie`: the console's cookie sent back, under its tag.
pub fn cookie_datagram(tag_remote: u32, cookie: &[u8; COOKIE_SIZE]) -> Vec<u8> {
    control(tag_remote, 0, ChunkType::Cookie, 0, cookie)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitAck {
    pub tag: u32,
    pub a_rwnd: u32,
    pub outbound_streams: u16,
    pub inbound_streams: u16,
    pub initial_seq_num: u32,
    pub cookie: [u8; COOKIE_SIZE],
}

fn expect_control(datagram: &[u8], tag_local: u32, chunk: ChunkType) -> Result<&[u8], TakionError> {
    let (&first, rest) = datagram.split_first().ok_or(TakionError::TooShort { need: 1, got: 0 })?;
    if first != PacketType::Control.code() {
        return Err(TakionError::Unexpected("a control packet"));
    }
    let msg = message::parse(rest, tag_local)?;
    if msg.chunk_type != chunk || msg.chunk_flags != 0 {
        return Err(TakionError::Unexpected(match chunk {
            ChunkType::InitAck => "an init ack",
            _ => "a cookie ack",
        }));
    }
    Ok(msg.payload)
}

/// chiaki-ng `takion_recv_message_init_ack` and the checks `takion_handshake` makes on it.
pub fn parse_init_ack(datagram: &[u8], tag_local: u32) -> Result<InitAck, TakionError> {
    let p = expect_control(datagram, tag_local, ChunkType::InitAck)?;
    if p.len() != 0x10 + COOKIE_SIZE {
        return Err(TakionError::TooShort { need: 1 + MESSAGE_HEADER_SIZE + 0x10 + COOKIE_SIZE, got: datagram.len() });
    }
    let u32_at = |i: usize| u32::from_be_bytes(p[i..i + 4].try_into().expect("4 bytes"));
    let u16_at = |i: usize| u16::from_be_bytes([p[i], p[i + 1]]);
    let ack = InitAck {
        tag: u32_at(0),
        a_rwnd: u32_at(4),
        outbound_streams: u16_at(8),
        inbound_streams: u16_at(0xa),
        initial_seq_num: u32_at(0xc),
        cookie: p[0x10..].try_into().expect("cookie size"),
    };
    if ack.tag == 0 {
        return Err(TakionError::Unexpected("a nonzero remote tag"));
    }
    if ack.outbound_streams == 0
        || ack.inbound_streams == 0
        || ack.outbound_streams > INBOUND_STREAMS
        || ack.inbound_streams < OUTBOUND_STREAMS
    {
        return Err(TakionError::Unexpected("stream counts within ours"));
    }
    Ok(ack)
}

/// chiaki-ng `takion_recv_message_cookie_ack`.
pub fn is_cookie_ack(datagram: &[u8], tag_local: u32) -> Result<(), TakionError> {
    expect_control(datagram, tag_local, ChunkType::CookieAck).map(|_| ())
}

/// chiaki-ng `takion_recv_message_cookie_ack` also skips one repeated init ack: true for that datagram.
pub fn is_init_ack_repeat(datagram: &[u8]) -> bool {
    datagram.get(0xd) == Some(&ChunkType::InitAck.code())
}

/// The sending half: our sequence numbers and key positions.
#[derive(Debug, Clone)]
pub struct Sender {
    tag_remote: u32,
    seq_num: u32,
    key_pos: u64,
    crypt: Option<GkCrypt>,
}

impl Sender {
    /// After the handshake. chiaki-ng starts our sequence numbers at our tag.
    pub fn new(tag_local: u32, tag_remote: u32) -> Self {
        Self { tag_remote, seq_num: tag_local, key_pos: 0, crypt: None }
    }

    /// Once the stream's keys are known (chiaki-ng `chiaki_takion_set_crypt`).
    pub fn set_crypt(&mut self, crypt: GkCrypt) {
        self.crypt = Some(crypt);
    }

    pub fn crypt(&self) -> Option<&GkCrypt> {
        self.crypt.as_ref()
    }

    pub fn next_seq_num(&self) -> u32 {
        self.seq_num
    }

    pub fn key_pos(&self) -> u64 {
        self.key_pos
    }

    /// chiaki-ng `chiaki_takion_crypt_advance_key_pos`. Without keys every position is 0. With them, the
    /// size is padded by `size % 16`, as chiaki-ng does (not up to a whole block).
    pub fn advance_key_pos(&mut self, size: usize) -> u64 {
        if self.crypt.is_none() {
            return 0;
        }
        let pos = self.key_pos;
        self.key_pos += (size + size % BLOCK_SIZE) as u64;
        pos
    }

    /// The datagram with its MAC filled in, or zeroed without keys (chiaki-ng `chiaki_takion_send`).
    fn finish(&self, datagram: Vec<u8>, key_pos: u64) -> Result<Vec<u8>, TakionError> {
        match &self.crypt {
            Some(c) => packet::sign(c, &datagram, key_pos),
            None => Ok(datagram),
        }
    }

    fn data_chunk(&mut self, cont: bool, chunk_flags: u8, channel: u16, data: &[u8]) -> Result<(u32, Vec<u8>), TakionError> {
        let key_pos = self.advance_key_pos(data.len());
        let seq = self.seq_num;
        self.seq_num = self.seq_num.wrapping_add(1);
        let mut p = Vec::with_capacity(DATA_HEADER + data.len());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&channel.to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        if !cont {
            p.push(data_type::PROTOBUF);
        }
        p.extend_from_slice(data);
        let datagram = control(self.tag_remote, key_pos, ChunkType::Data, chunk_flags, &p);
        Ok((seq, self.finish(datagram, key_pos)?))
    }

    /// chiaki-ng `chiaki_takion_send_message_data`: a first or only chunk. Flags 1 mark the last chunk.
    pub fn data(&mut self, chunk_flags: u8, channel: u16, data: &[u8]) -> Result<(u32, Vec<u8>), TakionError> {
        self.data_chunk(false, chunk_flags, channel, data)
    }

    /// chiaki-ng `chiaki_takion_send_message_data_cont`: a later chunk of a message split by MTU.
    pub fn data_cont(&mut self, chunk_flags: u8, channel: u16, data: &[u8]) -> Result<(u32, Vec<u8>), TakionError> {
        self.data_chunk(true, chunk_flags, channel, data)
    }

    /// chiaki-ng `chiaki_takion_send_message_data_ack`. The key position advances by the whole
    /// datagram's size, as chiaki-ng's does.
    pub fn data_ack(&mut self, seq_num: u32) -> Result<Vec<u8>, TakionError> {
        const SIZE: usize = 1 + MESSAGE_HEADER_SIZE + 0xc;
        let key_pos = self.advance_key_pos(SIZE);
        let mut p = Vec::with_capacity(0xc);
        p.extend_from_slice(&seq_num.to_be_bytes());
        p.extend_from_slice(&A_RWND.to_be_bytes());
        p.extend_from_slice(&[0; 4]);
        let datagram = control(self.tag_remote, key_pos, ChunkType::DataAck, 0, &p);
        self.finish(datagram, key_pos)
    }

    /// chiaki-ng `stream_connection_send_big`'s split: chunks of `mtu - 26` then `mtu - 25` bytes,
    /// flags 1 on the last. `mtu` already has chiaki-ng's 50 bytes of network overhead taken off.
    pub fn split_data(&mut self, channel: u16, data: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>, TakionError> {
        let mut out = Vec::new();
        let (mut pos, mut left, mut first) = (0usize, data.len(), true);
        while mtu < left + 26 || (mtu < left + 25 && !first) {
            let n = if first { mtu - 26 } else { mtu - 25 };
            let chunk = &data[pos..pos + n];
            out.push(if first { self.data(0, channel, chunk)?.1 } else { self.data_cont(0, channel, chunk)?.1 });
            first = false;
            pos += n;
            left -= n;
        }
        if left > 0 {
            let chunk = &data[pos..];
            out.push(if first { self.data(1, channel, chunk)?.1 } else { self.data_cont(1, channel, chunk)?.1 });
        }
        Ok(out)
    }
}

/// What a received datagram meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// A data message, in order: its type (see [`data_type`]), channel and bytes.
    Data { data_type: u8, channel: u16, data: Vec<u8> },
    /// The console acknowledged our data up to this sequence number.
    DataAck { cumulative_seq_num: u32 },
    /// A video or audio datagram, MAC checked when keys are set. Parsing it is the AV receiver's job.
    Av(Vec<u8>),
}

#[derive(Debug)]
struct DataEntry {
    channel: u16,
    payload: Vec<u8>,
}

/// The receiving half.
#[derive(Debug)]
pub struct Receiver {
    tag_local: u32,
    key_state: KeyState,
    crypt: Option<GkCrypt>,
    data_queue: ReorderQueue<u32, DataEntry>,
    /// AV datagrams that came before the keys (chiaki-ng's postponed packets, up to 32).
    postponed: Vec<Vec<u8>>,
}

/// chiaki-ng `TAKION_POSTPONE_PACKETS_SIZE`.
const POSTPONE_MAX: usize = 32;

impl Receiver {
    /// After the handshake. chiaki-ng starts the console's sequence numbers at its tag, not at the initial
    /// sequence number its init ack names.
    pub fn new(tag_local: u32, tag_remote: u32) -> Self {
        Self {
            tag_local,
            key_state: KeyState::default(),
            crypt: None,
            data_queue: ReorderQueue::new(DATA_QUEUE_SIZE_EXP, tag_remote),
            postponed: Vec::new(),
        }
    }

    /// Sets the console's keys. AV datagrams that arrived before them are returned to handle again.
    pub fn set_crypt(&mut self, crypt: GkCrypt) -> Vec<Vec<u8>> {
        self.crypt = Some(crypt);
        std::mem::take(&mut self.postponed)
    }

    pub fn key_state(&self) -> KeyState {
        self.key_state
    }

    /// chiaki-ng `takion_handle_packet`. Returns what the datagram carried and, when data was delivered,
    /// the sequence number to acknowledge. A datagram whose MAC fails is an error and changes nothing.
    pub fn handle(&mut self, datagram: &[u8]) -> Result<(Vec<Received>, Option<u32>), TakionError> {
        let ty = PacketType::of(datagram)?;
        if let Some(c) = &self.crypt
            && ty.mac_offset().is_some()
        {
            let (_, state) = packet::verify(c, datagram, self.key_state)?;
            self.key_state = state;
        }
        match ty {
            PacketType::Control => self.handle_control(&datagram[1..]),
            PacketType::Video | PacketType::Audio => {
                if self.crypt.is_none() {
                    if self.postponed.len() < POSTPONE_MAX {
                        self.postponed.push(datagram.to_vec());
                    }
                    return Ok((Vec::new(), None));
                }
                Ok((vec![Received::Av(datagram.to_vec())], None))
            }
            _ => Ok((Vec::new(), None)),
        }
    }

    fn handle_control(&mut self, buf: &[u8]) -> Result<(Vec<Received>, Option<u32>), TakionError> {
        let msg = message::parse(buf, self.tag_local)?;
        // chiaki-ng `takion_parse_message` commits the widened position as it parses.
        self.key_state = self.key_state.commit(self.key_state.request_pos(msg.key_pos_low));
        match msg.chunk_type {
            ChunkType::Data => {
                if msg.payload.len() < DATA_HEADER {
                    return Err(TakionError::TooShort { need: DATA_HEADER, got: msg.payload.len() });
                }
                let seq = u32::from_be_bytes(msg.payload[0..4].try_into().expect("4 bytes"));
                let channel = u16::from_be_bytes([msg.payload[4], msg.payload[5]]);
                self.data_queue.push(seq, DataEntry { channel, payload: msg.payload.to_vec() });
                Ok(self.flush())
            }
            ChunkType::DataAck => {
                if msg.payload.len() != 0xc {
                    return Err(TakionError::LengthMismatch { field: 0xc, len: msg.payload.len() });
                }
                let cumulative_seq_num = u32::from_be_bytes(msg.payload[0..4].try_into().expect("4 bytes"));
                Ok((vec![Received::DataAck { cumulative_seq_num }], None))
            }
            _ => Ok((Vec::new(), None)),
        }
    }

    /// chiaki-ng `takion_flush_data_queue`: everything now in order, and the last sequence number pulled.
    fn flush(&mut self) -> (Vec<Received>, Option<u32>) {
        let mut out = Vec::new();
        let mut ack = None;
        while let Some((seq, entry)) = self.data_queue.pull() {
            ack = Some(seq);
            out.push(Received::Data {
                data_type: entry.payload[8],
                channel: entry.channel,
                data: entry.payload[DATA_HEADER..].to_vec(),
            });
        }
        (out, ack)
    }
}
