// SPDX-License-Identifier: AGPL-3.0-only
//! The header of a Takion control message, the payload of a [`PacketType::Control`] datagram after its
//! type byte. Ported from chiaki-ng `takion_write_message_header` and `takion_parse_message`.
//!
//! [`PacketType::Control`]: crate::packet::PacketType::Control

use crate::TakionError;

pub const MESSAGE_HEADER_SIZE: usize = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkType {
    Data,
    Init,
    InitAck,
    DataAck,
    Cookie,
    CookieAck,
    Other(u8),
}

impl ChunkType {
    pub fn from_code(c: u8) -> Self {
        match c {
            0 => Self::Data,
            1 => Self::Init,
            2 => Self::InitAck,
            3 => Self::DataAck,
            0xa => Self::Cookie,
            0xb => Self::CookieAck,
            other => Self::Other(other),
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Init => 1,
            Self::InitAck => 2,
            Self::DataAck => 3,
            Self::Cookie => 0xa,
            Self::CookieAck => 0xb,
            Self::Other(c) => c,
        }
    }
}

/// A parsed message. `key_pos_low` is the wire's 32 bits; widening and committing them is the caller's
/// job, after the datagram's MAC has checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    pub tag: u32,
    pub key_pos_low: u32,
    pub chunk_type: ChunkType,
    pub chunk_flags: u8,
    pub payload: &'a [u8],
}

/// chiaki-ng `takion_write_message_header`: tag, four zero bytes for the MAC, the key position, chunk type
/// and flags, and the payload length plus 4.
pub fn header(tag: u32, key_pos: u64, chunk_type: ChunkType, chunk_flags: u8, payload_len: u16) -> [u8; MESSAGE_HEADER_SIZE] {
    let mut buf = [0u8; MESSAGE_HEADER_SIZE];
    buf[0..4].copy_from_slice(&tag.to_be_bytes());
    buf[8..12].copy_from_slice(&(key_pos as u32).to_be_bytes());
    buf[0xc] = chunk_type.code();
    buf[0xd] = chunk_flags;
    buf[0xe..0x10].copy_from_slice(&payload_len.wrapping_add(4).to_be_bytes());
    buf
}

/// chiaki-ng `takion_parse_message`, given the bytes after the datagram's type byte. Refuses a message
/// whose tag isn't ours, or whose length field doesn't match its size.
pub fn parse(buf: &[u8], tag_local: u32) -> Result<Message<'_>, TakionError> {
    if buf.len() < MESSAGE_HEADER_SIZE {
        return Err(TakionError::TooShort { need: MESSAGE_HEADER_SIZE, got: buf.len() });
    }
    let tag = u32::from_be_bytes(buf[0..4].try_into().expect("4 bytes"));
    if tag != tag_local {
        return Err(TakionError::TagMismatch { got: tag, want: tag_local });
    }
    let size_field = usize::from(u16::from_be_bytes([buf[0xe], buf[0xf]]));
    if buf.len() != size_field + 0xc || size_field < 4 {
        return Err(TakionError::LengthMismatch { field: size_field, len: buf.len() });
    }
    Ok(Message {
        tag,
        key_pos_low: u32::from_be_bytes(buf[8..12].try_into().expect("4 bytes")),
        chunk_type: ChunkType::from_code(buf[0xc]),
        chunk_flags: buf[0xd],
        payload: &buf[MESSAGE_HEADER_SIZE..],
    })
}
