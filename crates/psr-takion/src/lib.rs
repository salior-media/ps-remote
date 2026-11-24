// SPDX-License-Identifier: AGPL-3.0-only
//! Takion, the Remote Play stream transport. Ported from chiaki-ng `lib/src/takion.c`, `reorderqueue.c`,
//! `takionsendbuffer.c` and `seqnum.h`.
//!
//! Nothing here touches a socket: [`connection`] holds a connection's state and builds and reads its
//! datagrams, and psr-lan's stream connection drives it over UDP.

pub mod av;
pub mod connection;
pub mod message;
pub mod packet;
pub mod reorder;
pub mod send_buffer;
pub mod seqnum;

use packet::PacketType;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TakionError {
    #[error("datagram too short: need {need} bytes, got {got}")]
    TooShort { need: usize, got: usize },
    #[error("unknown Takion packet type {0:#x}")]
    UnknownType(u8),
    #[error("{0:?} packets carry no MAC")]
    NoMac(PacketType),
    #[error("{0:?} is not a video or audio packet")]
    NotAv(PacketType),
    #[error("MAC mismatch at key position {key_pos:#x}")]
    BadMac { key_pos: u64 },
    #[error("message tag {got:#010x} is not ours ({want:#010x})")]
    TagMismatch { got: u32, want: u32 },
    #[error("message length field {field} does not fit a {len}-byte message")]
    LengthMismatch { field: usize, len: usize },
    #[error("send buffer is full ({0} messages waiting)")]
    SendBufferFull(usize),
    #[error("sequence number {0:#x} is already waiting for an acknowledgement")]
    DuplicateSeqNum(u32),
    #[error("the console sent something else while ps-remote expected {0}")]
    Unexpected(&'static str),
}
