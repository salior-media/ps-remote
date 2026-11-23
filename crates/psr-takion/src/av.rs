// SPDX-License-Identifier: AGPL-3.0-only
//! Video and audio datagrams. Ported from chiaki-ng `av_packet_parse` (v9 and v12) and
//! `chiaki_takion_v7_av_packet_parse` in `lib/src/takion.c`.
//!
//! **Difference from chiaki-ng:** every skip is bounds-checked. chiaki-ng's v9/v12 parser checks the
//! length once against the header size, then skips three more bytes when the NALU-info flag is set. On a
//! short audio packet that runs past the end, and its `size_t` length wraps round to a huge value. Here
//! a packet too short for the fields its flags announce is an error.

use psr_crypto::gkcrypt::KeyState;

use crate::TakionError;
use crate::packet::PacketType;

pub const V9_AV_HEADER_SIZE_VIDEO: usize = 0x17;
pub const V9_AV_HEADER_SIZE_AUDIO: usize = 0x12;
pub const V12_AV_HEADER_SIZE_VIDEO: usize = 0x17;
pub const V12_AV_HEADER_SIZE_AUDIO: usize = 0x13;
pub const V7_AV_HEADER_SIZE_BASE: usize = 0x12;
pub const V7_AV_HEADER_SIZE_VIDEO_ADD: usize = 0x3;
pub const V7_AV_HEADER_SIZE_NALU_INFO_STRUCTS_ADD: usize = 0x3;

/// Which header layout the console uses (chiaki-ng picks one per target).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvVersion {
    V7,
    V9,
    V12,
}

/// A parsed video or audio datagram (chiaki-ng `ChiakiTakionAVPacket`). `data` borrows the datagram and
/// is still encrypted: decrypt it at `key_pos + 16`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvPacket<'a> {
    pub packet_index: u16,
    pub frame_index: u16,
    pub uses_nalu_info_structs: bool,
    pub is_video: bool,
    pub is_haptics: bool,
    pub unit_index: u16,
    /// Source units plus FEC units.
    pub units_in_frame_total: u16,
    pub units_in_frame_fec: u16,
    pub codec: u8,
    pub word_at_0x18: u16,
    pub adaptive_stream_index: u8,
    pub byte_at_0x2c: u8,
    pub key_pos: u64,
    pub data: &'a [u8],
}

impl AvPacket<'_> {
    pub fn audio_unit_size(&self) -> u8 {
        (self.units_in_frame_fec >> 8) as u8
    }

    pub fn audio_source_units_count(&self) -> u8 {
        (self.units_in_frame_fec & 0xf) as u8
    }

    pub fn audio_fec_units_count(&self) -> u8 {
        ((self.units_in_frame_fec >> 4) & 0xf) as u8
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn need(&self, n: usize) -> Result<(), TakionError> {
        let need = self.at + n;
        if need > self.buf.len() { Err(TakionError::TooShort { need, got: self.buf.len() }) } else { Ok(()) }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], TakionError> {
        self.need(n)?;
        let s = &self.buf[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, TakionError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TakionError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2 bytes")))
    }

    fn u32(&mut self) -> Result<u32, TakionError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }

    fn rest(self) -> &'a [u8] {
        &self.buf[self.at..]
    }
}

fn kind(datagram: &[u8]) -> Result<(bool, bool), TakionError> {
    let ty = PacketType::of(datagram)?;
    let is_video = match ty {
        PacketType::Video => true,
        PacketType::Audio => false,
        other => return Err(TakionError::NotAv(other)),
    };
    Ok((is_video, (datagram[0] >> 4) & 1 != 0))
}

fn units(is_video: bool, dword: u32) -> (u16, u16, u16) {
    if is_video {
        (((dword >> 0x15) & 0x7ff) as u16, (((dword >> 0xa) & 0x7ff) + 1) as u16, (dword & 0x3ff) as u16)
    } else {
        (((dword >> 0x18) & 0xff) as u16, (((dword >> 0x10) & 0xff) + 1) as u16, (dword & 0xffff) as u16)
    }
}

/// Parses a v9 or v12 datagram. The key position is widened with `state` but not committed: commit it
/// after the datagram's MAC has checked out.
fn parse_v9_v12(v12: bool, datagram: &[u8], state: KeyState) -> Result<AvPacket<'_>, TakionError> {
    let (is_video, nalu) = kind(datagram)?;
    let header = match (v12, is_video) {
        (false, true) => V9_AV_HEADER_SIZE_VIDEO,
        (false, false) => V9_AV_HEADER_SIZE_AUDIO,
        (true, true) => V12_AV_HEADER_SIZE_VIDEO,
        (true, false) => V12_AV_HEADER_SIZE_AUDIO,
    };
    // chiaki-ng: `av_size < av_header_size + 1` is refused.
    let need = 1 + header + 1;
    if datagram.len() < need {
        return Err(TakionError::TooShort { need, got: datagram.len() });
    }
    let mut r = Reader { buf: datagram, at: 1 };
    let packet_index = r.u16()?;
    let frame_index = r.u16()?;
    let (unit_index, units_in_frame_total, units_in_frame_fec) = units(is_video, r.u32()?);
    let codec = r.u8()?;
    r.take(4)?; // MAC
    let key_pos = state.request_pos(r.u32()?);
    // chiaki-ng reads an "unknown" byte here but doesn't skip it: for video it is the first byte of
    // `word_at_0x18`, and for audio the byte skipped just below.
    let (mut word_at_0x18, mut adaptive_stream_index, mut byte_at_0x2c) = (0, 0, 0);
    if is_video {
        word_at_0x18 = r.u16()?;
        adaptive_stream_index = r.u8()? >> 5;
        r.need(1)?;
        byte_at_0x2c = r.buf[r.at];
    } else {
        r.take(1)?; // unknown
    }
    if nalu {
        r.take(3)?;
    }
    let mut is_haptics = false;
    if v12 && !is_video {
        is_haptics = r.u8()? == 0x02;
    }
    Ok(AvPacket {
        packet_index,
        frame_index,
        uses_nalu_info_structs: nalu,
        is_video,
        is_haptics,
        unit_index,
        units_in_frame_total,
        units_in_frame_fec,
        codec,
        word_at_0x18,
        adaptive_stream_index,
        byte_at_0x2c,
        key_pos,
        data: r.rest(),
    })
}

/// chiaki-ng `chiaki_takion_v7_av_packet_parse`: older PS4 firmware, where the key position is sent
/// whole (32 bits, no widening) and video and audio share one unit layout.
fn parse_v7(datagram: &[u8]) -> Result<AvPacket<'_>, TakionError> {
    let (is_video, nalu) = kind(datagram)?;
    let mut header = V7_AV_HEADER_SIZE_BASE;
    if is_video {
        header += V7_AV_HEADER_SIZE_VIDEO_ADD;
    }
    if nalu {
        header += V7_AV_HEADER_SIZE_NALU_INFO_STRUCTS_ADD;
    }
    if datagram.len() < header {
        return Err(TakionError::TooShort { need: header, got: datagram.len() });
    }
    let mut r = Reader { buf: datagram, at: 1 };
    let packet_index = r.u16()?;
    let frame_index = r.u16()?;
    let (unit_index, units_in_frame_total, units_in_frame_fec) = units(true, r.u32()?);
    let codec = r.u8()?;
    r.take(4)?; // unknown
    let key_pos = u64::from(r.u32()?);
    let (mut word_at_0x18, mut adaptive_stream_index) = (0, 0);
    if is_video {
        word_at_0x18 = r.u16()?;
        adaptive_stream_index = r.u8()? >> 5;
    }
    if nalu {
        r.take(3)?;
    }
    Ok(AvPacket {
        packet_index,
        frame_index,
        uses_nalu_info_structs: nalu,
        is_video,
        is_haptics: false,
        unit_index,
        units_in_frame_total,
        units_in_frame_fec,
        codec,
        word_at_0x18,
        adaptive_stream_index,
        byte_at_0x2c: 0,
        key_pos,
        data: r.rest(),
    })
}

/// Parses a video or audio datagram in the given layout.
pub fn parse(version: AvVersion, datagram: &[u8], state: KeyState) -> Result<AvPacket<'_>, TakionError> {
    match version {
        AvVersion::V7 => parse_v7(datagram),
        AvVersion::V9 => parse_v9_v12(false, datagram, state),
        AvVersion::V12 => parse_v9_v12(true, datagram, state),
    }
}
