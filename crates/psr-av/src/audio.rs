// SPDX-License-Identifier: AGPL-3.0-only
//! Opus frames from the console's audio packets. Ported from chiaki-ng `lib/src/audioreceiver.c` and
//! `lib/src/audio.c` (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! Each audio packet carries a few new Opus frames (its source units), then copies of the frames just before
//! them (its "FEC" units), so a lost packet's frames usually arrive again in the next one. Every unit is the
//! same size.
//!
//! **Differences from chiaki-ng:**
//! - chiaki-ng holds frames in a jitter buffer for its own player and fills gaps with silence. Here each frame
//!   is handed on once, as soon as it arrives, with its index; whatever plays it (a browser's WebRTC receiver)
//!   has its own jitter buffer.
//! - Haptics packets (the DualSense's rumble, sent as audio) are not handed on.

use psr_takion::av::AvPacket;
use psr_takion::seqnum::SeqNum;

/// chiaki-ng only accepts audio packets with this codec byte: Opus.
pub const OPUS_CODEC: u8 = 5;
/// chiaki-ng `CHIAKI_AUDIO_HEADER_SIZE`.
pub const HEADER_SIZE: usize = 0xe;
/// How many recent frame indices are remembered to drop the copies.
const RECENT: u16 = 64;

/// The console's audio format, from the stream info (chiaki-ng `ChiakiAudioHeader`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioHeader {
    pub channels: u8,
    pub bits: u8,
    pub rate: u32,
    /// Samples per channel in each frame.
    pub frame_size: u32,
    pub unknown: u32,
}

impl AudioHeader {
    /// chiaki-ng `chiaki_audio_header_load`.
    pub fn load(b: &[u8; HEADER_SIZE]) -> Self {
        let u32_at = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        Self { channels: b[0], bits: b[1], rate: u32_at(2), frame_size: u32_at(6), unknown: u32_at(0xa) }
    }
}

/// One Opus frame, numbered by the console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFrame {
    pub index: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AudioError {
    #[error("codec {0} is not Opus ({OPUS_CODEC})")]
    NotOpus(u8),
    #[error("the packet is empty")]
    Empty,
    #[error("{source_units} source units and {fec_units} FEC units are not the packet's {total}")]
    UnitCount { source_units: u8, fec_units: u8, total: u16 },
    #[error("{len} bytes is not {units} units of {unit_size}")]
    Size { len: usize, units: u16, unit_size: u8 },
}

/// chiaki-ng `ChiakiAudioReceiver`, without its jitter buffer.
#[derive(Debug)]
pub struct AudioReceiver {
    /// chiaki-ng `frame_index_startup`: until the frame index passes 2^15, copies of frames from before the
    /// stream began are skipped.
    startup: bool,
    newest: Option<u16>,
    /// The indices handed on recently, so a copy is handed on only once.
    recent: Vec<u16>,
}

impl Default for AudioReceiver {
    fn default() -> Self {
        Self { startup: true, newest: None, recent: Vec::new() }
    }
}

impl AudioReceiver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Unpacks one audio packet, its payload already decrypted (chiaki-ng
    /// `chiaki_audio_receiver_av_packet`), and returns the frames not handed on before.
    pub fn av_packet(&mut self, packet: &AvPacket<'_>) -> Result<Vec<AudioFrame>, AudioError> {
        if packet.codec != OPUS_CODEC {
            return Err(AudioError::NotOpus(packet.codec));
        }
        let (source_units, fec_units) = (packet.audio_source_units_count(), packet.audio_fec_units_count());
        let unit_size = packet.audio_unit_size();
        if packet.data.is_empty() {
            return Err(AudioError::Empty);
        }
        let total = packet.units_in_frame_total;
        if u16::from(source_units) + u16::from(fec_units) != total {
            return Err(AudioError::UnitCount { source_units, fec_units, total });
        }
        if packet.data.len() != usize::from(unit_size) * usize::from(total) {
            return Err(AudioError::Size { len: packet.data.len(), units: total, unit_size });
        }
        if packet.is_haptics {
            return Ok(Vec::new());
        }
        if packet.frame_index > 1 << 15 {
            self.startup = false;
        }
        let mut out = Vec::new();
        for (i, unit) in packet.data.chunks(usize::from(unit_size)).enumerate() {
            let i = i as u16;
            let index = if i < u16::from(source_units) {
                packet.frame_index.wrapping_add(i)
            } else {
                let fec_index = i - u16::from(source_units);
                // chiaki-ng: at the start, a copy of a frame from before frame 0 is skipped.
                if self.startup && u32::from(packet.frame_index) + u32::from(fec_index) < u32::from(fec_units) + 1 {
                    continue;
                }
                packet.frame_index.wrapping_sub(u16::from(fec_units)).wrapping_add(fec_index)
            };
            if self.take(index) {
                out.push(AudioFrame { index, data: unit.to_vec() });
            }
        }
        Ok(out)
    }

    /// Whether `index` is new: not handed on already, and not older than the frames remembered.
    fn take(&mut self, index: u16) -> bool {
        if self.recent.contains(&index) {
            return false;
        }
        if let Some(newest) = self.newest {
            if index.lt(newest.wrapping_sub(RECENT)) {
                return false;
            }
            if index.gt(newest) {
                self.newest = Some(index);
            }
        } else {
            self.newest = Some(index);
        }
        self.recent.push(index);
        if self.recent.len() > usize::from(RECENT) {
            self.recent.remove(0);
        }
        true
    }
}
