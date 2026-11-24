// SPDX-License-Identifier: AGPL-3.0-only
//! Collects one frame's units and joins them into the frame. Ported from chiaki-ng
//! `lib/src/frameprocessor.c` (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! A frame is sent as `k` source units and `m` FEC units, all the same size once padded. Each source unit
//! starts with a big-endian `u16`: how many padding bytes were cut off its end before it was sent. The
//! frame is the source units joined, each without those two bytes. FEC units are sent whole.
//!
//! **Differences from chiaki-ng:** a frame whose shape is refused leaves no frame open, so the units that
//! follow are refused too, where chiaki-ng goes on with what was left of the frame before. And chiaki-ng's
//! bitrate counter (`ChiakiStreamStats`) is not here: it belongs with congestion control.

use psr_fec::Fec;
use psr_takion::av::AvPacket;

/// chiaki-ng `UNIT_SLOTS_MAX`.
pub const UNIT_SLOTS_MAX: usize = 512;
/// The padding length at the start of each source unit.
const PADDING_FIELD: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("the packet says {fec} of its frame's {total} units are FEC units")]
    FecAboveTotal { total: u16, fec: u16 },
    #[error("a {0}-byte source unit is too short for its padding length")]
    NoPaddingField(usize),
    #[error("the frame's units would be empty")]
    EmptyUnits,
    #[error("the frame would need {0} unit slots; at most {UNIT_SLOTS_MAX} are allowed")]
    TooManyUnits(usize),
    #[error("no frame is open")]
    NoFrame,
    #[error("unit {index} is outside the frame's {slots} units")]
    UnitIndex { index: u16, slots: usize },
    #[error("unit {0} is empty")]
    EmptyUnit(u16),
    #[error("unit {index} is {len} bytes, more than the frame's {unit_size}")]
    UnitTooBig { index: u16, len: usize, unit_size: usize },
    #[error("unit {0} arrived twice")]
    Duplicate(u16),
}

/// How a frame came out (chiaki-ng `ChiakiFrameProcessorFlushResult`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushResult {
    /// Every source unit arrived.
    Success,
    /// Some source units were lost and FEC brought them back.
    FecSuccess,
    /// Too many units were lost for FEC. What arrived is still joined, but the frame is damaged.
    FecFailed,
    /// No frame was open.
    Failed,
}

#[derive(Debug)]
struct Open {
    source_expected: usize,
    fec_expected: usize,
    /// Every unit's size once padded (chiaki-ng `buf_size_per_unit`).
    unit_size: usize,
    /// Source units first, then FEC units.
    units: Vec<Option<Vec<u8>>>,
    source_received: usize,
    fec_received: usize,
}

/// Collects the units of the frame being received (chiaki-ng `ChiakiFrameProcessor`).
#[derive(Debug, Default)]
pub struct FrameProcessor {
    open: Option<Open>,
}

impl FrameProcessor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens a new frame, shaped by its first packet to arrive (chiaki-ng `chiaki_frame_processor_alloc_frame`).
    /// `packet.data` must already be decrypted.
    pub fn alloc_frame(&mut self, packet: &AvPacket<'_>) -> Result<(), FrameError> {
        self.open = None;
        let (total, fec) = (packet.units_in_frame_total, packet.units_in_frame_fec);
        if total < fec {
            return Err(FrameError::FecAboveTotal { total, fec });
        }
        let source_expected = usize::from(total - fec);
        // chiaki-ng: a frame always has room for at least one FEC unit.
        let fec_expected = usize::from(fec).max(1);
        let mut unit_size = packet.data.len();
        if packet.is_video && usize::from(packet.unit_index) < source_expected {
            let padding = padding_of(packet.data).ok_or(FrameError::NoPaddingField(packet.data.len()))?;
            unit_size += usize::from(padding);
        }
        if unit_size == 0 {
            return Err(FrameError::EmptyUnits);
        }
        let slots = source_expected + fec_expected;
        if slots > UNIT_SLOTS_MAX {
            return Err(FrameError::TooManyUnits(slots));
        }
        self.open = Some(Open {
            source_expected,
            fec_expected,
            unit_size,
            units: vec![None; slots],
            source_received: 0,
            fec_received: 0,
        });
        Ok(())
    }

    /// Adds one unit of the open frame (chiaki-ng `chiaki_frame_processor_put_unit`). `packet.data` must
    /// already be decrypted.
    pub fn put_unit(&mut self, packet: &AvPacket<'_>) -> Result<(), FrameError> {
        let open = self.open.as_mut().ok_or(FrameError::NoFrame)?;
        let index = packet.unit_index;
        let i = usize::from(index);
        if index >= packet.units_in_frame_total || i >= open.units.len() {
            return Err(FrameError::UnitIndex { index, slots: open.units.len() });
        }
        if packet.data.is_empty() {
            return Err(FrameError::EmptyUnit(index));
        }
        if packet.data.len() > open.unit_size {
            return Err(FrameError::UnitTooBig { index, len: packet.data.len(), unit_size: open.unit_size });
        }
        if open.units[i].is_some() {
            return Err(FrameError::Duplicate(index));
        }
        open.units[i] = Some(packet.data.to_vec());
        if i < open.source_expected {
            open.source_received += 1;
        } else {
            open.fec_received += 1;
        }
        Ok(())
    }

    /// Whether enough units are in for the frame to be rebuilt (chiaki-ng `chiaki_frame_processor_flush_possible`).
    pub fn flush_possible(&self) -> bool {
        self.open.as_ref().is_some_and(|o| o.source_received + o.fec_received >= o.source_expected)
    }

    /// Units received and expected in the open frame, source and FEC together.
    pub fn units(&self) -> (usize, usize) {
        self.open.as_ref().map_or((0, 0), |o| (o.source_received + o.fec_received, o.units.len()))
    }

    /// Rebuilds the open frame, running FEC when source units are missing (chiaki-ng
    /// `chiaki_frame_processor_flush`). Returns the frame with how it came out; with
    /// [`FlushResult::Failed`] the frame is empty.
    pub fn flush(&mut self) -> (FlushResult, Vec<u8>) {
        let Some(open) = self.open.as_mut() else {
            return (FlushResult::Failed, Vec::new());
        };
        if open.source_expected == 0 {
            return (FlushResult::Failed, Vec::new());
        }
        let mut result = FlushResult::Success;
        if open.source_received < open.source_expected {
            result = if open.recover() { FlushResult::FecSuccess } else { FlushResult::FecFailed };
        }
        let mut frame = Vec::new();
        // A unit still missing, or one too short for its padding length, is left out, as chiaki-ng
        // leaves it out.
        for unit in open.units[..open.source_expected].iter().flatten() {
            if unit.len() >= PADDING_FIELD {
                frame.extend_from_slice(&unit[PADDING_FIELD..]);
            }
        }
        (result, frame)
    }
}

impl Open {
    /// chiaki-ng `chiaki_frame_processor_fec`: decodes over the padded units, then cuts each source unit
    /// back to its own length.
    fn recover(&mut self) -> bool {
        let Ok(fec) = Fec::new(self.source_expected, self.fec_expected) else {
            return false;
        };
        let padded: Vec<Option<Vec<u8>>> = self
            .units
            .iter()
            .map(|u| {
                u.as_ref().map(|u| {
                    let mut p = u.clone();
                    p.resize(self.unit_size, 0);
                    p
                })
            })
            .collect();
        let views: Vec<Option<&[u8]>> = padded.iter().map(|u| u.as_deref()).collect();
        let Ok(data) = fec.decode(&views) else {
            return false;
        };
        for (slot, mut unit) in self.units.iter_mut().zip(data) {
            // chiaki-ng: a padding length that would leave nothing is logged and the slot left as it was.
            let Some(padding) = padding_of(&unit).map(usize::from).filter(|&p| p < self.unit_size) else {
                continue;
            };
            unit.truncate(self.unit_size - padding);
            *slot = Some(unit);
        }
        true
    }
}

/// The console's side: splits `frame` into source units of `unit_size` bytes once padded, and adds `fec`
/// FEC units. Returns the units as they are sent: source units cut to their length, then FEC units whole.
/// For tests and fake consoles; nothing in the receive path uses it.
pub fn split_frame(frame: &[u8], unit_size: usize, fec: usize) -> Result<Vec<Vec<u8>>, psr_fec::FecError> {
    let chunk = unit_size.saturating_sub(PADDING_FIELD).max(1);
    let padded: Vec<Vec<u8>> = frame
        .chunks(chunk)
        .map(|c| {
            let padding = (chunk - c.len()) as u16;
            let mut u = padding.to_be_bytes().to_vec();
            u.extend_from_slice(c);
            u.resize(chunk + PADDING_FIELD, 0);
            u
        })
        .collect();
    let views: Vec<&[u8]> = padded.iter().map(Vec::as_slice).collect();
    let parity = Fec::new(padded.len(), fec)?.encode(&views)?;
    let mut sent: Vec<Vec<u8>> = padded
        .into_iter()
        .map(|mut u| {
            let padding = usize::from(u16::from_be_bytes([u[0], u[1]]));
            u.truncate(u.len() - padding);
            u
        })
        .collect();
    sent.extend(parity);
    Ok(sent)
}

fn padding_of(unit: &[u8]) -> Option<u16> {
    unit.get(..PADDING_FIELD).map(|b| u16::from_be_bytes([b[0], b[1]]))
}
