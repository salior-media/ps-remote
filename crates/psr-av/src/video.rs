// SPDX-License-Identifier: AGPL-3.0-only
//! Follows the video stream frame by frame: opens a frame when its first packet arrives, rebuilds it when
//! enough units are in, and reports frames that were lost so the console can repair the picture. Ported
//! from chiaki-ng `lib/src/videoreceiver.c` (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! **Differences from chiaki-ng:**
//! - chiaki-ng reads each frame's H.264 or H.265 slice header (`bitstream.c`) to drop P-frames whose
//!   reference frame was lost, or to point them at an older one. ps-remote does not decode, so every
//!   complete frame is handed on and the decoder at the other end judges it. When it reports a lost
//!   picture, ask the console for a keyframe (`Stream::request_keyframe` in psr-lan).
//! - chiaki-ng counts lost frames with signed arithmetic, which goes negative when the frame index wraps
//!   past 65535. Here the count wraps with the index.

use psr_takion::av::AvPacket;
use psr_takion::seqnum::SeqNum;

use crate::frame::{FlushResult, FrameProcessor};

/// A rebuilt frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub index: u16,
    /// The codec's own bytes (for H.264, NAL units in Annex B form), ready for a decoder.
    pub data: Vec<u8>,
    /// Some of its units were lost and FEC brought them back.
    pub fec_recovered: bool,
    /// Frames lost since the last frame handed on.
    pub frames_lost: u32,
}

/// What the video stream produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VideoEvent {
    /// The console switched to this resolution: its codec header (SPS and PPS for H.264) comes before
    /// the frames that follow, as chiaki-ng hands it to its decoder first.
    Header {
        profile: u8,
        data: Vec<u8>,
    },
    Frame(Frame),
    /// Frames `start..=end` were lost or damaged. Tell the console (chiaki-ng
    /// `stream_connection_send_corrupt_frame`) so it stops predicting from them.
    CorruptFrames {
        start: u16,
        end: u16,
    },
}

/// The state of the video stream (chiaki-ng `ChiakiVideoReceiver`).
#[derive(Debug)]
pub struct VideoReceiver {
    /// Each resolution's codec header, in the order the console's stream info listed them.
    headers: Vec<Vec<u8>>,
    profile_cur: Option<u8>,
    frame_index_cur: Option<u16>,
    /// The last frame flushed, rebuilt or not.
    frame_index_prev: Option<u16>,
    /// The last frame rebuilt.
    frame_index_prev_complete: u16,
    frame_processor: FrameProcessor,
    frames_lost: u32,
    frames_lost_total: u64,
    /// Units refused by the frame processor (chiaki-ng logs these and carries on).
    units_refused: u64,
}

impl VideoReceiver {
    /// `headers` holds each resolution's codec header from the stream info.
    pub fn new(headers: Vec<Vec<u8>>) -> Self {
        Self {
            headers,
            profile_cur: None,
            frame_index_cur: None,
            frame_index_prev: None,
            frame_index_prev_complete: 0,
            frame_processor: FrameProcessor::new(),
            frames_lost: 0,
            frames_lost_total: 0,
            units_refused: 0,
        }
    }

    pub fn frames_lost_total(&self) -> u64 {
        self.frames_lost_total
    }

    pub fn units_refused(&self) -> u64 {
        self.units_refused
    }

    /// Handles one video packet, in packet order, with its payload already decrypted (chiaki-ng
    /// `chiaki_video_receiver_av_packet`).
    pub fn av_packet(&mut self, packet: &AvPacket<'_>) -> Vec<VideoEvent> {
        let mut events = Vec::new();
        let frame_index = packet.frame_index;
        if self.frame_index_cur.is_some_and(|cur| frame_index.lt(cur)) {
            return events; // a packet of a frame already passed
        }

        if self.profile_cur != Some(packet.adaptive_stream_index) {
            let Some(header) = self.headers.get(usize::from(packet.adaptive_stream_index)) else {
                self.units_refused += 1;
                return events;
            };
            self.profile_cur = Some(packet.adaptive_stream_index);
            events.push(VideoEvent::Header { profile: packet.adaptive_stream_index, data: header.clone() });
        }

        if self.frame_index_cur.is_none_or(|cur| frame_index.gt(cur)) {
            // The frame before was never rebuilt: rebuild what there is of it now.
            if self.frame_index_cur.is_some() && self.frame_index_prev != self.frame_index_cur {
                self.flush_frame(&mut events);
            }
            let next_expected = self.frame_index_prev_complete.wrapping_add(1);
            // chiaki-ng also excuses frame 1 when it is the first frame. That changes nothing: the last
            // frame rebuilt starts at 0, so frame 1 is never past the one expected next.
            if frame_index.gt(next_expected) {
                events.push(VideoEvent::CorruptFrames { start: next_expected, end: frame_index.wrapping_sub(1) });
            }
            self.frame_index_cur = Some(frame_index);
            if self.frame_processor.alloc_frame(packet).is_err() {
                self.units_refused += 1;
            }
        }

        if self.frame_processor.put_unit(packet).is_err() {
            self.units_refused += 1;
        }

        let last_unit = packet.unit_index == packet.units_in_frame_total.wrapping_sub(1);
        if self.frame_index_cur != self.frame_index_prev && (self.frame_processor.flush_possible() || last_unit) {
            self.flush_frame(&mut events);
        }
        events
    }

    /// chiaki-ng `chiaki_video_receiver_flush_frame`, without the slice-header checks (see the module
    /// documentation).
    fn flush_frame(&mut self, events: &mut Vec<VideoEvent>) {
        let Some(cur) = self.frame_index_cur else {
            return;
        };
        let (result, data) = self.frame_processor.flush();
        match result {
            FlushResult::Failed => {}
            FlushResult::FecFailed => {
                let next_expected = self.frame_index_prev_complete.wrapping_add(1);
                events.push(VideoEvent::CorruptFrames { start: next_expected, end: cur });
                let lost = u32::from(cur.wrapping_sub(next_expected).wrapping_add(1));
                self.frames_lost += lost;
                self.frames_lost_total += u64::from(lost);
                self.frame_index_prev = Some(cur);
            }
            FlushResult::Success | FlushResult::FecSuccess => {
                events.push(VideoEvent::Frame(Frame {
                    index: cur,
                    data,
                    fec_recovered: result == FlushResult::FecSuccess,
                    frames_lost: std::mem::take(&mut self.frames_lost),
                }));
                self.frame_index_prev = Some(cur);
                self.frame_index_prev_complete = cur;
            }
        }
    }
}
