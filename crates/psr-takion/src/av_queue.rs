// SPDX-License-Identifier: AGPL-3.0-only
//! Puts video datagrams back in order before they are assembled into frames. Ported from chiaki-ng
//! `takion_handle_packet_av` and `takion_av_queue_flush_with_timeout` in `lib/src/takion.c`
//! (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! A packet that is missing at the head of the window is waited for, up to [`HEAD_TIMEOUT`], and then
//! skipped. The time is passed in, so the timeout can be tested without sleeping.

use std::time::{Duration, Instant};

use crate::reorder::{DropStrategy, ReorderQueue};
use crate::seqnum::SeqNum;

/// chiaki-ng `TAKION_AV_VIDEO_REORDER_QUEUE_SIZE_EXP`: 64 packets.
pub const SIZE_EXP: u32 = 6;
/// chiaki-ng `TAKION_AV_REORDER_TIMEOUT_US`: about one frame at 60 fps.
pub const HEAD_TIMEOUT: Duration = Duration::from_micros(16_000);

/// The video reorder window. `T` is whatever the caller keeps per packet (the datagram).
#[derive(Debug)]
pub struct AvQueue<T> {
    /// Created on the first packet, as chiaki-ng does, so the window starts at that packet's frame.
    queue: Option<ReorderQueue<u16, T>>,
    /// When the packet now missing at the head was first found missing.
    head_wait_start: Option<Instant>,
    head_wait_seq: u16,
}

impl<T> Default for AvQueue<T> {
    fn default() -> Self {
        Self { queue: None, head_wait_start: None, head_wait_seq: 0 }
    }
}

impl<T> AvQueue<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a packet and returns every packet now in order. Packets that fall out of the window are
    /// discarded, as chiaki-ng discards them.
    pub fn push(&mut self, packet_index: u16, unit_index: u16, value: T, now: Instant) -> Vec<T> {
        let queue = self.queue.get_or_insert_with(|| {
            // chiaki-ng starts the window at the first unit of this packet's frame.
            let begin = packet_index.wrapping_sub(unit_index);
            self.head_wait_seq = begin;
            let mut q = ReorderQueue::new(SIZE_EXP, begin);
            q.drop_strategy = DropStrategy::Begin;
            q
        });
        // Dropped packets are lost packets; FEC or a corrupt-frame report deals with them.
        let _dropped = queue.push(packet_index, value);
        self.flush(now)
    }

    /// Releases what is in order, skipping a missing head packet once it has been waited for long enough.
    /// chiaki-ng also runs this when its receive loop times out; call it from the same place.
    pub fn flush(&mut self, now: Instant) -> Vec<T> {
        let mut out = Vec::new();
        let Some(queue) = self.queue.as_mut() else {
            return out;
        };
        let mut progress = true;
        while progress {
            progress = false;
            while let Some((_, v)) = queue.pull() {
                out.push(v);
                progress = true;
            }
            if progress {
                self.head_wait_start = None;
            }
            if queue.count() == 0 {
                break;
            }
            if self.head_wait_start.is_some() && queue.begin() != self.head_wait_seq {
                if queue.begin().gt(self.head_wait_seq) {
                    // The missing head moved on within the same burst of loss: keep the time already
                    // waited, and follow the new missing packet.
                    self.head_wait_seq = queue.begin();
                } else {
                    self.head_wait_start = Some(now);
                    self.head_wait_seq = queue.begin();
                    break;
                }
            }
            let Some(start) = self.head_wait_start else {
                self.head_wait_start = Some(now);
                self.head_wait_seq = queue.begin();
                break;
            };
            if now.saturating_duration_since(start) <= HEAD_TIMEOUT {
                break;
            }
            // Skip straight to the first packet that is there, so a burst costs one timeout.
            if queue.skip_missing_head() == 0 {
                break;
            }
            self.head_wait_start = None;
            progress = true;
        }
        out
    }

    /// When [`AvQueue::flush`] should next run to skip a missing head packet, if one is being waited for.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.head_wait_start.map(|s| s + HEAD_TIMEOUT + Duration::from_micros(1))
    }
}
