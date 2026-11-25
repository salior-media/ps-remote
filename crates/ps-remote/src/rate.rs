// SPDX-License-Identifier: AGPL-3.0-only
//! The stream's bitrate, as the status reports it: the bytes of video and audio received over each second.

use std::time::{Duration, Instant};

/// How long each measurement runs.
pub const WINDOW: Duration = Duration::from_secs(1);

/// Bytes counted over a window, and the rate of the last whole window.
#[derive(Debug, Clone)]
pub struct Rate {
    since: Instant,
    bytes: u64,
    kbps: u64,
}

impl Rate {
    pub fn new(now: Instant) -> Self {
        Rate { since: now, bytes: 0, kbps: 0 }
    }

    /// Counts `bytes` received at `now`, closing the window first if it has run its course.
    pub fn add(&mut self, bytes: usize, now: Instant) {
        self.roll(now);
        self.bytes = self.bytes.saturating_add(bytes as u64);
    }

    /// Closes the window if it has run its course: its rate becomes the one reported. A window with nothing in
    /// it reports zero.
    pub fn roll(&mut self, now: Instant) {
        let took = now.saturating_duration_since(self.since);
        if took >= WINDOW {
            let ms = u64::try_from(took.as_millis()).unwrap_or(u64::MAX).max(1);
            self.kbps = self.bytes.saturating_mul(8) / ms;
            self.bytes = 0;
            self.since = now;
        }
    }

    /// Kilobits a second over the last whole window.
    pub fn kbps(&self) -> u64 {
        self.kbps
    }
}
