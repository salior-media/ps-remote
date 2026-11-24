// SPDX-License-Identifier: AGPL-3.0-only
//! Rebuilds whole video frames from the console's video packets, recovering lost units with FEC. Ported
//! from chiaki-ng `lib/src/frameprocessor.c` and `lib/src/videoreceiver.c`.
//!
//! Nothing is decoded: the frames come out as the console encoded them, to be passed on unchanged
//! (`docs/PORT-MAP.md` §3). Packets go in already in order and decrypted; psr-takion's `av_queue` orders
//! them and psr-lan's stream decrypts them.

pub mod frame;
pub mod video;
