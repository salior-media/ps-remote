// SPDX-License-Identifier: AGPL-3.0-only
//! What the console is told about the controller. Ported from chiaki-ng `lib/src/feedback.c`
//! (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! Two kinds of packet carry it. A **state** packet holds the sticks and motion, as they are now. A
//! **history** packet holds button and touchpad events, newest first, and repeats the recent ones so a
//! lost packet costs nothing.
//!
//! **Difference from chiaki-ng:** chiaki-ng converts motion to 16 bits with a C cast, which is undefined
//! for values outside the range (gyro ±30, accel ±5). Rust's cast clamps them to the range's ends.

use crate::controller::{ControllerState, button};

const GYRO_MIN: f32 = -30.0;
const GYRO_MAX: f32 = 30.0;
const ACCEL_MIN: f32 = -5.0;
const ACCEL_MAX: f32 = 5.0;

/// chiaki-ng `CHIAKI_FEEDBACK_STATE_BUF_SIZE_V9`.
pub const STATE_SIZE_V9: usize = 0x19;
/// chiaki-ng `CHIAKI_FEEDBACK_STATE_BUF_SIZE_V12`.
pub const STATE_SIZE_V12: usize = 0x1c;
/// chiaki-ng `CHIAKI_HISTORY_EVENT_SIZE_MAX`.
pub const EVENT_SIZE_MAX: usize = 5;

/// The sticks and motion (chiaki-ng `ChiakiFeedbackState`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FeedbackState {
    pub gyro: [f32; 3],
    pub accel: [f32; 3],
    /// A unit quaternion: x, y, z, w.
    pub orient: [f32; 4],
    pub left_x: i16,
    pub left_y: i16,
    pub right_x: i16,
    pub right_y: i16,
}

impl From<&ControllerState> for FeedbackState {
    fn from(s: &ControllerState) -> Self {
        Self {
            gyro: [s.gyro_x, s.gyro_y, s.gyro_z],
            accel: [s.accel_x, s.accel_y, s.accel_z],
            orient: [s.orient_x, s.orient_y, s.orient_z, s.orient_w],
            left_x: s.left_x,
            left_y: s.left_y,
            right_x: s.right_x,
            right_y: s.right_y,
        }
    }
}

/// `v` scaled from `min..max` to 16 bits, in chiaki-ng's order of operations, in single precision.
fn scale(v: f32, min: f32, max: f32) -> [u8; 2] {
    (((65535.0f32 * (v - min)) / (max - min)) as u16).to_le_bytes()
}

/// chiaki-ng `compress_quat`: the largest component's index and sign in 3 bits, then the other three
/// in 9 bits each. chiaki-ng mixes `float` with `double` constants here, so the steps that C promotes
/// to double are done in double.
fn compress_quat(q: [f32; 4]) -> u32 {
    use std::f64::consts::FRAC_1_SQRT_2;
    let mut largest = 0;
    for i in 1..4 {
        if q[i].abs() > q[largest].abs() {
            largest = i;
        }
    }
    let mut r = u32::from(q[largest] < 0.0) | ((largest as u32) << 1);
    let scale = f64::from(511.0f32) / (2.0 * FRAC_1_SQRT_2);
    for (i, qi) in (0..4).filter(|&i| i != largest).enumerate() {
        let mut v = q[qi];
        if f64::from(v) < -FRAC_1_SQRT_2 {
            v = -FRAC_1_SQRT_2 as f32;
        }
        if f64::from(v) > FRAC_1_SQRT_2 {
            v = FRAC_1_SQRT_2 as f32;
        }
        v = (f64::from(v) + FRAC_1_SQRT_2) as f32;
        v = (f64::from(v) * scale) as f32;
        r |= (v as u32) << (3 + i * 9);
    }
    r
}

/// chiaki-ng `chiaki_feedback_state_format_v9`: protocol 9 (PS4).
pub fn format_v9(s: &FeedbackState) -> [u8; STATE_SIZE_V9] {
    let mut b = [0u8; STATE_SIZE_V9];
    b[0] = 0xa0;
    for (i, &g) in s.gyro.iter().enumerate() {
        b[1 + 2 * i..3 + 2 * i].copy_from_slice(&scale(g, GYRO_MIN, GYRO_MAX));
    }
    for (i, &a) in s.accel.iter().enumerate() {
        b[7 + 2 * i..9 + 2 * i].copy_from_slice(&scale(a, ACCEL_MIN, ACCEL_MAX));
    }
    b[0xd..0x11].copy_from_slice(&compress_quat(s.orient).to_le_bytes());
    for (i, v) in [s.left_x, s.left_y, s.right_x, s.right_y].into_iter().enumerate() {
        b[0x11 + 2 * i..0x13 + 2 * i].copy_from_slice(&v.to_be_bytes());
    }
    b
}

/// chiaki-ng `chiaki_feedback_state_format_v12`: protocol 12 (PS5), protocol 9's bytes and then 0, 0, 1.
pub fn format_v12(s: &FeedbackState) -> [u8; STATE_SIZE_V12] {
    let mut b = [0u8; STATE_SIZE_V12];
    b[..STATE_SIZE_V9].copy_from_slice(&format_v9(s));
    b[0x1b] = 1;
    b
}

/// One button or touchpad event (chiaki-ng `ChiakiFeedbackHistoryEvent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HistoryEvent {
    buf: [u8; EVENT_SIZE_MAX],
    len: usize,
}

impl HistoryEvent {
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// chiaki-ng `chiaki_feedback_history_event_set_button`: `state` is 0 released, 0xff pressed, and
    /// anything between for L2 and R2. Some buttons carry the state in a third byte, others in their code.
    /// `None` for anything that is not a single button of [`button`].
    pub fn button(b: u32, state: u8) -> Option<Self> {
        let with_state = |code: u8| Self { buf: [0x80, code, state, 0, 0], len: 3 };
        let pressed_or_not =
            |down: u8, up: u8| Self { buf: [0x80, if state != 0 { down } else { up }, 0, 0, 0], len: 2 };
        Some(match b {
            button::CROSS => with_state(0x88),
            button::MOON => with_state(0x89),
            button::BOX => with_state(0x8a),
            button::PYRAMID => with_state(0x8b),
            button::DPAD_LEFT => with_state(0x82),
            button::DPAD_RIGHT => with_state(0x83),
            button::DPAD_UP => with_state(0x80),
            button::DPAD_DOWN => with_state(0x81),
            button::L1 => with_state(0x84),
            button::R1 => with_state(0x85),
            button::L2 => with_state(0x86),
            button::R2 => with_state(0x87),
            button::L3 => pressed_or_not(0xaf, 0x8f),
            button::R3 => pressed_or_not(0xb0, 0x90),
            button::OPTIONS => pressed_or_not(0xac, 0x8c),
            button::SHARE => pressed_or_not(0xad, 0x8d),
            button::TOUCHPAD => pressed_or_not(0xb1, 0x91),
            button::PS => pressed_or_not(0xae, 0x8e),
            _ => return None,
        })
    }

    /// chiaki-ng `chiaki_feedback_history_event_set_touchpad`: a finger (id 0 to 127) down or up at x
    /// (0 to 1920) and y (0 to 942), packed into 12 bits each.
    pub fn touchpad(down: bool, pointer_id: u8, x: u16, y: u16) -> Self {
        Self {
            buf: [
                if down { 0xd0 } else { 0xc0 },
                pointer_id & 0x7f,
                (x >> 4) as u8,
                (((x & 0xf) << 4) as u8) | ((y >> 8) as u8),
                y as u8,
            ],
            len: 5,
        }
    }
}

/// The most recent events, newest first (chiaki-ng `ChiakiFeedbackHistoryBuffer`, a ring buffer).
#[derive(Debug, Clone)]
pub struct HistoryBuffer {
    events: Vec<HistoryEvent>,
    begin: usize,
    len: usize,
}

impl HistoryBuffer {
    pub fn new(size: usize) -> Self {
        Self { events: vec![HistoryEvent::default(); size.max(1)], begin: 0, len: 0 }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Keeps only the newest `len` events.
    pub fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }

    /// chiaki-ng `chiaki_feedback_history_buffer_push`: adds an event as the newest.
    pub fn push(&mut self, event: HistoryEvent) {
        let size = self.events.len();
        self.begin = (self.begin + size - 1) % size;
        self.len = (self.len + 1).min(size);
        self.events[self.begin] = event;
    }

    /// chiaki-ng `chiaki_feedback_history_buffer_format`: every event's bytes, newest first.
    pub fn format(&self) -> Vec<u8> {
        (0..self.len).flat_map(|i| self.events[(self.begin + i) % self.events.len()].bytes().to_vec()).collect()
    }

    /// chiaki-ng `chiaki_feedback_history_buffer_record_state`: pushes the events for the change from
    /// `prev` to `now` in the order a real controller makes them (releases, then touches, then presses,
    /// then the triggers), calling `pushed` after each one: the console applies only one new event per
    /// packet, so each needs a packet of its own. Returns whether anything was pushed.
    ///
    /// As in chiaki-ng, a finger replaced by another in the same slot in one change sends only the first
    /// finger's lift; the new one is sent when it next moves.
    pub fn record_state(
        &mut self,
        prev: &ControllerState,
        now: &ControllerState,
        mut pushed: impl FnMut(&mut Self),
    ) -> bool {
        let mut any = false;
        let mut push = |buf: &mut Self, e: HistoryEvent| {
            buf.push(e);
            any = true;
            pushed(buf);
        };
        let buttons = |buf: &mut Self, push: &mut dyn FnMut(&mut Self, HistoryEvent), pressed: bool| {
            for i in 0..button::COUNT {
                let b = 1 << i;
                let (was, is) = (prev.buttons & b != 0, now.buttons & b != 0);
                if was != is && is == pressed {
                    // Every digital button has an event; none is skipped.
                    if let Some(e) = HistoryEvent::button(b, if is { 0xff } else { 0 }) {
                        push(buf, e);
                    }
                }
            }
        };
        buttons(self, &mut push, false);
        for (p, n) in prev.touches.iter().zip(&now.touches) {
            if let Some(lifted) = p.id
                && p.id != n.id
            {
                push(self, HistoryEvent::touchpad(false, lifted, p.x, p.y));
            } else if let Some(id) = n.id
                && (p.id != n.id || p.x != n.x || p.y != n.y)
            {
                push(self, HistoryEvent::touchpad(true, id, n.x, n.y));
            }
        }
        buttons(self, &mut push, true);
        for (b, was, is) in [(button::L2, prev.l2_state, now.l2_state), (button::R2, prev.r2_state, now.r2_state)] {
            if was != is
                && let Some(e) = HistoryEvent::button(b, is)
            {
                push(self, e);
            }
        }
        any
    }
}
