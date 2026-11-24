// SPDX-License-Identifier: AGPL-3.0-only
//! A controller's state: buttons, triggers, sticks, touchpad fingers and motion. Ported from chiaki-ng
//! `lib/src/controller.c` and `lib/include/chiaki/controller.h` (LicenseRef-AGPL-3.0-only-OpenSSL).

/// Button bits for [`ControllerState::buttons`] (chiaki-ng `ChiakiControllerButton`), and the two analog
/// triggers, which history events name the same way (`ChiakiControllerAnalogButton`).
pub mod button {
    pub const CROSS: u32 = 1 << 0;
    pub const MOON: u32 = 1 << 1;
    pub const BOX: u32 = 1 << 2;
    pub const PYRAMID: u32 = 1 << 3;
    pub const DPAD_LEFT: u32 = 1 << 4;
    pub const DPAD_RIGHT: u32 = 1 << 5;
    pub const DPAD_UP: u32 = 1 << 6;
    pub const DPAD_DOWN: u32 = 1 << 7;
    pub const L1: u32 = 1 << 8;
    pub const R1: u32 = 1 << 9;
    pub const L3: u32 = 1 << 10;
    pub const R3: u32 = 1 << 11;
    pub const OPTIONS: u32 = 1 << 12;
    pub const SHARE: u32 = 1 << 13;
    pub const TOUCHPAD: u32 = 1 << 14;
    pub const PS: u32 = 1 << 15;
    /// The digital buttons are the low 16 bits.
    pub const COUNT: u32 = 16;
    pub const L2: u32 = 1 << 16;
    pub const R2: u32 = 1 << 17;
}

/// chiaki-ng `CHIAKI_CONTROLLER_TOUCHES_MAX`.
pub const TOUCHES_MAX: usize = 2;
const TOUCH_ID_MASK: u8 = 0x7f;
/// chiaki-ng compares motion values with this tolerance.
const MOTION_EPSILON: f32 = 0.000_000_1;

/// One touchpad finger. `id` is `None` while the slot is free (chiaki-ng's -1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Touch {
    pub x: u16,
    pub y: u16,
    pub id: Option<u8>,
}

/// chiaki-ng `ChiakiControllerState`. [`Default`] is chiaki-ng's idle state: nothing pressed, the
/// controller lying flat (gravity on y) and unrotated.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ControllerState {
    /// Bits from [`button`].
    pub buttons: u32,
    pub l2_state: u8,
    pub r2_state: u8,
    pub left_x: i16,
    pub left_y: i16,
    pub right_x: i16,
    pub right_y: i16,
    pub touch_id_next: u8,
    pub touches: [Touch; TOUCHES_MAX],
    pub gyro_x: f32,
    pub gyro_y: f32,
    pub gyro_z: f32,
    pub accel_x: f32,
    pub accel_y: f32,
    pub accel_z: f32,
    pub orient_x: f32,
    pub orient_y: f32,
    pub orient_z: f32,
    pub orient_w: f32,
}

impl Default for ControllerState {
    /// chiaki-ng `chiaki_controller_state_set_idle`.
    fn default() -> Self {
        Self {
            buttons: 0,
            l2_state: 0,
            r2_state: 0,
            left_x: 0,
            left_y: 0,
            right_x: 0,
            right_y: 0,
            touch_id_next: 0,
            touches: [Touch::default(); TOUCHES_MAX],
            gyro_x: 0.0,
            gyro_y: 0.0,
            gyro_z: 0.0,
            accel_x: 0.0,
            accel_y: 1.0,
            accel_z: 0.0,
            orient_x: 0.0,
            orient_y: 0.0,
            orient_z: 0.0,
            orient_w: 1.0,
        }
    }
}

fn near(a: f32, b: f32) -> bool {
    !(a < b - MOTION_EPSILON || a > b + MOTION_EPSILON)
}

impl ControllerState {
    /// chiaki-ng `chiaki_controller_state_start_touch`: puts a finger down in the first free slot and
    /// returns its id, or `None` when both slots are taken.
    pub fn start_touch(&mut self, x: u16, y: u16) -> Option<u8> {
        let slot = self.touches.iter_mut().find(|t| t.id.is_none())?;
        let id = self.touch_id_next;
        *slot = Touch { x, y, id: Some(id) };
        self.touch_id_next = (self.touch_id_next + 1) & TOUCH_ID_MASK;
        Some(id)
    }

    /// chiaki-ng `chiaki_controller_state_stop_touch`.
    pub fn stop_touch(&mut self, id: u8) {
        if let Some(t) = self.touches.iter_mut().find(|t| t.id == Some(id)) {
            t.id = None;
        }
    }

    /// chiaki-ng `chiaki_controller_state_set_touch_pos`.
    pub fn set_touch_pos(&mut self, id: u8, x: u16, y: u16) {
        let id = id & TOUCH_ID_MASK;
        if let Some(t) = self.touches.iter_mut().find(|t| t.id == Some(id)) {
            t.x = x;
            t.y = y;
        }
    }

    /// The sticks and motion only, as chiaki-ng's feedback sender compares them to decide whether a state
    /// packet is worth sending.
    pub fn same_sticks_and_motion(&self, other: &Self) -> bool {
        self.left_x == other.left_x
            && self.left_y == other.left_y
            && self.right_x == other.right_x
            && self.right_y == other.right_y
            && self.same_motion(other)
    }

    fn same_motion(&self, other: &Self) -> bool {
        self.motion().iter().zip(other.motion()).all(|(&a, b)| near(a, b))
    }

    fn motion(&self) -> [f32; 10] {
        [
            self.gyro_x,
            self.gyro_y,
            self.gyro_z,
            self.accel_x,
            self.accel_y,
            self.accel_z,
            self.orient_x,
            self.orient_y,
            self.orient_z,
            self.orient_w,
        ]
    }

    /// chiaki-ng `chiaki_controller_state_equals`: motion within a small tolerance, and the position of a
    /// free touch slot ignored.
    pub fn equals(&self, other: &Self) -> bool {
        let same_touches = self
            .touches
            .iter()
            .zip(&other.touches)
            .all(|(a, b)| a.id == b.id && (a.id.is_none() || (a.x == b.x && a.y == b.y)));
        self.buttons == other.buttons
            && self.l2_state == other.l2_state
            && self.r2_state == other.r2_state
            && same_touches
            && self.same_sticks_and_motion(other)
    }

    /// chiaki-ng `chiaki_controller_state_or`: two controllers as one. Buttons are joined, triggers take
    /// the larger value, sticks the larger deflection, and touches `a`'s finger before `b`'s. Motion is not
    /// mixed: it is `a`'s if `a` has any (gyro or accel away from idle), otherwise `b`'s.
    pub fn or(a: &Self, b: &Self) -> Self {
        fn max_abs(a: i16, b: i16) -> i16 {
            if i32::from(a).abs() > i32::from(b).abs() { a } else { b }
        }
        let idle = Self::default();
        let a_moves = [a.gyro_x, a.gyro_y, a.gyro_z, a.accel_x, a.accel_y, a.accel_z]
            .iter()
            .zip([idle.gyro_x, idle.gyro_y, idle.gyro_z, idle.accel_x, idle.accel_y, idle.accel_z])
            .any(|(&v, d)| !near(v, d));
        let motion = if a_moves { a } else { b };
        let mut touches = [Touch::default(); TOUCHES_MAX];
        for (i, t) in touches.iter_mut().enumerate() {
            if a.touches[i].id.is_some() {
                *t = a.touches[i];
            } else if b.touches[i].id.is_some() {
                *t = b.touches[i];
            }
        }
        Self {
            buttons: a.buttons | b.buttons,
            l2_state: a.l2_state.max(b.l2_state),
            r2_state: a.r2_state.max(b.r2_state),
            left_x: max_abs(a.left_x, b.left_x),
            left_y: max_abs(a.left_y, b.left_y),
            right_x: max_abs(a.right_x, b.right_x),
            right_y: max_abs(a.right_y, b.right_y),
            touch_id_next: 0,
            touches,
            gyro_x: motion.gyro_x,
            gyro_y: motion.gyro_y,
            gyro_z: motion.gyro_z,
            accel_x: motion.accel_x,
            accel_y: motion.accel_y,
            accel_z: motion.accel_z,
            orient_x: motion.orient_x,
            orient_y: motion.orient_y,
            orient_z: motion.orient_z,
            orient_w: motion.orient_w,
        }
    }
}
