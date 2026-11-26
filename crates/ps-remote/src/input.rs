// SPDX-License-Identifier: AGPL-3.0-only
//! Controller input from the browser: one JSON object per change on the `input` data channel.
//!
//! The message is untrusted. It is checked whole: unknown fields, values out of range, and button bits
//! that are not a digital button are refused, and a refused message changes nothing.
//!
//! Touchpad fingers come as `touches`: up to two `{"id", "x", "y"}`, the id a small number the page gives each
//! finger while it is down, `x` and `y` from 0 to 1 across the picture, as chiaki-ng turns the mouse over its
//! stream into a finger on the touchpad. [`Touchpad`] keeps the console's own touch ids for them from one
//! message to the next. (A gamepad's touchpad reports only its press to a browser, which is button 17.)

use psr_input::controller::{ControllerState, TOUCHES_MAX, Touch};
use serde::Deserialize;

/// Input messages are a few dozen bytes; anything much bigger is refused before parsing.
pub const MESSAGE_MAX: usize = 512;
/// The digital buttons: psr-input's bits 0 to 15.
const BUTTONS_MASK: u32 = 0xffff;

/// The message, field by field. The types bound each value: `u8` for the triggers (0 to 255), `i16` for the
/// sticks (−32768 to 32767). serde refuses anything outside them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    #[serde(default)]
    buttons: u32,
    #[serde(default)]
    l2: u8,
    #[serde(default)]
    r2: u8,
    #[serde(default)]
    lx: i16,
    #[serde(default)]
    ly: i16,
    #[serde(default)]
    rx: i16,
    #[serde(default)]
    ry: i16,
    #[serde(default)]
    touches: Vec<FingerMessage>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FingerMessage {
    id: u8,
    x: f32,
    y: f32,
}

/// The page's ids for fingers are below this.
pub const FINGER_ID_MAX: u8 = 16;

/// A finger on the touchpad, as the page sent it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Finger {
    pub id: u8,
    /// 0 to 1, left to right.
    pub x: f32,
    /// 0 to 1, top to bottom.
    pub y: f32,
}

/// One input message: the controller state without its touches, and the fingers down.
#[derive(Debug, Clone, PartialEq)]
pub struct Input {
    pub state: ControllerState,
    pub fingers: Vec<Finger>,
}

/// The controller state a message sets, without its touches, or `None` if it fails any check. Motion is not
/// taken from the browser yet: it stays idle.
pub fn parse(data: &[u8]) -> Option<ControllerState> {
    parse_input(data).map(|i| i.state)
}

/// The whole message, fingers included, or `None` if any part fails its check: at most [`TOUCHES_MAX`]
/// fingers, each id below [`FINGER_ID_MAX`] and used once, each position a number from 0 to 1.
pub fn parse_input(data: &[u8]) -> Option<Input> {
    if data.len() > MESSAGE_MAX {
        return None;
    }
    // An object only: serde would also take a JSON array as the struct's fields in order.
    let value: serde_json::Value = serde_json::from_slice(data).ok()?;
    if !value.is_object() {
        return None;
    }
    let m = Message::deserialize(value).ok()?;
    if m.buttons & !BUTTONS_MASK != 0 {
        return None;
    }
    let in_range = |v: f32| (0.0..=1.0).contains(&v);
    if m.touches.len() > TOUCHES_MAX
        || m.touches.iter().any(|f| f.id >= FINGER_ID_MAX || !in_range(f.x) || !in_range(f.y))
        || m.touches.iter().enumerate().any(|(i, f)| m.touches[..i].iter().any(|g| g.id == f.id))
    {
        return None;
    }
    let fingers = m.touches.iter().map(|f| Finger { id: f.id, x: f.x, y: f.y }).collect();
    let state = ControllerState {
        buttons: m.buttons,
        l2_state: m.l2,
        r2_state: m.r2,
        left_x: m.lx,
        left_y: m.ly,
        right_x: m.rx,
        right_y: m.ry,
        ..ControllerState::default()
    };
    Some(Input { state, fingers })
}

/// chiaki-ng's touchpad ranges (`gui/src/streamsession.cpp`): a PS5's is 1919 by 1079, a PS4's 1920 by 942.
pub const PS5_TOUCHPAD: (f32, f32) = (1919.0, 1079.0);
pub const PS4_TOUCHPAD: (f32, f32) = (1920.0, 942.0);

/// The touchpad as the console sees it, across messages: each finger the page reports keeps the console's touch
/// id it got when it went down (chiaki-ng `chiaki_controller_state_start_touch` and its neighbours).
#[derive(Debug, Clone)]
pub struct Touchpad {
    max: (f32, f32),
    slots: ControllerState,
    /// The page's finger id, and the console's touch id for it.
    held: Vec<(u8, u8)>,
}

impl Touchpad {
    pub fn new(ps5: bool) -> Self {
        Touchpad {
            max: if ps5 { PS5_TOUCHPAD } else { PS4_TOUCHPAD },
            slots: ControllerState::default(),
            held: Vec::new(),
        }
    }

    /// Lifts every finger.
    pub fn clear(&mut self) {
        *self = Touchpad::new(self.max == PS5_TOUCHPAD);
    }

    /// Fingers no longer reported are lifted, those still down moved, new ones put down while a slot is free.
    /// The touches and next id to put in the controller state.
    pub fn apply(&mut self, fingers: &[Finger]) -> ([Touch; TOUCHES_MAX], u8) {
        let scale = |f: &Finger| {
            // In range by `parse_input`'s check, so the casts cannot overflow.
            ((f.x * self.max.0).round() as u16, (f.y * self.max.1).round() as u16)
        };
        let gone: Vec<(u8, u8)> =
            self.held.iter().copied().filter(|(page, _)| !fingers.iter().any(|f| f.id == *page)).collect();
        for (_, touch) in &gone {
            self.slots.stop_touch(*touch);
        }
        self.held.retain(|h| !gone.contains(h));
        for f in fingers {
            let (x, y) = scale(f);
            match self.held.iter().find(|(page, _)| *page == f.id) {
                Some(&(_, touch)) => self.slots.set_touch_pos(touch, x, y),
                None => {
                    if let Some(touch) = self.slots.start_touch(x, y) {
                        self.held.push((f.id, touch));
                    }
                }
            }
        }
        (self.slots.touches, self.slots.touch_id_next)
    }
}

/// Where the browser's input goes: to the console, through the touchpad's ids, or nowhere in a watch-only session.
/// A watch-only session is for someone playing on the TV with their own controller while this PC shows the game
/// (to share it in Discord, say): nothing the browser sends may press anything for them.
#[derive(Debug, Clone)]
pub struct Controls {
    touchpad: Touchpad,
    watch_only: bool,
}

impl Controls {
    pub fn new(ps5: bool, watch_only: bool) -> Self {
        Controls { touchpad: Touchpad::new(ps5), watch_only }
    }

    pub fn watch_only(&self) -> bool {
        self.watch_only
    }

    /// The controller state to send for `input`, or `None` in a watch-only session, which sends the browser's
    /// input nowhere.
    pub fn apply(&mut self, input: &Input) -> Option<ControllerState> {
        if self.watch_only {
            return None;
        }
        let mut state = input.state;
        (state.touches, state.touch_id_next) = self.touchpad.apply(&input.fingers);
        Some(state)
    }

    /// Lifts every finger.
    pub fn clear(&mut self) {
        self.touchpad.clear();
    }
}
