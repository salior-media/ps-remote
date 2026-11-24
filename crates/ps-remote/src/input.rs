// SPDX-License-Identifier: AGPL-3.0-only
//! Controller input from the browser: one JSON object per change on the `input` data channel.
//!
//! The message is untrusted. It is checked whole: unknown fields, values out of range, and button bits
//! that are not a digital button are refused, and a refused message changes nothing.

use psr_input::controller::ControllerState;
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
}

/// The controller state a message sets, or `None` if it fails any check. Touch and motion are not taken
/// from the browser yet: they stay idle.
pub fn parse(data: &[u8]) -> Option<ControllerState> {
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
    Some(ControllerState {
        buttons: m.buttons,
        l2_state: m.l2,
        r2_state: m.r2,
        left_x: m.lx,
        left_y: m.ly,
        right_x: m.rx,
        right_y: m.ry,
        ..ControllerState::default()
    })
}
