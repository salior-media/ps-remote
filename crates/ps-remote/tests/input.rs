// SPDX-License-Identifier: AGPL-3.0-only
// The input channel's messages are untrusted: each check that refuses one is tried here.

use ps_remote::input::{self, MESSAGE_MAX};
use psr_input::controller::{ControllerState, button};

#[test]
fn a_message_sets_buttons_triggers_and_sticks() {
    let s = input::parse(br#"{"buttons":129,"l2":10,"r2":255,"lx":-32768,"ly":32767,"rx":5,"ry":-5}"#).unwrap();
    assert_eq!(s.buttons, button::CROSS | button::DPAD_DOWN);
    assert_eq!((s.l2_state, s.r2_state, s.left_x, s.left_y, s.right_x, s.right_y), (10, 255, -32768, 32767, 5, -5));
    assert_eq!(s.accel_y, 1.0, "motion stays idle");
}

#[test]
fn missing_fields_are_zero() {
    assert_eq!(input::parse(b"{}"), Some(ControllerState::default()));
    assert_eq!(input::parse(br#"{"buttons":2}"#).unwrap().buttons, button::MOON);
}

#[test]
fn anything_out_of_bounds_is_refused() {
    for bad in [
        &br#"{"l2":256}"#[..],
        br#"{"l2":-1}"#,
        br#"{"lx":32768}"#,
        br#"{"ry":-32769}"#,
        br#"{"buttons":65536}"#,
        br#"{"buttons":-1}"#,
        br#"{"lx":1.5}"#,
        br#"{"buttons":1,"extra":true}"#,
        br#"{"buttons":"1"}"#,
        b"[]",
        b"not json",
        b"",
    ] {
        assert_eq!(input::parse(bad), None, "{}", String::from_utf8_lossy(bad));
    }
    assert_eq!(input::parse(br#"{"buttons":32768}"#).unwrap().buttons, button::PS, "the top button bit is fine");
}

#[test]
fn an_oversized_message_is_refused_before_parsing() {
    let mut big = br#"{"buttons":1"#.to_vec();
    big.resize(MESSAGE_MAX, b' ');
    big.push(b'}');
    assert_eq!(big.len(), MESSAGE_MAX + 1);
    assert_eq!(input::parse(&big), None, "valid JSON, but one byte too long");
    let mut fits = br#"{"buttons":1"#.to_vec();
    fits.resize(MESSAGE_MAX - 1, b' ');
    fits.push(b'}');
    assert!(input::parse(&fits).is_some(), "the same at the limit is taken");
}

#[test]
fn fingers_come_with_the_message_and_bad_ones_refuse_it() {
    let i = input::parse_input(br#"{"buttons":1,"touches":[{"id":0,"x":0.5,"y":1},{"id":3,"x":0,"y":0.25}]}"#).unwrap();
    assert_eq!(i.state.buttons, button::CROSS);
    assert_eq!(i.fingers.len(), 2);
    assert_eq!((i.fingers[1].id, i.fingers[1].x, i.fingers[1].y), (3, 0.0, 0.25));
    assert!(i.state.touches.iter().all(|t| t.id.is_none()), "the state's own touches stay for the touchpad to fill");
    for bad in [
        &br#"{"touches":[{"id":0,"x":0.5,"y":0.5},{"id":1,"x":0.5,"y":0.5},{"id":2,"x":0.5,"y":0.5}]}"#[..],
        br#"{"touches":[{"id":0,"x":1.01,"y":0.5}]}"#,
        br#"{"touches":[{"id":0,"x":-0.01,"y":0.5}]}"#,
        br#"{"touches":[{"id":16,"x":0.5,"y":0.5}]}"#,
        br#"{"touches":[{"id":1,"x":0.5,"y":0.5},{"id":1,"x":0.2,"y":0.2}]}"#,
        br#"{"touches":[{"id":0,"x":0.5}]}"#,
        br#"{"touches":[{"id":0,"x":0.5,"y":0.5,"z":1}]}"#,
        br#"{"touches":{"id":0}}"#,
    ] {
        assert_eq!(input::parse_input(bad), None, "{}", String::from_utf8_lossy(bad));
    }
}

#[test]
fn the_touchpad_keeps_each_fingers_console_id_and_scales_to_the_console() {
    let f = |id, x, y| input::Finger { id, x, y };
    let mut pad = input::Touchpad::new(true);
    let (t, next) = pad.apply(&[f(5, 1.0, 1.0)]);
    assert_eq!((t[0].id, t[0].x, t[0].y, next), (Some(0), 1919, 1079, 1));
    // A second finger takes the other slot and the next id; the first moves and keeps its own.
    let (t, next) = pad.apply(&[f(5, 0.5, 0.5), f(2, 0.0, 0.0)]);
    assert_eq!((t[0].id, t[0].x, t[0].y), (Some(0), 960, 540));
    assert_eq!((t[1].id, t[1].x, t[1].y, next), (Some(1), 0, 0, 2));
    // The first lifts; a new one gets its slot and a new id. A third at once is ignored, not refused.
    let (t, _) = pad.apply(&[f(2, 0.0, 0.0)]);
    assert_eq!(t[0].id, None);
    let (t, next) = pad.apply(&[f(2, 0.0, 0.0), f(7, 0.25, 0.0)]);
    assert_eq!((t[0].id, t[1].id, next), (Some(2), Some(1), 3));
    pad.clear();
    let (t, _) = pad.apply(&[]);
    assert!(t.iter().all(|t| t.id.is_none()));
    // A PS4's touchpad is shorter.
    let (t, _) = input::Touchpad::new(false).apply(&[f(0, 1.0, 1.0)]);
    assert_eq!((t[0].x, t[0].y), (1920, 942));
}
