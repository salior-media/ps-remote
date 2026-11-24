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
