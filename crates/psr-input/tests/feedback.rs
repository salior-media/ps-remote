// SPDX-License-Identifier: AGPL-3.0-only
// Ported from chiaki-ng `test/feedback.c` (LicenseRef-AGPL-3.0-only-OpenSSL), plus vectors printed by
// chiaki-ng's own `feedback.c` and `controller.c` (scripts/oracle/feedback).

use psr_input::controller::{ControllerState, Touch, button};
use psr_input::feedback::{self, FeedbackState, HistoryBuffer, HistoryEvent};

fn oracle(kind: &str) -> Vec<Vec<String>> {
    include_str!("vectors/feedback_oracle.txt")
        .lines()
        .filter_map(|l| l.strip_prefix(kind).and_then(|r| r.strip_prefix(' ')))
        .map(|r| r.split(' ').map(str::to_string).collect())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[allow(clippy::too_many_arguments)]
fn fs(g: [f32; 3], a: [f32; 3], o: [f32; 4], lx: i16, ly: i16, rx: i16, ry: i16) -> FeedbackState {
    FeedbackState { gyro: g, accel: a, orient: o, left_x: lx, left_y: ly, right_x: rx, right_y: ry }
}

/// The same states as scripts/oracle/feedback/main.c, in the same order.
fn oracle_states() -> Vec<FeedbackState> {
    vec![
        fs([0.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 0.0, 1.0], 0, 0, 0, 0),
        fs([1.5, -2.25, 29.9], [0.1, -0.98, 4.9], [0.0, 0.0, 0.0, 1.0], 32767, -32768, 1234, -4321),
        fs([-29.9, 0.001, -7.5], [-4.9, 0.5, -1.0], [0.5, -0.5, 0.5, -0.5], -1, 1, -2, 2),
        fs([0.0; 3], [0.0; 3], [-0.8, 0.36, 0.48, 0.0], 0, 0, 0, 0),
        fs([0.0; 3], [0.0; 3], [0.1, -0.9, 0.3, 0.3], 100, 200, 300, 400),
        fs([0.0; 3], [0.0; 3], [0.2, 0.1, -0.95, 0.2], 0, 0, 0, 0),
        // Values where chiaki-ng's order of operations truncates differently from the other order.
        fs([-3.2121782, 4.363926, 13.378345], [4.087205, 0.0, 0.0], [0.0, 0.0, 0.0, 1.0], 0, 0, 0, 0),
    ]
}

#[test]
fn state_packets_match_chiaki_ng() {
    let states = oracle_states();
    let (v9, v12) = (oracle("state_v9"), oracle("state_v12"));
    assert_eq!((v9.len(), v12.len()), (states.len(), states.len()));
    for (i, s) in states.iter().enumerate() {
        assert_eq!(hex(&feedback::format_v9(s)), v9[i][1], "state {i}, protocol 9");
        assert_eq!(hex(&feedback::format_v12(s)), v12[i][1], "state {i}, protocol 12");
    }
}

#[test]
fn button_events_match_chiaki_ng() {
    let cases = oracle("button");
    assert_eq!(cases.len(), 19 * 3);
    for c in cases {
        let (bit, level): (u32, u8) = (c[0].parse().unwrap(), c[1].parse().unwrap());
        let got = HistoryEvent::button(1 << bit, level).map_or_else(|| "invalid".to_string(), |e| hex(e.bytes()));
        assert_eq!(got, c[2], "button bit {bit} at {level}");
    }
    assert_eq!(HistoryEvent::button(button::CROSS | button::MOON, 0xff), None, "one button at a time");
}

#[test]
fn touchpad_events_match_chiaki_ng() {
    for c in oracle("touch") {
        let e =
            HistoryEvent::touchpad(c[0] == "1", c[1].parse().unwrap(), c[2].parse().unwrap(), c[3].parse().unwrap());
        assert_eq!(hex(e.bytes()), c[4], "{c:?}");
    }
}

/// The packets `record_state` produces, formatted after each event as chiaki-ng's sender does.
fn record(prev: &ControllerState, now: &ControllerState) -> Vec<String> {
    let mut history = HistoryBuffer::new(0x10);
    let mut packets = Vec::new();
    history.record_state(prev, now, |h| packets.push(hex(&h.format())));
    packets
}

fn with_buttons(b: u32) -> ControllerState {
    ControllerState { buttons: b, ..Default::default() }
}

#[test]
fn recorded_histories_match_chiaki_ng() {
    let idle = ControllerState::default();
    let mut cases: Vec<(&str, ControllerState, ControllerState)> = Vec::new();
    let three = with_buttons(button::CROSS | button::DPAD_DOWN | button::PS);
    cases.push(("press_three", idle, three));
    cases.push(("release_three", three, idle));
    cases.push(("swap", three, with_buttons(button::CROSS | button::R3)));
    let triggers = ControllerState { l2_state: 0x40, r2_state: 0xff, ..idle };
    cases.push(("triggers", idle, triggers));
    cases.push(("l2_moves", triggers, ControllerState { l2_state: 0x80, ..triggers }));
    let mut two = idle;
    two.start_touch(100, 200);
    two.start_touch(1800, 900);
    cases.push(("two_fingers_down", idle, two));
    let mut moved = two;
    moved.set_touch_pos(1, 1700, 800);
    cases.push(("finger_moves", two, moved));
    let mut replaced = two;
    replaced.stop_touch(0);
    replaced.start_touch(5, 6);
    cases.push(("finger_replaced", two, replaced));
    cases.push(("twelve_at_once", idle, with_buttons((1 << 12) - 1)));
    let mut tap = with_buttons(button::TOUCHPAD);
    tap.start_touch(100, 200);
    cases.push(("tap_down", idle, tap));
    cases.push(("tap_up", tap, idle));

    let expected = oracle("record");
    assert_eq!(expected.len(), cases.len());
    for ((name, prev, now), want) in cases.iter().zip(&expected) {
        assert_eq!(want[0], *name);
        assert_eq!(record(prev, now), want[1..], "{name}");
    }
}

// chiaki-ng test/feedback.c

#[test]
fn touchpad_click_release_before_touch_up() {
    // A tap releases click and finger in the same change; a console seeing the finger lift while the
    // click is still down keeps the finger down.
    let mut prev = ControllerState::default();
    prev.start_touch(100, 200);
    prev.buttons |= button::TOUCHPAD;
    let packets = record(&prev, &ControllerState::default());
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0], "8091", "click up");
    assert_eq!(packets[1].len(), (5 + 2) * 2);
    assert!(packets[1].starts_with("c0"), "then touch up");
}

#[test]
fn touchpad_touch_down_before_click_press() {
    let mut now = ControllerState::default();
    now.start_touch(100, 200);
    now.buttons |= button::TOUCHPAD;
    let packets = record(&ControllerState::default(), &now);
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].len(), 5 * 2);
    assert!(packets[0].starts_with("d0"), "touch down");
    assert_eq!(packets[1].len(), (2 + 5) * 2);
    assert!(packets[1].starts_with("80b1"), "then click press");
}

#[test]
fn simultaneous_l2_r2_one_packet_each() {
    // The console applies only the newest event of a packet, so L2 sharing a packet with R2 got lost.
    let now = ControllerState { l2_state: 0xff, r2_state: 0xff, ..Default::default() };
    let packets = record(&ControllerState::default(), &now);
    assert_eq!(packets, ["8086ff", "8087ff8086ff"]);
}

#[test]
fn no_change_no_packet() {
    let idle = ControllerState::default();
    let mut history = HistoryBuffer::new(0x10);
    assert!(!history.record_state(&idle, &idle, |_| panic!("nothing to push")));
}

// The ring buffer and the controller state.

#[test]
fn the_history_ring_keeps_the_newest_events() {
    let mut h = HistoryBuffer::new(3);
    for b in [button::CROSS, button::MOON, button::BOX, button::PYRAMID] {
        h.push(HistoryEvent::button(b, 0xff).unwrap());
    }
    assert_eq!(h.len(), 3);
    assert_eq!(hex(&h.format()), "808bff808aff8089ff", "newest first, the oldest gone");
    h.truncate(1);
    assert_eq!(hex(&h.format()), "808bff");
}

#[test]
fn touch_ids_count_up_and_wrap_at_128() {
    let mut s = ControllerState::default();
    assert_eq!(s.start_touch(1, 2), Some(0));
    assert_eq!(s.start_touch(3, 4), Some(1));
    assert_eq!(s.start_touch(5, 6), None, "two fingers at most");
    s.stop_touch(0);
    s.touch_id_next = 0x7f;
    assert_eq!(s.start_touch(7, 8), Some(0x7f));
    assert_eq!(s.touch_id_next, 0);
    s.set_touch_pos(0xff, 9, 10);
    assert_eq!(s.touches[0], Touch { x: 9, y: 10, id: Some(0x7f) }, "the id is masked to 7 bits");
}

#[test]
fn equality_ignores_free_slots_and_tiny_motion() {
    let a = ControllerState::default();
    let mut b = a;
    b.touches[1].x = 500; // a free slot's position
    b.gyro_x = 0.000_000_01;
    assert!(a.equals(&b));
    b.gyro_x = 0.001;
    assert!(!a.equals(&b));
    let mut c = a;
    c.l2_state = 1;
    assert!(!a.equals(&c));
    assert!(a.same_sticks_and_motion(&c), "triggers are not in a state packet");
}

#[test]
fn or_joins_two_controllers() {
    let mut a =
        ControllerState { buttons: button::CROSS, l2_state: 10, left_x: -300, right_y: 5, ..Default::default() };
    a.start_touch(1, 1);
    let mut b = ControllerState { buttons: button::MOON, l2_state: 20, left_x: 200, right_y: -6, ..Default::default() };
    b.start_touch(2, 2);
    b.start_touch(3, 3);
    b.gyro_x = 1.0;
    let o = ControllerState::or(&a, &b);
    assert_eq!(o.buttons, button::CROSS | button::MOON);
    assert_eq!((o.l2_state, o.left_x, o.right_y), (20, -300, -6));
    assert_eq!((o.touches[0].x, o.touches[1].x), (1, 3), "a's finger first, then b's");
    assert_eq!(o.gyro_x, 1.0, "a has no motion, so b's");
    a.accel_z = 0.5;
    assert_eq!(ControllerState::or(&a, &b).gyro_x, 0.0, "a moves, so a's motion whole");
}
