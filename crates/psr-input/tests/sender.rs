// SPDX-License-Identifier: AGPL-3.0-only
// Written from chiaki-ng `lib/src/feedbacksender.c` (LicenseRef-AGPL-3.0-only-OpenSSL), which has no tests
// of its own. The time is passed in, so each timing is checked exactly.

use std::time::{Duration, Instant};

use psr_input::controller::{ControllerState, button};
use psr_input::sender::{Feedback, FeedbackSender, STATE_INTERVAL_MAX};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn pressed(b: u32) -> ControllerState {
    ControllerState { buttons: b, ..Default::default() }
}

fn history(f: &Feedback) -> Option<(u16, u8, &[u8])> {
    match f {
        Feedback::History { seq_num, event_count, events } => Some((*seq_num, *event_count, events)),
        Feedback::State { .. } => None,
    }
}

#[test]
fn a_button_press_is_one_history_packet_and_no_state_packet() {
    let t = Instant::now();
    let mut s = FeedbackSender::new(t);
    assert!(s.poll(t).is_empty());
    s.set_controller_state(&pressed(button::DPAD_DOWN));
    let out = s.poll(t);
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(history(&out[0]), Some((0, 1, &[0x80, 0x81, 0xff][..])));
    s.set_controller_state(&ControllerState::default());
    let out = s.poll(t + ms(1));
    assert_eq!(history(&out[0]), Some((1, 2, &[0x80, 0x81, 0x00, 0x80, 0x81, 0xff][..])), "the press repeated");
}

#[test]
fn the_same_state_again_sends_nothing() {
    let t = Instant::now();
    let mut s = FeedbackSender::new(t);
    s.set_controller_state(&pressed(button::CROSS));
    s.poll(t);
    s.set_controller_state(&pressed(button::CROSS));
    assert_eq!(s.next_deadline(), t + ms(20), "nothing new to send: the next thing due is the first repeat");
    assert!(s.poll(t + ms(1)).is_empty());
}

#[test]
fn a_state_packet_is_compared_with_the_last_one_sent() {
    let t = Instant::now();
    let mut s = FeedbackSender::new(t);
    let moved = ControllerState { left_x: 1000, ..Default::default() };
    s.set_controller_state(&moved);
    assert_eq!(s.poll(t).len(), 1);
    // The same sticks with a button pressed: only the history packet goes out.
    s.set_controller_state(&ControllerState { buttons: button::CROSS, ..moved });
    let out = s.poll(t + ms(1));
    assert!(matches!(out[..], [Feedback::History { .. }]), "{out:?}");
}

#[test]
fn the_last_history_packet_is_repeated_at_20_50_100_and_200_ms() {
    let t = Instant::now();
    let mut s = FeedbackSender::new(t);
    s.set_controller_state(&pressed(button::CROSS));
    let first = s.poll(t);
    let mut repeats = Vec::new();
    for at in [19, 20, 49, 50, 99, 100, 199, 200, 1000] {
        let out: Vec<_> = s.poll(t + ms(at)).into_iter().filter(|f| history(f).is_some()).collect();
        if !out.is_empty() {
            assert_eq!(out, first, "the same packet, the same number");
            repeats.push(at);
        }
    }
    assert_eq!(repeats, [20, 50, 100, 200]);
}

#[test]
fn a_new_event_restarts_the_repeats() {
    let t = Instant::now();
    let mut s = FeedbackSender::new(t);
    s.set_controller_state(&pressed(button::CROSS));
    s.poll(t);
    s.poll(t + ms(20));
    s.set_controller_state(&ControllerState::default());
    assert_eq!(history(&s.poll(t + ms(30))[0]).unwrap().0, 1);
    assert_eq!(s.next_deadline(), t + ms(50), "20 ms after the new packet");
    assert!(s.poll(t + ms(49)).is_empty());
    assert_eq!(history(&s.poll(t + ms(50))[0]).unwrap().0, 1);
}

#[test]
fn a_state_packet_goes_out_every_200_ms_and_when_the_sticks_move() {
    let t = Instant::now();
    let mut s = FeedbackSender::new(t);
    assert_eq!(s.next_deadline(), t + STATE_INTERVAL_MAX);
    assert!(s.poll(t + ms(199)).is_empty());
    let out = s.poll(t + ms(200));
    assert!(matches!(out[..], [Feedback::State { seq_num: 0, .. }]), "{out:?}");
    let moved = ControllerState { left_x: 1000, ..Default::default() };
    s.set_controller_state(&moved);
    let out = s.poll(t + ms(210));
    let [Feedback::State { seq_num: 1, state }] = &out[..] else { panic!("{out:?}") };
    assert_eq!(state.left_x, 1000);
    assert_eq!(s.next_deadline(), t + ms(410));
}

#[test]
fn a_change_to_buttons_only_holds_back_a_due_state_packet() {
    // chiaki-ng: a changed state with the same sticks and motion sends no state packet, even when 200 ms
    // have passed; the next round sends it.
    let t = Instant::now();
    let mut s = FeedbackSender::new(t);
    s.set_controller_state(&pressed(button::CROSS));
    let out = s.poll(t + ms(250));
    assert_eq!(out.len(), 2, "{out:?}");
    assert!(history(&out[0]).is_some(), "the press first");
    assert!(matches!(out[1], Feedback::State { seq_num: 0, .. }), "then the overdue state, in the next round");
}

#[test]
fn every_event_gets_a_packet_and_packets_repeat_at_most_nine_events() {
    let t = Instant::now();
    let mut s = FeedbackSender::new(t);
    s.set_controller_state(&pressed((1 << 12) - 1));
    let out = s.poll(t);
    let counts: Vec<(u16, u8)> = out.iter().filter_map(history).map(|(n, c, _)| (n, c)).collect();
    assert_eq!(counts, (0..12).map(|i| (i, (i + 1).min(9) as u8)).collect::<Vec<_>>());
}

#[test]
fn a_full_queue_drops_its_oldest_packets_and_keeps_the_numbering() {
    let t = Instant::now();
    let mut s = FeedbackSender::new(t);
    // 40 rounds of all 16 buttons down then up: 1280 events without a poll.
    for _ in 0..40 {
        s.set_controller_state(&pressed(0xffff));
        s.set_controller_state(&ControllerState::default());
    }
    assert_eq!(s.queue_overflows(), 1280 - 64);
    let numbers: Vec<u16> = s.poll(t).iter().filter_map(history).map(|(n, ..)| n).collect();
    assert_eq!(numbers, (1280 - 64..1280).collect::<Vec<u16>>());
}
