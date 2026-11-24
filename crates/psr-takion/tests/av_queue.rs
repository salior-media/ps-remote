// SPDX-License-Identifier: AGPL-3.0-only
// Written from chiaki-ng `takion_handle_packet_av` and `takion_av_queue_flush_with_timeout` in
// `lib/src/takion.c` (LicenseRef-AGPL-3.0-only-OpenSSL), which have no tests of their own.

use std::time::{Duration, Instant};

use psr_takion::av_queue::{AvQueue, HEAD_TIMEOUT};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

#[test]
fn in_order_packets_come_straight_out() {
    let t = Instant::now();
    let mut q = AvQueue::new();
    assert_eq!(q.push(0, 0, 'a', t), ['a']);
    assert_eq!(q.push(1, 1, 'b', t), ['b']);
    assert_eq!(q.next_deadline(), None);
}

#[test]
fn a_late_packet_is_put_back_in_place() {
    let t = Instant::now();
    let mut q = AvQueue::new();
    q.push(10, 0, 'a', t);
    assert!(q.push(12, 2, 'c', t).is_empty());
    assert_eq!(q.push(11, 1, 'b', t + ms(5)), ['b', 'c']);
    assert_eq!(q.next_deadline(), None);
}

#[test]
fn the_window_starts_at_the_first_unit_of_the_first_frame() {
    let t = Instant::now();
    let mut q = AvQueue::new();
    // Unit 3 arrives first: units 0 to 2 (packets 7 to 9) are waited for.
    assert!(q.push(10, 3, 'd', t).is_empty());
    assert_eq!(q.push(7, 0, 'a', t), ['a']);
}

#[test]
fn a_lost_packet_is_skipped_after_the_timeout() {
    let t = Instant::now();
    let mut q = AvQueue::new();
    q.push(0, 0, 'a', t);
    assert!(q.push(2, 2, 'c', t).is_empty(), "packet 1 is missing");
    assert_eq!(q.next_deadline(), Some(t + HEAD_TIMEOUT + Duration::from_micros(1)));
    assert!(q.flush(t + HEAD_TIMEOUT).is_empty(), "chiaki-ng waits while the wait is at most the timeout");
    assert_eq!(q.flush(t + ms(17)), ['c']);
    assert_eq!(q.next_deadline(), None);
}

#[test]
fn a_skip_goes_to_the_first_packet_that_is_there_and_the_next_gap_waits_afresh() {
    let t = Instant::now();
    let mut q = AvQueue::new();
    q.push(0, 0, 'a', t);
    q.push(3, 3, 'd', t);
    q.push(5, 5, 'f', t);
    // 1 and 2 are skipped together; 4 then gets its own wait, from the moment it was found missing.
    assert_eq!(q.flush(t + ms(17)), ['d']);
    assert!(q.flush(t + ms(17) + HEAD_TIMEOUT).is_empty());
    assert_eq!(q.flush(t + ms(34)), ['f']);
}

#[test]
fn a_full_window_drops_its_oldest_slots() {
    let t = Instant::now();
    let mut q = AvQueue::new();
    q.push(0, 0, 0u16, t);
    // Packet 1 never comes. 64 packets later the window (64 slots) has to move past it.
    let mut out = Vec::new();
    for i in 2..=65u16 {
        out.extend(q.push(i, i, i, t));
    }
    assert_eq!(out, (2..=65).collect::<Vec<_>>(), "no timeout needed: the window overflowed");
}

#[test]
fn a_missing_head_moved_on_by_an_overflow_keeps_the_time_already_waited() {
    let t = Instant::now();
    let mut q = AvQueue::new();
    q.push(0, 0, 0u16, t);
    // 1 and 2 never come. Waiting for 1 starts at t.
    for i in 3..=64u16 {
        assert!(q.push(i, i, i, t).is_empty());
    }
    // 65 overflows the window past 1, onto 2, which is missing too: still the same burst of loss.
    assert!(q.push(65, 65, 65, t + ms(10)).is_empty());
    assert_eq!(q.flush(t + ms(17)), (3..=65).collect::<Vec<_>>(), "timed from t, not from t + 10 ms");
}

#[test]
fn flush_on_an_empty_queue_does_nothing() {
    let mut q: AvQueue<u8> = AvQueue::new();
    assert!(q.flush(Instant::now()).is_empty());
}
