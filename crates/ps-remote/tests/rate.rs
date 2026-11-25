// SPDX-License-Identifier: AGPL-3.0-only
use std::time::{Duration, Instant};

use ps_remote::rate::{Rate, WINDOW};

#[test]
fn the_rate_is_the_last_whole_windows() {
    let t0 = Instant::now();
    let mut r = Rate::new(t0);
    r.add(125_000, t0 + Duration::from_millis(100));
    r.add(125_000, t0 + Duration::from_millis(900));
    assert_eq!(r.kbps(), 0, "the first window has not closed");
    // 250 kB over 1 s is 2000 kbit/s; the byte that closes the window counts towards the next.
    r.add(1, t0 + WINDOW);
    assert_eq!(r.kbps(), 2000);
    // A window with nothing in it but that one byte, then a silent one.
    r.roll(t0 + WINDOW * 2);
    assert_eq!(r.kbps(), 0);
    r.roll(t0 + WINDOW * 3);
    assert_eq!(r.kbps(), 0);
}
