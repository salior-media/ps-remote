// SPDX-License-Identifier: AGPL-3.0-only
// Which of the account's consoles playing from away uses (chiaki-ng's holepunch takes the first with Remote
// Play on).

use psr_psn::devices::Device;
use psr_psn::play;

fn device(name: &str, remote_play: bool) -> Device {
    Device { duid: vec![0; 32], name: name.into(), remote_play }
}

#[test]
fn the_first_console_with_remote_play_on_is_the_one() {
    assert_eq!(play::chosen(&[device("a", false), device("b", true), device("c", true)]), Some(1));
    assert_eq!(play::chosen(&[device("a", false)]), None);
    assert_eq!(play::chosen(&[]), None);
}
