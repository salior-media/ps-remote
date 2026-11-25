// SPDX-License-Identifier: AGPL-3.0-only
// `psr_lan::udp`: waiting a while for a datagram without leaving a receive to time out (docs/PSN.md, step
// 9c-2). The regression test for the loss it fixes is psr-psn's `only_a_request_makes_a_derived_candidate`,
// which failed 9 runs in 20 with receive timeouts and none in 20 with this.

use std::net::{Ipv4Addr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use psr_lan::udp;

fn pair() -> (UdpSocket, UdpSocket) {
    let a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    b.connect(a.local_addr().unwrap()).unwrap();
    a.connect(b.local_addr().unwrap()).unwrap();
    (a, b)
}

#[test]
fn nothing_is_none_after_the_wait_and_not_before() {
    let (a, _b) = pair();
    let begun = Instant::now();
    assert!(udp::recv_within(&a, &mut [0u8; 16], Duration::from_millis(120)).unwrap().is_none());
    let took = begun.elapsed();
    assert!(took >= Duration::from_millis(120) && took < Duration::from_millis(400), "{took:?}");
    // A zero wait only looks.
    let begun = Instant::now();
    assert!(udp::recv_within(&a, &mut [0u8; 16], Duration::ZERO).unwrap().is_none());
    assert!(begun.elapsed() < Duration::from_millis(50));
}

#[test]
fn a_datagram_is_received_with_its_sender_and_the_socket_stays_blocking() {
    let (a, b) = pair();
    let t = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        b.send(b"hello").unwrap();
        b
    });
    let mut buf = [0u8; 16];
    let (n, from) = udp::recv_from_within(&a, &mut buf, Duration::from_secs(2)).unwrap().unwrap();
    let b = t.join().unwrap();
    assert_eq!((&buf[..n], from), (&b"hello"[..], b.local_addr().unwrap()));
    // Left as it was found: a plain receive with a timeout still waits rather than failing at once.
    a.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let begun = Instant::now();
    assert!(a.recv(&mut buf).is_err());
    assert!(begun.elapsed() >= Duration::from_millis(90), "{:?}", begun.elapsed());
}

#[test]
fn many_in_a_row_all_arrive() {
    const N: u32 = 5000;
    let (a, b) = pair();
    let t = thread::spawn(move || {
        for i in 0..N {
            b.send(&i.to_be_bytes()).unwrap();
            if i % 64 == 0 {
                thread::sleep(Duration::from_millis(1));
            }
        }
    });
    let mut seen = 0;
    let mut buf = [0u8; 16];
    let begun = Instant::now();
    while let Some(4) = udp::recv_within(&a, &mut buf, Duration::from_millis(500)).unwrap() {
        seen += 1;
    }
    t.join().unwrap();
    println!("{seen} of {N} in {:?}", begun.elapsed());
    assert_eq!(seen, N);
}
