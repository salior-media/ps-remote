// SPDX-License-Identifier: AGPL-3.0-only
// RUDP's framing, checked byte for byte against chiaki-ng `lib/src/remote/rudp.c`
// (LicenseRef-AGPL-3.0-only-OpenSSL), and its exchanges against a stand-in console on loopback.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use psr_psn::PsnError;
use psr_psn::rudp::{self, Expect, Message, Rudp};

const COUNTER: u16 = 0x1234;
const HEADER: u32 = 0x8899_AABB;

#[test]
fn init_and_cookie_requests_are_chiaki_ngs_bytes() {
    let init = rudp::init_request(COUNTER, HEADER);
    #[rustfmt::skip]
    let want = [
        0xC0, 0x16, 0x24, 0x4F, 0x24, 0x4F, 0x80, 0x30, // 0xC000 | 22, the constant, INIT_REQUEST
        0x12, 0x34, 0x0B, 0x01, 0x01, 0x00, 0x01, 0x00, // counter, then chiaki-ng's six bytes
        0x88, 0x99, 0xAA, 0xBB, 0x05, 0x82,             // the header word, then two more
    ];
    assert_eq!(init, want);
    let cookie = rudp::cookie_request(COUNTER, HEADER, &[0xDE, 0xAD]);
    assert_eq!(&cookie[..2], &[0xC0, 0x18]);
    assert_eq!(&cookie[6..8], &[0x90, 0x30]);
    assert_eq!(&cookie[8..], &[&want[8..], &[0xDE, 0xAD][..]].concat()[..]);
}

#[test]
fn a_session_message_chains_the_payload_in_a_ctrl_message() {
    let m = rudp::session_message(COUNTER, 0xBEEF, b"GET");
    #[rustfmt::skip]
    let want = [
        0xC0, 0x0C, 0x24, 0x4F, 0x24, 0x4F, 0x20, 0x30, 0x12, 0x34, 0xBE, 0xEF, // SESSION_MESSAGE: ours, theirs
        0xC0, 0x0D, 0x24, 0x4F, 0x24, 0x4F, 0x02, 0x30, 0x12, 0x34, b'G', b'E', b'T', // CTRL_MESSAGE: ours, payload
    ];
    assert_eq!(m, want);
    let ack = rudp::ack(COUNTER, 0xBEEF);
    assert_eq!(ack, [0xC0, 0x0E, 0x24, 0x4F, 0x24, 0x4F, 0x24, 0x30, 0x12, 0x34, 0xBE, 0xEF, 0x00, 0x92]);
}

#[test]
fn a_chain_parses_back_and_odd_lengths_are_cut_not_trusted() {
    let m = rudp::session_message(COUNTER, 0xBEEF, b"GET");
    let parsed = rudp::parse(&m);
    assert_eq!(
        parsed,
        [
            Message { kind: rudp::SESSION_MESSAGE, data: vec![0x12, 0x34, 0xBE, 0xEF] },
            Message { kind: rudp::CTRL_MESSAGE, data: vec![0x12, 0x34, b'G', b'E', b'T'] },
        ]
    );
    // A length past the end is cut to what came; one under 8 has no data; a tail too short is ignored.
    let mut long = rudp::serialize(&[(rudp::FINISH, &[1, 2, 3])]);
    long[1] = 0xFF;
    assert_eq!(rudp::parse(&long), [Message { kind: rudp::FINISH, data: vec![1, 2, 3] }]);
    let mut short = rudp::serialize(&[(rudp::FINISH, &[])]);
    short[1] = 0x03;
    short.extend([9, 9, 9]);
    assert_eq!(rudp::parse(&short), [Message { kind: rudp::FINISH, data: vec![] }]);
    assert!(rudp::parse(&[0xC0, 0x08, 0, 0, 0, 0, 0]).is_empty());
}

#[test]
fn counters_and_subtypes_follow_chiaki_ng() {
    let m = |kind, data: &[u8]| Message { kind, data: data.to_vec() };
    assert_eq!(m(rudp::COOKIE_RESPONSE, &[0x00, 0x41]).remote_counter(), Some(0x42));
    assert_eq!(m(rudp::COOKIE_RESPONSE, &[0xFF, 0xFF]).remote_counter(), Some(0));
    assert_eq!(m(rudp::COOKIE_RESPONSE, &[0x01]).remote_counter(), None);
    for kind in [rudp::CTRL_MESSAGE, rudp::OFFSET8, rudp::OFFSET10] {
        assert!(Expect::Ctrl.matches(&m(kind, &[])), "{kind:#06x}");
    }
    for kind in [rudp::ACK, rudp::SESSION_MESSAGE, rudp::STREAM_CONNECTION_SWITCH_ACK, rudp::FINISH] {
        assert!(!Expect::Ctrl.matches(&m(kind, &[])), "{kind:#06x}");
    }
    assert!(Expect::InitResponse.matches(&m(rudp::INIT_RESPONSE, &[])));
    assert!(Expect::CookieResponse.matches(&m(rudp::COOKIE_RESPONSE, &[])));
    assert!(Expect::Finish.matches(&m(rudp::FINISH, &[])));
    assert!(!Expect::Finish.matches(&m(rudp::INIT_RESPONSE, &[])));
}

/// A client hole connected to a stand-in console, and the console's socket.
fn pair() -> (UdpSocket, UdpSocket) {
    let console = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    client.connect(console.local_addr().unwrap()).unwrap();
    console.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    (client, console)
}

fn recv(console: &UdpSocket) -> (Vec<Message>, SocketAddr) {
    let mut buf = [0u8; 1500];
    let (n, from) = console.recv_from(&mut buf).unwrap();
    (rudp::parse(&buf[..n]), from)
}

/// The console's half of the handshake, the HTTP exchange and the finish. Before each answer it sends
/// what is not one: junk, a short datagram, and the right kind too short.
fn console_side(console: UdpSocket, cookie: &'static [u8], response: &'static [u8]) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (init, client) = recv(&console);
        assert_eq!(init[0].kind, rudp::INIT_REQUEST);
        let ours = u16::from_be_bytes([init[0].data[0], init[0].data[1]]);
        console.send_to(&[0u8; 88], client).unwrap();
        console.send_to(&[0xC0], client).unwrap();
        console.send_to(&rudp::serialize(&[(rudp::INIT_RESPONSE, &[0; 7])]), client).unwrap();
        let mut init_response = vec![0u8; 8];
        init_response.extend(cookie);
        console.send_to(&rudp::serialize(&[(rudp::INIT_RESPONSE, &init_response)]), client).unwrap();

        let (c, _) = recv(&console);
        assert_eq!(c[0].kind, rudp::COOKIE_REQUEST);
        assert_eq!(&c[0].data[14..], cookie, "the cookie goes back");
        assert_eq!(u16::from_be_bytes([c[0].data[0], c[0].data[1]]), ours.wrapping_add(1), "one INIT was sent");
        console.send_to(&rudp::serialize(&[(rudp::COOKIE_RESPONSE, &[0x10, 0x00])]), client).unwrap();

        let (s, _) = recv(&console);
        assert_eq!(s[0].kind, rudp::SESSION_MESSAGE);
        assert_eq!(&s[0].data[2..4], &[0x10, 0x01], "it names the counter after the console's");
        assert_eq!(&s[1].data[2..], b"POST / HTTP/1.1\r\n\r\n");
        // The answer chained behind something else, as chiaki-ng's chain walk allows.
        let mut answer = vec![0x20, 0x00];
        answer.extend(response);
        console
            .send_to(&rudp::serialize(&[(rudp::ACK, &[0, 0, 0, 0, 0, 0]), (rudp::CTRL_MESSAGE, &answer)]), client)
            .unwrap();

        let (a, _) = recv(&console);
        assert_eq!(a[0].kind, rudp::ACK);
        assert_eq!(&a[0].data[2..4], &[0x20, 0x01]);
        console.send_to(&rudp::serialize(&[(rudp::FINISH, &[])]), client).unwrap();
    })
}

#[test]
fn the_handshake_and_an_http_exchange_pass_over_what_is_not_the_answer() {
    let (client, console) = pair();
    let t = console_side(console, b"cookie!", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let mut r = Rudp::with(client, COUNTER, HEADER);
    let mut remote = r.handshake().unwrap();
    assert_eq!(remote, 0x1001);
    let body = r.http(&mut remote, b"POST / HTTP/1.1\r\n\r\n").unwrap();
    assert_eq!(body, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    assert_eq!(remote, 0x2001);
    r.finish(remote).unwrap();
    t.join().unwrap();
}

#[test]
fn an_answer_without_a_whole_http_header_is_refused() {
    let (client, console) = pair();
    let t = console_side(console, b"c", b"HTTP/1.1 200 OK\r\n");
    let mut r = Rudp::with(client, COUNTER, HEADER);
    let mut remote = r.handshake().unwrap();
    assert!(matches!(r.http(&mut remote, b"POST / HTTP/1.1\r\n\r\n"), Err(PsnError::Rudp(_))));
    // Let the stand-in finish its script.
    r.finish(remote).unwrap();
    t.join().unwrap();
}

#[test]
fn silence_is_three_tries_of_a_second_each() {
    let (client, console) = pair();
    let mut r = Rudp::with(client, 0xFFFF, HEADER);
    let begun = Instant::now();
    assert!(matches!(r.handshake(), Err(PsnError::Timeout(_))));
    let took = begun.elapsed();
    assert!(took >= rudp::EXPECT_TIMEOUT * 3 && took < rudp::EXPECT_TIMEOUT * 5, "{took:?}");
    // Three INITs, each with the next counter (wrapping as chiaki-ng's does).
    let counters: Vec<u16> = (0..3)
        .map(|_| {
            let (m, _) = recv(&console);
            assert_eq!(m[0].kind, rudp::INIT_REQUEST);
            u16::from_be_bytes([m[0].data[0], m[0].data[1]])
        })
        .collect();
    assert_eq!(counters, [0xFFFF, 0, 1]);
    assert_eq!(r.counter(), 2);
}

#[test]
fn a_stream_of_wrong_messages_does_not_hold_a_try_open() {
    let (client, console) = pair();
    let addr = client.local_addr().unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flood = {
        let stop = stop.clone();
        thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = console.send_to(&rudp::serialize(&[(rudp::ACK, &[0; 6])]), addr);
                thread::sleep(Duration::from_millis(20));
            }
        })
    };
    let mut r = Rudp::with(client, COUNTER, HEADER);
    let begun = Instant::now();
    assert!(matches!(r.handshake(), Err(PsnError::Timeout(_))));
    assert!(begun.elapsed() < rudp::EXPECT_TIMEOUT * 5, "{:?}", begun.elapsed());
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    flood.join().unwrap();
}
