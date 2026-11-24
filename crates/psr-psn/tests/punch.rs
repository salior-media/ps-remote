// SPDX-License-Identifier: AGPL-3.0-only
// Written from chiaki-ng `holepunch_session_create_offer`, `send_accept`, `session_message_serialize`, the
// `session_*_fmt` templates, `check_candidates`, `send_response_ps` and `receive_request_send_response_ps` in
// `lib/src/remote/holepunch.c` (LicenseRef-AGPL-3.0-only-OpenSSL). The UDP exchange runs on loopback against a
// stand-in console; nothing here talks to PSN or a console.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use psr_psn::holepunch::{self, Action, Candidate, CandidateKind};
use psr_psn::punch::{self, Ids, MSG_REQ, MSG_RESP, PACKET_LEN};

const OURS: Ids = Ids { sid: 0x0102_0304, hashed_id: [0x11; 20] };
const CONSOLE: Ids = Ids { sid: 0x0a0b_0c0d, hashed_id: [0x22; 20] };

fn v4(s: &str) -> SocketAddrV4 {
    s.parse().unwrap()
}

fn cand(kind: CandidateKind, addr: &str, port: u16) -> Candidate {
    Candidate { kind, addr: addr.parse().unwrap(), addr_mapped: "0.0.0.0".parse().unwrap(), port, port_mapped: 0 }
}

#[test]
fn the_request_is_chiaki_ngs_layout() {
    let p = punch::request_packet(&OURS, &CONSOLE, &[1, 2, 3, 4, 5]);
    let mut want = [0u8; PACKET_LEN];
    want[0..4].copy_from_slice(&[0x06, 0, 0, 0]);
    want[0x04..0x18].fill(0x11);
    want[0x24..0x38].fill(0x22);
    want[0x44..0x48].copy_from_slice(&[0x03, 0x04, 0x0c, 0x0d]);
    want[0x4b..0x50].copy_from_slice(&[1, 2, 3, 4, 5]);
    assert_eq!(p, want);
    assert_eq!(punch::packet_type(&p), Some(MSG_REQ));
    assert_eq!(punch::packet_type(&p[..87]), None);
}

#[test]
fn the_response_echoes_the_request_and_carries_the_address_xored() {
    let mut req = [0u8; PACKET_LEN];
    req[0x4b..0x50].copy_from_slice(&[9, 8, 7, 6, 5]);
    let p = punch::response_packet(&OURS, &CONSOLE, &req, v4("192.168.1.20:9303"));
    assert_eq!(&p[0..4], &[0x07, 0, 0, 0]);
    assert_eq!(&p[0x04..0x18], &[0x11; 20]);
    assert_eq!(&p[0x24..0x38], &[0x22; 20]);
    assert_eq!(&p[0x4b..0x50], &[9, 8, 7, 6, 5]);
    // chiaki-ng: htons(sid_local), htons(sid_console), htons(sid_local), XORed with the four address bytes and
    // then the two port bytes. 9303 = 0x2457.
    assert_eq!(&p[0x50..0x56], &[0x03 ^ 192, 0x04 ^ 168, 0x0c ^ 1, 0x0d ^ 20, 0x03 ^ 0x24, 0x04 ^ 0x57]);
    assert!(p[0x56..].iter().all(|&b| b == 0) && p[0x48..0x4b].iter().all(|&b| b == 0));
    assert_eq!(punch::packet_type(&p), Some(MSG_RESP));
}

#[test]
fn our_offer_is_chiaki_ngs_template() {
    let (candidates, _) = punch::our_candidates(v4("192.168.1.20:50000"), v4("203.0.113.5:61000"));
    let body = punch::offer_message(2, &OURS, 0, 1234567890123, &candidates);
    // session_message_fmt around session_connrequest_fmt, filled in by hand, once unescaped.
    let want = concat!(
        r#"{"action":"OFFER","reqId":2,"error":0,"connRequest":{"sid":16909060,"peerSid":0,"#,
        r#""skey":"AAAAAAAAAAAAAAAAAAAAAA==","natType":2,"candidate":["#,
        r#"{"type":"STUN","addr":"203.0.113.5","mappedAddr":"0.0.0.0","port":61000,"mappedPort":0},"#,
        r#"{"type":"STATIC","addr":"203.0.113.5","mappedAddr":"0.0.0.0","port":50000,"mappedPort":0},"#,
        r#"{"type":"LOCAL","addr":"192.168.1.20","mappedAddr":"0.0.0.0","port":50000,"mappedPort":0}],"#,
        r#""defaultRouteMacAddr":"","localPeerAddr":{"accountId":"1234567890123","platform":"REMOTE_PLAY"},"#,
        r#""localHashedId":"ERERERERERERERERERERERERERE="}}"#
    );
    assert_eq!(body, want);
    // It is what our own reader of the console's messages reads back, fields and all.
    let m = holepunch::parse_message(&serde_json::from_str(&body).unwrap()).unwrap();
    assert_eq!((m.action, m.req_id), (Action::Offer, 2));
    let r = m.conn_request.unwrap();
    assert_eq!((r.sid, r.nat_type, r.local_hashed_id, r.candidates), (OURS.sid, 2, OURS.hashed_id, candidates));
}

#[test]
fn sids_are_written_as_chiaki_ngs_percent_d_writes_them() {
    let body = punch::offer_message(5, &OURS, 0xffff_fffe, 1, &[]);
    assert!(body.contains(r#""peerSid":-2,"#), "{body}");
    for _ in 0..64 {
        let ids = Ids::random().unwrap();
        assert!(ids.sid >= 1 && ids.sid <= i32::MAX as u32, "our own sid is never written negative");
    }
}

#[test]
fn our_accept_carries_the_candidate_and_no_hashed_id() {
    let selected = Candidate {
        kind: CandidateKind::Local,
        addr: "192.168.1.30".parse().unwrap(),
        addr_mapped: "192.168.1.20".parse().unwrap(),
        port: 9296,
        port_mapped: 50000,
    };
    let body = punch::accept_message(3, &OURS, CONSOLE.sid, 7, &selected);
    let want = concat!(
        r#"{"action":"ACCEPT","reqId":3,"error":0,"connRequest":{"sid":16909060,"peerSid":168496141,"#,
        r#""skey":"AAAAAAAAAAAAAAAAAAAAAA==","natType":0,"candidate":["#,
        r#"{"type":"LOCAL","addr":"192.168.1.30","mappedAddr":"192.168.1.20","port":9296,"mappedPort":50000}],"#,
        r#""defaultRouteMacAddr":"","localPeerAddr":{"accountId":"7","platform":"REMOTE_PLAY"},"localHashedId":""}}"#
    );
    assert_eq!(body, want);
}

#[test]
fn our_candidates_are_chiaki_ngs_in_its_order() {
    let local = v4("192.168.1.20:50000");
    let (offer, ours) = punch::our_candidates(local, v4("203.0.113.5:61000"));
    let kinds: Vec<_> = offer.iter().map(|c| c.kind).collect();
    assert_eq!(kinds, [CandidateKind::Stun, CandidateKind::Static, CandidateKind::Local]);
    assert_eq!((ours[0].kind, ours[1].kind), (CandidateKind::Local, CandidateKind::Stun));
    // When the NAT kept our port, the STUN candidate would repeat STATIC, so it is left out.
    let (offer, ours) = punch::our_candidates(local, v4("203.0.113.5:50000"));
    assert_eq!(
        offer,
        [cand(CandidateKind::Static, "203.0.113.5", 50000), cand(CandidateKind::Local, "192.168.1.20", 50000)]
    );
    assert_eq!(ours[1].kind, CandidateKind::Static);
}

#[test]
fn the_accepted_candidate_names_which_of_ours_it_reached() {
    let (_, ours) = punch::our_candidates(v4("192.168.1.20:50000"), v4("203.0.113.5:61000"));
    let via = |c: Candidate| {
        let m = punch::mapped(&c, &ours);
        (m.addr_mapped.to_string(), m.port_mapped)
    };
    let lan = ("192.168.1.20".to_string(), 50000);
    let wan = ("203.0.113.5".to_string(), 61000);
    assert_eq!(via(cand(CandidateKind::Local, "192.168.1.30", 9296)), lan);
    assert_eq!(via(cand(CandidateKind::Static, "198.51.100.2", 9296)), wan);
    assert_eq!(via(cand(CandidateKind::Derived, "10.0.0.7", 9296)), lan, "a derived private address is local");
    assert_eq!(via(cand(CandidateKind::Derived, "172.20.0.7", 9296)), lan);
    assert_eq!(via(cand(CandidateKind::Derived, "172.32.0.7", 9296)), wan, "172.32 is not private");
    assert_eq!(via(cand(CandidateKind::Derived, "198.51.100.2", 9296)), wan);
}

fn bind() -> (UdpSocket, SocketAddrV4) {
    let s = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let SocketAddr::V4(a) = s.local_addr().unwrap() else { unreachable!() };
    (s, a)
}

fn recv(s: &UdpSocket) -> ([u8; PACKET_LEN], SocketAddrV4) {
    let mut buf = [0u8; 256];
    let (n, from) = s.recv_from(&mut buf).unwrap();
    let SocketAddr::V4(from) = from else { unreachable!() };
    (buf[..n].try_into().expect("an 88-byte datagram"), from)
}

/// A response to `req` as the console would send it: its IDs first, then ours.
fn console_response(req: &[u8; PACKET_LEN]) -> [u8; PACKET_LEN] {
    let mut r = punch::response_packet(&CONSOLE, &OURS, req, v4("127.0.0.1:1"));
    r[0x4b..0x50].copy_from_slice(&req[0x4b..0x50]);
    r
}

#[test]
fn the_candidate_that_answers_our_request_is_the_hole() {
    let (ours, our_addr) = bind();
    let (console, console_addr) = bind();
    let (silent, silent_addr) = bind();
    let t = thread::spawn(move || {
        let (req, from) = recv(&console);
        assert_eq!((punch::packet_type(&req), from), (Some(MSG_REQ), our_addr));
        assert_eq!(&req[0x04..0x18], &OURS.hashed_id);
        // Junk, a response to some other request, and a datagram of the wrong size: all passed over.
        console.send_to(b"junk", our_addr).unwrap();
        let mut stray = console_response(&req);
        stray[0x4b] ^= 0xff;
        console.send_to(&stray, our_addr).unwrap();
        console.send_to(&console_response(&req)[..87], our_addr).unwrap();
        // The console's own request is answered, and the answer carries the address it was sent to.
        console.send_to(&punch::request_packet(&CONSOLE, &OURS, &[7; 5]), our_addr).unwrap();
        let (resp, _) = recv(&console);
        assert_eq!(punch::packet_type(&resp), Some(MSG_RESP));
        assert_eq!(
            resp,
            punch::response_packet(&OURS, &CONSOLE, &punch::request_packet(&CONSOLE, &OURS, &[7; 5]), console_addr)
        );
        console.send_to(&console_response(&req), our_addr).unwrap();
        drop(silent);
    });
    let offered = [
        cand(CandidateKind::Static, "127.0.0.1", silent_addr.port()),
        cand(CandidateKind::Local, "127.0.0.1", console_addr.port()),
    ];
    let (found, responded) = punch::check_candidates(&ours, &OURS, &CONSOLE, &offered).unwrap();
    t.join().unwrap();
    assert_eq!(
        (found.addr, found.candidate.kind, responded, found.ids_mirrored),
        (console_addr, CandidateKind::Local, true, true)
    );
    // The socket is now connected: it reaches the console without an address.
    ours.send(b"x").unwrap();
}

#[test]
fn an_answer_from_an_address_not_offered_is_a_derived_candidate() {
    let (ours, our_addr) = bind();
    let (offered_sock, offered_addr) = bind();
    let (actual, actual_addr) = bind();
    let t = thread::spawn(move || {
        let (req, _) = recv(&offered_sock);
        // The console's NAT shows another port: its request comes from there, and so does its answer.
        actual.send_to(&punch::request_packet(&CONSOLE, &OURS, &[3; 5]), our_addr).unwrap();
        let (first, _) = recv(&actual);
        assert_eq!(punch::packet_type(&first), Some(MSG_RESP));
        let (again, _) = recv(&actual);
        assert_eq!(again, req, "our request goes to the new address too");
        actual.send_to(&console_response(&req), our_addr).unwrap();
    });
    let (found, _) = punch::check_candidates(
        &ours,
        &OURS,
        &CONSOLE,
        &[cand(CandidateKind::Static, "127.0.0.1", offered_addr.port())],
    )
    .unwrap();
    t.join().unwrap();
    assert_eq!((found.addr, found.candidate.kind), (actual_addr, CandidateKind::Derived));
    assert_eq!(found.candidate.addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
}

#[test]
fn no_more_than_three_addresses_are_taken_on_as_derived() {
    let (ours, our_addr) = bind();
    let (offered_sock, offered_addr) = bind();
    let t = thread::spawn(move || {
        let (req, _) = recv(&offered_sock);
        let strangers: Vec<_> = (0..5).map(|_| bind()).collect();
        for (s, _) in &strangers {
            s.send_to(&punch::request_packet(&CONSOLE, &OURS, &[1; 5]), our_addr).unwrap();
        }
        let answered = strangers.iter().filter(|(s, _)| {
            s.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
            let mut b = [0u8; 256];
            s.recv_from(&mut b).is_ok()
        });
        let n = answered.count();
        offered_sock.send_to(&console_response(&req), our_addr).unwrap();
        n
    });
    punch::check_candidates(&ours, &OURS, &CONSOLE, &[cand(CandidateKind::Static, "127.0.0.1", offered_addr.port())])
        .unwrap();
    assert_eq!(t.join().unwrap(), punch::EXTRA_CANDIDATES);
}

#[test]
fn after_the_hole_the_consoles_requests_are_answered_but_not_forever() {
    let (ours, _) = bind();
    let (console, console_addr) = bind();
    ours.connect(console_addr).unwrap();
    let our_addr = ours.local_addr().unwrap();
    let flood = thread::spawn(move || {
        let req = punch::request_packet(&CONSOLE, &OURS, &[5; 5]);
        let until = Instant::now() + Duration::from_secs(4);
        while Instant::now() < until {
            let _ = console.send_to(&req, our_addr);
            thread::sleep(Duration::from_millis(5));
        }
    });
    let started = Instant::now();
    assert!(punch::answer_requests(&ours, &OURS, &CONSOLE, console_addr).unwrap());
    assert!(started.elapsed() < Duration::from_secs(3), "stopped after ANSWER_MAX, not when the flood ended");
    flood.join().unwrap();
    // And with nothing to answer, it waits ANSWER_TIMEOUT and says none came.
    let (quiet, quiet_addr) = bind();
    let (lonely, _) = bind();
    lonely.connect(quiet_addr).unwrap();
    assert!(!punch::answer_requests(&lonely, &OURS, &CONSOLE, quiet_addr).unwrap());
    drop(quiet);
}

#[test]
fn an_address_at_an_ip_not_offered_is_passed_over() {
    let (ours, our_addr) = bind();
    let (offered_sock, offered_addr) = bind();
    // Another loopback address stands for another host.
    let stranger = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).unwrap();
    stranger.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let t = thread::spawn(move || {
        let (req, _) = recv(&offered_sock);
        stranger.send_to(&punch::request_packet(&CONSOLE, &OURS, &[1; 5]), our_addr).unwrap();
        let mut b = [0u8; 256];
        let heard = stranger.recv_from(&mut b).is_ok();
        offered_sock.send_to(&console_response(&req), our_addr).unwrap();
        heard
    });
    let (found, responded) = punch::check_candidates(
        &ours,
        &OURS,
        &CONSOLE,
        &[cand(CandidateKind::Static, "127.0.0.1", offered_addr.port())],
    )
    .unwrap();
    assert!(!t.join().unwrap(), "the stranger got neither an answer nor our request");
    assert_eq!((found.addr, responded), (offered_addr, false));
}

#[test]
fn a_stream_of_junk_neither_holds_the_check_open_nor_stops_the_resends() {
    let (ours, our_addr) = bind();
    let (silent, silent_addr) = bind();
    let stop = Instant::now() + Duration::from_secs(15);
    let junk = thread::spawn(move || {
        let (s, _) = bind();
        while Instant::now() < stop {
            let _ = s.send_to(b"junk", our_addr);
            thread::sleep(Duration::from_millis(100));
        }
    });
    let counter = thread::spawn(move || {
        silent.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut b = [0u8; 256];
        let mut n = 0;
        while silent.recv_from(&mut b).is_ok() {
            n += 1;
        }
        n
    });
    let started = Instant::now();
    let r = punch::check_candidates(&ours, &OURS, &CONSOLE, &[cand(CandidateKind::Static, "127.0.0.1", silent_addr.port())]);
    let took = started.elapsed();
    assert!(matches!(r, Err(psr_psn::PsnError::Timeout(_))), "{r:?}");
    assert!(took < Duration::from_secs(12), "took {took:?}");
    assert!(counter.join().unwrap() > punch::SELECT_TRIES as usize / 2, "the resends kept going");
    junk.join().unwrap();
}

#[test]
fn after_the_hole_a_stream_of_other_datagrams_ends_too() {
    let (ours, _) = bind();
    let (console, console_addr) = bind();
    ours.connect(console_addr).unwrap();
    let our_addr = ours.local_addr().unwrap();
    let flood = thread::spawn(move || {
        let not_a_request = punch::response_packet(&CONSOLE, &OURS, &[0; PACKET_LEN], v4("127.0.0.1:1"));
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            let _ = console.send_to(&not_a_request, our_addr);
            thread::sleep(Duration::from_millis(50));
        }
    });
    let started = Instant::now();
    assert!(!punch::answer_requests(&ours, &OURS, &CONSOLE, console_addr).unwrap());
    assert!(started.elapsed() < punch::ANSWER_TIMEOUT * 2 + Duration::from_millis(500));
    flood.join().unwrap();
}

#[test]
fn only_a_request_makes_a_derived_candidate() {
    let (ours, our_addr) = bind();
    let (offered_sock, offered_addr) = bind();
    let (other, _) = bind();
    other.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let t = thread::spawn(move || {
        let (req, _) = recv(&offered_sock);
        // A response-shaped datagram from a new port at the console's IP: not a request, so nothing back.
        other.send_to(&console_response(&[0; PACKET_LEN]), our_addr).unwrap();
        let mut b = [0u8; 256];
        let heard = other.recv_from(&mut b).is_ok();
        offered_sock.send_to(&console_response(&req), our_addr).unwrap();
        heard
    });
    let (found, _) =
        punch::check_candidates(&ours, &OURS, &CONSOLE, &[cand(CandidateKind::Static, "127.0.0.1", offered_addr.port())]).unwrap();
    assert!(!t.join().unwrap());
    assert_eq!(found.candidate.kind, CandidateKind::Static);
}

#[test]
fn a_response_must_carry_our_hashed_id() {
    let (ours, our_addr) = bind();
    let (console, console_addr) = bind();
    let t = thread::spawn(move || {
        let (req, _) = recv(&console);
        // The right request ID, but not our hashed ID: someone who saw only the request.
        let mut forged = console_response(&req);
        forged[0x24..0x38].fill(0x99);
        console.send_to(&forged, our_addr).unwrap();
        thread::sleep(Duration::from_millis(200));
        let mut real = console_response(&req);
        real[0x04..0x18].fill(0x77); // the console's own ID need not match what we were told
        console.send_to(&real, our_addr).unwrap();
    });
    let (found, _) =
        punch::check_candidates(&ours, &OURS, &CONSOLE, &[cand(CandidateKind::Local, "127.0.0.1", console_addr.port())]).unwrap();
    t.join().unwrap();
    assert!(!found.ids_mirrored, "the second, real answer was the one taken");
}

#[test]
fn debug_output_leaves_out_addresses() {
    let c = cand(CandidateKind::Static, "203.0.113.77", 9296);
    let shown = format!("{c:?}");
    assert!(!shown.contains("203.0.113.77") && !shown.contains("9296"), "{shown}");
    assert!(shown.contains("Static"));
}
