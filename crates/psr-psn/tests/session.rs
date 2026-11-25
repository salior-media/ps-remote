// SPDX-License-Identifier: AGPL-3.0-only
// The session request and ctrl over RUDP against a stand-in console on loopback, which does what the console
// must: answer the session request with a nonce, read RP-Auth with the cipher that nonce makes, send its
// session ID, read our feature messages at the counters chiaki-ng uses over RUDP, and ask for a heartbeat.
// Written from chiaki-ng `lib/src/session.c` and `lib/src/ctrl.c` (LicenseRef-AGPL-3.0-only-OpenSSL).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use psr_crypto::Target;
use psr_crypto::rpcrypt::RpCrypt;
use psr_lan::ctrl::{CtrlCipher, CtrlEvent, MessageType};
use psr_lan::regist::RegisteredHost;
use psr_lan::session::Codec;
use psr_psn::rudp::{self, Message, Rudp};
use psr_psn::session;

const NONCE: [u8; 16] = [0x4E; 16];
const RP_KEY: [u8; 16] = [0x52; 16];
const REGIST_KEY: [u8; 16] = *b"0123abcd\0\0\0\0\0\0\0\0";
const SESSION_ID: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Zz";

fn host() -> RegisteredHost {
    RegisteredHost {
        target: Target::Ps5V1,
        ap_ssid: None,
        ap_bssid: None,
        ap_key: None,
        ap_name: None,
        server_mac: [1, 2, 3, 4, 5, 6],
        server_nickname: None,
        rp_regist_key: REGIST_KEY,
        rp_key_type: 0,
        rp_key: RP_KEY,
    }
}

fn recv(sock: &UdpSocket) -> (Vec<Message>, SocketAddr) {
    let mut buf = [0u8; 4096];
    let (n, from) = sock.recv_from(&mut buf).unwrap();
    (rudp::parse(&buf[..n]), from)
}

/// Receives until a message of `kind` comes, passing over our ACKs and resends.
fn expect(sock: &UdpSocket, kind: u16) -> (Vec<Message>, SocketAddr) {
    loop {
        let (m, from) = recv(sock);
        if m.first().is_some_and(|m| m.kind == kind) {
            return (m, from);
        }
    }
}

fn handshake(sock: &UdpSocket) -> SocketAddr {
    let (_, client) = expect(sock, rudp::INIT_REQUEST);
    sock.send_to(&rudp::serialize(&[(rudp::INIT_RESPONSE, &[0; 12])]), client).unwrap();
    expect(sock, rudp::COOKIE_REQUEST);
    sock.send_to(&rudp::serialize(&[(rudp::COOKIE_RESPONSE, &[0x00, 0x07])]), client).unwrap();
    client
}

/// A request's text, from a SESSION_MESSAGE and its chained CTRL_MESSAGE.
fn request(sock: &UdpSocket) -> String {
    let (m, _) = expect(sock, rudp::SESSION_MESSAGE);
    String::from_utf8(m[1].data[2..].to_vec()).unwrap()
}

fn answer(sock: &UdpSocket, client: SocketAddr, counter: u16, text: &[u8]) {
    let data = [&counter.to_be_bytes()[..], text].concat();
    sock.send_to(&rudp::serialize(&[(rudp::CTRL_MESSAGE, &data)]), client).unwrap();
}

fn header<'a>(request: &'a str, name: &str) -> &'a str {
    request.lines().find_map(|l| l.strip_prefix(name)).unwrap_or_else(|| panic!("no {name} in {request}"))
}

#[test]
fn the_session_and_ctrl_start_through_the_hole() {
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let console = match sock.local_addr().unwrap() {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(_) => unreachable!(),
    };
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    client.connect(console).unwrap();

    let stand_in = thread::spawn(move || {
        let crypt = RpCrypt::auth(Target::Ps5V1, &NONCE, &RP_KEY).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        // The session request names the console's end of the hole and carries the registration key's text.
        let client = handshake(&sock);
        let r = request(&sock);
        assert!(r.starts_with("GET /sie/ps5/rp/sess/init HTTP/1.1\r\n"), "{r}");
        assert_eq!(header(&r, "Host: "), format!("127.0.0.1:{}", console.port()));
        assert_eq!(header(&r, "RP-Registkey: "), "3031323361626364");
        answer(&sock, client, 0x10, format!("HTTP/1.1 200 OK\r\nRP-Nonce: {}\r\n\r\n", b64.encode(NONCE)).as_bytes());
        let (a, _) = expect(&sock, rudp::ACK);
        assert_eq!(&a[0].data[2..4], &[0x00, 0x11]);
        sock.send_to(&rudp::serialize(&[(rudp::FINISH, &[])]), client).unwrap();

        // Ctrl: its own handshake, then the request, whose RP-Auth only the nonce's cipher reads.
        let client = handshake(&sock);
        let r = request(&sock);
        assert!(r.starts_with("GET /sie/ps5/rp/sess/ctrl HTTP/1.1\r\n"), "{r}");
        assert_eq!(header(&r, "Host: "), format!("127.0.0.1:{}", console.port()));
        let auth = b64.decode(header(&r, "RP-Auth: ")).unwrap();
        assert_eq!(crypt.decrypt(0, &auth), REGIST_KEY);
        answer(&sock, client, 0x20, b"HTTP/1.1 200 OK\r\n\r\n");
        expect(&sock, rudp::ACK);

        // The console's session ID, sealed by its own counter.
        let mut ours = CtrlCipher::new(crypt.clone());
        let mut id = vec![SESSION_ID.len() as u8];
        id.extend(SESSION_ID.as_bytes());
        answer(&sock, client, 0x30, &ours.seal(MessageType::SessionId.code(), &id));

        // Three feature messages: for a PS5 over RUDP the first is at counter 6, five request fields and the
        // one chiaki-ng skips.
        let mut seen = Vec::new();
        while seen.len() < 3 {
            let (m, _) = expect(&sock, rudp::CTRL_MESSAGE);
            let counter = u16::from_be_bytes([m[0].data[0], m[0].data[1]]);
            if !seen.iter().any(|(c, _)| *c == counter) {
                seen.push((counter, m[0].data[2..].to_vec()));
            }
        }
        let mic = &seen[0].1;
        assert_eq!(u16::from_be_bytes([mic[4], mic[5]]), MessageType::MicToggle.code());
        assert_eq!(crypt.decrypt(6, &mic[8..]), [0, 1, 1, 89]);
        assert_eq!(u16::from_be_bytes([seen[2].1[4], seen[2].1[5]]), MessageType::DisplayDevices.code());

        // A heartbeat request is answered; then, unasked, again after chiaki-ng's interval.
        answer(&sock, client, 0x31, &ours.seal(MessageType::HeartbeatReq.code(), &[]));
        let mut replies = Vec::new();
        let begun = Instant::now();
        while replies.len() < 2 && begun.elapsed() < Duration::from_secs(9) {
            let (m, from) = expect(&sock, rudp::CTRL_MESSAGE);
            let counter = u16::from_be_bytes([m[0].data[0], m[0].data[1]]);
            let ty = u16::from_be_bytes([m[0].data[6], m[0].data[7]]);
            if ty == MessageType::HeartbeatRep.code() && !replies.iter().any(|(c, _)| *c == counter) {
                replies.push((counter, begun.elapsed()));
            }
            // Acknowledge it, so it is not resent: the counter after ours.
            let ack = rudp::serialize(&[(
                rudp::ACK,
                &[&[0, 0x32][..], &counter.wrapping_add(1).to_be_bytes(), &[0, 0x92]].concat(),
            )]);
            sock.send_to(&ack, from).unwrap();
        }
        replies
    });

    let mut s = session::start(Rudp::new(client).unwrap(), console, &host(), Codec::H264, &[3; 32]).unwrap();
    assert_eq!(s.session_id(), SESSION_ID);
    assert!(!s.session_id_was_fallback());
    let begun = Instant::now();
    let mut heartbeats = 0;
    while begun.elapsed() < Duration::from_secs(7) {
        heartbeats +=
            s.poll(Duration::from_millis(200)).unwrap().iter().filter(|e| **e == CtrlEvent::HeartbeatRequested).count();
    }
    assert_eq!(heartbeats, 1);
    let replies = stand_in.join().unwrap();
    assert_eq!(replies.len(), 2, "{replies:?}");
    let gap = replies[1].1 - replies[0].1;
    assert!(gap >= Duration::from_millis(4800) && gap < Duration::from_millis(5600), "{gap:?}");
}

#[test]
fn a_refused_session_request_is_reported() {
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let console: SocketAddrV4 = match sock.local_addr().unwrap() {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(_) => unreachable!(),
    };
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    client.connect(console).unwrap();
    let stand_in = thread::spawn(move || {
        let client = handshake(&sock);
        request(&sock);
        answer(&sock, client, 0x10, b"HTTP/1.1 403 Forbidden\r\nRP-Application-Reason: 0x80108b10\r\n\r\n");
        expect(&sock, rudp::ACK);
        sock.send_to(&rudp::serialize(&[(rudp::FINISH, &[])]), client).unwrap();
    });
    let e = session::start(Rudp::new(client).unwrap(), console, &host(), Codec::H264, &[3; 32]).unwrap_err();
    stand_in.join().unwrap();
    assert!(
        matches!(
            e,
            psr_psn::PsnError::Lan(psr_lan::LanError::SessionRefused { code: 403, reason: Some(0x8010_8b10), .. })
        ),
        "{e:?}"
    );
}

#[test]
fn the_data_hole_is_drained_until_quiet_or_a_second() {
    let hole = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let console = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    hole.connect(console.local_addr().unwrap()).unwrap();
    for _ in 0..3 {
        console.send_to(&[0x06; 88], hole.local_addr().unwrap()).unwrap();
    }
    let begun = Instant::now();
    assert_eq!(session::drain(&hole).unwrap(), 3);
    let took = begun.elapsed();
    // chiaki-ng's: 200 ms with nothing, a second in all.
    assert_eq!((session::DRAIN_QUIET, session::DRAIN_MAX), (Duration::from_millis(200), Duration::from_secs(1)));
    assert!(took >= session::DRAIN_QUIET && took < session::DRAIN_QUIET * 3, "{took:?}");
    // A trickle that never goes quiet is cut off at a second.
    let to = hole.local_addr().unwrap();
    let t = thread::spawn(move || {
        let end = Instant::now() + session::DRAIN_MAX * 2;
        while Instant::now() < end {
            console.send_to(&[0x06; 88], to).unwrap();
            thread::sleep(Duration::from_millis(50));
        }
    });
    let begun = Instant::now();
    assert!(session::drain(&hole).unwrap() > 5);
    let took = begun.elapsed();
    assert!(took >= session::DRAIN_MAX && took < session::DRAIN_MAX + session::DRAIN_QUIET, "{took:?}");
    t.join().unwrap();
}
