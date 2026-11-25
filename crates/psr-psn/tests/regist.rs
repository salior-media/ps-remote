// SPDX-License-Identifier: AGPL-3.0-only
// Registration over PSN against a stand-in console on loopback, which does what the console must: recover
// the ambassador from the payload's aeropause bytes, derive the cipher from the session's customData1, data1
// and data2, read the account ID, and answer with the keys encrypted the same way. Written from chiaki-ng
// `lib/src/regist.c` and `lib/src/rpcrypt.c` (LicenseRef-AGPL-3.0-only-OpenSSL).

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

use psr_crypto::Target;
use psr_crypto::rpcrypt::{self, RpCrypt};
use psr_lan::LanError;
use psr_psn::holepunch::Started;
use psr_psn::rudp::{self, Message, Rudp};
use psr_psn::{PsnError, regist};

const ACCOUNT_ID: u64 = 0x0807_0605_0403_0201;
const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 7);

fn started() -> Started {
    Started { custom_data1: [0x11; 16], data1: [0x22; 16], data2: [0x33; 16] }
}

/// The console's side: the cipher it derives from the request, and the inner header it reads.
fn console_reads(target: Target, payload: &[u8], s: &Started) -> (RpCrypt, String) {
    let key_0_off = usize::from(payload[0x18d] & 0x1f);
    let key_1_off = usize::from(payload[0] >> 3);
    let mut aeropause = [0u8; 16];
    aeropause[8..].copy_from_slice(&payload[0xc7..0xcf]);
    aeropause[..8].copy_from_slice(&payload[0x191..0x199]);
    let ambassador = rpcrypt::ambassador_from_aeropause(target, key_1_off, &aeropause).unwrap();
    let crypt = RpCrypt::regist_psn(target, &ambassador, key_0_off, &s.custom_data1, &s.data1, &s.data2).unwrap();
    let inner = String::from_utf8_lossy(&crypt.decrypt(0, &payload[0x1e0..])).into_owned();
    (crypt, inner)
}

fn split(request: &[u8]) -> (String, &[u8]) {
    let end = psr_lan::http::header_end(request).unwrap();
    (String::from_utf8(request[..end].to_vec()).unwrap(), &request[end..])
}

#[test]
fn the_request_is_chiaki_ngs_with_our_address_and_the_sessions_cipher() {
    let ambassador = [0x5A; 16];
    let (request, crypt) = regist::request(Target::Ps5V1, ACCOUNT_ID, &started(), LOCAL, &ambassador).unwrap();
    let (header, payload) = split(&request);
    assert_eq!(
        header,
        format!(
            "POST /sie/ps5/rp/sess/rgst HTTP/1.1\r\n HTTP/1.1\r\nHOST: 192.0.2.7\r\nUser-Agent: remoteplay Windows\r\nConnection: close\r\nContent-Length: {}\r\nRP-Version: 1.0\r\n\r\n",
            payload.len()
        )
    );
    let (console_crypt, inner) = console_reads(Target::Ps5V1, payload, &started());
    assert_eq!(console_crypt, crypt);
    // The account ID little-endian, as chiaki-ng's script and the session's offer have it.
    assert_eq!(
        inner,
        "Client-Type: dabfa2ec873de5839bee8d3f4c0239c4282c07c25c6077a2931afcf0adc0d34f\r\nNp-AccountId: AQIDBAUGBwg=\r\n"
    );
    // Any of the three session values wrong, and the console derives another cipher.
    for change in 0..3 {
        let mut s = started();
        [&mut s.custom_data1, &mut s.data1, &mut s.data2][change][0] ^= 1;
        assert_ne!(console_reads(Target::Ps5V1, payload, &s).0, crypt, "value {change}");
    }
}

#[test]
fn a_ps4_before_10_does_not_register_over_psn() {
    assert!(matches!(
        regist::request(Target::Ps4V9, ACCOUNT_ID, &started(), LOCAL, &[0; 16]),
        Err(PsnError::Lan(LanError::NoPsnRegist(Target::Ps4V9)))
    ));
}

const KEYS: &str = "PS5-Nickname: PS5-TEST\r\nPS5-RegistKey: 3031323334353637\r\nRP-KeyType: 2\r\nRP-Key: 00112233445566778899aabbccddeeff\r\nPS5-Mac: a1b2c3d4e5f6\r\n";

fn recv(console: &UdpSocket) -> (Vec<Message>, SocketAddr) {
    let mut buf = [0u8; 4096];
    let (n, from) = console.recv_from(&mut buf).unwrap();
    (rudp::parse(&buf[..n]), from)
}

/// The stand-in console: the RUDP handshake, then the registration answered with `status`.
fn console(sock: UdpSocket, status: &'static str, finish: bool) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (_, client) = recv(&sock);
        sock.send_to(&rudp::serialize(&[(rudp::INIT_RESPONSE, &[0; 12])]), client).unwrap();
        recv(&sock);
        sock.send_to(&rudp::serialize(&[(rudp::COOKIE_RESPONSE, &[0x00, 0x07])]), client).unwrap();
        let (m, _) = recv(&sock);
        let (_, payload) = split(&m[1].data[2..]);
        let (crypt, inner) = console_reads(Target::Ps5V1, payload, &started());
        assert!(inner.contains("Np-AccountId: AQIDBAUGBwg="));
        let body = crypt.encrypt(0, KEYS.as_bytes());
        let mut answer = vec![0x00, 0x08];
        answer.extend(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes());
        answer.extend(body);
        sock.send_to(&rudp::serialize(&[(rudp::CTRL_MESSAGE, &answer)]), client).unwrap();
        let (a, _) = recv(&sock);
        assert_eq!(a[0].kind, rudp::ACK);
        if finish {
            sock.send_to(&rudp::serialize(&[(rudp::FINISH, &[])]), client).unwrap();
        }
    })
}

fn pair() -> (UdpSocket, UdpSocket) {
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    client.connect(sock.local_addr().unwrap()).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    (client, sock)
}

#[test]
fn the_console_registers_us_through_the_hole() {
    let (client, sock) = pair();
    let t = console(sock, "200 OK", true);
    let mut r = Rudp::new(client).unwrap();
    let done = regist::register(&mut r, Target::Ps5V1, ACCOUNT_ID, &started(), LOCAL).unwrap();
    t.join().unwrap();
    assert!(done.finished);
    assert_eq!(done.host.server_mac, [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]);
    assert_eq!(&done.host.rp_regist_key[..8], b"01234567");
    assert_eq!(done.host.rp_key[0], 0x00);
    assert_eq!(done.host.rp_key[15], 0xff);
}

#[test]
fn no_finish_is_carried_on_from_and_a_refusal_is_reported() {
    let (client, sock) = pair();
    let t = console(sock, "200 OK", false);
    let done = regist::register(&mut Rudp::new(client).unwrap(), Target::Ps5V1, ACCOUNT_ID, &started(), LOCAL).unwrap();
    t.join().unwrap();
    assert!(!done.finished);

    let (client, sock) = pair();
    let t = console(sock, "403 Forbidden", true);
    let refused = regist::register(&mut Rudp::new(client).unwrap(), Target::Ps5V1, ACCOUNT_ID, &started(), LOCAL);
    t.join().unwrap();
    assert!(matches!(refused, Err(PsnError::Lan(LanError::Refused { code: 403, .. }))), "{refused:?}");
}

#[test]
fn a_malformed_answer_names_no_key_in_its_error() {
    let target = Target::Ps5V1;
    let crypt = RpCrypt::regist_psn(target, &[1; 16], 0, &[2; 16], &[3; 16], &[4; 16]).unwrap();
    let answer = |plain: &[u8], length: Option<&str>| {
        let body = crypt.encrypt(0, plain);
        let len = length.map_or(body.len().to_string(), str::to_string);
        let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n").into_bytes();
        r.extend(body);
        r
    };
    let secret = "00112233445566778899aabbccddeeff";
    for plain in [
        format!("RP-Key: {secret}\r\n\u{0}").into_bytes().into_iter().chain([0xFF]).collect::<Vec<u8>>(),
        [format!("RP-Key: {secret}\r\n").as_bytes(), &[0xFF, b'\r', b'\n']].concat(),
        format!("RP-Key: {secret}\r\nno colon here {secret}\r\n").into_bytes(),
        format!("PS5-RegistKey:\r\nRP-Key: {secret}\r\n").into_bytes(),
    ] {
        let e = psr_lan::regist::parse_response(target, &crypt, &answer(&plain, None)).unwrap_err();
        for shown in [e.to_string(), format!("{e:?}")] {
            assert!(!shown.contains(secret), "{shown}");
        }
    }
    // A length that would overflow is a short answer, not a crash.
    let e = psr_lan::regist::parse_response(target, &crypt, &answer(b"x", Some("18446744073709551615"))).unwrap_err();
    assert!(matches!(e, LanError::Truncated), "{e:?}");
}
