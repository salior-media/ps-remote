// SPDX-License-Identifier: AGPL-3.0-only
// The first three tests are ported from chiaki-ng `test/regist.c` (LicenseRef-AGPL-3.0-only-OpenSSL); its
// expected payload is extracted into vectors/ by script. The rest are written from `lib/src/regist.c`.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};

use psr_crypto::Target;
use psr_crypto::rpcrypt::{self, RpCrypt};
use psr_lan::LanError;
use psr_lan::regist::{self, Identity, REGIST_PORT};

const AMBASSADOR: [u8; 16] = [0x13, 0x37, 0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0x42, 0x63, 0x68, 0x69, 0x61, 0x6b, 0x69];
const PIN: u32 = 13_374_201;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn aeropause_ps4_pre10() {
    assert_eq!(
        rpcrypt::aeropause_ps4_pre10(&AMBASSADOR),
        [0x0b, 0xe1, 0x2f, 0xbb, 0x4c, 0x7c, 0x99, 0x4a, 0x41, 0x1e, 0x2d, 0x4c, 0xa4, 0x19, 0xf4, 0x35]
    );
}

#[test]
fn pin_bright_ps4_pre10() {
    assert_eq!(
        *RpCrypt::regist_ps4_pre10(&AMBASSADOR, PIN).bright(),
        [0x3f, 0xd0, 0xd6, 0x4f, 0xdc, 0xbb, 0x3e, 0xcc, 0x50, 0xba, 0xed, 0xef, 0x97, 0x34, 0xc7, 0xc9]
    );
}

#[test]
fn request_payload_ps4_pre10() {
    let text = include_str!("vectors/regist_ps4_pre10_payload.hex");
    let expected = hex(text.lines().find(|l| !l.starts_with('#')).unwrap().trim());
    let (payload, _) =
        regist::request_payload(Target::Ps4V9, &AMBASSADOR, &Identity::OnlineId("ChiakiNanami1337".into()), PIN).unwrap();
    assert_eq!(payload, expected);
}

const ACCOUNT_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

/// What a PS5 does with our payload, written from the client side of chiaki-ng's code: recover the
/// ambassador from the aeropause bytes, derive the same cipher from the PIN, decrypt the inner header.
fn console_side(payload: &[u8], pin: u32) -> (RpCrypt, String) {
    let key_0_off = usize::from(payload[0x18d] & 0x1f);
    let key_1_off = usize::from(payload[0] >> 3);
    let mut aeropause = [0u8; 16];
    aeropause[8..].copy_from_slice(&payload[0xc7..0xcf]);
    aeropause[..8].copy_from_slice(&payload[0x191..0x199]);
    // aeropause[i] = (ambassador[i] ^ k[i]) + w + i, with w = -0x2d for a PS5; invert by brute force over
    // the 256 candidates per byte, using the library's own forward function as the reference.
    let mut ambassador = [0u8; 16];
    for i in 0..16 {
        ambassador[i] = (0..=255u8)
            .find(|&a| {
                let mut probe = [0u8; 16];
                probe[i] = a;
                rpcrypt::aeropause(Target::Ps5V1, key_1_off, &probe).unwrap()[i] == aeropause[i]
            })
            .unwrap();
    }
    let crypt = RpCrypt::regist(Target::Ps5V1, &ambassador, key_0_off, pin).unwrap();
    let inner = String::from_utf8_lossy(&crypt.decrypt(0, &payload[0x1e0..])).into_owned();
    (crypt, inner)
}

#[test]
fn a_ps5_payload_decrypts_on_the_console_side_to_the_account_id() {
    let (payload, crypt) = regist::request_payload(Target::Ps5V1, &AMBASSADOR, &Identity::AccountId(ACCOUNT_ID), PIN).unwrap();
    assert!(payload[..0x1e0].iter().enumerate().all(|(i, &b)| (0xc7..0xcf).contains(&i) || (0x191..0x199).contains(&i) || b == b'A'));
    let (console_crypt, inner) = console_side(&payload, PIN);
    assert_eq!(console_crypt, crypt);
    assert_eq!(inner, "Client-Type: dabfa2ec873de5839bee8d3f4c0239c4282c07c25c6077a2931afcf0adc0d34f\r\nNp-AccountId: AQIDBAUGBwg=\r\n");
    // A wrong PIN derives a different cipher, so the console can't read the account ID.
    assert_ne!(console_side(&payload, PIN + 1).0, crypt);
}

#[test]
fn the_online_id_is_refused_for_ps5() {
    assert!(matches!(
        regist::request_payload(Target::Ps5V1, &AMBASSADOR, &Identity::OnlineId("x".into()), PIN),
        Err(LanError::NeedsAccountId(Target::Ps5V1))
    ));
}

#[test]
fn request_header_matches_chiaki_ng() {
    assert_eq!(
        regist::request_header(Target::Ps5V1, 0x203).unwrap(),
        "POST /sie/ps5/rp/sess/rgst HTTP/1.1\r\n HTTP/1.1\r\nHOST: 10.0.2.15\r\nUser-Agent: remoteplay Windows\r\nConnection: close\r\nContent-Length: 515\r\nRP-Version: 1.0\r\n\r\n"
    );
    assert!(regist::request_header(Target::Ps4V8, 1).unwrap().starts_with("POST /sce/rp/regist HTTP/1.1"));
    assert!(!regist::request_header(Target::Ps4V8, 1).unwrap().contains("RP-Version"));
}

#[test]
fn account_id_base64_is_eight_bytes() {
    assert_eq!(Identity::account_id_from_base64("AQIDBAUGBwg=").unwrap(), Identity::AccountId(ACCOUNT_ID));
    assert!(Identity::account_id_from_base64("AQID").is_err());
    assert!(Identity::account_id_from_base64("not base64!").is_err());
}

fn reply_body() -> String {
    // Field names are chiaki-ng's; the values are made up.
    "AP-Ssid: home\r\nPS5-Nickname: PS5-TEST\r\nPS5-RegistKey: 3031323334353637\r\nRP-KeyType: 2\r\nRP-Key: 00112233445566778899aabbccddeeff\r\nPS5-Mac: a1b2c3d4e5f6\r\n".into()
}

#[test]
fn a_reply_without_its_key_mac_or_regist_key_is_refused() {
    let crypt = RpCrypt::regist(Target::Ps5V1, &AMBASSADOR, 1, PIN).unwrap();
    for drop in ["PS5-RegistKey", "RP-Key", "PS5-Mac"] {
        let body: String = reply_body().split("\r\n").filter(|l| !l.starts_with(drop)).map(|l| format!("{l}\r\n")).collect();
        let enc = crypt.encrypt(0, body.trim_end_matches("\r\n\r\n").as_bytes());
        let mut resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", enc.len()).into_bytes();
        resp.extend_from_slice(&enc);
        assert!(matches!(regist::parse_response(Target::Ps5V1, &crypt, &resp), Err(LanError::MissingField(_))), "{drop}");
    }
    // chiaki-ng also refuses a MAC or RP key of the wrong length.
    for (from, to) in [("PS5-Mac: a1b2c3d4e5f6", "PS5-Mac: a1b2c3"), ("RP-Key: 00112233445566778899aabbccddeeff", "RP-Key: 0011")] {
        let enc = crypt.encrypt(0, reply_body().replace(from, to).as_bytes());
        let mut resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", enc.len()).into_bytes();
        resp.extend_from_slice(&enc);
        assert!(matches!(regist::parse_response(Target::Ps5V1, &crypt, &resp), Err(LanError::MissingField(_))), "{to}");
    }
    let refused = b"HTTP/1.1 403 Forbidden\r\nRP-Application-Reason: 0x80108b09\r\n\r\n";
    assert!(matches!(
        regist::parse_response(Target::Ps5V1, &crypt, refused),
        Err(LanError::Refused { code: 403, reason: Some(0x8010_8b09) })
    ));
}

#[test]
fn registers_with_a_fake_ps5_on_loopback() {
    let (udp, tcp) = match (UdpSocket::bind((Ipv4Addr::LOCALHOST, REGIST_PORT)), TcpListener::bind((Ipv4Addr::LOCALHOST, REGIST_PORT))) {
        (Ok(u), Ok(t)) => (u, t),
        _ => {
            eprintln!("skipped: port {REGIST_PORT} is busy on this machine");
            return;
        }
    };
    let console = std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        let (n, from) = udp.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"SRC3\0");
        udp.send_to(b"RES3", from).unwrap();
        let (mut conn, _) = tcp.accept().unwrap();
        let mut req = Vec::new();
        let mut chunk = [0u8; 1024];
        let (header_len, content_len) = loop {
            let n = conn.read(&mut chunk).unwrap();
            req.extend_from_slice(&chunk[..n]);
            if let Some(end) = psr_lan::http::header_end(&req) {
                let text = String::from_utf8_lossy(&req[..end]).to_string();
                let len: usize = text.lines().find_map(|l| l.strip_prefix("Content-Length: ")).unwrap().parse().unwrap();
                if req.len() >= end + len {
                    break (end, len);
                }
            }
        };
        let (crypt, inner) = console_side(&req[header_len..header_len + content_len], PIN);
        assert!(inner.contains("Np-AccountId: AQIDBAUGBwg="));
        let enc = crypt.encrypt(0, reply_body().as_bytes());
        let mut resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", enc.len()).into_bytes();
        resp.extend_from_slice(&enc);
        conn.write_all(&resp).unwrap();
    });
    let host = regist::register(IpAddr::V4(Ipv4Addr::LOCALHOST), Target::Ps5V1, &Identity::AccountId(ACCOUNT_ID), PIN).unwrap();
    console.join().unwrap();
    assert_eq!(host.server_nickname.as_deref(), Some("PS5-TEST"));
    assert_eq!(host.server_mac, [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]);
    assert_eq!(host.rp_key_type, 2);
    assert_eq!(host.rp_key[0], 0x00);
    // "01234567" as text, read as hex for wake-up, as chiaki-ng does.
    assert_eq!(host.wakeup_credential(), Some(0x0123_4567));
    assert!(!format!("{host:?}").contains("0123"), "Debug must not print the keys");
}

#[test]
fn a_registered_console_round_trips_through_its_saved_file() {
    let crypt = RpCrypt::regist(Target::Ps5V1, &AMBASSADOR, 1, PIN).unwrap();
    let enc = crypt.encrypt(0, reply_body().as_bytes());
    let mut resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", enc.len()).into_bytes();
    resp.extend_from_slice(&enc);
    let host = regist::parse_response(Target::Ps5V1, &crypt, &resp).unwrap();
    let dir = std::env::temp_dir().join(format!("ps-remote-store-test-{}", std::process::id()));
    let path = psr_lan::store::save(&dir, &host).unwrap();
    assert!(path.ends_with("a1b2c3d4e5f6.txt"));
    assert_eq!(psr_lan::store::load_all(&dir).unwrap(), vec![host]);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(psr_lan::store::from_text("format=other\n").is_err());
}
