// SPDX-License-Identifier: AGPL-3.0-only
// Written from chiaki-ng `lib/src/session.c` and `lib/src/ctrl.c` (LicenseRef-AGPL-3.0-only-OpenSSL), which
// have no tests of their own. The cipher underneath, `RpCrypt::auth`, is checked against chiaki-ng's
// vectors in psr-crypto. Here the console's side is played by a second cipher with the same keys: a
// field only decrypts to what was sent if both sides used the same counter.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use base64::Engine;
use psr_crypto::Target;
use psr_crypto::rpcrypt::RpCrypt;
use psr_lan::LanError;
use psr_lan::ctrl::{self, CtrlCipher, CtrlEvent, Framer, MessageType};
use psr_lan::regist::RegisteredHost;
use psr_lan::session::{self, Codec};

const NONCE: [u8; 16] = [0x91, 0x4c, 0x07, 0x3e, 0xa2, 0x5d, 0x11, 0xf0, 0x6b, 0x38, 0xc9, 0x02, 0x7a, 0xe4, 0x55, 0x1d];
const MORNING: [u8; 16] = [0x2b, 0x84, 0xd3, 0x6f, 0x10, 0xaa, 0x9c, 0x47, 0xe5, 0x21, 0x0e, 0xb8, 0x73, 0x5a, 0xcd, 0x96];
/// A registration key as consoles hand it out: the text of a hexadecimal number, zero-padded.
const REGIST_KEY: [u8; 16] = *b"3a9f0c71\0\0\0\0\0\0\0\0";
const DID: [u8; 32] = [7; 32];

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

fn header<'a>(request: &'a str, key: &str) -> Option<&'a str> {
    request.lines().find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(": ")))
}

fn crypt(target: Target) -> RpCrypt {
    RpCrypt::auth(target, &NONCE, &MORNING).unwrap()
}

#[test]
fn did_has_chiaki_ngs_prefix_and_suffix() {
    let random = [0xabu8; 16];
    let did = session::did(&random);
    assert_eq!(did[..10], [0x00, 0x18, 0x00, 0x00, 0x00, 0x07, 0x00, 0x40, 0x00, 0x80]);
    assert_eq!(did[10..26], random);
    assert_eq!(did[26..], [0; 6]);
}

#[test]
fn session_request_ps5() {
    let request = session::session_request(Target::Ps5V1, "192.168.0.9", &REGIST_KEY).unwrap();
    assert_eq!(
        request,
        "GET /sie/ps5/rp/sess/init HTTP/1.1\r\n\
         Host: 192.168.0.9:9295\r\n\
         User-Agent: remoteplay Windows\r\n\
         Connection: close\r\n\
         Content-Length: 0\r\n\
         RP-Registkey: 3361396630633731\r\n\
         Rp-Version: 1.0\r\n\
         \r\n"
    );
}

#[test]
fn session_request_paths_by_target() {
    let path = |t| session::session_request(t, "h", &REGIST_KEY).unwrap().lines().next().unwrap().to_string();
    assert_eq!(path(Target::Ps4V9), "GET /sce/rp/session HTTP/1.1");
    assert_eq!(path(Target::Ps4V10), "GET /sie/ps4/rp/sess/init HTTP/1.1");
    assert!(matches!(session::session_request(Target::Ps5Unknown, "h", &REGIST_KEY), Err(LanError::NoRpVersion(_))));
}

#[test]
fn session_response_nonce() {
    let reply = format!("HTTP/1.1 200 OK\r\nRP-Nonce: {}\r\nContent-Length: 0\r\n\r\n", b64(&NONCE));
    assert_eq!(session::parse_session_response(reply.as_bytes()).unwrap(), NONCE);
}

#[test]
fn session_response_without_a_good_nonce_is_refused() {
    let none = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    assert!(matches!(session::parse_session_response(none.as_bytes()), Err(LanError::SessionRefused { code: 200, .. })));
    let short = format!("HTTP/1.1 200 OK\r\nRP-Nonce: {}\r\n\r\n", b64(&NONCE[..15]));
    assert!(matches!(session::parse_session_response(short.as_bytes()), Err(LanError::BadNonce)));
}

#[test]
fn session_response_in_use() {
    let reply = "HTTP/1.1 403 Forbidden\r\nRP-Application-Reason: 80108b10\r\n\r\n";
    let err = session::parse_session_response(reply.as_bytes()).unwrap_err();
    assert!(matches!(err, LanError::SessionRefused { code: 403, reason: Some(0x8010_8b10), .. }), "{err:?}");
    assert!(err.to_string().contains("already in use"), "{err}");
}

#[test]
fn version_mismatch_names_the_consoles_version() {
    let refused = |reason: &str, version: &str| {
        let reply = format!("HTTP/1.1 403 Forbidden\r\nRP-Application-Reason: {reason}\r\nRP-Version: {version}\r\n\r\n");
        session::parse_session_response(reply.as_bytes()).unwrap_err()
    };
    assert_eq!(session::retry_target(&refused("80108b11", "9.0"), Target::Ps4V10), Some(Target::Ps4V9));
    assert_eq!(session::retry_target(&refused("80108bff", "8.0"), Target::Ps4V10), Some(Target::Ps4V8));
    // chiaki-ng: a PS4 reporting 5.0 "is probably nonsense, let's try with 9.0".
    assert_eq!(session::retry_target(&refused("80108b11", "5.0"), Target::Ps4V10), Some(Target::Ps4V9));
    // The same version, an unknown one, or another reason: no retry.
    assert_eq!(session::retry_target(&refused("80108b11", "10.0"), Target::Ps4V10), None);
    assert_eq!(session::retry_target(&refused("80108b11", "7.0"), Target::Ps4V10), None);
    assert_eq!(session::retry_target(&refused("80108b10", "9.0"), Target::Ps4V10), None);
    assert_eq!(session::retry_target(&refused("80108b11", "2.0"), Target::Ps5V1), None);
}

#[test]
fn ctrl_request_ps5_fields_decrypt_in_order() {
    let console = crypt(Target::Ps5V1);
    let mut cipher = CtrlCipher::new(crypt(Target::Ps5V1));
    let request = ctrl::ctrl_request(Target::Ps5V1, "192.168.0.9", &mut cipher, &REGIST_KEY, &DID, Codec::H264).unwrap();
    assert!(request.starts_with("GET /sie/ps5/rp/sess/ctrl HTTP/1.1\r\nHost: 192.168.0.9:9295\r\n"), "{request}");
    assert!(request.ends_with("\r\n\r\n"));
    assert_eq!(header(&request, "Connection"), Some("keep-alive"));
    assert_eq!(header(&request, "RP-Version"), Some("1.0"));
    assert_eq!(header(&request, "RP-ControllerType"), Some("3"));
    assert_eq!(header(&request, "RP-ClientType"), Some("11"));
    assert_eq!(header(&request, "RP-ConPath"), Some("1"));
    assert_eq!(header(&request, "RP-PadProcNo"), Some("3"));
    let field = |key, counter| console.decrypt(counter, &unb64(header(&request, key).unwrap()));
    assert_eq!(field("RP-Auth", 0), REGIST_KEY);
    assert_eq!(field("RP-Did", 1), DID);
    assert_eq!(field("RP-OSType", 2), b"Win10.0.0\0");
    assert_eq!(field("RP-StartBitrate", 3), [0; 4]);
    assert_eq!(field("RP-StreamingType", 4), 1u32.to_le_bytes());
    // The next message is sealed at counter 5.
    assert_eq!(cipher.local(), 5);
}

#[test]
fn ctrl_request_streaming_type_by_codec() {
    let streaming = |codec| {
        let mut cipher = CtrlCipher::new(crypt(Target::Ps5V1));
        let request = ctrl::ctrl_request(Target::Ps5V1, "h", &mut cipher, &REGIST_KEY, &DID, codec).unwrap();
        crypt(Target::Ps5V1).decrypt(4, &unb64(header(&request, "RP-StreamingType").unwrap()))
    };
    assert_eq!(streaming(Codec::H265), 2u32.to_le_bytes());
    assert_eq!(streaming(Codec::H265Hdr), 3u32.to_le_bytes());
}

#[test]
fn ctrl_request_ps4_v9_has_no_bitrate_or_streaming_type() {
    let mut cipher = CtrlCipher::new(crypt(Target::Ps4V9));
    let request = ctrl::ctrl_request(Target::Ps4V9, "h", &mut cipher, &REGIST_KEY, &DID, Codec::H264).unwrap();
    assert!(request.starts_with("GET /sce/rp/session/ctrl HTTP/1.1\r\n"));
    for absent in ["RP-StartBitrate", "RP-StreamingType", "RP-PadProcNo"] {
        assert_eq!(header(&request, absent), None, "{absent}");
    }
    assert_eq!(cipher.local(), 3);
}

#[test]
fn ctrl_response_server_type_takes_the_first_remote_counter() {
    let console = crypt(Target::Ps5V1);
    let server_type = console.encrypt(0, &[2; 16]);
    let reply = format!("HTTP/1.1 200 OK\r\nRP-Server-Type: {}\r\nRP-Prohibit: 0\r\n\r\n", b64(&server_type));
    let mut cipher = CtrlCipher::new(crypt(Target::Ps5V1));
    let parsed = ctrl::parse_ctrl_response(reply.as_bytes(), &mut cipher).unwrap();
    assert_eq!(parsed.server_type, Some(2));
    assert!(!parsed.prohibit);
    assert_eq!(cipher.remote(), 1);
}

#[test]
fn ctrl_request_ps4_v10_has_a_start_bitrate_but_no_streaming_type() {
    let mut cipher = CtrlCipher::new(crypt(Target::Ps4V10));
    let request = ctrl::ctrl_request(Target::Ps4V10, "h", &mut cipher, &REGIST_KEY, &DID, Codec::H264).unwrap();
    assert!(request.starts_with("GET /sie/ps4/rp/sess/ctrl HTTP/1.1\r\n"));
    let bitrate = crypt(Target::Ps4V10).decrypt(3, &unb64(header(&request, "RP-StartBitrate").unwrap()));
    assert_eq!(bitrate, [0; 4]);
    assert_eq!(header(&request, "RP-StreamingType"), None);
    assert_eq!(cipher.local(), 4);
}

#[test]
fn ctrl_response_server_type_of_the_wrong_size_is_ignored() {
    let server_type = crypt(Target::Ps5V1).encrypt(0, &[2; 15]);
    let reply = format!("HTTP/1.1 200 OK\r\nRP-Server-Type: {}\r\n\r\n", b64(&server_type));
    let mut cipher = CtrlCipher::new(crypt(Target::Ps5V1));
    assert_eq!(ctrl::parse_ctrl_response(reply.as_bytes(), &mut cipher).unwrap().server_type, None);
    assert_eq!(cipher.remote(), 0);
}

#[test]
fn ctrl_response_without_server_type_leaves_the_counter() {
    let mut cipher = CtrlCipher::new(crypt(Target::Ps5V1));
    let parsed = ctrl::parse_ctrl_response(b"HTTP/1.1 200 OK\r\nRP-Prohibit: 1\r\n\r\n", &mut cipher).unwrap();
    assert_eq!(parsed.server_type, None);
    assert!(parsed.prohibit);
    assert_eq!(cipher.remote(), 0);
}

#[test]
fn ctrl_response_not_ok_is_refused() {
    let mut cipher = CtrlCipher::new(crypt(Target::Ps5V1));
    let err = ctrl::parse_ctrl_response(b"HTTP/1.1 403 Forbidden\r\n\r\n", &mut cipher).unwrap_err();
    assert!(matches!(err, LanError::CtrlRefused(403)), "{err:?}");
}

#[test]
fn message_frame_layout() {
    let mut cipher = CtrlCipher::new(crypt(Target::Ps5V1));
    cipher.set_local(5);
    let frame = cipher.seal(MessageType::DisplayDevices.code(), &[0, 0, 0, 0]);
    assert_eq!(frame[..8], [0, 0, 0, 4, 0x09, 0x10, 0, 0]);
    assert_eq!(frame[8..], crypt(Target::Ps5V1).encrypt(5, &[0, 0, 0, 0])[..]);
    assert_eq!(cipher.local(), 6);
    // An empty payload is sent bare and does not use a counter.
    assert_eq!(cipher.seal(MessageType::HeartbeatRep.code(), &[]), [0, 0, 0, 0, 0x01, 0xfe, 0, 0]);
    assert_eq!(cipher.local(), 6);
}

#[test]
fn framer_reassembles_split_and_joined_frames() {
    let mut console = CtrlCipher::new(crypt(Target::Ps5V1));
    let mut stream = console.seal(0x33, b"Jabc");
    stream.extend(console.seal(0xfe, &[]));
    stream.extend(console.seal(0x16, &[1, 0xff]));
    let mut client = CtrlCipher::new(crypt(Target::Ps5V1));
    let mut framer = Framer::default();
    let mut got = Vec::new();
    for byte in stream.chunks(3) {
        framer.push(byte).unwrap();
        while let Some((ty, payload)) = framer.next_frame() {
            got.push((ty, client.open(&payload)));
        }
    }
    assert_eq!(got, [(0x33, b"Jabc".to_vec()), (0xfe, vec![]), (0x16, vec![1, 0xff])]);
    assert_eq!(client.remote(), 2);
}

#[test]
fn framer_refuses_a_frame_bigger_than_chiaki_ngs_buffer() {
    let mut framer = Framer::default();
    assert!(matches!(framer.push(&[0, 0, 0x01, 0xf9, 0, 0x33, 0, 0]), Err(LanError::CtrlOverflow)));
    let mut ok = Framer::default();
    ok.push(&[0, 0, 0x01, 0xf8, 0, 0x33, 0, 0]).unwrap();
    ok.push(&[0; 0x1f8]).unwrap();
    assert!(ok.next_frame().is_some());
}

#[test]
fn session_id_rules() {
    let id = |s: &[u8]| ctrl::parse_session_id(&[&[0x4a], s].concat());
    assert_eq!(id(b"abcdefghijklmnopqrstuvwx").as_deref(), Some("abcdefghijklmnopqrstuvwx"));
    assert_eq!(id(b"abcdefghijklmnopqrstuvw"), None, "23 characters is too short");
    assert_eq!(id(b"abcdefghijklmnopqrstuvw-"), None, "only letters and digits");
    assert_eq!(id(&[b'a'; 78]).map(|s| s.len()), Some(78));
    assert_eq!(id(&[b'a'; 79]), None, "too long");
    assert_eq!(ctrl::parse_session_id(&[0x4a]), None);
}

/// A console on loopback: answers the session request and the ctrl request, asks for a heartbeat, hands
/// out a session ID, and returns what the client sent once the session ID went out.
/// The ctrl request the fake console read, and the decrypted messages the client sent after it.
type Seen = (String, Vec<(u16, Vec<u8>)>);

fn fake_console(listener: TcpListener, session_id: &'static [u8]) -> std::thread::JoinHandle<Seen> {
    std::thread::spawn(move || {
        let read_head = |s: &mut TcpStream| {
            let mut buf = Vec::new();
            let mut byte = [0u8];
            while !buf.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut byte).unwrap();
                buf.push(byte[0]);
            }
            String::from_utf8(buf).unwrap()
        };
        let (mut s, _) = listener.accept().unwrap();
        let init = read_head(&mut s);
        assert!(init.starts_with("GET /sie/ps5/rp/sess/init "), "{init}");
        s.write_all(format!("HTTP/1.1 200 OK\r\nRP-Nonce: {}\r\nContent-Length: 0\r\n\r\n", b64(&NONCE)).as_bytes()).unwrap();
        drop(s);

        let (mut s, _) = listener.accept().unwrap();
        let ctrl_request = read_head(&mut s);
        let mut console = CtrlCipher::new(crypt(Target::Ps5V1));
        let server_type = crypt(Target::Ps5V1).encrypt(0, &[2; 16]);
        console.set_remote(5);
        console.set_local(1);
        let mut reply = format!("HTTP/1.1 200 OK\r\nRP-Server-Type: {}\r\n\r\n", b64(&server_type)).into_bytes();
        reply.extend(console.seal(MessageType::HeartbeatReq.code(), &[]));
        reply.extend(console.seal(MessageType::SessionId.code(), &[&[0x4a], session_id].concat()));
        s.write_all(&reply).unwrap();

        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut framer = Framer::default();
        let mut got = Vec::new();
        let mut chunk = [0u8; 256];
        // Heartbeat reply, two microphone toggles, display devices.
        while got.len() < 4 {
            let n = s.read(&mut chunk).unwrap();
            assert!(n > 0, "client closed early");
            framer.push(&chunk[..n]).unwrap();
            while let Some((ty, payload)) = framer.next_frame() {
                got.push((ty, console.open(&payload)));
            }
        }
        (ctrl_request, got)
    })
}

fn host() -> RegisteredHost {
    RegisteredHost {
        target: Target::Ps5V1,
        ap_ssid: None,
        ap_bssid: None,
        ap_key: None,
        ap_name: None,
        server_mac: [0; 6],
        server_nickname: Some("fake".into()),
        rp_regist_key: REGIST_KEY,
        rp_key_type: 0,
        rp_key: MORNING,
    }
}

#[test]
fn start_against_a_fake_console_gets_the_session_id() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let console = fake_console(listener, b"ABCDEFGHIJKLmnopqrstuvwx0123");
    let mut session = session::start_at(addr, &host(), Codec::H264, &DID).unwrap();
    assert_eq!(session.session_id(), "ABCDEFGHIJKLmnopqrstuvwx0123");
    assert_eq!(session.server_type(), Some(2));
    // Keep answering until the console has seen everything it waits for.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !console.is_finished() && std::time::Instant::now() < deadline {
        let _ = session.poll(Duration::from_millis(50));
    }
    let (ctrl_request, got) = console.join().unwrap();
    let auth = crypt(Target::Ps5V1).decrypt(0, &unb64(header(&ctrl_request, "RP-Auth").unwrap()));
    assert_eq!(auth, REGIST_KEY);
    assert_eq!(header(&ctrl_request, "Host"), Some(format!("{}:9295", addr.ip()).as_str()));
    let types: Vec<u16> = got.iter().map(|(t, _)| *t).collect();
    assert_eq!(types, [0x1fe, 0x36, 0x36, 0x910]);
    assert_eq!(got[1].1, [0, 1, 1, 89], "chiaki-ng's microphone message, as it sends it");
    assert_eq!(got[3].1, [0; 4]);
}

#[test]
fn poll_reports_events_after_start() {
    let mut events = Vec::new();
    let mut console = CtrlCipher::new(crypt(Target::Ps5V1));
    let mut framer = Framer::default();
    framer.push(&console.seal(MessageType::LoginPinReq.code(), &[])).unwrap();
    framer.push(&console.seal(0x99, &[1, 2])).unwrap();
    let mut client = CtrlCipher::new(crypt(Target::Ps5V1));
    while let Some((ty, payload)) = framer.next_frame() {
        events.push(ctrl::event(ty, &client.open(&payload)));
    }
    assert_eq!(events, [CtrlEvent::LoginPinRequested, CtrlEvent::Other { message_type: 0x99, payload: vec![1, 2] }]);
}

#[test]
fn current_ps5_session_id_form_takes_the_fallback() {
    // Seen from a PS5 on 2026-11-24: the length byte 0x10, then 16 letters and digits.
    assert_eq!(ctrl::parse_session_id(&[&[0x10], &b"AbCdEfGh12345678"[..]].concat()), None);
}

#[test]
fn fallback_session_id_is_74_characters() {
    let id = session::fallback_session_id(1_764_000_000, &[0x5a; 48]);
    assert_eq!(id.len(), 74);
    assert!(id.starts_with("1764000000"));
}
