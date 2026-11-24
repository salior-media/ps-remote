// SPDX-License-Identifier: AGPL-3.0-only
// The launch spec is checked against chiaki-ng's own `lib/src/launchspec.c`, compiled by
// scripts/oracle/launchspec. The rest is written from `lib/src/streamconnection.c`
// (LicenseRef-AGPL-3.0-only-OpenSSL), which has no tests: a fake console on loopback runs the whole
// connect with its own keys, so the exchange only works if both sides derive the same ones.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use base64::Engine;
use prost::Message;
use psr_crypto::Target;
use psr_crypto::ecdh::Ecdh;
use psr_crypto::gkcrypt::GkCrypt;
use psr_crypto::rpcrypt::RpCrypt;
use psr_lan::LanError;
use psr_lan::session::Codec;
use psr_lan::stream::{self, StreamEvent, VideoProfile};
use psr_proto::takion_message::PayloadType;
use psr_proto::{BangPayload, ResolutionPayload, StreamInfoPayload, TakionMessage};
use psr_takion::connection::{Received, Receiver, Sender};
use psr_takion::message::{self, ChunkType};
use psr_takion::packet;

const NONCE: [u8; 16] = [0x91; 16];
const MORNING: [u8; 16] = [0x2b; 16];
const SESSION_ID: &str = "1764000000AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnopqrstuvwxyz01";

fn oracle(name: &str) -> String {
    let text = include_str!("vectors/launchspec_oracle.txt");
    text.lines().find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(' '))).unwrap().to_string()
}

fn key() -> [u8; 16] {
    std::array::from_fn(|i| (i * 17 + 3) as u8)
}

fn rpcrypt() -> RpCrypt {
    RpCrypt::auth(Target::Ps5V1, &NONCE, &MORNING).unwrap()
}

#[test]
fn launch_spec_matches_chiaki_ng() {
    let spec = |t, p: &VideoProfile| stream::launch_spec(t, p, 1454, 1, &key());
    assert_eq!(spec(Target::Ps5V1, &VideoProfile::p720_60(Codec::H264)), oracle("ps5_h264"));
    assert_eq!(spec(Target::Ps5V1, &VideoProfile::p1080_60(Codec::H265Hdr)), oracle("ps5_hdr"));
    assert_eq!(spec(Target::Ps4V10, &VideoProfile::p1080_60(Codec::H264)), oracle("ps4"));
}

#[test]
fn launch_spec_encoding_is_the_json_and_its_nul_xored_with_the_auth_pad() {
    let json = oracle("ps5_h264");
    let enc = base64::engine::general_purpose::STANDARD.decode(stream::encode_launch_spec(&rpcrypt(), &json)).unwrap();
    assert_eq!(enc.len(), json.len() + 1);
    let pad = rpcrypt().encrypt(0, &vec![0; enc.len()]);
    let plain: Vec<u8> = enc.iter().zip(&pad).map(|(a, b)| a ^ b).collect();
    assert_eq!(&plain[..json.len()], json.as_bytes());
    assert_eq!(plain[json.len()], 0);
}

#[test]
fn small_messages_match_nanopb() {
    // chiaki-ng encodes with nanopb: the required type first, then the set optional fields.
    assert_eq!(stream::heartbeat_message(), [0x08, 0x03]);
    assert_eq!(stream::streaminfo_ack_message(), [0x08, 0x0e]);
    let big = stream::big_message(12, "id", "spec", &[1], &[2]);
    assert_eq!(big[..3], [0x08, 0x00, 0x12], "BIG = 0 is still written, then field 2");
    let decoded = TakionMessage::decode(big.as_slice()).unwrap().big_payload.unwrap();
    assert_eq!((decoded.client_version, decoded.encrypted_key), (12, vec![0; 4]));
    let disconnect = TakionMessage::decode(stream::disconnect_message().as_slice()).unwrap();
    assert_eq!(disconnect.disconnect_payload.unwrap().reason, "Client Disconnecting");
    let controller = TakionMessage::decode(stream::controller_connection_message().as_slice()).unwrap();
    let c = controller.controller_connection_payload.unwrap();
    assert_eq!((c.controller_id, c.connected, c.controller_type), (None, Some(true), Some(2)));
}

#[test]
fn microphone_header_bytes_follow_chiaki_ngs_save_order() {
    assert_eq!(stream::microphone_audio_header(), [1, 16, 0, 0, 0xbb, 0x80, 0, 0, 0x01, 0xe0, 0, 0, 0, 1]);
}

fn bang(accept_version: bool, accept_key: bool, pub_key: Option<Vec<u8>>, sig: Option<Vec<u8>>) -> TakionMessage {
    TakionMessage {
        r#type: PayloadType::Bang as i32,
        bang_payload: Some(BangPayload {
            server_version: 12,
            token: 0,
            encrypted_key_accepted: accept_key,
            version_accepted: accept_version,
            session_key: String::new(),
            extended_info: None,
            server_version_string: None,
            ecdh_pub_key: pub_key,
            ecdh_sig: sig,
        }),
        ..Default::default()
    }
}

#[test]
fn bang_checks() {
    let ok = || (Some(vec![4; 65]), Some(vec![1; 32]));
    assert!(stream::check_bang(&bang(true, true, ok().0, ok().1)).is_ok());
    for refused in [
        bang(false, true, ok().0, ok().1),
        bang(true, false, ok().0, ok().1),
        bang(true, true, None, ok().1),
        bang(true, true, Some(vec![]), ok().1),
        bang(true, true, ok().0, None),
    ] {
        assert!(matches!(stream::check_bang(&refused), Err(LanError::Bang(_))), "{refused:?}");
    }
}

#[test]
fn both_sides_derive_the_same_stream_keys() {
    let hk = key();
    let (ours, console) = (Ecdh::generate().unwrap(), Ecdh::generate().unwrap());
    let (console_key, console_sig) = console.signed_public_key(&hk);
    let (local, remote) = stream::stream_keys(&ours, &hk, &console_key, &console_sig).unwrap();
    let (our_key, _) = ours.signed_public_key(&hk);
    let secret = console.derive_secret(&our_key, &hk, &ours.signed_public_key(&hk).1).unwrap();
    assert_eq!(local.key_base(), GkCrypt::new(2, &hk, &secret).key_base());
    assert_eq!(remote.key_base(), GkCrypt::new(3, &hk, &secret).key_base());
    let mut bad_sig = console_sig;
    bad_sig[0] ^= 1;
    assert!(stream::stream_keys(&ours, &hk, &console_key, &bad_sig).is_err(), "the console's signature is checked");
}

fn stream_info_message() -> TakionMessage {
    TakionMessage {
        r#type: PayloadType::Streaminfo as i32,
        stream_info_payload: Some(StreamInfoPayload {
            resolution: vec![ResolutionPayload { width: 1280, height: 720, video_header: vec![0, 0, 0, 1, 0x67] }],
            audio_header: vec![2, 16, 0, 0, 0xbb, 0x80, 0, 0, 0x01, 0xe0, 0, 0, 0, 0],
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn stream_info_needs_a_14_byte_audio_header() {
    let info = stream::parse_stream_info(&stream_info_message()).unwrap();
    assert_eq!(info.resolutions[0].width, 1280);
    assert_eq!(info.resolutions[0].video_header, [0, 0, 0, 1, 0x67]);
    let mut short = stream_info_message();
    short.stream_info_payload.as_mut().unwrap().audio_header.pop();
    assert!(matches!(stream::parse_stream_info(&short), Err(LanError::StreamInfo(_))));
}

/// What the fake console saw: the decoded BIG and the client's messages after stream info, with their
/// channels, and finally the reason in the client's disconnect.
struct Seen {
    big: psr_proto::BigPayload,
    after_info: Vec<(u16, TakionMessage)>,
    disconnect_reason: String,
}

const CONSOLE_TAG: u32 = 0x0bad_cafe;

fn recv(socket: &UdpSocket) -> Vec<u8> {
    let mut buf = [0u8; 1500];
    let (n, _) = socket.recv_from(&mut buf).unwrap();
    buf[..n].to_vec()
}

/// Ways the fake console can behave that chiaki-ng allows for.
#[derive(Clone, Copy, Default)]
struct Quirks {
    /// Send the init ack a second time before the cookie ack.
    repeat_init_ack: bool,
    /// Send stream info before BANG.
    early_stream_info: bool,
    /// Send a video datagram with a bad MAC before the good one.
    forged_video: bool,
}

fn fake_console(socket: UdpSocket, q: Quirks) -> std::thread::JoinHandle<Seen> {
    std::thread::spawn(move || {
        socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 1500];
        let (n, client) = socket.recv_from(&mut buf).unwrap();
        socket.connect(client).unwrap();
        let init = &buf[..n];
        let client_tag = u32::from_be_bytes(init[0x11..0x15].try_into().unwrap());
        let cookie = [0x5a; 32];
        let mut p = Vec::new();
        p.extend_from_slice(&CONSOLE_TAG.to_be_bytes());
        p.extend_from_slice(&0x19000u32.to_be_bytes());
        p.extend_from_slice(&[0, 0x64, 0, 0x64]);
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&cookie);
        let mut ack = vec![0];
        ack.extend_from_slice(&message::header(client_tag, 0, ChunkType::InitAck, 0, p.len() as u16));
        ack.extend(p);
        socket.send(&ack).unwrap();
        let c = recv(&socket);
        assert_eq!(c[1..5], CONSOLE_TAG.to_be_bytes());
        assert_eq!(c[0x11..], cookie);
        if q.repeat_init_ack {
            socket.send(&ack).unwrap();
        }
        let mut cookie_ack = vec![0];
        cookie_ack.extend_from_slice(&message::header(client_tag, 0, ChunkType::CookieAck, 0, 0));
        socket.send(&cookie_ack).unwrap();

        let mut sender = Sender::new(CONSOLE_TAG, client_tag);
        let mut receiver = Receiver::new(CONSOLE_TAG, client_tag);
        // BIG, perhaps in chunks: the first after a 9-byte data header, later ones after 8.
        let mut big = Vec::new();
        loop {
            let d = recv(&socket);
            receiver.handle(&d).unwrap();
            let m = message::parse(&d[1..], CONSOLE_TAG).unwrap();
            big.extend_from_slice(&m.payload[if big.is_empty() { 9 } else { 8 }..]);
            if m.chunk_flags == 1 {
                break;
            }
        }
        let big = TakionMessage::decode(big.as_slice()).unwrap().big_payload.unwrap();
        let spec = base64::engine::general_purpose::STANDARD.decode(&big.launch_spec).unwrap();
        let pad = rpcrypt().encrypt(0, &vec![0; spec.len()]);
        let json = String::from_utf8(spec.iter().zip(&pad).map(|(a, b)| a ^ b).take(spec.len() - 1).collect()).unwrap();
        let hk_b64 = json.split("\"handshakeKey\":\"").nth(1).unwrap().trim_end_matches("\"}");
        let hk: [u8; 16] = base64::engine::general_purpose::STANDARD.decode(hk_b64).unwrap().try_into().unwrap();
        let ecdh = Ecdh::generate().unwrap();
        let secret = ecdh.derive_secret(big.ecdh_pub_key.as_ref().unwrap(), &hk, big.ecdh_sig.as_ref().unwrap()).unwrap();
        let (console_key, console_sig) = ecdh.signed_public_key(&hk);
        if q.early_stream_info {
            let (_, d) = sender.data(1, 1, &stream_info_message().encode_to_vec()).unwrap();
            socket.send(&d).unwrap();
            // Its acknowledgement comes before any keys, so unsigned, as chiaki-ng's would.
            let (got, _) = receiver.handle(&recv(&socket)).unwrap();
            assert!(matches!(got[..], [Received::DataAck { .. }]), "{got:?}");
        }
        // BANG goes out before the keys exist; the client's acknowledgement of it is already signed.
        let (_, d) = sender.data(1, 1, &bang(true, true, Some(console_key.to_vec()), Some(console_sig.to_vec())).encode_to_vec()).unwrap();
        socket.send(&d).unwrap();
        receiver.set_crypt(GkCrypt::new(2, &hk, &secret));
        sender.set_crypt(GkCrypt::new(3, &hk, &secret));
        if !q.early_stream_info {
            let (_, d) = sender.data(1, 1, &stream_info_message().encode_to_vec()).unwrap();
            socket.send(&d).unwrap();
        }

        let mut after_info = Vec::new();
        let mut disconnect_reason = String::new();
        let mut sent_extras = false;
        while disconnect_reason.is_empty() {
            let d = recv(&socket);
            let (got, _) = receiver.handle(&d).expect("the client's datagrams carry valid MACs");
            for r in got {
                let Received::Data { channel, data, .. } = r else { continue };
                let m = TakionMessage::decode(data.as_slice()).unwrap();
                if m.r#type == PayloadType::Disconnect as i32 {
                    disconnect_reason = m.disconnect_payload.unwrap().reason;
                } else {
                    after_info.push((channel, m));
                }
            }
            if after_info.len() == 3 && !sent_extras {
                sent_extras = true;
                // A video datagram, then a disconnect of our own.
                let mut video = vec![0x02u8];
                video.extend_from_slice(&[0; 0x20]);
                if q.forged_video {
                    let mut forged = packet::sign(&GkCrypt::new(3, &hk, &secret), &video, 0).unwrap();
                    forged[0xa] ^= 0xff;
                    socket.send(&forged).unwrap();
                }
                socket.send(&packet::sign(&GkCrypt::new(3, &hk, &secret), &video, 0).unwrap()).unwrap();
                let bye = TakionMessage {
                    r#type: PayloadType::Disconnect as i32,
                    disconnect_payload: Some(psr_proto::DisconnectPayload { reason: "Server shutting down".into(), extended_info: None }),
                    ..Default::default()
                };
                let (_, d) = sender.data(1, 1, &bye.encode_to_vec()).unwrap();
                socket.send(&d).unwrap();
            }
        }
        Seen { big, after_info, disconnect_reason }
    })
}

fn run_against_fake_console(q: Quirks) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr: SocketAddr = socket.local_addr().unwrap();
    let console = fake_console(socket, q);
    let profile = VideoProfile::p720_60(Codec::H264);
    let mut s = stream::connect_at(addr, Target::Ps5V1, SESSION_ID, &rpcrypt(), &profile).unwrap();
    assert_eq!(s.info().resolutions.len(), 1);
    assert_eq!(s.info().audio_header[0], 2);

    let mut events = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !events.iter().any(|e| matches!(e, StreamEvent::Disconnected(_))) {
        assert!(std::time::Instant::now() < deadline, "no disconnect from the fake console; got {events:?}");
        events.extend(s.poll(Duration::from_millis(200)).unwrap());
    }
    assert!(matches!(&events[0], StreamEvent::Av { video: true, .. }), "{events:?}");
    assert_eq!(events.iter().filter(|e| matches!(e, StreamEvent::Av { .. })).count(), 1, "the forged one is not passed on");
    assert_eq!(events.last(), Some(&StreamEvent::Disconnected("Server shutting down".into())));
    assert_eq!(s.dropped(), u64::from(q.forged_video));
    s.disconnect().unwrap();

    let seen = console.join().unwrap();
    assert_eq!(seen.big.client_version, 12);
    assert_eq!(seen.big.session_key, SESSION_ID);
    assert_eq!(seen.big.encrypted_key, [0; 4]);
    let kinds: Vec<(u16, i32)> = seen.after_info.iter().map(|(c, m)| (*c, m.r#type)).collect();
    assert_eq!(
        kinds,
        [
            (9, PayloadType::Streaminfoack as i32),
            (1, PayloadType::Controllerconnection as i32),
            (1, PayloadType::Streaminfo as i32),
        ]
    );
    let mic = seen.after_info[2].1.stream_info_payload.as_ref().unwrap();
    assert_eq!(mic.audio_header, stream::microphone_audio_header());
    assert_eq!(seen.disconnect_reason, "Client Disconnecting");
}

#[test]
fn connect_against_a_fake_console() {
    run_against_fake_console(Quirks::default());
}

#[test]
fn a_repeated_init_ack_is_skipped() {
    run_against_fake_console(Quirks { repeat_init_ack: true, ..Default::default() });
}

#[test]
fn stream_info_before_bang_is_kept() {
    run_against_fake_console(Quirks { early_stream_info: true, ..Default::default() });
}

#[test]
fn a_datagram_with_a_bad_mac_is_dropped_and_counted() {
    run_against_fake_console(Quirks { forged_video: true, ..Default::default() });
}

#[test]
fn connect_times_out_without_a_console() {
    // Bound but silent: INIT goes unanswered.
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = silent.local_addr().unwrap();
    let start = std::time::Instant::now();
    let err = stream::connect_at(addr, Target::Ps5V1, SESSION_ID, &rpcrypt(), &VideoProfile::p720_60(Codec::H264)).unwrap_err();
    assert!(matches!(err, LanError::Timeout("stream init ack")), "{err:?}");
    assert!(start.elapsed() >= Duration::from_secs(14), "three tries of five seconds");
}
