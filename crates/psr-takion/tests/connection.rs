// SPDX-License-Identifier: AGPL-3.0-only
// Written from chiaki-ng `lib/src/takion.c` (LicenseRef-AGPL-3.0-only-OpenSSL), whose connect and data paths
// have no tests of their own. A second Sender or Receiver plays the console.

use psr_crypto::gkcrypt::GkCrypt;
use psr_takion::TakionError;
use psr_takion::connection::{self, COOKIE_SIZE, InitAck, Received, Receiver, Sender};
use psr_takion::message::{self, ChunkType};
use psr_takion::packet;

const TAG_LOCAL: u32 = 0x1122_3344;
const TAG_REMOTE: u32 = 0x5566_7788;
const COOKIE: [u8; COOKIE_SIZE] = [0xc0; COOKIE_SIZE];

fn crypt(index: u8) -> GkCrypt {
    GkCrypt::new(index, &[0x42; 16], &[0x24; 32])
}

fn init_ack(tag: u32, outbound: u16, inbound: u16) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&tag.to_be_bytes());
    p.extend_from_slice(&0x19000u32.to_be_bytes());
    p.extend_from_slice(&outbound.to_be_bytes());
    p.extend_from_slice(&inbound.to_be_bytes());
    p.extend_from_slice(&0xdead_beefu32.to_be_bytes());
    p.extend_from_slice(&COOKIE);
    let mut d = vec![0];
    d.extend_from_slice(&message::header(TAG_LOCAL, 0, ChunkType::InitAck, 0, p.len() as u16));
    d.extend(p);
    d
}

#[test]
fn init_datagram_layout() {
    let d = connection::init_datagram(TAG_LOCAL, TAG_LOCAL);
    assert_eq!(d.len(), 1 + 0x10 + 0x10);
    assert_eq!(d[0], 0);
    assert_eq!(d[1..5], [0; 4], "the console's tag is not known yet");
    assert_eq!(d[0xd], 1, "INIT");
    assert_eq!(d[0xf..0x11], [0x00, 0x14], "payload length plus 4");
    assert_eq!(d[0x11..0x15], TAG_LOCAL.to_be_bytes());
    assert_eq!(d[0x15..0x19], 0x19000u32.to_be_bytes());
    assert_eq!(d[0x19..0x1d], [0, 0x64, 0, 0x64]);
    assert_eq!(d[0x1d..0x21], TAG_LOCAL.to_be_bytes());
}

#[test]
fn cookie_datagram_echoes_the_cookie() {
    let d = connection::cookie_datagram(TAG_REMOTE, &COOKIE);
    assert_eq!(d[1..5], TAG_REMOTE.to_be_bytes());
    assert_eq!(d[0xd], 0xa);
    assert_eq!(d[0x11..], COOKIE);
}

#[test]
fn init_ack_parses() {
    let ack = connection::parse_init_ack(&init_ack(TAG_REMOTE, 0x64, 0x64), TAG_LOCAL).unwrap();
    assert_eq!(
        ack,
        InitAck { tag: TAG_REMOTE, a_rwnd: 0x19000, outbound_streams: 0x64, inbound_streams: 0x64, initial_seq_num: 0xdead_beef, cookie: COOKIE }
    );
}

#[test]
fn init_ack_checks() {
    let parse = |d: &[u8]| connection::parse_init_ack(d, TAG_LOCAL);
    assert!(matches!(parse(&init_ack(0, 0x64, 0x64)), Err(TakionError::Unexpected(_))), "remote tag 0");
    assert!(parse(&init_ack(TAG_REMOTE, 0x65, 0x64)).is_err(), "more outbound streams than our inbound");
    assert!(parse(&init_ack(TAG_REMOTE, 0x64, 0x63)).is_err(), "fewer inbound streams than our outbound");
    assert!(parse(&init_ack(TAG_REMOTE, 0, 0x64)).is_err());
    assert!(connection::parse_init_ack(&init_ack(TAG_REMOTE, 0x64, 0x64), TAG_LOCAL + 1).is_err(), "not our tag");
    let mut wrong = init_ack(TAG_REMOTE, 0x64, 0x64);
    wrong[0xd] = 0xb;
    assert!(parse(&wrong).is_err(), "a cookie ack is not an init ack");
    assert!(connection::is_init_ack_repeat(&init_ack(TAG_REMOTE, 0x64, 0x64)));
}

#[test]
fn cookie_ack() {
    let mut d = vec![0];
    d.extend_from_slice(&message::header(TAG_LOCAL, 0, ChunkType::CookieAck, 0, 0));
    assert!(connection::is_cookie_ack(&d, TAG_LOCAL).is_ok());
    d[0xe] = 1;
    assert!(connection::is_cookie_ack(&d, TAG_LOCAL).is_err(), "flags must be 0");
}

#[test]
fn data_before_keys_has_no_mac_and_key_position_0() {
    let mut s = Sender::new(TAG_LOCAL, TAG_REMOTE);
    let (seq, d) = s.data(1, 1, b"hello").unwrap();
    assert_eq!(seq, TAG_LOCAL, "our sequence numbers start at our tag");
    assert_eq!(d[1..5], TAG_REMOTE.to_be_bytes());
    assert_eq!(d[5..9], [0; 4], "no MAC");
    assert_eq!(d[9..13], [0; 4], "key position 0");
    assert_eq!(d[0xd..0xf], [0, 1], "DATA, last chunk");
    assert_eq!(d[0xf..0x11], (9u16 + 5 + 4).to_be_bytes());
    assert_eq!(d[0x11..0x15], TAG_LOCAL.to_be_bytes());
    assert_eq!(d[0x15..0x1a], [0, 1, 0, 0, 0], "channel 1, two zero bytes, protobuf");
    assert_eq!(&d[0x1a..], b"hello");
    assert_eq!(s.next_seq_num(), TAG_LOCAL + 1);
    assert_eq!(s.key_pos(), 0);
}

#[test]
fn data_with_keys_advances_like_chiaki_ng_and_verifies() {
    let mut s = Sender::new(TAG_LOCAL, TAG_REMOTE);
    s.set_crypt(crypt(2));
    let (_, first) = s.data(1, 1, &[7; 20]).unwrap();
    // 20 bytes advance by 20 + 20 % 16 = 24.
    assert_eq!(s.key_pos(), 24);
    let (_, second) = s.data(1, 1, &[7; 3]).unwrap();
    assert_eq!(second[9..13], 24u32.to_be_bytes());
    assert_eq!(s.key_pos(), 24 + 6);
    // The console checks it with the same keys.
    let console = crypt(2);
    let (pos, state) = packet::verify(&console, &first, Default::default()).unwrap();
    assert_eq!(pos, 0);
    assert_eq!(packet::verify(&console, &second, state).unwrap().0, 24);
    let mut forged = second.clone();
    forged[0x1b] ^= 1;
    assert!(packet::verify(&console, &forged, state).is_err());
}

#[test]
fn data_ack_layout() {
    let mut s = Sender::new(TAG_LOCAL, TAG_REMOTE);
    s.set_crypt(crypt(2));
    let d = s.data_ack(0x0102_0304).unwrap();
    assert_eq!(d.len(), 1 + 0x10 + 0xc);
    assert_eq!(d[0xd], 3);
    assert_eq!(d[0x11..0x1d], [1, 2, 3, 4, 0, 1, 0x90, 0, 0, 0, 0, 0]);
    // chiaki-ng advances by the whole datagram: 29 + 29 % 16.
    assert_eq!(s.key_pos(), 29 + 13);
}

#[test]
fn split_data_by_mtu() {
    let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
    let mut s = Sender::new(TAG_LOCAL, TAG_REMOTE);
    let chunks = s.split_data(1, &data, 426).unwrap();
    // 400 bytes, then 401, then the last 199.
    let sizes: Vec<usize> = chunks.iter().map(Vec::len).collect();
    assert_eq!(sizes, [1 + 16 + 9 + 400, 1 + 16 + 8 + 401, 1 + 16 + 8 + 199]);
    let flags: Vec<u8> = chunks.iter().map(|c| c[0xe]).collect();
    assert_eq!(flags, [0, 0, 1]);
    let joined: Vec<u8> = [&chunks[0][26..], &chunks[1][25..], &chunks[2][25..]].concat();
    assert_eq!(joined, data);
    // A message that fits is one chunk with flags 1.
    let one = s.split_data(1, &data[..100], 426).unwrap();
    assert_eq!(one.len(), 1);
    assert_eq!(one[0][0xe], 1);
    assert_eq!(one[0].len(), 26 + 100);
}

/// A data datagram as the console sends it to us.
fn console_data(console: &mut Sender, payload: &[u8]) -> (u32, Vec<u8>) {
    console.data(1, 1, payload).unwrap()
}

#[test]
fn receiver_delivers_in_order_and_names_the_ack() {
    let mut console = Sender::new(TAG_REMOTE, TAG_LOCAL);
    let (s0, d0) = console_data(&mut console, b"zero");
    let (s1, d1) = console_data(&mut console, b"one");
    let (_, d2) = console_data(&mut console, b"two");
    let mut r = Receiver::new(TAG_LOCAL, TAG_REMOTE);
    assert_eq!(s0, TAG_REMOTE, "the console's sequence numbers start at its tag");
    let (got, ack) = r.handle(&d1).unwrap();
    assert!(got.is_empty() && ack.is_none(), "waits for the first");
    let (got, ack) = r.handle(&d0).unwrap();
    assert_eq!(ack, Some(s1));
    assert_eq!(
        got,
        [
            Received::Data { data_type: 0, channel: 1, data: b"zero".to_vec() },
            Received::Data { data_type: 0, channel: 1, data: b"one".to_vec() },
        ]
    );
    assert_eq!(r.handle(&d2).unwrap().0.len(), 1);
}

#[test]
fn receiver_reads_a_data_ack() {
    let mut console = Sender::new(TAG_REMOTE, TAG_LOCAL);
    let mut r = Receiver::new(TAG_LOCAL, TAG_REMOTE);
    let (got, ack) = r.handle(&console.data_ack(TAG_LOCAL + 4).unwrap()).unwrap();
    assert_eq!(got, [Received::DataAck { cumulative_seq_num: TAG_LOCAL + 4 }]);
    assert_eq!(ack, None);
}

#[test]
fn receiver_checks_macs_once_keys_are_set() {
    let mut console = Sender::new(TAG_REMOTE, TAG_LOCAL);
    console.set_crypt(crypt(3));
    let mut r = Receiver::new(TAG_LOCAL, TAG_REMOTE);
    r.set_crypt(crypt(3));
    let (_, good) = console_data(&mut console, b"signed");
    let (_, next) = console_data(&mut console, b"next");
    let mut forged = next.clone();
    forged[5] ^= 0xff;
    assert!(matches!(r.handle(&forged), Err(TakionError::BadMac { .. })));
    assert_eq!(r.key_state(), Default::default(), "a forged datagram moves nothing");
    assert_eq!(r.handle(&good).unwrap().0.len(), 1);
    assert_eq!(r.handle(&next).unwrap().0.len(), 1);
    // Signed with the wrong keys.
    let mut other = Sender::new(TAG_REMOTE, TAG_LOCAL);
    other.set_crypt(crypt(2));
    assert!(r.handle(&console_data(&mut other, b"x").1).is_err());
}

#[test]
fn av_before_keys_is_postponed() {
    let mut r = Receiver::new(TAG_LOCAL, TAG_REMOTE);
    let mut video = vec![0x02u8];
    video.extend_from_slice(&[0; 0x20]);
    assert_eq!(r.handle(&video).unwrap(), (vec![], None));
    let back = r.set_crypt(crypt(3));
    assert_eq!(back, [video]);
}

#[test]
fn a_verified_av_datagram_moves_the_key_state() {
    let mut r = Receiver::new(TAG_LOCAL, TAG_REMOTE);
    r.set_crypt(crypt(3));
    let mut video = vec![0x02u8];
    video.extend_from_slice(&[0; 0x20]);
    video[0xe..0x12].copy_from_slice(&1000u32.to_be_bytes());
    let signed = packet::sign(&crypt(3), &video, 1000).unwrap();
    let (got, _) = r.handle(&signed).unwrap();
    assert_eq!(got, [Received::Av(signed)]);
    assert_eq!(r.key_state(), psr_crypto::gkcrypt::KeyState::default().commit(1000));
}
