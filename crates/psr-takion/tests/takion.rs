// SPDX-License-Identifier: AGPL-3.0-only
// Ported from chiaki-ng `test/takion.c`, `test/takion_av_packet_parse_real_video.inl`, `test/seqnum.c` and
// `test/reorderqueue.c` (LicenseRef-AGPL-3.0-only-OpenSSL). Byte arrays were extracted from those files
// by script (scripts/extract_tables.py, scripts/convert_real_video.py), not retyped.

use base64::Engine;
use psr_crypto::gkcrypt::{GkCrypt, KeyState};
use psr_takion::TakionError;
use psr_takion::av::{self, AvVersion};
use psr_takion::message::{self, ChunkType};
use psr_takion::packet::{self, Congestion, PacketType};
use psr_takion::reorder::{DropStrategy, ReorderQueue};
use psr_takion::send_buffer::SendBuffer;
use psr_takion::seqnum::SeqNum;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().unwrap()
}

const AV_PACKET: &str = "02002d000500c01c0103000000000000e41003670029f32f98f699828378db2943a9e588f2110420e62096e906ee0d27a1838288e62149027574325bf6e9dc93ea31880d2b4b34f9ec1b26ccbbbb81f2d92d8ea1b9e2b3cab27da331f042b7b61e8f6da27046fd7e9b6085b0ed4f20b50171a9aa186b2a90f3a78436fd6d148368a39b3ac8d43a31a09b61dea7ed46b4a3df3f448fad6409fc7ae724f0d242d3575a7600c5e093a9f5325deef79d";

// --- test/takion.c ---

#[test]
fn av_packet_parse() {
    let packet = hex(AV_PACKET);
    let p = av::parse(AvVersion::V9, &packet, KeyState::default()).unwrap();
    assert!(p.is_video);
    assert_eq!(p.packet_index, 45);
    assert_eq!(p.frame_index, 5);
    assert_eq!(p.unit_index, 6);
    assert_eq!(p.units_in_frame_total, 8);
    assert_eq!(p.units_in_frame_fec, 1);
    assert_eq!(p.codec, 3);
    assert_eq!(p.adaptive_stream_index, 0);
    // chiaki-ng checks the data pointer is packet + 0x15 and the size 0x99.
    assert_eq!(p.data.as_ptr(), packet[0x15..].as_ptr());
    assert_eq!(p.data.len(), 0x99);
}

#[test]
fn av_packet_parse_real_video() {
    let text = include_str!("vectors/real_video.txt");
    let mut lines = text.lines().filter(|l| !l.starts_with('#'));
    let key: Vec<&str> = lines.next().unwrap().split(' ').collect();
    assert_eq!(key[0], "key");
    let crypt = GkCrypt::new(key[3].parse().unwrap(), &arr(key[1]), &arr(key[2]));
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut state = KeyState::default();
    let mut n = 0;
    for line in lines {
        let f: Vec<&str> = line.split(' ').collect();
        let packet = b64.decode(f[2]).unwrap();
        assert_eq!(packet.len(), f[1].parse::<usize>().unwrap(), "packet {}", f[0]);
        let nalu = b64.decode(f[4]).unwrap();
        assert_eq!(nalu.len(), f[3].parse::<usize>().unwrap(), "nalu {}", f[0]);
        let p = av::parse(AvVersion::V9, &packet, state).unwrap();
        assert!(p.is_video, "packet {}", f[0]);
        assert_eq!(p.data.len(), nalu.len(), "packet {}", f[0]);
        assert_eq!(crypt.crypt(p.key_pos + 16, p.data), nalu, "packet {}", f[0]);
        // chiaki-ng commits inside the parse; here the caller does.
        state = state.commit(p.key_pos);
        n += 1;
    }
    assert_eq!(n, 24);
}

#[test]
fn send_buffer_acks_everything_up_to_the_acked_number() {
    const COUNT: usize = 0x30;
    // chiaki-ng uses munit's random numbers; this is a fixed xorshift so a failure always reproduces.
    let mut x: u32 = 0x9e37_79b9;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    let mut nums: Vec<u32> = Vec::new();
    while nums.len() < COUNT + 1 {
        let n = next();
        if !nums.contains(&n) {
            nums.push(n);
        }
    }
    let mut buf = SendBuffer::new(COUNT);
    for &n in &nums[..COUNT] {
        buf.push(n, vec![0; 8]).unwrap();
    }
    assert_eq!(buf.push(nums[COUNT], vec![0; 8]), Err(TakionError::SendBufferFull(COUNT)));
    // As in chiaki-ng: ack near the last waiting number, ±32. A negative offset may leave it waiting; the
    // next round tries again, and a non-negative one always removes it, so the loop ends.
    let mut expected = nums[..COUNT].to_vec();
    let mut rounds = 0;
    while !expected.is_empty() {
        let delta = i64::from(next() % 65) - 32;
        let ack = (i64::from(*expected.last().unwrap()) + delta) as u32;
        let acked = buf.ack(ack);
        let before = expected.len();
        expected.retain(|&n| !(n == ack || n.lt(ack)));
        assert_eq!(acked.len(), before - expected.len(), "after ack {ack:#x}");
        let mut have: Vec<u32> = buf.pending().iter().map(|p| p.seq_num).collect();
        let mut want = expected.clone();
        have.sort_unstable();
        want.sort_unstable();
        assert_eq!(have, want, "after ack {ack:#x}");
        rounds += 1;
        assert!(rounds < 10_000, "acks stopped making progress");
    }
    assert!(buf.is_empty());
}

#[test]
fn format_congestion_and_its_mac() {
    let crypt = GkCrypt::new(
        2,
        &arr("54654c345cac56b8eae6152ade1ce2e8"),
        &arr("0034f821c7d9dea9e911ca5ad67d11ce4f02b1ce1ee7c38d5439fa64e3dbd80d"),
    );
    let key_pos = 0x1e5;
    let buf = Congestion { word_0: 0x42, received: 26, lost: 10 }.format(key_pos);
    assert_eq!(buf.to_vec(), hex("050042001a000a000000000000 01e5".replace(' ', "").as_str()));
    let signed = packet::sign(&crypt, &buf, key_pos).unwrap();
    assert_eq!(signed, hex("050042001a000a648a7c74000001e5"));
}

// --- test/seqnum.c ---

#[test]
fn seq_num_16() {
    let mut a: u16 = 0;
    loop {
        let b = a.wrapping_add(1);
        assert!(b.gt(a) && !a.gt(b) && a.lt(b) && !b.lt(a), "a = {a}");
        a = b;
        if a == 0 {
            break;
        }
    }
    let mut a: u16 = 0;
    loop {
        let b = a.wrapping_add(0xfff);
        assert!(b.gt(a) && !a.gt(b) && a.lt(b) && !b.lt(a), "a = {a}");
        a = a.wrapping_add(1);
        if a == 0 {
            break;
        }
    }
    assert!(1u16.gt(0xfff5));
    assert!(!0xfff5u16.gt(1));
}

#[test]
fn seq_num_32() {
    assert!(1u32.gt(0));
    assert!(!0u32.gt(1));
    assert!(!1u32.lt(0));
    assert!(0u32.lt(1));
    assert!(1u32.gt(0xffff_fff5));
    assert!(!0xffff_fff5u32.gt(1));
}

// --- test/reorderqueue.c ---

#[test]
fn reorder_queue_16() {
    let mut q: ReorderQueue<u16, u32> = ReorderQueue::new(2, 42);
    assert_eq!(q.size(), 4);
    assert_eq!(q.count(), 0);
    q.drop_strategy = DropStrategy::End;

    assert_eq!(q.pull(), None);
    assert!(q.push(42, 0).is_empty());
    assert_eq!(q.count(), 1);
    assert_eq!(q.pull(), Some((42, 0)));
    assert_eq!(q.count(), 0);

    // outdated
    assert_eq!(q.push(42, 0), vec![(42, 0)]);
    assert_eq!(q.count(), 0);

    // fill out of order, nothing pullable until the head arrives
    assert!(q.push(46, 1).is_empty());
    assert_eq!(q.pull(), None);
    assert!(q.push(45, 2).is_empty());
    assert_eq!(q.pull(), None);
    assert!(q.push(44, 3).is_empty());
    assert_eq!(q.pull(), None);
    assert!(q.push(43, 4).is_empty());

    // full: under End the newcomer is dropped
    assert_eq!(q.push(47, 5), vec![(47, 5)]);
    // under Begin the oldest goes
    q.drop_strategy = DropStrategy::Begin;
    assert_eq!(q.push(47, 5), vec![(43, 4)]);

    assert_eq!(q.pull(), Some((44, 3)));
    assert_eq!(q.pull(), Some((45, 2)));
    assert_eq!(q.pull(), Some((46, 1)));
    assert_eq!(q.pull(), Some((47, 5)));
    assert_eq!(q.pull(), None);
    assert_eq!(q.count(), 0);

    // far ahead: relocate
    assert!(q.push(1337, 6).is_empty());
    assert_eq!(q.count(), 1);
    assert_eq!(q.pull(), Some((1337, 6)));
    assert_eq!(q.count(), 0);

    // far ahead with one waiting: it is dropped
    assert!(q.push(1338, 7).is_empty());
    assert_eq!(q.count(), 1);
    assert_eq!(q.push(2000, 8), vec![(1338, 7)]);
    assert_eq!(q.count(), 1);
    assert_eq!(q.pull(), Some((2000, 8)));
    assert_eq!(q.count(), 0);
}

#[test]
fn reorder_queue_drop() {
    let mut q: ReorderQueue<u16, u32> = ReorderQueue::new(2, 42);
    for (s, v) in [(42, 0), (43, 1), (44, 2)] {
        assert!(q.push(s, v).is_empty());
    }
    assert_eq!(q.count(), 3);
    // drop the head: it can no longer be peeked or pulled
    assert_eq!(q.drop_at(0), Some((42, 0)));
    assert_eq!(q.peek(0), None);
    assert_eq!(q.pull(), None);
    // dropping it again does nothing
    assert_eq!(q.drop_at(0), None);
    // drop the tail: the window shrinks to the last element still there
    assert_eq!(q.drop_at(2), Some((44, 2)));
    assert_eq!(q.count(), 2);
    // a packet into the dropped head slot is pulled, then the remaining one
    assert!(q.push(42, 3).is_empty());
    assert_eq!(q.pull(), Some((42, 3)));
    assert_eq!(q.pull(), Some((43, 1)));
    assert_eq!(q.count(), 0);
}

// --- Not in chiaki-ng ---

/// A datagram laid out as chiaki-ng's `av_packet_parse` reads it: type, packet and frame index, the unit
/// dword, codec, MAC, key position, then the per-kind bytes. Built by hand: chiaki-ng has no v12 vector.
fn av_datagram(first: u8, after_key_pos: &[u8], data: &[u8]) -> Vec<u8> {
    let mut d = vec![first, 0, 7, 0, 3, 0, 0, 0x21, 0x02, 3, 0, 0, 0, 0, 0, 0, 0x10, 0];
    d.extend_from_slice(after_key_pos);
    d.extend_from_slice(data);
    d
}

#[test]
fn v12_audio_reads_the_haptics_flag_and_v9_audio_has_none() {
    let data = [0xaa, 0xbb, 0xcc];
    let (haptic, not_haptic) = (av_datagram(0x03, &[0x00, 0x02], &data), av_datagram(0x03, &[0x00, 0x01], &data));
    // v12 audio: one unknown byte, then the haptics flag
    let p = av::parse(AvVersion::V12, &haptic, KeyState::default()).unwrap();
    assert!(!p.is_video && p.is_haptics);
    assert_eq!(p.data, data);
    assert_eq!((p.packet_index, p.frame_index, p.key_pos), (7, 3, 0x1000));
    let p = av::parse(AvVersion::V12, &not_haptic, KeyState::default()).unwrap();
    assert!(!p.is_haptics);
    // v9 audio: the same bytes, but the second one is already data
    let p = av::parse(AvVersion::V9, &haptic, KeyState::default()).unwrap();
    assert!(!p.is_haptics);
    assert_eq!(p.data, [0x02, 0xaa, 0xbb, 0xcc]);
}

#[test]
fn the_nalu_info_flag_skips_three_bytes_before_the_data() {
    let video_tail = [0x03, 0x67, 0x20]; // word_at_0x18 = 0x0367, adaptive stream index 1
    let plain = av_datagram(0x02, &video_tail, &[1, 2, 3, 4, 5, 6]);
    let flagged = av_datagram(0x12, &video_tail, &[9, 9, 9, 4, 5, 6]);
    let a = av::parse(AvVersion::V9, &plain, KeyState::default()).unwrap();
    let b = av::parse(AvVersion::V9, &flagged, KeyState::default()).unwrap();
    assert_eq!((a.word_at_0x18, a.adaptive_stream_index), (0x0367, 1));
    assert_eq!(a.data, [1, 2, 3, 4, 5, 6]);
    assert!(b.uses_nalu_info_structs);
    assert_eq!(b.data, [4, 5, 6]);
}

#[test]
fn exactly_half_the_space_apart_is_neither_greater_nor_less_either_way() {
    for a in [0u16, 1, 42, 0x7fff, 0x8000, 0xffff] {
        let b = a.wrapping_add(0x8000);
        assert!(!a.gt(b) && !a.lt(b) && !b.gt(a) && !b.lt(a), "a = {a:#x}");
    }
    for a in [0u32, 7, 0x8000_0000, 0xffff_ffff] {
        let b = a.wrapping_add(0x8000_0000);
        assert!(!a.gt(b) && !a.lt(b) && !b.gt(a) && !b.lt(a), "a = {a:#x}");
    }
}

#[test]
fn a_number_exactly_half_the_space_away_rebases_an_empty_begin_queue_and_is_dropped_otherwise() {
    let far = 42u16.wrapping_add(0x8000);
    let mut q: ReorderQueue<u16, u32> = ReorderQueue::new(2, 42);
    q.drop_strategy = DropStrategy::Begin;
    assert!(q.push(far, 1).is_empty());
    assert_eq!(q.pull(), Some((far, 1)));
    let mut q: ReorderQueue<u16, u32> = ReorderQueue::new(2, 42);
    assert_eq!(q.push(far, 1), vec![(far, 1)]);
    assert_eq!(q.count(), 0);
}

#[test]
fn acking_an_exact_number_removes_it_and_everything_before_it_only() {
    let mut buf = SendBuffer::new(8);
    for n in [10u32, 11, 12, 13] {
        buf.push(n, vec![]).unwrap();
    }
    assert_eq!(buf.push(11, vec![]), Err(TakionError::DuplicateSeqNum(11)));
    assert_eq!(buf.ack(12), vec![10, 11, 12]);
    assert_eq!(buf.pending().iter().map(|p| p.seq_num).collect::<Vec<_>>(), vec![13]);
    // across the wrap: 0xffff_fffe is serially before 1
    let mut buf = SendBuffer::new(4);
    buf.push(0xffff_fffe, vec![]).unwrap();
    buf.push(1, vec![]).unwrap();
    buf.push(5, vec![]).unwrap();
    assert_eq!(buf.ack(1), vec![0xffff_fffe, 1]);
}

#[test]
fn a_short_audio_packet_with_the_nalu_flag_is_refused_not_overread() {
    // v9 audio: type 3 with the NALU-info flag (0x10), exactly header + 1 bytes long. chiaki-ng would skip
    // three bytes past the end here and wrap its size_t length.
    let mut packet = vec![0u8; 1 + av::V9_AV_HEADER_SIZE_AUDIO + 1];
    packet[0] = 0x13;
    assert!(matches!(av::parse(AvVersion::V9, &packet, KeyState::default()), Err(TakionError::TooShort { .. })));
}

#[test]
fn a_tampered_datagram_fails_verification_and_the_key_state_does_not_move() {
    let crypt = GkCrypt::new(3, &[1; 16], &[2; 32]);
    let state = KeyState::default();
    let mut packet = hex(AV_PACKET);
    let key_pos = state.request_pos(packet::key_pos_low(&packet).unwrap());
    let signed = packet::sign(&crypt, &packet, key_pos).unwrap();
    let (pos, next) = packet::verify(&crypt, &signed, state).unwrap();
    assert_eq!(pos, key_pos);
    assert_eq!(next, state.commit(key_pos));
    packet.clone_from(&signed);
    packet[0x20] ^= 1;
    assert_eq!(packet::verify(&crypt, &packet, state), Err(TakionError::BadMac { key_pos }));
}

#[test]
fn message_header_round_trips_and_wrong_tags_or_lengths_are_refused() {
    let payload = [9u8, 8, 7];
    let mut buf = message::header(0xdead_beef, 0x1_0000_0042, ChunkType::Data, 1, payload.len() as u16).to_vec();
    buf.extend_from_slice(&payload);
    let m = message::parse(&buf, 0xdead_beef).unwrap();
    assert_eq!((m.tag, m.key_pos_low, m.chunk_type, m.chunk_flags, m.payload), (0xdead_beef, 0x42, ChunkType::Data, 1, &payload[..]));
    assert!(matches!(message::parse(&buf, 1), Err(TakionError::TagMismatch { .. })));
    assert!(matches!(message::parse(&buf[..buf.len() - 1], 0xdead_beef), Err(TakionError::LengthMismatch { .. })));
}

#[test]
fn packet_types_and_their_offsets() {
    assert_eq!(PacketType::of(&[0x12]).unwrap(), PacketType::Video);
    assert_eq!(PacketType::of(&[0x07]), Err(TakionError::UnknownType(7)));
    assert_eq!(PacketType::Video.mac_offset(), Some(0xa));
    assert_eq!(PacketType::Handshake.mac_offset(), None);
}
