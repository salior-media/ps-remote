// SPDX-License-Identifier: AGPL-3.0-only
// Written from chiaki-ng `lib/src/audioreceiver.c` and `lib/src/audio.c` (LicenseRef-AGPL-3.0-only-OpenSSL),
// which have no tests of their own.

use psr_av::audio::{AudioError, AudioFrame, AudioHeader, AudioReceiver, OPUS_CODEC};
use psr_takion::av::AvPacket;

const UNIT: u8 = 4;

/// An audio packet: `source` new frames from `frame_index` on, then `fec` copies of the frames before it.
/// Each unit is four bytes holding its own frame index, so the test can see which frame is which.
fn packet(frame_index: u16, source: u8, fec: u8) -> (AvPacket<'static>, Vec<u8>) {
    let mut data = Vec::new();
    for i in 0..u16::from(source) {
        data.extend_from_slice(&[0xaa, 0]);
        data.extend_from_slice(&frame_index.wrapping_add(i).to_be_bytes());
    }
    for j in 0..u16::from(fec) {
        data.extend_from_slice(&[0xcc, 0]);
        data.extend_from_slice(&frame_index.wrapping_sub(u16::from(fec)).wrapping_add(j).to_be_bytes());
    }
    let p = AvPacket {
        packet_index: 0,
        frame_index,
        uses_nalu_info_structs: false,
        is_video: false,
        is_haptics: false,
        unit_index: 0,
        units_in_frame_total: u16::from(source) + u16::from(fec),
        units_in_frame_fec: (u16::from(UNIT) << 8) | (u16::from(fec) << 4) | u16::from(source),
        codec: OPUS_CODEC,
        word_at_0x18: 0,
        adaptive_stream_index: 0,
        byte_at_0x2c: 0,
        key_pos: 0,
        data: &[],
    };
    (p, data)
}

fn frames(rx: &mut AudioReceiver, frame_index: u16, source: u8, fec: u8) -> Vec<u16> {
    let (p, data) = packet(frame_index, source, fec);
    let got = rx.av_packet(&AvPacket { data: &data, ..p }).unwrap();
    for f in &got {
        assert_eq!(u16::from_be_bytes([f.data[2], f.data[3]]), f.index, "each frame is the unit for its index");
    }
    got.iter().map(|f: &AudioFrame| f.index).collect()
}

#[test]
fn the_header_reads_like_chiaki_ngs() {
    let h = AudioHeader::load(&[2, 16, 0, 0, 0xbb, 0x80, 0, 0, 0x01, 0xe0, 0, 0, 0, 7]);
    assert_eq!(h, AudioHeader { channels: 2, bits: 16, rate: 48_000, frame_size: 480, unknown: 7 });
}

#[test]
fn new_frames_come_out_once_and_copies_fill_gaps() {
    let mut rx = AudioReceiver::new();
    assert_eq!(frames(&mut rx, 100, 3, 2), [100, 101, 102, 98, 99]);
    // The next packet repeats 101 and 102: already handed on.
    assert_eq!(frames(&mut rx, 103, 3, 2), [103, 104, 105]);
    // The packet with 106 to 108 is lost; the next one's copies bring back 107 and 108.
    assert_eq!(frames(&mut rx, 109, 3, 2), [109, 110, 111, 107, 108]);
}

#[test]
fn at_the_start_copies_of_frames_before_frame_0_are_skipped() {
    let mut rx = AudioReceiver::new();
    assert_eq!(frames(&mut rx, 0, 1, 2), [0]);
    assert_eq!(frames(&mut rx, 1, 1, 2), [1]);
    assert_eq!(frames(&mut rx, 2, 1, 2), [2], "copy 0 (index 2 + 0 < 3) skipped, copy 1 is frame 1, already out");
}

#[test]
fn the_start_rule_ends_once_the_index_passes_half_the_range() {
    let mut rx = AudioReceiver::new();
    frames(&mut rx, 40_000, 1, 2);
    // Past 2^15, chiaki-ng stops skipping, so after the wrap copies of 65534 and 65535 come out.
    let mut rx2 = AudioReceiver::new();
    frames(&mut rx2, 40_000, 1, 0);
    assert_eq!(frames(&mut rx2, 0, 1, 2), [0, 65534, 65535]);
    let mut fresh = AudioReceiver::new();
    assert_eq!(frames(&mut fresh, 0, 1, 2), [0], "a fresh receiver still skips them");
}

#[test]
fn frames_far_behind_the_newest_are_dropped() {
    let mut rx = AudioReceiver::new();
    frames(&mut rx, 1000, 1, 0);
    assert!(frames(&mut rx, 900, 1, 0).is_empty(), "100 frames old");
    assert_eq!(frames(&mut rx, 950, 1, 0), [950], "50 frames old, still in the window");
}

#[test]
fn bad_packets_are_refused() {
    let mut rx = AudioReceiver::new();
    let (p, data) = packet(5, 2, 1);
    assert_eq!(rx.av_packet(&AvPacket { data: &data, codec: 6, ..p.clone() }), Err(AudioError::NotOpus(6)));
    assert_eq!(rx.av_packet(&AvPacket { data: &[], ..p.clone() }), Err(AudioError::Empty));
    assert_eq!(
        rx.av_packet(&AvPacket { data: &data, units_in_frame_total: 4, ..p.clone() }),
        Err(AudioError::UnitCount { source_units: 2, fec_units: 1, total: 4 })
    );
    assert_eq!(
        rx.av_packet(&AvPacket { data: &data[1..], ..p.clone() }),
        Err(AudioError::Size { len: 11, units: 3, unit_size: UNIT })
    );
    assert_eq!(
        rx.av_packet(&AvPacket { data: &data, is_haptics: true, ..p }),
        Ok(Vec::new()),
        "haptics are not passed on"
    );
}
