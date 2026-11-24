// SPDX-License-Identifier: AGPL-3.0-only
// Written from chiaki-ng `lib/src/frameprocessor.c` and `lib/src/videoreceiver.c`
// (LicenseRef-AGPL-3.0-only-OpenSSL), which have no tests of their own. The FEC units come from psr-fec,
// whose encoder is checked byte for byte against chiaki-ng's Jerasure vectors, so a frame rebuilt here
// is rebuilt the way the console's encoder means it.

use psr_av::frame::{self, FlushResult, FrameError, FrameProcessor};
use psr_av::video::{Frame, VideoEvent, VideoReceiver};
use psr_takion::av::AvPacket;

const UNIT: usize = 64;
const HEADER: &[u8] = &[0, 0, 0, 1, 0x67, 0x42];

fn frame_bytes(index: u16, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31) ^ index as u8).collect()
}

fn packet(frame_index: u16, unit_index: u16, total: u16, fec: u16, data: &[u8]) -> AvPacket<'_> {
    AvPacket {
        packet_index: 0,
        frame_index,
        uses_nalu_info_structs: false,
        is_video: true,
        is_haptics: false,
        unit_index,
        units_in_frame_total: total,
        units_in_frame_fec: fec,
        codec: 6,
        word_at_0x18: 0,
        adaptive_stream_index: 0,
        byte_at_0x2c: 0,
        key_pos: 0,
        data,
    }
}

/// Sends a frame of `len` bytes with `fec` FEC units, leaving out the units in `lost`.
fn send(rx: &mut VideoReceiver, index: u16, len: usize, fec: usize, lost: &[usize]) -> Vec<VideoEvent> {
    let units = frame::split_frame(&frame_bytes(index, len), UNIT, fec).unwrap();
    let total = units.len() as u16;
    let mut events = Vec::new();
    for (i, u) in units.iter().enumerate() {
        if !lost.contains(&i) {
            events.extend(rx.av_packet(&packet(index, i as u16, total, fec as u16, u)));
        }
    }
    events
}

fn frames(events: &[VideoEvent]) -> Vec<&Frame> {
    events.iter().filter_map(|e| if let VideoEvent::Frame(f) = e { Some(f) } else { None }).collect()
}

fn receiver() -> VideoReceiver {
    VideoReceiver::new(vec![HEADER.to_vec()])
}

#[test]
fn a_whole_frame_comes_out_after_the_codec_header() {
    let mut rx = receiver();
    let events = send(&mut rx, 1, 300, 2, &[]);
    assert_eq!(events[0], VideoEvent::Header { profile: 0, data: HEADER.to_vec() });
    let f = frames(&events);
    assert_eq!(f.len(), 1);
    assert_eq!((f[0].index, f[0].fec_recovered, f[0].frames_lost), (1, false, 0));
    assert_eq!(f[0].data, frame_bytes(1, 300));
    assert_eq!(events.len(), 2, "no corrupt-frame report for frame 1: {events:?}");
}

#[test]
fn lost_source_units_are_rebuilt_with_fec() {
    let mut rx = receiver();
    // 300 bytes in 62-byte chunks: units 0..=4 are source, 5 and 6 are FEC.
    for lost in [vec![0], vec![4], vec![1, 3], vec![0, 4]] {
        let mut rx2 = receiver();
        let f = send(&mut rx2, 1, 300, 2, &lost);
        let f = frames(&f);
        assert_eq!(f.len(), 1, "lost {lost:?}");
        assert!(f[0].fec_recovered);
        assert_eq!(f[0].data, frame_bytes(1, 300), "lost {lost:?}");
    }
    // Losing an FEC unit needs no recovery.
    let f = send(&mut rx, 1, 300, 2, &[6]);
    assert!(!frames(&f)[0].fec_recovered);
}

#[test]
fn a_frame_beyond_fec_is_reported_and_counted() {
    let mut rx = receiver();
    assert_eq!(frames(&send(&mut rx, 1, 300, 1, &[])).len(), 1);
    // Two units lost with one FEC unit: rebuilding is tried at the frame's last unit, and fails.
    let events = send(&mut rx, 2, 300, 1, &[1, 2]);
    assert_eq!(events, [VideoEvent::CorruptFrames { start: 2, end: 2 }]);
    // chiaki-ng reports frame 2 again when frame 3 starts: frame 1 is still the last one rebuilt.
    let events = send(&mut rx, 3, 300, 1, &[]);
    assert_eq!(events[0], VideoEvent::CorruptFrames { start: 2, end: 2 });
    let f = frames(&events);
    assert_eq!((f[0].index, f[0].frames_lost), (3, 1));
    assert_eq!(rx.frames_lost_total(), 1);
    let events = send(&mut rx, 4, 300, 1, &[]);
    assert_eq!(frames(&events)[0].frames_lost, 0, "the count starts again after each frame handed on");
}

#[test]
fn a_frame_whose_last_unit_is_lost_is_rebuilt_when_the_next_one_starts() {
    let mut rx = receiver();
    // 300 bytes: five source units and one FEC unit. Units 3 and 5 are lost, so neither "enough units"
    // nor "last unit" ever triggers; frame 2's first packet does.
    let events = send(&mut rx, 1, 300, 1, &[3, 5]);
    assert!(frames(&events).is_empty(), "{events:?}");
    let events = send(&mut rx, 2, 300, 1, &[]);
    assert_eq!(events[0], VideoEvent::CorruptFrames { start: 1, end: 1 }, "frame 1 failed FEC");
    assert_eq!(events[1], VideoEvent::CorruptFrames { start: 1, end: 1 }, "and is still missing as frame 2 opens");
    assert_eq!(frames(&events)[0].index, 2);
}

#[test]
fn a_frame_that_never_arrived_is_reported() {
    let mut rx = receiver();
    send(&mut rx, 1, 100, 1, &[]);
    let events = send(&mut rx, 4, 100, 1, &[]);
    assert_eq!(events[0], VideoEvent::CorruptFrames { start: 2, end: 3 });
    assert_eq!(frames(&events)[0].index, 4);
    // chiaki-ng counts only frames that failed FEC.
    assert_eq!(rx.frames_lost_total(), 0);
}

#[test]
fn the_first_frame_need_not_be_frame_one() {
    let mut rx = receiver();
    let events = send(&mut rx, 5, 100, 1, &[]);
    assert_eq!(events[1], VideoEvent::CorruptFrames { start: 1, end: 4 }, "chiaki-ng excuses frame 1 only");
    let mut rx = receiver();
    assert!(!send(&mut rx, 1, 100, 1, &[]).iter().any(|e| matches!(e, VideoEvent::CorruptFrames { .. })));
}

#[test]
fn packets_of_a_passed_frame_and_duplicates_are_ignored() {
    let mut rx = receiver();
    let units = frame::split_frame(&frame_bytes(1, 100), UNIT, 1).unwrap();
    let total = units.len() as u16;
    send(&mut rx, 2, 100, 1, &[]);
    assert!(rx.av_packet(&packet(1, 0, total, 1, &units[0])).is_empty(), "frame 1 is older than frame 2");
    assert_eq!(rx.units_refused(), 0, "an old frame's packet never reaches the frame processor");
    let mut rx = receiver();
    rx.av_packet(&packet(1, 0, total, 1, &units[0]));
    rx.av_packet(&packet(1, 0, total, 1, &units[0]));
    assert_eq!(rx.units_refused(), 1);
}

#[test]
fn frame_indices_wrap() {
    let mut rx = receiver();
    send(&mut rx, 65534, 100, 1, &[]);
    assert_eq!(send(&mut rx, 65535, 100, 1, &[0, 1]), [VideoEvent::CorruptFrames { start: 65535, end: 65535 }]);
    // 65535 failed FEC and 0 never came: one report across the wrap.
    let events = send(&mut rx, 1, 100, 1, &[]);
    assert_eq!(events[0], VideoEvent::CorruptFrames { start: 65535, end: 0 });
    let f = frames(&events);
    assert_eq!((f[0].index, f[0].frames_lost), (1, 1));
    assert_eq!(rx.frames_lost_total(), 1);
}

#[test]
fn a_new_profile_sends_its_header_and_an_unknown_one_is_refused() {
    let mut rx = VideoReceiver::new(vec![HEADER.to_vec(), vec![0, 0, 0, 1, 0x67, 0x64]]);
    let units = frame::split_frame(&frame_bytes(1, 50), UNIT, 1).unwrap();
    let mut p = packet(1, 0, units.len() as u16, 1, &units[0]);
    p.adaptive_stream_index = 1;
    assert_eq!(rx.av_packet(&p)[0], VideoEvent::Header { profile: 1, data: vec![0, 0, 0, 1, 0x67, 0x64] });
    p.adaptive_stream_index = 2;
    assert!(rx.av_packet(&p).is_empty());
    assert_eq!(rx.units_refused(), 1);
}

#[test]
fn frame_processor_refuses_bad_shapes_and_units() {
    let mut fp = FrameProcessor::new();
    let u = vec![0, 0, 1, 2, 3];
    assert_eq!(fp.alloc_frame(&packet(1, 0, 2, 3, &u)), Err(FrameError::FecAboveTotal { total: 2, fec: 3 }));
    assert_eq!(fp.alloc_frame(&packet(1, 0, 600, 1, &u)), Err(FrameError::TooManyUnits(600)));
    assert_eq!(fp.alloc_frame(&packet(1, 0, 2, 1, &[7])), Err(FrameError::NoPaddingField(1)));
    assert_eq!(fp.put_unit(&packet(1, 0, 2, 1, &u)), Err(FrameError::NoFrame), "a refused shape leaves no frame open");
    assert_eq!(fp.flush().0, FlushResult::Failed);

    fp.alloc_frame(&packet(1, 0, 3, 1, &u)).unwrap();
    assert_eq!(fp.put_unit(&packet(1, 3, 3, 1, &u)), Err(FrameError::UnitIndex { index: 3, slots: 3 }));
    assert_eq!(fp.put_unit(&packet(1, 1, 3, 1, &[])), Err(FrameError::EmptyUnit(1)));
    assert_eq!(
        fp.put_unit(&packet(1, 1, 3, 1, &[0; 6])),
        Err(FrameError::UnitTooBig { index: 1, len: 6, unit_size: 5 })
    );
    fp.put_unit(&packet(1, 0, 3, 1, &u)).unwrap();
    assert_eq!(fp.put_unit(&packet(1, 0, 3, 1, &u)), Err(FrameError::Duplicate(0)));
}

#[test]
fn frame_size_comes_from_the_padding_of_a_source_unit_or_the_size_of_an_fec_unit() {
    let units = frame::split_frame(&frame_bytes(1, 10), UNIT, 1).unwrap();
    assert_eq!(units.len(), 2);
    assert_eq!(units[0].len(), 12, "two bytes of padding length, then the ten bytes");
    assert_eq!(units[1].len(), UNIT);
    // Only the FEC unit arrives: it shapes the frame alone, and rebuilds the source unit.
    let mut fp = FrameProcessor::new();
    fp.alloc_frame(&packet(1, 1, 2, 1, &units[1])).unwrap();
    fp.put_unit(&packet(1, 1, 2, 1, &units[1])).unwrap();
    assert!(fp.flush_possible());
    assert_eq!(fp.flush(), (FlushResult::FecSuccess, frame_bytes(1, 10)));
}

#[test]
fn a_short_source_unit_arriving_first_still_sizes_the_frame() {
    // 100 bytes: a full unit, a 40-byte one (24 bytes of padding cut), and the FEC unit. Unit 0 is lost,
    // so the short unit opens the frame, and its padding length makes room for the 64-byte FEC unit.
    let mut rx = receiver();
    let f = send(&mut rx, 1, 100, 1, &[0]);
    let f = frames(&f);
    assert_eq!(rx.units_refused(), 0);
    assert!(f[0].fec_recovered);
    assert_eq!(f[0].data, frame_bytes(1, 100));
}

#[test]
fn a_recovered_unit_with_impossible_padding_is_left_out() {
    // One source unit whose padding length (0xffff) is more than the unit: FEC "recovers" it, and
    // chiaki-ng then leaves it out of the frame rather than cut it to a negative length.
    let source = {
        let mut u = vec![0xff, 0xff];
        u.resize(UNIT, 7);
        u
    };
    let parity = psr_fec::Fec::new(1, 1).unwrap().encode(&[&source]).unwrap().remove(0);
    let mut fp = FrameProcessor::new();
    fp.alloc_frame(&packet(1, 1, 2, 1, &parity)).unwrap();
    fp.put_unit(&packet(1, 1, 2, 1, &parity)).unwrap();
    assert_eq!(fp.flush(), (FlushResult::FecSuccess, Vec::new()));
}

#[test]
fn a_frame_without_fec_units_still_counts_one() {
    // chiaki-ng gives every frame room for at least one FEC unit, and counts it as expected.
    let units = frame::split_frame(&frame_bytes(1, 100), UNIT, 1).unwrap();
    let mut fp = FrameProcessor::new();
    fp.alloc_frame(&packet(1, 0, 2, 0, &units[0])).unwrap();
    fp.put_unit(&packet(1, 0, 2, 0, &units[0])).unwrap();
    assert_eq!(fp.units(), (1, 3));
}

#[test]
fn not_enough_units_fails_fec_but_joins_what_came() {
    let units = frame::split_frame(&frame_bytes(1, 124), UNIT, 1).unwrap();
    let total = units.len() as u16;
    assert_eq!(total, 3);
    let mut fp = FrameProcessor::new();
    fp.alloc_frame(&packet(1, 0, total, 1, &units[0])).unwrap();
    fp.put_unit(&packet(1, 0, total, 1, &units[0])).unwrap();
    assert!(!fp.flush_possible());
    let (result, data) = fp.flush();
    assert_eq!(result, FlushResult::FecFailed);
    assert_eq!(data, frame_bytes(1, 124)[..62]);
}
