// SPDX-License-Identifier: AGPL-3.0-only
// The WebRTC bridge against a str0m peer playing the browser, over loopback: the offer and answer, ICE and
// DTLS, then frames to the browser whole and input back from it.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use ps_remote::bridge::{Bridge, BridgeEvent, INPUT_CHANNEL};
use psr_input::controller::button;
use str0m::change::{SdpOffer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::media::{Direction, KeyframeRequestKind, MediaKind, Mid};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc, RtcConfig};

/// The browser's side, driven by hand.
struct Browser {
    rtc: Rtc,
    socket: UdpSocket,
    local: SocketAddr,
    video: Mid,
    channel: Option<ChannelId>,
    connected: bool,
    received: Vec<(MediaKind, Vec<u8>)>,
}

impl Browser {
    fn offer() -> (Self, SdpOffer, SdpPendingOffer) {
        let mut rtc = RtcConfig::new().clear_codecs().enable_h264(true).enable_opus(true, false).build(Instant::now());
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let local = socket.local_addr().unwrap();
        rtc.add_local_candidate(Candidate::host(local, "udp").unwrap()).unwrap();
        let mut api = rtc.sdp_api();
        let video = api.add_media(MediaKind::Video, Direction::RecvOnly, None, None, None);
        api.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
        api.add_channel(INPUT_CHANNEL.into());
        let (offer, pending) = api.apply().unwrap();
        let b = Self { rtc, socket, local, video, channel: None, connected: false, received: Vec::new() };
        (b, offer, pending)
    }

    fn pump(&mut self) {
        let now = Instant::now();
        let mut buf = [0u8; 2000];
        while let Ok((n, source)) = self.socket.recv_from(&mut buf) {
            let contents = buf[..n].try_into().unwrap();
            let input =
                Input::Receive(now, Receive { proto: Protocol::Udp, source, destination: self.local, contents });
            self.rtc.handle_input(input).unwrap();
        }
        self.rtc.handle_input(Input::Timeout(now)).unwrap();
        loop {
            match self.rtc.poll_output().unwrap() {
                Output::Timeout(_) => break,
                Output::Transmit(t) => {
                    self.socket.send_to(&t.contents, t.destination).unwrap();
                }
                Output::Event(Event::Connected) => self.connected = true,
                Output::Event(Event::ChannelOpen(id, _)) => self.channel = Some(id),
                Output::Event(Event::MediaData(d)) => {
                    let kind = if d.mid == self.video { MediaKind::Video } else { MediaKind::Audio };
                    self.received.push((kind, d.data.to_vec()));
                }
                Output::Event(_) => {}
            }
        }
    }

    fn got(&self, kind: MediaKind) -> Option<&Vec<u8>> {
        self.received.iter().find(|(k, _)| *k == kind).map(|(_, d)| d)
    }
}

/// Runs both sides until `done` or five seconds pass, collecting the bridge's events.
fn run(
    bridge: &mut Bridge,
    browser: &mut Browser,
    events: &mut Vec<BridgeEvent>,
    done: impl Fn(&Bridge, &Browser, &[BridgeEvent]) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done(bridge, browser, events) {
        assert!(Instant::now() < deadline, "timed out; bridge events {events:?}");
        events.extend(bridge.pump(Instant::now()).unwrap());
        browser.pump();
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn connected() -> (Bridge, Browser, Vec<BridgeEvent>) {
    let (mut browser, offer, pending) = Browser::offer();
    let (mut bridge, answer) = Bridge::accept(offer, "127.0.0.1".parse().unwrap(), Instant::now()).unwrap();
    assert!(bridge.local_addr().ip().is_loopback());
    browser.rtc.sdp_api().accept_answer(pending, answer).unwrap();
    let mut events = Vec::new();
    run(&mut bridge, &mut browser, &mut events, |b, br, ev| {
        b.sending() && br.connected && br.channel.is_some() && ev.contains(&BridgeEvent::Connected)
    });
    (bridge, browser, events)
}

#[test]
fn frames_reach_the_browser_whole() {
    let (mut bridge, mut browser, mut events) = connected();
    let header = [0, 0, 0, 1, 0x67, 0x4d, 0x40, 0x20, 0, 0, 0, 1, 0x68, 0xee, 0x3c, 0x80];
    let mut frame = vec![0, 0, 0, 1, 0x65];
    frame.extend((0..3000u32).map(|i| (i % 251) as u8 | 1));
    bridge.send_video(&header, &frame, Instant::now()).unwrap();
    let opus = [0xfcu8, 1, 2, 3, 4, 5];
    bridge.send_audio(7, 480, &opus, Instant::now()).unwrap();
    run(&mut bridge, &mut browser, &mut events, |_, br, _| {
        br.got(MediaKind::Video).is_some() && br.got(MediaKind::Audio).is_some()
    });
    let video = browser.got(MediaKind::Video).unwrap();
    // The frame is split into RTP packets (FU-A) and joined again: every NAL unit arrives intact.
    let find = |needle: &[u8]| video.windows(needle.len()).any(|w| w == needle);
    assert!(find(&header[4..8]), "the SPS");
    assert!(find(&header[12..]), "the PPS");
    assert!(find(&frame[4..]), "the whole IDR slice, {} bytes", frame.len() - 4);
    assert_eq!(browser.got(MediaKind::Audio).unwrap(), &opus);
}

#[test]
fn input_comes_back_and_bad_input_is_named() {
    let (mut bridge, mut browser, mut events) = connected();
    let id = browser.channel.unwrap();
    let mut ch = browser.rtc.channel(id).unwrap();
    ch.write(false, br#"{"buttons":128,"lx":-100}"#).unwrap();
    ch.write(false, br#"{"buttons":65536}"#).unwrap();
    run(&mut bridge, &mut browser, &mut events, |_, _, ev| ev.contains(&BridgeEvent::BadInput));
    let inputs: Vec<_> =
        events.iter().filter_map(|e| if let BridgeEvent::Input(s) = e { Some(*s) } else { None }).collect();
    assert_eq!(inputs.len(), 1);
    assert_eq!((inputs[0].buttons, inputs[0].left_x), (button::DPAD_DOWN, -100));
}

#[test]
fn a_picture_loss_from_the_browser_asks_for_a_keyframe() {
    let (mut bridge, mut browser, mut events) = connected();
    // The browser has to have seen the stream before it can ask about it.
    bridge.send_video(&[0, 0, 0, 1, 0x67, 1], &[0, 0, 0, 1, 0x65, 2, 3], Instant::now()).unwrap();
    run(&mut bridge, &mut browser, &mut events, |_, br, _| br.got(MediaKind::Video).is_some());
    let video = browser.video;
    let mut w = browser.rtc.writer(video).expect("a writer for the receiving side's feedback");
    w.request_keyframe(None, KeyframeRequestKind::Pli).unwrap();
    run(&mut bridge, &mut browser, &mut events, |_, _, ev| ev.contains(&BridgeEvent::KeyframeRequested));
}
