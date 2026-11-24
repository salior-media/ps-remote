// SPDX-License-Identifier: AGPL-3.0-only
//! The WebRTC side of a session: one browser peer, sent the console's H.264 frames and Opus frames as they
//! are, and taking controller input from a data channel. Built on `str0m`, which does no networking of its
//! own: this module owns the UDP socket and drives it.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Instant;

use psr_input::controller::ControllerState;
use str0m::change::{SdpAnswer, SdpOffer};
use str0m::channel::ChannelId;
use str0m::format::{Codec, PayloadParams};
use str0m::media::{Direction, Frequency, MediaKind, MediaTime, Mid, Pt};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcConfig};

use crate::input;

/// The data channel the test page and the games app send input on.
pub const INPUT_CHANNEL: &str = "input";
const RECV_BUF: usize = 2000;
/// Datagrams handled per [`Bridge::pump`], so a flood cannot hold the session loop there.
const PUMP_MAX: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("WebRTC: {0}")]
    Rtc(#[from] str0m::RtcError),
    #[error("the offer was refused: {0}")]
    Offer(String),
    #[error("network: {0}")]
    Io(#[from] std::io::Error),
}

/// What the browser did.
#[derive(Debug, Clone, PartialEq)]
pub enum BridgeEvent {
    /// The browser's media is connected.
    Connected,
    /// A new controller state from the input channel.
    Input(ControllerState),
    /// The browser lost its picture (a PLI or FIR): ask the console for a keyframe.
    KeyframeRequested,
    /// An input message that failed its checks, dropped.
    BadInput,
    /// The browser went away.
    Closed,
}

/// One browser peer (a `str0m::Rtc` and its UDP socket).
pub struct Bridge {
    rtc: Rtc,
    socket: UdpSocket,
    local: SocketAddr,
    video: Option<(Mid, Pt)>,
    audio: Option<(Mid, Pt)>,
    started: Instant,
    /// The audio frame index, extended past 65535 so the RTP clock never steps back.
    audio_index: Option<(u16, u64)>,
    /// The data channel named [`INPUT_CHANNEL`], once the browser opens it. Other channels are ignored.
    input_channel: Option<ChannelId>,
    closed: bool,
}

impl std::fmt::Debug for Bridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bridge").field("local", &self.local).finish_non_exhaustive()
    }
}

/// The H.264 payload type to send with: packetization mode 1, preferring the Main profile the console
/// encodes in.
fn pick_h264<'a>(params: impl Iterator<Item = &'a PayloadParams>) -> Option<Pt> {
    let h264: Vec<&PayloadParams> =
        params.filter(|p| p.spec().codec == Codec::H264 && p.spec().format.packetization_mode == Some(1)).collect();
    let main = |p: &&&PayloadParams| p.spec().format.profile_level_id.is_some_and(|id| id >> 16 == 0x4d);
    h264.iter().find(main).or(h264.first()).map(|p| p.pt())
}

fn pick_opus<'a>(mut params: impl Iterator<Item = &'a PayloadParams>) -> Option<Pt> {
    params.find(|p| p.spec().codec == Codec::Opus).map(|p| p.pt())
}

impl Bridge {
    /// Answers a browser's offer, with one UDP socket on `bind` for the media (a random port).
    pub fn accept(offer: SdpOffer, bind: IpAddr, now: Instant) -> Result<(Self, SdpAnswer), BridgeError> {
        let mut rtc =
            RtcConfig::new().clear_codecs().enable_h264(true).enable_opus(true, false).set_ice_lite(true).build(now);
        let socket = UdpSocket::bind((bind, 0))?;
        let local = socket.local_addr()?;
        let candidate = Candidate::host(local, "udp").map_err(|e| BridgeError::Offer(e.to_string()))?;
        if rtc.add_local_candidate(candidate).is_none() {
            return Err(BridgeError::Offer("the media address was refused as a candidate".into()));
        }
        let answer = rtc.sdp_api().accept_offer(offer)?;
        socket.set_nonblocking(true)?;
        let bridge = Self {
            rtc,
            socket,
            local,
            video: None,
            audio: None,
            started: now,
            audio_index: None,
            input_channel: None,
            closed: false,
        };
        Ok((bridge, answer))
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Whether both tracks are ready to take media.
    pub fn sending(&self) -> bool {
        self.video.is_some() && self.audio.is_some()
    }

    /// Sends one H.264 frame. `header` (the SPS and PPS) goes in front, so the browser can start decoding
    /// at any keyframe.
    pub fn send_video(&mut self, header: &[u8], frame: &[u8], now: Instant) -> Result<(), BridgeError> {
        let Some((mid, pt)) = self.video else { return Ok(()) };
        let Some(writer) = self.rtc.writer(mid) else { return Ok(()) };
        let mut data = Vec::with_capacity(header.len() + frame.len());
        data.extend_from_slice(header);
        data.extend_from_slice(frame);
        let micros = now.saturating_duration_since(self.started).as_micros() as u64;
        writer.write(pt, now, MediaTime::from_90khz(micros * 9 / 100), data)?;
        Ok(())
    }

    /// Sends one Opus frame of `frame_size` samples, timed by the console's frame index.
    pub fn send_audio(&mut self, index: u16, frame_size: u32, data: &[u8], now: Instant) -> Result<(), BridgeError> {
        let Some((mid, pt)) = self.audio else { return Ok(()) };
        let extended = match self.audio_index {
            None => 0,
            Some((last, ext)) => ext.wrapping_add_signed(i64::from(index.wrapping_sub(last) as i16)),
        };
        self.audio_index = Some((index, extended));
        let Some(writer) = self.rtc.writer(mid) else { return Ok(()) };
        let time = MediaTime::new(extended * u64::from(frame_size), Frequency::FORTY_EIGHT_KHZ);
        writer.write(pt, now, time, data.to_vec())?;
        Ok(())
    }

    /// Feeds the socket and the clock to `str0m`, sends what it wants sent, and returns what the browser did.
    /// Never blocks.
    pub fn pump(&mut self, now: Instant) -> Result<Vec<BridgeEvent>, BridgeError> {
        let mut events = Vec::new();
        let mut buf = [0u8; RECV_BUF];
        for _ in 0..PUMP_MAX {
            match self.socket.recv_from(&mut buf) {
                Ok((n, source)) => {
                    let Ok(contents) = buf[..n].try_into() else { continue };
                    let input = Input::Receive(
                        now,
                        Receive { proto: Protocol::Udp, source, destination: self.local, contents },
                    );
                    if self.rtc.accepts(&input) {
                        self.rtc.handle_input(input)?;
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
                // Windows reports an ICMP port-unreachable from an earlier send this way.
                Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.rtc.handle_input(Input::Timeout(now))?;
        self.drain_output(&mut events)?;
        Ok(events)
    }

    fn drain_output(&mut self, events: &mut Vec<BridgeEvent>) -> Result<(), BridgeError> {
        loop {
            match self.rtc.poll_output()? {
                Output::Timeout(_) => return Ok(()),
                Output::Transmit(t) => {
                    // A send that fails is a lost packet, which WebRTC recovers from; it is not worth ending
                    // the session for.
                    let _ = self.socket.send_to(&t.contents, t.destination);
                }
                Output::Event(e) => self.event(e, events),
            }
        }
    }

    fn event(&mut self, e: Event, events: &mut Vec<BridgeEvent>) {
        match e {
            Event::Connected => events.push(BridgeEvent::Connected),
            Event::IceConnectionStateChange(IceConnectionState::Disconnected) => {
                self.closed = true;
                events.push(BridgeEvent::Closed);
            }
            Event::MediaAdded(m) if m.direction == Direction::SendOnly || m.direction == Direction::SendRecv => {
                let Some(writer) = self.rtc.writer(m.mid) else { return };
                match m.kind {
                    MediaKind::Video => self.video = pick_h264(writer.payload_params()).map(|pt| (m.mid, pt)),
                    MediaKind::Audio => self.audio = pick_opus(writer.payload_params()).map(|pt| (m.mid, pt)),
                }
            }
            Event::KeyframeRequest(_) => events.push(BridgeEvent::KeyframeRequested),
            Event::ChannelOpen(id, label) if label == INPUT_CHANNEL => self.input_channel = Some(id),
            Event::ChannelData(d) if Some(d.id) == self.input_channel && !d.binary => match input::parse(&d.data) {
                Some(state) => events.push(BridgeEvent::Input(state)),
                None => events.push(BridgeEvent::BadInput),
            },
            _ => {}
        }
    }
}
