// SPDX-License-Identifier: AGPL-3.0-only
//! The stream connection: Takion over UDP port 9296, the BIG / BANG key exchange, and the console's stream
//! info. Ported from chiaki-ng `lib/src/streamconnection.c` and `lib/src/launchspec.c`
//! (LicenseRef-AGPL-3.0-only-OpenSSL). Video comes out as whole frames, put back in order and rebuilt by
//! psr-av, and audio as Opus frames.
//!
//! **Difference from chiaki-ng:** Senkusha, chiaki-ng's MTU and latency probe, is not run. chiaki-ng
//! carries on without it when it fails, with an MTU of 1454 and an RTT of 1 ms, and those are the values
//! used here. The receive buffer is left at the system's size: chiaki-ng sets it to its `a_rwnd`.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use base64::Engine;
use prost::Message;
use psr_crypto::Target;
use psr_crypto::ecdh::Ecdh;
use psr_crypto::gkcrypt::{GkCrypt, HANDSHAKE_KEY_SIZE};
use psr_crypto::rpcrypt::RpCrypt;
use psr_proto::takion_message::PayloadType;
use psr_av::audio::{AudioFrame, AudioReceiver};
use psr_av::video::{VideoEvent, VideoReceiver};
use psr_input::controller::ControllerState;
use psr_input::feedback;
use psr_input::sender::{Feedback, FeedbackSender};
use psr_crypto::gkcrypt::BLOCK_SIZE;
use psr_proto::{BigPayload, ControllerConnectionPayload, CorruptFramePayload, DisconnectPayload, StreamInfoPayload, TakionMessage};
use psr_takion::av::{self, AvPacket, AvVersion};
use psr_takion::av_queue::AvQueue;
use psr_takion::connection::{self, Received, Receiver, Sender, data_type};

use crate::LanError;
use crate::session::{Codec, Session};

pub const STREAM_PORT: u16 = 9296;
/// chiaki-ng's values when Senkusha does not run or fails.
pub const FALLBACK_MTU: u32 = 1454;
pub const FALLBACK_RTT_US: u32 = 1000;
/// chiaki-ng `EXPECT_TIMEOUT_MS` and `TAKION_EXPECT_TIMEOUT_MS`.
const EXPECT_TIMEOUT: Duration = Duration::from_secs(5);
/// chiaki-ng `MAX_CONNECT_RESEND_TRIES`.
const CONNECT_TRIES: usize = 3;
/// chiaki-ng `HEARTBEAT_INTERVAL_MS`.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
/// chiaki-ng takes 50 bytes off the MTU for network overhead before splitting BIG.
const MTU_OVERHEAD: u32 = 50;
/// chiaki-ng `CHIAKI_AUDIO_HEADER_SIZE`.
pub const AUDIO_HEADER_SIZE: usize = 0xe;
const RECV_BUF: usize = 1500;
/// At most this many datagrams are handled in one poll, so a flood cannot hold the caller there.
const DRAIN_MAX: usize = 1024;
/// The low nibble of a video datagram's first byte.
const VIDEO_TYPE: u8 = 2;
/// The channel the stream's protobuf messages use, and the one chiaki-ng acknowledges stream info on.
const CHANNEL: u16 = 1;
const STREAMINFO_ACK_CHANNEL: u16 = 9;
/// chiaki-ng sends corrupt-frame reports and keyframe requests on channel 2.
const VIDEO_FEEDBACK_CHANNEL: u16 = 2;
/// Video datagrams kept while the stream info, which says how to read them, has not come yet.
const EARLY_VIDEO_MAX: usize = 256;

/// What to ask the console for (chiaki-ng `ChiakiConnectVideoProfile`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoProfile {
    pub width: u32,
    pub height: u32,
    pub max_fps: u32,
    pub bitrate_kbps: u32,
    pub codec: Codec,
}

impl VideoProfile {
    /// chiaki-ng's 720p preset at 60 fps.
    pub const fn p720_60(codec: Codec) -> Self {
        Self { width: 1280, height: 720, max_fps: 60, bitrate_kbps: 10_000, codec }
    }

    /// chiaki-ng's 1080p preset at 60 fps.
    pub const fn p1080_60(codec: Codec) -> Self {
        Self { width: 1920, height: 1080, max_fps: 60, bitrate_kbps: 15_000, codec }
    }
}

/// chiaki-ng `chiaki_launchspec_format`, character for character.
pub fn launch_spec(target: Target, profile: &VideoProfile, mtu: u32, rtt_ms: u32, handshake_key: &[u8; HANDSHAKE_KEY_SIZE]) -> String {
    let key = base64::engine::general_purpose::STANDARD.encode(handshake_key);
    let (adaptive, codec, range) = if target.is_ps5() {
        (
            ",\"adaptiveStreamMode\": \"resize\"",
            if matches!(profile.codec, Codec::H264) { "\"videoCodec\":\"avc\"," } else { "\"videoCodec\":\"hevc\"," },
            if matches!(profile.codec, Codec::H265Hdr) { "\"dynamicRange\":\"HDR\"," } else { "\"dynamicRange\":\"SDR\"," },
        )
    } else {
        ("", "", "")
    };
    format!(
        concat!(
            "{{\"sessionId\":\"sessionId4321\",\"streamResolutions\":[{{\"resolution\":{{\"width\":{},\"height\":{}}},",
            "\"maxFps\":{},\"score\":10}}],\"network\":{{\"bwKbpsSent\":{},\"bwLoss\":0.001000,\"mtu\":{},\"rtt\":{},",
            "\"ports\":[53,2053]}},\"slotId\":1,\"appSpecification\":{{\"minFps\":30,\"minBandwidth\":0,",
            "\"extTitleId\":\"ps3\",\"version\":1,\"timeLimit\":1,\"startTimeout\":100,\"afkTimeout\":100,",
            "\"afkTimeoutDisconnect\":100}},\"konan\":{{\"ps3AccessToken\":\"accessToken\",",
            "\"ps3RefreshToken\":\"refreshToken\"}},\"requestGameSpecification\":{{\"model\":\"bravia_tv\",",
            "\"platform\":\"android\",\"audioChannels\":\"5.1\",\"language\":\"sp\",\"acceptButton\":\"X\",",
            "\"connectedControllers\":[\"xinput\",\"ds3\",\"ds4\"],\"yuvCoefficient\":\"bt601\",",
            "\"videoEncoderProfile\":\"hw4.1\",\"audioEncoderProfile\":\"audio1\"{}}},\"userProfile\":{{",
            "\"onlineId\":\"psnId\",\"npId\":\"npId\",\"region\":\"US\",\"languagesUsed\":[\"en\",\"jp\"]}},",
            "{}{}\"handshakeKey\":\"{}\"}}"
        ),
        profile.width, profile.height, profile.max_fps, profile.bitrate_kbps, mtu, rtt_ms, adaptive, codec, range, key
    )
}

/// chiaki-ng `stream_connection_send_big`'s launch spec encoding: the JSON with its trailing NUL, XORed
/// with the auth cipher's encryption of as many zero bytes at counter 0, then base64.
pub fn encode_launch_spec(crypt: &RpCrypt, json: &str) -> String {
    let mut plain = json.as_bytes().to_vec();
    plain.push(0);
    let pad = crypt.encrypt(0, &vec![0u8; plain.len()]);
    let mixed: Vec<u8> = plain.iter().zip(&pad).map(|(a, b)| a ^ b).collect();
    base64::engine::general_purpose::STANDARD.encode(mixed)
}

/// chiaki-ng's BIG message. The encrypted key is four zero bytes, as chiaki-ng sends it.
pub fn big_message(client_version: u32, session_id: &str, launch_spec_b64: &str, pub_key: &[u8], sig: &[u8]) -> Vec<u8> {
    TakionMessage {
        r#type: PayloadType::Big as i32,
        big_payload: Some(BigPayload {
            client_version,
            session_key: session_id.to_string(),
            launch_spec: launch_spec_b64.to_string(),
            encrypted_key: vec![0; 4],
            ecdh_pub_key: Some(pub_key.to_vec()),
            ecdh_sig: Some(sig.to_vec()),
        }),
        ..Default::default()
    }
    .encode_to_vec()
}

fn typed(t: PayloadType) -> TakionMessage {
    TakionMessage { r#type: t as i32, ..Default::default() }
}

pub fn heartbeat_message() -> Vec<u8> {
    typed(PayloadType::Heartbeat).encode_to_vec()
}

pub fn streaminfo_ack_message() -> Vec<u8> {
    typed(PayloadType::Streaminfoack).encode_to_vec()
}

/// chiaki-ng `stream_connection_send_controller_connection`, with DualSense features off: a DualShock 4.
pub fn controller_connection_message() -> Vec<u8> {
    TakionMessage {
        controller_connection_payload: Some(ControllerConnectionPayload {
            controller_id: None,
            connected: Some(true),
            controller_type: Some(psr_proto::controller_connection_payload::ControllerType::Dualshock4 as i32),
        }),
        ..typed(PayloadType::Controllerconnection)
    }
    .encode_to_vec()
}

/// chiaki-ng `chiaki_audio_header_set(&h, 16, 1, 48000, 480)` then `chiaki_audio_header_save`, which
/// writes bits before channels: so the bytes are 1, 16.
pub fn microphone_audio_header() -> [u8; AUDIO_HEADER_SIZE] {
    let mut h = [0u8; AUDIO_HEADER_SIZE];
    h[0] = 1;
    h[1] = 16;
    h[2..6].copy_from_slice(&48_000u32.to_be_bytes());
    h[6..10].copy_from_slice(&480u32.to_be_bytes());
    h[10..14].copy_from_slice(&1u32.to_be_bytes());
    h
}

/// chiaki-ng `stream_connection_enable_microphone`: a stream info message carrying only our audio header.
pub fn microphone_message() -> Vec<u8> {
    TakionMessage {
        stream_info_payload: Some(StreamInfoPayload { audio_header: microphone_audio_header().to_vec(), ..Default::default() }),
        ..typed(PayloadType::Streaminfo)
    }
    .encode_to_vec()
}

/// chiaki-ng `stream_connection_send_corrupt_frame`: frames `start..=end` were lost or damaged.
pub fn corrupt_frame_message(start: u16, end: u16) -> Vec<u8> {
    TakionMessage {
        corrupt_payload: Some(CorruptFramePayload { start: start.into(), end: end.into() }),
        ..typed(PayloadType::Corruptframe)
    }
    .encode_to_vec()
}

/// chiaki-ng `stream_connection_send_idr_request`: asks the console for a keyframe.
pub fn idr_request_message() -> Vec<u8> {
    typed(PayloadType::Idrrequest).encode_to_vec()
}

pub fn disconnect_message() -> Vec<u8> {
    TakionMessage {
        disconnect_payload: Some(DisconnectPayload { reason: "Client Disconnecting".into(), extended_info: None }),
        ..typed(PayloadType::Disconnect)
    }
    .encode_to_vec()
}

/// The keys both directions of the stream use from BANG on (chiaki-ng `stream_connection_init_crypt`):
/// index 2 for ours, 3 for the console's.
pub fn stream_keys(
    ecdh: &Ecdh,
    handshake_key: &[u8; HANDSHAKE_KEY_SIZE],
    remote_pub_key: &[u8],
    remote_sig: &[u8],
) -> Result<(GkCrypt, GkCrypt), LanError> {
    let secret = ecdh.derive_secret(remote_pub_key, handshake_key, remote_sig).map_err(|e| LanError::Bang(e.to_string()))?;
    Ok((GkCrypt::new(2, handshake_key, &secret), GkCrypt::new(3, handshake_key, &secret)))
}

/// The console's BANG, checked as chiaki-ng `stream_connection_takion_data_expect_bang` checks it.
pub fn check_bang(msg: &TakionMessage) -> Result<(Vec<u8>, Vec<u8>), LanError> {
    let bang = msg.bang_payload.as_ref().ok_or_else(|| LanError::Bang("no BANG payload".into()))?;
    if !bang.version_accepted {
        return Err(LanError::Bang("the console did not accept the protocol version".into()));
    }
    if !bang.encrypted_key_accepted {
        return Err(LanError::Bang("the console did not accept the encrypted key".into()));
    }
    let key = bang.ecdh_pub_key.clone().filter(|k| !k.is_empty()).ok_or_else(|| LanError::Bang("no ECDH public key".into()))?;
    let sig = bang.ecdh_sig.clone().filter(|s| !s.is_empty()).ok_or_else(|| LanError::Bang("no ECDH signature".into()))?;
    Ok((key, sig))
}

/// One video resolution the console offers, with its codec header (for H.264, the SPS and PPS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub width: u32,
    pub height: u32,
    pub video_header: Vec<u8>,
}

/// The console's stream info (chiaki-ng `stream_connection_takion_data_expect_streaminfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamInfo {
    pub resolutions: Vec<Resolution>,
    pub audio_header: [u8; AUDIO_HEADER_SIZE],
}

pub fn parse_stream_info(msg: &TakionMessage) -> Result<StreamInfo, LanError> {
    let info = msg.stream_info_payload.as_ref().ok_or(LanError::StreamInfo("no stream info payload"))?;
    let audio_header = info.audio_header.as_slice().try_into().map_err(|_| LanError::StreamInfo("audio header is not 14 bytes"))?;
    Ok(StreamInfo {
        resolutions: info
            .resolution
            .iter()
            .map(|r| Resolution { width: r.width, height: r.height, video_header: r.video_header.clone() })
            .collect(),
        audio_header,
    })
}

fn disconnect_reason(msg: &TakionMessage) -> String {
    msg.disconnect_payload.as_ref().map_or_else(String::new, |d| d.reason.clone())
}

/// What arrived on a running stream.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamEvent {
    /// A codec header, a whole frame, or frames reported lost (the report is already sent).
    Video(VideoEvent),
    /// An Opus frame, decrypted, each one once.
    Audio(AudioFrame),
    /// A protobuf message other than the ones handled here.
    Message(Box<TakionMessage>),
    /// The console ended the stream.
    Disconnected(String),
}

fn io(e: std::io::Error) -> LanError {
    LanError::Io(e)
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

/// A connected stream: Takion is up, keys are exchanged, and the console has said what it will send.
pub struct Stream {
    socket: UdpSocket,
    sender: Sender,
    receiver: Receiver,
    info: StreamInfo,
    last_heartbeat: Instant,
    /// Received before the step that wanted it: kept for [`Stream::poll`].
    pending: Vec<StreamEvent>,
    /// Datagrams dropped because they failed a check (MAC, tag, length).
    dropped: u64,
    av_version: AvVersion,
    video_queue: AvQueue<Vec<u8>>,
    /// Made once the stream info has given the codec headers.
    video: Option<VideoReceiver>,
    early_video: Vec<Vec<u8>>,
    audio: AudioReceiver,
    feedback: FeedbackSender,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream").field("resolutions", &self.info.resolutions.len()).finish_non_exhaustive()
    }
}

/// Receives one datagram within `timeout`; `None` when none came.
fn recv(socket: &UdpSocket, timeout: Duration) -> Result<Option<Vec<u8>>, LanError> {
    let mut buf = [0u8; RECV_BUF];
    match crate::udp::recv_within(socket, &mut buf, timeout) {
        Ok(n) => Ok(n.map(|n| buf[..n].to_vec())),
        Err(e) if is_timeout(&e) => Ok(None),
        // Windows reports an ICMP port-unreachable from an earlier send this way.
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => Ok(None),
        Err(e) => Err(io(e)),
    }
}

/// chiaki-ng `takion_handshake`: INIT until an init ack comes (three tries), then COOKIE until its ack.
fn handshake(socket: &UdpSocket, tag_local: u32) -> Result<u32, LanError> {
    // Each try ends with whatever came first: chiaki-ng resends INIT after a timeout or a reply that
    // is not an init ack alike.
    let mut ack = Err(LanError::Timeout("stream init ack"));
    for _ in 0..CONNECT_TRIES {
        socket.send(&connection::init_datagram(tag_local, tag_local)).map_err(io)?;
        if let Some(d) = recv(socket, EXPECT_TIMEOUT)? {
            ack = connection::parse_init_ack(&d, tag_local).map_err(LanError::from);
            if ack.is_ok() {
                break;
            }
        }
    }
    let ack = ack?;
    for _ in 0..CONNECT_TRIES {
        socket.send(&connection::cookie_datagram(ack.tag, &ack.cookie)).map_err(io)?;
        let Some(mut d) = recv(socket, EXPECT_TIMEOUT)? else { continue };
        if connection::is_init_ack_repeat(&d) {
            let Some(next) = recv(socket, EXPECT_TIMEOUT)? else { continue };
            d = next;
        }
        connection::is_cookie_ack(&d, tag_local)?;
        return Ok(ack.tag);
    }
    Err(LanError::Timeout("stream cookie ack"))
}

/// Opens the stream connection for a started session (chiaki-ng `chiaki_stream_connection_run`, up to
/// the point it reports the stream connected).
pub fn connect(host: IpAddr, session: &Session, profile: &VideoProfile) -> Result<Stream, LanError> {
    connect_at(SocketAddr::new(host, STREAM_PORT), session.target(), session.session_id(), session.rpcrypt(), profile)
}

/// [`connect`] at any address, given what it needs from the session.
pub fn connect_at(
    addr: SocketAddr,
    target: Target,
    session_id: &str,
    rpcrypt: &RpCrypt,
    profile: &VideoProfile,
) -> Result<Stream, LanError> {
    let any: IpAddr = if addr.is_ipv4() { std::net::Ipv4Addr::UNSPECIFIED.into() } else { std::net::Ipv6Addr::UNSPECIFIED.into() };
    let socket = UdpSocket::bind((any, 0)).map_err(io)?;
    socket.connect(addr).map_err(io)?;

    let mut random = [0u8; 4 + HANDSHAKE_KEY_SIZE];
    getrandom::fill(&mut random).map_err(|e| LanError::Random(e.to_string()))?;
    let tag_local = u32::from_be_bytes(random[..4].try_into().expect("4 bytes")).max(1);
    let handshake_key: [u8; HANDSHAKE_KEY_SIZE] = random[4..].try_into().expect("16 bytes");
    let tag_remote = handshake(&socket, tag_local)?;

    let ecdh = Ecdh::generate().map_err(|e| LanError::Bang(e.to_string()))?;
    let (pub_key, sig) = ecdh.signed_public_key(&handshake_key);
    let spec = launch_spec(target, profile, FALLBACK_MTU, FALLBACK_RTT_US / 1000, &handshake_key);
    // chiaki-ng: Takion protocol 12 for a PS5, 9 for a PS4.
    let version = if target.is_ps5() { 12 } else { 9 };
    let big = big_message(version, session_id, &encode_launch_spec(rpcrypt, &spec), &pub_key, &sig);

    let mut stream = Stream {
        socket,
        sender: Sender::new(tag_local, tag_remote),
        receiver: Receiver::new(tag_local, tag_remote),
        info: StreamInfo { resolutions: Vec::new(), audio_header: [0; AUDIO_HEADER_SIZE] },
        last_heartbeat: Instant::now(),
        pending: Vec::new(),
        dropped: 0,
        // chiaki-ng reads protocol 12's layout from a PS5 and protocol 9's from a PS4.
        av_version: if target.is_ps5() { AvVersion::V12 } else { AvVersion::V9 },
        video_queue: AvQueue::new(),
        video: None,
        early_video: Vec::new(),
        audio: AudioReceiver::new(),
        feedback: FeedbackSender::new(Instant::now()),
    };
    for d in stream.sender.split_data(CHANNEL, &big, (FALLBACK_MTU - MTU_OVERHEAD) as usize)? {
        stream.socket.send(&d).map_err(io)?;
    }

    let mut early_info = None;
    let (bang, bang_ack) = stream.wait_for(|msg| msg.r#type == PayloadType::Bang as i32, &mut early_info, "BANG")?;
    let (key, sig) = check_bang(&bang)?;
    let (local, remote) = stream_keys(&ecdh, &handshake_key, &key, &sig)?;
    stream.sender.set_crypt(local);
    stream.ack(bang_ack)?;
    for d in stream.receiver.set_crypt(remote) {
        // Video that came before the keys: handle it now that it can be checked.
        let (got, _) = stream.receiver.handle(&d)?;
        stream.queue(got)?;
    }

    let info = match early_info.take() {
        Some(m) => m,
        None => {
            let (m, ack) = stream.wait_for(|msg| msg.r#type == PayloadType::Streaminfo as i32, &mut None, "stream info")?;
            stream.ack(ack)?;
            m
        }
    };
    stream.info = parse_stream_info(&info)?;
    stream.video = Some(VideoReceiver::new(stream.info.resolutions.iter().map(|r| r.video_header.clone()).collect()));
    for d in std::mem::take(&mut stream.early_video) {
        stream.video_datagram(d)?;
    }
    stream.send_message(STREAMINFO_ACK_CHANNEL, &streaminfo_ack_message())?;
    stream.send_message(CHANNEL, &controller_connection_message())?;
    stream.send_message(CHANNEL, &microphone_message())?;
    stream.last_heartbeat = Instant::now();
    // chiaki-ng starts its feedback sender once the stream is connected.
    stream.feedback = FeedbackSender::new(Instant::now());
    Ok(stream)
}

impl Stream {
    pub fn info(&self) -> &StreamInfo {
        &self.info
    }

    /// How many datagrams were dropped for failing a check (MAC, tag or length).
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    fn send_message(&mut self, channel: u16, msg: &[u8]) -> Result<(), LanError> {
        let (_, d) = self.sender.data(1, channel, msg)?;
        self.socket.send(&d).map_err(io)?;
        Ok(())
    }

    /// Asks the console for a keyframe: the answer to a decoder that lost its picture (a WebRTC PLI).
    /// Sets what the controller is doing now: buttons, triggers, sticks, touches and motion. The change
    /// goes out at once, and is repeated as chiaki-ng repeats it while [`Stream::poll`] keeps running.
    pub fn set_controller_state(&mut self, state: &ControllerState) -> Result<(), LanError> {
        self.feedback.set_controller_state(state);
        self.send_feedback()
    }

    /// Sends the controller feedback that is due (chiaki-ng's feedback sender thread).
    fn send_feedback(&mut self) -> Result<(), LanError> {
        for f in self.feedback.poll(Instant::now()) {
            let d = match f {
                Feedback::State { seq_num, state } => {
                    let bytes = if self.av_version == AvVersion::V12 {
                        feedback::format_v12(&state).to_vec()
                    } else {
                        feedback::format_v9(&state).to_vec()
                    };
                    self.sender.feedback_state(seq_num, &bytes)?
                }
                Feedback::History { seq_num, event_count, events } => {
                    self.sender.feedback_history(seq_num, event_count, &events)?
                }
            };
            self.socket.send(&d).map_err(io)?;
        }
        Ok(())
    }

    pub fn request_keyframe(&mut self) -> Result<(), LanError> {
        self.send_message(VIDEO_FEEDBACK_CHANNEL, &idr_request_message())
    }

    /// Frames lost so far, as the video receiver counts them.
    pub fn frames_lost(&self) -> u64 {
        self.video.as_ref().map_or(0, VideoReceiver::frames_lost_total)
    }

    fn queue(&mut self, got: Vec<Received>) -> Result<(), LanError> {
        for r in got {
            if let Received::Av(datagram) = r {
                if datagram.first().is_some_and(|b| b & 0xf == VIDEO_TYPE) {
                    self.video_datagram(datagram)?;
                } else {
                    self.audio_datagram(&datagram);
                }
            }
        }
        Ok(())
    }

    /// chiaki-ng `stream_connection_takion_av` for audio: decrypts the packet and takes out its Opus frames.
    /// A packet that fails its checks is dropped and counted, as chiaki-ng logs and drops it.
    fn audio_datagram(&mut self, datagram: &[u8]) {
        let Some(crypt) = self.receiver.crypt() else { return };
        let Ok(p) = av::parse(self.av_version, datagram, self.receiver.key_state()) else {
            self.dropped += 1;
            return;
        };
        let data = crypt.crypt(p.key_pos + BLOCK_SIZE as u64, p.data);
        match self.audio.av_packet(&AvPacket { data: &data, ..p }) {
            Ok(frames) => self.pending.extend(frames.into_iter().map(StreamEvent::Audio)),
            Err(_) => self.dropped += 1,
        }
    }

    /// Puts a video datagram in order and hands on whatever that releases.
    fn video_datagram(&mut self, datagram: Vec<u8>) -> Result<(), LanError> {
        if self.video.is_none() {
            if self.early_video.len() < EARLY_VIDEO_MAX {
                self.early_video.push(datagram);
            }
            return Ok(());
        }
        let Ok(p) = av::parse(self.av_version, &datagram, self.receiver.key_state()) else {
            self.dropped += 1;
            return Ok(());
        };
        let (packet_index, unit_index) = (p.packet_index, p.unit_index);
        let ordered = self.video_queue.push(packet_index, unit_index, datagram, Instant::now());
        self.video_ordered(ordered)
    }

    /// chiaki-ng `stream_connection_takion_av`: decrypts each packet and gives it to the video receiver.
    fn video_ordered(&mut self, ordered: Vec<Vec<u8>>) -> Result<(), LanError> {
        for datagram in ordered {
            let (Some(crypt), Some(video)) = (self.receiver.crypt(), self.video.as_mut()) else { continue };
            let Ok(p) = av::parse(self.av_version, &datagram, self.receiver.key_state()) else {
                self.dropped += 1;
                continue;
            };
            let data = crypt.crypt(p.key_pos + BLOCK_SIZE as u64, p.data);
            let events = video.av_packet(&AvPacket { data: &data, ..p });
            for e in events {
                if let VideoEvent::CorruptFrames { start, end } = e {
                    self.send_message(VIDEO_FEEDBACK_CHANNEL, &corrupt_frame_message(start, end))?;
                }
                self.pending.push(StreamEvent::Video(e));
            }
        }
        Ok(())
    }

    /// Handles one datagram: checks it and returns the protobuf messages it carried, with the sequence
    /// number to acknowledge once they are handled. A datagram that fails its checks is dropped, as
    /// chiaki-ng drops it.
    fn take(&mut self, datagram: &[u8]) -> Result<(Vec<TakionMessage>, Option<u32>), LanError> {
        let Ok((got, ack)) = self.receiver.handle(datagram) else {
            self.dropped += 1;
            return Ok((Vec::new(), None));
        };
        let mut messages = Vec::new();
        let mut rest = Vec::new();
        for r in got {
            match r {
                Received::Data { data_type: data_type::PROTOBUF, data, .. } => {
                    // A message that does not decode is dropped, as chiaki-ng logs and drops it.
                    if let Ok(m) = TakionMessage::decode(data.as_slice()) {
                        messages.push(m);
                    }
                }
                other => rest.push(other),
            }
        }
        self.queue(rest)?;
        Ok((messages, ack))
    }

    /// chiaki-ng acknowledges data after its handler ran, so the acknowledgement of BANG is already
    /// signed with the keys BANG brought.
    fn ack(&mut self, seq: Option<u32>) -> Result<(), LanError> {
        if let Some(seq) = seq {
            let d = self.sender.data_ack(seq)?;
            self.socket.send(&d).map_err(io)?;
        }
        Ok(())
    }

    /// Waits for one message, within chiaki-ng's five seconds, and returns it with its acknowledgement
    /// still to send. A stream info that comes early (before BANG) is kept in `early`, as chiaki-ng
    /// keeps it.
    fn wait_for(
        &mut self,
        want: impl Fn(&TakionMessage) -> bool,
        early: &mut Option<TakionMessage>,
        what: &'static str,
    ) -> Result<(TakionMessage, Option<u32>), LanError> {
        let deadline = Instant::now() + EXPECT_TIMEOUT;
        loop {
            let left = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(LanError::Timeout(what))?;
            let Some(d) = recv(&self.socket, left)? else { continue };
            let (messages, ack) = self.take(&d)?;
            let mut found = None;
            for m in messages {
                if found.is_none() && want(&m) {
                    found = Some(m);
                } else if m.r#type == PayloadType::Disconnect as i32 {
                    return Err(LanError::StreamDisconnected(disconnect_reason(&m)));
                } else if m.r#type == PayloadType::Streaminfo as i32 && early.is_none() {
                    *early = Some(m);
                }
            }
            match found {
                Some(m) => return Ok((m, ack)),
                None => self.ack(ack)?,
            }
        }
    }

    /// Receives for up to `timeout`, sending the heartbeat each second as chiaki-ng does.
    pub fn poll(&mut self, timeout: Duration) -> Result<Vec<StreamEvent>, LanError> {
        if self.last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
            self.send_message(CHANNEL, &heartbeat_message())?;
            self.last_heartbeat = Instant::now();
        }
        self.send_feedback()?;
        // Wake in time to skip a lost video packet, as chiaki-ng's receive loop does, and for the next
        // controller feedback.
        let now = Instant::now();
        let timeout = [self.video_queue.next_deadline(), Some(self.feedback.next_deadline())]
            .into_iter()
            .flatten()
            .fold(timeout, |t, d| t.min(d.saturating_duration_since(now)));
        if self.pending.is_empty()
            && let Some(first) = recv(&self.socket, timeout)?
        {
            self.handle(&first)?;
            // Then everything already waiting: video comes in bursts of dozens of datagrams, and the
            // system's receive buffer must not fill between two polls.
            self.socket.set_nonblocking(true).map_err(io)?;
            let drained = self.drain();
            self.socket.set_nonblocking(false).map_err(io)?;
            drained?;
        }
        let ordered = self.video_queue.flush(Instant::now());
        self.video_ordered(ordered)?;
        Ok(std::mem::take(&mut self.pending))
    }

    fn handle(&mut self, datagram: &[u8]) -> Result<(), LanError> {
        let (messages, ack) = self.take(datagram)?;
        self.ack(ack)?;
        for m in messages {
            let event = if m.r#type == PayloadType::Disconnect as i32 {
                StreamEvent::Disconnected(disconnect_reason(&m))
            } else {
                StreamEvent::Message(Box::new(m))
            };
            self.pending.push(event);
        }
        Ok(())
    }

    /// Handles the datagrams already received, on a non-blocking socket, up to [`DRAIN_MAX`].
    fn drain(&mut self) -> Result<(), LanError> {
        let mut buf = [0u8; RECV_BUF];
        for _ in 0..DRAIN_MAX {
            match self.socket.recv(&mut buf) {
                Ok(n) => self.handle(&buf[..n])?,
                Err(e) if is_timeout(&e) => break,
                // Windows reports an ICMP port-unreachable from an earlier send this way.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                Err(e) => return Err(io(e)),
            }
        }
        Ok(())
    }

    /// chiaki-ng `stream_connection_send_disconnect`.
    pub fn disconnect(mut self) -> Result<(), LanError> {
        self.send_message(CHANNEL, &disconnect_message())
    }
}
