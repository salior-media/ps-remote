// SPDX-License-Identifier: AGPL-3.0-only
//! One session on its own thread: the console's stream on one side, the browser's WebRTC peer on the other.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use psr_av::audio::{AudioHeader, HEADER_SIZE};
use psr_av::video::VideoEvent;
use psr_input::controller::ControllerState;
use psr_lan::regist::RegisteredHost;
use psr_lan::session::{self, Codec, Session};
use psr_lan::stream::{self, Stream, StreamEvent, VideoProfile};
use serde::Serialize;
use str0m::change::{SdpAnswer, SdpOffer};

use crate::bridge::{Bridge, BridgeEvent};

/// How long one round of the loop waits for the console's datagrams. Short, because the browser's side is
/// served in the same loop.
const STREAM_WAIT: Duration = Duration::from_millis(1);
/// The ctrl connection only carries heartbeats once the stream runs; it is read this often.
const CTRL_INTERVAL: Duration = Duration::from_millis(50);
/// chiaki-ng's audio frame when the stream info carries none.
const DEFAULT_FRAME_SIZE: u32 = 480;

/// What `GET /api/status` reports.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Status {
    pub running: bool,
    pub browser_connected: bool,
    pub frames: u64,
    pub frames_lost: u64,
    pub audio_frames: u64,
    pub datagrams_dropped: u64,
    pub bad_input: u64,
    /// Why the session ended, once it has.
    pub ended: Option<String>,
}

enum Command {
    Offer(Box<SdpOffer>, Sender<Result<SdpAnswer, String>>),
    Stop,
}

/// A way to reach the session thread that can be cloned and used without the API's lock.
#[derive(Debug, Clone)]
pub struct Remote {
    tx: Sender<Command>,
    status: Arc<Mutex<Status>>,
}

impl Remote {
    pub fn status(&self) -> Status {
        self.status.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Answers a browser's offer. A new offer replaces the browser before it.
    pub fn offer(&self, offer: SdpOffer) -> Result<SdpAnswer, String> {
        if !self.status().running {
            return Err("no session is running".into());
        }
        let (reply, answer) = mpsc::channel();
        self.tx.send(Command::Offer(Box::new(offer), reply)).map_err(|_| "the session has ended".to_string())?;
        answer.recv_timeout(Duration::from_secs(5)).map_err(|_| "the session did not answer".to_string())?
    }
}

/// The running session, as the API sees it.
pub struct Handle {
    tx: Sender<Command>,
    status: Arc<Mutex<Status>>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handle").finish_non_exhaustive()
    }
}

/// The address this machine reaches `host` from: the browser's media goes to it. Loopback is not used,
/// because Firefox refuses 127.0.0.1 candidates.
pub fn media_address(host: IpAddr) -> std::io::Result<IpAddr> {
    let any: IpAddr = if host.is_ipv4() { Ipv4Addr::UNSPECIFIED.into() } else { Ipv6Addr::UNSPECIFIED.into() };
    let probe = UdpSocket::bind((any, 0))?;
    // Connecting a UDP socket sends nothing; it only picks the route.
    probe.connect((host, 9))?;
    Ok(probe.local_addr()?.ip())
}

/// Starts a session with `console` at `host` (this blocks for the session and stream handshakes, a second
/// or two), then runs it on its own thread.
pub fn start(host: IpAddr, console: &RegisteredHost) -> Result<Handle, String> {
    let media_ip = media_address(host).map_err(|e| format!("no route to the console: {e}"))?;
    let ctrl = session::start(host, console, Codec::H264).map_err(|e| e.to_string())?;
    let stream = stream::connect(host, &ctrl, &VideoProfile::p720_60(Codec::H264)).map_err(|e| e.to_string())?;
    spawn(ctrl, stream, media_ip, None)
}

/// Starts a session from away, through PSN (`psr_psn::play`; this blocks for the holepunch, around 40 s),
/// then runs it as [`start`] does. Sony's session is left when the session ends.
pub fn start_psn(app_secret: &str, config_dir: &Path) -> Result<Handle, String> {
    let playing = psr_psn::play::connect(app_secret, config_dir, &VideoProfile::p720_60(Codec::H264), |_| {})
        .map_err(|e| e.to_string())?;
    // The browser is on this machine: its media goes to our address on the network the holes left by.
    let media_ip = IpAddr::V4(playing.local_ip);
    let (ctrl, stream, leaver) = playing.into_parts();
    spawn(ctrl, stream, media_ip, Some(leaver))
}

fn spawn(
    ctrl: Session,
    stream: Stream,
    media_ip: IpAddr,
    psn: Option<psr_psn::play::Leaver>,
) -> Result<Handle, String> {
    let (tx, rx) = mpsc::channel();
    let status = Arc::new(Mutex::new(Status { running: true, ..Status::default() }));
    let thread_status = Arc::clone(&status);
    let thread = std::thread::Builder::new()
        .name("ps-remote session".into())
        .spawn(move || {
            let mut s =
                Loop { ctrl, stream, media_ip, rx, status: thread_status, bridge: None, header: Vec::new(), psn };
            // Whatever happens in the loop, even a panic, the console is told the stream ended and the
            // status says so; otherwise the console could hold a session the API thinks is gone.
            let ended = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.run())) {
                Ok(Ok(())) => "stopped".into(),
                Ok(Err(e)) => e,
                Err(_) => "the session failed inside ps-remote".into(),
            };
            s.finish(ended);
        })
        .map_err(|e| e.to_string())?;
    Ok(Handle { tx, status, thread: Some(thread) })
}

impl Handle {
    pub fn status(&self) -> Status {
        self.status.lock().map(|s| s.clone()).unwrap_or_default()
    }

    pub fn is_running(&self) -> bool {
        self.status().running
    }

    pub fn remote(&self) -> Remote {
        Remote { tx: self.tx.clone(), status: Arc::clone(&self.status) }
    }

    /// Ends the session and waits for its thread.
    pub fn stop(mut self) {
        let _ = self.tx.send(Command::Stop);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

struct Loop {
    ctrl: Session,
    stream: Stream,
    media_ip: IpAddr,
    rx: Receiver<Command>,
    status: Arc<Mutex<Status>>,
    bridge: Option<Bridge>,
    /// The codec header (SPS and PPS), sent in front of each frame.
    header: Vec<u8>,
    /// Over PSN, what leaves Sony's session; dropped after the stream ends.
    psn: Option<psr_psn::play::Leaver>,
}

impl Loop {
    fn update(&self, f: impl FnOnce(&mut Status)) {
        if let Ok(mut s) = self.status.lock() {
            f(&mut s);
        }
    }

    /// Runs until the console or the API ends the session; the error is why.
    fn run(&mut self) -> Result<(), String> {
        let header: &[u8; HEADER_SIZE] = &self.stream.info().audio_header;
        let frame_size = match AudioHeader::load(header).frame_size {
            0 => DEFAULT_FRAME_SIZE,
            n => n,
        };
        let mut last_ctrl = Instant::now();
        loop {
            if self.commands()? {
                return Ok(());
            }
            for e in self.stream.poll(STREAM_WAIT).map_err(|e| e.to_string())? {
                self.stream_event(e, frame_size)?;
            }
            if last_ctrl.elapsed() >= CTRL_INTERVAL {
                self.ctrl.poll(Duration::from_millis(1)).map_err(|e| e.to_string())?;
                last_ctrl = Instant::now();
            }
            self.browser()?;
            let (lost, dropped) = (self.stream.frames_lost(), self.stream.dropped());
            self.update(|s| {
                s.frames_lost = lost;
                s.datagrams_dropped = dropped;
            });
        }
    }

    /// Handles the API's commands; true when asked to stop.
    fn commands(&mut self) -> Result<bool, String> {
        loop {
            match self.rx.try_recv() {
                Ok(Command::Offer(offer, reply)) => {
                    let answer = Bridge::accept(*offer, self.media_ip, Instant::now());
                    let _ = reply.send(match answer {
                        Ok((bridge, answer)) => {
                            self.release_input()?;
                            self.bridge = Some(bridge);
                            self.update(|s| s.browser_connected = false);
                            Ok(answer)
                        }
                        Err(e) => Err(e.to_string()),
                    });
                }
                Ok(Command::Stop) | Err(TryRecvError::Disconnected) => return Ok(true),
                Err(TryRecvError::Empty) => return Ok(false),
            }
        }
    }

    fn stream_event(&mut self, e: StreamEvent, frame_size: u32) -> Result<(), String> {
        let now = Instant::now();
        match e {
            StreamEvent::Video(VideoEvent::Header { data, .. }) => self.header = data,
            StreamEvent::Video(VideoEvent::Frame(f)) => {
                self.update(|s| s.frames += 1);
                if let Some(b) = self.bridge.as_mut() {
                    b.send_video(&self.header, &f.data, now).map_err(|e| e.to_string())?;
                }
            }
            StreamEvent::Audio(a) => {
                self.update(|s| s.audio_frames += 1);
                if let Some(b) = self.bridge.as_mut() {
                    b.send_audio(a.index, frame_size, &a.data, now).map_err(|e| e.to_string())?;
                }
            }
            StreamEvent::Disconnected(reason) => return Err(format!("the console ended the stream: {reason}")),
            StreamEvent::Video(VideoEvent::CorruptFrames { .. }) | StreamEvent::Message(_) => {}
        }
        Ok(())
    }

    /// Serves the browser's peer, and acts on what it did.
    fn browser(&mut self) -> Result<(), String> {
        let Some(b) = self.bridge.as_mut() else { return Ok(()) };
        let events = match b.pump(Instant::now()) {
            Ok(events) => events,
            // A broken peer ends the browser's side, not the session: a new offer can replace it.
            Err(_) => vec![BridgeEvent::Closed],
        };
        for e in events {
            match e {
                BridgeEvent::Connected => {
                    self.update(|s| s.browser_connected = true);
                    // The browser can only start decoding at a keyframe: ask for one now.
                    self.stream.request_keyframe().map_err(|e| e.to_string())?;
                }
                BridgeEvent::KeyframeRequested => self.stream.request_keyframe().map_err(|e| e.to_string())?,
                BridgeEvent::Input(state) => self.stream.set_controller_state(&state).map_err(|e| e.to_string())?,
                BridgeEvent::BadInput => self.update(|s| s.bad_input += 1),
                BridgeEvent::Closed => {
                    self.bridge = None;
                    self.update(|s| s.browser_connected = false);
                    self.release_input()?;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Lets go of every button, so nothing stays held when a browser goes away.
    fn release_input(&mut self) -> Result<(), String> {
        self.stream.set_controller_state(&ControllerState::default()).map_err(|e| e.to_string())
    }

    fn finish(self, ended: String) {
        let Loop { stream, psn, status, .. } = self;
        let _ = stream.disconnect();
        // Sony's session is left once the console has been told the stream ended.
        drop(psn);
        let finish_status = status;
        if let Ok(mut s) = finish_status.lock() {
            s.running = false;
            s.browser_connected = false;
            s.ended = Some(ended);
        }
    }
}
