// SPDX-License-Identifier: AGPL-3.0-only
//! Starts a session with a linked console, opens the stream connection, and counts the whole video frames
//! and the audio datagrams that arrive for a number of seconds. With an output file, the frames are also
//! written to it, after the codec header, as a raw H.264 stream that `ffprobe` or `ffplay` can read.
//!
//!     cargo run -p psr-lan --example stream -- <console-ip> [seconds] [out.h264]
//!
//! Link the console first with the `link` example, and have it on (this example does not wake it). The
//! console shows that Remote Play has connected while it runs. Nothing secret is printed.

use std::io::Write;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use psr_lan::ctrl::CtrlEvent;
use psr_lan::session::{self, Codec};
use psr_av::video::VideoEvent;
use psr_lan::store;
use psr_lan::stream::{self, StreamEvent, VideoProfile};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let ip: IpAddr = args.next().ok_or("usage: stream <console-ip> [seconds]")?.parse()?;
    let seconds: u64 = args.next().map_or(Ok(10), |s| s.parse())?;
    let mut out = args.next().map(std::fs::File::create).transpose()?;
    let dir = store::default_dir().ok_or("no configuration folder (APPDATA / HOME) on this system")?;
    let console = store::load_all(&dir)?.into_iter().next().ok_or("no linked console saved; run the link example first")?;

    let mut ctrl = session::start(ip, &console, Codec::H264)?;
    println!("session started ({:?}, server type {:?})", ctrl.target(), ctrl.server_type());
    let profile = VideoProfile::p720_60(Codec::H264);
    let mut s = stream::connect(ip, &ctrl, &profile)?;
    for r in &s.info().resolutions {
        println!("console offers {}x{}, codec header {} bytes", r.width, r.height, r.video_header.len());
    }

    let (mut frames, mut fec, mut corrupt, mut audio, mut bytes, mut messages) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut largest = 0usize;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut ended = None;
    while Instant::now() < deadline && ended.is_none() {
        for e in s.poll(Duration::from_millis(20))? {
            match e {
                StreamEvent::Video(VideoEvent::Header { profile, data }) => {
                    println!("codec header for profile {profile}, {} bytes", data.len());
                    if let Some(f) = out.as_mut() {
                        f.write_all(&data)?;
                    }
                }
                StreamEvent::Video(VideoEvent::Frame(frame)) => {
                    frames += 1;
                    fec += u64::from(frame.fec_recovered);
                    bytes += frame.data.len() as u64;
                    largest = largest.max(frame.data.len());
                    if let Some(f) = out.as_mut() {
                        f.write_all(&frame.data)?;
                    }
                }
                StreamEvent::Video(VideoEvent::CorruptFrames { .. }) => corrupt += 1,
                StreamEvent::Audio(_) => audio += 1,
                StreamEvent::Message(_) => messages += 1,
                StreamEvent::Disconnected(reason) => ended = Some(reason),
            }
        }
        for e in ctrl.poll(Duration::from_millis(1))? {
            if !matches!(e, CtrlEvent::HeartbeatRequested) {
                println!("ctrl: {}", match e {
                    CtrlEvent::SessionId(_) => "another session ID".to_string(),
                    other => format!("{other:?}"),
                });
            }
        }
    }
    println!("{frames} whole frames ({} kB, largest {largest} bytes, {fec} rebuilt with FEC)", bytes / 1000);
    println!("{corrupt} corrupt-frame reports, {} frames lost", s.frames_lost());
    println!("{audio} Opus frames, {messages} other messages, {} datagrams dropped", s.dropped());
    match ended {
        Some(reason) => println!("the console ended the stream: {reason:?}"),
        None => {
            s.disconnect()?;
            println!("disconnected after {seconds} s");
        }
    }
    Ok(())
}
