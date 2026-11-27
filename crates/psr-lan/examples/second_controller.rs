// SPDX-License-Identifier: AGPL-3.0-only
//! The second-controller experiment (games scope *PlayStation next*, §3): starts a stream with a linked console, then
//! tells it a second controller, id 1, connected, and keeps the stream up while someone watches the TV. Does the PS5
//! ask "who is using this controller?", or show a player 2? At the end it says controller 1 went away and stops.
//!
//!     cargo run -p psr-lan --example second_controller -- <console-ip> [seconds, default 60]
//!
//! It presses nothing: the stream's input packets carry no controller id, so this only asks whether the console
//! takes a second controller at all. Nothing secret is printed.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use psr_lan::session::{self, Codec};
use psr_lan::store;
use psr_lan::stream::{self, Stream, StreamEvent, VideoProfile};

/// How long the stream runs before controller 1 is announced, so the console settles first.
const SETTLE: Duration = Duration::from_secs(5);

/// Polls the stream and the session's ctrl connection for `d`, counting frames. Ends early if the console does.
fn run_for(
    s: &mut Stream,
    ctrl: &mut session::Session,
    start: Instant,
    d: Duration,
    frames: &mut u64,
) -> Result<(), String> {
    let until = Instant::now() + d;
    while Instant::now() < until {
        for e in s.poll(Duration::from_millis(5)).map_err(|e| e.to_string())? {
            match e {
                StreamEvent::Video(psr_av::video::VideoEvent::Frame(_)) => *frames += 1,
                StreamEvent::Disconnected(reason) => return Err(format!("the console ended the stream: {reason}")),
                // A message from the console after the announcement is part of the answer: its type, and any
                // controller or microphone fields, which carry nothing secret.
                StreamEvent::Message(m) => println!(
                    "{:.1} s: the console sent message type {} controller {:?} mic {:?}",
                    start.elapsed().as_secs_f32(),
                    m.r#type,
                    m.controller_connection_payload,
                    m.mic_connection_payload
                ),
                _ => {}
            }
        }
        ctrl.poll(Duration::from_millis(1)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: second_controller <console-ip> [seconds]";
    let ip: IpAddr = args.next().ok_or(usage)?.parse()?;
    let seconds: u64 = args.next().map(|a| a.parse()).transpose()?.unwrap_or(60);
    let dir = store::default_dir().ok_or("no configuration folder (APPDATA / HOME) on this system")?;
    let console =
        store::load_all(&dir)?.into_iter().next().ok_or("no linked console saved; run the link example first")?;

    let mut ctrl = session::start(ip, &console, Codec::H264)?;
    let mut s = stream::connect(ip, &ctrl, &VideoProfile::p720_60(Codec::H264))?;
    let start = Instant::now();
    let mut frames = 0;
    run_for(&mut s, &mut ctrl, start, SETTLE, &mut frames)?;
    println!("{:.1} s: announcing controller 1 (connected). Watch the TV now.", start.elapsed().as_secs_f32());
    s.announce_controller(1, true)?;
    let watched = run_for(&mut s, &mut ctrl, start, Duration::from_secs(seconds), &mut frames);
    if let Err(e) = &watched {
        println!("{:.1} s: {e}", start.elapsed().as_secs_f32());
    } else {
        println!("{:.1} s: announcing controller 1 gone, then stopping.", start.elapsed().as_secs_f32());
        s.announce_controller(1, false)?;
        run_for(&mut s, &mut ctrl, start, Duration::from_secs(2), &mut frames)?;
        s.disconnect()?;
    }
    println!("{frames} frames over {:.1} s", start.elapsed().as_secs_f32());
    Ok(())
}
