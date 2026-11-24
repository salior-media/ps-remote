// SPDX-License-Identifier: AGPL-3.0-only
//! Starts a stream with a linked console and presses buttons on it, two seconds apart, while writing the
//! video to a raw H.264 file. Comparing frames before and after each press shows whether it moved the game.
//!
//!     cargo run -p psr-lan --example press -- <console-ip> <out.h264> <button>...
//!
//! Buttons: up, down, left, right, cross, moon, box, pyramid, l1, r1, options. Each is held for 150 ms.
//! Pick ones that are safe where the console is (moving through a menu, say). Nothing secret is printed.

use std::io::Write;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use psr_av::video::VideoEvent;
use psr_input::controller::{ControllerState, button};
use psr_lan::session::{self, Codec};
use psr_lan::store;
use psr_lan::stream::{self, Stream, StreamEvent, VideoProfile};

const GAP: Duration = Duration::from_secs(2);
const HOLD: Duration = Duration::from_millis(150);

fn button_named(name: &str) -> Option<u32> {
    Some(match name {
        "up" => button::DPAD_UP,
        "down" => button::DPAD_DOWN,
        "left" => button::DPAD_LEFT,
        "right" => button::DPAD_RIGHT,
        "cross" => button::CROSS,
        "moon" => button::MOON,
        "box" => button::BOX,
        "pyramid" => button::PYRAMID,
        "l1" => button::L1,
        "r1" => button::R1,
        "options" => button::OPTIONS,
        _ => return None,
    })
}

/// Polls the stream (and the session's ctrl connection) for `d`, writing frames to `out`.
fn run_for(
    s: &mut Stream,
    ctrl: &mut session::Session,
    out: &mut std::fs::File,
    d: Duration,
    frames: &mut u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let until = Instant::now() + d;
    while Instant::now() < until {
        for e in s.poll(Duration::from_millis(5))? {
            match e {
                StreamEvent::Video(VideoEvent::Header { data, .. }) => out.write_all(&data)?,
                StreamEvent::Video(VideoEvent::Frame(f)) => {
                    out.write_all(&f.data)?;
                    *frames += 1;
                }
                StreamEvent::Disconnected(reason) => {
                    return Err(format!("the console ended the stream: {reason}").into());
                }
                _ => {}
            }
        }
        ctrl.poll(Duration::from_millis(1))?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: press <console-ip> <out.h264> <button>...";
    let ip: IpAddr = args.next().ok_or(usage)?.parse()?;
    let mut out = std::fs::File::create(args.next().ok_or(usage)?)?;
    let presses: Vec<(String, u32)> = args
        .map(|a| button_named(&a).map(|b| (a.clone(), b)).ok_or(format!("unknown button {a:?}")))
        .collect::<Result<_, _>>()?;
    let dir = store::default_dir().ok_or("no configuration folder (APPDATA / HOME) on this system")?;
    let console =
        store::load_all(&dir)?.into_iter().next().ok_or("no linked console saved; run the link example first")?;

    let mut ctrl = session::start(ip, &console, Codec::H264)?;
    let mut s = stream::connect(ip, &ctrl, &VideoProfile::p720_60(Codec::H264))?;
    let start = Instant::now();
    let mut frames = 0;
    run_for(&mut s, &mut ctrl, &mut out, GAP, &mut frames)?;
    for (name, b) in presses {
        println!("{:.2} s: pressing {name}", start.elapsed().as_secs_f32());
        s.set_controller_state(&ControllerState { buttons: b, ..Default::default() })?;
        run_for(&mut s, &mut ctrl, &mut out, HOLD, &mut frames)?;
        s.set_controller_state(&ControllerState::default())?;
        run_for(&mut s, &mut ctrl, &mut out, GAP, &mut frames)?;
    }
    s.disconnect()?;
    println!("{frames} frames written over {:.1} s", start.elapsed().as_secs_f32());
    Ok(())
}
