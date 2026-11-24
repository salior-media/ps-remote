// SPDX-License-Identifier: AGPL-3.0-only
//! A WebRTC client for a running `ps-remote serve`, doing what the test page does without a browser: it
//! reads the token file, starts a session with the linked console, receives the video for a few seconds
//! into a raw H.264 file, and presses buttons on the input channel.
//!
//!     cargo run -p ps-remote --example client -- <port> <out.h264> <seconds> [button-bits...]
//!
//! Each button (psr-input's bits, e.g. 128 for D-pad down, 64 for up) is held for 150 ms, two seconds
//! apart, starting two seconds in.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use psr_lan::store;
use str0m::change::SdpAnswer;
use str0m::media::{Direction, MediaKind};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, RtcConfig};

fn http(port: u16, token: &str, method: &str, path: &str, ctype: &str, body: &str) -> Result<String, String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut out = String::new();
    s.read_to_string(&mut out).map_err(|e| e.to_string())?;
    let (head, body) = out.split_once("\r\n\r\n").ok_or("no HTTP response")?;
    if !head.starts_with("HTTP/1.1 2") {
        return Err(format!("{method} {path}: {} {body}", head.lines().next().unwrap_or("")));
    }
    // The service's small responses are not chunked.
    Ok(body.to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: client <port> <out.h264> <seconds> [button-bits...]";
    let port: u16 = args.next().ok_or(usage)?.parse()?;
    let mut out = std::fs::File::create(args.next().ok_or(usage)?)?;
    let seconds: u64 = args.next().ok_or(usage)?.parse()?;
    let presses: Vec<u32> = args.map(|a| a.parse()).collect::<Result<_, _>>()?;
    let consoles = store::default_dir().ok_or("no configuration folder")?;
    let token = std::fs::read_to_string(consoles.parent().ok_or("no parent")?.join("service-token"))?;

    let list = http(port, &token, "GET", "/api/consoles", "application/json", "")?;
    let consoles: serde_json::Value = serde_json::from_str(&list)?;
    let c = consoles
        .as_array()
        .and_then(|a| a.iter().find(|c| c["address"].is_string()))
        .ok_or("no linked console answered")?;
    println!("playing {} at {}", c["nickname"], c["address"]);
    let play = serde_json::json!({ "host": c["address"], "console": c["mac"] }).to_string();
    http(port, &token, "POST", "/api/play", "application/json", &play)?;

    let mut rtc = RtcConfig::new().clear_codecs().enable_h264(true).enable_opus(true, false).build(Instant::now());
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let local: SocketAddr = (
        ps_remote::runner::media_address(c["address"].as_str().ok_or("address")?.parse()?)?,
        socket.local_addr()?.port(),
    )
        .into();
    let socket = {
        drop(socket);
        UdpSocket::bind(local)?
    };
    socket.set_read_timeout(Some(Duration::from_millis(2)))?;
    rtc.add_local_candidate(Candidate::host(local, "udp")?).ok_or("candidate refused")?;
    let mut api = rtc.sdp_api();
    let video = api.add_media(MediaKind::Video, Direction::RecvOnly, None, None, None);
    api.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
    let channel = api.add_channel("input".into());
    let (offer, pending) = api.apply().ok_or("no offer")?;
    let answer = http(port, &token, "POST", "/api/offer", "application/sdp", &offer.to_sdp_string())?;
    rtc.sdp_api().accept_answer(pending, SdpAnswer::from_sdp_string(&answer)?)?;

    let start = Instant::now();
    let (mut frames, mut audio, mut bytes) = (0u64, 0u64, 0u64);
    let mut next_press = 0usize;
    let mut held_until: Option<Instant> = None;
    let mut buf = [0u8; 2000];
    while start.elapsed() < Duration::from_secs(seconds) {
        if let Ok((n, source)) = socket.recv_from(&mut buf) {
            let input = Input::Receive(
                Instant::now(),
                Receive { proto: Protocol::Udp, source, destination: local, contents: buf[..n].try_into()? },
            );
            rtc.handle_input(input)?;
        }
        rtc.handle_input(Input::Timeout(Instant::now()))?;
        loop {
            match rtc.poll_output()? {
                Output::Timeout(_) => break,
                Output::Transmit(t) => {
                    socket.send_to(&t.contents, t.destination)?;
                }
                Output::Event(Event::MediaData(d)) if d.mid == video => {
                    frames += 1;
                    bytes += d.data.len() as u64;
                    out.write_all(&d.data)?;
                }
                Output::Event(Event::MediaData(_)) => audio += 1,
                Output::Event(Event::Connected) => println!("{:.2} s: WebRTC connected", start.elapsed().as_secs_f32()),
                Output::Event(_) => {}
            }
        }
        let due = Duration::from_secs(2 * (next_press as u64 + 1));
        let mut send = |msg: String| -> Result<(), Box<dyn std::error::Error>> {
            if let Some(mut ch) = rtc.channel(channel) {
                ch.write(false, msg.as_bytes())?;
            }
            Ok(())
        };
        if let Some(until) = held_until
            && Instant::now() >= until
        {
            send(r#"{"buttons":0}"#.into())?;
            held_until = None;
        } else if held_until.is_none() && next_press < presses.len() && start.elapsed() >= due {
            println!("{:.2} s: pressing {}", start.elapsed().as_secs_f32(), presses[next_press]);
            send(format!(r#"{{"buttons":{}}}"#, presses[next_press]))?;
            held_until = Some(Instant::now() + Duration::from_millis(150));
            next_press += 1;
        }
    }
    println!("{frames} video frames ({} kB) and {audio} audio frames through WebRTC", bytes / 1000);
    println!("status: {}", http(port, &token, "GET", "/api/status", "application/json", "")?);
    http(port, &token, "POST", "/api/stop", "application/json", "")?;
    Ok(())
}
