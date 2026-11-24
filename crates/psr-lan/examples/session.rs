// SPDX-License-Identifier: AGPL-3.0-only
//! Starts a Remote Play session with a linked console on the home network and keeps its ctrl channel
//! open, answering heartbeats, for a number of seconds.
//!
//!     cargo run -p psr-lan --example session -- <console-ip> [seconds]
//!
//! Link the console first with the `link` example. A console in rest mode is woken first. The console
//! shows that Remote Play has connected; it ends when this program exits. Nothing secret is printed:
//! the session ID is shown by its length only.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use psr_lan::discovery::{self, Console, HostState};
use psr_lan::session::{self, Codec};
use psr_lan::{ctrl::CtrlEvent, regist::RegisteredHost, store};

const WAKE_WAIT: Duration = Duration::from_secs(40);

fn hex_mac(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02X}")).collect()
}

fn find(ip: IpAddr) -> Result<discovery::Host, Box<dyn std::error::Error>> {
    let IpAddr::V4(v4) = ip else { return Err("only IPv4 consoles are searched for".into()) };
    discovery::search(v4, Duration::from_secs(2))?
        .into_iter()
        .find(|h| h.addr == ip)
        .ok_or_else(|| "the console didn't answer a search; is it on and on this network?".into())
}

fn saved_console(host: &discovery::Host) -> Result<RegisteredHost, Box<dyn std::error::Error>> {
    let dir = store::default_dir().ok_or("no configuration folder (APPDATA / HOME) on this system")?;
    let mut saved = store::load_all(&dir)?;
    if let Some(id) = &host.host_id
        && let Some(i) = saved.iter().position(|c| hex_mac(&c.server_mac).eq_ignore_ascii_case(id))
    {
        return Ok(saved.swap_remove(i));
    }
    match saved.len() {
        1 => Ok(saved.remove(0)),
        0 => Err("no linked console saved; run the link example first".into()),
        _ => Err("several consoles are saved and none matches this one's host-id".into()),
    }
}

fn wake_if_resting(ip: IpAddr, host: discovery::Host, console: &RegisteredHost) -> Result<(), Box<dyn std::error::Error>> {
    if host.state != HostState::Standby {
        return Ok(());
    }
    let credential = console.wakeup_credential().ok_or("the saved registration key is not a wake-up credential")?;
    let kind = if host.is_ps5() { Console::Ps5 } else { Console::Ps4 };
    println!("console is in rest mode; waking it");
    discovery::wake(ip, kind, credential)?;
    let deadline = Instant::now() + WAKE_WAIT;
    while Instant::now() < deadline {
        if find(ip).is_ok_and(|h| h.state == HostState::Ready) {
            return Ok(());
        }
    }
    Err("the console did not wake within 40 seconds".into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let ip: IpAddr = args.next().ok_or("usage: session <console-ip> [seconds]")?.parse()?;
    let seconds: u64 = args.next().map_or(Ok(20), |s| s.parse())?;
    let host = find(ip)?;
    let console = saved_console(&host)?;
    println!("found {} ({:?})", host.host_name.as_deref().unwrap_or("console"), host.state);
    wake_if_resting(ip, host, &console)?;

    let mut s = session::start(ip, &console, Codec::H264)?;
    println!(
        "session started: target {:?}, server type {:?}, session ID {} characters{}",
        s.target(),
        s.server_type(),
        s.session_id().len(),
        if s.session_id_was_fallback() { " (chiaki-ng's fallback, as the console's is in a newer form)" } else { "" }
    );
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut heartbeats = 0;
    while Instant::now() < deadline {
        for event in s.poll(Duration::from_millis(500))? {
            match event {
                CtrlEvent::HeartbeatRequested => heartbeats += 1,
                CtrlEvent::SessionId(_) => println!("ctrl: another session ID"),
                CtrlEvent::Other { message_type, payload } => {
                    println!("ctrl message {message_type:#x} ({} bytes)", payload.len());
                }
                other => println!("ctrl: {other:?}"),
            }
        }
    }
    println!("answered {heartbeats} heartbeats in {seconds} s; closing the session");
    Ok(())
}
