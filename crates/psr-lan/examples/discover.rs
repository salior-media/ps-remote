// SPDX-License-Identifier: AGPL-3.0-only
//! Searches the home network for PlayStation consoles and prints what answers. It only sends search
//! broadcasts and listens; it never wakes or changes a console.
//!
//!     cargo run -p psr-lan --example discover -- [broadcast-address] [seconds]
//!
//! The broadcast address defaults to 255.255.255.255, the wait to 3 seconds.

use std::net::Ipv4Addr;
use std::time::Duration;

use psr_lan::discovery;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let broadcast: Ipv4Addr = args.next().map_or(Ok(Ipv4Addr::BROADCAST), |a| a.parse())?;
    let secs: u64 = args.next().map_or(Ok(3), |a| a.parse())?;
    eprintln!("searching {broadcast} for {secs}s ...");
    let hosts = discovery::search(broadcast, Duration::from_secs(secs))?;
    if hosts.is_empty() {
        println!("no console answered");
    }
    for h in &hosts {
        println!(
            "{}  {:?}  {}  {}  system {}  target {:?}  request port {}  app {}",
            h.addr,
            h.state,
            h.host_type.as_deref().unwrap_or("?"),
            h.host_name.as_deref().unwrap_or("?"),
            h.system_version.as_deref().unwrap_or("?"),
            h.target(),
            h.host_request_port,
            h.running_app_name.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}
