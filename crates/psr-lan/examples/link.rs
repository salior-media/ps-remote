// SPDX-License-Identifier: AGPL-3.0-only
//! Links this device with a PS5 on the home network (Remote Play's "Link Device").
//!
//!     cargo run -p psr-lan --example link -- <console-ip>
//!
//! First open *Settings → System → Remote Play → Link Device* on the console. The program asks for your
//! PSN account ID (from the `psn_account_id` example) and the 8-digit PIN the console shows, then saves
//! the console's keys in your configuration folder (`%APPDATA%\ps-remote\consoles` on Windows). It
//! prints where, and never prints the keys.

use std::io::{BufRead, Write};
use std::net::IpAddr;

use psr_lan::{discovery, regist, store};

fn ask(prompt: &str) -> std::io::Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ip: IpAddr = std::env::args().nth(1).ok_or("usage: link <console-ip>")?.parse()?;
    // Ask the console what it is, so the right protocol is used.
    let hosts = match ip {
        IpAddr::V4(v4) => discovery::search(v4, std::time::Duration::from_secs(2))?,
        IpAddr::V6(_) => Vec::new(),
    };
    let host = hosts.iter().find(|h| h.addr == ip).ok_or("the console didn't answer a search; is it on and on this network?")?;
    let target = host.target();
    println!("found {} ({:?}, {:?})", host.host_name.as_deref().unwrap_or("console"), host.state, target);

    let identity = regist::Identity::account_id_from_base64(&ask("PSN account ID: ")?)?;
    let pin: u32 = ask("PIN shown on the console: ")?.replace(' ', "").parse().map_err(|_| "the PIN is 8 digits")?;

    let registered = regist::register(ip, target, &identity, pin)?;
    let dir = store::default_dir().ok_or("no configuration folder (APPDATA / HOME) on this system")?;
    let path = store::save(&dir, &registered)?;
    println!("linked with {}; saved to {}", registered.server_nickname.as_deref().unwrap_or("the console"), path.display());
    Ok(())
}
