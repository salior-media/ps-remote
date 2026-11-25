// SPDX-License-Identifier: AGPL-3.0-only
//! Steps 9b-1 and 9b-2 against PSN. With the saved sign-in, opens Sony's push websocket, creates a remote-play
//! session, and waits for Sony's "created" and "joined" notifications.
//!
//! With `--start`, it then starts remote play on the account's PS5 (the one with Remote Play on), waits for the
//! console to join and send its `customData1`, punches the control hole, and registers through it (step
//! 9c-1). It reports whether the console's keys match the ones saved when it was registered at home, never
//! the keys. (The data hole comes later: the console offers it only once the control protocol runs over the
//! control hole, step 9c-2.)
//!
//! Either way it leaves the session at the end. It prints what happened: counts and kinds, never addresses,
//! account IDs, or tokens.
//!
//!     PSN_RP_CLIENT_SECRET=... cargo run -p psr-psn --example psn_session [-- --start]

use std::net::IpAddr;
use std::time::Instant;

use psr_crypto::Target;
use psr_psn::holepunch;
use psr_psn::punch::{Port, Puncher};
use psr_psn::rudp::Rudp;
use psr_psn::{auth, devices, push, regist, rps, secret};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let with_start = std::env::args().any(|a| a == "--start");
    let app_secret = std::env::var(auth::SECRET_VAR)?.trim().to_string();
    let dir =
        psr_lan::store::default_dir().ok_or("no configuration folder")?.parent().ok_or("no parent")?.to_path_buf();
    let refresh = secret::load_refresh_token(&dir)?.ok_or("not signed in; run `ps-remote signin`")?;
    let tokens = auth::refresh(&app_secret, &refresh)?;
    if tokens.refresh != refresh {
        secret::save_refresh_token(&dir, &tokens.refresh)?;
    }
    let console = if with_start {
        let list = devices::list(&tokens.access)?;
        let d = list.into_iter().find(|d| d.remote_play).ok_or("no PS5 on this account has Remote Play on")?;
        let duid: [u8; 32] = d.duid.as_slice().try_into().map_err(|_| "the console's device ID is not 32 bytes")?;
        Some((psr_psn::printable(&d.name), duid))
    } else {
        None
    };

    let start = Instant::now();
    let t = || format!("{:>5} ms", start.elapsed().as_millis());
    let fqdn = push::fqdn(&tokens.access)?;
    let mut ws = push::Push::connect(&fqdn, &tokens.access)?;
    println!("{}  push websocket open", t());
    let session = rps::create(&tokens.access, &mut ws)?;
    println!("{}  session created and joined", t());

    let outcome = (|| -> Result<(), psr_psn::PsnError> {
        let Some((name, duid)) = &console else { return Ok(()) };
        let started = holepunch::start(&tokens.access, &session.created, duid, &mut ws)?;
        println!("{}  {name} joined the session; customData1 is {} bytes", t(), started.custom_data1.len());
        let mut puncher = Puncher::new(&tokens.access, &session.created, duid)?;
        puncher.on_step = |step| println!("{:>14}  - {step}", "");
        puncher.on_passed_over = |a, req, err| println!("{:>14}  ? passed over {a:?}, request {req}, error {err}", "");
        {
            let port = Port::Ctrl;
            let hole = puncher.punch(&mut ws, port)?;
            let ours = if private(hole.candidate.addr_mapped) { "LAN" } else { "public" };
            let ids = if hole.ids_mirrored { "mirrored" } else { "did not mirror" };
            println!(
                "{}  {port:?} hole punched at the console's {:?} candidate, through our {ours} address; its answer {ids} our IDs",
                t(),
                hole.candidate.kind
            );
            let local_ip = hole.local_ip;
            let mut rudp = Rudp::new(hole.socket)?;
            let done = regist::register(&mut rudp, Target::Ps5V1, session.created.account_id, &started, local_ip)?;
            let consoles = dir.join("consoles");
            let saved = psr_lan::store::load_all(&consoles).map_err(psr_psn::PsnError::Lan)?;
            let same = match saved.iter().find(|h| h.server_mac == done.host.server_mac) {
                Some(h) if h.rp_regist_key == done.host.rp_regist_key && h.rp_key == done.host.rp_key => "match",
                Some(_) => "differ from",
                None => "have nothing saved at home to compare with, for",
            };
            let finished = if done.finished { "and finished" } else { "without the console's FINISH" };
            println!("{}  registered through the hole {finished}; its keys {same} the ones saved at home", t());
        }
        Ok(())
    })();
    // Leave whatever happened, so no session is left behind at Sony.
    rps::leave(&tokens.access, &session.created.session_id)?;
    println!("{}  left the session", t());
    ws.close();
    outcome?;
    Ok(())
}

fn private(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.is_private())
}
