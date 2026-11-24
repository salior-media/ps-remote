// SPDX-License-Identifier: AGPL-3.0-only
//! Steps 9b-1 and 9b-2a against PSN. With the saved sign-in, opens Sony's push websocket, creates a remote-play
//! session, and waits for Sony's "created" and "joined" notifications.
//!
//! With `--start`, it then starts remote play on the account's PS5 (the one with Remote Play on). It waits for
//! the console to join and send its `customData1`, then for the console's first offer, and acknowledges it.
//!
//! Either way it leaves the session at the end. It prints what happened: counts and kinds, never addresses,
//! account IDs, or tokens.
//!
//!     PSN_RP_CLIENT_SECRET=... cargo run -p psr-psn --example psn_session [-- --start]

use std::time::Instant;

use psr_psn::holepunch::{self, Action};
use psr_psn::{auth, devices, push, rps, secret};

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
        let offer = holepunch::wait_message(&mut ws, &[Action::Offer], Instant::now() + holepunch::START_TIMEOUT)?;
        let req = offer.conn_request.as_ref();
        let kinds: Vec<String> =
            req.map(|r| r.candidates.iter().map(|c| format!("{:?}", c.kind)).collect()).unwrap_or_default();
        println!(
            "{}  the console's offer: request {}, NAT type {}, {} candidates {:?}",
            t(),
            offer.req_id,
            req.map_or(0, |r| r.nat_type),
            kinds.len(),
            kinds
        );
        let ack = holepunch::short_message("RESULT", offer.req_id, 0);
        holepunch::send_message(&tokens.access, &session.created, duid, &ack)?;
        println!("{}  acknowledged the offer", t());
        Ok(())
    })();
    // Leave whatever happened, so no session is left behind at Sony.
    rps::leave(&tokens.access, &session.created.session_id)?;
    println!("{}  left the session", t());
    ws.close();
    outcome?;
    Ok(())
}
