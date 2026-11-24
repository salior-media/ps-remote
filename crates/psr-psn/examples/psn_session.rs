// SPDX-License-Identifier: AGPL-3.0-only
//! Step 9b-1 against PSN: with the saved sign-in, opens Sony's push websocket, creates a remote-play session,
//! waits for Sony's "created" and "joined" notifications, then leaves the session. The console is not
//! involved. Prints what happened, not the account's IDs or any token.
//!
//!     PSN_RP_CLIENT_SECRET=... cargo run -p psr-psn --example psn_session

use std::time::Instant;

use psr_psn::{auth, push, rps, secret};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app_secret = std::env::var(auth::SECRET_VAR)?.trim().to_string();
    let dir =
        psr_lan::store::default_dir().ok_or("no configuration folder")?.parent().ok_or("no parent")?.to_path_buf();
    let refresh = secret::load_refresh_token(&dir)?.ok_or("not signed in; run `ps-remote signin`")?;
    let tokens = auth::refresh(&app_secret, &refresh)?;
    if tokens.refresh != refresh {
        secret::save_refresh_token(&dir, &tokens.refresh)?;
    }
    let start = Instant::now();
    let fqdn = push::fqdn(&tokens.access)?;
    println!("{:>5} ms  push server found", start.elapsed().as_millis());
    let mut ws = push::Push::connect(&fqdn, &tokens.access)?;
    println!("{:>5} ms  push websocket open (TLS verified with the shipped intermediate)", start.elapsed().as_millis());
    let session = rps::create(&tokens.access, &mut ws)?;
    println!(
        "{:>5} ms  session created and joined: session ID {} characters, account ID present, online ID {} characters",
        start.elapsed().as_millis(),
        session.created.session_id.len(),
        session.online_id.len()
    );
    rps::leave(&tokens.access, &session.created.session_id)?;
    println!("{:>5} ms  left the session", start.elapsed().as_millis());
    ws.close();
    Ok(())
}
