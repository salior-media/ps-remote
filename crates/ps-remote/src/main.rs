// SPDX-License-Identifier: AGPL-3.0-only
//! The `ps-remote` command.
//!
//! - `ps-remote serve [--port N]`: the service. It listens on 127.0.0.1 only, writes its token to the
//!   configuration folder (`service-token`, beside `consoles`, readable by this user only), and prints the link
//!   to its test page, with the token in the link's fragment.
//! - `ps-remote signin`: signs in to PSN on Sony's own page, for play from away (`docs/PSN.md`). Only the refresh
//!   token is kept, encrypted on Windows.
//! - `ps-remote psn-consoles`: the PS5s on the signed-in account.
//! - `ps-remote signout`: forgets the PSN sign-in.

use std::io::BufRead;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use ps_remote::api;
use psr_lan::store;
use psr_psn::{auth, devices, secret};

/// The default port: chiaki-ng's session port plus 100, free of the console's own ports.
const DEFAULT_PORT: u16 = 9395;
const TOKEN_FILE: &str = "service-token";
const USAGE: &str = "usage: ps-remote serve [--port N] | signin | psn-consoles | signout";

type Error = Box<dyn std::error::Error + Send + Sync>;

/// The configuration folder (`%APPDATA%\ps-remote` on Windows), beside `consoles`.
fn config_dir() -> Result<PathBuf, Error> {
    let consoles = store::default_dir().ok_or("no configuration folder (APPDATA / HOME) on this system")?;
    Ok(consoles.parent().ok_or("the configuration folder has no parent")?.to_path_buf())
}

fn app_secret() -> Result<String, Error> {
    let s = std::env::var(auth::SECRET_VAR).map_err(|_| {
        format!("set {} to the CLIENT_SECRET value in chiaki-ng's scripts/psn-account-id.py first", auth::SECRET_VAR)
    })?;
    Ok(s.trim().to_string())
}

fn signin() -> Result<(), Error> {
    let secret = app_secret()?;
    println!("1. Open this address in your browser and sign in to PSN on Sony's page:\n\n{}\n", auth::login_url());
    println!("2. When the page shows \"redirect\", copy the whole address from the address bar and paste it here:");
    let mut pasted = String::new();
    std::io::stdin().lock().read_line(&mut pasted)?;
    let code = auth::code_from_redirect(&pasted)?;
    let tokens = auth::exchange_code(&secret, &code)?;
    let dir = config_dir()?;
    secret::save_refresh_token(&dir, &tokens.refresh)?;
    println!(
        "\nSigned in. The sign-in is kept in {} (encrypted on Windows).",
        dir.join(secret::REFRESH_TOKEN_FILE).display()
    );
    Ok(())
}

fn psn_consoles() -> Result<(), Error> {
    let secret = app_secret()?;
    let dir = config_dir()?;
    let refresh = secret::load_refresh_token(&dir)?.ok_or("not signed in to PSN; run `ps-remote signin` first")?;
    let tokens = auth::refresh(&secret, &refresh)?;
    // Sony may hand out a new refresh token; keep whichever is current.
    if tokens.refresh != refresh {
        secret::save_refresh_token(&dir, &tokens.refresh)?;
    }
    let list = devices::list(&tokens.access)?;
    if list.is_empty() {
        println!("no PS5 on this account");
    }
    for d in &list {
        println!("{}  Remote Play {}", psr_psn::printable(&d.name), if d.remote_play { "on" } else { "off" });
    }
    Ok(())
}

async fn serve(port: u16) -> Result<(), Error> {
    let dir = config_dir()?;
    let consoles_dir = store::default_dir().ok_or("no configuration folder")?;
    store::create_private_dir(&dir)?;
    let token = api::new_token()?;
    let token_file = dir.join(TOKEN_FILE);
    store::write_private(&token_file, token.as_bytes())?;

    let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await?;
    let port = listener.local_addr()?.port();
    // The link carries the token in its fragment, which a browser never sends; the test page reads it there.
    println!("ps-remote is listening. Open http://127.0.0.1:{port}/#token={token}");
    println!("(The token is also in {}, for other clients.)", token_file.display());
    axum::serve(listener, api::router(api::Service::new(token, port, consoles_dir))).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["serve"] => serve(DEFAULT_PORT).await,
        ["serve", "--port", p] => serve(p.parse().map_err(|_| format!("not a port: {p}"))?).await,
        // Blocking calls (stdin, HTTP) off the async runtime.
        ["signin"] => tokio::task::spawn_blocking(signin).await?,
        ["psn-consoles"] => tokio::task::spawn_blocking(psn_consoles).await?,
        ["signout"] => {
            secret::forget(&config_dir()?)?;
            println!("Signed out on this machine: the saved PSN sign-in is deleted.");
            println!("It stays valid at Sony until it expires; to cut it off now, remove the Remote Play app's access");
            println!("in your PSN account's security settings.");
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}
