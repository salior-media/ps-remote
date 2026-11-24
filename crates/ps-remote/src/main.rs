// SPDX-License-Identifier: AGPL-3.0-only
//! `ps-remote serve [--port N]`: the service. It listens on 127.0.0.1 only, writes its token to the
//! configuration folder (`service-token`, beside `consoles`, readable by this user only), and prints the
//! link to its test page, with the token in the link's fragment.

use std::net::{Ipv4Addr, SocketAddr};

use ps_remote::api;
use psr_lan::store;

/// The default port: chiaki-ng's session port plus 100, free of the console's own ports.
const DEFAULT_PORT: u16 = 9395;
const TOKEN_FILE: &str = "service-token";

fn port_from_args() -> Result<u16, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["serve"] => Ok(DEFAULT_PORT),
        ["serve", "--port", p] => p.parse().map_err(|_| format!("not a port: {p}")),
        _ => Err("usage: ps-remote serve [--port N]".into()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = port_from_args()?;
    let consoles_dir = store::default_dir().ok_or("no configuration folder (APPDATA / HOME) on this system")?;
    let dir = consoles_dir.parent().ok_or("the configuration folder has no parent")?.to_path_buf();
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
