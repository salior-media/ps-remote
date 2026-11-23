// SPDX-License-Identifier: AGPL-3.0-only
//! Remote Play on the home network. Ported from chiaki-ng: so far discovery and wake-up
//! (`discovery.c`) and the console's HTTP dialect (`http.c`). Registration and session start follow in
//! steps 5 and 6 of `docs/PORT-MAP.md`.

pub mod discovery;
pub mod http;

#[derive(Debug, thiserror::Error)]
pub enum LanError {
    #[error("not an HTTP/1.1 response")]
    NotHttp,
    #[error("malformed header line: {0:?}")]
    BadHeader(String),
    #[error("network: {0}")]
    Io(std::io::Error),
}
