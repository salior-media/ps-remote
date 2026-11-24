// SPDX-License-Identifier: AGPL-3.0-only
//! Remote Play on the home network. Ported from chiaki-ng: discovery and wake-up (`discovery.c`), the
//! console's HTTP dialect (`http.c`) and registration (`regist.c`). Session start follows in step 6 of
//! `docs/PORT-MAP.md`.

pub mod discovery;
pub mod http;
pub mod regist;
pub mod store;

use psr_crypto::{CryptoError, Target};

#[derive(Debug, thiserror::Error)]
pub enum LanError {
    #[error("not an HTTP/1.1 response")]
    NotHttp,
    #[error("malformed header line: {0:?}")]
    BadHeader(String),
    #[error("network: {0}")]
    Io(std::io::Error),
    #[error("timed out waiting for the console's {0}")]
    Timeout(&'static str),
    #[error("nothing is listening on the console's registration port; is Remote Play turned on?")]
    NotListening,
    #[error("the console refused registration (HTTP {code}, reason {reason:?}); check the PIN and that the Link Device screen is open")]
    Refused { code: u16, reason: Option<u32> },
    #[error("the console's reply is missing {0}")]
    MissingField(&'static str),
    #[error("the console's reply was cut short")]
    Truncated,
    #[error("a PSN account ID is 8 bytes, given as base64 (12 characters)")]
    BadAccountId,
    #[error("{0:?} registers with the account ID, not the online ID")]
    NeedsAccountId(Target),
    #[error("no RP-Version for {0:?}")]
    NoRpVersion(Target),
    #[error("the system random number generator failed: {0}")]
    Random(String),
    #[error("saved console file is invalid: {0}")]
    BadStore(&'static str),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}
