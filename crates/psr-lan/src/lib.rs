// SPDX-License-Identifier: AGPL-3.0-only
//! Remote Play on the home network. Ported from chiaki-ng: discovery and wake-up (`discovery.c`), the
//! console's HTTP dialect (`http.c`), registration (`regist.c`), the start of a session (`session.c`,
//! `ctrl.c`) and the stream connection (`streamconnection.c`).

pub mod ctrl;
pub mod discovery;
pub mod http;
pub mod regist;
pub mod session;
pub mod store;
pub mod stream;

use psr_crypto::{CryptoError, Target};

use crate::session::reason_text;

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
    #[error("{0:?} cannot register over PSN; it registers at home with a PIN")]
    NoPsnRegist(Target),
    #[error("the system random number generator failed: {0}")]
    Random(String),
    #[error("saved console file is invalid: {0}")]
    BadStore(&'static str),
    #[error("the console refused the session (HTTP {code}): {}", reason_text(*reason))]
    SessionRefused { code: u16, reason: Option<u32>, rp_version: Option<String> },
    #[error("the console's session nonce is not 16 bytes of base64")]
    BadNonce,
    #[error("the console refused the ctrl connection (HTTP {0})")]
    CtrlRefused(u16),
    #[error("the console sent a ctrl message larger than 512 bytes")]
    CtrlOverflow,
    #[error("the console closed the ctrl connection")]
    CtrlClosed,
    #[error("the console asks for the PSN user's login passcode, which ps-remote does not send yet")]
    LoginPinRequired,
    #[error("the console's BANG was refused: {0}")]
    Bang(String),
    #[error("the console's stream info is invalid: {0}")]
    StreamInfo(&'static str),
    #[error("the console ended the stream: {0:?}")]
    StreamDisconnected(String),
    #[error(transparent)]
    Takion(#[from] psr_takion::TakionError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}
