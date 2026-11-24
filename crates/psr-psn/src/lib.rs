// SPDX-License-Identifier: AGPL-3.0-only
//! Remote Play over PSN, from away from home (`docs/PSN.md`). Step 9a: signing in on Sony's own page, keeping
//! only the refresh token (encrypted on Windows), and listing the account's consoles.

pub mod auth;
pub mod devices;
pub mod secret;

#[derive(Debug, thiserror::Error)]
pub enum PsnError {
    #[error("that is not the address of Sony's Remote Play redirect page")]
    NotRedirect,
    #[error("the redirect address has no sign-in code in it")]
    NoCode,
    #[error("PSN's reply has no usable \"{0}\"")]
    MissingField(&'static str),
    #[error("PSN's reply has a malformed \"{0}\"")]
    BadField(&'static str),
    /// Sony refused: an expired or revoked sign-in, or a wrong app secret, among others. The body is not kept:
    /// it can echo what was sent.
    #[error("PSN answered HTTP {0}")]
    Status(u16),
    #[error("PSN could not be reached: {0}")]
    Network(String),
    #[error("the saved sign-in could not be encrypted or decrypted for this user")]
    Seal,
    #[error("the configuration folder: {0}")]
    Io(std::io::Error),
}

impl PsnError {
    pub(crate) fn from_ureq(e: ureq::Error) -> Self {
        match e {
            ureq::Error::StatusCode(code) => Self::Status(code),
            other => Self::Network(other.to_string()),
        }
    }
}
