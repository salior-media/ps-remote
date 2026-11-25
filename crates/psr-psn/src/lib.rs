// SPDX-License-Identifier: AGPL-3.0-only
//! Remote Play over PSN, from away from home (`docs/PSN.md`). Step 9a: signing in on Sony's own page, keeping
//! only the refresh token (encrypted on Windows), and listing the account's consoles. Step 9b: Sony's push
//! notifications and the remote-play session the holepunch meets in.

pub mod auth;
pub mod devices;
pub mod holepunch;
pub mod punch;
pub mod push;
pub mod regist;
pub mod rps;
pub mod rudp;
pub mod session;
pub mod secret;
pub mod stun;

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
    /// Sony refused: an expired or revoked sign-in, or a wrong app secret, among others. Only Sony's error
    /// code and message are kept from the body, never the rest, which could echo what was sent.
    #[error("PSN refused the {what} (HTTP {code}){}", reason.as_deref().map(|r| format!(": {r}")).unwrap_or_default())]
    Status { what: &'static str, code: u16, reason: Option<String> },
    #[error("PSN could not be reached: {0}")]
    Network(String),
    #[error("the saved sign-in could not be encrypted or decrypted for this user")]
    Seal,
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    #[error("the console ended the remote-play session")]
    Terminated,
    #[error("the configuration folder: {0}")]
    Io(std::io::Error),
    /// The console's RUDP answer was not what the exchange needs.
    #[error("RUDP: {0}")]
    Rudp(&'static str),
    /// The console sent RUDP's FINISH where ctrl was running: it has closed the channel.
    #[error("the console finished the ctrl channel")]
    Finished,
    /// What the console said once the exchange reached it: a refused registration, a malformed answer.
    #[error(transparent)]
    Lan(psr_lan::LanError),
}

/// Longest error message kept from a refusal.
const REASON_MAX: usize = 200;

/// Sony's own error code and message from a refusal's body, in either of the two shapes its services use:
/// `{"error":"invalid_grant","error_description":"...","error_code":4159}` from the sign-in service, and
/// `{"error":{"code":2281604,"message":"..."}}` from the others.
pub fn refusal_reason(body: &serde_json::Value) -> Option<String> {
    let e = &body["error"];
    let parts: Vec<String> = [
        e.as_str().map(str::to_string),
        body["error_code"].as_i64().map(|c| c.to_string()),
        body["error_description"].as_str().map(str::to_string),
        e["code"].as_i64().map(|c| c.to_string()),
        e["message"].as_str().map(str::to_string),
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut reason = printable(&parts.join(" "));
    if reason.is_empty() {
        return None;
    }
    if let Some((cut, _)) = reason.char_indices().nth(REASON_MAX) {
        reason.truncate(cut);
    }
    Some(reason)
}

/// Text from the network made safe to print: control characters (a terminal's escape sequences among them)
/// become `?`.
pub fn printable(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

/// The agent every PSN request goes through: chiaki-ng's timeout, HTTPS only, and no redirects (a redirect
/// could send a request carrying a token on to another address). Refusals come back as responses, so their
/// reason can be read.
pub fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(auth::TIMEOUT))
        .https_only(true)
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into()
}

/// The JSON body of a successful reply, or the refusal with Sony's reason. `what` names the request.
pub(crate) fn reply(
    what: &'static str,
    sent: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<serde_json::Value, PsnError> {
    let mut r = sent.map_err(|e| PsnError::Network(e.to_string()))?;
    let code = r.status().as_u16();
    let json: Option<serde_json::Value> = r.body_mut().read_json().ok();
    if !(200..300).contains(&code) {
        return Err(PsnError::Status { what, code, reason: json.as_ref().and_then(refusal_reason) });
    }
    json.ok_or(PsnError::MissingField("body"))
}

/// As [`reply`], for requests whose success may come with no body at all (Sony answers some with 204).
pub(crate) fn reply_any(
    what: &'static str,
    sent: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<Option<serde_json::Value>, PsnError> {
    let mut r = sent.map_err(|e| PsnError::Network(e.to_string()))?;
    let code = r.status().as_u16();
    let json: Option<serde_json::Value> = r.body_mut().read_json().ok();
    if !(200..300).contains(&code) {
        return Err(PsnError::Status { what, code, reason: json.as_ref().and_then(refusal_reason) });
    }
    Ok(json)
}
