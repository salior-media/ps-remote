// SPDX-License-Identifier: AGPL-3.0-only
//! Signing in to PSN on Sony's own page, and keeping the session going with the refresh token. Ported from
//! chiaki-ng `gui/src/psntoken.cpp` and `gui/include/psnaccountid.h` (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! The person signs in on Sony's page in their own browser, so ps-remote never sees the password. Sony
//! then sends the browser to [`REDIRECT_URI`] with a one-time code in the address, which is traded here for
//! tokens.

use std::time::{Duration, SystemTime};

use base64::Engine;
use url::Url;

use crate::PsnError;

/// The client ID of Sony's Remote Play app for Windows, which chiaki-ng uses too. It names the app, not the
/// person.
pub const CLIENT_ID: &str = "ba495a24-818c-472b-b12d-ff231c1b5745";
/// Where the app's secret is read from. It is not kept in this repository (`docs/PSN.md`).
pub const SECRET_VAR: &str = "PSN_RP_CLIENT_SECRET";
pub const REDIRECT_URI: &str = "https://remoteplay.dl.playstation.net/remoteplay/redirect";
pub const TOKEN_URL: &str = "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/token";
/// chiaki-ng's scopes: the app itself, the country settings, push notifications over a websocket, and
/// remote-play sessions. The last two are for the holepunch (step 9b).
pub const SCOPE: &str = "psn:clientapp referenceDataService:countryConfig.read pushNotification:webSocket.desktop.connect sessionManager:remotePlaySession.system.update";
/// chiaki-ng's timeout for each PSN request.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// chiaki-ng `PSNAuth::LOGIN_URL`: Sony's sign-in page for the Remote Play app, with the spaces between the
/// scopes written as `%20`. chiaki-ng opens its address in its own web view, which encodes them; this one is
/// printed for the person to open, and an address copied from a terminal stops at its first space, which
/// signs in with `psn:clientapp` alone. Every later refresh asking for the four scopes is then refused as
/// `invalid_scope` (seen 2026-11-25).
pub fn login_url() -> String {
    let scope = SCOPE.replace(' ', "%20");
    format!(
        "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?service_entity=urn:service-entity:psn&response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={scope}&request_locale=en_US&ui=pr&service_logo=ps&layout_type=popup&smcid=remoteplay&prompt=always&PlatformPrivacyWs1=minimal&"
    )
}

/// The one-time code from the address Sony's sign-in sent the browser to. The address must be the redirect
/// page itself, so a code from anywhere else is refused.
pub fn code_from_redirect(address: &str) -> Result<String, PsnError> {
    let url = Url::parse(address.trim()).map_err(|_| PsnError::NotRedirect)?;
    let redirect = Url::parse(REDIRECT_URI).expect("a valid constant");
    let exact = url.scheme() == "https"
        && url.host_str() == redirect.host_str()
        && url.path() == redirect.path()
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    if !exact {
        return Err(PsnError::NotRedirect);
    }
    url.query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .filter(|c| !c.is_empty())
        .ok_or(PsnError::NoCode)
}

/// A form body with each value percent-encoded, and spaces sent as `%20` rather than the form encoding's `+`:
/// chiaki-ng sends the scopes with plain spaces, and `%20` is the closest encoded match. Whether Sony also
/// accepts `+` has not been tested. (Every `+` in a value is `%2B` by then, so each `+` left is a space.)
fn form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish().replace('+', "%20")
}

/// The body that trades a sign-in code for tokens (chiaki-ng `PSNToken::InitPsnToken`). Each value is
/// form-encoded, so a pasted code cannot add fields of its own.
pub fn code_request(code: &str) -> String {
    form(&[("grant_type", "authorization_code"), ("code", code), ("scope", SCOPE), ("redirect_uri", REDIRECT_URI)])
}

/// The body that trades the refresh token for a new access token (chiaki-ng `PSNToken::RefreshPsnToken`).
pub fn refresh_request(refresh_token: &str) -> String {
    form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("scope", SCOPE),
        ("redirect_uri", REDIRECT_URI),
    ])
}

/// HTTP Basic with the app's ID and secret, as Sony's token endpoint wants.
pub fn basic_auth(secret: &str) -> String {
    let pair = format!("{CLIENT_ID}:{secret}");
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair))
}

/// What the token endpoint gives back. The tokens are credentials: `Debug` hides them.
#[derive(Clone, PartialEq, Eq)]
pub struct Tokens {
    pub access: String,
    pub refresh: String,
    pub access_expires: SystemTime,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tokens").field("access_expires", &self.access_expires).finish_non_exhaustive()
    }
}

/// chiaki-ng `PSNToken::handleAccessTokenResponse`: the access token, the refresh token, and when the access
/// token expires (`expires_in` seconds from `now`).
pub fn parse_tokens(json: &serde_json::Value, now: SystemTime) -> Result<Tokens, PsnError> {
    let text = |k: &'static str| {
        json[k].as_str().filter(|s| !s.is_empty()).map(str::to_string).ok_or(PsnError::MissingField(k))
    };
    let seconds = json["expires_in"].as_u64().ok_or(PsnError::MissingField("expires_in"))?;
    Ok(Tokens {
        access: text("access_token")?,
        refresh: text("refresh_token")?,
        access_expires: now + Duration::from_secs(seconds),
    })
}

fn post_token(what: &'static str, secret: &str, body: String) -> Result<Tokens, PsnError> {
    let sent = crate::agent()
        .post(TOKEN_URL)
        .header("Authorization", basic_auth(secret))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(body);
    parse_tokens(&crate::reply(what, sent)?, SystemTime::now())
}

/// Trades the code from Sony's sign-in for tokens.
pub fn exchange_code(secret: &str, code: &str) -> Result<Tokens, PsnError> {
    post_token("sign-in", secret, code_request(code))
}

/// A new access token (and refresh token) from the refresh token.
pub fn refresh(secret: &str, refresh_token: &str) -> Result<Tokens, PsnError> {
    post_token("token refresh", secret, refresh_request(refresh_token))
}
