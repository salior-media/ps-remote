// SPDX-License-Identifier: AGPL-3.0-only
//! Finds your PSN account ID, which linking needs. Ported from chiaki-ng `scripts/psn-account-id.py`
//! (thanks to grill2010).
//!
//!     cargo run -p psr-lan --example psn_account_id
//!
//! You sign in on Sony's own page in your own browser; this program never sees your password. Sony then
//! sends the browser to a "redirect" page whose address holds a one-time code. You paste that address
//! here, and the program trades the code for a token, asks Sony for your account's user ID, and prints
//! it in the base64 form the console expects. Nothing is saved.
//!
//! The sign-in uses the client ID and secret of Sony's own Remote Play app for Windows, the same ones
//! chiaki-ng's script uses. They identify the app, not you. The secret is not kept in this repository:
//! set `PSN_RP_CLIENT_SECRET` to the `CLIENT_SECRET` value in chiaki-ng's `scripts/psn-account-id.py`
//! before running.

use std::io::BufRead;

use base64::Engine;

const CLIENT_ID: &str = "ba495a24-818c-472b-b12d-ff231c1b5745";
const SECRET_VAR: &str = "PSN_RP_CLIENT_SECRET";
const REDIRECT_URI: &str = "https://remoteplay.dl.playstation.net/remoteplay/redirect";
const TOKEN_URL: &str = "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/token";

fn login_url() -> String {
    format!(
        "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?service_entity=urn:service-entity:psn&response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=psn:clientapp&request_locale=en_US&ui=pr&service_logo=ps&layout_type=popup&smcid=remoteplay&prompt=always&PlatformPrivacyWs1=minimal&"
    )
}

fn basic_auth(secret: &str) -> String {
    let pair = format!("{CLIENT_ID}:{secret}");
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = std::env::var(SECRET_VAR).map_err(|_| {
        format!("set {SECRET_VAR} to the CLIENT_SECRET value from chiaki-ng's scripts/psn-account-id.py first")
    })?;
    let secret = secret.trim();
    println!("1. Open this address in your browser and sign in to PSN:\n\n{}\n", login_url());
    println!("2. When the page shows \"redirect\", copy the whole address from the address bar and paste it here:");
    let mut pasted = String::new();
    std::io::stdin().lock().read_line(&mut pasted)?;
    let url = url::Url::parse(pasted.trim())?;
    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .filter(|c| !c.is_empty())
        .ok_or("that address has no `code` in it; copy the address of the redirect page")?;

    let body = format!("grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI}&");
    let mut token_resp = ureq::post(TOKEN_URL)
        .header("Authorization", basic_auth(secret))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(body)?;
    let token: serde_json::Value = token_resp.body_mut().read_json()?;
    let access = token["access_token"].as_str().ok_or("Sony's reply has no access_token")?;

    let info_url = format!("{TOKEN_URL}/{}", url::form_urlencoded::byte_serialize(access.as_bytes()).collect::<String>());
    let mut info_resp = ureq::get(&info_url).header("Authorization", basic_auth(secret)).call()?;
    let info: serde_json::Value = info_resp.body_mut().read_json()?;
    // Sony sends the ID as a string of digits.
    let user_id: u64 = info["user_id"].as_str().and_then(|s| s.parse().ok()).ok_or("Sony's reply has no user_id")?;
    let account_id = base64::engine::general_purpose::STANDARD.encode(user_id.to_le_bytes());
    println!("\nYour PSN account ID: {account_id}");
    Ok(())
}
