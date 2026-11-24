// SPDX-License-Identifier: AGPL-3.0-only
// Written from chiaki-ng `gui/include/psnaccountid.h`, `gui/src/psntoken.cpp` and
// `chiaki_holepunch_list_devices` in `lib/src/remote/holepunch.c` (LicenseRef-AGPL-3.0-only-OpenSSL).
// Nothing here talks to PSN.

use std::time::{Duration, SystemTime};

use psr_psn::PsnError;
use psr_psn::auth::{self, CLIENT_ID, REDIRECT_URI, SCOPE};
use psr_psn::devices::{self, Device};
use psr_psn::secret;
use serde_json::json;

/// chiaki-ng's `LOGIN_URL`, copied as it is, with its `%1` for the client ID.
const CHIAKI_LOGIN_URL: &str = "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?service_entity=urn:service-entity:psn&response_type=code&client_id=%1&redirect_uri=https://remoteplay.dl.playstation.net/remoteplay/redirect&scope=psn:clientapp referenceDataService:countryConfig.read pushNotification:webSocket.desktop.connect sessionManager:remotePlaySession.system.update&request_locale=en_US&ui=pr&service_logo=ps&layout_type=popup&smcid=remoteplay&prompt=always&PlatformPrivacyWs1=minimal&";

#[test]
fn the_sign_in_page_is_chiaki_ngs_with_no_spaces() {
    // chiaki-ng's web view encodes the spaces between the scopes; a printed address must do it itself, or
    // copying it from a terminal cuts it at the first space and signs in with one scope only.
    let url = auth::login_url();
    assert!(!url.contains(' '), "{url}");
    assert_eq!(url, CHIAKI_LOGIN_URL.replace("%1", CLIENT_ID).replace(' ', "%20"));
    let parsed = url::Url::parse(&url).unwrap();
    let scope = parsed.query_pairs().find(|(k, _)| k == "scope").unwrap().1.into_owned();
    assert_eq!(scope, SCOPE, "Sony reads all four scopes");
}

#[test]
fn the_code_comes_only_from_the_redirect_page() {
    assert_eq!(auth::code_from_redirect(&format!("{REDIRECT_URI}?code=v3.AbC-_9")).unwrap(), "v3.AbC-_9");
    assert_eq!(
        auth::code_from_redirect(&format!("  {REDIRECT_URI}?cid=x&code=abc  ")).unwrap(),
        "abc",
        "pasted with spaces"
    );
    for bad in [
        "http://remoteplay.dl.playstation.net/remoteplay/redirect?code=abc",
        "https://evil.example/remoteplay/redirect?code=abc",
        "https://remoteplay.dl.playstation.net.evil.example/remoteplay/redirect?code=abc",
        "https://remoteplay.dl.playstation.net/elsewhere?code=abc",
        "not a url",
    ] {
        assert!(matches!(auth::code_from_redirect(bad), Err(PsnError::NotRedirect)), "{bad}");
    }
    for no_code in
        [REDIRECT_URI.to_string(), format!("{REDIRECT_URI}?code="), format!("{REDIRECT_URI}?error=access_denied")]
    {
        assert!(matches!(auth::code_from_redirect(&no_code), Err(PsnError::NoCode)), "{no_code}");
    }
}

fn fields(body: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(body.as_bytes()).into_owned().collect()
}

#[test]
fn token_requests_carry_exactly_chiaki_ngs_fields() {
    let pairs = |p: &[(&str, &str)]| p.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();
    assert_eq!(
        fields(&auth::code_request("abc")),
        pairs(&[
            ("grant_type", "authorization_code"),
            ("code", "abc"),
            ("scope", SCOPE),
            ("redirect_uri", REDIRECT_URI)
        ])
    );
    assert_eq!(
        fields(&auth::refresh_request("r1")),
        pairs(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "r1"),
            ("scope", SCOPE),
            ("redirect_uri", REDIRECT_URI)
        ])
    );
}

#[test]
fn a_pasted_code_cannot_add_fields() {
    // %26 is '&': once decoded from the address, the code must stay one value in the request body.
    let code = auth::code_from_redirect(&format!("{REDIRECT_URI}?code=abc%26grant_type%3Dpassword")).unwrap();
    assert_eq!(code, "abc&grant_type=password");
    let f = fields(&auth::code_request(&code));
    assert_eq!(f.len(), 4);
    assert_eq!(f.iter().filter(|(k, _)| k == "grant_type").count(), 1);
    assert_eq!(f[1], ("code".to_string(), code));
}

#[test]
fn basic_auth_is_the_app_id_and_secret() {
    use base64::Engine;
    let h = auth::basic_auth("s3cret");
    let decoded = base64::engine::general_purpose::STANDARD.decode(h.strip_prefix("Basic ").unwrap()).unwrap();
    assert_eq!(decoded, format!("{CLIENT_ID}:s3cret").as_bytes());
}

#[test]
fn tokens_are_read_and_never_printed() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let t = auth::parse_tokens(
        &json!({"access_token":"AAA","refresh_token":"RRR","expires_in":3599,"token_type":"bearer"}),
        now,
    )
    .unwrap();
    assert_eq!((t.access.as_str(), t.refresh.as_str()), ("AAA", "RRR"));
    assert_eq!(t.access_expires, now + Duration::from_secs(3599));
    let shown = format!("{t:?}");
    assert!(!shown.contains("AAA") && !shown.contains("RRR"), "{shown}");
    for (missing, want) in
        [("access_token", "access_token"), ("refresh_token", "refresh_token"), ("expires_in", "expires_in")]
    {
        let mut j = json!({"access_token":"A","refresh_token":"R","expires_in":1});
        j.as_object_mut().unwrap().remove(missing);
        assert!(matches!(auth::parse_tokens(&j, now), Err(PsnError::MissingField(f)) if f == want), "{missing}");
    }
    assert!(auth::parse_tokens(&json!({"access_token":"","refresh_token":"R","expires_in":1}), now).is_err(), "empty");
}

fn client(duid: &str, name: &str, features: serde_json::Value) -> serde_json::Value {
    json!({"duid": duid, "device": {"name": name, "enabledFeatures": features, "platform": "PS5"}})
}

#[test]
fn devices_are_read_with_their_remote_play_flag() {
    let duid = "000000070040008011223344556677889900aabbccddeeff0011223344556677";
    let reply = json!({"clients": [
        client(duid, "PS5-455", json!(["remotePlay", "wakeUp"])),
        client("ab", "Other", json!(["wakeUp"])),
    ]});
    let list = devices::parse_devices(&reply).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].duid.len(), 32);
    assert_eq!(list[0].duid[..4], [0, 0, 0, 7]);
    assert_eq!((list[0].name.as_str(), list[0].remote_play), ("PS5-455", true));
    assert_eq!(list[1], Device { duid: vec![0xab], name: "Other".into(), remote_play: false });
    assert_eq!(devices::parse_devices(&json!({"clients": []})).unwrap(), []);
}

#[test]
fn a_malformed_device_fails_the_whole_reply_as_in_chiaki_ng() {
    let ok = client("ab", "x", json!([]));
    let mut cases: Vec<(serde_json::Value, &str)> = vec![(json!({}), "clients"), (json!({"clients": {}}), "clients")];
    for (path, field) in [("duid", "duid"), ("device", "device")] {
        let mut c = ok.clone();
        c.as_object_mut().unwrap().remove(path);
        cases.push((json!({"clients": [c]}), field));
    }
    for field in ["name", "enabledFeatures"] {
        let mut c = ok.clone();
        c["device"].as_object_mut().unwrap().remove(field);
        cases.push((json!({"clients": [c]}), field));
    }
    for (reply, field) in cases {
        assert!(matches!(devices::parse_devices(&reply), Err(PsnError::MissingField(f)) if f == field), "{field}");
    }
    for bad in ["abc", "zz", &"00".repeat(33)] {
        let reply = json!({"clients": [client(bad, "x", json!([]))]});
        assert!(matches!(devices::parse_devices(&reply), Err(PsnError::BadField("duid"))), "{bad}");
    }
}

#[test]
fn the_refresh_token_is_sealed_at_rest() {
    let sealed = secret::seal(b"refresh-me").unwrap();
    assert_eq!(secret::open(&sealed).unwrap(), b"refresh-me");
    if cfg!(windows) {
        assert!(!sealed.windows(10).any(|w| w == b"refresh-me"), "DPAPI: the token is not in the file as text");
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(secret::open(&tampered), Err(PsnError::Seal)), "altered bytes are refused");
    }
}

#[test]
fn save_load_and_forget() {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).unwrap();
    let dir =
        std::env::temp_dir().join(format!("psr-psn-test-{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()));
    assert_eq!(secret::load_refresh_token(&dir).unwrap(), None, "nobody signed in");
    secret::save_refresh_token(&dir, "tok-1").unwrap();
    secret::save_refresh_token(&dir, "tok-2").unwrap();
    assert_eq!(secret::load_refresh_token(&dir).unwrap().as_deref(), Some("tok-2"));
    let on_disk = std::fs::read(dir.join(secret::REFRESH_TOKEN_FILE)).unwrap();
    assert_eq!(on_disk.windows(5).any(|w| w == b"tok-2"), !cfg!(windows), "encrypted on Windows only");
    secret::forget(&dir).unwrap();
    secret::forget(&dir).unwrap();
    assert_eq!(secret::load_refresh_token(&dir).unwrap(), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn spaces_are_sent_as_percent_20_and_plus_signs_survive() {
    // Sony's token service reads '+' literally: the scopes must be joined by %20.
    let body = auth::refresh_request("a+b c");
    assert!(!body.contains('+'), "{body}");
    assert!(body.contains("scope=psn%3Aclientapp%20referenceDataService"), "{body}");
    let f = fields(&body);
    assert_eq!(f[1], ("refresh_token".to_string(), "a+b c".to_string()), "a real '+' in a value stays one");
    assert_eq!(f[2].1, SCOPE);
}
