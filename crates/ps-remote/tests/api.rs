// SPDX-License-Identifier: AGPL-3.0-only
// The local API's guards, against the real server on a random loopback port, with raw HTTP so each header
// is exactly what the test says.

use ps_remote::api;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Server {
    port: u16,
    token: String,
    dir: TempDir,
}

/// A configuration folder of its own, removed afterwards.
struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn server() -> Server {
    let dir = std::env::temp_dir().join(format!("ps-remote-api-test-{}", api::new_token().unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let token = api::new_token().unwrap();
    let service = api::Service::new(token.clone(), port, dir.clone());
    tokio::spawn(async move { axum::serve(listener, api::router(service)).await.unwrap() });
    Server { port, token, dir: TempDir(dir) }
}

/// A server with playing over PSN on (a made-up app secret), its PSN sign-in kept in its own folder.
async fn server_psn() -> Server {
    let dir = std::env::temp_dir().join(format!("ps-remote-api-test-{}", api::new_token().unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let token = api::new_token().unwrap();
    let psn = api::Psn { app_secret: "not-the-real-secret".into(), config_dir: dir.clone() };
    let service = api::Service::with_psn(token.clone(), port, dir.clone(), Some(psn));
    tokio::spawn(async move { axum::serve(listener, api::router(service)).await.unwrap() });
    Server { port, token, dir: TempDir(dir) }
}

/// Sends one request and returns the status code and the body.
async fn request(port: u16, method: &str, path: &str, host: &str, token: Option<&str>, body: &str) -> (u16, String) {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let auth = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    // A server that refuses early may close before reading a large body; what it sent still counts.
    let _ = s.read_to_end(&mut out).await;
    let out = String::from_utf8_lossy(&out).to_string();
    let code = out.get(9..12).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = out.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (code, body)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_page_is_served_without_the_token_and_only_for_the_right_host() {
    let s = server().await;
    let host = format!("127.0.0.1:{}", s.port);
    let (code, body) = request(s.port, "GET", "/", &host, None, "").await;
    assert_eq!(code, 200);
    // Any local process can fetch the page, so the token is not in it: the page reads it from the URL's
    // fragment, which the service prints and browsers never send.
    assert!(!body.contains(&s.token));
    assert!(body.contains("location.hash"));
    let (code, _) = request(s.port, "GET", "/", &format!("localhost:{}", s.port), None, "").await;
    assert_eq!(code, 200, "localhost is the same service");
    for wrong in
        ["evil.example:80".to_string(), format!("evil.example:{}", s.port), "127.0.0.1:1".into(), String::new()]
    {
        let (code, body) = request(s.port, "GET", "/", &wrong, None, "").await;
        assert_eq!(code, 421, "Host {wrong:?}");
        assert!(!body.contains(&s.token), "a rebinding page never sees the token");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_api_route_needs_the_token() {
    let s = server().await;
    let host = format!("127.0.0.1:{}", s.port);
    let wrong = "0".repeat(64);
    let short = &s.token[..63];
    let routes = [
        ("GET", "/api/status"),
        ("GET", "/api/consoles"),
        ("POST", "/api/play"),
        ("POST", "/api/offer"),
        ("POST", "/api/stop"),
        ("POST", "/api/link"),
        ("POST", "/api/wake"),
        ("GET", "/api/psn-status"),
        ("GET", "/api/psn-signin-url"),
        ("POST", "/api/psn-signin"),
        ("POST", "/api/psn-signout"),
    ];
    for (method, path) in routes {
        for token in [None, Some(wrong.as_str()), Some(short), Some("")] {
            let (code, _) = request(s.port, method, path, &host, token, "{}").await;
            assert_eq!(code, 401, "{method} {path} with {token:?}");
        }
    }
    let (code, _) = request(s.port, "GET", "/api/status", "evil.example", Some(&s.token), "").await;
    assert_eq!(code, 421, "the Host check comes first, token or not");
}

#[tokio::test(flavor = "multi_thread")]
async fn with_the_token_the_routes_answer() {
    let s = server().await;
    let host = format!("127.0.0.1:{}", s.port);
    let t = Some(s.token.as_str());
    let (code, body) = request(s.port, "GET", "/api/status", &host, t, "").await;
    assert_eq!((code, body.contains("\"running\":false")), (200, true), "{body}");
    let (code, body) = request(s.port, "GET", "/api/consoles", &host, t, "").await;
    assert_eq!((code, body.as_str()), (200, "[]"), "nothing linked in a fresh folder");
    let (code, _) = request(s.port, "POST", "/api/play", &host, t, r#"{"host":"127.0.0.1"}"#).await;
    assert_eq!(code, 400, "no linked console to play");
    let (code, _) = request(s.port, "POST", "/api/play", &host, t, r#"{"host":"127.0.0.1","admin":true}"#).await;
    assert_eq!(code, 422, "unknown fields are refused");
    let (code, _) = request(s.port, "POST", "/api/offer", &host, t, "not sdp").await;
    assert_eq!(code, 400);
    let (code, _) = request(s.port, "POST", "/api/stop", &host, t, "").await;
    assert_eq!(code, 204, "stopping nothing is fine");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_huge_body_is_refused() {
    let s = server().await;
    let host = format!("127.0.0.1:{}", s.port);
    let big = "v=0\r\n".repeat(20_000);
    let (code, _) = request(s.port, "POST", "/api/offer", &host, Some(&s.token), &big).await;
    assert_eq!(code, 413);
}

/// Saves a made-up linked console (no real keys) in the server's folder.
fn link_fake_console(s: &Server) {
    let host = psr_lan::regist::RegisteredHost {
        target: psr_crypto::Target::Ps5V1,
        ap_ssid: None,
        ap_bssid: None,
        ap_key: None,
        ap_name: None,
        server_mac: [0x02, 0, 0, 0, 0, 0x01],
        server_nickname: Some("fake".into()),
        rp_regist_key: [0x31; 16],
        rp_key_type: 2,
        rp_key: [0x5a; 16],
    };
    psr_lan::store::save(&s.dir.0, &host).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn play_only_starts_where_the_console_answers_as_itself() {
    let s = server().await;
    link_fake_console(&s);
    let host = format!("127.0.0.1:{}", s.port);
    let t = Some(s.token.as_str());
    // Nothing answers discovery at 127.0.0.1, so no session request (with its credentials) is sent there.
    let (code, body) = request(s.port, "POST", "/api/play", &host, t, r#"{"host":"127.0.0.1"}"#).await;
    assert_eq!(code, 400, "{body}");
    assert!(body.contains("did not answer as"), "{body}");
    let (code, _) = request(s.port, "POST", "/api/play", &host, t, r#"{"host":"::1"}"#).await;
    assert_eq!(code, 400, "IPv6 is not searched, so it is refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn only_one_session_start_at_a_time() {
    let s = server().await;
    link_fake_console(&s);
    let host = format!("127.0.0.1:{}", s.port);
    let t = Some(s.token.as_str());
    let body = r#"{"host":"127.0.0.1"}"#;
    let (a, b) = tokio::join!(request(s.port, "POST", "/api/play", &host, t, body), async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        request(s.port, "POST", "/api/play", &host, t, body).await
    });
    assert_eq!((a.0, b.0), (400, 409), "the second start is refused while the first runs: {a:?} {b:?}");
}

#[tokio::test]
async fn play_over_psn_needs_the_token_and_says_when_it_is_off() {
    let s = server().await;
    let host = format!("127.0.0.1:{}", s.port);
    let (code, _) = request(s.port, "POST", "/api/play-psn", &host, None, "").await;
    assert_eq!(code, 401);
    let (code, _) = request(s.port, "POST", "/api/play-psn", "evil.example", Some(&s.token), "").await;
    assert_ne!(code, 204);
    // This service was made without Sony's app secret: the route says so, and starts nothing.
    let (code, body) = request(s.port, "POST", "/api/play-psn", &host, Some(&s.token), "").await;
    assert_eq!(code, 503, "{body}");
    assert!(body.contains("PSN_RP_CLIENT_SECRET"), "{body}");
}

#[tokio::test]
async fn the_psn_console_list_needs_the_token_and_says_when_it_is_off() {
    let s = server().await;
    let host = format!("127.0.0.1:{}", s.port);
    let (code, _) = request(s.port, "GET", "/api/psn-consoles", &host, None, "").await;
    assert_eq!(code, 401);
    let (code, body) = request(s.port, "GET", "/api/psn-consoles", &host, Some(&s.token), "").await;
    assert_eq!(code, 503, "{body}");
}

const ACCOUNT: &str = "AQIDBAUGBwg="; // 8 bytes, base64

/// A POST with the token and the right Host.
async fn post(s: &Server, path: &str, body: &str) -> (u16, String) {
    request(s.port, "POST", path, &format!("127.0.0.1:{}", s.port), Some(&s.token), body).await
}

#[tokio::test(flavor = "multi_thread")]
async fn link_checks_its_request_before_it_reaches_a_console() {
    let s = server().await;
    let s = &s;
    let link = |body: String| async move { post(s, "/api/link", &body).await };
    for pin in ["1234567", "123456789", "1234abcd", "", "-1234567", "+1234567"] {
        let (code, body) = link(format!(r#"{{"host":"127.0.0.1","pin":"{pin}","account_id":"{ACCOUNT}"}}"#)).await;
        assert_eq!(code, 400, "PIN {pin:?}: {body}");
        assert!(body.contains("8 digits"), "{body}");
        assert!(pin.is_empty() || !body.contains(pin), "the PIN is not echoed: {body}");
    }
    let (code, _) = link(format!(r#"{{"host":"::1","pin":"12345678","account_id":"{ACCOUNT}"}}"#)).await;
    assert_eq!(code, 400, "IPv6 is not searched");
    let (code, body) = link(format!(r#"{{"host":"8.8.8.8","pin":"12345678","account_id":"{ACCOUNT}"}}"#)).await;
    assert_eq!(code, 400, "an internet address is not searched: {body}");
    assert!(body.contains("home network"), "{body}");
    // A PIN sent as a number is refused without quoting it back.
    let (code, body) = link(r#"{"host":"127.0.0.1","pin":87654321}"#.into()).await;
    assert_eq!(code, 422, "{body}");
    assert!(!body.contains("87654321"), "{body}");
    let (code, body) = link(r#"{"host":"127.0.0.1","pin":"12345678","account_id":"not base64!"}"#.into()).await;
    assert_eq!(code, 400, "{body}");
    let (code, body) = link(r#"{"host":"127.0.0.1","pin":"12345678"}"#.into()).await;
    assert_eq!(code, 400, "no account ID, and PSN is off: {body}");
    assert!(body.contains("account_id"), "{body}");
    let (code, _) = link(format!(r#"{{"host":"127.0.0.1","pin":"12345678","account_id":"{ACCOUNT}","x":1}}"#)).await;
    assert_eq!(code, 422, "unknown fields are refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn link_only_registers_where_a_console_answers() {
    let s = server().await;
    let host = format!("127.0.0.1:{}", s.port);
    let body = format!(r#"{{"host":"127.0.0.1","pin":"1234 5678","account_id":"{ACCOUNT}"}}"#);
    let (code, answer) = request(s.port, "POST", "/api/link", &host, Some(&s.token), &body).await;
    assert_eq!(code, 400, "{answer}");
    assert!(answer.contains("did not answer"), "{answer}");
    assert!(!answer.contains("12345678") && !answer.contains("1234 5678"), "{answer}");
    let (_, consoles) = request(s.port, "GET", "/api/consoles", &host, Some(&s.token), "").await;
    assert_eq!(consoles, "[]", "nothing was saved");
}

#[tokio::test(flavor = "multi_thread")]
async fn wake_only_goes_where_the_console_answers_as_itself() {
    let s = server().await;
    let host = format!("127.0.0.1:{}", s.port);
    let t = Some(s.token.as_str());
    let (code, _) = request(s.port, "POST", "/api/wake", &host, t, r#"{"host":"127.0.0.1"}"#).await;
    assert_eq!(code, 400, "no linked console");
    link_fake_console(&s);
    let (code, body) = request(s.port, "POST", "/api/wake", &host, t, r#"{"host":"127.0.0.1"}"#).await;
    assert_eq!(code, 400, "{body}");
    assert!(body.contains("did not answer as"), "{body}");
    let (code, _) = request(s.port, "POST", "/api/wake", &host, t, r#"{"host":"::1"}"#).await;
    assert_eq!(code, 400, "IPv6 is not searched");
    let (code, body) = request(s.port, "POST", "/api/wake", &host, t, r#"{"host":"8.8.8.8"}"#).await;
    assert_eq!(code, 400, "{body}");
    assert!(body.contains("home network"), "the credential is never sent to the internet: {body}");
    let (code, _) = request(s.port, "POST", "/api/wake", &host, t, r#"{"host":"127.0.0.1","pin":"1"}"#).await;
    assert_eq!(code, 422, "unknown fields are refused");
}

async fn get(s: &Server, path: &str) -> (u16, String) {
    request(s.port, "GET", path, &format!("127.0.0.1:{}", s.port), Some(&s.token), "").await
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_app_secret_psn_sign_in_says_it_is_off() {
    let s = server().await;
    assert_eq!(get(&s, "/api/psn-status").await, (200, r#"{"available":false,"signed_in":false}"#.into()));
    assert_eq!(get(&s, "/api/psn-signin-url").await.0, 503);
    let redirect = r#"{"redirect":"https://remoteplay.dl.playstation.net/remoteplay/redirect?code=abc"}"#;
    assert_eq!(post(&s, "/api/psn-signin", redirect).await.0, 503);
    assert_eq!(post(&s, "/api/psn-signout", "").await.0, 503, "it cannot claim to have forgotten anything");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sign_in_routes_answer_only_their_own_host() {
    let s = server_psn().await;
    for (method, path) in [
        ("GET", "/api/psn-status"),
        ("GET", "/api/psn-signin-url"),
        ("POST", "/api/psn-signin"),
        ("POST", "/api/psn-signout"),
    ] {
        let (code, _) = request(s.port, method, path, "evil.example", Some(&s.token), "{}").await;
        assert_eq!(code, 421, "{method} {path}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_saved_sign_in_that_does_not_open_can_still_be_forgotten() {
    let s = server_psn().await;
    std::fs::write(s.dir.0.join(psr_psn::secret::REFRESH_TOKEN_FILE), b"not a sealed token").unwrap();
    std::fs::write(s.dir.0.join(format!("{}.tmp", psr_psn::secret::REFRESH_TOKEN_FILE)), b"left over").unwrap();
    assert_eq!(get(&s, "/api/psn-status").await, (200, r#"{"available":true,"signed_in":true}"#.into()));
    assert_eq!(post(&s, "/api/psn-signout", "").await.0, 204);
    assert_eq!(get(&s, "/api/psn-status").await.1, r#"{"available":true,"signed_in":false}"#);
    assert!(!s.dir.0.join(format!("{}.tmp", psr_psn::secret::REFRESH_TOKEN_FILE)).exists(), "the leftover went too");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sign_in_page_is_sonys_with_a_new_device_id_each_time() {
    let s = server_psn().await;
    let (code, a) = get(&s, "/api/psn-signin-url").await;
    assert_eq!(code, 200, "{a}");
    let url =
        |body: &str| serde_json::from_str::<serde_json::Value>(body).unwrap()["url"].as_str().unwrap().to_string();
    let first = url(&a);
    assert!(first.starts_with("https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?"), "{first}");
    assert!(first.contains("&duid=0000000700410080"), "{first}");
    let second = url(&get(&s, "/api/psn-signin-url").await.1);
    assert_ne!(first, second, "each sign-in gets its own device ID");
}

#[tokio::test(flavor = "multi_thread")]
async fn only_sonys_redirect_page_is_taken_and_never_echoed() {
    let s = server_psn().await;
    for address in [
        "https://evil.example/remoteplay/redirect?code=SECRETCODE1",
        "http://remoteplay.dl.playstation.net/remoteplay/redirect?code=SECRETCODE1",
        "https://remoteplay.dl.playstation.net/elsewhere?code=SECRETCODE1",
        "https://remoteplay.dl.playstation.net:444/remoteplay/redirect?code=SECRETCODE1",
        "not an address SECRETCODE1",
    ] {
        let (code, body) = post(&s, "/api/psn-signin", &format!(r#"{{"redirect":"{address}"}}"#)).await;
        assert_eq!(code, 400, "{address}: {body}");
        assert!(!body.contains("SECRETCODE1") && !body.contains("evil"), "{body}");
    }
    let (code, body) =
        post(&s, "/api/psn-signin", r#"{"redirect":"https://remoteplay.dl.playstation.net/remoteplay/redirect?x=1"}"#)
            .await;
    assert_eq!(code, 400, "no code: {body}");
    // A body that is not the expected JSON is refused without quoting it.
    let (code, body) = post(&s, "/api/psn-signin", r#"{"redirect":12345,"code":"SECRETCODE1"}"#).await;
    assert_eq!(code, 422, "{body}");
    assert!(!body.contains("SECRETCODE1") && !body.contains("12345"), "{body}");
    assert_eq!(get(&s, "/api/psn-status").await.1, r#"{"available":true,"signed_in":false}"#, "nothing was saved");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_status_follows_the_saved_sign_in_and_sign_out_forgets_it() {
    let s = server_psn().await;
    assert_eq!(get(&s, "/api/psn-status").await, (200, r#"{"available":true,"signed_in":false}"#.into()));
    psr_psn::secret::save_refresh_token(&s.dir.0, "a-made-up-refresh-token").unwrap();
    let (code, body) = get(&s, "/api/psn-status").await;
    assert_eq!((code, body.as_str()), (200, r#"{"available":true,"signed_in":true}"#));
    assert!(!body.contains("made-up"), "the token is never answered");
    assert_eq!(post(&s, "/api/psn-signout", "").await.0, 204);
    assert_eq!(get(&s, "/api/psn-status").await.1, r#"{"available":true,"signed_in":false}"#);
    assert_eq!(post(&s, "/api/psn-signout", "").await.0, 204, "signing out twice is fine");
}
