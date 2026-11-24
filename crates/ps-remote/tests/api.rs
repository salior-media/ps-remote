// SPDX-License-Identifier: AGPL-3.0-only
// The local API's guards, against the real server on a random loopback port, with raw HTTP so each header
// is exactly what the test says.

use ps_remote::api;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Server {
    port: u16,
    token: String,
    _dir: TempDir,
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
    Server { port, token, _dir: TempDir(dir) }
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
async fn the_page_carries_the_token_and_only_for_the_right_host() {
    let s = server().await;
    let host = format!("127.0.0.1:{}", s.port);
    let (code, body) = request(s.port, "GET", "/", &host, None, "").await;
    assert_eq!(code, 200);
    assert!(body.contains(&s.token));
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
