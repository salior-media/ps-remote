// SPDX-License-Identifier: AGPL-3.0-only
// Written from chiaki-ng `websocket_thread_func`, `parse_notification_type`, `http_create_session` and
// `random_uuidv4` in `lib/src/remote/holepunch.c` (LicenseRef-AGPL-3.0-only-OpenSSL). The certificate check
// replays the real push server's certificate (captured 2026-11-25) at a fixed date; nothing here talks to PSN.

use std::time::Duration;

use psr_psn::PsnError;
use psr_psn::push::{self, Kind, Notification};
use psr_psn::rps;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::json;
use sha2::{Digest, Sha256};

const LEAF: &[u8] = include_bytes!("vectors/push-server-leaf.der");
const HOST: &str = "44-234-160-96-pushcl.np.communication.playstation.net";
/// 2026-11-25, inside both certificates' validity.
const TODAY: u64 = 1_795_564_800;
/// 2027-03-05, the day after the push server's certificate expires.
const AFTER_LEAF: u64 = 1_804_204_800;

fn check(extra: Option<&[u8]>, host: &str, at: u64) -> Result<(), rustls::Error> {
    let v = push::verifier(extra).unwrap();
    let name = ServerName::try_from(host.to_string()).unwrap();
    v.verify_server_cert(
        &CertificateDer::from(LEAF),
        &[],
        &name,
        &[],
        UnixTime::since_unix_epoch(Duration::from_secs(at)),
    )
    .map(|_| ())
}

#[test]
fn the_shipped_intermediate_is_the_one_pinned_in_its_readme() {
    let hex: String = Sha256::digest(push::PUSH_INTERMEDIATE).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "02ab57e4e67a0cb48dd2ff34830e8ac40f4476fb08ca6be3f5cd846f646840f0");
}

#[test]
fn the_push_servers_chain_verifies_only_with_the_shipped_intermediate() {
    // What the live connection hit before the fix: the server sends no intermediate.
    let plain = check(None, HOST, TODAY).unwrap_err();
    assert!(format!("{plain:?}").contains("UnknownIssuer"), "{plain:?}");
    check(Some(push::PUSH_INTERMEDIATE), HOST, TODAY).expect("the chain completes to a public root");
}

#[test]
fn the_intermediate_does_not_weaken_anything_else() {
    let extra = Some(push::PUSH_INTERMEDIATE);
    assert!(check(extra, "evil.example", TODAY).is_err(), "the host name is still checked");
    assert!(check(extra, HOST, AFTER_LEAF).is_err(), "dates are still checked");
    let mut altered = push::PUSH_INTERMEDIATE.to_vec();
    let n = altered.len();
    altered[n - 10] ^= 0xff; // inside the signature
    assert!(check(Some(&altered), HOST, TODAY).is_err(), "an altered intermediate fails");
    assert!(push::tls_config().is_ok());
}

#[test]
fn notification_kinds_are_chiaki_ngs() {
    for (t, k) in [
        ("psn:sessionManager:sys:remotePlaySession:created", Kind::SessionCreated),
        ("psn:sessionManager:sys:rps:members:created", Kind::MemberCreated),
        ("psn:sessionManager:sys:rps:members:deleted", Kind::MemberDeleted),
        ("psn:sessionManager:sys:rps:customData1:updated", Kind::CustomData1Updated),
        ("psn:sessionManager:sys:rps:sessionMessage:created", Kind::SessionMessageCreated),
        ("psn:sessionManager:sys:remotePlaySession:deleted", Kind::SessionDeleted),
        ("psn:something:else", Kind::Unknown),
    ] {
        assert_eq!(Kind::of(t), k, "{t}");
    }
    let n = Notification::parse(br#"{"dataType":"psn:sessionManager:sys:rps:members:created","body":{}}"#).unwrap();
    assert_eq!(n.kind, Kind::MemberCreated);
    for bad in [&b"not json"[..], b"[]", br#"{"body":{}}"#, br#"{"dataType":5}"#] {
        assert_eq!(Notification::parse(bad), None, "{}", String::from_utf8_lossy(bad));
    }
}

#[test]
fn the_upgrade_request_has_chiaki_ngs_headers_spelled_as_curl_sends_them() {
    let req = push::upgrade_request(HOST, "TOKEN", "KEY==").unwrap();
    assert!(req.starts_with("GET /np/pushNotification HTTP/1.1\r\n"));
    assert!(req.ends_with("\r\n\r\n"));
    for line in [
        &format!("Host: {HOST}")[..],
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Key: KEY==",
        "Authorization: Bearer TOKEN",
        "Sec-WebSocket-Protocol: np-pushpacket",
        "User-Agent: WebSocket++/0.8.2",
        "X-PSN-APP-TYPE: REMOTE_PLAY",
        "X-PSN-APP-VER: RemotePlay/1.0",
        "X-PSN-KEEP-ALIVE-STATUS-TYPE: 3",
        "X-PSN-OS-VER: Windows/10.0",
        "X-PSN-PROTOCOL-VERSION: 2.1",
        "X-PSN-RECONNECTION: false",
    ] {
        assert!(req.contains(&format!("\r\n{line}\r\n")), "{line}");
    }
}

#[test]
fn the_upgrade_response_must_accept_our_key() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    // RFC 6455's own example.
    let ok = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nsec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    push::check_upgrade_response(ok, key).unwrap();
    let wrong = ok.replace("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    assert!(matches!(push::check_upgrade_response(&wrong, key), Err(PsnError::BadField("Sec-WebSocket-Accept"))));
    let no_accept = "HTTP/1.1 101 Switching Protocols\r\n\r\n";
    assert!(push::check_upgrade_response(no_accept, key).is_err());
    let refused = "HTTP/1.1 403 Forbidden\r\nServer: nginx\r\nX-NP-RETRY-INTERVAL: 60\r\n\r\n";
    match push::check_upgrade_response(refused, key) {
        Err(PsnError::Status { code: 403, reason: Some(r), .. }) => assert_eq!(r, "X-NP-RETRY-INTERVAL: 60"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_push_server_name_is_one_of_sonys() {
    // The bearer token goes to this host: Sony's own push domain only, and a well-formed name.
    assert!(push::valid_fqdn(HOST));
    for bad in [
        "",
        "a b",
        "evil.example",
        "evil.example.com",
        "1.2.3.4",
        "np.communication.playstation.net",
        "x.np.communication.playstation.net.evil.example",
        "a..np.communication.playstation.net",
        "-a.np.communication.playstation.net",
        "a-.np.communication.playstation.net",
        "evil.example/x.np.communication.playstation.net",
        "h\r\nX-Injected: 1.np.communication.playstation.net",
        "évil.np.communication.playstation.net",
    ] {
        assert!(!push::valid_fqdn(bad), "{bad:?}");
    }
    assert!(!push::valid_fqdn(&format!("{}.np.communication.playstation.net", "a".repeat(64))), "a label over 63");
}

#[test]
fn nothing_unchecked_reaches_the_upgrade_request() {
    assert!(push::upgrade_request("evil.example", "T", "K==").is_err(), "a host outside Sony's");
    for token in ["t\r\nEvil: 1", "t ok", "", "t\u{7f}"] {
        assert!(push::upgrade_request(HOST, token, "K==").is_err(), "{token:?}");
    }
    assert!(push::upgrade_request(HOST, "T", "K\r\nX: y").is_err(), "the key");
}

#[test]
fn a_session_id_is_checked_before_it_goes_into_a_url() {
    assert!(rps::valid_session_id("1b2c3d4e-0000-4000-8000-123456789abc"));
    for bad in ["../../x", "1b2c3d4e-0000-4000-8000-123456789ab?", "", "1b2c3d4e-0000-4000-8000-123456789abc0"] {
        assert!(!rps::valid_session_id(bad), "{bad:?}");
        assert!(matches!(rps::leave("token", bad), Err(PsnError::BadField("sessionId"))), "{bad:?}");
    }
}

#[test]
fn reads_stop_at_the_deadline_however_slowly_the_bytes_come() {
    use std::io::Read;
    use std::time::Instant;
    /// One byte per read, for ever: a server dribbling a frame.
    struct Trickle;
    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            buf[0] = b'x';
            Ok(1)
        }
    }
    let mut s = push::Deadline::new(Trickle);
    let mut b = [0u8; 4];
    assert_eq!(s.read(&mut b).unwrap(), 1, "no deadline: reads go through");
    s.set_deadline(Some(Instant::now() + Duration::from_secs(60)));
    assert_eq!(s.read(&mut b).unwrap(), 1);
    s.set_deadline(Some(Instant::now() - Duration::from_millis(1)));
    let e = s.read(&mut b).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "past the deadline the stream stops, bytes or not");
}

#[test]
fn the_online_id_is_cleaned_and_capped() {
    assert_eq!(rps::clean_online_id("Player_1"), "Player_1");
    assert_eq!(rps::clean_online_id("a\u{1b}[2Jb"), "a?[2Jb");
    assert_eq!(rps::clean_online_id(&"x".repeat(500)).len(), rps::ONLINE_ID_MAX);
}

#[test]
fn the_session_request_is_chiaki_ngs_template() {
    // chiaki-ng's session_create_json_fmt, with the push context ID filled in.
    let want = r#"{"remotePlaySessions":[{"members":[{"accountId":"me","deviceUniqueId":"me","platform":"me","pushContexts":[{"pushContextId":"ctx"}]}]}]}"#;
    let got: serde_json::Value = serde_json::from_str(&rps::create_body("ctx")).unwrap();
    assert_eq!(got, serde_json::from_str::<serde_json::Value>(want).unwrap());
}

#[test]
fn a_created_session_is_read_as_chiaki_ng_reads_it() {
    let id = "1b2c3d4e-0000-4000-8000-123456789abc";
    let reply = |account: serde_json::Value| json!({"remotePlaySessions":[{"sessionId": id, "members":[{"accountId": account}]}]});
    assert_eq!(
        rps::parse_created(&reply(json!("1234567890"))).unwrap(),
        rps::Created { session_id: id.into(), account_id: 1234567890 }
    );
    assert_eq!(rps::parse_created(&reply(json!(42))).unwrap().account_id, 42, "a number works too");
    assert!(matches!(rps::parse_created(&reply(json!(true))), Err(PsnError::MissingField("accountId"))));
    assert!(matches!(rps::parse_created(&reply(json!("x"))), Err(PsnError::BadField("accountId"))));
    let short = json!({"remotePlaySessions":[{"sessionId": "abc", "members":[{"accountId": "1"}]}]});
    assert!(matches!(rps::parse_created(&short), Err(PsnError::BadField("sessionId"))));
    let odd = json!({"remotePlaySessions":[{"sessionId": "../../../../../../../../../../../xx/y", "members":[{"accountId": "1"}]}]});
    assert!(matches!(rps::parse_created(&odd), Err(PsnError::BadField("sessionId"))), "it goes into a URL path");
    assert!(matches!(rps::parse_created(&json!({})), Err(PsnError::MissingField("sessionId"))));
}

#[test]
fn push_context_ids_are_random_version_4_uuids() {
    let (a, b) = (rps::random_uuid().unwrap(), rps::random_uuid().unwrap());
    assert_ne!(a, b);
    let parts: Vec<&str> = a.split('-').collect();
    assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), [8, 4, 4, 4, 12]);
    assert!(parts[2].starts_with('4'), "version 4: {a}");
    assert!(matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'), "RFC 4122 variant: {a}");
}
