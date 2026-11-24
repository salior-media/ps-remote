// SPDX-License-Identifier: AGPL-3.0-only
// Written from chiaki-ng `http_start_session`, `decode_customdata1`, `session_message_get_payload`,
// `session_message_parse`, `short_message_serialize` and the JSON templates at the top of
// `lib/src/remote/holepunch.c` (LicenseRef-AGPL-3.0-only-OpenSSL). Nothing here talks to PSN.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use psr_psn::PsnError;
use psr_psn::holepunch::{self, Action, CandidateKind};
use psr_psn::push::Notification;
use serde_json::json;

#[test]
fn the_start_command_is_chiaki_ngs_template() {
    let duid = [0xabu8; 32];
    let (d1, d2) = ([1u8; 16], [2u8; 16]);
    let body = holepunch::start_body(1234567890123, "1b2c3d4e-0000-4000-8000-123456789abc", &duid, &d1, &d2);
    // chiaki-ng session_start_envelope_fmt and session_start_payload_fmt, filled in by hand.
    let want = concat!(
        r#"{"commandDetail":{"commandType":"remotePlay","duid":""#,
        "abababababababababababababababababababababababababababababababab",
        r#"","messageDestination":"SQS","parameters":{"initialParams":"{\"accountId\":1234567890123,\"roomId\":0,"#,
        r#"\"sessionId\":\"1b2c3d4e-0000-4000-8000-123456789abc\",\"clientType\":\"Windows\","#,
        r#"\"data1\":\"AQEBAQEBAQEBAQEBAQEBAQ==\",\"data2\":\"AgICAgICAgICAgICAgICAg==\"}"},"platform":"PS5"}}"#
    );
    assert_eq!(body, want);
    // And it is JSON whose initialParams is JSON too.
    let outer: serde_json::Value = serde_json::from_str(&body).unwrap();
    let inner: serde_json::Value =
        serde_json::from_str(outer["commandDetail"]["parameters"]["initialParams"].as_str().unwrap()).unwrap();
    assert_eq!(inner["accountId"], 1234567890123u64);
}

fn custom_data1(bytes: &[u8]) -> String {
    B64.encode(B64.encode(bytes))
}

#[test]
fn custom_data1_is_base64_of_base64_of_16_bytes() {
    let v: Vec<u8> = (0..16).collect();
    let text = custom_data1(&v);
    assert_eq!(text.len(), 32);
    assert_eq!(holepunch::decode_custom_data1(&text).unwrap().to_vec(), v);
    // chiaki-ng tolerates up to four more bytes, and drops them (two still fit 32 characters).
    let mut longer = v.clone();
    longer.extend([9, 9]);
    assert_eq!(holepunch::decode_custom_data1(&custom_data1(&longer)).unwrap().to_vec(), v);
    for bad in [custom_data1(&v[..15]), custom_data1(&v)[..31].to_string(), "!".repeat(32), String::new()] {
        assert!(matches!(holepunch::decode_custom_data1(&bad), Err(PsnError::BadField("customData1"))), "{bad:?}");
    }
}

/// A session-message notification with this text after `body=`.
fn notification(body: &str) -> Notification {
    Notification::parse(
        json!({
            "dataType": "psn:sessionManager:sys:rps:sessionMessage:created",
            "body": {"data": {"sessionMessage": {"payload": format!("ver=1.0, type=text, body={body}")}}}
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap()
}

/// An offer as the console sends it, with Sony's broken `"localPeerAddr":` (no value).
const OFFER: &str = concat!(
    r#"{"action":"OFFER","reqId":1,"error":0,"connRequest":{"sid":305419896,"peerSid":0,"#,
    r#""skey":"AAECAwQFBgcICQoLDA0ODw==","natType":2,"candidate":["#,
    r#"{"type":"STATIC","addr":"203.0.113.7","mappedAddr":"0.0.0.0","port":9296,"mappedPort":0},"#,
    r#"{"type":"LOCAL","addr":"192.168.0.132","mappedAddr":"0.0.0.0","port":9296,"mappedPort":0}],"#,
    r#""defaultRouteMacAddr":"00:e4:21:2e:a0:07","localPeerAddr":,"localHashedId":"AQIDBAUGBwgJCgsMDQ4PEBESExQ="}}"#
);

#[test]
fn an_offer_with_sonys_broken_local_peer_addr_is_read() {
    let json = holepunch::message_json(&notification(OFFER)).unwrap();
    assert_eq!(json["connRequest"]["localPeerAddr"], json!({}), "chiaki-ng's fix: an empty object");
    let m = holepunch::parse_message(&json).unwrap();
    assert_eq!((m.action, m.req_id, m.error), (Action::Offer, 1, 0));
    let r = m.conn_request.unwrap();
    assert_eq!((r.sid, r.peer_sid, r.nat_type), (305419896, 0, 2));
    assert_eq!(r.skey, (0..16).collect::<Vec<u8>>());
    assert_eq!(r.local_hashed_id, (1..=20).collect::<Vec<u8>>());
    assert_eq!(r.default_route_mac, Some([0x00, 0xe4, 0x21, 0x2e, 0xa0, 0x07]));
    assert_eq!(r.candidates.len(), 2);
    assert_eq!(
        (r.candidates[0].kind, r.candidates[0].addr.as_str(), r.candidates[0].port),
        (CandidateKind::Static, "203.0.113.7", 9296)
    );
    assert_eq!(r.candidates[1].kind, CandidateKind::Local);
}

#[test]
fn a_well_formed_local_peer_addr_is_left_alone() {
    let body = OFFER.replace(r#""localPeerAddr":,"#, r#""localPeerAddr":{"accountId":"1","platform":"PROSPERO"},"#);
    let json = holepunch::message_json(&notification(&body)).unwrap();
    assert_eq!(json["connRequest"]["localPeerAddr"]["platform"], "PROSPERO");
}

#[test]
fn a_result_has_no_connection_request() {
    let m = holepunch::parse_message(
        &holepunch::message_json(&notification(&holepunch::short_message("RESULT", 7, 0))).unwrap(),
    )
    .unwrap();
    assert_eq!((m.action, m.req_id, m.conn_request), (Action::Result, 7, None));
}

#[test]
fn short_messages_are_chiaki_ngs_template() {
    // chiaki-ng session_message_fmt with an empty connRequest, as the console reads it once unescaped.
    assert_eq!(holepunch::short_message("RESULT", 3, 0), r#"{"action":"RESULT","reqId":3,"error":0,"connRequest":{}}"#);
}

#[test]
fn the_envelope_carries_the_message_to_the_console() {
    let duid = [0x0fu8; 32];
    let env: serde_json::Value = serde_json::from_str(&holepunch::message_envelope("{}", 42, &duid)).unwrap();
    assert_eq!(env["channel"], "remote_play:1");
    assert_eq!(env["payload"], "ver=1.0, type=text, body={}");
    assert_eq!(env["to"][0], json!({"accountId": "42", "deviceUniqueId": "0f".repeat(32), "platform": "PS5"}));
}

#[test]
fn malformed_messages_are_refused() {
    let parse = |body: &str| holepunch::parse_message(&holepunch::message_json(&notification(body))?);
    assert!(parse(r#"{"action":"OFFER","error":0,"connRequest":{}}"#).is_err(), "no reqId");
    assert!(parse(r#"{"action":"OFFER","reqId":70000,"error":0,"connRequest":{}}"#).is_err(), "reqId past 16 bits");
    assert!(parse(r#"{"action":"OFFER","reqId":1,"error":0}"#).is_err(), "no connRequest");
    assert!(parse("not json").is_err());
    let long = OFFER.replace("203.0.113.7", &"1".repeat(46));
    assert!(matches!(parse(&long), Err(PsnError::BadField("addr"))), "an address too long to be one");
    let port = OFFER
        .replace(r#""port":9296,"mappedPort":0},{"type":"LOCAL""#, r#""port":70000,"mappedPort":0},{"type":"LOCAL""#);
    assert!(matches!(parse(&port), Err(PsnError::BadField("port"))), "a port past 16 bits");
    let unknown = holepunch::parse_message(&json!({"action":"WAVE","reqId":1,"error":0,"connRequest":{}})).unwrap();
    assert_eq!(unknown.action, Action::Unknown);
    let no_mac = OFFER.replace("00:e4:21:2e:a0:07", "");
    assert_eq!(
        parse(&no_mac).unwrap().conn_request.unwrap().default_route_mac,
        None,
        "an empty MAC is none, as in chiaki-ng"
    );
    assert!(holepunch::message_json(&Notification::parse(br#"{"dataType":"x","body":{}}"#).unwrap()).is_err());
}

#[test]
fn only_the_console_asked_for_may_join() {
    let want = "ab".repeat(32);
    let joined = |duid: serde_json::Value| {
        Notification::parse(
            json!({"dataType":"psn:sessionManager:sys:rps:members:created","body":{"data":{"members":[{"deviceUniqueId": duid}]}}})
                .to_string()
                .as_bytes(),
        )
        .unwrap()
    };
    holepunch::check_joined(&joined(json!(want)), &want).unwrap();
    holepunch::check_joined(&joined(json!(want.to_uppercase())), &want).expect("hex case does not matter");
    for other in [json!("cd".repeat(32)), json!("ab".repeat(31)), json!(5)] {
        assert!(holepunch::check_joined(&joined(other.clone()), &want).is_err(), "{other}");
    }
}
