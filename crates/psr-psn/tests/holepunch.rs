// SPDX-License-Identifier: AGPL-3.0-only
// Written from chiaki-ng `http_start_session`, `decode_customdata1`, `session_message_get_payload`,
// `session_message_parse`, `short_message_serialize` and the JSON templates at the top of
// `lib/src/remote/holepunch.c` (LicenseRef-AGPL-3.0-only-OpenSSL). The notification shapes are the ones the
// household's PS5 sent through PSN on 2026-11-25 (paths and types recorded; the values here are made up).
// Nothing here talks to PSN.

use std::net::IpAddr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use psr_psn::PsnError;
use psr_psn::holepunch::{self, Action, CandidateKind, Peer, Seen};
use psr_psn::push::Notification;
use serde_json::json;

const SESSION: &str = "1b2c3d4e-0000-4000-8000-123456789abc";
const OTHER_SESSION: &str = "99999999-0000-4000-8000-123456789abc";
const CONSOLE: [u8; 32] = [0xab; 32];
const STRANGER: [u8; 32] = [0xcd; 32];
const PEER: Peer<'static> = Peer { session_id: SESSION, console_duid: &CONSOLE };

#[test]
fn the_start_command_is_chiaki_ngs_template() {
    let (d1, d2) = ([1u8; 16], [2u8; 16]);
    let body = holepunch::start_body(1234567890123, SESSION, &CONSOLE, &d1, &d2).unwrap();
    // chiaki-ng session_start_envelope_fmt and session_start_payload_fmt, filled in by hand.
    let want = concat!(
        r#"{"commandDetail":{"commandType":"remotePlay","duid":""#,
        "abababababababababababababababababababababababababababababababab",
        r#"","messageDestination":"SQS","parameters":{"initialParams":"{\"accountId\":1234567890123,\"roomId\":0,"#,
        r#"\"sessionId\":\"1b2c3d4e-0000-4000-8000-123456789abc\",\"clientType\":\"Windows\","#,
        r#"\"data1\":\"AQEBAQEBAQEBAQEBAQEBAQ==\",\"data2\":\"AgICAgICAgICAgICAgICAg==\"}"},"platform":"PS5"}}"#
    );
    assert_eq!(body, want);
    let outer: serde_json::Value = serde_json::from_str(&body).unwrap();
    let inner: serde_json::Value =
        serde_json::from_str(outer["commandDetail"]["parameters"]["initialParams"].as_str().unwrap()).unwrap();
    assert_eq!(inner["accountId"], 1234567890123u64);
}

#[test]
fn the_start_command_refuses_a_session_id_that_could_change_its_json() {
    for bad in [r#"\",\"roomId\":1,\"x\":\""#, "", "1b2c3d4e 0000"] {
        assert!(
            matches!(holepunch::start_body(1, bad, &CONSOLE, &[0; 16], &[0; 16]), Err(PsnError::BadField("sessionId"))),
            "{bad:?}"
        );
    }
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

fn hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// A notification as the console's arrive: for `session`, sent from `from`, with these fields beside.
fn notification(data_type: &str, session: &str, from: &[u8; 32], data: serde_json::Value) -> Notification {
    let mut body =
        json!({"sessionId": session, "customProperties": {"from": {"accountId": "1", "deviceUniqueId": hex(from)}}});
    for (k, v) in data.as_object().unwrap() {
        body[k] = v.clone();
    }
    Notification::parse(json!({"dataType": data_type, "body": {"data": body}}).to_string().as_bytes()).unwrap()
}

fn message_from(session: &str, from: &[u8; 32], body: &str) -> Notification {
    notification(
        "psn:sessionManager:sys:rps:sessionMessage:created",
        session,
        from,
        json!({"sessionMessage": {"payload": format!("ver=1.0, type=text, body={body}")}}),
    )
}

/// A session message from the console, in this session, with this text after `body=`.
fn message(body: &str) -> Notification {
    message_from(SESSION, &CONSOLE, body)
}

/// An offer as the console sends it, with Sony's broken `"localPeerAddr":` (no value).
const OFFER: &str = concat!(
    r#"{"action":"OFFER","reqId":1,"error":0,"connRequest":{"sid":305419896,"peerSid":0,"#,
    r#""skey":"AAECAwQFBgcICQoLDA0ODw==","natType":2,"candidate":["#,
    r#"{"type":"STATIC","addr":"203.0.113.7","mappedAddr":"0.0.0.0","port":9296,"mappedPort":0},"#,
    r#"{"type":"LOCAL","addr":"192.168.0.132","mappedAddr":"0.0.0.0","port":9296,"mappedPort":0}],"#,
    r#""defaultRouteMacAddr":"00:e4:21:2e:a0:07","localPeerAddr":,"localHashedId":"AQIDBAUGBwgJCgsMDQ4PEBESExQ="}}"#
);
const TERMINATE: &str = r#"{"action":"TERMINATE","reqId":2,"error":0,"connRequest":{}}"#;

fn read(n: &Notification) -> Result<Seen, PsnError> {
    holepunch::read_message(n, &PEER)
}

fn offer(body: &str) -> Result<holepunch::ConnRequest, PsnError> {
    match read(&message(body))? {
        Seen::Message(m) => Ok(m.conn_request.expect("an offer has a connection request")),
        Seen::Other => panic!("the console's message was passed over"),
    }
}

#[test]
fn the_consoles_offer_is_read() {
    let json = holepunch::message_json(&message(OFFER)).unwrap();
    assert_eq!(json["connRequest"]["localPeerAddr"], json!({}), "chiaki-ng's fix: an empty object");
    let Seen::Message(m) = read(&message(OFFER)).unwrap() else { panic!("passed over") };
    assert_eq!((m.action, m.req_id, m.error), (Action::Offer, 1, 0));
    let r = m.conn_request.unwrap();
    assert_eq!((r.sid, r.peer_sid, r.nat_type), (305419896, 0, 2));
    assert_eq!(r.skey.to_vec(), (0..16).collect::<Vec<u8>>());
    assert_eq!(r.local_hashed_id.to_vec(), (1..=20).collect::<Vec<u8>>());
    assert_eq!(r.default_route_mac, Some([0x00, 0xe4, 0x21, 0x2e, 0xa0, 0x07]));
    assert_eq!(r.candidates.len(), 2);
    let c = &r.candidates[0];
    assert_eq!((c.kind, c.addr, c.port), (CandidateKind::Static, "203.0.113.7".parse::<IpAddr>().unwrap(), 9296));
    assert!(c.addr_mapped.is_unspecified(), "0.0.0.0 as the mapped address means none");
    assert_eq!(r.candidates[1].kind, CandidateKind::Local);
}

#[test]
fn only_the_consoles_messages_for_this_session_are_read() {
    // The same offer from another device, or for another session, is passed over, not taken as the console's.
    assert_eq!(read(&message_from(SESSION, &STRANGER, OFFER)).unwrap(), Seen::Other);
    assert_eq!(read(&message_from(OTHER_SESSION, &CONSOLE, OFFER)).unwrap(), Seen::Other);
    // Nor does anyone else end the wait, with junk or a TERMINATE: only the console can.
    assert_eq!(read(&message_from(SESSION, &STRANGER, "x")).unwrap(), Seen::Other);
    assert_eq!(read(&message_from(SESSION, &STRANGER, TERMINATE)).unwrap(), Seen::Other);
    assert_eq!(read(&message_from(OTHER_SESSION, &CONSOLE, TERMINATE)).unwrap(), Seen::Other);
    assert!(matches!(read(&message(TERMINATE)), Err(PsnError::Terminated)));
    assert!(read(&message("x")).is_err(), "the console's own bad message is an error");
    let joined = notification("psn:sessionManager:sys:rps:members:created", SESSION, &CONSOLE, json!({}));
    assert_eq!(read(&joined).unwrap(), Seen::Other, "not a session message");
    // A notification with no sender at all is nobody's.
    let bare = Notification::parse(
        json!({"dataType": "psn:sessionManager:sys:rps:sessionMessage:created",
               "body": {"data": {"sessionId": SESSION, "sessionMessage": {"payload": format!("ver=1.0, type=text, body={OFFER}")}}}})
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(read(&bare).unwrap(), Seen::Other);
}

#[test]
fn only_the_console_asked_for_joins_this_session() {
    let joined = |session: &str, members: serde_json::Value| {
        notification("psn:sessionManager:sys:rps:members:created", session, &CONSOLE, json!({"members": members}))
    };
    assert!(holepunch::check_joined(&joined(SESSION, json!([{"deviceUniqueId": hex(&CONSOLE)}])), &PEER));
    let second_and_upper = json!([{"deviceUniqueId": "x"}, {"deviceUniqueId": hex(&CONSOLE).to_uppercase()}]);
    assert!(
        holepunch::check_joined(&joined(SESSION, second_and_upper), &PEER),
        "the console need not be listed first, and hex case does not matter"
    );
    assert!(!holepunch::check_joined(&joined(SESSION, json!([{"deviceUniqueId": hex(&STRANGER)}])), &PEER));
    assert!(!holepunch::check_joined(&joined(OTHER_SESSION, json!([{"deviceUniqueId": hex(&CONSOLE)}])), &PEER));
    assert!(!holepunch::check_joined(&joined(SESSION, json!([{"deviceUniqueId": 5}])), &PEER));
    assert!(!holepunch::check_joined(&joined(SESSION, json!([])), &PEER));
}

#[test]
fn a_well_formed_or_spaced_local_peer_addr_is_handled() {
    let object = OFFER.replace(r#""localPeerAddr":,"#, r#""localPeerAddr":{"accountId":"1","platform":"PROSPERO"},"#);
    let json = holepunch::message_json(&message(&object)).unwrap();
    assert_eq!(json["connRequest"]["localPeerAddr"]["platform"], "PROSPERO");
    let spaced = OFFER.replace(r#""localPeerAddr":,"#, r#""localPeerAddr": {"accountId":"1"},"#);
    assert_eq!(holepunch::message_json(&message(&spaced)).unwrap()["connRequest"]["localPeerAddr"]["accountId"], "1");
    let missing_spaced = OFFER.replace(r#""localPeerAddr":,"#, r#""localPeerAddr": ,"#);
    assert_eq!(holepunch::message_json(&message(&missing_spaced)).unwrap()["connRequest"]["localPeerAddr"], json!({}));
}

#[test]
fn candidates_must_be_addresses_a_probe_may_go_to() {
    let with = |addr: &str| OFFER.replace("203.0.113.7", addr);
    for bad in [
        "evil.example",
        "",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "255.255.255.255",
        "ff02::1",
        "1.2.3.4:5",
    ] {
        assert!(matches!(offer(&with(bad)), Err(PsnError::BadField("addr"))), "{bad:?}");
    }
    for ok in ["198.51.100.1", "10.0.0.5", "169.254.10.10", "2001:db8::1"] {
        assert!(offer(&with(ok)).is_ok(), "{ok}");
    }
    let first_port = |p: &str| {
        OFFER.replace(
            r#""port":9296,"mappedPort":0},{"type":"LOCAL""#,
            &format!(r#""port":{p},"mappedPort":0}},{{"type":"LOCAL""#),
        )
    };
    assert!(matches!(offer(&first_port("0")), Err(PsnError::BadField("addr"))), "port 0");
    assert!(matches!(offer(&first_port("70000")), Err(PsnError::BadField("port"))), "a port past 16 bits");
}

#[test]
fn keys_have_chiaki_ngs_sizes_and_candidates_are_capped() {
    for skey in [B64.encode([0u8; 15]), B64.encode([0u8; 17]), "!!".to_string()] {
        let bad = OFFER.replace("AAECAwQFBgcICQoLDA0ODw==", &skey);
        assert!(matches!(offer(&bad), Err(PsnError::BadField("skey"))), "{skey:?}");
    }
    for id in [B64.encode([0u8; 19]), B64.encode([0u8; 21])] {
        let bad = OFFER.replace("AQIDBAUGBwgJCgsMDQ4PEBESExQ=", &id);
        assert!(matches!(offer(&bad), Err(PsnError::BadField("localHashedId"))), "{id:?}");
    }
    let one = r#"{"type":"LOCAL","addr":"192.168.0.132","mappedAddr":"0.0.0.0","port":9296,"mappedPort":0}"#;
    let with_candidates = |n: usize| {
        let start = OFFER.find(r#""candidate":["#).unwrap() + r#""candidate":"#.len();
        let end = OFFER.find(r#"],"defaultRouteMacAddr""#).unwrap() + 1;
        format!("{}[{}]{}", &OFFER[..start], vec![one; n].join(","), &OFFER[end..])
    };
    assert_eq!(offer(&with_candidates(holepunch::CANDIDATES_MAX)).unwrap().candidates.len(), holepunch::CANDIDATES_MAX);
    assert!(matches!(offer(&with_candidates(holepunch::CANDIDATES_MAX + 1)), Err(PsnError::BadField("candidate"))));
}

#[test]
fn a_result_has_no_connection_request() {
    let Seen::Message(m) = read(&message(&holepunch::result_message(7))).unwrap() else { panic!("passed over") };
    assert_eq!((m.action, m.req_id, m.conn_request), (Action::Result, 7, None));
}

#[test]
fn the_result_is_chiaki_ngs_template() {
    // chiaki-ng session_message_fmt with an empty connRequest, as the console reads it once unescaped.
    assert_eq!(holepunch::result_message(3), r#"{"action":"RESULT","reqId":3,"error":0,"connRequest":{}}"#);
}

#[test]
fn the_envelope_carries_the_message_to_the_console() {
    let env: serde_json::Value = serde_json::from_str(&holepunch::message_envelope("{}", 42, &[0x0f; 32])).unwrap();
    assert_eq!(env["channel"], "remote_play:1");
    assert_eq!(env["payload"], "ver=1.0, type=text, body={}");
    assert_eq!(env["to"][0], json!({"accountId": "42", "deviceUniqueId": "0f".repeat(32), "platform": "PS5"}));
}

#[test]
fn the_consoles_malformed_messages_are_refused() {
    for bad in [
        r#"{"action":"OFFER","error":0,"connRequest":{}}"#,
        r#"{"action":"OFFER","reqId":70000,"error":0,"connRequest":{}}"#,
        r#"{"action":"OFFER","reqId":1,"error":0}"#,
        "not json",
    ] {
        assert!(read(&message(bad)).is_err(), "{bad}");
    }
    let unknown = holepunch::parse_message(&json!({"action":"WAVE","reqId":1,"error":0,"connRequest":{}})).unwrap();
    assert_eq!(unknown.action, Action::Unknown);
    let no_mac = OFFER.replace("00:e4:21:2e:a0:07", "");
    assert_eq!(offer(&no_mac).unwrap().default_route_mac, None, "an empty MAC is none, as in chiaki-ng");
    assert!(holepunch::message_json(&Notification::parse(br#"{"dataType":"x","body":{}}"#).unwrap()).is_err());
}

#[test]
fn an_empty_key_is_all_zeros_as_the_consoles_accept_sends_it() {
    let accept = OFFER
        .replace(r#""action":"OFFER""#, r#""action":"ACCEPT""#)
        .replace("AQIDBAUGBwgJCgsMDQ4PEBESExQ=", "")
        .replace("AAECAwQFBgcICQoLDA0ODw==", "");
    let r = offer(&accept).unwrap();
    assert_eq!((r.local_hashed_id, r.skey), ([0; 20], [0; 16]));
}
