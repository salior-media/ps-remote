// SPDX-License-Identifier: AGPL-3.0-only
//! Bringing the console into the remote-play session, and the session messages the two sides exchange to
//! punch the hole. Ported from chiaki-ng `chiaki_holepunch_session_start`, `http_start_session`,
//! `decode_customdata1`, `session_message_get_payload`, `session_message_parse`, `short_message_serialize`,
//! `http_send_session_message` and `wait_for_session_message` in `lib/src/remote/holepunch.c`
//! (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! The messages are JSON inside a text payload inside a notification. chiaki-ng builds them as string
//! templates, because Sony's own app sends JSON that is not always valid; here they are built the same way,
//! from values that are checked or made here (numbers, hex, base64, UUIDs).

use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::PsnError;
use crate::push::{Kind, Notification, Push};
use crate::rps::{Created, SESSION_CREATE_URL};

/// chiaki-ng `session_command_url`: where the command that starts remote play on the console is sent.
pub const SESSION_COMMAND_URL: &str = "https://web.np.playstation.com/api/cloudAssistedNavigation/v2/users/me/commands";
/// chiaki-ng `SESSION_START_TIMEOUT_SEC`.
pub const START_TIMEOUT: Duration = Duration::from_secs(30);
/// chiaki-ng `CUSTOMDATA1_EXTRA_BYTES_MAX`: bytes past the 16 that are tolerated, and dropped.
const CUSTOMDATA1_EXTRA_MAX: usize = 4;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn random<const N: usize>() -> Result<[u8; N], PsnError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| PsnError::Network(format!("random numbers: {e}")))?;
    Ok(b)
}

/// chiaki-ng `session_start_envelope_fmt` around `session_start_payload_fmt`: the `remotePlay` command for
/// the console with this device ID, carrying the session, the account, and the client's two random values.
pub fn start_body(
    account_id: u64,
    session_id: &str,
    console_duid: &[u8; 32],
    data1: &[u8; 16],
    data2: &[u8; 16],
) -> String {
    // The inner JSON is a string inside the outer one, so its quotes are escaped, as chiaki-ng's are.
    let payload = format!(
        r#"{{\"accountId\":{account_id},\"roomId\":0,\"sessionId\":\"{session_id}\",\"clientType\":\"Windows\",\"data1\":\"{}\",\"data2\":\"{}\"}}"#,
        B64.encode(data1),
        B64.encode(data2)
    );
    format!(
        r#"{{"commandDetail":{{"commandType":"remotePlay","duid":"{}","messageDestination":"SQS","parameters":{{"initialParams":"{payload}"}},"platform":"PS5"}}}}"#,
        hex(console_duid)
    )
}

/// chiaki-ng `decode_customdata1`: base64 of base64 of 16 bytes (up to four more are tolerated and dropped).
pub fn decode_custom_data1(text: &str) -> Result<[u8; 16], PsnError> {
    let bad = || PsnError::BadField("customData1");
    if text.len() != 32 {
        return Err(bad());
    }
    let round1 = B64.decode(text).map_err(|_| bad())?;
    let round2 = B64.decode(&round1).map_err(|_| bad())?;
    // With 32 characters, two decodes give at most 18 bytes, so the upper bound is chiaki-ng's, kept for when
    // the length check changes rather than because it can trip today.
    if round2.len() < 16 || round2.len() > 16 + CUSTOMDATA1_EXTRA_MAX {
        return Err(bad());
    }
    Ok(round2[..16].try_into().expect("checked length"))
}

/// chiaki-ng's check on the "member created" notification after the start: the member who joined must be the
/// console asked for (`want`, its device ID as hex). Anyone else in the session is refused.
pub fn check_joined(n: &Notification, want: &str) -> Result<(), PsnError> {
    let duid = n.json.pointer("/body/data/members/0/deviceUniqueId").and_then(|v| v.as_str());
    let duid = duid.ok_or(PsnError::MissingField("members[0].deviceUniqueId"))?;
    if duid.len() != 64 || !duid.eq_ignore_ascii_case(want) {
        return Err(PsnError::BadField("deviceUniqueId: another device joined the session"));
    }
    Ok(())
}

/// What starting the session brings: the console's `customData1`, and the client's `data1` and `data2`. All
/// three go into the console's registration later (chiaki-ng `chiaki_get_regist_info`).
#[derive(Clone, PartialEq, Eq)]
pub struct Started {
    pub custom_data1: [u8; 16],
    pub data1: [u8; 16],
    pub data2: [u8; 16],
}

impl std::fmt::Debug for Started {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Started").finish_non_exhaustive()
    }
}

/// chiaki-ng `chiaki_holepunch_session_start` for a PS5: sends the `remotePlay` command, then waits for the
/// console to join the session (its device ID must be the one asked for) and for its `customData1`.
pub fn start(
    access_token: &str,
    created: &Created,
    console_duid: &[u8; 32],
    push: &mut Push,
) -> Result<Started, PsnError> {
    let (data1, data2) = (random::<16>()?, random::<16>()?);
    let sent = crate::agent()
        .post(SESSION_COMMAND_URL)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Content-Type", "application/json; charset=utf-8")
        .header("User-Agent", "RpNetHttpUtilImpl")
        .send(start_body(created.account_id, &created.session_id, console_duid, &data1, &data2));
    crate::reply_any("session start", sent)?;

    let deadline = Instant::now() + START_TIMEOUT;
    let want = hex(console_duid);
    let (mut joined, mut custom_data1) = (false, None);
    while !joined || custom_data1.is_none() {
        let n = push.next(deadline)?.ok_or(PsnError::Timeout("the console to join the session"))?;
        match n.kind {
            Kind::MemberCreated => {
                check_joined(&n, &want)?;
                joined = true;
            }
            Kind::CustomData1Updated => {
                let text = n.json.pointer("/body/data/customData1").and_then(|v| v.as_str());
                custom_data1 = Some(decode_custom_data1(text.ok_or(PsnError::MissingField("customData1"))?)?);
            }
            // chiaki-ng refuses anything else here; a notification of another kind is skipped instead.
            _ => {}
        }
    }
    Ok(Started { custom_data1: custom_data1.expect("the loop waits for it"), data1, data2 })
}

/// chiaki-ng `SessionMessageAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Offer,
    Accept,
    Terminate,
    Result,
    Unknown,
}

/// chiaki-ng `CandidateType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    Static,
    Local,
    Stun,
    Derived,
}

/// An address a side can perhaps be reached at (chiaki-ng `Candidate`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub addr: String,
    pub addr_mapped: String,
    pub port: u16,
    pub port_mapped: u16,
}

/// chiaki-ng `ConnectionRequest`.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnRequest {
    pub sid: u32,
    pub peer_sid: u32,
    pub skey: Vec<u8>,
    pub nat_type: u8,
    pub candidates: Vec<Candidate>,
    pub default_route_mac: Option<[u8; 6]>,
    pub local_hashed_id: Vec<u8>,
}

impl std::fmt::Debug for ConnRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnRequest")
            .field("sid", &self.sid)
            .field("nat_type", &self.nat_type)
            .field("candidates", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

/// chiaki-ng `SessionMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub action: Action,
    pub req_id: u16,
    pub error: u16,
    pub conn_request: Option<ConnRequest>,
}

/// chiaki-ng `session_message_get_payload`: the message JSON from a notification, after `body=` in its
/// payload. Sony's app leaves `"localPeerAddr":` without a value when it has none, which is not JSON; as
/// chiaki-ng does, an empty object is put there before parsing.
pub fn message_json(n: &Notification) -> Result<serde_json::Value, PsnError> {
    let payload = n.json.pointer("/body/data/sessionMessage/payload").and_then(|v| v.as_str());
    let payload = payload.ok_or(PsnError::MissingField("sessionMessage.payload"))?;
    let (_, body) = payload.split_once("body=").ok_or(PsnError::MissingField("body="))?;
    const KEY: &str = "\"localPeerAddr\":";
    let fixed;
    let text = match body.find(KEY) {
        Some(at) if !body[at + KEY.len()..].starts_with('{') => {
            let cut = at + KEY.len();
            fixed = format!("{}{{}}{}", &body[..cut], &body[cut..]);
            fixed.as_str()
        }
        _ => body,
    };
    serde_json::from_str(text).map_err(|_| PsnError::BadField("session message"))
}

fn int<T: TryFrom<i64>>(v: &serde_json::Value, field: &'static str) -> Result<T, PsnError> {
    let i = v.get(field).and_then(|x| x.as_i64()).ok_or(PsnError::MissingField(field))?;
    T::try_from(i).map_err(|_| PsnError::BadField(field))
}

fn text<'a>(v: &'a serde_json::Value, field: &'static str) -> Result<&'a str, PsnError> {
    v.get(field).and_then(|x| x.as_str()).ok_or(PsnError::MissingField(field))
}

/// chiaki-ng's `defaultRouteMacAddr`: six colon-separated hex bytes, or anything else for none.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    if s.len() != 17 {
        return None;
    }
    let parts: Vec<u8> = s.split(':').map(|p| u8::from_str_radix(p, 16).ok()).collect::<Option<_>>()?;
    parts.try_into().ok()
}

fn parse_candidate(c: &serde_json::Value) -> Result<Candidate, PsnError> {
    let kind = match text(c, "type")? {
        "LOCAL" => CandidateKind::Local,
        "STUN" => CandidateKind::Stun,
        "DERIVED" => CandidateKind::Derived,
        _ => CandidateKind::Static,
    };
    // chiaki-ng copies addresses into INET6_ADDRSTRLEN (46) bytes; longer is not an address.
    let addr = |f| text(c, f).and_then(|a| if a.len() < 46 { Ok(a.to_string()) } else { Err(PsnError::BadField(f)) });
    Ok(Candidate {
        kind,
        addr: addr("addr")?,
        addr_mapped: addr("mappedAddr")?,
        port: int(c, "port")?,
        port_mapped: int(c, "mappedPort")?,
    })
}

fn parse_conn_request(c: &serde_json::Value) -> Result<ConnRequest, PsnError> {
    let b64 = |f| B64.decode(text(c, f)?).map_err(|_| PsnError::BadField(f));
    let candidates = c.get("candidate").and_then(|x| x.as_array()).ok_or(PsnError::MissingField("candidate"))?;
    Ok(ConnRequest {
        sid: int(c, "sid")?,
        peer_sid: int(c, "peerSid")?,
        skey: b64("skey")?,
        nat_type: int(c, "natType")?,
        default_route_mac: parse_mac(text(c, "defaultRouteMacAddr")?),
        local_hashed_id: b64("localHashedId")?,
        candidates: candidates.iter().map(parse_candidate).collect::<Result<_, _>>()?,
    })
}

/// chiaki-ng `session_message_parse`. An empty `connRequest` object means none.
pub fn parse_message(json: &serde_json::Value) -> Result<Message, PsnError> {
    let action = match text(json, "action")? {
        "OFFER" => Action::Offer,
        "ACCEPT" => Action::Accept,
        "TERMINATE" => Action::Terminate,
        "RESULT" => Action::Result,
        _ => Action::Unknown,
    };
    let cr = json.get("connRequest").and_then(|x| x.as_object()).ok_or(PsnError::MissingField("connRequest"))?;
    let conn_request = if cr.is_empty() { None } else { Some(parse_conn_request(&json["connRequest"])?) };
    Ok(Message { action, req_id: int(json, "reqId")?, error: int(json, "error")?, conn_request })
}

/// chiaki-ng `short_message_serialize`: a message with an empty `connRequest`, such as the RESULT that
/// acknowledges one.
pub fn short_message(action: &str, req_id: u16, error: u16) -> String {
    format!(r#"{{"action":"{action}","reqId":{req_id},"error":{error},"connRequest":{{}}}}"#)
}

/// chiaki-ng `session_message_envelope_fmt`: a message to the console, on channel `remote_play:1`.
pub fn message_envelope(body: &str, account_id: u64, console_duid: &[u8; 32]) -> String {
    serde_json::json!({
        "channel": "remote_play:1",
        "payload": format!("ver=1.0, type=text, body={body}"),
        "to": [{"accountId": account_id.to_string(), "deviceUniqueId": hex(console_duid), "platform": "PS5"}],
    })
    .to_string()
}

/// chiaki-ng `http_send_session_message`.
pub fn send_message(
    access_token: &str,
    created: &Created,
    console_duid: &[u8; 32],
    body: &str,
) -> Result<(), PsnError> {
    if !crate::rps::valid_session_id(&created.session_id) {
        return Err(PsnError::BadField("sessionId"));
    }
    let url = format!("{SESSION_CREATE_URL}/{}/sessionMessage", created.session_id);
    let sent = crate::agent()
        .post(&url)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Content-Type", "application/json; charset=utf-8")
        .send(message_envelope(body, created.account_id, console_duid));
    crate::reply_any("session message", sent).map(|_| ())
}

/// chiaki-ng `wait_for_session_message`: the next session message with one of `actions`. A TERMINATE ends the
/// wait as an error, as in chiaki-ng; messages of other actions are passed over.
pub fn wait_message(push: &mut Push, actions: &[Action], deadline: Instant) -> Result<Message, PsnError> {
    loop {
        let n = push.next(deadline)?.ok_or(PsnError::Timeout("a session message from the console"))?;
        if n.kind != Kind::SessionMessageCreated {
            continue;
        }
        let m = parse_message(&message_json(&n)?)?;
        if m.action == Action::Terminate {
            return Err(PsnError::Terminated);
        }
        if actions.contains(&m.action) {
            return Ok(m);
        }
    }
}
