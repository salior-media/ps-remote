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
//!
//! **Differences from chiaki-ng:**
//! - **Notifications must be this session's, from this console.** chiaki-ng takes any session message as the
//!   console's. Here each one must name this session (`body.data.sessionId`) and come from the console's device
//!   (`body.data.customProperties.from.deviceUniqueId`, as Sony relays it); others are passed over.
//! - **The offer's fields are typed.** Candidates are IP addresses with a port, `skey` is 16 bytes and
//!   `localHashedId` 20 (the sizes chiaki-ng's structs have, and the console sends), and at most
//!   [`CANDIDATES_MAX`] candidates are read. chiaki-ng copies the strings as they come.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::PsnError;
use crate::push::{Kind, Notification, Push};
use crate::rps::{Created, SESSION_CREATE_URL, valid_session_id};

/// chiaki-ng `session_command_url`: where the command that starts remote play on the console is sent.
pub const SESSION_COMMAND_URL: &str = "https://web.np.playstation.com/api/cloudAssistedNavigation/v2/users/me/commands";
/// chiaki-ng `SESSION_START_TIMEOUT_SEC`.
pub const START_TIMEOUT: Duration = Duration::from_secs(30);
/// chiaki-ng `CUSTOMDATA1_EXTRA_BYTES_MAX`: bytes past the 16 that are tolerated, and dropped.
const CUSTOMDATA1_EXTRA_MAX: usize = 4;
/// More candidates than any side offers (the console sends two; chiaki-ng's offer has four).
pub const CANDIDATES_MAX: usize = 16;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Sixteen random bytes from the system's generator, as the device ID wants.
pub fn random_bytes() -> Result<[u8; 16], PsnError> {
    random()
}

pub(crate) fn random<const N: usize>() -> Result<[u8; N], PsnError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| PsnError::Network(format!("random numbers: {e}")))?;
    Ok(b)
}

/// The session and the console a notification must belong to.
#[derive(Debug, Clone, Copy)]
pub struct Peer<'a> {
    pub session_id: &'a str,
    pub console_duid: &'a [u8; 32],
}

impl Peer<'_> {
    /// Whether `n` names this session and comes from this console, as Sony relays the sender.
    pub fn sent(&self, n: &Notification) -> bool {
        let session = n.json.pointer("/body/data/sessionId").and_then(|v| v.as_str());
        let from = n.json.pointer("/body/data/customProperties/from/deviceUniqueId").and_then(|v| v.as_str());
        session == Some(self.session_id) && from.is_some_and(|d| d.eq_ignore_ascii_case(&hex(self.console_duid)))
    }
}

/// chiaki-ng `session_start_envelope_fmt` around `session_start_payload_fmt`: the `remotePlay` command for
/// the console with this device ID, carrying the session, the account, and the client's two random values.
/// The session ID is checked first: it goes into the JSON as it is.
pub fn start_body(
    account_id: u64,
    session_id: &str,
    console_duid: &[u8; 32],
    data1: &[u8; 16],
    data2: &[u8; 16],
) -> Result<String, PsnError> {
    if !valid_session_id(session_id) {
        return Err(PsnError::BadField("sessionId"));
    }
    // The inner JSON is a string inside the outer one, so its quotes are escaped, as chiaki-ng's are.
    let payload = format!(
        r#"{{\"accountId\":{account_id},\"roomId\":0,\"sessionId\":\"{session_id}\",\"clientType\":\"Windows\",\"data1\":\"{}\",\"data2\":\"{}\"}}"#,
        B64.encode(data1),
        B64.encode(data2)
    );
    Ok(format!(
        r#"{{"commandDetail":{{"commandType":"remotePlay","duid":"{}","messageDestination":"SQS","parameters":{{"initialParams":"{payload}"}},"platform":"PS5"}}}}"#,
        hex(console_duid)
    ))
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

/// chiaki-ng's check on the "member created" notification after the start: the console asked for is among the
/// members (chiaki-ng looks at the first only). The notification must also be this session's.
pub fn check_joined(n: &Notification, peer: &Peer<'_>) -> bool {
    let want = hex(peer.console_duid);
    let session = n.json.pointer("/body/data/sessionId").and_then(|v| v.as_str());
    let members = n.json.pointer("/body/data/members").and_then(|v| v.as_array());
    session == Some(peer.session_id)
        && members.is_some_and(|m| {
            m.iter()
                .any(|x| x["deviceUniqueId"].as_str().is_some_and(|d| d.len() == 64 && d.eq_ignore_ascii_case(&want)))
        })
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
/// console to join the session and for its `customData1`, each from the console and for this session.
pub fn start(
    access_token: &str,
    created: &Created,
    console_duid: &[u8; 32],
    push: &mut Push,
) -> Result<Started, PsnError> {
    let (data1, data2) = (random::<16>()?, random::<16>()?);
    let body = start_body(created.account_id, &created.session_id, console_duid, &data1, &data2)?;
    let sent = crate::agent()
        .post(SESSION_COMMAND_URL)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Content-Type", "application/json; charset=utf-8")
        .header("User-Agent", "RpNetHttpUtilImpl")
        .send(body);
    crate::reply_any("session start", sent)?;

    let peer = Peer { session_id: &created.session_id, console_duid };
    let deadline = Instant::now() + START_TIMEOUT;
    let (mut joined, mut custom_data1) = (false, None);
    while !joined || custom_data1.is_none() {
        let n = push.next(deadline)?.ok_or(PsnError::Timeout("the console to join the session"))?;
        match n.kind {
            Kind::MemberCreated if check_joined(&n, &peer) => joined = true,
            // Taken once, and only from the console.
            Kind::CustomData1Updated if custom_data1.is_none() && peer.sent(&n) => {
                let text = n.json.pointer("/body/data/customData1").and_then(|v| v.as_str());
                custom_data1 = Some(decode_custom_data1(text.ok_or(PsnError::MissingField("customData1"))?)?);
            }
            // Anything else (another member, another session, another kind) is not the console's start.
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

/// An address a side can perhaps be reached at (chiaki-ng `Candidate`). `addr` is checked to be one a probe may
/// be sent to; `addr_mapped` is often `0.0.0.0` (none) and is only read, never sent to. Its `Debug` shows only
/// the kind, so no address reaches a log.
#[derive(Clone, PartialEq, Eq)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub addr: IpAddr,
    pub addr_mapped: IpAddr,
    pub port: u16,
    pub port_mapped: u16,
}

impl std::fmt::Debug for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Candidate").field("kind", &self.kind).finish_non_exhaustive()
    }
}

/// chiaki-ng `ConnectionRequest`.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnRequest {
    pub sid: u32,
    pub peer_sid: u32,
    pub skey: [u8; 16],
    pub nat_type: u8,
    pub candidates: Vec<Candidate>,
    pub default_route_mac: Option<[u8; 6]>,
    pub local_hashed_id: [u8; 20],
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
/// chiaki-ng does, an empty object is put there before parsing (here only where the value is missing: the
/// next character, past any space, is `,` or `}`).
pub fn message_json(n: &Notification) -> Result<serde_json::Value, PsnError> {
    let payload = n.json.pointer("/body/data/sessionMessage/payload").and_then(|v| v.as_str());
    let payload = payload.ok_or(PsnError::MissingField("sessionMessage.payload"))?;
    let (_, body) = payload.split_once("body=").ok_or(PsnError::MissingField("body="))?;
    const KEY: &str = "\"localPeerAddr\":";
    let fixed;
    let text = match body.find(KEY) {
        Some(at) if body[at + KEY.len()..].trim_start().starts_with([',', '}']) => {
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

/// An address a probe may be sent to: an IP address (never a name to resolve), not unspecified, loopback,
/// multicast or the IPv4 broadcast address.
pub fn probe_address(ip: IpAddr) -> bool {
    let v4_broadcast = matches!(ip, IpAddr::V4(v) if v.is_broadcast());
    !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || v4_broadcast)
}

fn parse_candidate(c: &serde_json::Value) -> Result<Candidate, PsnError> {
    let kind = match text(c, "type")? {
        "LOCAL" => CandidateKind::Local,
        "STUN" => CandidateKind::Stun,
        "DERIVED" => CandidateKind::Derived,
        _ => CandidateKind::Static,
    };
    let ip = |f| text(c, f)?.parse::<IpAddr>().map_err(|_| PsnError::BadField(f));
    let (addr, port) = (ip("addr")?, int::<u16>(c, "port")?);
    if !probe_address(addr) || port == 0 {
        return Err(PsnError::BadField("addr"));
    }
    Ok(Candidate { kind, addr, port, addr_mapped: ip("mappedAddr")?, port_mapped: int(c, "mappedPort")? })
}

/// A base64 field of exactly `N` bytes. An empty one is all zeros: chiaki-ng's decoder leaves its zeroed buffer
/// as it is, and both its ACCEPT and the console's send `localHashedId` empty (seen live, 2026-11-25).
fn fixed<const N: usize>(c: &serde_json::Value, field: &'static str) -> Result<[u8; N], PsnError> {
    let text = text(c, field)?;
    if text.is_empty() {
        return Ok([0; N]);
    }
    let bytes = B64.decode(text).map_err(|_| PsnError::BadField(field))?;
    bytes.try_into().map_err(|_| PsnError::BadField(field))
}

fn parse_conn_request(c: &serde_json::Value) -> Result<ConnRequest, PsnError> {
    let candidates = c.get("candidate").and_then(|x| x.as_array()).ok_or(PsnError::MissingField("candidate"))?;
    if candidates.len() > CANDIDATES_MAX {
        return Err(PsnError::BadField("candidate"));
    }
    Ok(ConnRequest {
        sid: int(c, "sid")?,
        peer_sid: int(c, "peerSid")?,
        skey: fixed(c, "skey")?,
        nat_type: int(c, "natType")?,
        default_route_mac: parse_mac(text(c, "defaultRouteMacAddr")?),
        local_hashed_id: fixed(c, "localHashedId")?,
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

/// chiaki-ng `short_message_serialize`: a message with an empty `connRequest`. Only the RESULT that
/// acknowledges a message is sent this way.
pub fn result_message(req_id: u16) -> String {
    format!(r#"{{"action":"RESULT","reqId":{req_id},"error":0,"connRequest":{{}}}}"#)
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
    if !valid_session_id(&created.session_id) {
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

/// What one notification means to a wait for the console's messages.
#[derive(Debug, PartialEq, Eq)]
pub enum Seen {
    /// Not a session message from the console for this session: passed over.
    Other,
    Message(Message),
}

/// One notification, judged: [`Seen::Other`] unless it is a session message from the console for this
/// session. The console's own message that does not parse, or its TERMINATE, is an error.
pub fn read_message(n: &Notification, peer: &Peer<'_>) -> Result<Seen, PsnError> {
    if n.kind != Kind::SessionMessageCreated || !peer.sent(n) {
        return Ok(Seen::Other);
    }
    let m = parse_message(&message_json(n)?)?;
    if m.action == Action::Terminate {
        return Err(PsnError::Terminated);
    }
    Ok(Seen::Message(m))
}

/// chiaki-ng `wait_for_session_message`: the console's next session message with one of `actions`. Messages of
/// other actions, and anything not from the console for this session, are passed over.
pub fn wait_message(
    push: &mut Push,
    peer: &Peer<'_>,
    actions: &[Action],
    deadline: Instant,
) -> Result<Message, PsnError> {
    loop {
        let n = push.next(deadline)?.ok_or(PsnError::Timeout("a session message from the console"))?;
        if let Seen::Message(m) = read_message(&n, peer)?
            && actions.contains(&m.action)
        {
            return Ok(m);
        }
    }
}
