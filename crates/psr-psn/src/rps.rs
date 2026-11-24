// SPDX-License-Identifier: AGPL-3.0-only
//! A remote-play session at Sony's session manager: the meeting point through which the client and the
//! console exchange the messages that punch the hole. Ported from chiaki-ng `http_create_session`,
//! `chiaki_holepunch_session_create` and `deleteSession` in `lib/src/remote/holepunch.c`
//! (LicenseRef-AGPL-3.0-only-OpenSSL).

use std::time::{Duration, Instant};

use crate::PsnError;
use crate::push::{Kind, Push};

/// chiaki-ng `session_create_url`.
pub const SESSION_CREATE_URL: &str = "https://web.np.playstation.com/api/sessionManager/v1/remotePlaySessions";
/// chiaki-ng `SESSION_CREATION_TIMEOUT_SEC`.
pub const CREATION_TIMEOUT: Duration = Duration::from_secs(30);

/// chiaki-ng `session_create_json_fmt`: one member, "me", with this client's push context.
pub fn create_body(push_context_id: &str) -> String {
    serde_json::json!({
        "remotePlaySessions": [{
            "members": [{
                "accountId": "me",
                "deviceUniqueId": "me",
                "platform": "me",
                "pushContexts": [{"pushContextId": push_context_id}],
            }]
        }]
    })
    .to_string()
}

/// A created session: its ID, and the account ID Sony fills in for "me".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Created {
    pub session_id: String,
    pub account_id: u64,
}

/// chiaki-ng `http_create_session`'s reading of the reply: `remotePlaySessions[0].sessionId` (36 characters,
/// a UUID) and its first member's `accountId`, a string or a number.
pub fn parse_created(json: &serde_json::Value) -> Result<Created, PsnError> {
    let s = &json["remotePlaySessions"][0];
    let session_id = s["sessionId"].as_str().ok_or(PsnError::MissingField("sessionId"))?;
    if session_id.len() != 36 || !session_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return Err(PsnError::BadField("sessionId"));
    }
    let account = &s["members"][0]["accountId"];
    let account_id = match account {
        serde_json::Value::String(v) => v.parse().map_err(|_| PsnError::BadField("accountId"))?,
        serde_json::Value::Number(n) => n.as_u64().ok_or(PsnError::BadField("accountId"))?,
        _ => return Err(PsnError::MissingField("accountId")),
    };
    Ok(Created { session_id: session_id.to_string(), account_id })
}

/// A random UUID, version 4 (chiaki-ng `random_uuidv4`), for the push context.
pub fn random_uuid() -> Result<String, PsnError> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| PsnError::Network(format!("random numbers: {e}")))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]))
}

/// What creating a session found out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub created: Created,
    pub push_context_id: String,
    /// The account's online ID, from the "session created" notification.
    pub online_id: String,
}

/// chiaki-ng `chiaki_holepunch_session_create`, after the websocket is open: creates the session, then waits
/// for Sony's two notifications, "session created" and "member created" (this client joining).
pub fn create(access_token: &str, push: &mut Push) -> Result<Session, PsnError> {
    let push_context_id = random_uuid()?;
    let sent = crate::agent()
        .post(SESSION_CREATE_URL)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Content-Type", "application/json; charset=utf-8")
        .send(create_body(&push_context_id));
    let created = parse_created(&crate::reply("session create", sent)?)?;
    let deadline = Instant::now() + CREATION_TIMEOUT;
    let (mut online_id, mut joined) = (None, false);
    while online_id.is_none() || !joined {
        let n = push.next(deadline)?.ok_or(PsnError::Timeout("the session's created and joined notifications"))?;
        match n.kind {
            Kind::SessionCreated => {
                let id = n.json.pointer("/to/onlineId").and_then(|v| v.as_str());
                online_id = Some(id.ok_or(PsnError::MissingField("to.onlineId"))?.to_string());
            }
            Kind::MemberCreated => joined = true,
            // chiaki-ng refuses anything else at this point; a notification for another session or an older
            // one is skipped instead, as it is not this session's business.
            _ => {}
        }
    }
    Ok(Session { created, push_context_id, online_id: online_id.expect("the loop waits for it") })
}

/// chiaki-ng `deleteSession`: leaves the session, which ends it.
pub fn leave(access_token: &str, session_id: &str) -> Result<(), PsnError> {
    let url = format!("{SESSION_CREATE_URL}/{session_id}/members/me");
    let sent = crate::agent()
        .delete(&url)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("Content-Type", "application/json; charset=utf-8")
        .call();
    let mut r = sent.map_err(|e| PsnError::Network(e.to_string()))?;
    let code = r.status().as_u16();
    if !(200..300).contains(&code) {
        let json: Option<serde_json::Value> = r.body_mut().read_json().ok();
        return Err(PsnError::Status {
            what: "session leave",
            code,
            reason: json.as_ref().and_then(crate::refusal_reason),
        });
    }
    Ok(())
}
