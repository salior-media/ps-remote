// SPDX-License-Identifier: AGPL-3.0-only
//! Starting a session over PSN: the session request, then ctrl, both through the punched control hole.
//! Ported from chiaki-ng `lib/src/session.c` (`session_thread_request_session`) and `lib/src/ctrl.c`
//! (`ctrl_connect`), their `rudp` paths (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! The requests are the home network's (`psr_lan::session`, `psr_lan::ctrl`), with `Host` naming the
//! console's end of the hole, each sent over RUDP after its own handshake. Once ctrl's answer is in, the
//! home network's [`Session`] takes over, on the hole ([`Rudp`] is its link), and also sends a heartbeat reply
//! every [`HEARTBEAT_EVERY`] once the console has asked for one, as chiaki-ng does over RUDP.
//!
//! chiaki-ng's other RUDP quirk is kept: for a PS5, the ctrl cipher's local counter skips one after the
//! request (`ctrl_connect`'s `crypt_counter_local++` under `session->rudp`).

use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use psr_crypto::Target;
use psr_crypto::rpcrypt::RpCrypt;
use psr_lan::ctrl::{self, CtrlCipher, CtrlEvent};
use psr_lan::regist::RegisteredHost;
use psr_lan::session::{self as lan, Codec, Session};
use psr_lan::stream::{self, Stream, VideoProfile};

use crate::PsnError;
use crate::punch::Hole;
use crate::rudp::Rudp;

/// chiaki-ng `CTRL_RUDP_HEARTBEAT_REP_INTERVAL_MS`.
pub const HEARTBEAT_EVERY: Duration = Duration::from_millis(4950);
/// chiaki-ng `SESSION_EXPECT_TIMEOUT_MS`: how long the console has to acknowledge the switch to the stream.
pub const SWITCH_TIMEOUT: Duration = Duration::from_secs(5);
/// chiaki-ng `takion_read_extra_sock_messages`: what is left of the holepunch on the data hole is read and
/// dropped until this long passes with none, or [`DRAIN_MAX`] in all.
pub const DRAIN_QUIET: Duration = Duration::from_millis(200);
pub const DRAIN_MAX: Duration = Duration::from_secs(1);
const RESET_PAUSE: Duration = Duration::from_millis(1);
/// chiaki-ng: "PS4 doesn't always react right away, sleep a bit".
const BEFORE_CTRL_DELAY: Duration = Duration::from_millis(10);

/// An answer split at the end of its HTTP header (which [`Rudp::http`] has checked is there).
fn split(answer: &[u8]) -> (&[u8], &[u8]) {
    let end = psr_lan::http::header_end(answer).unwrap_or(answer.len());
    answer.split_at(end)
}

/// One session request over the hole: the handshake, the request, then ACK and FINISH (chiaki-ng carries on
/// without FINISH).
fn request_nonce(rudp: &mut Rudp, target: Target, console: SocketAddrV4, key: &[u8; 16]) -> Result<[u8; 16], PsnError> {
    let request =
        lan::session_request_port(target, &console.ip().to_string(), console.port(), key).map_err(PsnError::Lan)?;
    let mut remote = rudp.handshake()?;
    let answer = rudp.http(&mut remote, request.as_bytes())?;
    let _ = rudp.finish(remote);
    lan::parse_session_response(split(&answer).0).map_err(PsnError::Lan)
}

/// chiaki-ng's session start over PSN, up to ctrl's session ID: `rudp` is the control hole's, `console` the
/// address it is connected to, and `host` the console as registered (9c-1 does that through the hole too).
pub fn start(
    mut rudp: Rudp,
    console: SocketAddrV4,
    host: &RegisteredHost,
    codec: Codec,
    did: &[u8; 32],
) -> Result<Session, PsnError> {
    let key = &host.rp_regist_key;
    // As at home: asked up to three times, following the console's RP-Version each time it names a new one.
    let mut target = host.target;
    let mut nonce = request_nonce(&mut rudp, target, console, key);
    for _ in 0..2 {
        let Some(next) = nonce.as_ref().err().and_then(|e| match e {
            PsnError::Lan(e) => lan::retry_target(e, target),
            _ => None,
        }) else {
            break;
        };
        target = next;
        nonce = request_nonce(&mut rudp, target, console, key);
    }
    let nonce = nonce?;
    let mut cipher = CtrlCipher::new(RpCrypt::auth(target, &nonce, &host.rp_key).map_err(|e| PsnError::Lan(e.into()))?);
    std::thread::sleep(BEFORE_CTRL_DELAY);

    let request =
        ctrl::ctrl_request_port(target, &console.ip().to_string(), console.port(), &mut cipher, key, did, codec)
            .map_err(PsnError::Lan)?;
    if target.is_ps5() {
        cipher.set_local(cipher.local() + 1);
    }
    let mut remote = rudp.handshake()?;
    // chiaki-ng sends the ctrl request once more when the first goes unanswered.
    let answer = match rudp.http(&mut remote, request.as_bytes()) {
        Err(PsnError::Timeout(_)) => rudp.http(&mut remote, request.as_bytes())?,
        other => other?,
    };
    // chiaki-ng acknowledges the answer and does not wait for FINISH: ctrl goes on over the same exchange.
    rudp.send_ack(remote)?;
    let (head, rest) = split(&answer);
    let response = ctrl::parse_ctrl_response(head, &mut cipher).map_err(PsnError::Lan)?;
    let rest = rest.to_vec();
    Session::over(Box::new(rudp), target, cipher, &rest, response, Some(HEARTBEAT_EVERY)).map_err(PsnError::Lan)
}

/// chiaki-ng `takion_read_extra_sock_messages`: drops what is waiting on the data hole (the holepunch's last
/// requests), so the stream's handshake reads only the stream. How many were dropped.
pub fn drain(sock: &std::net::UdpSocket) -> Result<usize, PsnError> {
    let end = Instant::now() + DRAIN_MAX;
    let mut buf = [0u8; 1500];
    let mut dropped = 0;
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(dropped);
        }
        match psr_lan::udp::recv_within(sock, &mut buf, left.min(DRAIN_QUIET)) {
            Ok(Some(_)) => dropped += 1,
            Ok(None) => return Ok(dropped),
            // An earlier send that went unanswered (an ICMP port-unreachable: a reset on Windows, a refusal
            // elsewhere) says nothing about the stream to come: passed over, after a pause so a stream of them
            // cannot spin. Any other error ends the stream's start.
            Err(e)
                if matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused) =>
            {
                std::thread::sleep(RESET_PAUSE);
            }
            Err(e) => return Err(PsnError::Network(format!("the data hole: {e}"))),
        }
    }
}

/// chiaki-ng's stream start over PSN (`session_thread_func` from the switch on): the switch to the stream
/// connection over ctrl, then the data hole drained, then the stream connection on it, as at home. With the
/// stream, the ctrl messages that came while it waited for the switch, for the caller to handle.
///
/// The console's switch is known by its type alone, as in chiaki-ng: anyone who can send to the control hole
/// as the console can answer first, and the stream's start then fails when the console does not take it up.
pub fn open_stream(
    ctrl: &mut Session,
    data: Hole,
    profile: &VideoProfile,
) -> Result<(Stream, Vec<CtrlEvent>), PsnError> {
    let events = ctrl.switch_to_stream(SWITCH_TIMEOUT).map_err(PsnError::Lan)?;
    drain(&data.socket)?;
    let stream = stream::connect_on(data.socket, ctrl.target(), ctrl.session_id(), ctrl.rpcrypt(), profile)
        .map_err(PsnError::Lan)?;
    Ok((stream, events))
}
