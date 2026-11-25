// SPDX-License-Identifier: AGPL-3.0-only
//! Registration over PSN: the console hands this client its registration key and RP key through the punched
//! control hole, with no PIN. Ported from chiaki-ng `lib/src/regist.c`, the `holepunch_info` path
//! (LicenseRef-AGPL-3.0-only-OpenSSL), which `session.c` runs before every PSN session.
//!
//! The request is the home network's (`psr_lan::regist`), with the cipher made from the session's
//! `customData1`, `data1` and `data2` instead of a PIN, and this client's local address as `HOST`. It goes
//! over RUDP: the handshake, the request and its response, then ACK and FINISH.

use std::net::Ipv4Addr;

use psr_crypto::Target;
use psr_lan::regist::{self, RegisteredHost};

use crate::PsnError;
use crate::holepunch::{self, Started};
use crate::rudp::Rudp;

/// How registration went, beside the keys: whether the console's FINISH came (chiaki-ng carries on
/// without it).
#[derive(Debug)]
pub struct Registered {
    pub host: RegisteredHost,
    pub finished: bool,
}

/// The request: the header with `local_ip` as `HOST`, then the payload; and the cipher for the answer.
pub fn request(
    target: Target,
    account_id: u64,
    started: &Started,
    local_ip: Ipv4Addr,
    ambassador: &[u8; 16],
) -> Result<(Vec<u8>, psr_crypto::rpcrypt::RpCrypt), PsnError> {
    let (payload, crypt) = regist::request_payload_psn(
        target,
        ambassador,
        &account_id.to_le_bytes(),
        &started.custom_data1,
        &started.data1,
        &started.data2,
    )
    .map_err(PsnError::Lan)?;
    let mut out =
        regist::request_header_host(target, payload.len(), &local_ip.to_string()).map_err(PsnError::Lan)?.into_bytes();
    out.extend(payload);
    Ok((out, crypt))
}

/// chiaki-ng `regist_thread_func` with `holepunch_info`. `account_id` is the PSN account's, as the session
/// was created with; the console must be one that registers over PSN (a PS5, or a PS4 on 10 or later).
pub fn register(
    rudp: &mut Rudp,
    target: Target,
    account_id: u64,
    started: &Started,
    local_ip: Ipv4Addr,
) -> Result<Registered, PsnError> {
    let ambassador = holepunch::random::<16>()?;
    let (request, crypt) = request(target, account_id, started, local_ip, &ambassador)?;
    let mut remote_counter = rudp.handshake()?;
    let response = rudp.http(&mut remote_counter, &request)?;
    let finished = rudp.finish(remote_counter).is_ok();
    // chiaki-ng: the whole answer must have come in the one message; `parse_response` checks the length.
    let host = regist::parse_response(target, &crypt, &response).map_err(PsnError::Lan)?;
    Ok(Registered { host, finished })
}
