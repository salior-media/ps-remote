// SPDX-License-Identifier: AGPL-3.0-only
//! Punching the hole: our offer, the UDP exchange that finds a console candidate that answers, and the
//! accepts. Ported from chiaki-ng `holepunch_session_create_offer`, `send_offer`, `send_accept`,
//! `session_message_serialize`, `wait_for_session_message_ack`, `check_candidates`, `send_response_ps`,
//! `send_responseto_ps`, `receive_request_send_response_ps` and `chiaki_holepunch_session_punch_hole` in
//! `lib/src/remote/holepunch.c` (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! It is done twice, for the control port and then the data port, each with its own UDP socket.
//!
//! **Differences from chiaki-ng:**
//! - **IPv4, one socket, no UPnP and no port guessing.** Our offer is the STUN candidate (when the NAT changed
//!   the port), the STATIC one (our public address with our port) and the LOCAL one. chiaki-ng adds UPnP port
//!   mappings and, behind NATs that allocate ports in steps or at random, guessed candidates sent from up to 250
//!   sockets; neither is ported yet (`docs/PSN.md`).
//! - **Our local address is the route's.** chiaki-ng walks the network adapters and prefers wired ones; here it
//!   is the address the system would send from to the STUN server.
//! - **Malformed datagrams are passed over.** chiaki-ng ends the exchange on a datagram of the wrong size or type
//!   from a candidate; anyone can send one, so here it is ignored, and only the timeouts end the exchange.
//! - **A new address must be at an offered IP.** chiaki-ng takes an address the console did not offer, when a
//!   datagram comes from it, as a DERIVED candidate, and sends it our request, whose ID is all a response needs;
//!   so anyone who learns our port could answer in the console's place. Here a DERIVED candidate must share an
//!   IP address with one the console offered (its NAT showing another port), and only a request of the
//!   console's makes one; others are passed over.
//! - **A response must carry our hashed ID.** chiaki-ng takes any response with our 5-byte request ID. The
//!   console's carries our 20-byte hashed ID at 0x24, where our request carries its own (every live run,
//!   2026-11-25), so here that is required too: someone who saw only the request ID cannot answer.
//! - **Deadlines are absolute.** chiaki-ng's waits restart with every datagram that arrives, so a stream of junk
//!   could hold the exchange open; here the candidate check ends after [`SELECT_TRIES`] resends' time, and the
//!   answering after the hole after twice [`ANSWER_TIMEOUT`], whatever arrives. A reply that cannot be sent to
//!   one candidate does not end the exchange.
//! - **The exchange after the hole is bounded.** chiaki-ng answers the console's requests until a second passes
//!   with none; here that also stops after [`ANSWER_MAX`] requests, so a sender cannot keep it going.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::PsnError;
use crate::holepunch::{self, Action, Candidate, CandidateKind, Message, Peer, START_TIMEOUT, random};
use crate::push::Push;
use crate::rps::Created;
use crate::stun;

/// The size of every datagram in the exchange.
pub const PACKET_LEN: usize = 88;
/// chiaki-ng `MSG_TYPE_REQ` and `MSG_TYPE_RESP`.
pub const MSG_REQ: u32 = 0x0600_0000;
pub const MSG_RESP: u32 = 0x0700_0000;
/// chiaki-ng `SELECT_CANDIDATE_TIMEOUT_SEC` and `SELECT_CANDIDATE_TRIES`: the requests go out again every half
/// second, up to twenty times, until a candidate answers.
pub const SELECT_TIMEOUT: Duration = Duration::from_millis(500);
pub const SELECT_TRIES: u32 = 20;
/// chiaki-ng `WAIT_RESPONSE_TIMEOUT_SEC`: after the hole, the console's requests are answered until this long
/// passes without one.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(1);
/// The most requests answered after the hole (see the module notes).
pub const ANSWER_MAX: usize = 32;
/// chiaki-ng `EXTRA_CANDIDATE_ADDRESSES`: addresses the console answered from that it did not offer.
pub const EXTRA_CANDIDATES: usize = 3;
/// chiaki-ng's offer: `natType` 2, and an all-zero `skey`.
const OUR_NAT_TYPE: u8 = 2;

/// One side's identity in the exchange: chiaki-ng `sid_local` and `hashed_id_local` (or the console's).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ids {
    pub sid: u32,
    pub hashed_id: [u8; 20],
}

impl std::fmt::Debug for Ids {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ids").finish_non_exhaustive()
    }
}

impl Ids {
    /// Ours, made at random as chiaki-ng's are. The sid is kept below 2^31: chiaki-ng writes it with `%d`, so a
    /// larger one would be sent negative.
    pub fn random() -> Result<Self, PsnError> {
        let sid = u32::from_be_bytes(random()?) & 0x7fff_ffff;
        Ok(Ids { sid: sid.max(1), hashed_id: random()? })
    }
}

/// chiaki-ng's request datagram: the type, our hashed ID, the console's, both sids (their low 16 bits), and a
/// random 5-byte request ID at 0x4b.
pub fn request_packet(ours: &Ids, console: &Ids, request_id: &[u8; 5]) -> [u8; PACKET_LEN] {
    let mut p = [0u8; PACKET_LEN];
    header(&mut p, MSG_REQ, ours, console);
    p[0x4b..0x50].copy_from_slice(request_id);
    p
}

fn header(p: &mut [u8; PACKET_LEN], kind: u32, ours: &Ids, console: &Ids) {
    p[0..4].copy_from_slice(&kind.to_be_bytes());
    p[0x04..0x18].copy_from_slice(&ours.hashed_id);
    p[0x24..0x38].copy_from_slice(&console.hashed_id);
    p[0x44..0x46].copy_from_slice(&(ours.sid as u16).to_be_bytes());
    p[0x46..0x48].copy_from_slice(&(console.sid as u16).to_be_bytes());
}

/// chiaki-ng `send_response_ps`: the answer to the console's request `req`, sent to `to`. It echoes the request
/// ID and carries `to` itself, XORed with the sids, at 0x50.
pub fn response_packet(ours: &Ids, console: &Ids, req: &[u8; PACKET_LEN], to: SocketAddrV4) -> [u8; PACKET_LEN] {
    let mut p = [0u8; PACKET_LEN];
    header(&mut p, MSG_RESP, ours, console);
    p[0x4b..0x50].copy_from_slice(&req[0x4b..0x50]);
    let (local, remote) = ((ours.sid as u16).to_be_bytes(), (console.sid as u16).to_be_bytes());
    let addr = to.ip().octets();
    let port = to.port().to_be_bytes();
    p[0x50..0x56].copy_from_slice(&[
        local[0] ^ addr[0],
        local[1] ^ addr[1],
        remote[0] ^ addr[2],
        remote[1] ^ addr[3],
        local[0] ^ port[0],
        local[1] ^ port[1],
    ]);
    p
}

/// The type of a datagram of the exchange's size, or `None`.
pub fn packet_type(p: &[u8]) -> Option<u32> {
    (p.len() == PACKET_LEN).then(|| u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
}

fn kind_name(k: CandidateKind) -> &'static str {
    match k {
        CandidateKind::Static => "STATIC",
        CandidateKind::Local => "LOCAL",
        CandidateKind::Stun => "STUN",
        CandidateKind::Derived => "DERIVED",
    }
}

fn candidate_json(c: &Candidate) -> String {
    // chiaki-ng session_connrequest_candidate_fmt. Addresses are typed, so they need no escaping.
    format!(
        r#"{{"type":"{}","addr":"{}","mappedAddr":"{}","port":{},"mappedPort":{}}}"#,
        kind_name(c.kind),
        c.addr,
        c.addr_mapped,
        c.port,
        c.port_mapped
    )
}

/// chiaki-ng `session_message_serialize` for an OFFER or an ACCEPT. `sid` and `peerSid` are written as
/// chiaki-ng's `%d` writes them; `localHashedId` is empty when it is all zeros; `defaultRouteMacAddr` is always
/// empty, as chiaki-ng's is.
#[allow(clippy::too_many_arguments)]
fn conn_message(
    action: &str,
    req_id: u16,
    sid: u32,
    peer_sid: u32,
    nat_type: u8,
    account_id: u64,
    candidates: &[Candidate],
    hashed_id: &[u8; 20],
) -> String {
    let candidates: Vec<String> = candidates.iter().map(candidate_json).collect();
    let hashed = if hashed_id.iter().all(|&b| b == 0) { String::new() } else { B64.encode(hashed_id) };
    format!(
        concat!(
            r#"{{"action":"{}","reqId":{},"error":0,"connRequest":{{"sid":{},"peerSid":{},"skey":"{}","natType":{},"#,
            r#""candidate":[{}],"defaultRouteMacAddr":"","localPeerAddr":{{"accountId":"{}","platform":"REMOTE_PLAY"}},"#,
            r#""localHashedId":"{}"}}}}"#
        ),
        action,
        req_id,
        sid as i32,
        peer_sid as i32,
        B64.encode([0u8; 16]),
        nat_type,
        candidates.join(","),
        account_id,
        hashed
    )
}

/// Our OFFER: chiaki-ng's `natType` 2, our sid and hashed ID, and the candidates.
pub fn offer_message(req_id: u16, ours: &Ids, peer_sid: u32, account_id: u64, candidates: &[Candidate]) -> String {
    conn_message("OFFER", req_id, ours.sid, peer_sid, OUR_NAT_TYPE, account_id, candidates, &ours.hashed_id)
}

/// Our ACCEPT (chiaki-ng `send_accept`): `natType` 0, no hashed ID, and the candidate the hole was found at.
pub fn accept_message(req_id: u16, ours: &Ids, peer_sid: u32, account_id: u64, selected: &Candidate) -> String {
    conn_message("ACCEPT", req_id, ours.sid, peer_sid, 0, account_id, std::slice::from_ref(selected), &[0; 20])
}

fn v4(ip: Ipv4Addr, port: u16, kind: CandidateKind) -> Candidate {
    let none = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    Candidate { kind, addr: IpAddr::V4(ip), addr_mapped: none, port, port_mapped: 0 }
}

/// Our candidates, in chiaki-ng's order: STUN first (the address the NAT showed the STUN server) when it differs
/// from STATIC (our public address with our own port), then STATIC, then LOCAL. The second value is chiaki-ng's
/// `local_candidates`: the LOCAL candidate, and the first of the offer, used to fill in the accepted candidate's
/// mapped address.
pub fn our_candidates(local: SocketAddrV4, public: SocketAddrV4) -> (Vec<Candidate>, [Candidate; 2]) {
    let stun = v4(*public.ip(), public.port(), CandidateKind::Stun);
    let fixed = v4(*public.ip(), local.port(), CandidateKind::Static);
    let lan = v4(*local.ip(), local.port(), CandidateKind::Local);
    let offer = if public.port() == local.port() { vec![fixed, lan.clone()] } else { vec![stun, fixed, lan.clone()] };
    let first = offer[0].clone();
    (offer, [lan, first])
}

/// chiaki-ng's last step of `check_candidates`: the accepted candidate carries which of ours it reached. A LOCAL
/// candidate, or a DERIVED one at a private address, reached our LOCAL candidate; any other, the first of the
/// offer.
pub fn mapped(selected: &Candidate, ours: &[Candidate; 2]) -> Candidate {
    let private = match selected.addr {
        IpAddr::V4(ip) => ip.is_private(),
        // chiaki-ng: an address starting fc or fd.
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00,
    };
    let via = if selected.kind == CandidateKind::Local || (selected.kind == CandidateKind::Derived && private) {
        &ours[0]
    } else {
        &ours[1]
    };
    Candidate { addr_mapped: via.addr, port_mapped: via.port, ..selected.clone() }
}

const ALL_ACTIONS: &[Action] = &[Action::Offer, Action::Accept, Action::Result, Action::Unknown];

/// What [`check_candidates`] found. Its `Debug` leaves out the addresses.
pub struct Found {
    /// The console's candidate that answered: one it offered, or one it answered from ([`CandidateKind::Derived`]).
    pub candidate: Candidate,
    pub addr: SocketAddrV4,
    /// Whether the answer carried the console's hashed ID first, where our requests carry ours. Recorded, not
    /// required; ours in the second place is required (see the module notes).
    pub ids_mirrored: bool,
}

fn io(e: std::io::Error) -> PsnError {
    PsnError::Network(format!("the holepunch socket: {e}"))
}

/// chiaki-ng `check_candidates` (with its one request per candidate): our request to every IPv4 candidate of the
/// console's, again every [`SELECT_TIMEOUT`], until a response to it arrives. The console's own requests are
/// answered along the way. On success the socket is connected to the candidate that answered.
pub fn check_candidates(
    sock: &UdpSocket,
    ours: &Ids,
    console: &Ids,
    candidates: &[Candidate],
) -> Result<(Found, bool), PsnError> {
    let request_id: [u8; 5] = random()?;
    let request = request_packet(ours, console, &request_id);
    let mut targets: Vec<(Candidate, SocketAddrV4)> = candidates
        .iter()
        .filter_map(|c| match c.addr {
            IpAddr::V4(ip) => Some((c.clone(), SocketAddrV4::new(ip, c.port))),
            IpAddr::V6(_) => None,
        })
        .collect();
    if targets.is_empty() {
        return Err(PsnError::MissingField("an IPv4 candidate"));
    }
    let offered = targets.len();
    let send_all = |targets: &[(Candidate, SocketAddrV4)]| {
        // A send to one candidate can fail (an unreachable network) while another works, as in chiaki-ng.
        targets.iter().filter(|(_, a)| sock.send_to(&request, a).is_ok()).count()
    };
    if send_all(&targets) == 0 {
        return Err(PsnError::Network("no candidate of the console's could be sent to".into()));
    }
    // One deadline for the whole exchange, and the resends on their own clock: datagrams arriving, junk or not,
    // never hold either back (the security review's finding: a read timeout alone restarts with each one).
    let deadline = Instant::now() + SELECT_TIMEOUT * (SELECT_TRIES + 1);
    let mut next_resend = Instant::now() + SELECT_TIMEOUT;
    let mut responded = false;
    let mut buf = [0u8; 2048];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(PsnError::Timeout("an answer from the console's candidates"));
        }
        if now >= next_resend {
            send_all(&targets);
            next_resend += SELECT_TIMEOUT;
        }
        let wait = next_resend.min(deadline).saturating_duration_since(now).max(Duration::from_millis(1));
        sock.set_read_timeout(Some(wait)).map_err(io)?;
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok((n, SocketAddr::V4(from))) => (n, from),
            Ok(_) => continue,
            Err(e) if stun::is_transient(&e) => continue,
            Err(e) => return Err(io(e)),
        };
        let Ok(packet) = <[u8; PACKET_LEN]>::try_from(&buf[..n]) else { continue };
        let i = match targets.iter().position(|(_, a)| *a == from) {
            Some(i) => i,
            // chiaki-ng: an address the console did not offer becomes a DERIVED candidate, up to three of them.
            // Here only at an IP address it did offer, and only by sending a request (see the module notes).
            None if targets.len() < offered + EXTRA_CANDIDATES
                && packet_type(&packet) == Some(MSG_REQ)
                && targets[..offered].iter().any(|(_, a)| a.ip() == from.ip()) =>
            {
                targets.push((v4(*from.ip(), from.port(), CandidateKind::Derived), from));
                targets.len() - 1
            }
            None => continue,
        };
        match packet_type(&packet) {
            Some(MSG_REQ) => {
                // A reply that cannot go out is not fatal, as a request that cannot is not (chiaki-ng ends here).
                if sock.send_to(&response_packet(ours, console, &packet, from), from).is_ok() {
                    responded = true;
                }
                if targets[i].0.kind == CandidateKind::Derived {
                    // So the new address gets a request of ours too (chiaki-ng does this once; again is harmless).
                    let _ = sock.send_to(&request, from);
                }
            }
            // Our request ID, and our hashed ID where the console puts it (see the module notes).
            Some(MSG_RESP) if packet[0x4b..0x50] == request_id && packet[0x24..0x38] == ours.hashed_id => {
                sock.connect(from).map_err(io)?;
                let ids_mirrored = packet[0x04..0x18] == console.hashed_id;
                return Ok((Found { candidate: targets.swap_remove(i).0, addr: from, ids_mirrored }, responded));
            }
            // A response to someone else's request, or any other type: passed over.
            _ => {}
        }
    }
}

/// chiaki-ng `receive_request_send_response_ps`: on the connected socket, the console's requests are answered
/// until [`ANSWER_TIMEOUT`] passes with none, [`ANSWER_MAX`] are answered, or twice [`ANSWER_TIMEOUT`] has
/// passed in all. Whether any came.
pub fn answer_requests(sock: &UdpSocket, ours: &Ids, console: &Ids, to: SocketAddrV4) -> Result<bool, PsnError> {
    let deadline = Instant::now() + ANSWER_TIMEOUT * 2;
    let (mut answered, mut buf) = (0, [0u8; 2048]);
    let mut idle_until = Instant::now() + ANSWER_TIMEOUT;
    while answered < ANSWER_MAX {
        let now = Instant::now();
        let until = idle_until.min(deadline);
        if now >= until {
            break;
        }
        sock.set_read_timeout(Some((until - now).max(Duration::from_millis(1)))).map_err(io)?;
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e) if stun::is_transient(&e) => continue,
            Err(e) => return Err(io(e)),
        };
        if let Ok(req) = <[u8; PACKET_LEN]>::try_from(&buf[..n])
            && packet_type(&req) == Some(MSG_REQ)
        {
            // As in `check_candidates`, a reply that cannot go out is not fatal.
            let _ = sock.send(&response_packet(ours, console, &req, to));
            answered += 1;
            idle_until = Instant::now() + ANSWER_TIMEOUT;
        }
    }
    Ok(answered > 0)
}

/// A punched hole: a UDP socket connected to the console. Its `Debug` leaves out the addresses.
pub struct Hole {
    pub socket: UdpSocket,
    pub console: SocketAddrV4,
    /// The console's candidate, with which of ours it reached, as sent in our ACCEPT.
    pub candidate: Candidate,
    /// See [`Found::ids_mirrored`].
    pub ids_mirrored: bool,
    /// Our local address, the one our LOCAL candidate offered; registration sends it as `HOST`.
    pub local_ip: Ipv4Addr,
}

impl std::fmt::Debug for Found {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Found")
            .field("candidate", &self.candidate)
            .field("ids_mirrored", &self.ids_mirrored)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Hole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hole")
            .field("candidate", &self.candidate)
            .field("ids_mirrored", &self.ids_mirrored)
            .finish_non_exhaustive()
    }
}

/// Which hole: chiaki-ng `ChiakiHolepunchPortType`. The control hole comes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Port {
    Ctrl,
    Data,
}

/// The holepunch for one session, after [`holepunch::start`]: chiaki-ng's `Session` state between punches.
pub struct Puncher<'a> {
    pub access_token: &'a str,
    pub created: &'a Created,
    pub console_duid: &'a [u8; 32],
    ours: Ids,
    /// The console's sid and hashed ID, from its latest offer.
    console: Option<Ids>,
    /// chiaki-ng `local_req_id`.
    next_req: u16,
    /// chiaki-ng `SESSION_STATE_CTRL_ESTABLISHED`: the data hole is punched only after the control hole.
    ctrl_done: bool,
    /// Told the name of each step as it completes (chiaki-ng's log lines); never addresses or IDs.
    pub on_step: fn(&'static str),
    /// Told each message of the console's that a wait passes over: its action, request ID and error.
    pub on_passed_over: fn(Action, u16, u16),
}

impl<'a> Puncher<'a> {
    pub fn new(access_token: &'a str, created: &'a Created, console_duid: &'a [u8; 32]) -> Result<Self, PsnError> {
        Ok(Puncher {
            access_token,
            created,
            console_duid,
            ours: Ids::random()?,
            console: None,
            next_req: 1,
            ctrl_done: false,
            on_step: |_| {},
            on_passed_over: |_, _, _| {},
        })
    }

    fn take_req(&mut self) -> u16 {
        let id = self.next_req;
        self.next_req = self.next_req.wrapping_add(1);
        id
    }

    fn send(&self, body: &str) -> Result<(), PsnError> {
        holepunch::send_message(self.access_token, self.created, self.console_duid, body)
    }

    /// The console's next message with `action` (and for a RESULT, this request ID), others passed over.
    fn wait(&self, push: &mut Push, action: Action, req_id: Option<u16>) -> Result<Message, PsnError> {
        let peer = Peer { session_id: &self.created.session_id, console_duid: self.console_duid };
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            let m = holepunch::wait_message(push, &peer, ALL_ACTIONS, deadline)?;
            if m.action == action && req_id.is_none_or(|id| id == m.req_id) {
                return Ok(m);
            }
            (self.on_passed_over)(m.action, m.req_id, m.error);
        }
    }

    /// chiaki-ng `holepunch_session_create_offer` then `chiaki_holepunch_session_punch_hole`: a new socket and
    /// our candidates; the console's offer, acknowledged; our offer, acknowledged; the candidates checked; and
    /// the accepts, both ways.
    pub fn punch(&mut self, push: &mut Push, port: Port) -> Result<Hole, PsnError> {
        if port == Port::Data && !self.ctrl_done {
            return Err(PsnError::MissingField("the control hole, punched before the data hole"));
        }
        // The offer is made before the console's arrives, as chiaki-ng makes it.
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(io)?;
        let (public, server) = stun::external_address(&sock)?;
        let local_port = sock.local_addr().map_err(io)?.port();
        let local_ip = route_address(server)?;
        let (candidates, ours_for_mapping) = our_candidates(SocketAddrV4::new(local_ip, local_port), public);
        let _unused = self.take_req(); // chiaki-ng numbers the offer once when making it, and again when sending it
        let offer_peer_sid = self.console.map_or(0, |c| c.sid);
        (self.on_step)("our candidates");

        let console_offer = self.wait(push, Action::Offer, None)?;
        let req = console_offer.conn_request.as_ref().ok_or(PsnError::MissingField("connRequest"))?;
        let console = Ids { sid: req.sid, hashed_id: req.local_hashed_id };
        self.console = Some(console);
        (self.on_step)("the console's offer");
        self.send(&holepunch::result_message(console_offer.req_id))?;

        let offer_id = self.take_req();
        self.send(&offer_message(offer_id, &self.ours, offer_peer_sid, self.created.account_id, &candidates))?;
        (self.on_step)("our offer sent");
        self.wait(push, Action::Result, Some(offer_id))?;
        (self.on_step)("our offer acknowledged");

        let (found, responded) = check_candidates(&sock, &self.ours, &console, &req.candidates)?;
        let selected = mapped(&found.candidate, &ours_for_mapping);
        (self.on_step)("a candidate answered");
        // chiaki-ng, at the end of `check_candidates`: the console's own requests on the new hole are answered
        // before the ACCEPT, and the hole fails if it never sent one, before or now. The console does not send
        // its ACCEPT until its requests are answered (seen live, 2026-11-25).
        let requested = answer_requests(&sock, &self.ours, &console, found.addr)?;
        if !responded && !requested {
            return Err(PsnError::Timeout("a request from the console"));
        }
        (self.on_step)("the console's requests answered");
        let accept_id = self.take_req();
        self.send(&accept_message(accept_id, &self.ours, console.sid, self.created.account_id, &selected))?;
        (self.on_step)("our accept sent");
        let accept = self.wait(push, Action::Accept, None)?;
        (self.on_step)("the console's accept");
        self.send(&holepunch::result_message(accept.req_id))?;

        // chiaki-ng answers the console's requests once more after the accepts; none coming is fine then.
        answer_requests(&sock, &self.ours, &console, found.addr)?;
        self.ctrl_done = true;
        Ok(Hole { socket: sock, console: found.addr, candidate: selected, ids_mirrored: found.ids_mirrored, local_ip })
    }
}

/// The local address the system would send from to `to`: a UDP socket connected to it, which sends nothing.
fn route_address(to: SocketAddrV4) -> Result<Ipv4Addr, PsnError> {
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(io)?;
    probe.connect(to).map_err(io)?;
    match probe.local_addr().map_err(io)? {
        SocketAddr::V4(a) if !a.ip().is_unspecified() => Ok(*a.ip()),
        _ => Err(PsnError::Network("no local IPv4 address routes to the internet".into())),
    }
}
