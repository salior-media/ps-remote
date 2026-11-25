// SPDX-License-Identifier: AGPL-3.0-only
//! The local API (`docs/SERVICE.md`): HTTP on loopback, every `/api` route behind a bearer token and a
//! `Host` check.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use psr_lan::discovery;
use psr_lan::discovery::{Console, HostState};
use psr_lan::regist::{self, Identity, RegisteredHost};
use psr_lan::store;
use serde::{Deserialize, Serialize};
use str0m::change::SdpOffer;
use subtle::ConstantTimeEq;

use crate::runner::{self, Handle, Status};

/// How long `GET /api/consoles` listens for consoles on the home network.
const DISCOVERY_WAIT: Duration = Duration::from_millis(1500);
/// Request bodies are an SDP offer at most; anything bigger is refused.
const BODY_MAX: usize = 64 * 1024;
const PAGE: &str = include_str!("page.html");

/// Everything a request handler needs.
pub struct Service {
    token: String,
    /// The `Host` values accepted: `127.0.0.1:<port>` and `localhost:<port>`.
    hosts: [String; 2],
    consoles_dir: PathBuf,
    session: Mutex<Option<Handle>>,
    /// A session start is under way: a second one is refused until it ends.
    starting: AtomicBool,
    /// One discovery search at a time, so many requests cannot fill the blocking pool with them.
    discovery: tokio::sync::Mutex<()>,
    /// What playing over PSN needs, when the service was started with it: Sony's Remote Play app secret
    /// (from the environment, never stored) and the folder with the saved sign-in.
    psn: Option<Psn>,
}

/// See [`Service::psn`]. It has no `Debug`, so neither can be printed.
pub struct Psn {
    pub app_secret: String,
    pub config_dir: PathBuf,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service").field("hosts", &self.hosts).finish_non_exhaustive()
    }
}

impl Service {
    /// The session slot. A handler that panicked holding it leaves nothing half-written (it holds an
    /// `Option` that is replaced whole), so a poisoned lock is still usable.
    fn session(&self) -> MutexGuard<'_, Option<Handle>> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn new(token: String, port: u16, consoles_dir: PathBuf) -> Arc<Self> {
        Self::with_psn(token, port, consoles_dir, None)
    }

    /// [`Service::new`], able to play over PSN too.
    pub fn with_psn(token: String, port: u16, consoles_dir: PathBuf, psn: Option<Psn>) -> Arc<Self> {
        Arc::new(Self {
            token,
            hosts: [format!("127.0.0.1:{port}"), format!("localhost:{port}")],
            consoles_dir,
            session: Mutex::new(None),
            starting: AtomicBool::new(false),
            discovery: tokio::sync::Mutex::new(()),
            psn,
        })
    }
}

/// The token: 32 random bytes, as hex.
pub fn new_token() -> Result<String, getrandom::Error> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

pub fn router(service: Arc<Service>) -> Router {
    let api = Router::new()
        .route("/consoles", get(consoles))
        .route("/play", post(play))
        .route("/play-psn", post(play_psn))
        .route("/psn-consoles", get(psn_consoles))
        .route("/offer", post(offer))
        .route("/stop", post(stop))
        .route("/link", post(link))
        .route("/wake", post(wake))
        .route("/psn-status", get(psn_status))
        .route("/psn-signin-url", get(psn_signin_url))
        .route("/psn-signin", post(psn_signin))
        .route("/psn-signout", post(psn_signout))
        .route("/status", get(status))
        .route_layer(middleware::from_fn_with_state(Arc::clone(&service), require_token));
    Router::new()
        .route("/", get(page))
        .nest("/api", api)
        .layer(middleware::from_fn_with_state(Arc::clone(&service), require_host))
        .layer(DefaultBodyLimit::max(BODY_MAX))
        .with_state(service)
}

fn refuse(code: StatusCode, why: &'static str) -> Response {
    (code, why).into_response()
}

/// Every request, the page included, must name this service as its `Host`: a page that reaches the port by
/// DNS rebinding names its own.
async fn require_host(State(s): State<Arc<Service>>, req: Request, next: Next) -> Response {
    let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok());
    if !host.is_some_and(|h| s.hosts.iter().any(|ok| ok == h)) {
        return refuse(StatusCode::MISDIRECTED_REQUEST, "wrong Host");
    }
    next.run(req).await
}

async fn require_token(State(s): State<Arc<Service>>, req: Request, next: Next) -> Response {
    let given = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");
    // Compared in constant time; the lengths are public (a fixed 64 hex digits).
    if !bool::from(given.as_bytes().ct_eq(s.token.as_bytes())) {
        return refuse(StatusCode::UNAUTHORIZED, "missing or wrong token");
    }
    next.run(req).await
}

/// The test page. It holds no token: any local process can fetch it. The page reads the token from its
/// URL's fragment, which the service prints at start and browsers never send.
async fn page() -> Response {
    let mut r = Html(PAGE).into_response();
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; media-src 'self' blob:; frame-ancestors 'none'"),
    );
    r
}

#[derive(Serialize)]
struct ConsoleInfo {
    nickname: Option<String>,
    mac: String,
    target: String,
    /// Where it answered on the home network just now, and its state, if it did.
    address: Option<IpAddr>,
    state: Option<String>,
}

fn mac_hex(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect()
}

/// The saved registrations, or the response that says why they could not be read.
fn linked(s: &Service) -> Result<Vec<RegisteredHost>, Box<Response>> {
    store::load_all(&s.consoles_dir)
        .map_err(|e| Box::new(refuse_owned(StatusCode::INTERNAL_SERVER_ERROR, format!("the linked consoles: {e}"))))
}

fn refuse_owned(code: StatusCode, why: String) -> Response {
    (code, why).into_response()
}

/// The linked consoles, without their keys, each with where it answered on the home network.
async fn consoles(State(s): State<Arc<Service>>) -> Response {
    let list = match linked(&s) {
        Ok(l) => l,
        Err(r) => return *r,
    };
    // Discovery only listens for answers to a search broadcast; it wakes nothing. If it fails, the
    // consoles are listed without addresses.
    let found = search(&s, Ipv4Addr::BROADCAST).await;
    let info: Vec<ConsoleInfo> = list
        .iter()
        .map(|c| {
            let mac = mac_hex(&c.server_mac);
            let here = found.iter().find(|h| h.host_id.as_deref().is_some_and(|id| id.eq_ignore_ascii_case(&mac)));
            ConsoleInfo {
                nickname: c.server_nickname.clone(),
                target: format!("{:?}", c.target),
                address: here.map(|h| h.addr),
                state: here.map(|h| format!("{:?}", h.state)),
                mac,
            }
        })
        .collect();
    axum::Json(info).into_response()
}

/// A discovery search sent to `to` (the broadcast address, or one console), one at a time.
async fn search(s: &Service, to: Ipv4Addr) -> Vec<discovery::Host> {
    let _one = s.discovery.lock().await;
    tokio::task::spawn_blocking(move || discovery::search(to, DISCOVERY_WAIT))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default()
}

/// Clears [`Service::starting`] when dropped. It goes into the blocking start itself, so a client that gives
/// up while a start runs cannot let a second one begin beside it (the security review of 9c-3b): the start
/// cannot be cancelled, and only its end frees the slot.
struct Starting(Arc<Service>);

impl Starting {
    /// Takes the slot, or `None` when a start is already under way.
    fn take(s: &Arc<Service>) -> Option<Self> {
        s.starting
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Starting(Arc::clone(s)))
    }
}

impl Drop for Starting {
    fn drop(&mut self) {
        self.0.starting.store(false, Ordering::Release);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlayRequest {
    host: IpAddr,
    /// Which linked console, by MAC (12 hex digits). Needed only when more than one is linked.
    console: Option<String>,
}

/// The linked console a request names by MAC, or the only one when it names none.
fn pick(list: Vec<RegisteredHost>, mac: Option<&str>) -> Option<RegisteredHost> {
    match (mac, list.len()) {
        (Some(mac), _) => list.into_iter().find(|c| mac_hex(&c.server_mac) == mac.to_ascii_lowercase()),
        (None, 1) => list.into_iter().next(),
        (None, _) => None,
    }
}

/// Where `console` answers discovery as itself at `host`, if it does.
async fn answering_as(s: &Service, host: Ipv4Addr, console: &RegisteredHost) -> Option<discovery::Host> {
    let mac = mac_hex(&console.server_mac);
    search(s, host)
        .await
        .into_iter()
        .find(|h| h.addr == IpAddr::V4(host) && h.host_id.as_deref().is_some_and(|id| id.eq_ignore_ascii_case(&mac)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkRequest {
    host: IpAddr,
    /// The 8 digits on the console's *Link Device* screen; spaces are ignored.
    pin: String,
    /// The PSN account ID, base64. Without it, the service asks Sony using the saved sign-in.
    account_id: Option<String>,
}

#[derive(Serialize)]
struct Linked {
    nickname: Option<String>,
    mac: String,
}

/// The PIN as a number, if it is 8 digits. Never echoed: it is a secret for as long as the screen shows it.
fn pin(text: &str) -> Option<u32> {
    let digits: String = text.chars().filter(|c| *c != ' ').collect();
    (digits.len() == 8 && digits.bytes().all(|b| b.is_ascii_digit())).then(|| digits.parse().ok()).flatten()
}

/// Whether `ip` can be a console on the home network: a private or link-local address (or this machine, for
/// tests). Discovery and registration are never sent out to the internet.
fn on_home_network(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local() || ip.is_loopback()
}

/// Whether the console that registered is the one that answered discovery: its MAC is the `host-id` it gave.
/// Either is only what the device on the network says, but a device that answers as one console and registers
/// as another is refused, so a link cannot replace another console's saved keys.
fn same_console(host_id: Option<&str>, registered_mac: &[u8; 6]) -> bool {
    host_id.is_some_and(|id| id.eq_ignore_ascii_case(&mac_hex(registered_mac)))
}

/// Links with the console at `host` (`docs/SERVICE.md`, step 8c), as the `link` example does.
async fn link(State(s): State<Arc<Service>>, body: Result<axum::Json<LinkRequest>, JsonRejection>) -> Response {
    // axum's own refusal quotes the value it could not read, which could be the PIN: a fixed message instead.
    let req = match body {
        Ok(axum::Json(req)) => req,
        Err(rejected) => {
            return refuse(rejected.status(), "the body is JSON: {\"host\", \"pin\"} and, optionally, \"account_id\"");
        }
    };
    let Some(pin) = pin(&req.pin) else {
        return refuse(StatusCode::BAD_REQUEST, "the PIN is the 8 digits on the console's Link Device screen");
    };
    let IpAddr::V4(ip) = req.host else {
        return refuse(StatusCode::BAD_REQUEST, "consoles are found over IPv4; give the console's IPv4 address");
    };
    if !on_home_network(ip) {
        return refuse(StatusCode::BAD_REQUEST, "a console is on the home network: give its private address");
    }
    let given = match req.account_id.as_deref().map(Identity::account_id_from_base64) {
        Some(Ok(id)) => Some(id),
        Some(Err(e)) => return refuse_owned(StatusCode::BAD_REQUEST, e.to_string()),
        None if s.psn.is_none() => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "give account_id (from the psn_account_id example), or start the service with PSN_RP_CLIENT_SECRET and sign in",
            );
        }
        None => None,
    };
    let Some(starting) = Starting::take(&s) else {
        return refuse(StatusCode::CONFLICT, "a session is starting");
    };
    let Some(found) = search(&s, ip).await.into_iter().find(|h| h.addr == req.host) else {
        return refuse(StatusCode::BAD_REQUEST, "that address did not answer discovery as a console; is it on?");
    };
    let psn = s.psn.as_ref().map(|p| (p.app_secret.clone(), p.config_dir.clone()));
    let dir = s.consoles_dir.clone();
    // Registration and the account ID lookup block for seconds: off the async runtime, holding the start slot.
    let done = tokio::task::spawn_blocking(move || {
        let _starting = starting;
        let identity = match (given, psn) {
            (Some(id), _) => id,
            (None, Some((secret, config))) => Identity::AccountId(
                psr_psn::play::account_id(&secret, &config).map_err(|e| format!("the account ID from PSN: {e}"))?,
            ),
            (None, None) => unreachable!("refused above when there is no account ID and no PSN"),
        };
        let registered = regist::register(found.addr, found.target(), &identity, pin)
            .map_err(|e| format!("linking did not work: {e}"))?;
        if !same_console(found.host_id.as_deref(), &registered.server_mac) {
            return Err("the console that registered is not the one that answered at that address; nothing was saved"
                .to_string());
        }
        store::save(&dir, &registered).map_err(|e| format!("linked, but the keys could not be saved: {e}"))?;
        Ok::<_, String>(Linked { nickname: registered.server_nickname.clone(), mac: mac_hex(&registered.server_mac) })
    })
    .await;
    match done {
        Ok(Ok(linked)) => axum::Json(linked).into_response(),
        Ok(Err(why)) => refuse_owned(StatusCode::BAD_GATEWAY, why),
        Err(_) => refuse(StatusCode::INTERNAL_SERVER_ERROR, "linking failed"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WakeRequest {
    host: IpAddr,
    console: Option<String>,
}

/// Wakes a linked console from rest mode. The datagram carries its wake-up credential, so it goes only to an
/// address that claims to be that console. The claim is unauthenticated (discovery is plain UDP), so this keeps
/// the credential from going to the wrong address by mistake; it does not stop a device on the home network that
/// lies, which could also read the datagram off the network.
async fn wake(State(s): State<Arc<Service>>, axum::Json(req): axum::Json<WakeRequest>) -> Response {
    let list = match linked(&s) {
        Ok(l) => l,
        Err(r) => return *r,
    };
    let Some(console) = pick(list, req.console.as_deref()) else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "no such linked console (name one by \"console\" when several are linked)",
        );
    };
    let IpAddr::V4(ip) = req.host else {
        return refuse(StatusCode::BAD_REQUEST, "consoles are found over IPv4; give the console's IPv4 address");
    };
    if !on_home_network(ip) {
        return refuse(StatusCode::BAD_REQUEST, "a console is on the home network: give its private address");
    }
    let Some(found) = answering_as(&s, ip, &console).await else {
        return refuse(StatusCode::BAD_REQUEST, "that address did not answer as the linked console");
    };
    if found.state != HostState::Standby {
        // Not in rest mode: awake, or a state discovery does not know, which is said as it is.
        return axum::Json(serde_json::json!({ "sent": false, "state": format!("{:?}", found.state) })).into_response();
    }
    let Some(credential) = console.wakeup_credential() else {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "the saved registration key is not a wake-up credential");
    };
    let kind = if found.is_ps5() { Console::Ps5 } else { Console::Ps4 };
    let sent = tokio::task::spawn_blocking(move || discovery::wake(found.addr, kind, credential)).await;
    match sent {
        Ok(Ok(())) => axum::Json(serde_json::json!({ "sent": true })).into_response(),
        Ok(Err(e)) => refuse_owned(StatusCode::BAD_GATEWAY, format!("the wake-up did not go out: {e}")),
        Err(_) => refuse(StatusCode::INTERNAL_SERVER_ERROR, "waking failed"),
    }
}

async fn play(State(s): State<Arc<Service>>, axum::Json(req): axum::Json<PlayRequest>) -> Response {
    let list = match linked(&s) {
        Ok(l) => l,
        Err(r) => return *r,
    };
    let Some(console) = pick(list, req.console.as_deref()) else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "no such linked console (name one by \"console\" when several are linked)",
        );
    };
    let IpAddr::V4(ip) = req.host else {
        return refuse(StatusCode::BAD_REQUEST, "consoles are found over IPv4; give the console's IPv4 address");
    };
    let Some(starting) = Starting::take(&s) else {
        return refuse(StatusCode::CONFLICT, "a session is already starting");
    };
    if s.session().as_ref().is_some_and(Handle::is_running) {
        return refuse(StatusCode::CONFLICT, "a session is already running");
    }
    // The session request carries credentials made from the console's keys, so it only goes to an address
    // where that console answers discovery as itself.
    let mac = mac_hex(&console.server_mac);
    let answered = search(&s, ip).await;
    if !answered
        .iter()
        .any(|h| h.addr == req.host && h.host_id.as_deref().is_some_and(|id| id.eq_ignore_ascii_case(&mac)))
    {
        return refuse(StatusCode::BAD_REQUEST, "that address did not answer as the linked console");
    }
    // The handshakes block for a second or two: off the async runtime.
    let started = tokio::task::spawn_blocking(move || {
        let _starting = starting;
        runner::start(req.host, &console)
    })
    .await;
    match started {
        Ok(Ok(handle)) => {
            let old = s.session().replace(handle);
            if let Some(old) = old {
                tokio::task::spawn_blocking(move || old.stop());
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(e)) => refuse_owned(StatusCode::BAD_GATEWAY, format!("the session did not start: {e}")),
        Err(_) => refuse(StatusCode::INTERNAL_SERVER_ERROR, "the session start failed"),
    }
}

const PSN_OFF: &str = "playing over PSN needs PSN_RP_CLIENT_SECRET set when the service starts";

/// Whether playing over PSN is on, and whether a sign-in is saved (`docs/SERVICE.md`, step 8d). The saved
/// sign-in is opened to see that it is there and readable; it is not sent anywhere.
async fn psn_status(State(s): State<Arc<Service>>) -> Response {
    let signed_in = match s.psn.as_ref() {
        None => false,
        Some(psn) => {
            let dir = psn.config_dir.clone();
            let saved = tokio::task::spawn_blocking(move || psr_psn::secret::load_refresh_token(&dir)).await;
            match saved {
                Ok(Ok(found)) => found.is_some(),
                Ok(Err(e)) => {
                    return refuse_owned(StatusCode::INTERNAL_SERVER_ERROR, format!("the saved sign-in: {e}"));
                }
                Err(_) => return refuse(StatusCode::INTERNAL_SERVER_ERROR, "reading the saved sign-in failed"),
            }
        }
    };
    axum::Json(serde_json::json!({ "available": s.psn.is_some(), "signed_in": signed_in })).into_response()
}

/// Sony's sign-in page, with a new client device ID, as `ps-remote signin` prints it.
async fn psn_signin_url(State(s): State<Arc<Service>>) -> Response {
    if s.psn.is_none() {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, PSN_OFF);
    }
    match psr_psn::auth::client_duid() {
        Ok(duid) => {
            let mut r = axum::Json(serde_json::json!({ "url": psr_psn::auth::login_url(&duid) })).into_response();
            r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            r
        }
        Err(e) => refuse_owned(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigninRequest {
    /// The address of Sony's redirect page, with the one-time code in it.
    redirect: String,
}

/// Trades the code in Sony's redirect address for tokens and saves the refresh token, as `ps-remote signin`
/// does. The address carries a one-time code, so it is never echoed: refusals are fixed sentences.
async fn psn_signin(State(s): State<Arc<Service>>, body: Result<axum::Json<SigninRequest>, JsonRejection>) -> Response {
    let Some(psn) = s.psn.as_ref() else {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, PSN_OFF);
    };
    // axum's own refusal quotes the value it could not read.
    let req = match body {
        Ok(axum::Json(req)) => req,
        Err(rejected) => return refuse(rejected.status(), "the body is JSON: {\"redirect\": \"<address>\"}"),
    };
    let code = match psr_psn::auth::code_from_redirect(&req.redirect) {
        Ok(code) => code,
        // Both errors are fixed sentences that do not include the address.
        Err(e) => return refuse_owned(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let Some(starting) = Starting::take(&s) else {
        return refuse(StatusCode::CONFLICT, "a session is starting");
    };
    let (secret, dir) = (psn.app_secret.clone(), psn.config_dir.clone());
    let done = tokio::task::spawn_blocking(move || {
        let _starting = starting;
        let tokens = psr_psn::auth::exchange_code(&secret, &code)?;
        psr_psn::secret::save_refresh_token(&dir, &tokens.refresh)
    })
    .await;
    match done {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => refuse_owned(StatusCode::BAD_GATEWAY, format!("signing in did not work: {e}")),
        Err(_) => refuse(StatusCode::INTERNAL_SERVER_ERROR, "signing in failed"),
    }
}

/// Forgets the saved sign-in here, as `ps-remote signout` does. It stays valid at Sony until it expires.
async fn psn_signout(State(s): State<Arc<Service>>) -> Response {
    let Some(psn) = s.psn.as_ref() else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let Some(starting) = Starting::take(&s) else {
        return refuse(StatusCode::CONFLICT, "a session is starting");
    };
    let dir = psn.config_dir.clone();
    let done = tokio::task::spawn_blocking(move || {
        let _starting = starting;
        psr_psn::secret::forget(&dir)
    })
    .await;
    match done {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => refuse_owned(StatusCode::INTERNAL_SERVER_ERROR, format!("signing out did not work: {e}")),
        Err(_) => refuse(StatusCode::INTERNAL_SERVER_ERROR, "signing out failed"),
    }
}

/// One of the PSN account's consoles, as `GET /api/psn-consoles` lists it: no device ID.
#[derive(Serialize)]
struct PsnConsoleInfo {
    name: String,
    remote_play: bool,
    /// The one `/api/play-psn` plays. The others are home network only.
    plays_over_psn: bool,
}

/// The PSN account's consoles (`docs/PSN.md`), from Sony: each call refreshes the saved sign-in, so it takes
/// the start slot, and is refused while a start runs, as a second start would be.
async fn psn_consoles(State(s): State<Arc<Service>>) -> Response {
    let Some(psn) = s.psn.as_ref() else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "playing over PSN needs PSN_RP_CLIENT_SECRET set when the service starts",
        );
    };
    let Some(starting) = Starting::take(&s) else {
        return refuse(StatusCode::CONFLICT, "a session is starting");
    };
    let (secret, dir) = (psn.app_secret.clone(), psn.config_dir.clone());
    let listed = tokio::task::spawn_blocking(move || {
        let _starting = starting;
        psr_psn::play::account_consoles(&secret, &dir)
    })
    .await;
    match listed {
        Ok(Ok(list)) => {
            let chosen = psr_psn::play::chosen(&list);
            let info: Vec<PsnConsoleInfo> = list
                .iter()
                .enumerate()
                .map(|(i, d)| PsnConsoleInfo {
                    name: psr_psn::printable(&d.name),
                    remote_play: d.remote_play,
                    plays_over_psn: chosen == Some(i),
                })
                .collect();
            axum::Json(info).into_response()
        }
        Ok(Err(e)) => refuse_owned(StatusCode::BAD_GATEWAY, format!("PSN's console list: {e}")),
        Err(_) => refuse(StatusCode::INTERNAL_SERVER_ERROR, "PSN's console list failed"),
    }
}

/// Plays the account's console from away, through PSN (`docs/PSN.md`). No body: the console is the
/// account's first with Remote Play on. Takes around 40 s.
async fn play_psn(State(s): State<Arc<Service>>) -> Response {
    let Some(psn) = s.psn.as_ref() else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "playing over PSN needs PSN_RP_CLIENT_SECRET set when the service starts",
        );
    };
    let Some(starting) = Starting::take(&s) else {
        return refuse(StatusCode::CONFLICT, "a session is already starting");
    };
    if s.session().as_ref().is_some_and(Handle::is_running) {
        return refuse(StatusCode::CONFLICT, "a session is already running");
    }
    let (secret, dir) = (psn.app_secret.clone(), psn.config_dir.clone());
    let started = tokio::task::spawn_blocking(move || {
        let _starting = starting;
        runner::start_psn(&secret, &dir)
    })
    .await;
    match started {
        Ok(Ok(handle)) => {
            let old = s.session().replace(handle);
            if let Some(old) = old {
                tokio::task::spawn_blocking(move || old.stop());
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(e)) => refuse_owned(StatusCode::BAD_GATEWAY, format!("the session did not start: {e}")),
        Err(_) => refuse(StatusCode::INTERNAL_SERVER_ERROR, "the session start failed"),
    }
}

async fn offer(State(s): State<Arc<Service>>, body: String) -> Response {
    let offer = match SdpOffer::from_sdp_string(&body) {
        Ok(o) => o,
        Err(_) => return refuse(StatusCode::BAD_REQUEST, "not an SDP offer"),
    };
    let Some(remote) = s.session().as_ref().map(Handle::remote) else {
        return refuse(StatusCode::CONFLICT, "no session is running");
    };
    let answer = tokio::task::spawn_blocking(move || remote.offer(offer)).await;
    match answer {
        Ok(Ok(a)) => {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/sdp"));
            (headers, Body::from(a.to_sdp_string())).into_response()
        }
        Ok(Err(e)) => refuse_owned(StatusCode::CONFLICT, e),
        Err(_) => refuse(StatusCode::INTERNAL_SERVER_ERROR, "the offer failed"),
    }
}

async fn stop(State(s): State<Arc<Service>>) -> Response {
    let handle = s.session().take();
    if let Some(h) = handle {
        let _ = tokio::task::spawn_blocking(move || h.stop()).await;
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn status(State(s): State<Arc<Service>>) -> Response {
    let st = s.session().as_ref().map(Handle::status);
    axum::Json(st.unwrap_or_else(Status::default)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_is_saved_only_for_the_console_that_answered() {
        let mac = [0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22];
        assert!(same_console(Some("AABBCC001122"), &mac));
        assert!(same_console(Some("aabbcc001122"), &mac));
        assert!(!same_console(Some("AABBCC001123"), &mac), "another console's MAC");
        assert!(!same_console(None, &mac), "a reply with no host-id");
        assert!(!same_console(Some(""), &mac));
    }

    #[test]
    fn only_home_network_addresses_are_searched() {
        for ok in ["192.168.1.20", "10.0.0.5", "172.16.3.4", "169.254.1.1", "127.0.0.1"] {
            assert!(on_home_network(ok.parse().unwrap()), "{ok}");
        }
        for no in ["8.8.8.8", "1.1.1.1", "255.255.255.255", "224.0.0.1", "100.64.0.1"] {
            assert!(!on_home_network(no.parse().unwrap()), "{no}");
        }
    }
}
