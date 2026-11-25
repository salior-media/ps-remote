// SPDX-License-Identifier: AGPL-3.0-only
//! Playing from away, start to stream, in one call: everything step 9 built, in chiaki-ng's order. From the
//! saved sign-in: Sony's push websocket and a remote-play session; the account's console woken and joined;
//! the control hole; registration, the session and ctrl through it; the data hole, with ctrl answered on a
//! thread meanwhile; and the stream on it.
//!
//! The push websocket and Sony's session are kept for as long as the stream plays, on a thread of their own
//! that keeps reading the websocket (so Sony's pings are answered); [`Playing`] leaves Sony's session when it
//! is dropped, whatever ended it, so none is left behind. Before that point, a failure leaves it at once.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use psr_crypto::Target;
use psr_lan::ctrl::CtrlEvent;
use psr_lan::session::Session;
use psr_lan::stream::{Stream, VideoProfile};

use crate::punch::{Port, Puncher};
use crate::rudp::Rudp;
use crate::{PsnError, auth, devices, holepunch, push, regist, rps, secret, session};

/// How often the push websocket is read while the stream plays.
const KEEP_READ: Duration = Duration::from_millis(500);
/// How often ctrl is polled on its thread while the data hole is punched.
const CTRL_POLL: Duration = Duration::from_millis(200);

/// Each step's name as it completes (no addresses, IDs or keys), for whoever shows progress.
pub type Progress = fn(&'static str);

/// A stream from away, with its ctrl, and Sony's session kept until this is dropped.
pub struct Playing {
    pub ctrl: Session,
    pub stream: Stream,
    /// Our local address on the network the holes go out of: where a browser on this machine can be sent media.
    pub local_ip: Ipv4Addr,
    /// The console's name, as Sony lists it, made printable.
    pub console_name: String,
    /// Ctrl messages that came while the stream started.
    pub ctrl_events: Vec<CtrlEvent>,
    keeper: Keeper,
}

impl std::fmt::Debug for Playing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Playing").field("ctrl", &self.ctrl).finish_non_exhaustive()
    }
}

impl Playing {
    /// Ends the stream, then leaves Sony's session.
    pub fn end(self) {
        let Playing { stream, keeper, .. } = self;
        let _ = stream.disconnect();
        drop(keeper);
    }

    /// Ctrl, the stream and what leaves Sony's session, for a caller that runs them itself. Drop the
    /// [`Leaver`] after the stream has ended.
    pub fn into_parts(self) -> (Session, Stream, Leaver) {
        (self.ctrl, self.stream, Leaver(self.keeper))
    }
}

/// Leaves Sony's session (and closes the push websocket) when dropped.
pub struct Leaver(#[allow(dead_code, reason = "held only to be dropped, which leaves the session")] Keeper);

impl std::fmt::Debug for Leaver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Leaver").finish_non_exhaustive()
    }
}

/// Keeps the push websocket read until dropped, then leaves Sony's session and closes the websocket.
struct Keeper {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// What leaving Sony's session takes: the session, and a sign-in that may need refreshing by then.
struct Leave {
    session_id: String,
    access: String,
    refresh: String,
    app_secret: String,
    config_dir: PathBuf,
}

impl Leave {
    /// Leaves Sony's session. The access token may have expired while the stream played (the security review
    /// of 9c-3b), so a refused leave is tried once more with a fresh one. Failures are only reported: the
    /// session then ends at Sony when it times out.
    fn leave(&self) {
        if rps::leave(&self.access, &self.session_id).is_ok() {
            return;
        }
        let fresh = match auth::refresh(&self.app_secret, &self.refresh) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("ps-remote: Sony's session was not left ({e}); it ends when Sony times it out");
                return;
            }
        };
        if fresh.refresh != self.refresh {
            keep_refresh_token(&self.config_dir, &fresh.refresh);
        }
        if let Err(e) = rps::leave(&fresh.access, &self.session_id) {
            eprintln!("ps-remote: Sony's session was not left ({e}); it ends when Sony times it out");
        }
    }
}

/// Owned by the keeper thread: however the thread ends, a panic included, or if it never starts, Sony's session
/// is left and the websocket closed when this is dropped.
struct LeaveOnDrop {
    ws: Option<push::Push>,
    leave: Leave,
}

impl Drop for LeaveOnDrop {
    fn drop(&mut self) {
        self.leave.leave();
        if let Some(ws) = self.ws.take() {
            ws.close();
        }
    }
}

impl Keeper {
    fn start(ws: push::Push, leave: Leave) -> Result<Self, PsnError> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let mut guard = LeaveOnDrop { ws: Some(ws), leave };
        // If the thread cannot be made, the closure, and the guard in it, is dropped here: the session is
        // still left.
        let thread = std::thread::Builder::new()
            .name("ps-remote psn keeper".into())
            .spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    // Notifications are not needed once the holes are up; reading answers Sony's pings. A failure
                    // ends the reading only: the stream does not depend on the websocket.
                    let Some(ws) = guard.ws.as_mut() else { break };
                    if ws.next(Instant::now() + KEEP_READ).is_err() {
                        while !flag.load(Ordering::Relaxed) {
                            std::thread::sleep(KEEP_READ);
                        }
                        break;
                    }
                }
                drop(guard);
            })
            .map_err(|e| PsnError::Network(format!("could not start the push keeper: {e}")))?;
        Ok(Keeper { stop, thread: Some(thread) })
    }
}

/// Saves a refresh token Sony rotated. A failure is reported, not fatal: what is in hand still works for this
/// session (the security review of 9c-3b), and the next sign-in will need `ps-remote signin` only if Sony has
/// retired the one saved.
fn keep_refresh_token(config_dir: &Path, refresh: &str) {
    if let Err(e) = secret::save_refresh_token(config_dir, refresh) {
        eprintln!(
            "ps-remote: the renewed PSN sign-in could not be saved ({e}); if a later start is refused, run `ps-remote signin`"
        );
    }
}

impl Drop for Keeper {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The access token from the saved sign-in in `config_dir`, keeping the refresh token Sony hands back.
fn sign_in(app_secret: &str, config_dir: &Path) -> Result<auth::Tokens, PsnError> {
    let refresh = secret::load_refresh_token(config_dir)?
        .ok_or(PsnError::MissingField("a saved PSN sign-in (run `ps-remote signin`)"))?;
    let tokens = auth::refresh(app_secret, &refresh)?;
    if tokens.refresh != refresh {
        keep_refresh_token(config_dir, &tokens.refresh);
    }
    Ok(tokens)
}

/// Which of the account's consoles playing from away uses: the first with Remote Play on, as chiaki-ng's
/// holepunch does. The others are home network only.
pub fn chosen(devices: &[devices::Device]) -> Option<usize> {
    devices.iter().position(|d| d.remote_play)
}

/// The account's consoles, from the saved sign-in.
pub fn account_consoles(app_secret: &str, config_dir: &Path) -> Result<Vec<devices::Device>, PsnError> {
    devices::list(&sign_in(app_secret, config_dir)?.access)
}

/// Signs in with the saved refresh token in `config_dir` (keeping the new one Sony hands back), and plays the
/// account's first console with Remote Play on.
pub fn connect(
    app_secret: &str,
    config_dir: &Path,
    profile: &VideoProfile,
    progress: Progress,
) -> Result<Playing, PsnError> {
    let tokens = sign_in(app_secret, config_dir)?;
    let mut list = devices::list(&tokens.access)?;
    let i = chosen(&list).ok_or(PsnError::MissingField("a console with Remote Play on"))?;
    let device = list.swap_remove(i);
    let duid: [u8; 32] = device.duid.as_slice().try_into().map_err(|_| PsnError::BadField("deviceUniqueId"))?;
    let console_name = crate::printable(&device.name);

    let fqdn = push::fqdn(&tokens.access)?;
    let mut ws = push::Push::connect(&fqdn, &tokens.access)?;
    progress("push websocket open");
    let rps_session = rps::create(&tokens.access, &mut ws)?;
    progress("session created");
    match through_the_holes(&tokens.access, &rps_session, &duid, &mut ws, profile, progress) {
        Ok((ctrl, stream, local_ip, ctrl_events)) => {
            let leave = Leave {
                session_id: rps_session.created.session_id.clone(),
                access: tokens.access,
                refresh: tokens.refresh,
                app_secret: app_secret.to_string(),
                config_dir: config_dir.to_path_buf(),
            };
            match Keeper::start(ws, leave) {
                Ok(keeper) => Ok(Playing { ctrl, stream, local_ip, console_name, ctrl_events, keeper }),
                Err(e) => {
                    let _ = stream.disconnect();
                    Err(e)
                }
            }
        }
        Err(e) => {
            // Leave whatever happened, so no session is left behind at Sony.
            let _ = rps::leave(&tokens.access, &rps_session.created.session_id);
            ws.close();
            Err(e)
        }
    }
}

type Through = (Session, Stream, Ipv4Addr, Vec<CtrlEvent>);

fn through_the_holes(
    access: &str,
    rps_session: &rps::Session,
    duid: &[u8; 32],
    ws: &mut push::Push,
    profile: &VideoProfile,
    progress: Progress,
) -> Result<Through, PsnError> {
    let started = holepunch::start(access, &rps_session.created, duid, ws)?;
    progress("the console joined");
    let mut puncher = Puncher::new(access, &rps_session.created, duid)?;
    let hole = puncher.punch(ws, Port::Ctrl)?;
    progress("control hole punched");
    let (local_ip, console) = (hole.local_ip, hole.console);
    let mut rudp = Rudp::new(hole.socket)?;
    let done = regist::register(&mut rudp, Target::Ps5V1, rps_session.created.account_id, &started, local_ip)?;
    progress("registered through the hole");
    let did = psr_lan::session::did(&holepunch::random_bytes()?);
    let mut ctrl = session::start(rudp, console, &done.host, profile.codec, &did)?;
    progress("ctrl up");
    let stop = AtomicBool::new(false);
    let (data, polled) = std::thread::scope(|scope| {
        let poller = scope.spawn(|| -> Result<(), PsnError> {
            while !stop.load(Ordering::Relaxed) {
                ctrl.poll(CTRL_POLL).map_err(PsnError::Lan)?;
            }
            Ok(())
        });
        // Set however the punch ends, a panic included, so the scope's wait for the poller always ends.
        let stopper = StopOnDrop(&stop);
        let data = puncher.punch(ws, Port::Data);
        drop(stopper);
        (data, poller.join())
    });
    polled.map_err(|_| PsnError::Rudp("the ctrl thread panicked"))??;
    let data = data?;
    progress("data hole punched");
    let (stream, events) = session::open_stream(&mut ctrl, data, profile)?;
    progress("stream connected");
    Ok((ctrl, stream, local_ip, events))
}

/// Sets its flag when dropped.
struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}
