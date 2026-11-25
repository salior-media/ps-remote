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
use std::path::Path;
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

impl Keeper {
    fn start(mut ws: push::Push, access_token: String, session_id: String) -> Result<Self, PsnError> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("ps-remote psn keeper".into())
            .spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    // Notifications are not needed once the holes are up; reading answers Sony's pings. A failure
                    // ends the reading only: the stream does not depend on the websocket.
                    if ws.next(Instant::now() + KEEP_READ).is_err() {
                        while !flag.load(Ordering::Relaxed) {
                            std::thread::sleep(KEEP_READ);
                        }
                        break;
                    }
                }
                let _ = rps::leave(&access_token, &session_id);
                ws.close();
            })
            .map_err(|e| PsnError::Network(format!("could not start the push keeper: {e}")))?;
        Ok(Keeper { stop, thread: Some(thread) })
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

/// Signs in with the saved refresh token in `config_dir` (keeping the new one Sony hands back), and plays the
/// account's first console with Remote Play on.
pub fn connect(
    app_secret: &str,
    config_dir: &Path,
    profile: &VideoProfile,
    progress: Progress,
) -> Result<Playing, PsnError> {
    let refresh = secret::load_refresh_token(config_dir)?
        .ok_or(PsnError::MissingField("a saved PSN sign-in (run `ps-remote signin`)"))?;
    let tokens = auth::refresh(app_secret, &refresh)?;
    if tokens.refresh != refresh {
        secret::save_refresh_token(config_dir, &tokens.refresh)?;
    }
    let list = devices::list(&tokens.access)?;
    let device =
        list.into_iter().find(|d| d.remote_play).ok_or(PsnError::MissingField("a console with Remote Play on"))?;
    let duid: [u8; 32] = device.duid.as_slice().try_into().map_err(|_| PsnError::BadField("deviceUniqueId"))?;
    let console_name = crate::printable(&device.name);

    let fqdn = push::fqdn(&tokens.access)?;
    let mut ws = push::Push::connect(&fqdn, &tokens.access)?;
    progress("push websocket open");
    let rps_session = rps::create(&tokens.access, &mut ws)?;
    progress("session created");
    match through_the_holes(&tokens.access, &rps_session, &duid, &mut ws, profile, progress) {
        Ok((ctrl, stream, local_ip, ctrl_events)) => {
            let keeper = Keeper::start(ws, tokens.access, rps_session.created.session_id.clone())?;
            Ok(Playing { ctrl, stream, local_ip, console_name, ctrl_events, keeper })
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
        let data = puncher.punch(ws, Port::Data);
        stop.store(true, Ordering::Relaxed);
        (data, poller.join())
    });
    polled.map_err(|_| PsnError::Rudp("the ctrl thread panicked"))??;
    let data = data?;
    progress("data hole punched");
    let (stream, events) = session::open_stream(&mut ctrl, data, profile)?;
    progress("stream connected");
    Ok((ctrl, stream, local_ip, events))
}
