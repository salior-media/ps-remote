# The ps-remote service (step 8a)

> Owner, 2026-11-25: *"Merge, start next"*, then, asked how step 8 should go when the games app's play UI does not
> exist yet: **"Service first (Recommended)"**: the service, its local API and WebRTC, with a small test page the
> service serves itself. The games app's *PlayStation* tab is built later against the same API.

Step 8 of the port map is "the games app's PlayStation tab plays the PS5 at home". The tab lives in the games app's
play UI (the games scope's phase G2), which is not built. So step 8 is split:

- **8a, here:** the `ps-remote` service plays a linked console in a browser, over WebRTC, through a local API.
- **8b, later:** the PlayStation tab in the games app, using the same API.

## What runs

`ps-remote serve` starts one process with two parts:

1. **The local API**, HTTP on `127.0.0.1` only (`axum`). It lists consoles, starts and stops a session, and takes the
   browser's WebRTC offer.
2. **One session at a time**, on its own thread: the session and stream from `psr-lan`, the frames from `psr-av`,
   input through `psr-input`, and a `str0m` WebRTC peer that sends the video and audio to the browser and takes its
   input from a data channel. The input message carries buttons, triggers and sticks, and up to two touchpad
   fingers (`touches`, each `{"id", "x", "y"}` with `x` and `y` from 0 to 1); the test page makes the picture the
   touchpad, as chiaki-ng makes its stream window, and a gamepad's touchpad press is its button 17.

Nothing is decoded or re-encoded (port map §3):
- **Video:** the console's H.264 frames go into the WebRTC video track as they are. Each frame is sent with the codec
  header (SPS and PPS) in front, so a decoder can start at any keyframe.
- **Audio:** the console's Opus frames go into the WebRTC audio track as they are.

## The API

Every `/api` request needs `Authorization: Bearer <token>`, and a `Host` of `127.0.0.1:<port>` or
`localhost:<port>`. The `Host` check stops a web page from reaching the service by DNS rebinding.

The token is 32 random bytes, made at each start. The service writes it to the configuration folder
(`service-token`, readable by this user only), where the games app will read it. It prints the test page's link
with the token in the fragment (`http://127.0.0.1:<port>/#token=...`): browsers never send a fragment, and the page
takes it off the address bar once read. The page itself holds no token, because any local process can fetch it.

| route | does |
|---|---|
| `GET /` | the test page: a video element, and a gamepad sent as input |
| `GET /api/consoles` | the linked consoles (the saved registrations), without keys |
| `GET /api/psn-consoles` | the PSN account's consoles from Sony (name, Remote Play on or off, and which one `/api/play-psn` plays; the others are home network only). No device IDs. Each call refreshes the saved sign-in, so it takes the start slot (409 while a start runs); 503 without `PSN_RP_CLIENT_SECRET` |
| `POST /api/play` | `{"host": "<console IPv4>"}` starts a session with the linked console there, once that address answers discovery as that console. One session, and one start, at a time |
| `POST /api/play-psn` | No body. Plays the PSN account's first console with Remote Play on, from away, through Sony's servers and two punched holes (`docs/PSN.md`, 9c-3b); around 30 to 40 s. Needs `PSN_RP_CLIENT_SECRET` in the service's environment when it starts (kept in memory only) and a saved sign-in (`ps-remote signin`); otherwise 503. Same one-at-a-time rules as `/api/play`; the browser then connects with `/api/offer` as for a home session |
| `POST /api/link` | `{"host": "<console IPv4>", "pin": "<8 digits>"}`, with `"account_id"` (base64, as the `psn_account_id` example prints it) unless the service has PSN on and a saved sign-in, in which case it asks Sony. Links with the console that answers discovery there, with the PIN from its *Link Device* screen, and saves its keys as the `link` example does. Answers the console's nickname and MAC, never its keys. Takes the start slot (409 while a start runs) |
| `POST /api/wake` | `{"host": "<console IPv4>"}` (and `"console"` when several are linked) wakes the linked console there from rest mode, once that address answers discovery as that console (a private address only). Answers `{"sent": true}` when it sent one, and `{"sent": false, "state": …}` when the console was not in rest mode |
| `GET /api/psn-status` | `{"available", "signed_in"}`: whether playing over PSN is on (the app secret was set when the service started) and whether a PSN sign-in is saved. It reads only whether the saved sign-in is there and opens, and never sends it anywhere |
| `GET /api/psn-signin-url` | `{"url"}`: Sony's sign-in page for the Remote Play app, with a new client device ID, as `ps-remote signin` prints it. 503 without the app secret |
| `POST /api/psn-signin` | `{"redirect": "<the address of Sony's redirect page>"}` trades the one-time code in it for tokens and saves the refresh token, as `ps-remote signin` does. Only Sony's redirect page is accepted, the address is never echoed, and nothing is answered but 204 or the reason. Takes the start slot (409 while a start runs) |
| `POST /api/psn-signout` | forgets the saved sign-in on this machine, as `ps-remote signout` does (it stays valid at Sony until it expires) |
| `POST /api/offer` | the browser's SDP offer, answered with the service's SDP answer |
| `POST /api/stop` | ends the session |
| `GET /api/status` | whether a session runs, its frame, loss and drop counts, and `bitrate_kbps`: the video and audio received over the last second. The console-to-service delay is not reported: chiaki-ng's way to measure it (Senkusha) is compiled there but never switched on, as no build defines `ENABLE_SENKUSHA`. The test page shows the browser's share instead, from WebRTC's own counters: the browser-to-service round trip, and per frame the time buffered, decoding, and from received to shown |

**Input** on the data channel `input` is a JSON object per change: `buttons` (psr-input's bits), `l2` and `r2`
(0 to 255), and `lx`, `ly`, `rx` and `ry` (−32768 to 32767). The service checks each field's range and drops a message
that fails, and it never panics on one.

**A picture lost in the browser** (a WebRTC PLI or FIR) becomes the console's IDR request.

## Linking and waking (step 8c)

> Owner, 2026-11-26, after the PlayStation tab played in their browser (*"iitt   work"*), asked what was left and
> offered *link and wake from the tab* first: *"okay lets contuine"*.

The play-anywhere scope's PlayStation tab *"lists consoles, links them, wakes them, plays"*. Until now linking was
the `link` example and waking had no route. Two routes add them, built from the same parts the examples use:

- **`/api/link`** runs `psr_lan::regist::register` against the console that answers discovery at the given address,
  then `psr_lan::store::save`. The PSN account ID comes from the request, or from Sony using the saved sign-in
  (`psr_psn::auth::account_id`, chiaki-ng's `scripts/psn-account-id.py`). The PIN is checked to be 8 digits and is
  never logged or echoed.
- **`/api/wake`** sends chiaki-ng's `WAKEUP` datagram (`psr_lan::discovery::wake`) only to a private address that
  answered discovery as that linked console, in rest mode, because the datagram carries the console's wake-up
  credential. Discovery is unauthenticated UDP, so this check stops a mistake, not a liar: a device on the home
  network that claims the console's ID gets the datagram, and anything that can watch the network can read it, as
  with chiaki-ng. Play has the same limit.
- **Linking saves only the console that answered.** The MAC in the registration reply must be the `host-id` the
  address gave in discovery, so a device cannot answer as one console and replace another console's keys.

game-play forwards both, and its PlayStation tab gets *Link a console* (address and PIN) and *Wake* controls.

**Done when:** the routes' checks are tested (token, Host, PIN shape, IPv4 only, unknown fields, an address that does
not answer as a console, no account ID without PSN), and live, the household PS5 wakes from rest mode from the tab.
Linking live needs the console's *Link Device* screen open; it re-links the same console, which replaces its saved keys.

**Review, 2026-11-26:** a security review found no critical or high issues. Its two mediums are fixed (linking
saves only the console that answered; the wake docs no longer claim more than an unauthenticated check gives), and
so are three lows: private addresses only, no echo of a malformed body, and the state said when nothing is sent.
Left as they are: a save can fail if `/api/consoles` holds the file open at that moment (the reply says the keys
were not saved), the consoles folder fails closed on a bad file, and nothing on this side limits PIN attempts (the
console does). No test has a fake console answering registration, so linking's success path is tested live only.

**Live, 2026-11-26, through game-play:** the household PS5 was in rest mode; `/api/wake` answered `{"sent": true}`
and the console answered discovery as ready about 10 to 12 s later (done twice). Waking it while awake answered
`{"sent": false, "state": "Ready"}`. A wake to another address, to an internet address, and a link with a malformed
PIN were refused. Linking itself was not run live: it needs the *Link Device* screen open.

## PSN sign-in through the API (step 8d)

> Owner, 2026-11-26, after linking and waking merged: *"lleets conuine then"*. PSN sign-in from the tab was next on
> the list of what is left.

Signing in was `ps-remote signin` in a terminal. Four routes put it behind the API, built from the same parts
(`psr_psn::auth::login_url`, `code_from_redirect`, `exchange_code`, `psr_psn::secret`):

- The person still signs in **on Sony's own page**, in their own browser; ps-remote never sees the password. Sony
  then shows its redirect page, whose address carries a one-time code, and the person pastes that address back.
  There is no way round the paste: Sony sends the Remote Play app's sign-in only to its own redirect page.
- The pasted address is checked to be exactly that page before its code is read, and is never echoed back or kept.
  Only the refresh token is saved, as before (encrypted with DPAPI on Windows); no token is ever answered.
- Signing in takes the start slot, so it cannot race a PSN start or console list over which refresh token is
  current.

game-play forwards all four, and its PlayStation tab shows a *Sign in to PSN* box when playing over PSN is on and no
sign-in is saved, with *Sign out* once one is.

**Done when:** the routes' checks are tested (token, Host, 503 without the app secret, an address that is not Sony's
redirect page refused without being echoed, no code, the status before and after a saved sign-in, sign-out), and
live, the owner signs in from the tab and the PSN console list answers.

## Why each choice

- **Loopback only, with a token:** the API can start a session with the household's console, so nothing but this
  machine may reach it, and on this machine only a client that can read the token file (or was given the printed
  link) may. A web page in the same browser can't: it can't read the service's responses (no CORS headers), and the
  `Authorization` header needs a preflight the service never grants.
- **Play only where the console answers as itself:** the session request carries credentials made from the console's
  keys, so it goes only to an address that answers discovery with the linked console's ID.
- **The network can't end a session:** anyone on the LAN can send to the media port. A datagram that is too big,
  unreadable, or refused by str0m is dropped and counted; only the browser's own peer state ends its side. (Joining a
  session as the peer needs the ICE credentials and DTLS fingerprint from the loopback offer and answer.)
- **A panic in the session thread still ends the console's stream** and marks the session stopped, so the console is
  never left holding a session the API thinks is gone.

The 2026-11-25 security review of the first commit found the token in the served page, junk datagrams ending a
session, play sending credentials to any address, loose file modes on Unix, an audio clock overflow, and concurrent
starts. Each is fixed above, with a test.
- **WebRTC media on the LAN address, not loopback:** Firefox refuses 127.0.0.1 candidates (str0m's own example says so).
  The UDP port is chosen at random for each session.
- **str0m with its `rust-crypto` backend:** no OpenSSL. It is not pure Rust, as this said at first (corrected
  2026-11-25): str0m's DTLS certificate is made by `rcgen` on aws-lc, a C library, through `dimpl`'s `rcgen`
  feature, which str0m does not let a user turn off. str0m 0.25.0 (2026-11-03) is pinned: 0.26.0 was less than two
  weeks old (port map §2's version note).
- **Audio without chiaki-ng's jitter buffer:** chiaki-ng buffers audio for its own player. A WebRTC receiver has its
  own jitter buffer, so the service sends each Opus frame once, as soon as it arrives, numbered by its frame index.

## Done when

- A browser on this PC opens the test page, starts the session, and plays the PS5: it shows the picture, plays the
  sound, and a gamepad's buttons move the game.
- The API refuses a request with no token, with a wrong token, and with a wrong `Host`.
- An automated test runs the WebRTC side against a str0m peer standing in for the browser: frames arrive whole, input
  comes back, and a picture loss asks for a keyframe. (The console side has its own fake-console tests in `psr-lan`;
  joining the two fakes in one test would need them in a shared test crate, which is not worth it yet.)
- The `client` example does what the test page does without a browser, against the real console.
