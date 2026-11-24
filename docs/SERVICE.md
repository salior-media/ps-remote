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
   input from a data channel.

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
| `POST /api/play` | `{"host": "<console IPv4>"}` starts a session with the linked console there, once that address answers discovery as that console. One session, and one start, at a time |
| `POST /api/offer` | the browser's SDP offer, answered with the service's SDP answer |
| `POST /api/stop` | ends the session |
| `GET /api/status` | whether a session runs, and its frame, loss and drop counts |

**Input** on the data channel `input` is a JSON object per change: `buttons` (psr-input's bits), `l2` and `r2`
(0 to 255), and `lx`, `ly`, `rx` and `ry` (−32768 to 32767). The service checks each field's range and drops a message
that fails, and it never panics on one.

**A picture lost in the browser** (a WebRTC PLI or FIR) becomes the console's IDR request.

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
- **str0m with its `rust-crypto` backend:** pure Rust, like `psr-crypto`, so there is no OpenSSL or C toolchain.
  str0m 0.25.0 (2026-11-03) is pinned: 0.26.0 is less than two weeks old (port map §2's version note).
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
