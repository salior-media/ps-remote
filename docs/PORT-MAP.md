# Port map: chiaki-ng's `lib/` to ps-remote's Rust crates

**Phase:** P1a of the games scope (`salior-media/games`, `docs/SCOPE-play-anywhere-2026-11-24.md` §7.2) · **Read:**
2026-11-24, from `chiaki-ng/chiaki-ng` on `main` (last pushed 2026-11-14) · **Owner:** *"we are just making our own
more flexabl;e version of that. and using it with our game app as another tav"*

Every fact below was read from chiaki-ng's source on that date. Where a choice is mine, it says so.

## 1. What chiaki-ng is built on

| need | chiaki-ng uses | file |
|---|---|---|
| key exchange | ECDH on **secp256k1**, with the handshake signed by **HMAC-SHA256** | `lib/src/ecdh.c` |
| stream encryption | **AES-128-GCM**, plus a keystream made with **AES-ECB**, and **SHA-256** for key derivation | `lib/src/gkcrypt.c` |
| registration encryption | **AES-128-CFB128**, with **HMAC** | `lib/src/rpcrypt.c` |
| loss correction | **Jerasure**: Cauchy Reed-Solomon (`cauchy_original_coding_matrix`), word size **8**, over gf-complete | `lib/src/fec.c`, `third-party/jerasure`, `third-party/gf-complete` |
| stream messages | **protobuf** (nanopb), with one schema: `lib/protobuf/takion.proto` (`TakionMessage` and about 30 payloads, including `ControllerConnectionPayload`, `CorruptFramePayload` and `BitratePayload`) | `lib/protobuf/` |
| video | **H.264, H.265 and H.265 HDR** (`ChiakiCodec`), decoded by FFmpeg or the Pi decoder | `lib/include/chiaki/common.h`, `ffmpegdecoder.c` |
| audio | **Opus** in, and Opus out for the microphone | `opusdecoder.c`, `opusencoder.c` |
| PSN and HTTP | curl, and json-c | `lib/CMakeLists.txt`, `remote/holepunch.c` |
| crypto backend | OpenSSL, or mbedTLS as a build option | `lib/CMakeLists.txt` |

**Tests chiaki-ng already has** (`test/`): `fec.c` (with `fec_test_cases.inl`), `gkcrypt.c`, `rpcrypt.c`, `regist.c`,
`takion.c` (with `takion_av_packet_parse_real_video.inl`, real captured video packets), `reorderqueue.c`, `seqnum.c`,
`bitstream.c`, `feedback.c`, `keystate.c`, `http.c`. **Their vectors are ported first**, so each Rust module starts from
a failing test with known-good answers.

## 2. The Rust crates

The layout below is my choice. Each crate is small and testable alone, and only the last one does I/O to the outside
world.

| crate | ports | Rust building blocks (crates.io, 2026-11-24) | notes |
|---|---|---|---|
| `psr-crypto` | `ecdh`, `gkcrypt`, `rpcrypt`, `random`, `base64` | `k256` 0.14 (ECDH), `hmac` + `sha2`, `aes` + `aes-gcm` 0.11, `cfb-mode` 0.9 | pure Rust, no OpenSSL. So the OpenSSL exception never applies here |
| `psr-fec` | `fec` | **written ourselves**: GF(2⁸) tables and the Cauchy original matrix | general Reed-Solomon crates build a different matrix. The console encodes with Jerasure's Cauchy matrix, so ours must match it byte for byte. `fec_test_cases.inl` proves it does |
| `psr-proto` | `takion.proto`, `pb_utils` | `prost` 0.14 | `takion.proto` is copied in, with its AGPL header and credit |
| `psr-takion` | `takion`, `takionsendbuffer`, `reorderqueue`, `seqnum`, `streamconnection`, `congestioncontrol`, `packetstats`, `senkusha` | `tokio` UDP | the stream transport; `senkusha` is the network test before streaming |
| `psr-lan` | `discovery`, `discoveryservice`, `regist`, `session`, `ctrl`, `http`, `launchspec` | `tokio` TCP and UDP, `httparse`, `serde_json` | finding, waking, the *Link Device* PIN, and session start, all on the home network |
| `psr-av` | `videoreceiver`, `frameprocessor`, `bitstream`, `audioreceiver` | — | rebuilds whole video frames and audio packets. **No decoding** (§3) |
| `psr-input` | `controller`, `orientation`, `feedback`, `feedbacksender` | — | controller state, with several slots (games scope §9.1); rumble back |
| `psr-psn` | `remote/holepunch`, `remote/rudp`, `remote/stun.h`, and the PSN sign-in from `scripts/psn-account-id.*` | `reqwest` (rustls), `tokio-tungstenite` 0.30, `serde_json` | Sony's "Remote Play over Internet", main console only. Sign-in uses Sony's own page in the browser; the refresh token is stored encrypted, never the password |
| `ps-remote` | the front ends (`cli`, `gui`), rewritten | `axum` (local API, loopback and a token), `str0m` (WebRTC), `service-manager` 0.11 | the service, its commands, and its WebRTC output to the games app and `game-watch` |

**Version note:** `str0m` 0.26.0 came out on 2026-11-22. Pin a release at least two weeks old when the crate is first
added.

## 3. Where ps-remote is more flexible than chiaki-ng

1. **No decode and re-encode for the browser.** chiaki-ng decodes video to show it in its own window. ps-remote's job is
   to forward it to a browser over WebRTC. WebRTC carries **H.264** and **Opus** as they are, so ps-remote can pass the
   console's own H.264 frames and Opus packets straight into WebRTC tracks, unchanged. That costs no GPU, adds no
   encoding delay and loses no quality.
   - **To prove:** the session is asked for **H.264**, since browser support for H.265 varies.
   - **To prove:** a browser's "picture lost" request (PLI) is turned into the console's own request for a new
     keyframe, through `CorruptFramePayload` or the equivalent in `takion.proto`.
2. **Several controllers.** `takion.proto` has a `ControllerConnectionPayload`. Whether the PS5 takes a second Remote
   Play controller is P0's question 2. If it does, `psr-input` sends each slot's state.
3. **A service, not a window.** Everything chiaki-ng's GUI does is a command on the local API instead: `consoles`,
   `link`, `signin`, `wake`, `play`, `input`, `stop`, `status`.

## 4. Order of work

Each step starts from the ported chiaki-ng tests, failing, and ends with them passing.

| # | step | done when |
|---|---|---|
| 1 | `psr-crypto` | `gkcrypt`, `rpcrypt` and the ECDH test vectors pass |
| 2 | `psr-fec` | every case in `fec_test_cases.inl` passes |
| 3 | `psr-proto` and `psr-takion` | `takion`, `reorderqueue` and `seqnum` tests pass, and the real captured video packets parse |
| 4 | `psr-lan`: discovery and wake | finds and wakes the household PS5 (needs the console) |
| 5 | `psr-lan`: registration | links with the PS5 using its PIN; the `regist` test passes |
| 6 | `psr-lan` session, `psr-av` | a session starts, and whole H.264 frames arrive. The capture-card test (games scope §7.2) compares them with the TV |
| 7 | `psr-input` | `feedback` and `keystate` tests pass; buttons move the game |
| 8 | `ps-remote` service and WebRTC | the games app's PlayStation tab plays the PS5 at home |
| 9 | `psr-psn` | the same works from away, through PSN, with no home PC |

Steps 1–3 need no console and can start now. Steps 4–9 need the household PS5.

## 5. Licence rules for the port

- Every Rust file ported from a chiaki-ng file says so in its header, naming that file, and carries
  `SPDX-License-Identifier: AGPL-3.0-only`.
- Code taken from a file marked `LicenseRef-AGPL-3.0-only-OpenSSL` keeps that exception. Since `psr-crypto` uses pure
  Rust and no OpenSSL, the exception doesn't matter in practice.
- Ported test vectors keep their origin in a comment.
- The games app never links these crates. It talks to the `ps-remote` service through its API.
