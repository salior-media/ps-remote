# Playing from away, through PSN (step 9)

> Owner, 2026-11-25: *"Start step 9"*. The games scope (§7.2) asks for the same play as at home, *"from away through
> PSN with no home PC. The account's main console works; others are shown as home network only."*

chiaki-ng reaches a console away from home in its `lib/src/remote/` (read at `43728af`): `holepunch.c` (6,348 lines),
`rudp.c` and `rudpsendbuffer.c` (1,002), and `stun.h` (643). The sign-in lives in its GUI (`gui/src/psntoken.cpp`,
`gui/include/psnaccountid.h`). Step 9 follows chiaki-ng's own split, in three parts, each verified against the
household's account and PS5 before the next:

| part | ports | done when |
|---|---|---|
| **9a, sign-in and devices** | the PSN sign-in and token refresh (`psntoken.cpp`), and `chiaki_holepunch_list_devices` | `ps-remote signin` signs in on Sony's page, keeps only the refresh token (encrypted), and `ps-remote psn-consoles` lists the account's PS5 with Remote Play on |
| **9b, the holepunch** | `holepunch.c`'s session: the session manager, its push notifications over a websocket, STUN, and the candidate exchange | a hole is punched to the PS5 from a network other than its own |
| **9c, the transport** | `rudp.c`, `rudpsendbuffer.c`, and the session and stream over them | the PS5 plays from away in the test page, as at home |

## 9a in detail

**Sign-in** works as the linking step's account-ID example already does:
1. The user signs in on **Sony's own page**, in their own browser, so ps-remote never sees the password.
2. Sony sends the browser to `https://remoteplay.dl.playstation.net/remoteplay/redirect?code=...`.
3. The user pastes that address into `ps-remote signin`. The code is single-use and short-lived.
4. ps-remote trades it at `auth.api.sonyentertainmentnetwork.com/2.0/oauth/token` for an access token and a refresh
   token.

The scopes are chiaki-ng's: `psn:clientapp referenceDataService:countryConfig.read
pushNotification:webSocket.desktop.connect sessionManager:remotePlaySession.system.update`.

The client ID and secret are the ones Sony's Remote Play app for Windows uses, and chiaki-ng uses them too. They
identify the app, not the user. As with the account-ID example, the secret is not kept in this repository: it is
read from `PSN_RP_CLIENT_SECRET`.

**Only the refresh token is kept** (scope §7.2, *"keeps only the refresh token, and never stores the password"*):
- **On Windows** it is encrypted with DPAPI (`CryptProtectData`, tied to the Windows user), then written owner-only
  to `psn-refresh-token` in the configuration folder.
- **On Linux and macOS** there is no OS keystore in reach without a desktop session, so it is written owner-only
  (0600). This is weaker, and the gap is named rather than hidden.

An access token lives in memory only, and is made from the refresh token when needed.

What the encryption does and doesn't do: DPAPI ties the sealed token to this Windows user, so other users, a copy
on another machine, and backups can't open it. Any program running as the same user can, and the fixed entropy
ps-remote adds is no boundary against that, since it's in this public source. The file is replaced whole on each
save (written to a temporary file, then renamed over), so a crash mid-save can't lose the sign-in.

`ps-remote signout` deletes the saved sign-in on this machine but does not revoke it at Sony. To cut it off at
once, remove the app's access in the PSN account's security settings.

Like chiaki-ng, the sign-in has no `state` value, so whoever pastes a redirect address is signed in to that
address's account. A paste of someone else's address would only list their consoles. The person pastes their own,
so this is accepted, and named here.

**Devices** come from `web.np.playstation.com/api/cloudAssistedNavigation/v2/users/me/clients?platform=PS5`, with
the access token. Each client has a `duid` (hex), a `device.name`, and `device.enabledFeatures`, which lists
`remotePlay` when it is on. As in chiaki-ng, only PS5s are listed.

**Every request has a timeout** (chiaki-ng uses 5 s), goes over HTTPS only, and follows no redirect. A redirect
could send a request carrying a token on to another address. The HTTP client is `ureq` over rustls, as in
`psr-lan`'s examples. The port map named `reqwest`; `ureq` is the blocking client the rest of this code already uses.

**Staying unbanned** (scope §7.2): only the endpoints Sony's app calls for the same thing, only when a person asks,
and nothing polled in the background.

## Found while verifying 9a (2026-11-25)

The first sign-in on the household's account was granted `psn:clientapp` only. Every later refresh asking for the
four scopes was then refused: `invalid_scope`, Sony's code 4153.
- **The cause:** the printed sign-in address had spaces between the scopes. An address copied from a terminal stops
  at its first space, and chiaki-ng never meets this because it opens the address in its own web view.
- **The diagnosis:** a refresh asking for `psn:clientapp` alone succeeded and reported that single granted scope.
- **The fix:** the address is printed with `%20`.
- **The check:** after signing in again, the console list works, and so does a second refresh from the saved token.

Request bodies send spaces as `%20`, closest to chiaki-ng's plain spaces. This was changed during the diagnosis,
before the real cause was found; whether Sony also accepts `+` was not tested.

## 9b in detail

9b is split in two, because `holepunch.c`'s session is about 4,000 lines:

- **9b-1, the control plane (this branch).** Sony's push websocket, and a remote-play session at the session
  manager: create it, see Sony's "created" and "joined" notifications, and leave it. The console is not involved
  yet. It ports `get_websocket_fqdn`, `websocket_thread_func`, `parse_notification_type`, `http_create_session`,
  `chiaki_holepunch_session_create` and `deleteSession`.
- **9b-2a, the console joins.** The `remotePlay` command to the console; the console joining the session
  (its device ID checked against the one asked for) and its `customData1`; the session messages, read with
  chiaki-ng's fix for Sony's broken `localPeerAddr`; and the console's first offer, acknowledged. It ports
  `chiaki_holepunch_session_start`, `http_start_session`, `decode_customdata1`, `session_message_get_payload`,
  `session_message_parse`, `short_message_serialize`, `http_send_session_message` and
  `wait_for_session_message`.
- **9b-2b, the hole itself.** Our candidates and offer (`punch.rs`), our public address from STUN (`stun.rs`),
  the UDP exchange that finds a candidate that answers, and both accepts. It ports
  `holepunch_session_create_offer`, `send_offer`, `send_accept`, `session_message_serialize`,
  `wait_for_session_message_ack`, `check_candidates`, `send_response_ps`, `receive_request_send_response_ps`,
  `chiaki_holepunch_session_punch_hole` and `stun_get_external_address_from_server`.

**What 9b-2b does and does not do yet:**
- The **control hole** is punched and verified live on the LAN (below).
- The **data hole** uses the same code (`Puncher::punch(.., Port::Data)`) but is **not verified**. The console
  offers it only once registration, the session request and the control protocol have run over the control hole
  (chiaki-ng `session.c`, the `holepunch_session_create_offer` call before `CHIAKI_HOLEPUNCH_PORT_TYPE_DATA`), and
  those come with 9c. chiaki-ng's own `holepunch-test.c` punches only the control hole for the same reason.
- **Not ported yet:** UPnP port mappings, IPv6, and port guessing for NATs that allocate ports in steps or at
  random (chiaki-ng's four-server allocation test and up to 250 probing sockets). Without them, a console and a
  client both behind such NATs will not meet; a cone NAT on either side is enough for the hole.
- **Not tested from another network yet.** On the LAN, the console's `LOCAL` candidate wins; from outside, its
  `STATIC` one (its public address) would have to.

**Differences from chiaki-ng** (each in the module notes of `punch.rs` and `stun.rs`):
- **The STUN servers are only chiaki-ng's built-in ones,** never a list downloaded at run time, and a reply counts
  only if it comes from the server asked.
- **A DERIVED candidate must share an IP address with an offered one.** chiaki-ng sends our request, whose ID is all
  a response needs, to any address that sends us a datagram, so anyone who found our port could answer in the
  console's place.
- **Malformed datagrams are passed over** rather than ending the exchange, and the answering after the hole stops
  after 32 requests.
- **Our local address is the route's** to the STUN server, not the first wired adapter.
- **A response must carry our 20-byte hashed ID** at 0x24 as well as our 5-byte request ID; chiaki-ng checks only
  the request ID. Every live answer carried it.
- **Every wait in the exchange has an absolute deadline.** chiaki-ng's restart with each datagram that arrives.

**What the security review of 9b-2b changed** (ten findings, all reasoned from the code; eight fixed):
- **A stream of datagrams could hold the candidate check open forever** (medium): its timeout was per read, so any
  datagram every half second, junk included, kept it waiting and stopped the resends. The check now has one
  deadline (twenty resends' time) and resends on its own clock. The answering after the hole has a deadline too.
- Only a request of the console's makes a DERIVED candidate, and a response must carry our hashed ID.
- A reply that cannot be sent to one candidate, or a STUN server that cannot be sent to, no longer ends the attempt;
  a STUN server's name has 3 s to resolve.
- `Candidate`, `Found` and `Hole` no longer show addresses in `Debug` output.
- **Left as they are:** the console's candidates may still be private or link-local addresses (a LAN console's
  `LOCAL` one can be), and a pong is only waited for by reads with at least two seconds to give (every wait here has
  thirty).

**9b-2b against the household's PS5, on the LAN (2026-11-25):**
1. The control hole was punched about 10 s after the console joined (and again, 10.6 s, after the review's fixes): the console's `LOCAL` candidate answered our
   request, both ACCEPTs went through, and the socket is connected to the console. Its response carried its own
   hashed ID first and ours second, the mirror of our request (recorded, not yet required).
2. **The console holds its ACCEPT until its own UDP requests on the new hole are answered.** The first port answered
   them only after the accepts, and the console acknowledged our ACCEPT but never sent its own. chiaki-ng answers
   them for a second at the end of `check_candidates`, before the ACCEPT; the port now does too.
3. **The console's ACCEPT has an empty `localHashedId`**, as ours does. 9b-2a refused an empty one; now an empty
   base64 field reads as zeros, as chiaki-ng's decoder leaves it, and any other must still be exactly 16 or 20 bytes.
4. While we waited for the console to acknowledge our offer, it sent another OFFER (request 1, 5 or 7 across runs).
   It is passed over, as chiaki-ng passes it over.
5. **The push websocket no longer mistakes UDP time for a dead server.** The punch spends seconds on UDP without
   reading the websocket; a pong that arrived meanwhile now has two seconds of the next read to be found
   (`push::pong_overdue`), where before the read would have given up on the server at once. This was found by
   reading the code while porting, not seen live.

**9b-2a against the household's PS5 (2026-11-25):**
1. The PS5 was in rest mode, and the `remotePlay` command woke it: it joined the session about 19 s after the
   start, with a 16-byte `customData1`.
2. About 6 s later its first offer arrived: request 1, NAT type 2, with two candidates, one `STATIC` and one
   `LOCAL`.
3. Our acknowledgment was accepted, and the session was left cleanly.
4. After the security review's fixes (below) the run was repeated with the same result: joined at 20.7 s, offer
   at 26.8 s.

**What the security review of 9b-2a changed:**
- Only the console's messages are read. A session message counts only if its `sessionId` is this session and its
  sender (`customProperties.from.deviceUniqueId`) is the console asked for; anything else is passed over, so
  another member can neither feed in an offer nor end the wait with a `TERMINATE` or junk. The join is checked the
  same way, against any entry of `members`, not just the first. The sender is what Sony relays and cannot be
  checked independently; the console's keys authenticate it later, in the registration.
- Candidate addresses are typed IP addresses, never names to resolve, and a probe may not go to an unspecified,
  loopback, multicast or broadcast address, or to port 0. At most 16 candidates are read.
- `skey` must be exactly 16 bytes and `localHashedId` exactly 20, chiaki-ng's sizes.
- The session ID is checked before it goes into the start command's JSON, and the `localPeerAddr` repair applies
  only where the value is truly missing, whitespace included.

**Three findings from verifying 9b-1 (2026-11-25):**

1. **Sony's push server sends an incomplete certificate chain.** It sends its own certificate
   (`*.np.communication.playstation.net`) without the intermediate `COMODO RSA Domain Validation Secure Server CA`,
   and rustls refused it: `UnknownIssuer`. chiaki-ng fetches the intermediate from the certificate's AIA address.
   psr-psn ships that one public certificate instead (`crates/psr-psn/certs/README.md`) and offers it to rustls's own
   WebPKI verifier beside the server's chain, so the root, signatures, dates and host name are all still checked.
   `tests/push.rs` replays the real server certificate: it fails without the intermediate, passes with it, and still
   fails for another host name, after the certificate's expiry, or with an altered intermediate.
2. **The push server refuses (HTTP 403) a token signed in without a client device ID.** chiaki-ng's GUI appends
   `duid=<16 random bytes after 0000000700410080>` to its sign-in address (`QmlBackend::psnLoginUrl`). The port
   copied `LOGIN_URL` without that step. The sign-in address now carries one, and signing in again made the
   websocket open.
3. **A wrong guess first:** before finding the device ID, I took the 403 to be tungstenite lowercasing header names,
   and wrote the upgrade request by hand with chiaki-ng's spelling. It was still 403. The hand-written handshake
   stays, because it leaves nothing about the request to a library, but header case was not the cause.

## 9c in detail

> Owner, 2026-11-25: *"Merge, start 9c"*.

After the control hole, chiaki-ng's `session.c` runs everything over **RUDP** on it, in this order, before it
punches the data hole: registration, the session request, then ctrl. 9c follows that order in three steps:

| step | ports | done when |
|---|---|---|
| **9c-1** | `rudp.c`'s framing, handshake and HTTP exchange; `regist.c`'s `holepunch_info` path | the console registers this client through the hole |
| **9c-2** | the session request and ctrl over RUDP (`session.c`, `ctrl.c`), `rudpsendbuffer.c` | ctrl runs through the hole and the console offers the data hole |
| **9c-3** | the data hole, and Takion and the stream over it | the PS5 plays in the test page through the holes |

**9c-1, RUDP and registration.** `crates/psr-psn/src/rudp.rs` frames messages as chiaki-ng does: an 8-byte header
(`0xC000 | length`, the constant `0x244F244F`, the type), the data, and possibly a second message chained after it.
The handshake is INIT, answered with a cookie, then COOKIE carrying it back. An HTTP request goes in a
SESSION_MESSAGE with the request chained in a CTRL_MESSAGE; the answer is a CTRL_MESSAGE, then ACK and FINISH.
`crates/psr-psn/src/regist.rs` sends the home network's registration request through it, with two changes from
chiaki-ng's `holepunch_info` path: the cipher is made from the session's `customData1`, `data1` and `data2`
instead of a PIN, and `HOST` is this client's local address.

Differences from chiaki-ng, each in the module's header:
- **A wrong message does not cost a try.** chiaki-ng resends as soon as one datagram is not the answer; here each
  of the 3 tries listens its whole second, passing over the rest, so a late holepunch request cannot use them up.
- **A datagram too short to be RUDP is passed over**, where chiaki-ng ends the exchange.
- **An answer too short for what is read from it is passed over** like any other wrong message, not taken and
  then checked.

**9c-1 against the household's PS5 (2026-11-25), on the LAN:** the hole was punched 33.3 s after the start, and
the console registered this client through it 88 ms later and sent FINISH. Its registration key and RP key match
the ones saved when it was registered at home with a PIN (the example compares them and prints only whether they
match). That is also the first check that our side of the session's `data1` and `data2` is what the console
uses: a wrong value would have derived another cipher, and the console would have refused.

**What the security review of 9c-1 changed** (10 findings, none critical or high, all reasoned from the code):
- **No header value reaches an error message.** A malformed header used to be quoted whole, and for a registration
  answer that text is the decrypted body with both keys in it. Errors now name the header only (`name_only` in
  `psr-lan`'s `http.rs`), at home and over PSN alike.
- **A `Content-Length` that would overflow** is a short answer, not a crash.
- **A message's header must be well formed**: the length word's `0xC` tag and the constant, or the rest of the
  datagram is passed over. chiaki-ng matches answers on one byte. Every message the PS5 sent passed the check in
  a second live run (registered 77 ms after the hole, keys matching).
- **A request too long for one message is refused** instead of framed with a cut length; a connection reset is
  waited out 10 ms at a time instead of spinning; `Message`'s `Debug` shows the type and length, not the bytes.
- Left as chiaki-ng has them: a failed send counts as a try with no answer, and `HOST` carries our LAN address (the
  console is the only one who sees it).

**Not verified yet:** any of it from another network.

**9c-2, the session and ctrl through the hole.** `crates/psr-psn/src/session.rs` sends the home network's session
request and ctrl request through the hole, each after its own RUDP handshake, with `Host` naming the console's
end of the hole. Ctrl then runs on the home network's `Session`, which now takes its frames from a link
(`psr_lan::session::CtrlLink`): TCP at home, and the hole's RUDP over PSN, with RUDP's acknowledgments and the
send buffer's resends (`rudpsendbuffer.c`: every 400 ms, up to 25 times, 16 at once). Two RUDP quirks of
chiaki-ng's are kept: for a PS5 the ctrl cipher's local counter skips one after the request, and a heartbeat reply
goes out unasked every 4.95 s once the console has asked for one. Differences from chiaki-ng, in `rudp.rs`'s
header: one ACK per datagram rather than per message, and the resends are made by the ctrl loop as it reads, in
steps of chiaki-ng's 200 ms resend wake-up, rather than by a thread.

**9c-2 against the household's PS5 (2026-11-25), on the LAN:**
1. After registration, the session request was answered, ctrl's 83 ms later, and the console's login result
   57 ms after that. The data hole's offer came, and the data hole was punched through the console's `LOCAL`
   candidate 16.8 s after ctrl was up, with ctrl answered on a thread meanwhile: 4 heartbeat requests answered,
   2 other messages, and ctrl still up 12 s later.
2. **The console sent no session ID** in the 10 s it is given. chiaki-ng waits the same 10 s and then makes its
   fallback ID, and so does the port (at home the PS5 sends one, in a form chiaki-ng's rules refuse, so the
   fallback is used there too). The 10 s is the whole of the gap between registration and ctrl being up.

**What the security review of 9c-2 changed** (9 findings, none critical or high, all reasoned from the code):
- **A datagram whose counter is not new is acknowledged but not read again** (MEDIUM). Read twice, as when the
  console resends because our ACK was late or someone replays one, a frame advances the ctrl cipher's counter
  and every message after it decrypts to garbage. The live run after the change was as before: 4 heartbeat
  requests answered, 2 other messages, ctrl still up.
- **What a spoofed datagram can do is narrowed** (MEDIUM). An empty session ID, which uses no cipher counter, no
  longer ends the wait for the console's; heartbeat requests closer than 1 s to our last reply are not answered,
  so a flood cannot fill the 16-slot send buffer; a frame over ctrl's 512 bytes is passed over instead of ending
  ctrl. The home network's ctrl gets the first two too, since it shares the code.
- **A console that stops acknowledging is reported**: after 25 resends reading ctrl fails, where chiaki-ng drops
  the message and carries on.
- Deliberate breaks: 23 on 9c-2 (19 caught at first; the size, the counter a message waits under and the bytes
  after ctrl's answer got tests; one miss was a stale build), and 10 on these fixes, all caught after one more
  test (the give-up report).
- A full send buffer is refused before a counter is taken or anything sent; a failed ACK no longer ends ctrl (the
  console's resend brings another chance); `Incoming`'s `Debug` shows the frames' length, not their bytes.
- **Left as they are, because RUDP and ctrl carry no authentication** (as in chiaki-ng): anyone who can put
  datagrams on the hole with the console's address can still send FINISH, acknowledge our messages so they are
  not resent, answer the session request first with a nonce of their choosing, or ask for the login PIN. Over
  PSN the hole's address is the only thing in the way; at home TCP's sequence numbers made that harder. The
  session request also carries the registration key in the clear, as at home.

**9c-3a, the stream over the data hole.** chiaki-ng's last steps before the stream over PSN, ported in
`crates/psr-psn/src/session.rs` `open_stream`: ctrl sends RUDP's switch to the stream connection (a CTRL_MESSAGE
of our counter, eight fixed bytes and 16 random ones, resent until acknowledged like any ctrl message) and waits
up to 5 s for the console's `SwitchToStreamConnection`; then what the holepunch left on the data hole is read
and dropped, until 200 ms pass with none or a second in all (`takion_read_extra_sock_messages`); then the home
network's stream connection runs on the data hole's socket (`psr_lan::stream::connect_on`), Takion, keys and
all, unchanged. Not ported: chiaki-ng also sets the socket's receive buffer to Takion's window, which the home
path does not do either.

**9c-3a against the household's PS5 (2026-11-25), on the LAN:** the stream connected 1.6 s after the data hole,
with one resolution offered, and ran 15 s: 890 video frames (59.3 a second, of the 60 asked for), 1,497 audio
frames, no frame lost and no datagram dropped, with ctrl polled every 100 ms as the app does. The console was on
its home screen, so the video was small (174 KiB). Nothing was decoded or shown: that is the app's part, 9c-3b.

**What the security review of 9c-3a changed** (7 findings, none critical or high, reasoned from the code):
- The drain passes over "connection refused" as it does Windows' reset (both are an earlier send unanswered),
  pausing 1 ms each, where a refusal used to end the stream's start on Linux and macOS and a run of resets spun.
- The ctrl messages that come while waiting for the switch are returned to the caller, at most 64, where they
  were dropped; and the unasked heartbeat reply goes out during that wait too.
- **Left as chiaki-ng has it (MEDIUM, DoS only):** the console's switch is known by its type, and an empty frame
  uses no cipher counter, so someone who can send to the control hole as the console can answer the switch
  first. The stream's start then fails when the console does not take it up (about 15 s); nothing is learned or
  taken over, as Takion's own handshake and keys are unchanged. A datagram arriving on the data hole after the
  drain goes quiet can likewise end the stream's handshake, as it could at home.
- Deliberate breaks: 8 on 9c-3a, 6 caught; the drain's two timings got a test pinning chiaki-ng's values; the
  drain inside `open_stream` is checked only by the live run. The new bound was broken and caught.

**Found while verifying 9c-2, and fixed: on Windows an answer that arrives as a receive times out can be lost.**
1. The punch test `only_a_request_makes_a_derived_candidate` failed 9 runs in 20. Its stand-in console answers
   1.5 s after our first request, as one of our 500 ms waits ends, and on failing runs the answer never came out
   of the receive. `an_address_at_an_ip_not_offered_is_passed_over`, answering at 500 ms, failed the same way.
2. Guesses that were wrong, each falsified by a run: the stand-in's socket closing (held open: still 6 in 20),
   and the junk datagram the first test also sends (left out: still 6 in 20). A plain reproduction, a receiver
   with 5 ms timeouts and a sender paced to them, lost nothing in 400 datagrams, with or without sends between
   the waits; so the loss needs something of the punch's pattern that is not understood. Any output written
   while the test ran, even into memory, made it stop failing.
3. What discriminated: the same test, unchanged, with only the receive replaced by `WSAPoll` (waiting for the
   socket to be readable, then receiving without a timeout of its own) went from 9 failures in 20 to none in
   20; the whole punch suite then passed 20 runs in 20, and with the old receive put back inside the new helper
   it failed 4 runs in 10. Winsock's documentation says nothing about what a timed-out receive leaves behind.
4. **The fix:** `psr_lan::udp::recv_within` and `recv_from_within`, which every UDP wait now uses: STUN, the
   candidate check and the answers after it, RUDP's two loops, and at home discovery, the registration search
   and the stream. Both tests stay on the boundary as its regression test. Elsewhere than Windows the read
   timeout is used as before. The whole path ran live again after the change, to the data hole.
5. **Its security review** (no critical or high findings; reasoned, not run) changed three things. A readiness
   with nothing behind it now waits again for the rest of the time, instead of reading as the wait over, which
   would have ended discovery and the registration search early; such a wake pauses 1 ms, so it cannot spin; and
   a datagram received is kept even if blocking mode cannot be put back. A test checks that a send to a closed
   port still surfaces as Windows' connection reset through the wait, which the registration search reads as
   the console not listening. Not tested: the spurious readiness itself, which needs a seam to fake; and the
   cost to the home stream, now four system calls a packet instead of two, not measured against a real stream.

**Not verified yet:** any of it from another network; the data hole's use (the stream over it is 9c-3).

## What 9a does not do yet

9a doesn't wake a console over PSN, run the holepunch session, or carry any media. 9b-1 adds the session's control
plane, 9b-2a wakes the console and reads its offer, and 9b-2b punches the control hole. 9c-1 runs RUDP over that
hole and registers through it; 9c-2 runs the session request and ctrl through it and punches the data hole; the
stream over the data hole is 9c-3.
