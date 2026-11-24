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

**Devices** come from `web.np.playstation.com/api/cloudAssistedNavigation/v2/users/me/clients?platform=PS5`, with
the access token. Each client has a `duid` (hex), a `device.name`, and `device.enabledFeatures`, which lists
`remotePlay` when it is on. As in chiaki-ng, only PS5s are listed.

**Every request has a timeout** (chiaki-ng uses 5 s), and the HTTP client is `ureq` over rustls, as in `psr-lan`'s
examples. The port map named `reqwest`; `ureq` is the blocking client the rest of this code already uses.

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

## What 9a does not do yet

It doesn't wake a console over PSN, run the holepunch session, or carry any media. Those are 9b and 9c.
