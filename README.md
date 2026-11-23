# ps-remote

Our own PlayStation Remote Play client, written in Rust and run as a background service. It is a port of
[chiaki-ng](https://github.com/chiaki-ng/chiaki-ng), made more flexible:

- it runs without a window, as a service;
- it sends the picture as a WebRTC stream for watchers;
- it takes input from several controllers, so another player can join or take over.

It is used by the games app's *PlayStation* tab. The games app is a separate program and talks to it only through the
service's local API.

**Status:** planning. There is no code yet. The plan is §7 of the games repository's
`docs/SCOPE-play-anywhere-2026-11-24.md`.

## What it does

- Finds PS5 consoles on the home network, and wakes them when someone asks.
- Links with a console using the PIN from the console's own *Settings → System → Remote Play → Link Device* screen.
- Plays on the home network directly, or from anywhere through Sony's own "Remote Play over Internet" path. That path
  reaches only the account's main console.
- Signs in to PSN once, on Sony's own sign-in page. It keeps only the refresh token, encrypted on the device, and
  never sees or stores the password.

Nothing on the console is modified. It uses the PS5's own Remote Play feature.

## Credits and licence

ps-remote is derived from **chiaki-ng** and the original **Chiaki** by Florian Märkl and contributors, and is
distributed under the same licence: the **GNU Affero General Public License v3.0** (see `LICENSE`). chiaki-ng's files
carry `LicenseRef-AGPL-3.0-only-OpenSSL`, the AGPL plus an exception for linking OpenSSL. ps-remote keeps that
exception wherever it carries code over from chiaki-ng.

Because of the AGPL, anyone who uses ps-remote, including over a network, can get its full source. This repository is
public for that reason.

ps-remote is not affiliated with, endorsed by or certified by Sony Interactive Entertainment. PlayStation and PS5 are
Sony's trademarks. Using an unofficial client with a PSN account is at the account owner's own risk.
