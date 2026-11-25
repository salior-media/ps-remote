# ps-remote

Our own PlayStation Remote Play client, written in Rust and run as a background service. It is a port of
[chiaki-ng](https://github.com/chiaki-ng/chiaki-ng), made more flexible:

- it runs without a window, as a service with a local API;
- it sends the picture and sound to a browser over WebRTC, as the console sent them, with no decoding;
- it takes input from the browser: a gamepad, the keyboard, and the picture as the touchpad.

It is meant for the games app's *PlayStation* tab. The games app is a separate program and talks to it only through
the service's local API. That tab is not built yet; until it is, the service serves a small test page of its own.

## Status

Steps 1–9 of [`docs/PORT-MAP.md`](docs/PORT-MAP.md) are built.

- **Seen working, on the home network:** finding the PS5, linking with its PIN, and playing it in the test page,
  at about 60 frames a second. Waking it, sound, and input are built and tested in code; the touchpad has not been
  tried on the console yet.
- **Built, tested on the home network only:** playing through Sony's servers ("Remote Play over Internet"). Its
  stream ran at about 60 frames a second, none lost. Playing from another network has not been tried yet.
- **Not built:** a second controller, the games app's tab, and a measure of the console-to-service delay.
  chiaki-ng measures none either (its Senkusha code is compiled but switched off).

## Using it

```
cargo run -p psr-lan --example psn_account_id      # your PSN account ID, needed to link
cargo run -p psr-lan --example link -- <console-ip> # with Settings → System → Remote Play → Link Device open
cargo run -p ps-remote -- serve                     # prints a link to the test page
```

Playing through PSN needs a sign-in first (`ps-remote signin`) and `PSN_RP_CLIENT_SECRET` set when the service
starts. [`docs/SERVICE.md`](docs/SERVICE.md) describes the service and its API; [`docs/PSN.md`](docs/PSN.md)
describes playing through PSN.

- The sign-in happens on Sony's own page in your browser. ps-remote never sees the password, and keeps only the
  refresh token. On Windows that token is encrypted for your Windows user (DPAPI); elsewhere it is in a file only
  you can read, but not encrypted.
- Playing through PSN uses the account's first console with Remote Play on, as chiaki-ng does.
- Nothing on the console is modified. It uses the PS5's own Remote Play feature.

## Credits and licence

ps-remote is derived from **chiaki-ng** and the original **Chiaki** by Florian Märkl and contributors, and is
distributed under the same licence: the **GNU Affero General Public License v3.0** (see `LICENSE`). chiaki-ng's files
carry `LicenseRef-AGPL-3.0-only-OpenSSL`, the AGPL plus an exception for linking OpenSSL. ps-remote keeps that
exception wherever it carries code over from chiaki-ng. It uses no OpenSSL itself: its cryptography is pure Rust.

Because of the AGPL, anyone who uses ps-remote, including over a network, can get its full source. This repository is
public for that reason.

ps-remote is not affiliated with, endorsed by or certified by Sony Interactive Entertainment. PlayStation and PS5 are
Sony's trademarks. Using an unofficial client with a PSN account is at the account owner's own risk.
