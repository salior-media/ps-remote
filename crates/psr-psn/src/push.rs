// SPDX-License-Identifier: AGPL-3.0-only
//! Sony's push notifications, over a websocket: how PSN tells the client that a remote-play session was
//! created, that a member joined, or that the console sent a message. Ported from chiaki-ng
//! `get_websocket_fqdn`, `websocket_thread_func` and `parse_notification_type` in
//! `lib/src/remote/holepunch.c` (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! chiaki-ng runs the websocket on its own thread; here it is read with a deadline by whoever waits on it.
//!
//! **Difference from chiaki-ng:** Sony's push server sends only its own certificate, without the
//! intermediate CA. chiaki-ng fetches that through the certificate's AIA address; here the intermediate is
//! shipped (`certs/README.md`) and offered to rustls's own verifier beside the server's chain, which still
//! checks it all the way to a public root.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use tungstenite::protocol::Role;
use tungstenite::{Message, WebSocket};

use crate::PsnError;

/// chiaki-ng `ws_fqdn_api_url`: where Sony says which push server to use.
pub const FQDN_URL: &str = "https://mobile-pushcl.np.communication.playstation.net/np/serveraddr?version=2.1&fields=keepAliveStatus&keepAliveStatusType=3";
/// chiaki-ng `WEBSOCKET_PING_INTERVAL_SEC`, and the time it gives a pong to come back.
pub const PING_INTERVAL: Duration = Duration::from_secs(5);
/// chiaki-ng `SESSION_CREATION_TIMEOUT_SEC`, used for the connection too.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest handshake response read before giving up.
const RESPONSE_HEAD_MAX: usize = 16 * 1024;
/// chiaki-ng `WEBSOCKET_MAX_FRAME_SIZE`.
pub const MAX_FRAME: usize = 64 * 1024;
/// The intermediate CA Sony's push server leaves out (`certs/README.md`).
pub const PUSH_INTERMEDIATE: &[u8] = include_bytes!("../certs/comodo-rsa-domain-validation-secure-server-ca.der");

/// chiaki-ng `NotificationType`, from a notification's `dataType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    SessionCreated,
    MemberCreated,
    MemberDeleted,
    CustomData1Updated,
    SessionMessageCreated,
    SessionDeleted,
    Unknown,
}

impl Kind {
    /// chiaki-ng `parse_notification_type`.
    pub fn of(data_type: &str) -> Self {
        match data_type {
            "psn:sessionManager:sys:remotePlaySession:created" => Self::SessionCreated,
            "psn:sessionManager:sys:rps:members:created" => Self::MemberCreated,
            "psn:sessionManager:sys:rps:members:deleted" => Self::MemberDeleted,
            "psn:sessionManager:sys:rps:customData1:updated" => Self::CustomData1Updated,
            "psn:sessionManager:sys:rps:sessionMessage:created" => Self::SessionMessageCreated,
            "psn:sessionManager:sys:remotePlaySession:deleted" => Self::SessionDeleted,
            _ => Self::Unknown,
        }
    }
}

/// One notification: its kind, and the whole JSON for whoever needs its fields.
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    pub kind: Kind,
    pub json: serde_json::Value,
}

impl Notification {
    /// A text or binary frame's JSON. A frame that is not a JSON object with a `dataType` string is `None`,
    /// as chiaki-ng logs and skips it.
    pub fn parse(frame: &[u8]) -> Option<Self> {
        let json: serde_json::Value = serde_json::from_slice(frame).ok()?;
        let kind = Kind::of(json.get("dataType")?.as_str()?);
        Some(Self { kind, json })
    }
}

/// The push server's host name, from Sony (chiaki-ng `get_websocket_fqdn`).
pub fn fqdn(access_token: &str) -> Result<String, PsnError> {
    let sent = crate::agent().get(FQDN_URL).header("Authorization", format!("Bearer {access_token}")).call();
    let json = crate::reply("push server lookup", sent)?;
    let fqdn = json["fqdn"].as_str().ok_or(PsnError::MissingField("fqdn"))?;
    if !valid_fqdn(fqdn) {
        return Err(PsnError::BadField("fqdn"));
    }
    Ok(fqdn.to_string())
}

/// A host name and nothing else (letters, digits, dots and hyphens): it goes into a URL and a request line.
pub fn valid_fqdn(fqdn: &str) -> bool {
    !fqdn.is_empty() && fqdn.len() <= 253 && fqdn.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// rustls's WebPKI verifier, offered [`PUSH_INTERMEDIATE`] beside the chain the server sends.
#[derive(Debug)]
struct WithIntermediate {
    inner: Arc<WebPkiServerVerifier>,
    extra: CertificateDer<'static>,
}

impl ServerCertVerifier for WithIntermediate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain: Vec<CertificateDer<'_>> = intermediates.to_vec();
        chain.push(self.extra.clone());
        self.inner.verify_server_cert(end_entity, &chain, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// rustls's WebPKI verifier over the public roots of `webpki-roots`, offered `extra` as one more
/// intermediate beside the server's chain (none for the plain verifier).
pub fn verifier(extra: Option<&[u8]>) -> Result<Arc<dyn ServerCertVerifier>, PsnError> {
    let roots = Arc::new(rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() });
    let inner = WebPkiServerVerifier::builder_with_provider(roots, provider())
        .build()
        .map_err(|e| PsnError::Network(e.to_string()))?;
    Ok(match extra {
        Some(der) => Arc::new(WithIntermediate { inner, extra: CertificateDer::from(der.to_vec()) }),
        None => inner,
    })
}

/// The TLS configuration for the push server: the public roots, and the shipped intermediate.
pub fn tls_config() -> Result<Arc<rustls::ClientConfig>, PsnError> {
    let verifier = verifier(Some(PUSH_INTERMEDIATE))?;
    let config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| PsnError::Network(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

type Tls = StreamOwned<ClientConnection, TcpStream>;

/// An open push connection (chiaki-ng's websocket, without its thread).
pub struct Push {
    ws: WebSocket<Tls>,
    last_ping: Instant,
    awaiting_pong: bool,
}

impl std::fmt::Debug for Push {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Push").finish_non_exhaustive()
    }
}

fn ws_err(e: tungstenite::Error) -> PsnError {
    PsnError::Network(format!("push websocket: {e}"))
}

/// The upgrade request, with each header name spelled as chiaki-ng (through curl) sends it, written here so
/// nothing about it is left to a library; tungstenite takes over after the handshake.
pub fn upgrade_request(fqdn: &str, access_token: &str, key: &str) -> String {
    let headers = [
        ("Host", fqdn),
        ("Upgrade", "websocket"),
        ("Connection", "Upgrade"),
        ("Sec-WebSocket-Version", "13"),
        ("Sec-WebSocket-Key", key),
        ("Authorization", &format!("Bearer {access_token}")),
        ("Sec-WebSocket-Protocol", "np-pushpacket"),
        ("User-Agent", "WebSocket++/0.8.2"),
        ("X-PSN-APP-TYPE", "REMOTE_PLAY"),
        ("X-PSN-APP-VER", "RemotePlay/1.0"),
        ("X-PSN-KEEP-ALIVE-STATUS-TYPE", "3"),
        ("X-PSN-OS-VER", "Windows/10.0"),
        ("X-PSN-PROTOCOL-VERSION", "2.1"),
        ("X-PSN-RECONNECTION", "false"),
    ];
    let mut r = String::from("GET /np/pushNotification HTTP/1.1\r\n");
    for (k, v) in headers {
        r.push_str(&format!("{k}: {v}\r\n"));
    }
    r.push_str("\r\n");
    r
}

/// The status code and headers of a handshake response, checked: 101 with `Sec-WebSocket-Accept` matching
/// `key`. Header names are compared without regard to case.
pub fn check_upgrade_response(head: &str, key: &str) -> Result<(), PsnError> {
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let code: u16 = status.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    if code != 101 {
        // The push server explains a refusal in its X-NP-* headers, not the body.
        let np: Vec<String> = head
            .split("\r\n")
            .filter(|l| l.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("x-np-")))
            .map(crate::printable)
            .collect();
        let reason = (!np.is_empty()).then(|| np.join("; "));
        return Err(PsnError::Status { what: "push websocket", code, reason });
    }
    let accept = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("Sec-WebSocket-Accept"))
        .map(|(_, v)| v.trim());
    if accept != Some(tungstenite::handshake::derive_accept_key(key.as_bytes()).as_str()) {
        return Err(PsnError::BadField("Sec-WebSocket-Accept"));
    }
    Ok(())
}

/// Reads up to and including the blank line that ends a response's head, a byte at a time so nothing after
/// it is taken from the websocket.
fn read_head(stream: &mut Tls) -> Result<String, PsnError> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= RESPONSE_HEAD_MAX {
            return Err(PsnError::BadField("push handshake response"));
        }
        stream.read_exact(&mut byte).map_err(|e| PsnError::Network(format!("push websocket handshake: {e}")))?;
        head.push(byte[0]);
    }
    String::from_utf8(head).map_err(|_| PsnError::BadField("push handshake response"))
}

impl Push {
    /// Connects to `wss://<fqdn>/np/pushNotification` with the headers Sony's app sends (chiaki-ng
    /// `websocket_thread_func`).
    pub fn connect(fqdn: &str, access_token: &str) -> Result<Self, PsnError> {
        let addr = (fqdn, 443)
            .to_socket_addrs()
            .map_err(|e| PsnError::Network(e.to_string()))?
            .next()
            .ok_or_else(|| PsnError::Network(format!("{fqdn} has no address")))?;
        let tcp = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|e| PsnError::Network(e.to_string()))?;
        tcp.set_read_timeout(Some(CONNECT_TIMEOUT)).map_err(PsnError::Io)?;
        tcp.set_write_timeout(Some(CONNECT_TIMEOUT)).map_err(PsnError::Io)?;
        let name = ServerName::try_from(fqdn.to_string()).map_err(|_| PsnError::BadField("fqdn"))?;
        let tls = ClientConnection::new(tls_config()?, name).map_err(|e| PsnError::Network(e.to_string()))?;
        let mut stream = StreamOwned::new(tls, tcp);

        let key = tungstenite::handshake::client::generate_key();
        let request = upgrade_request(fqdn, access_token, &key);
        stream
            .write_all(request.as_bytes())
            .map_err(|e| PsnError::Network(format!("push websocket handshake: {e}")))?;
        stream.flush().map_err(|e| PsnError::Network(format!("push websocket handshake: {e}")))?;
        check_upgrade_response(&read_head(&mut stream)?, &key)?;

        let mut config = tungstenite::protocol::WebSocketConfig::default();
        config.max_message_size = Some(MAX_FRAME);
        config.max_frame_size = Some(MAX_FRAME);
        let ws = WebSocket::from_raw_socket(stream, Role::Client, Some(config));
        Ok(Self { ws, last_ping: Instant::now(), awaiting_pong: false })
    }

    fn set_read_timeout(&mut self, d: Duration) -> Result<(), PsnError> {
        self.ws.get_mut().sock.set_read_timeout(Some(d.max(Duration::from_millis(1)))).map_err(PsnError::Io)
    }

    /// The next notification before `deadline`, keeping the connection alive with a ping every five
    /// seconds as chiaki-ng does. `None` when the deadline passes first. A missing pong, a close, or a broken
    /// connection is an error.
    pub fn next(&mut self, deadline: Instant) -> Result<Option<Notification>, PsnError> {
        loop {
            let now = Instant::now();
            if self.awaiting_pong && now.duration_since(self.last_ping) > PING_INTERVAL {
                return Err(PsnError::Network("the push server stopped answering pings".into()));
            }
            if now.duration_since(self.last_ping) >= PING_INTERVAL {
                self.ws.send(Message::Ping(Vec::new().into())).map_err(ws_err)?;
                self.last_ping = now;
                self.awaiting_pong = true;
            }
            if now >= deadline {
                return Ok(None);
            }
            let until_ping = (self.last_ping + PING_INTERVAL).saturating_duration_since(now);
            self.set_read_timeout(until_ping.min(deadline - now))?;
            match self.ws.read() {
                Ok(Message::Text(t)) => {
                    if let Some(n) = Notification::parse(t.as_bytes()) {
                        return Ok(Some(n));
                    }
                }
                Ok(Message::Binary(b)) => {
                    if let Some(n) = Notification::parse(&b) {
                        return Ok(Some(n));
                    }
                }
                // tungstenite answers pings itself.
                Ok(Message::Ping(_) | Message::Frame(_)) => {}
                Ok(Message::Pong(_)) => self.awaiting_pong = false,
                Ok(Message::Close(_)) => return Err(PsnError::Network("the push server closed the connection".into())),
                Err(tungstenite::Error::Io(e))
                    if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(e) => return Err(ws_err(e)),
            }
        }
    }

    /// Closes the connection politely; errors are ignored, as the connection is being dropped anyway.
    pub fn close(mut self) {
        let _ = self.ws.close(None);
        let _ = self.ws.flush();
    }
}
