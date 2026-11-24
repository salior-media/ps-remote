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

/// Sony's push domain. The bearer token is sent to the push server, so the name Sony's lookup returns must be
/// in it: TLS checks a certificate against the name asked for, and would not stop a lookup that named another
/// host with a certificate of its own.
pub const PUSH_DOMAIN: &str = ".np.communication.playstation.net";

/// A well-formed host name under [`PUSH_DOMAIN`]: labels of 1 to 63 letters, digits and hyphens, none starting or
/// ending with a hyphen, 253 characters at most. It goes into a request line and a TLS name.
pub fn valid_fqdn(fqdn: &str) -> bool {
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    fqdn.len() <= 253
        && fqdn.strip_suffix(PUSH_DOMAIN).is_some_and(|host| !host.is_empty() && host.split('.').all(label_ok))
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

/// A stream that stops at a deadline: once it has passed, every read and write fails with `TimedOut`, however
/// the bytes are coming. A socket timeout alone bounds each read, not their sum, so a server sending one byte at
/// a time could hold a handshake or a half-sent frame for as long as it liked.
#[derive(Debug)]
pub struct Deadline<S> {
    inner: S,
    deadline: Option<Instant>,
}

impl<S> Deadline<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, deadline: None }
    }

    pub fn set_deadline(&mut self, deadline: Option<Instant>) {
        self.deadline = deadline;
    }

    fn check(&self) -> std::io::Result<()> {
        match self.deadline {
            Some(d) if Instant::now() >= d => Err(std::io::ErrorKind::TimedOut.into()),
            _ => Ok(()),
        }
    }
}

impl<S: Read> Read for Deadline<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.check()?;
        self.inner.read(buf)
    }
}

impl<S: Write> Write for Deadline<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.check()?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.check()?;
        self.inner.flush()
    }
}

// The deadline is under TLS, on the socket: rustls may read the socket several times in one read of its own.
type Tls = StreamOwned<ClientConnection, Deadline<TcpStream>>;

/// An open push connection (chiaki-ng's websocket, without its thread).
pub struct Push {
    ws: WebSocket<Tls>,
    last_ping: Instant,
    /// The payload of the ping not yet answered: only a pong carrying it counts.
    awaiting_pong: Option<[u8; 8]>,
}

impl std::fmt::Debug for Push {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Push").finish_non_exhaustive()
    }
}

fn ws_err(e: tungstenite::Error) -> PsnError {
    PsnError::Network(format!("push websocket: {e}"))
}

/// Visible ASCII only (no space or control character): a token or key that could not end a header line early.
fn header_safe(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// The upgrade request, with each header name spelled as chiaki-ng (through curl) sends it, written here so
/// nothing about it is left to a library; tungstenite takes over after the handshake. Every value from outside
/// is checked, so none can add a header or a second request.
pub fn upgrade_request(fqdn: &str, access_token: &str, key: &str) -> Result<String, PsnError> {
    if !valid_fqdn(fqdn) {
        return Err(PsnError::BadField("fqdn"));
    }
    if !header_safe(access_token) {
        return Err(PsnError::BadField("access token"));
    }
    if !header_safe(key) {
        return Err(PsnError::BadField("Sec-WebSocket-Key"));
    }
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
    Ok(r)
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

/// A handshake's I/O error: running out of time is a timeout, anything else a network error.
fn handshake_io(e: std::io::Error) -> PsnError {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => PsnError::Timeout("the push handshake"),
        _ => PsnError::Network(format!("push websocket handshake: {e}")),
    }
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
        stream.read_exact(&mut byte).map_err(handshake_io)?;
        head.push(byte[0]);
    }
    String::from_utf8(head).map_err(|_| PsnError::BadField("push handshake response"))
}

/// Each of the name's addresses in turn, all within `deadline`.
fn connect_tcp(fqdn: &str, deadline: Instant) -> Result<TcpStream, PsnError> {
    let addrs = (fqdn, 443).to_socket_addrs().map_err(|e| PsnError::Network(e.to_string()))?;
    let mut last = PsnError::Network(format!("{fqdn} has no address"));
    for addr in addrs {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(PsnError::Timeout("the push server to accept the connection"));
        }
        match TcpStream::connect_timeout(&addr, left) {
            Ok(tcp) => return Ok(tcp),
            Err(e) => last = PsnError::Network(e.to_string()),
        }
    }
    Err(last)
}

impl Push {
    /// Connects to `wss://<fqdn>/np/pushNotification` with the headers Sony's app sends (chiaki-ng
    /// `websocket_thread_func`). The whole of it, from the address lookup to the handshake's last byte, has
    /// [`CONNECT_TIMEOUT`].
    pub fn connect(fqdn: &str, access_token: &str) -> Result<Self, PsnError> {
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let key = tungstenite::handshake::client::generate_key();
        // Checked before anything is sent.
        let request = upgrade_request(fqdn, access_token, &key)?;
        let tcp = connect_tcp(fqdn, deadline)?;
        tcp.set_read_timeout(Some(CONNECT_TIMEOUT)).map_err(PsnError::Io)?;
        tcp.set_write_timeout(Some(CONNECT_TIMEOUT)).map_err(PsnError::Io)?;
        let name = ServerName::try_from(fqdn.to_string()).map_err(|_| PsnError::BadField("fqdn"))?;
        let tls = ClientConnection::new(tls_config()?, name).map_err(|e| PsnError::Network(e.to_string()))?;
        let mut stream = StreamOwned::new(tls, Deadline::new(tcp));
        stream.sock.set_deadline(Some(deadline));

        stream.write_all(request.as_bytes()).map_err(handshake_io)?;
        stream.flush().map_err(handshake_io)?;
        check_upgrade_response(&read_head(&mut stream)?, &key)?;
        stream.sock.set_deadline(None);

        let mut config = tungstenite::protocol::WebSocketConfig::default();
        config.max_message_size = Some(MAX_FRAME);
        config.max_frame_size = Some(MAX_FRAME);
        let ws = WebSocket::from_raw_socket(stream, Role::Client, Some(config));
        Ok(Self { ws, last_ping: Instant::now(), awaiting_pong: None })
    }

    /// The socket timeout for one read, and the stream's deadline for the whole of [`Push::next`]'s wait.
    fn bound_reads(&mut self, timeout: Duration, deadline: Instant) -> Result<(), PsnError> {
        let stream = self.ws.get_mut();
        stream.sock.set_deadline(Some(deadline));
        stream.sock.inner.set_read_timeout(Some(timeout.max(Duration::from_millis(1)))).map_err(PsnError::Io)
    }

    /// The next notification before `deadline`, keeping the connection alive with a ping every five
    /// seconds as chiaki-ng does. `None` when the deadline passes first. A missing pong, a close, or a broken
    /// connection is an error.
    pub fn next(&mut self, deadline: Instant) -> Result<Option<Notification>, PsnError> {
        loop {
            let now = Instant::now();
            if self.awaiting_pong.is_some() && now.duration_since(self.last_ping) > PING_INTERVAL {
                return Err(PsnError::Network("the push server stopped answering pings".into()));
            }
            if now.duration_since(self.last_ping) >= PING_INTERVAL {
                let mut payload = [0u8; 8];
                getrandom::fill(&mut payload).map_err(|e| PsnError::Network(format!("random numbers: {e}")))?;
                // No deadline on the stream while sending: it is for reads.
                self.ws.get_mut().sock.set_deadline(None);
                self.ws.send(Message::Ping(payload.to_vec().into())).map_err(ws_err)?;
                self.last_ping = now;
                self.awaiting_pong = Some(payload);
            }
            if now >= deadline {
                return Ok(None);
            }
            // Wake for the next ping, or the caller's deadline, whichever is first, however slowly a frame arrives.
            let wake = (self.last_ping + PING_INTERVAL).min(deadline);
            self.bound_reads(wake - now, wake)?;
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
                // Only the answer to our own ping: an unasked pong does not prove the server is listening.
                Ok(Message::Pong(p)) => {
                    if self.awaiting_pong.is_some_and(|want| p.as_ref() == want) {
                        self.awaiting_pong = None;
                    }
                }
                Ok(Message::Close(_)) => return Err(PsnError::Network("the push server closed the connection".into())),
                Err(tungstenite::Error::Io(e))
                    if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(e) => return Err(ws_err(e)),
            }
        }
    }

    /// Closes the connection politely; errors are ignored, as the connection is being dropped anyway.
    pub fn close(mut self) {
        self.ws.get_mut().sock.set_deadline(Some(Instant::now() + PING_INTERVAL));
        let _ = self.ws.close(None);
        let _ = self.ws.flush();
    }
}
