//! Raw peer sessions for the probe: a pipe to the host (TCP, or a ws pipe),
//! TLS that the probe may get wrong on purpose, and mux frames written by
//! hand, so the probe can send what a real caller never would.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mousse_net_core::control::ControlMessage;
use mousse_net_core::identity::{IdentityPublicKey, SoftwareKey};
use mousse_net_core::mux::{decode_frame, Frame, PriorityClass, StreamId};
use mousse_net_core::pairing::{join_proof_mac, AttemptId, Ticket};
use mousse_net_core::session_cert::SessionCertificate;
use mousse_net_core::{ErrorCode, ALPN, PROTOCOL_MINOR_VERSION, PROTOCOL_VERSION};
use mousse_net_io::certs::CertManager;
use mousse_net_io::pipe::Pipe;
use mousse_net_io::tls::{self, Handshake};
use mousse_net_io::{SystemClock, TlsPolicy};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::ws;
use super::Waits;

/// A boxed pipe, whatever the route.
pub type BoxPipe = Box<dyn Pipe>;

/// Where the probe dials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// `tcp://<ip>:<port>`.
    Tcp(SocketAddr),
    /// `ws://<loopback ip>:<port><path>`: the host's loopback ws listener.
    Ws { addr: SocketAddr, path: String },
    /// The system `ssh` running the remote `pipe`.
    Ssh(super::ssh::SshRoute),
}

impl Target {
    /// Parse a route hint. Only IP literals: the probe never resolves a
    /// name, so it cannot reach anything the check did not name.
    pub fn parse(hint: &str) -> Result<Self, String> {
        if let Some(rest) = hint.strip_prefix("tcp://") {
            let addr: SocketAddr = rest
                .parse()
                .map_err(|_| format!("{hint}: tcp routes need an IP literal and a port"))?;
            return Ok(Target::Tcp(addr));
        }
        if let Some(rest) = hint.strip_prefix("ws://") {
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], rest[i..].to_owned()),
                None => (rest, "/".to_owned()),
            };
            let addr: SocketAddr = authority
                .parse()
                .map_err(|_| format!("{hint}: ws routes need an IP literal and a port"))?;
            if !addr.ip().is_loopback() {
                return Err(format!(
                    "{hint}: plain ws is only for a loopback listener (wss goes through the tunnel stand-in)"
                ));
            }
            return Ok(Target::Ws { addr, path });
        }
        if hint == "ssh" || hint.starts_with("ssh://") {
            return Err(format!(
                "{hint}: the ssh route needs --ssh-config, --ssh-host and --ssh-profile"
            ));
        }
        Err(format!("{hint}: the probe dials tcp:// or ws:// routes"))
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Target::Tcp(_) => "tcp",
            Target::Ws { .. } => "ws",
            Target::Ssh(_) => "ssh",
        }
    }

    /// The TCP address dialled; `None` for ssh, which runs a program.
    pub fn addr(&self) -> Option<SocketAddr> {
        match self {
            Target::Tcp(a) | Target::Ws { addr: a, .. } => Some(*a),
            Target::Ssh(_) => None,
        }
    }

    /// A pipe that carries bytes to the host's TLS: TCP, or TCP plus a ws
    /// upgrade.
    pub async fn pipe(&self, waits: &Waits) -> Result<BoxPipe, String> {
        let addr = match self {
            Target::Ssh(route) => return route.pipe(waits).await,
            Target::Tcp(a) | Target::Ws { addr: a, .. } => *a,
        };
        let tcp = tcp(addr, waits).await?;
        match self {
            Target::Ssh(_) | Target::Tcp(_) => Ok(Box::new(tcp)),
            Target::Ws { path, .. } => {
                let (tcp, status) = ws::upgrade(tcp, &ws::Request::good(addr, path), waits)
                    .await
                    .map_err(|e| format!("ws upgrade: {e}"))?;
                match tcp {
                    Some(tcp) => Ok(Box::new(ws::bridge(tcp))),
                    None => Err(format!("ws upgrade refused: {status}")),
                }
            }
        }
    }
}

pub async fn tcp(addr: SocketAddr, waits: &Waits) -> Result<TcpStream, String> {
    match tokio::time::timeout(waits.connect, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Ok(Err(e)) => Err(format!("connect {addr}: {e}")),
        Err(_) => Err(format!("connect {addr}: timed out")),
    }
}

/// A device identity for the probe: fresh, or loaded from a key file.
pub struct Device {
    pub key: Arc<SoftwareKey>,
    pub cert: SessionCertificate,
}

impl Device {
    pub fn fresh() -> Result<Self, String> {
        Self::from_key(SoftwareKey::generate(&mut mousse_net_io::rng::os_rng()))
    }

    pub fn from_key(key: SoftwareKey) -> Result<Self, String> {
        let key = Arc::new(key);
        let certs = CertManager::new(key.clone(), Arc::new(SystemClock::new()));
        let cert = certs
            .current()
            .map_err(|e| format!("session certificate: {e}"))?;
        Ok(Self { key, cert })
    }

    pub fn identity(&self) -> IdentityPublicKey {
        *self.cert.identity()
    }
}

/// How the probe does TLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsMode {
    /// As a caller should: TLS 1.3, `mousse/1`, our certificate, the host
    /// pinned.
    Proper,
    /// No client certificate.
    NoCert,
    /// ALPN `http/1.1`, with our certificate.
    WrongAlpn,
}

/// One TLS session over a pipe, with frames written and read by hand.
pub struct Raw {
    io: tokio_rustls::client::TlsStream<BoxPipe>,
    buf: Vec<u8>,
    pub handshake: Option<Handshake>,
    next_stream: u32,
}

/// How a case ended on the wire.
#[derive(Clone, Debug)]
pub struct Ending {
    /// `goaway:<code>`, `code_abort:<code>`, `closed (...)` or `open`.
    pub end: String,
    /// What came before the end, other than `HELLO` and keepalives.
    pub noted: Vec<String>,
    pub elapsed: Duration,
}

impl Ending {
    /// The wire result of a refusal: the end alone when the host answered
    /// at once and let nothing through first. A refusal that only came
    /// after `prompt` (the proof wait closing a silent connection) or after
    /// anything else is reported with what preceded it, so it cannot match
    /// the expected close.
    pub fn refusal(&self, prompt: Option<Duration>) -> String {
        if !self.noted.is_empty() {
            return format!("{} after {}", self.end, self.noted.join(", "));
        }
        match prompt {
            Some(limit) if self.elapsed >= limit => {
                format!("{} only after {} ms", self.end, self.elapsed.as_millis())
            }
            _ => self.end.clone(),
        }
    }
}

/// What the host did next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seen {
    Frame(Frame),
    /// The pipe ended (EOF, reset, or a TLS alert).
    Closed(String),
    /// Nothing within the wait.
    Nothing,
}

impl Raw {
    /// Step 1 as `mode` says. `Proper` checks the host against `pin`; the
    /// other modes accept any server certificate, since the point is the
    /// host's answer to a bad client.
    pub async fn connect(
        pipe: BoxPipe,
        device: &Device,
        pin: IdentityPublicKey,
        mode: TlsMode,
        waits: &Waits,
    ) -> Result<Self, String> {
        if mode == TlsMode::Proper {
            let (stream, handshake) = tls::connect(
                pipe,
                &device.cert,
                pin,
                Arc::new(SystemClock::new()),
                waits.tls(),
            )
            .await
            .map_err(|e| format!("TLS: {e}"))?;
            let io = match stream {
                tokio_rustls::TlsStream::Client(c) => c,
                tokio_rustls::TlsStream::Server(_) => return Err("TLS: not a client".into()),
            };
            return Ok(Self {
                io,
                buf: Vec::new(),
                handshake: Some(handshake),
                next_stream: 1,
            });
        }
        let config = wrong_config(device, mode)?;
        let name = ServerName::try_from("mousse-session").map_err(|e| e.to_string())?;
        let io = tokio::time::timeout(waits.close, TlsConnector::from(config).connect(name, pipe))
            .await
            .map_err(|_| "TLS: timed out".to_owned())?
            .map_err(|e| format!("TLS: {e}"))?;
        Ok(Self {
            io,
            buf: Vec::new(),
            handshake: None,
            next_stream: 1,
        })
    }

    pub async fn send(&mut self, frame: &Frame) -> Result<(), String> {
        self.io
            .write_all(&frame.encode())
            .await
            .map_err(|e| format!("write: {e}"))?;
        self.io.flush().await.map_err(|e| format!("write: {e}"))
    }

    pub async fn control(&mut self, msg: &ControlMessage) -> Result<(), String> {
        self.send(&Frame::Control {
            payload: msg.encode(),
        })
        .await
    }

    pub async fn hello(&mut self) -> Result<(), String> {
        self.control(&ControlMessage::Hello {
            major_version: PROTOCOL_VERSION,
            minor_version: PROTOCOL_MINOR_VERSION,
        })
        .await
    }

    /// Open the next caller stream with `label`, without asking anyone.
    pub async fn open(&mut self, label: &str) -> Result<StreamId, String> {
        let stream = StreamId(self.next_stream);
        self.next_stream += 2;
        self.send(&Frame::Open {
            stream,
            class: PriorityClass::Interactive,
            label: label.to_owned(),
        })
        .await?;
        Ok(stream)
    }

    /// A join proof for `ticket`, valid unless `spoil` is set.
    pub async fn join_proof(
        &mut self,
        ticket: &Ticket,
        joiner: &IdentityPublicKey,
        spoil: bool,
    ) -> Result<(), String> {
        let exporter = self
            .handshake
            .as_ref()
            .ok_or("a join proof needs a proper handshake")?
            .exporters
            .join;
        let mut mac = join_proof_mac(
            &ticket.secret,
            &ticket.invitation,
            &ticket.host_identity,
            joiner,
            &exporter,
        );
        if spoil {
            mac[0] ^= 0x01;
        }
        self.control(&ControlMessage::JoinProof {
            invitation: ticket.invitation,
            mac,
            name: "mousse-check probe".into(),
        })
        .await
    }

    /// A code-exchange message that is not one.
    pub async fn garbage_code(&mut self) -> Result<(), String> {
        let attempt = AttemptId(mousse_net_io::rng::random_bytes::<16>());
        self.control(&ControlMessage::CodeExchange {
            attempt,
            payload: vec![0x5a; 32],
        })
        .await
    }

    /// The next frame, the end of the pipe, or nothing by `until`.
    pub async fn next(&mut self, until: Instant) -> Seen {
        loop {
            match decode_frame(&self.buf) {
                Ok(Some((frame, used))) => {
                    self.buf.drain(..used);
                    return Seen::Frame(frame);
                }
                Ok(None) => {}
                Err(e) => return Seen::Closed(format!("bad frame from host: {e:?}")),
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Seen::Nothing;
            }
            let mut chunk = [0u8; 16 * 1024];
            match tokio::time::timeout(left, self.io.read(&mut chunk)).await {
                Err(_) => return Seen::Nothing,
                Ok(Ok(0)) => return Seen::Closed("eof".into()),
                Ok(Ok(n)) => self.buf.extend_from_slice(&chunk[..n]),
                Ok(Err(e)) => return Seen::Closed(e.to_string()),
            }
        }
    }

    /// Read until the host closes or answers in a way that ends the case:
    /// `GOAWAY`, `CODE_ABORT`, the pipe closing, or `wait` passing.
    /// Keepalives are answered; everything else is noted on the way.
    pub async fn until_close(&mut self, wait: Duration) -> Ending {
        let start = Instant::now();
        let until = start + wait;
        let mut noted = Vec::new();
        let end = loop {
            match self.next(until).await {
                Seen::Frame(Frame::GoAway { code }) => break format!("goaway:{}", code.name()),
                Seen::Frame(Frame::Ping { opaque }) => {
                    let _ = self.send(&Frame::Pong { opaque }).await;
                }
                Seen::Frame(Frame::Control { payload }) => match ControlMessage::decode(&payload) {
                    Ok(ControlMessage::CodeAbort { code, .. }) => {
                        break format!("code_abort:{}", code.name())
                    }
                    Ok(ControlMessage::Hello { .. }) => {}
                    Ok(m) => noted.push(control_word(&m)),
                    Err(e) => noted.push(format!("bad control {e:?}")),
                },
                // Any stream frame means the host let our stream frame
                // through its gate (a RESET too: the gate passed it on).
                Seen::Frame(f) => noted.push(format!("stream frame {f:?}")),
                Seen::Closed(why) => break format!("closed ({why})"),
                Seen::Nothing => break "open".into(),
            }
        };
        Ending {
            end,
            noted,
            elapsed: start.elapsed(),
        }
    }

    /// Wait for the host's `AUTHORIZED`; returns its state word, or how the
    /// connection ended instead.
    pub async fn authorized(&mut self, wait: Duration) -> Result<String, String> {
        let until = Instant::now() + wait;
        loop {
            match self.next(until).await {
                Seen::Frame(Frame::Control { payload }) => match ControlMessage::decode(&payload) {
                    Ok(ControlMessage::Authorized { state }) => {
                        return Ok(format!("{state:?}").to_lowercase())
                    }
                    Ok(_) => {}
                    Err(e) => return Err(format!("bad control {e:?}")),
                },
                Seen::Frame(Frame::GoAway { code }) => {
                    return Err(format!("goaway:{}", code.name()))
                }
                Seen::Frame(Frame::Ping { opaque }) => {
                    let _ = self.send(&Frame::Pong { opaque }).await;
                }
                Seen::Frame(_) => {}
                Seen::Closed(why) => return Err(format!("closed ({why})")),
                Seen::Nothing => return Err("no AUTHORIZED".into()),
            }
        }
    }

    /// Wait for the host's answer to a proof: a second `AUTHORIZED` after
    /// step 2's notice when the identity was live, or the first otherwise.
    pub async fn answer_to_proof(&mut self, wait: Duration) -> Result<String, String> {
        let first = self.authorized(wait).await?;
        if first == "live" {
            return self.authorized(wait).await;
        }
        Ok(first)
    }

    /// Bytes the host sent on `stream` until it ended the stream, the
    /// connection, or `wait` passed.
    pub async fn stream_bytes(&mut self, stream: StreamId, wait: Duration) -> (Vec<u8>, String) {
        let until = Instant::now() + wait;
        let mut got = Vec::new();
        loop {
            match self.next(until).await {
                Seen::Frame(Frame::Data { stream: s, payload }) if s == stream => {
                    got.extend_from_slice(&payload);
                    if super::tunnel::complete(&got) {
                        return (got, "message".into());
                    }
                }
                Seen::Frame(Frame::Fin { stream: s }) if s == stream => return (got, "fin".into()),
                Seen::Frame(Frame::Reset { stream: s, code }) if s == stream => {
                    return (got, format!("reset:{}", code.name()))
                }
                Seen::Frame(Frame::GoAway { code }) => {
                    return (got, format!("goaway:{}", code.name()))
                }
                Seen::Frame(Frame::Ping { opaque }) => {
                    let _ = self.send(&Frame::Pong { opaque }).await;
                }
                Seen::Frame(_) => {}
                Seen::Closed(why) => return (got, format!("closed ({why})")),
                Seen::Nothing => return (got, "open".into()),
            }
        }
    }

    /// Say goodbye, so the host's counters settle quickly.
    pub async fn goodbye(mut self) {
        let _ = self
            .send(&Frame::GoAway {
                code: ErrorCode::NoError,
            })
            .await;
        let _ = self.io.shutdown().await;
    }
}

fn control_word(m: &ControlMessage) -> String {
    match m {
        ControlMessage::Hello { .. } => "hello".into(),
        ControlMessage::Authorized { state } => format!("authorized:{state:?}").to_lowercase(),
        other => format!("{other:?}"),
    }
}

/// Read what a host sends a client whose TLS it must refuse: the end of the
/// pipe, or (wrongly) the first mux frame. TLS 1.3 lets a client finish its
/// side before the host has checked the client's certificate, so a refusal
/// can arrive as an alert on the first read.
pub async fn refused_after_handshake(raw: &mut Raw, wait: Duration) -> String {
    let _ = raw.hello().await;
    match raw.next(Instant::now() + wait).await {
        Seen::Frame(f) => format!("frame {f:?}"),
        Seen::Closed(_) => "tls_refused".into(),
        Seen::Nothing => "open".into(),
    }
}

/// Send bytes that are not TLS and see what comes back: the pipe should
/// close, with at most a TLS alert before it.
pub async fn not_tls(mut pipe: BoxPipe, wait: Duration) -> String {
    // 0x00 is no TLS content type, so any TLS server stops at the first byte.
    if pipe
        .write_all(b"\x00\x00mousse-check: these bytes are not TLS\r\n")
        .await
        .is_err()
    {
        return "tls_refused".into();
    }
    let until = Instant::now() + wait;
    let mut got = Vec::new();
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return "open".into();
        }
        let mut chunk = [0u8; 1024];
        match tokio::time::timeout(left, pipe.read(&mut chunk)).await {
            Err(_) => return "open".into(),
            Ok(Ok(0)) | Ok(Err(_)) => {
                // Only an alert record (content type 21) may come first.
                return if got.is_empty() || got[0] == 21 {
                    "tls_refused".into()
                } else {
                    format!("{} bytes that are not a TLS alert", got.len())
                };
            }
            Ok(Ok(n)) => got.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Offer TLS 1.2 only, with a ClientHello written by hand (the kit's rustls
/// is built without TLS 1.2, like the engine's), and report the answer: a
/// TLS 1.3-only host sends an alert or closes.
pub async fn tls12_only(mut pipe: BoxPipe, wait: Duration) -> String {
    if pipe.write_all(&tls12_client_hello()).await.is_err() {
        return "tls_refused".into();
    }
    let mut first = [0u8; 1];
    match tokio::time::timeout(wait, pipe.read(&mut first)).await {
        Err(_) => "open".into(),
        Ok(Ok(0)) | Ok(Err(_)) => "tls_refused".into(),
        // 21: alert. 22 would be a ServerHello: the host spoke TLS 1.2.
        Ok(Ok(_)) if first[0] == 21 => "tls_refused".into(),
        Ok(Ok(_)) => format!("TLS record type {} (TLS 1.2 accepted)", first[0]),
    }
}

/// A TLS 1.2 ClientHello: no `supported_versions`, ECDHE suites, P-256 and
/// X25519, ECDSA P-256 signatures, ALPN `mousse/1`.
pub fn tls12_client_hello() -> Vec<u8> {
    fn ext(id: u16, body: &[u8]) -> Vec<u8> {
        let mut e = id.to_be_bytes().to_vec();
        e.extend_from_slice(&(body.len() as u16).to_be_bytes());
        e.extend_from_slice(body);
        e
    }
    let mut exts = Vec::new();
    // supported_groups: x25519, secp256r1.
    exts.extend(ext(10, &[0, 4, 0x00, 0x1d, 0x00, 0x17]));
    // ec_point_formats: uncompressed.
    exts.extend(ext(11, &[1, 0]));
    // signature_algorithms: ecdsa_secp256r1_sha256.
    exts.extend(ext(13, &[0, 2, 0x04, 0x03]));
    // ALPN: mousse/1.
    let mut alpn = vec![ALPN.len() as u8];
    alpn.extend_from_slice(ALPN);
    let mut list = (alpn.len() as u16).to_be_bytes().to_vec();
    list.extend(alpn);
    exts.extend(ext(16, &list));
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&mousse_net_io::rng::random_bytes::<32>());
    body.push(0); // no session id
    body.extend_from_slice(&[0, 4, 0xc0, 0x2b, 0xc0, 0x2f]);
    body.extend_from_slice(&[1, 0]); // null compression
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend(exts);
    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend(body);
    let mut rec = vec![22, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    rec
}

fn wrong_config(device: &Device, mode: TlsMode) -> Result<Arc<ClientConfig>, String> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServer));
    let mut config = match mode {
        TlsMode::NoCert => builder.with_no_client_auth(),
        _ => builder.with_client_cert_resolver(tls::client_cert_resolver(&device.cert)),
    };
    config.alpn_protocols = match mode {
        TlsMode::WrongAlpn => vec![b"http/1.1".to_vec()],
        _ => vec![ALPN.to_vec()],
    };
    config.enable_sni = false;
    Ok(Arc::new(config))
}

/// Accepts any server: only for handshakes the host must refuse anyway.
#[derive(Debug)]
struct AnyServer;

impl ServerCertVerifier for AnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// One silent connection (the admission case): TCP for tcp and ws (the
/// slot is taken at accept), an ssh session past its marker for ssh.
pub async fn silent(target: &Target, waits: &Waits) -> Result<BoxPipe, String> {
    match target.addr() {
        Some(a) => Ok(Box::new(tcp(a, waits).await?)),
        None => target.pipe(waits).await,
    }
}

/// Whether a silent connection was closed by the host within `wait`.
pub async fn closed_within<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, wait: Duration) -> bool {
    let mut b = [0u8; 64];
    matches!(
        tokio::time::timeout(wait, s.read(&mut b)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

impl Waits {
    pub fn tls(&self) -> TlsPolicy {
        TlsPolicy::default()
    }
}
