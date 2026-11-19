//! The outer connection to a relay (§B.2): TLS 1.3 pinned to the relay id,
//! the hybrid key exchange required, a WebSocket on `/mousse-relay/1` with
//! the `mousse-relay.1` subprotocol, binary messages only.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::Duration;

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mousse_net_core::identity::{PublicKey, RawSignature, SoftwareKey};
use mousse_net_core::relay_wire::{
    certificate_key, relay_id, Binding, CloseCode, Mode, RelayId, RelayMessage, RELAY_ALPN,
    RELAY_EXPORTER_LABEL, RELAY_MESSAGE_MAX, RELAY_PATH, RELAY_SUBPROTOCOL, RELAY_VERSION,
    WS_MESSAGE_MAX,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::Resumption;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime as PkiTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, NamedGroup, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use super::RelayError;
use crate::tls::{provider, SCHEME};

/// Most bytes written per WebSocket message once spliced.
pub const WRITE_CHUNK: usize = 16 * 1024;

/// Where to dial a relay: the classified address, and the name for SNI
/// when it was a DNS name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayAddr {
    /// The address dialled.
    pub addr: SocketAddr,
    /// The DNS name it was resolved from, if any.
    pub name: Option<String>,
}

/// The WebSocket limits on every relay connection.
pub fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(WS_MESSAGE_MAX))
        .max_frame_size(Some(WS_MESSAGE_MAX))
}

/// Client side: the relay's certificate key must hash to the pinned id,
/// and it must sign the handshake. The chain, the name and the dates are
/// ignored.
#[derive(Debug)]
struct RelayPin(RelayId);

fn pinned_key(pin: &RelayId, cert: &CertificateDer<'_>) -> Result<PublicKey, TlsError> {
    let key = certificate_key(cert.as_ref()).ok_or(TlsError::InvalidCertificate(
        rustls::CertificateError::BadEncoding,
    ))?;
    #[cfg(not(mousse_control = "no-pin-relay"))]
    if relay_id(&key) != *pin {
        return Err(TlsError::General(RELAY_PIN_MISMATCH.into()));
    }
    #[cfg(mousse_control = "no-pin-relay")]
    let _ = pin;
    Ok(key)
}

const RELAY_PIN_MISMATCH: &str = "relay key is not the pinned relay";

impl ServerCertVerifier for RelayPin {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: PkiTime,
    ) -> Result<ServerCertVerified, TlsError> {
        pinned_key(&self.0, end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 is not allowed".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        if dss.scheme != SCHEME {
            return Err(TlsError::PeerMisbehaved(
                rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ));
        }
        let key = pinned_key(&self.0, cert)?;
        let sig = RawSignature::from_der(dss.signature())
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadSignature))?;
        key.verify(message, &sig)
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadSignature))?;
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SCHEME]
    }
}

fn client_config(pin: RelayId) -> Result<Arc<ClientConfig>, RelayError> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| RelayError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RelayPin(pin)))
        .with_no_client_auth();
    config.alpn_protocols = vec![RELAY_ALPN.to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

type ClientTls = tokio_rustls::client::TlsStream<TcpStream>;

/// One outer connection to a relay, before it is spliced: relay messages
/// one per WebSocket message.
pub struct RelayLink<S = ClientTls> {
    ws: WebSocketStream<S>,
    binding: Binding,
    mode: Mode,
    boot_id: [u8; 16],
}

impl<S> fmt::Debug for RelayLink<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelayLink({:?})", self.mode)
    }
}

impl RelayLink<ClientTls> {
    /// Dial the relay pinned as `relay` at `addr`, upgrade, and read
    /// `RELAY_HELLO`, all within `within`. A wrong relay key fails before
    /// any relay message.
    pub async fn connect(
        addr: &RelayAddr,
        relay: RelayId,
        within: Duration,
    ) -> Result<Self, RelayError> {
        tokio::time::timeout(within, Self::connect_inner(addr, relay))
            .await
            .map_err(|_| RelayError::Timeout)?
    }

    async fn connect_inner(addr: &RelayAddr, relay: RelayId) -> Result<Self, RelayError> {
        let tcp = TcpStream::connect(addr.addr)
            .await
            .map_err(RelayError::Io)?;
        tcp.set_nodelay(true).map_err(RelayError::Io)?;
        let name = match &addr.name {
            Some(name) => {
                ServerName::try_from(name.clone()).map_err(|e| RelayError::Tls(e.to_string()))?
            }
            None => ServerName::IpAddress(addr.addr.ip().into()),
        };
        let tls = TlsConnector::from(client_config(relay)?)
            .connect(name, tcp)
            .await
            .map_err(|e| {
                let text = e.to_string();
                if text.contains(RELAY_PIN_MISMATCH) {
                    RelayError::WrongRelay
                } else {
                    RelayError::Tls(text)
                }
            })?;
        let conn = tls.get_ref().1;
        let group = conn.negotiated_key_exchange_group().map(|g| g.name());
        if group != Some(NamedGroup::X25519MLKEM768) {
            return Err(RelayError::Tls(format!(
                "key exchange {group:?} is not the hybrid group"
            )));
        }
        if conn.alpn_protocol() != Some(RELAY_ALPN) {
            return Err(RelayError::Tls("ALPN http/1.1 was not negotiated".into()));
        }
        let mut exporter = [0u8; 32];
        conn.export_keying_material(&mut exporter, RELAY_EXPORTER_LABEL.as_bytes(), None)
            .map_err(|e| RelayError::Tls(e.to_string()))?;
        let host = match &addr.name {
            Some(name) => format!("{name}:{}", addr.addr.port()),
            None => addr.addr.to_string(),
        };
        let mut request = format!("wss://{host}{RELAY_PATH}")
            .into_client_request()
            .map_err(|e| RelayError::Upgrade(e.to_string()))?;
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static(RELAY_SUBPROTOCOL),
        );
        let (ws, response) =
            tokio_tungstenite::client_async_with_config(request, tls, Some(ws_config()))
                .await
                .map_err(|e| RelayError::Upgrade(e.to_string()))?;
        let chosen = response
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|v| v.to_str().ok());
        if chosen != Some(RELAY_SUBPROTOCOL) {
            return Err(RelayError::Upgrade(
                "the relay did not select mousse-relay.1".into(),
            ));
        }
        let mut link = RelayLink {
            ws,
            binding: Binding {
                relay,
                nonce: [0; 32],
                exporter,
            },
            mode: Mode::SelfHosted,
            boot_id: [0; 16],
        };
        match link.recv().await? {
            RelayMessage::Hello {
                version,
                nonce,
                boot_id,
                mode,
            } if version == RELAY_VERSION => {
                link.binding.nonce = nonce;
                link.mode = mode;
                link.boot_id = boot_id;
                Ok(link)
            }
            RelayMessage::Hello { version, .. } => {
                Err(RelayError::Protocol(format!("relay version {version}")))
            }
            other => Err(RelayError::Protocol(format!(
                "expected RELAY_HELLO, got type {}",
                other.kind()
            ))),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> RelayLink<S> {
    /// A link on an accepted connection (the relay side), with its binding.
    pub fn from_parts(ws: WebSocketStream<S>, binding: Binding, mode: Mode) -> Self {
        Self {
            ws,
            binding,
            mode,
            boot_id: [0; 16],
        }
    }

    /// What this connection's proofs are bound to.
    pub fn binding(&self) -> Binding {
        self.binding
    }

    /// The relay's mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The relay's boot id.
    pub fn boot_id(&self) -> [u8; 16] {
        self.boot_id
    }

    /// Send one relay message.
    pub async fn send(&mut self, msg: &RelayMessage) -> Result<(), RelayError> {
        self.ws
            .send(Message::binary(msg.encode()))
            .await
            .map_err(|e| RelayError::Io(io::Error::other(e)))
    }

    /// The next relay message. A close from the relay is
    /// [`RelayError::Closed`] with its code.
    pub async fn recv(&mut self) -> Result<RelayMessage, RelayError> {
        loop {
            match self.ws.next().await {
                Some(Ok(Message::Binary(b))) => {
                    if b.len() > RELAY_MESSAGE_MAX {
                        return Err(RelayError::Protocol("relay message too large".into()));
                    }
                    return RelayMessage::decode(&b)
                        .map_err(|e| RelayError::Protocol(e.to_string()));
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                Some(Ok(Message::Text(_))) => {
                    return Err(RelayError::Protocol("text message".into()))
                }
                Some(Ok(Message::Close(frame))) => {
                    return Err(RelayError::Closed(frame.map(|f| u16::from(f.code))))
                }
                Some(Err(e)) => return Err(RelayError::Io(io::Error::other(e))),
                None => return Err(RelayError::Closed(None)),
            }
        }
    }

    /// Close with a code.
    pub async fn close(&mut self, code: u16) {
        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode as WsCode;
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        let _ = self
            .ws
            .close(Some(CloseFrame {
                code: WsCode::from(code),
                reason: "".into(),
            }))
            .await;
    }

    /// After `SPLICED`: the connection as a byte pipe for the peer TLS.
    pub fn into_pipe(self) -> WsPipe<S> {
        WsPipe::new(self.ws)
    }

    /// The WebSocket, for splicing on the relay side.
    pub fn into_ws(self) -> WebSocketStream<S> {
        self.ws
    }
}

/// How a spliced relay connection ended, once it has.
#[derive(Clone, Default, Debug)]
pub struct CloseWatch(Arc<Mutex<Option<u16>>>);

impl CloseWatch {
    /// The relay's close code, if one arrived.
    pub fn code(&self) -> Option<u16> {
        *self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The close code as ours, if it is one.
    pub fn reason(&self) -> Option<CloseCode> {
        self.code().and_then(CloseCode::from_code)
    }

    fn set(&self, code: u16) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(code);
    }
}

/// A spliced relay connection as a byte stream: each WebSocket message's
/// payload in order, writes in messages of at most [`WRITE_CHUNK`] bytes.
pub struct WsPipe<S = ClientTls> {
    ws: WebSocketStream<S>,
    pending: Vec<u8>,
    at: usize,
    eof: bool,
    closed: CloseWatch,
}

impl<S> fmt::Debug for WsPipe<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WsPipe")
    }
}

impl<S> WsPipe<S> {
    fn new(ws: WebSocketStream<S>) -> Self {
        Self {
            ws,
            pending: Vec::new(),
            at: 0,
            eof: false,
            closed: CloseWatch::default(),
        }
    }

    /// Where the relay's close code appears.
    pub fn close_watch(&self) -> CloseWatch {
        self.closed.clone()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsPipe<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.at < this.pending.len() {
                let n = buf.remaining().min(this.pending.len() - this.at);
                buf.put_slice(&this.pending[this.at..this.at + n]);
                this.at += n;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut this.ws).poll_next(cx)) {
                Some(Ok(Message::Binary(b))) => {
                    this.pending = b.into();
                    this.at = 0;
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "text message on a relay circuit",
                    )))
                }
                Some(Ok(Message::Close(frame))) => {
                    if let Some(f) = frame {
                        this.closed.set(u16::from(f.code));
                    }
                    this.eof = true;
                }
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => this.eof = true,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsPipe<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let ws = &mut self.ws;
        ready!(Pin::new(&mut *ws).poll_ready(cx)).map_err(io::Error::other)?;
        let n = buf.len().min(WRITE_CHUNK);
        Pin::new(&mut *ws)
            .start_send(Message::binary(buf[..n].to_vec()))
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}

/// A relay's identity key as a rustls signing key, for the relay side of
/// the outer TLS.
pub struct RelaySigningKey(Arc<SoftwareKey>);

impl RelaySigningKey {
    /// Sign the outer TLS with `key`.
    pub fn new(key: Arc<SoftwareKey>) -> Self {
        Self(key)
    }
}

impl fmt::Debug for RelaySigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelaySigningKey(..)")
    }
}

impl rustls::sign::SigningKey for RelaySigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        offered
            .contains(&SCHEME)
            .then(|| Box::new(RelaySigner(self.0.clone())) as Box<dyn rustls::sign::Signer>)
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}

struct RelaySigner(Arc<SoftwareKey>);

impl fmt::Debug for RelaySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelaySigner(..)")
    }
}

impl rustls::sign::Signer for RelaySigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TlsError> {
        Ok(self.0.sign_raw(message).to_der())
    }

    fn scheme(&self) -> SignatureScheme {
        SCHEME
    }
}
