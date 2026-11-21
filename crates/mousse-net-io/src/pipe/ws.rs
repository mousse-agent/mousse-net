//! `ws` and `wss` pipes (Phase 1b §4): the session's TLS byte stream
//! carried in WebSocket binary messages, through a tunnel the host's owner
//! runs.
//!
//! - **Host:** a loopback listener for the owner's tunnel client. Each
//!   connection holds a ws pre-auth place from accept; [`accept`] reads the
//!   upgrade request itself within `WS_UPGRADE_WAIT_MS` and
//!   `WS_HEADER_MAX_BYTES`, then checks, in order: method `GET`, the path
//!   suffix (else 404), no `Origin` (else 403), the `mousse.1` subprotocol
//!   (else 400) and the admission fence (else 503).
//! - **Caller:** [`dial`] connects to an address the caller already
//!   classified (§1.2). `wss` runs an outer TLS client with the platform
//!   verifier and SNI equal to the route's host; that outer TLS only gets
//!   through the tunnel, the pinned session TLS runs inside. Plain `ws` goes
//!   only to loopback, the local hop of a tunnel client.
//! - **Messages:** binary only (a text message closes with 1003), at most
//!   `WS_MESSAGE_MAX_BYTES` each, no compression; at most 16 KiB written per
//!   message. Pings are answered by the library.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use futures_core::Stream;
use futures_sink::Sink;
use mousse_net_core::pairing::{Route, RouteHost, WSS_PATH_SUFFIX};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::WebSocketStream;

use crate::error::NetError;
use crate::limits::{ms, IoLimits};

/// The one subprotocol, offered by the caller and selected by the host.
pub const SUBPROTOCOL: &str = "mousse.1";

/// Most bytes written in one message.
pub const WRITE_MESSAGE_MAX_BYTES: usize = 16 * 1024;

/// The debug-only extra root for the outer `wss` TLS: a DER certificate
/// file (§4.2). Release builds never read it.
pub const TEST_EXTRA_ROOT_VAR: &str = "MOUSSE_NET_TEST_EXTRA_ROOT";

/// A `ws` or `wss` destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WsTarget {
    /// `wss` (outer TLS) or plain `ws`.
    pub secure: bool,
    /// The host, also the outer TLS name and the `Host` header.
    pub host: RouteHost,
    /// The TCP port.
    pub port: u16,
    /// The request path, ending in `/mousse-net/1`.
    pub path: String,
}

impl WsTarget {
    /// The target of a `wss` route.
    pub fn from_route(route: &Route) -> Option<Self> {
        match route {
            Route::Wss { host, port, path } => Some(Self {
                secure: true,
                host: host.clone(),
                port: *port,
                path: path.clone(),
            }),
            _ => None,
        }
    }

    /// An owner-entered `ws://` or `wss://` address. A plain `ws` host must
    /// be a loopback literal and needs a port (§1.1).
    pub fn parse(text: &str) -> Option<Self> {
        if text.starts_with("wss:") {
            return Route::parse(text).ok().as_ref().and_then(Self::from_route);
        }
        let rest = text.strip_prefix("ws:")?;
        // The `wss` grammar, and an explicit port.
        let authority = rest.strip_prefix("//")?.split('/').next()?;
        let has_port = match authority.strip_prefix('[') {
            Some(v6) => v6.contains("]:"),
            None => authority.contains(':'),
        };
        let mut target = Route::parse(&format!("wss:{rest}"))
            .ok()
            .as_ref()
            .and_then(Self::from_route)?;
        let loopback = match &target.host {
            RouteHost::Ipv4(ip) => ip.is_loopback(),
            RouteHost::Ipv6(ip) => ip.is_loopback(),
            RouteHost::Dns(_) => false,
        };
        if !has_port || !loopback {
            return None;
        }
        target.secure = false;
        Some(target)
    }

    fn authority(&self) -> String {
        match &self.host {
            RouteHost::Ipv4(ip) => format!("{ip}:{}", self.port),
            RouteHost::Ipv6(ip) => format!("[{ip}]:{}", self.port),
            RouteHost::Dns(name) => format!("{name}:{}", self.port),
        }
    }

    /// The canonical text: scheme, lower-case host, explicit port, path.
    pub fn uri(&self) -> String {
        let scheme = if self.secure { "wss" } else { "ws" };
        format!("{scheme}://{}{}", self.authority(), self.path)
    }
}

fn config(limits: &IoLimits) -> WebSocketConfig {
    let max = usize::try_from(limits.ws_message_max_bytes()).unwrap_or(usize::MAX);
    WebSocketConfig::default()
        // Each message goes out when it is sent; the session's TLS layer
        // does its own batching.
        .write_buffer_size(0)
        .max_message_size(Some(max))
        .max_frame_size(Some(max))
}

fn io_error(e: WsError) -> io::Error {
    match e {
        WsError::Io(e) => e,
        WsError::ConnectionClosed | WsError::AlreadyClosed => {
            io::Error::new(io::ErrorKind::BrokenPipe, "the ws connection closed")
        }
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}

/// Where a text message's refusal stands.
enum Refuse {
    /// The 1003 close is still to be queued.
    Send(CloseFrame),
    /// It is queued; flush it, then fail the read.
    Flush,
}

/// A WebSocket as a byte stream.
pub struct WsPipe<S> {
    ws: WebSocketStream<S>,
    /// A received message not read out yet, and how far it was read.
    unread: Option<(tokio_tungstenite::tungstenite::Bytes, usize)>,
    /// A text message arrived: the 1003 close still to send, or to flush,
    /// before the read fails. Kept across `Pending`.
    refuse: Option<Refuse>,
    eof: bool,
}

impl<S> WsPipe<S> {
    fn new(ws: WebSocketStream<S>) -> Self {
        Self {
            ws,
            unread: None,
            refuse: None,
            eof: false,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsPipe<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some((bytes, at)) = &mut this.unread {
                let n = buf.remaining().min(bytes.len() - *at);
                buf.put_slice(&bytes[*at..*at + n]);
                *at += n;
                if *at == bytes.len() {
                    this.unread = None;
                }
                return Poll::Ready(Ok(()));
            }
            match this.refuse.take() {
                // A text message: close with 1003, then fail the read.
                Some(Refuse::Send(frame)) => {
                    let mut ws = Pin::new(&mut this.ws);
                    match ws.as_mut().poll_ready(cx) {
                        Poll::Pending => {
                            this.refuse = Some(Refuse::Send(frame));
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(io_error(e))),
                        Poll::Ready(Ok(())) => {}
                    }
                    let _ = ws.start_send(Message::Close(Some(frame)));
                    this.refuse = Some(Refuse::Flush);
                    continue;
                }
                Some(Refuse::Flush) => {
                    if Pin::new(&mut this.ws).poll_flush(cx).is_pending() {
                        this.refuse = Some(Refuse::Flush);
                        return Poll::Pending;
                    }
                    this.eof = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "a ws text message",
                    )));
                }
                None => {}
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut this.ws).poll_next(cx)) {
                None | Some(Ok(Message::Close(_))) => this.eof = true,
                Some(Ok(Message::Binary(bytes))) => {
                    if !bytes.is_empty() {
                        this.unread = Some((bytes, 0));
                    }
                }
                Some(Ok(Message::Text(_))) => {
                    this.refuse = Some(Refuse::Send(CloseFrame {
                        code: CloseCode::Unsupported,
                        reason: "binary messages only".into(),
                    }));
                }
                // Pings are answered by the library; pongs and raw frames
                // carry nothing.
                Some(Ok(_)) => {}
                Some(Err(e)) => return Poll::Ready(Err(io_error(e))),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsPipe<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut ws = Pin::new(&mut self.get_mut().ws);
        ready!(ws.as_mut().poll_ready(cx)).map_err(io_error)?;
        let n = buf.len().min(WRITE_MESSAGE_MAX_BYTES);
        ws.start_send(Message::binary(buf[..n].to_vec()))
            .map_err(io_error)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().ws)
            .poll_flush(cx)
            .map_err(io_error)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match ready!(Pin::new(&mut self.get_mut().ws).poll_close(cx)) {
            Ok(()) | Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io_error(e))),
        }
    }
}

/// A stream that first gives back bytes already read from it.
pub struct Replay<S> {
    head: Vec<u8>,
    at: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.at < this.head.len() {
            let n = buf.remaining().min(this.head.len() - this.at);
            buf.put_slice(&this.head[this.at..this.at + n]);
            this.at += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Why [`accept`] gave no pipe.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Closed with no answer: the request was too slow or too large, or
    /// not HTTP.
    Closed(&'static str),
    /// Answered with this status.
    Status(u16),
    /// The library refused the upgrade (bad WebSocket headers).
    Upgrade(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(why) => write!(f, "closed: {why}"),
            Self::Status(code) => write!(f, "answered {code}"),
            Self::Upgrade(why) => write!(f, "upgrade refused: {why}"),
        }
    }
}

fn status_line(code: u16) -> &'static str {
    match code {
        400 => "400 Bad Request",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        405 => "405 Method Not Allowed",
        _ => "503 Service Unavailable",
    }
}

/// Read the upgrade request up to its blank line, within the caps.
async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    max: usize,
) -> Result<Vec<u8>, Refusal> {
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|_| Refusal::Closed("read failed"))?;
        if n == 0 {
            return Err(Refusal::Closed("ended before the request did"));
        }
        let from = head.len().saturating_sub(3);
        head.extend_from_slice(&chunk[..n]);
        let end = head[from..]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| from + i + 4);
        match end {
            Some(end) if end <= max => return Ok(head),
            Some(_) => return Err(Refusal::Closed("upgrade request past WS_HEADER_MAX_BYTES")),
            None if head.len() > max => {
                return Err(Refusal::Closed("upgrade request past WS_HEADER_MAX_BYTES"))
            }
            None => {}
        }
    }
}

/// Check the parsed request (§4.1 steps 1 to 4); the status to answer.
fn check_request(head: &[u8]) -> Result<(), Refusal> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(Refusal::Closed("not an HTTP request")),
    }
    if req.method != Some("GET") {
        return Err(Refusal::Status(405));
    }
    if !req.path.is_some_and(|p| p.ends_with(WSS_PATH_SUFFIX)) {
        return Err(Refusal::Status(404));
    }
    let headers: &[httparse::Header<'_>] = req.headers;
    let named = |name: &'static str| {
        headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
    };
    // Control (tests only): a browser's request gets through.
    if named("origin").next().is_some() && !cfg!(mousse_control = "ws-allow-origin") {
        return Err(Refusal::Status(403));
    }
    let offered = named("sec-websocket-protocol").any(|h| {
        std::str::from_utf8(h.value)
            .map(|v| v.split(',').any(|p| p.trim() == SUBPROTOCOL))
            .unwrap_or(false)
    });
    if !offered {
        return Err(Refusal::Status(400));
    }
    Ok(())
}

/// Select `mousse.1` in the upgrade answer; [`check_request`] already saw
/// it offered.
#[allow(clippy::result_large_err)] // The library's callback type.
fn select_subprotocol(_: &Request, mut response: Response) -> Result<Response, ErrorResponse> {
    response.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(SUBPROTOCOL),
    );
    Ok(response)
}

/// The host side of one `ws` connection, already holding its pre-auth
/// place. `fenced` is asked last, after the request passed its checks.
/// On a refusal the socket is answered (when there is a status) and
/// closed.
pub async fn accept<S>(
    mut stream: S,
    limits: &IoLimits,
    fenced: impl FnOnce() -> bool,
) -> Result<WsPipe<Replay<S>>, Refusal>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let max = usize::try_from(limits.ws_header_max_bytes()).unwrap_or(usize::MAX);
    let wait = ms(limits.ws_upgrade_wait_ms());
    let head = match tokio::time::timeout(wait, read_request(&mut stream, max)).await {
        Ok(Ok(head)) => head,
        Ok(Err(refusal)) => return Err(refusal),
        Err(_) => return Err(Refusal::Closed("upgrade request past WS_UPGRADE_WAIT_MS")),
    };
    let checked = check_request(&head).and_then(|()| {
        if fenced() {
            Err(Refusal::Status(503))
        } else {
            Ok(())
        }
    });
    if let Err(refusal) = checked {
        if let Refusal::Status(code) = refusal {
            let answer = format!(
                "HTTP/1.1 {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                status_line(code)
            );
            let _ = stream.write_all(answer.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
        return Err(refusal);
    }
    let replay = Replay {
        head,
        at: 0,
        inner: stream,
    };
    let upgrade = tokio_tungstenite::accept_hdr_async_with_config(
        replay,
        select_subprotocol,
        Some(config(limits)),
    );
    match tokio::time::timeout(wait, upgrade).await {
        Ok(Ok(ws)) => Ok(WsPipe::new(ws)),
        Ok(Err(e)) => Err(Refusal::Upgrade(e.to_string())),
        Err(_) => Err(Refusal::Closed("upgrade past WS_UPGRADE_WAIT_MS")),
    }
}

/// Whether a build reads [`TEST_EXTRA_ROOT_VAR`]: debug builds only.
pub fn reads_test_root(release: bool) -> bool {
    // Control (tests only): release builds read it too.
    !release || cfg!(mousse_control = "release-test-root")
}

fn extra_root() -> Result<Option<CertificateDer<'static>>, NetError> {
    if !reads_test_root(!cfg!(debug_assertions)) {
        return Ok(None);
    }
    let Some(path) = std::env::var_os(TEST_EXTRA_ROOT_VAR) else {
        return Ok(None);
    };
    let der = std::fs::read(&path).map_err(|e| {
        NetError::Refused(format!(
            "{TEST_EXTRA_ROOT_VAR} {}: {e}",
            path.to_string_lossy()
        ))
    })?;
    Ok(Some(CertificateDer::from(der)))
}

/// The outer TLS client: the platform verifier, plus the test root in
/// debug builds; ALPN `http/1.1`.
fn outer_tls() -> Result<Arc<rustls::ClientConfig>, NetError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = match extra_root()? {
        Some(root) => {
            rustls_platform_verifier::Verifier::new_with_extra_roots([root], provider.clone())
        }
        None => rustls_platform_verifier::Verifier::new(provider.clone()),
    }
    .map_err(|e| NetError::Refused(format!("outer TLS: {e}")))?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| NetError::Refused(format!("outer TLS: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// The caller's transport under the WebSocket.
pub enum Outer {
    /// Plain `ws` to loopback.
    Plain(TcpStream),
    /// `wss`.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Outer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Outer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Dial `target` at `addr`, an address the caller classified from the
/// target's host (§1.2; a name is never resolved again here). The caller
/// bounds the whole try, step 1 included, by `WS_DIAL_TIMEOUT_MS`.
pub async fn dial(
    target: &WsTarget,
    addr: SocketAddr,
    limits: &IoLimits,
) -> Result<WsPipe<Outer>, NetError> {
    // Control (tests only): plain ws leaves this computer.
    if !target.secure && !addr.ip().is_loopback() && !cfg!(mousse_control = "plain-ws-off-loopback")
    {
        return Err(NetError::Refused(format!(
            "plain ws goes only to a loopback address, not {addr}"
        )));
    }
    super::test_egress::check_ip(addr.ip(), addr.port())?;
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let outer = if target.secure {
        let name = match &target.host {
            RouteHost::Dns(name) => ServerName::try_from(name.clone())
                .map_err(|e| NetError::Refused(format!("outer TLS name: {e}")))?,
            RouteHost::Ipv4(ip) => ServerName::IpAddress(std::net::IpAddr::V4(*ip).into()),
            RouteHost::Ipv6(ip) => ServerName::IpAddress(std::net::IpAddr::V6(*ip).into()),
        };
        let tls = tokio_rustls::TlsConnector::from(outer_tls()?)
            .connect(name, tcp)
            .await?;
        Outer::Tls(Box::new(tls))
    } else {
        Outer::Plain(tcp)
    };
    let mut request = target
        .uri()
        .into_client_request()
        .map_err(|e| NetError::Refused(format!("ws request: {e}")))?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(SUBPROTOCOL),
    );
    match tokio_tungstenite::client_async_with_config(request, outer, Some(config(limits))).await {
        Ok((ws, response)) => {
            let selected = response
                .headers()
                .get("Sec-WebSocket-Protocol")
                .is_some_and(|v| v.as_bytes() == SUBPROTOCOL.as_bytes());
            if !selected {
                return Err(NetError::Refused(
                    "ws: the host did not select mousse.1".into(),
                ));
            }
            Ok(WsPipe::new(ws))
        }
        Err(WsError::Http(response)) if response.status().is_redirection() => {
            Err(NetError::Refused("ws_redirect".into()))
        }
        Err(WsError::Http(response)) => Err(NetError::Refused(format!(
            "ws upgrade refused: {}",
            response.status().as_u16()
        ))),
        Err(e) => Err(NetError::Refused(format!("ws upgrade: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::protocol::Role;

    /// A stream whose first `stalls` writes are not ready yet.
    struct StallFirstWrite<S> {
        inner: S,
        stalls: u32,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for StallFirstWrite<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for StallFirstWrite<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.stalls > 0 {
                this.stalls -= 1;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// A text message is refused with a 1003 close even when the close
    /// cannot be written at once: the refusal survives `Pending`.
    #[tokio::test]
    async fn a_text_message_is_closed_with_1003_through_backpressure() {
        use futures_core::Stream as _;
        let (near, far) = tokio::io::duplex(1 << 16);
        let host = StallFirstWrite {
            inner: near,
            // The queued close's write, then its flush.
            stalls: 2,
        };
        let mut pipe = WsPipe::new(
            WebSocketStream::from_raw_socket(host, Role::Server, Some(config(&IoLimits::DEFAULT)))
                .await,
        );
        let mut peer = WebSocketStream::from_raw_socket(far, Role::Client, None).await;
        Pin::new(&mut peer)
            .start_send(Message::text("hello"))
            .unwrap();
        std::future::poll_fn(|cx| Pin::new(&mut peer).poll_flush(cx))
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let read = tokio::time::timeout(std::time::Duration::from_secs(5), pipe.read(&mut buf))
            .await
            .expect("the read never ended");
        assert!(read.is_err(), "{read:?}");
        let close = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            std::future::poll_fn(|cx| Pin::new(&mut peer).poll_next(cx)),
        )
        .await
        .expect("no close arrived");
        match close {
            Some(Ok(Message::Close(Some(frame)))) => {
                assert_eq!(frame.code, CloseCode::Unsupported)
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn owner_ws_addresses_are_loopback_with_a_port() {
        let ok = WsTarget::parse("ws://127.0.0.1:8080/mousse-net/1").unwrap();
        assert!(!ok.secure);
        assert_eq!(ok.uri(), "ws://127.0.0.1:8080/mousse-net/1");
        assert!(WsTarget::parse("ws://[::1]:9/x/mousse-net/1").is_some());
        for bad in [
            "ws://127.0.0.1/mousse-net/1",
            "ws://192.168.1.2:80/mousse-net/1",
            "ws://localhost:80/mousse-net/1",
            "ws://127.0.0.1:80/other",
        ] {
            assert!(WsTarget::parse(bad).is_none(), "{bad}");
        }
        let tunnel = WsTarget::parse("wss://X.example/mousse-net/1").unwrap();
        assert!(tunnel.secure);
        assert_eq!(tunnel.uri(), "wss://x.example:443/mousse-net/1");
    }
}
