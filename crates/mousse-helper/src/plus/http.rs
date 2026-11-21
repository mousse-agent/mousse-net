//! One HTTP/1.1 request to Plus at a time: TLS 1.3 with the platform
//! verifier and no pin (Plus is not a trust anchor, A.2), one connection
//! per request (`Connection: close`).
//!
//! Debug builds also speak plain HTTP to a loopback origin, for the test
//! stand-in; [`crate::limits::check_plus_url`] refuses it everywhere else.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::proto::{API_VERSION, REQUEST_MAX};

/// A Plus origin, parsed.
#[derive(Clone, Debug)]
pub struct Origin {
    /// `https://host[:port]` as configured.
    pub text: String,
    tls: bool,
    host: String,
    port: u16,
}

impl Origin {
    /// Parse a URL [`crate::limits::check_plus_url`] accepted.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = crate::limits::check_plus_url(text)?;
        let (scheme, authority) = text.split_once("://").ok_or("no scheme")?;
        let tls = scheme == "https";
        let default = if tls { 443 } else { 80 };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or("bad IPv6 address")?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| "bad port")?,
                None => default,
            };
            (h.to_owned(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_owned(), p.parse().map_err(|_| "bad port")?),
                None => (authority.to_owned(), default),
            }
        };
        Ok(Self {
            text,
            tls,
            host,
            port,
        })
    }

    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Why a request got no HTTP answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Connect, TLS, write or read failed, or the answer was malformed.
    Io(String),
    /// No answer within `MOUSSE_NET_PLUS_TIMEOUT_MS`.
    Timeout,
    /// The request body is over `REQUEST_MAX` (a bug; never sent).
    TooLarge,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "Plus could not be reached: {e}"),
            TransportError::Timeout => f.write_str("Plus did not answer in time"),
            TransportError::TooLarge => f.write_str("request too large"),
        }
    }
}

/// An HTTP answer.
#[derive(Debug)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The body.
    pub body: Vec<u8>,
}

/// Sends requests to one Plus origin.
pub struct Transport {
    origin: Origin,
    tls: Option<Arc<rustls::ClientConfig>>,
    timeout: Duration,
    answer_max: usize,
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls_platform_verifier::Verifier::new(provider.clone())
        .map_err(|e| format!("platform verifier: {e}"))?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

impl Transport {
    /// A transport for `origin`.
    pub fn new(origin: Origin) -> Result<Self, String> {
        let tls = if origin.tls {
            Some(tls_config()?)
        } else {
            None
        };
        let limits = crate::limits::helper();
        Ok(Self {
            origin,
            tls,
            timeout: crate::limits::ms(limits.plus_timeout_ms()),
            answer_max: limits.plus_answer_max_bytes() as usize,
        })
    }

    /// The origin.
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// `GET` (no body) or `POST` (a CBOR body) `path`, with an optional
    /// `Authorization` value.
    pub async fn request(
        &self,
        path: &str,
        body: Option<&[u8]>,
        authorization: Option<&str>,
    ) -> Result<Response, TransportError> {
        if body.is_some_and(|b| b.len() > REQUEST_MAX) {
            return Err(TransportError::TooLarge);
        }
        match tokio::time::timeout(self.timeout, self.exchange(path, body, authorization)).await {
            Ok(r) => r,
            Err(_) => Err(TransportError::Timeout),
        }
    }

    async fn exchange(
        &self,
        path: &str,
        body: Option<&[u8]>,
        authorization: Option<&str>,
    ) -> Result<Response, TransportError> {
        let io = |e: std::io::Error| TransportError::Io(e.to_string());
        let tcp = TcpStream::connect((self.origin.host.as_str(), self.origin.port))
            .await
            .map_err(io)?;
        let _ = tcp.set_nodelay(true);
        let request = self.head(path, body, authorization);
        match &self.tls {
            None => send(tcp, &request, body, self.answer_max).await,
            Some(config) => {
                let name = rustls::pki_types::ServerName::try_from(self.origin.host.clone())
                    .map_err(|e| TransportError::Io(e.to_string()))?;
                let stream = tokio_rustls::TlsConnector::from(config.clone())
                    .connect(name, tcp)
                    .await
                    .map_err(io)?;
                send(stream, &request, body, self.answer_max).await
            }
        }
    }

    fn head(&self, path: &str, body: Option<&[u8]>, authorization: Option<&str>) -> String {
        let method = if body.is_some() { "POST" } else { "GET" };
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nMousse-Plus-Api: {API_VERSION}\r\nAccept: application/cbor\r\nConnection: close\r\n",
            self.origin.authority()
        );
        if let Some(auth) = authorization {
            head.push_str(&format!("Authorization: {auth}\r\n"));
        }
        if let Some(b) = body {
            head.push_str(&format!(
                "Content-Type: application/cbor\r\nContent-Length: {}\r\n",
                b.len()
            ));
        }
        head.push_str("\r\n");
        head
    }
}

async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    head: &str,
    body: Option<&[u8]>,
    answer_max: usize,
) -> Result<Response, TransportError> {
    let io = |e: std::io::Error| TransportError::Io(e.to_string());
    let mut out = head.as_bytes().to_vec();
    if let Some(b) = body {
        out.extend_from_slice(b);
    }
    stream.write_all(&out).await.map_err(io)?;
    stream.flush().await.map_err(io)?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16_384];
    loop {
        let n = stream.read(&mut chunk).await.map_err(io)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > answer_max + 16_384 {
            return Err(TransportError::Io("answer too large".into()));
        }
        if let Some(response) = parse(&buf, false, answer_max)? {
            return Ok(response);
        }
    }
    parse(&buf, true, answer_max)?.ok_or_else(|| TransportError::Io("answer cut short".into()))
}

/// Parse an HTTP/1.1 answer from `buf`; `None` while more is needed. At
/// `eof`, a body without a length runs to the end.
fn parse(buf: &[u8], eof: bool, answer_max: usize) -> Result<Option<Response>, TransportError> {
    let bad = |why: &str| TransportError::Io(format!("malformed answer: {why}"));
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if eof {
            Err(bad("no header end"))
        } else {
            Ok(None)
        };
    };
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| bad("header not text"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(|| bad("no status line"))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(bad("not HTTP/1"));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| bad("no status"))?;
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(bad("header line"));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(value.parse::<usize>().map_err(|_| bad("content-length"))?);
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }
    let rest = &buf[end + 4..];
    let body = if chunked {
        match dechunk(rest, answer_max).map_err(|_| bad("chunked body"))? {
            Some(b) => b,
            None if eof => return Err(bad("chunked body cut short")),
            None => return Ok(None),
        }
    } else if let Some(len) = length {
        if len > answer_max {
            return Err(bad("answer too large"));
        }
        if rest.len() < len {
            return if eof {
                Err(bad("body cut short"))
            } else {
                Ok(None)
            };
        }
        rest[..len].to_vec()
    } else if eof {
        rest.to_vec()
    } else {
        return Ok(None);
    };
    if body.len() > answer_max {
        return Err(bad("answer too large"));
    }
    Ok(Some(Response { status, body }))
}

/// A whole chunked body, or `None` while more is needed. A chunk size past
/// `answer_max`, or a body growing past it, is an error before any
/// arithmetic on it.
fn dechunk(mut rest: &[u8], answer_max: usize) -> Result<Option<Vec<u8>>, ()> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let size_text = std::str::from_utf8(&rest[..line_end]).map_err(|_| ())?;
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| ())?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(Some(out));
        }
        if size > answer_max || out.len().saturating_add(size) > answer_max {
            return Err(());
        }
        let Some(with_crlf) = size.checked_add(2) else {
            return Err(());
        };
        if rest.len() < with_crlf {
            return Ok(None);
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[with_crlf..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_with_a_length_or_chunks_parse_and_wait_for_more() {
        let full = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(parse(full, false, 100).unwrap().unwrap().body, b"abc");
        assert!(parse(&full[..full.len() - 1], false, 100)
            .unwrap()
            .is_none());
        assert!(parse(&full[..full.len() - 1], true, 100).is_err());
        let chunked = b"HTTP/1.1 409 Conflict\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1\r\nc\r\n0\r\n\r\n";
        let r = parse(chunked, false, 100).unwrap().unwrap();
        assert_eq!((r.status, r.body.as_slice()), (409, &b"abc"[..]));
        let big = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
        assert!(parse(big, false, 100).is_err());
    }

    #[test]
    fn a_huge_or_oversized_chunk_is_refused_not_overflowed() {
        // A chunk size of usize::MAX would wrap `size + 2` and slice past
        // the buffer.
        let huge = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\nab\r\n0\r\n\r\n",
            usize::MAX
        );
        assert!(parse(huge.as_bytes(), false, 100).is_err());
        assert!(parse(huge.as_bytes(), true, 100).is_err());
        // A chunk past the cap is refused while it is still arriving, not
        // waited for; chunks that each fit but together pass it too.
        let over = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n40\r\n";
        assert!(parse(over, false, 63).is_err());
        let two = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n2\r\ncd\r\n";
        assert!(parse(two, false, 3).is_err());
    }

    #[test]
    fn origins_keep_their_port() {
        let o = Origin::parse("https://plus.example:8443").unwrap();
        assert_eq!(
            (o.host.as_str(), o.port, o.tls),
            ("plus.example", 8443, true)
        );
        assert_eq!(o.authority(), "plus.example:8443");
        let o = Origin::parse("https://plus.example").unwrap();
        assert_eq!((o.port, o.authority()), (443, "plus.example".to_string()));
    }
}
