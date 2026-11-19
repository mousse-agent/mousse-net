//! One HTTP/1.1 `POST` to Plus with a CBOR body (`docs/phase34-design.md`
//! §A.2): a fresh connection per call, TLS 1.3 with the platform verifier
//! and no pin (Plus is not a trust anchor), `Mousse-Plus-Api: 1.0`, and
//! `Connection: close`. The relay calls Plus every few seconds at most, so
//! it keeps no connection open.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use mousse_net_core::relay_hosted::ErrorBody;

use crate::settings::PlusUrl;

/// The API version this build speaks (§A.2: major in the path, minor here).
pub const API_VERSION: &str = "1.0";

/// Longest response head read.
const HEAD_MAX: usize = 16_384;

/// Why a call to Plus failed.
#[derive(Debug)]
pub enum CallError {
    /// No answer: connect, TLS, write or read failed.
    Io(std::io::Error),
    /// No full answer within `MOUSSE_NET_RELAY_PLUS_TIMEOUT_MS`.
    Timeout,
    /// The answer was not well-formed HTTP, or was too large.
    BadAnswer(&'static str),
    /// Plus answered with an error status and, usually, a code.
    Plus {
        /// The HTTP status.
        status: u16,
        /// The error code, when the body had one.
        code: Option<String>,
        /// Seconds to wait, when given.
        retry_after_secs: Option<u64>,
    },
}

impl CallError {
    /// The Plus error code, if Plus sent one.
    pub fn code(&self) -> Option<&str> {
        match self {
            CallError::Plus { code, .. } => code.as_deref(),
            _ => None,
        }
    }
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallError::Io(e) => write!(f, "Plus unreachable: {}", e.kind()),
            CallError::Timeout => f.write_str("Plus did not answer in time"),
            CallError::BadAnswer(why) => write!(f, "Plus answer unreadable: {why}"),
            CallError::Plus { status, code, .. } => match code {
                Some(c) => write!(f, "Plus answered {status} {c}"),
                None => write!(f, "Plus answered {status}"),
            },
        }
    }
}

impl std::error::Error for CallError {}

impl From<std::io::Error> for CallError {
    fn from(e: std::io::Error) -> Self {
        CallError::Io(e)
    }
}

/// A TLS client configuration for Plus: TLS 1.3 only, the platform's
/// certificate verifier.
pub fn tls_config() -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls_platform_verifier::Verifier::new(provider.clone())
        .map_err(|e| format!("platform certificate verifier: {e}"))?;
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS 1.3: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// A Plus endpoint the relay posts to.
#[derive(Clone)]
pub struct PlusHttp {
    url: PlusUrl,
    tls: Option<TlsConnector>,
    timeout: Duration,
    answer_max: usize,
}

impl fmt::Debug for PlusHttp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlusHttp")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl PlusHttp {
    /// Calls to `url`, each limited to `timeout`, reading answers of at
    /// most `answer_max` bytes.
    pub fn new(url: PlusUrl, timeout: Duration, answer_max: usize) -> Result<Self, String> {
        let tls = if url.tls {
            Some(TlsConnector::from(tls_config()?))
        } else {
            None
        };
        Ok(Self {
            url,
            tls,
            timeout,
            answer_max,
        })
    }

    /// `POST` `body` to the API path `path` (such as `/v1/relay/boot`) and
    /// return the body of a 200 answer.
    pub async fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, CallError> {
        match tokio::time::timeout(self.timeout, self.post_inner(path, body)).await {
            Ok(r) => r,
            Err(_) => Err(CallError::Timeout),
        }
    }

    async fn post_inner(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, CallError> {
        let tcp = TcpStream::connect((self.url.host.as_str(), self.url.port)).await?;
        let _ = tcp.set_nodelay(true);
        match &self.tls {
            Some(tls) => {
                let name = ServerName::try_from(self.url.host.clone())
                    .map_err(|_| CallError::BadAnswer("Plus host is not a valid TLS name"))?;
                let stream = tls.connect(name, tcp).await?;
                self.exchange(stream, path, body).await
            }
            None => self.exchange(tcp, path, body).await,
        }
    }

    async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut stream: S,
        path: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, CallError> {
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/cbor\r\nAccept: application/cbor\r\nMousse-Plus-Api: {API_VERSION}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.url.target(path),
            self.url.authority(),
            body.len()
        );
        let mut request = Vec::with_capacity(head.len() + body.len());
        request.extend_from_slice(head.as_bytes());
        request.extend_from_slice(body);
        stream.write_all(&request).await?;
        stream.flush().await?;

        let limit = HEAD_MAX + self.answer_max;
        let mut raw = Vec::new();
        let mut buf = [0u8; 8_192];
        loop {
            let n = stream.read(&mut buf).await;
            let n = match n {
                Ok(n) => n,
                // A peer that closes TLS without close_notify after a full
                // answer: use what arrived if it parses.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.len() > limit {
                return Err(CallError::BadAnswer("answer too large"));
            }
            if let Some(done) = parse_response(&raw, self.answer_max)? {
                return finish(done);
            }
        }
        match parse_response(&raw, self.answer_max)? {
            Some(done) => finish(done),
            None => Err(CallError::BadAnswer("answer ended early")),
        }
    }
}

fn finish((status, body): (u16, Vec<u8>)) -> Result<Vec<u8>, CallError> {
    if status == 200 {
        return Ok(body);
    }
    let parsed = ErrorBody::decode(&body).ok();
    Err(CallError::Plus {
        status,
        code: parsed.as_ref().map(|b| b.code.clone()),
        retry_after_secs: parsed.and_then(|b| b.retry_after_secs),
    })
}

/// A complete response in `raw`: its status and body. `None` while more
/// bytes are needed.
fn parse_response(raw: &[u8], answer_max: usize) -> Result<Option<(u16, Vec<u8>)>, CallError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let head_len = match resp.parse(raw) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => {
            if raw.len() > HEAD_MAX {
                return Err(CallError::BadAnswer("answer head too large"));
            }
            return Ok(None);
        }
        Err(_) => return Err(CallError::BadAnswer("not HTTP")),
    };
    let status = resp.code.ok_or(CallError::BadAnswer("no status"))?;
    let mut length: Option<usize> = None;
    let mut chunked = false;
    for h in resp.headers.iter() {
        if h.name.eq_ignore_ascii_case("content-length") {
            let v = std::str::from_utf8(h.value)
                .ok()
                .and_then(|v| v.trim().parse::<usize>().ok())
                .ok_or(CallError::BadAnswer("bad Content-Length"))?;
            length = Some(v);
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = std::str::from_utf8(h.value)
                .map(|v| v.to_ascii_lowercase().contains("chunked"))
                .unwrap_or(false);
        }
    }
    let rest = &raw[head_len..];
    if chunked {
        return dechunk(rest, answer_max).map(|b| b.map(|b| (status, b)));
    }
    match length {
        Some(n) if n > answer_max => Err(CallError::BadAnswer("answer too large")),
        Some(n) if rest.len() >= n => Ok(Some((status, rest[..n].to_vec()))),
        Some(_) => Ok(None),
        // No length: the body runs to the end of the connection, which the
        // caller sees as a read of 0; until then, wait.
        None => Ok(None),
    }
}

/// Decode a chunked body. `None` until the last chunk has arrived.
fn dechunk(mut rest: &[u8], answer_max: usize) -> Result<Option<Vec<u8>>, CallError> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let line = std::str::from_utf8(&rest[..line_end])
            .map_err(|_| CallError::BadAnswer("bad chunk size"))?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| CallError::BadAnswer("bad chunk size"))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(Some(out));
        }
        if out.len() + size > answer_max {
            return Err(CallError::BadAnswer("answer too large"));
        }
        if rest.len() < size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_length_delimited_answer_parses() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(
            parse_response(raw, 100).unwrap(),
            Some((200, b"abc".to_vec()))
        );
        assert_eq!(parse_response(&raw[..raw.len() - 1], 100).unwrap(), None);
        assert!(parse_response(raw, 2).is_err());
    }

    #[test]
    fn a_chunked_answer_parses() {
        let raw = b"HTTP/1.1 409 Conflict\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1\r\nc\r\n0\r\n\r\n";
        assert_eq!(
            parse_response(raw, 100).unwrap(),
            Some((409, b"abc".to_vec()))
        );
        assert_eq!(parse_response(&raw[..raw.len() - 5], 100).unwrap(), None);
    }

    #[test]
    fn an_error_answer_carries_its_code() {
        let body = ErrorBody {
            code: "stale_generation".into(),
            retry_after_secs: None,
        }
        .encode();
        let e = finish((409, body)).unwrap_err();
        assert_eq!(e.code(), Some("stale_generation"));
    }
}
