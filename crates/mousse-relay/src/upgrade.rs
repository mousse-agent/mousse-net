//! The relay's side of the WebSocket upgrade (spec `relay.md` 2): `GET
//! /mousse-relay/1` with subprotocol `mousse-relay.1`, no extensions, a
//! request of at most `RELAY_HEADER_MAX_BYTES`.

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

/// Request path.
pub const PATH: &str = "/mousse-relay/1";
/// WebSocket subprotocol.
pub const SUBPROTOCOL: &str = "mousse-relay.1";
/// Largest WebSocket message, either way (fixed).
pub const WS_MESSAGE_MAX: usize = mousse_net_core::relay::msg::WS_MESSAGE_MAX;

/// Read buffer per connection. The library default (128 KiB) cost about
/// 168 KB of relay memory per connection in E-R0; messages larger than this
/// still arrive whole.
pub const READ_BUFFER_BYTES: usize = 16 * 1024;

/// The WebSocket configuration of both ends. Each message is written out at
/// once rather than collected in a write buffer.
pub fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(WS_MESSAGE_MAX))
        .max_frame_size(Some(WS_MESSAGE_MAX))
        .accept_unmasked_frames(false)
        .read_buffer_size(READ_BUFFER_BYTES)
        .write_buffer_size(0)
}

/// Why an upgrade was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum UpgradeError {
    /// The request is larger than the limit.
    TooLarge,
    /// The stream ended or failed.
    Closed,
    /// Not a WebSocket upgrade for our path and subprotocol.
    Refused(&'static str),
}

fn header<'b>(req: &httparse::Request<'_, 'b>, name: &str) -> Vec<&'b str> {
    req.headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name))
        .filter_map(|h| std::str::from_utf8(h.value).ok())
        .collect()
}

fn has_token(req: &httparse::Request<'_, '_>, name: &str, token: &str) -> bool {
    header(req, name)
        .iter()
        .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
}

/// Read the upgrade request from `stream`, check it, and answer `101`, or
/// answer an error status and fail. Reads nothing past the request.
pub async fn accept<S>(stream: &mut S, max_bytes: usize) -> Result<(), UpgradeError>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    let mut request = Vec::new();
    loop {
        let buf = stream.fill_buf().await.map_err(|_| UpgradeError::Closed)?;
        if buf.is_empty() {
            return Err(UpgradeError::Closed);
        }
        // Take bytes up to and including the blank line, never more.
        let start = request.len().saturating_sub(3);
        let mut take = buf.len();
        let mut done = false;
        request.extend_from_slice(buf);
        if let Some(pos) = request[start..].windows(4).position(|w| w == b"\r\n\r\n") {
            let end = start + pos + 4;
            take -= request.len() - end;
            request.truncate(end);
            done = true;
        }
        stream.consume(take);
        if request.len() > max_bytes {
            let _ = respond(stream, "431 Request Header Fields Too Large", "").await;
            return Err(UpgradeError::TooLarge);
        }
        if done {
            break;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let refuse = |why| UpgradeError::Refused(why);
    let parsed = req.parse(&request);
    let problem = match parsed {
        Ok(httparse::Status::Complete(_)) => {
            if req.method != Some("GET") || req.version != Some(1) {
                Some(("400 Bad Request", "not GET HTTP/1.1"))
            } else if req.path != Some(PATH) {
                Some(("404 Not Found", "wrong path"))
            } else if !has_token(&req, "Upgrade", "websocket")
                || !has_token(&req, "Connection", "upgrade")
                || !header(&req, "Sec-WebSocket-Version")
                    .iter()
                    .any(|v| v.trim() == "13")
            {
                Some(("400 Bad Request", "not a WebSocket upgrade"))
            } else if !has_token(&req, "Sec-WebSocket-Protocol", SUBPROTOCOL) {
                Some(("400 Bad Request", "wrong subprotocol"))
            } else {
                None
            }
        }
        _ => Some(("400 Bad Request", "malformed request")),
    };
    if let Some((status, why)) = problem {
        let _ = respond(stream, status, "").await;
        return Err(refuse(why));
    }
    let Some(key) = header(&req, "Sec-WebSocket-Key").first().copied() else {
        let _ = respond(stream, "400 Bad Request", "").await;
        return Err(refuse("no key"));
    };
    let accept = derive_accept_key(key.trim().as_bytes());
    let extra = format!(
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: {SUBPROTOCOL}\r\n"
    );
    respond(stream, "101 Switching Protocols", &extra)
        .await
        .map_err(|_| UpgradeError::Closed)
}

async fn respond<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: &str,
    headers: &str,
) -> std::io::Result<()> {
    let body = if status.starts_with("101") {
        String::new()
    } else {
        "Content-Length: 0\r\nConnection: close\r\n".to_owned()
    };
    stream
        .write_all(format!("HTTP/1.1 {status}\r\n{headers}{body}\r\n").as_bytes())
        .await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, BufReader};

    async fn run(request: &str, max: usize) -> (Result<(), UpgradeError>, String, Vec<u8>) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let mut server = BufReader::new(server);
        let (mut cr, mut cw) = tokio::io::split(client);
        cw.write_all(request.as_bytes()).await.unwrap();
        cw.write_all(b"after").await.unwrap();
        let result = accept(&mut server, max).await;
        drop(cw);
        let mut leftover = vec![0u8; 5];
        let _ = server.read_exact(&mut leftover).await;
        drop(server);
        let mut answer = String::new();
        let _ = cr.read_to_string(&mut answer).await;
        (result, answer, leftover)
    }

    const GOOD: &str = "GET /mousse-relay/1 HTTP/1.1\r\nHost: r\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: other, mousse-relay.1\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n";

    #[tokio::test]
    async fn accepts_only_our_path_and_subprotocol_and_reads_nothing_more() {
        let (r, answer, leftover) = run(GOOD, 8192).await;
        assert_eq!(r, Ok(()));
        assert!(answer.starts_with("HTTP/1.1 101"), "{answer}");
        assert!(answer.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
        assert!(answer.contains("Sec-WebSocket-Protocol: mousse-relay.1\r\n"));
        assert!(!answer.contains("Extensions"));
        assert_eq!(leftover, b"after");
        for (bad, status) in [
            (GOOD.replace("/mousse-relay/1", "/other"), "404"),
            (
                GOOD.replace("other, mousse-relay.1", "mousse-relay.2"),
                "400",
            ),
            (GOOD.replace("GET", "POST"), "400"),
            (GOOD.replace("Version: 13", "Version: 8"), "400"),
        ] {
            let (r, answer, _) = run(&bad, 8192).await;
            assert!(r.is_err());
            assert!(
                answer.starts_with(&format!("HTTP/1.1 {status}")),
                "{answer}"
            );
        }
        let (r, answer, _) = run(GOOD, 100).await;
        assert_eq!(r, Err(UpgradeError::TooLarge));
        assert!(answer.starts_with("HTTP/1.1 431"));
    }
}
