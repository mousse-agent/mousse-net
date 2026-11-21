//! A WebSocket client written by hand (RFC 6455), so the probe can send the
//! upgrade requests and messages the host's ws listener must refuse.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;

use super::Waits;

/// The subprotocol the listener selects (Phase 1b §4.1).
pub const SUBPROTOCOL: &str = "mousse.1";

/// One upgrade request.
pub struct Request {
    pub method: &'static str,
    pub path: String,
    pub host: String,
    pub upgrade: bool,
    pub origin: Option<String>,
    pub subprotocol: Option<String>,
    pub padding: usize,
}

impl Request {
    /// What a caller sends.
    pub fn good(addr: SocketAddr, path: &str) -> Self {
        Self {
            method: "GET",
            path: path.to_owned(),
            host: addr.to_string(),
            upgrade: true,
            origin: None,
            subprotocol: Some(SUBPROTOCOL.to_owned()),
            padding: 0,
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut r = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\n",
            self.method, self.path, self.host
        );
        if self.upgrade {
            r.push_str(
                "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n",
            );
            r.push_str(&format!(
                "Sec-WebSocket-Key: {}\r\n",
                base64(&mousse_net_io::rng::random_bytes::<16>())
            ));
        }
        if let Some(p) = &self.subprotocol {
            r.push_str(&format!("Sec-WebSocket-Protocol: {p}\r\n"));
        }
        if let Some(o) = &self.origin {
            r.push_str(&format!("Origin: {o}\r\n"));
        }
        if self.padding > 0 {
            // One long header line, then more so no single line is absurd.
            let mut left = self.padding;
            let mut n = 0;
            while left > 0 {
                let take = left.min(1000);
                r.push_str(&format!("X-Mousse-Pad-{n}: {}\r\n", "a".repeat(take)));
                left -= take;
                n += 1;
            }
        }
        r.push_str("\r\n");
        r.into_bytes()
    }
}

/// Send `req` and read the status line. On `101` the socket is returned
/// for the ws session; otherwise the status ("404", "closed", ...).
pub async fn upgrade(
    mut tcp: TcpStream,
    req: &Request,
    waits: &Waits,
) -> Result<(Option<TcpStream>, String), String> {
    if tcp.write_all(&req.bytes()).await.is_err() {
        return Ok((None, "closed".into()));
    }
    let status = read_status(&mut tcp, waits.close).await;
    if status == "101" {
        Ok((Some(tcp), status))
    } else {
        Ok((None, status))
    }
}

/// The status code of the response head, `closed` if the socket ended
/// first, or `open` if nothing came within `wait`.
pub async fn read_status(tcp: &mut TcpStream, wait: Duration) -> String {
    let until = Instant::now() + wait;
    let mut head = Vec::new();
    loop {
        if let Some(end) = find(&head, b"\r\n\r\n") {
            let text = String::from_utf8_lossy(&head[..end]);
            let line = text.lines().next().unwrap_or("");
            return line
                .split_whitespace()
                .nth(1)
                .unwrap_or("unreadable")
                .to_owned();
        }
        // Read one byte at a time past the head, so no ws frame is eaten.
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return "open".into();
        }
        let mut b = [0u8; 1];
        match tokio::time::timeout(left, tcp.read(&mut b)).await {
            Err(_) => return "open".into(),
            Ok(Ok(0)) | Ok(Err(_)) => return "closed".into(),
            Ok(Ok(_)) => head.push(b[0]),
        }
        if head.len() > 64 * 1024 {
            return "unreadable".into();
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Send the upgrade request one byte at a time, spread past `wait`, and
/// say whether the host closed the socket before the request was done.
pub async fn trickle(mut tcp: TcpStream, req: &Request, wait: Duration, step: Duration) -> String {
    let bytes = req.bytes();
    let until = Instant::now() + wait + wait / 2;
    let (mut rd, mut wr) = tcp.split();
    let reader = async {
        let mut b = [0u8; 256];
        loop {
            match rd.read(&mut b).await {
                Ok(0) | Err(_) => return "closed".to_owned(),
                Ok(_) => {}
            }
        }
    };
    let writer = async {
        for byte in bytes.iter().cycle() {
            if Instant::now() >= until {
                break;
            }
            if wr.write_all(&[*byte]).await.is_err() {
                return "closed".to_owned();
            }
            tokio::time::sleep(step).await;
        }
        "open".to_owned()
    };
    tokio::select! {
        r = reader => r,
        w = writer => w,
    }
}

/// One ws frame from the client: FIN set, masked.
pub fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | len as u8);
    } else if len <= 0xffff {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let mask = mousse_net_io::rng::random_bytes::<4>();
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

/// One frame from the server (unmasked).
pub struct ServerFrame {
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// Read one server frame.
pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<ServerFrame> {
    let mut h = [0u8; 2];
    r.read_exact(&mut h).await?;
    let opcode = h[0] & 0x0f;
    let masked = h[1] & 0x80 != 0;
    let mut len = u64::from(h[1] & 0x7f);
    if len == 126 {
        let mut b = [0u8; 2];
        r.read_exact(&mut b).await?;
        len = u64::from(u16::from_be_bytes(b));
    } else if len == 127 {
        let mut b = [0u8; 8];
        r.read_exact(&mut b).await?;
        len = u64::from_be_bytes(b);
    }
    if len > 1 << 20 {
        return Err(std::io::Error::other("ws frame over 1 MiB"));
    }
    let mut mask = [0u8; 4];
    if masked {
        r.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Ok(ServerFrame { opcode, payload })
}

/// After an upgrade, send a text message and report how the host answered:
/// `close:<code>`, `closed`, or `open`.
pub async fn text_message(mut tcp: TcpStream, wait: Duration) -> String {
    if tcp.write_all(&frame(0x1, b"mousse-check")).await.is_err() {
        return "closed".into();
    }
    let until = Instant::now() + wait;
    loop {
        let left = until.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, read_frame(&mut tcp)).await {
            Err(_) => return "open".into(),
            Ok(Err(_)) => return "closed".into(),
            Ok(Ok(f)) if f.opcode == 0x8 => {
                return match f.payload.get(..2) {
                    Some(c) => format!("close:{}", u16::from_be_bytes([c[0], c[1]])),
                    None => "close:none".into(),
                }
            }
            Ok(Ok(_)) => {}
        }
    }
}

/// Carry a byte stream over binary ws messages: the returned end is the
/// pipe TLS runs on. Pings are answered; a close ends the stream.
pub fn bridge(tcp: TcpStream) -> DuplexStream {
    let (ours, theirs) = duplex(256 * 1024);
    let (mut from_tls, mut to_tls) = tokio::io::split(theirs);
    let (mut rd, mut wr) = tcp.into_split();
    let (pong_tx, mut pong_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        loop {
            match read_frame(&mut rd).await {
                Ok(f) if f.opcode == 0x2 || f.opcode == 0x0 => {
                    if to_tls.write_all(&f.payload).await.is_err() {
                        break;
                    }
                }
                Ok(f) if f.opcode == 0x9 => {
                    let _ = pong_tx.send(f.payload);
                }
                Ok(f) if f.opcode == 0x8 => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = to_tls.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            tokio::select! {
                n = from_tls.read(&mut buf) => match n {
                    Ok(0) | Err(_) => {
                        let _ = wr.write_all(&frame(0x8, &1000u16.to_be_bytes())).await;
                        break;
                    }
                    Ok(n) => {
                        if wr.write_all(&frame(0x2, &buf[..n])).await.is_err() {
                            break;
                        }
                    }
                },
                Some(p) = pong_rx.recv() => {
                    if wr.write_all(&frame(0xA, &p)).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    ours
}

/// Standard base64 with padding (for `Sec-WebSocket-Key`).
pub fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_4648_examples() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[tokio::test]
    async fn a_client_frame_is_masked_and_reads_back() {
        let bytes = frame(0x2, &[1, 2, 3, 4, 5]);
        assert_eq!(bytes[0], 0x82);
        assert_eq!(bytes[1], 0x80 | 5);
        let f = read_frame(&mut &bytes[..]).await.unwrap();
        assert_eq!((f.opcode, f.payload), (0x2, vec![1, 2, 3, 4, 5]));
    }
}
