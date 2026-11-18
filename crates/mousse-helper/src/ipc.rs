//! Local control channel between `serve` and the other commands.
//!
//! Only the OS user running `serve` can use it:
//! - Windows: a named pipe whose security allows only the current user,
//!   refusing remote clients. Another user cannot open it.
//! - Unix: 127.0.0.1 at a random port.
//!
//! `serve` writes where it listens and a random token to `control.json` in
//! the state directory. The folder and the file are owner-only, so only the
//! same user can read the token, and every request carries it. Messages are
//! JSON, one per line.

use std::path::{Path, PathBuf};

use mousse_net_io::store::write_atomic;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf,
};

const CONTROL_FILE: &str = "control.json";

#[derive(Serialize, Deserialize)]
struct ControlFile {
    /// The pipe name (Windows) or `127.0.0.1:<port>` (Unix).
    addr: String,
    token: String,
    pid: u32,
}

fn control_path(dir: &Path) -> PathBuf {
    dir.join(CONTROL_FILE)
}

/// Record where the running `serve` listens.
pub fn write_control_file(dir: &Path, addr: &str, token: &str) -> Result<(), String> {
    let file = ControlFile {
        addr: addr.to_owned(),
        token: token.to_owned(),
        pid: std::process::id(),
    };
    let bytes = serde_json::to_vec(&file).map_err(|e| e.to_string())?;
    write_atomic(&control_path(dir), &bytes).map_err(|e| e.to_string())
}

/// Forget the control file (on exit).
pub fn remove_control_file(dir: &Path) {
    let _ = std::fs::remove_file(control_path(dir));
}

/// Compare tokens without stopping at the first difference.
pub fn token_matches(given: &str, expected: &str) -> bool {
    let (a, b) = (given.as_bytes(), expected.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Where `serve` takes control connections.
pub struct ControlListener {
    addr: String,
    #[cfg(windows)]
    next: tokio::net::windows::named_pipe::NamedPipeServer,
    #[cfg(not(windows))]
    tcp: tokio::net::TcpListener,
}

impl ControlListener {
    /// Start listening at a fresh, unguessable place.
    pub async fn bind() -> Result<Self, String> {
        #[cfg(windows)]
        {
            let addr = format!(
                r"\\.\pipe\mousse-helper-{}",
                mousse_net_io::store::hex(&mousse_net_io::rng::random_bytes::<16>())
            );
            // The first instance fails if the name exists: nobody else can
            // have set up a pipe here first.
            let next = mousse_net_io::private::create_pipe_server(&addr, true)
                .map_err(|e| format!("control channel: {e}"))?;
            Ok(Self { addr, next })
        }
        #[cfg(not(windows))]
        {
            let tcp = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|e| format!("control channel: {e}"))?;
            let addr = tcp.local_addr().map_err(|e| e.to_string())?.to_string();
            Ok(Self { addr, tcp })
        }
    }

    /// Where it listens, as written to the control file.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// The next connection. Cancel-safe.
    pub async fn accept(&mut self) -> Result<Channel, String> {
        #[cfg(windows)]
        {
            self.next.connect().await.map_err(|e| e.to_string())?;
            let fresh = mousse_net_io::private::create_pipe_server(&self.addr, false)
                .map_err(|e| e.to_string())?;
            let connected = std::mem::replace(&mut self.next, fresh);
            Ok(Channel::new(connected))
        }
        #[cfg(not(windows))]
        {
            let (stream, _) = self.tcp.accept().await.map_err(|e| e.to_string())?;
            Ok(Channel::new(stream))
        }
    }
}

type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// One line-delimited JSON connection.
pub struct Channel {
    lines: Lines<BufReader<BoxRead>>,
    wr: BoxWrite,
}

impl Channel {
    /// Wrap an accepted or dialled stream.
    pub fn new<S: AsyncRead + AsyncWrite + Send + 'static>(stream: S) -> Self {
        let (rd, wr): (ReadHalf<S>, WriteHalf<S>) = tokio::io::split(stream);
        Self {
            lines: BufReader::new(Box::new(rd) as BoxRead).lines(),
            wr: Box::new(wr),
        }
    }

    /// Send one message.
    pub async fn send(&mut self, value: &Value) -> Result<(), String> {
        let mut line = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        line.push(b'\n');
        self.wr.write_all(&line).await.map_err(|e| e.to_string())?;
        self.wr.flush().await.map_err(|e| e.to_string())
    }

    /// The next message; `None` when the other side closed.
    pub async fn recv(&mut self) -> Result<Option<Value>, String> {
        match self.lines.next_line().await {
            Ok(None) => Ok(None),
            Ok(Some(line)) => serde_json::from_str(&line)
                .map(Some)
                .map_err(|e| format!("bad control message: {e}")),
            // A pipe whose other end went away reads as an error on Windows.
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Open the control channel at `addr`. `Ok(None)` if nothing listens there.
async fn connect(addr: &str) -> Result<Option<Channel>, String> {
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        const ERROR_PIPE_BUSY: i32 = 231;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match ClientOptions::new().open(addr) {
                Ok(client) => return Ok(Some(Channel::new(client))),
                Err(e)
                    if e.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && std::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(format!("control channel: {e}")),
            }
        }
    }
    #[cfg(not(windows))]
    {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => Ok(Some(Channel::new(stream))),
            Err(_) => Ok(None),
        }
    }
}

/// Connect to the running `serve` of `dir` and send `request` (the token is
/// added). `Ok(None)` if no `serve` is running there.
pub async fn request(dir: &Path, mut request: Value) -> Result<Option<Channel>, String> {
    let Ok(bytes) = std::fs::read(control_path(dir)) else {
        return Ok(None);
    };
    let file: ControlFile =
        serde_json::from_slice(&bytes).map_err(|e| format!("control.json: {e}"))?;
    let Some(mut channel) = connect(&file.addr).await? else {
        return Ok(None);
    };
    if let Some(map) = request.as_object_mut() {
        map.insert("token".into(), Value::String(file.token));
    }
    channel.send(&request).await?;
    Ok(Some(channel))
}

/// Send `request` and return the single reply.
pub async fn call(dir: &Path, request: Value) -> Result<Option<Value>, String> {
    let Some(mut channel) = self::request(dir, request).await? else {
        return Ok(None);
    };
    let reply = channel
        .recv()
        .await?
        .ok_or("the running serve closed the control channel")?;
    if let Some(err) = reply.get("error").and_then(Value::as_str) {
        return Err(err.to_owned());
    }
    Ok(Some(reply))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_must_match_exactly() {
        assert!(token_matches("abc", "abc"));
        assert!(!token_matches("abd", "abc"));
        assert!(!token_matches("ab", "abc"));
    }

    #[tokio::test]
    async fn a_request_reaches_the_listener_and_the_reply_comes_back() {
        let mut listener = ControlListener::bind().await.unwrap();
        let addr = listener.addr().to_owned();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let mut ch = listener.accept().await.unwrap();
                let got = ch.recv().await.unwrap().unwrap();
                ch.send(&serde_json::json!({"echo": got})).await.unwrap();
            }
        });
        for n in 0..2 {
            let mut ch = connect(&addr).await.unwrap().unwrap();
            ch.send(&serde_json::json!({"n": n})).await.unwrap();
            let reply = ch.recv().await.unwrap().unwrap();
            assert_eq!(reply["echo"]["n"], n);
        }
        server.await.unwrap();
    }
}
