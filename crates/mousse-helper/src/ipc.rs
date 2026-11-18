//! Local control channel between `serve` and the other commands.
//!
//! `serve` listens on 127.0.0.1 at a random port and writes the port and a
//! random token to `control.json` in the state directory (owner-only on
//! Unix). Every request carries the token. Messages are JSON, one per line.

use std::path::{Path, PathBuf};

use mousse_net_io::store::write_atomic;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

const CONTROL_FILE: &str = "control.json";

#[derive(Serialize, Deserialize)]
struct ControlFile {
    port: u16,
    token: String,
    pid: u32,
}

fn control_path(dir: &Path) -> PathBuf {
    dir.join(CONTROL_FILE)
}

/// Record where the running `serve` listens.
pub fn write_control_file(dir: &Path, port: u16, token: &str) -> Result<(), String> {
    let file = ControlFile {
        port,
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

/// One line-delimited JSON connection.
pub struct Channel {
    lines: Lines<BufReader<OwnedReadHalf>>,
    wr: OwnedWriteHalf,
}

impl Channel {
    /// Wrap an accepted or dialled stream.
    pub fn new(stream: TcpStream) -> Self {
        let (rd, wr) = stream.into_split();
        Self {
            lines: BufReader::new(rd).lines(),
            wr,
        }
    }

    /// Send one message.
    pub async fn send(&mut self, value: &Value) -> Result<(), String> {
        let mut line = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        line.push(b'\n');
        self.wr.write_all(&line).await.map_err(|e| e.to_string())
    }

    /// The next message; `None` when the other side closed.
    pub async fn recv(&mut self) -> Result<Option<Value>, String> {
        match self.lines.next_line().await.map_err(|e| e.to_string())? {
            None => Ok(None),
            Some(line) => serde_json::from_str(&line)
                .map(Some)
                .map_err(|e| format!("bad control message: {e}")),
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
    let Ok(stream) = TcpStream::connect(("127.0.0.1", file.port)).await else {
        return Ok(None);
    };
    if let Some(map) = request.as_object_mut() {
        map.insert("token".into(), Value::String(file.token));
    }
    let mut channel = Channel::new(stream);
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
}
