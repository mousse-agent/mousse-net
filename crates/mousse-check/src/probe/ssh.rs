//! The `ssh` route for the probe: the system `ssh` client runs the remote
//! `mousse-helper pipe --profile <selector>`, and its stdin and stdout are
//! the pipe (Phase 1b §3). Plus case 8, the helper's pipe IPC itself:
//! a wrong token, a line past `IPC_LINE_MAX_BYTES`, and a stopped helper.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use super::session::BoxPipe;
use super::Waits;

/// The line the remote `pipe` writes before any pipe byte.
pub const MARKER: &str = "mousse-ssh/1";

/// How the probe reaches the remote `pipe`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshRoute {
    /// The `ssh` program (`MOUSSE_NET_SSH_BIN`, else `ssh`).
    pub bin: PathBuf,
    /// An ssh config file holding `host` (test-sshd writes one).
    pub config: PathBuf,
    pub host: String,
    /// The remote command, such as `mousse-helper pipe --profile <selector>`.
    pub command: String,
    /// A known_hosts file of the probe's own: the probe is not the party
    /// that pins SSH host keys, the pinned TLS inside is what it tests.
    pub known_hosts: PathBuf,
}

impl SshRoute {
    /// One `ssh` session, read past the marker. Most `preamble_max` bytes
    /// may come before it, as a login shell's output.
    pub async fn pipe(&self, waits: &Waits) -> Result<BoxPipe, String> {
        let mut child = Command::new(&self.bin)
            .arg("-F")
            .arg(&self.config)
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
            ])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts.display()))
            .arg("--")
            .arg(&self.host)
            .arg(&self.command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("{}: {e}", self.bin.display()))?;
        let stdin = child.stdin.take().ok_or("ssh: no stdin")?;
        let mut stdout = BufReader::new(child.stdout.take().ok_or("ssh: no stdout")?);
        // The session ends when the pipe is dropped (stdin closes).
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
        let until = Instant::now() + waits.ssh_wait;
        let mut seen = 0usize;
        loop {
            let mut line = Vec::new();
            let left = until.saturating_duration_since(Instant::now());
            match tokio::time::timeout(left, stdout.read_until(b'\n', &mut line)).await {
                Err(_) => return Err("ssh: no marker in time".into()),
                Ok(Err(e)) => return Err(format!("ssh: {e}")),
                Ok(Ok(0)) => return Err("ssh: ended before the marker".into()),
                Ok(Ok(n)) => {
                    if line
                        .strip_suffix(b"\n")
                        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
                        == Some(MARKER.as_bytes())
                    {
                        break;
                    }
                    seen += n;
                    if seen > waits.preamble_max {
                        return Err(
                            "ssh: more output than SSH_PREAMBLE_MAX_BYTES before the marker".into(),
                        );
                    }
                }
            }
        }
        Ok(Box::new(tokio::io::join(stdout, stdin)))
    }
}

/// `control.json` of a running helper.
#[derive(serde::Deserialize)]
struct ControlFile {
    addr: String,
    token: String,
}

/// Open the helper's IPC from its control file.
async fn open_ipc(state: &Path, addr: &str) -> Result<BoxPipe, String> {
    #[cfg(windows)]
    {
        let _ = state;
        let client = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(addr)
            .map_err(|e| format!("ipc {addr}: {e}"))?;
        Ok(Box::new(client))
    }
    #[cfg(not(windows))]
    {
        let _ = addr;
        let s = tokio::net::UnixStream::connect(state.join("control.sock"))
            .await
            .map_err(|e| format!("ipc: {e}"))?;
        Ok(Box::new(s))
    }
}

/// The first line the helper sends, or how the stream ended.
async fn answer(ipc: &mut BoxPipe, wait: Duration) -> String {
    let mut got = Vec::new();
    let until = Instant::now() + wait;
    loop {
        let left = until.saturating_duration_since(Instant::now());
        let mut b = [0u8; 1024];
        match tokio::time::timeout(left, ipc.read(&mut b)).await {
            Err(_) => return "open".into(),
            Ok(Ok(0)) | Ok(Err(_)) => {
                return if got.is_empty() {
                    "closed".into()
                } else {
                    String::from_utf8_lossy(&got).trim().to_owned()
                }
            }
            Ok(Ok(n)) => {
                got.extend_from_slice(&b[..n]);
                if let Some(i) = got.iter().position(|&c| c == b'\n') {
                    return String::from_utf8_lossy(&got[..i]).trim().to_owned();
                }
            }
        }
    }
}

/// A pipe request with a wrong token: `refused` when the helper's answer
/// says so.
pub async fn wrong_token(state: &Path, waits: &Waits) -> Result<String, String> {
    let control: ControlFile = serde_json::from_slice(
        &std::fs::read(state.join("control.json")).map_err(|e| format!("control.json: {e}"))?,
    )
    .map_err(|e| format!("control.json: {e}"))?;
    let mut ipc = open_ipc(state, &control.addr).await?;
    let mut wrong = control.token.clone().into_bytes();
    if let Some(b) = wrong.first_mut() {
        *b = if *b == b'0' { b'1' } else { b'0' };
    }
    let req = serde_json::json!({"cmd": "pipe", "token": String::from_utf8_lossy(&wrong)});
    ipc.write_all(format!("{req}\n").as_bytes())
        .await
        .map_err(|e| format!("ipc: {e}"))?;
    let line = answer(&mut ipc, waits.close).await;
    // The helper answers a wrong token with an error, never `ok`.
    let refused = serde_json::from_str::<serde_json::Value>(&line)
        .map(|v| v.get("error").is_some() && v.get("ok") != Some(&serde_json::Value::Bool(true)))
        .unwrap_or(false);
    Ok(if refused || line == "closed" {
        "refused".into()
    } else {
        format!("answered {line:?}")
    })
}

/// A first line longer than `IPC_LINE_MAX_BYTES`: the helper closes.
pub async fn long_line(state: &Path, waits: &Waits) -> Result<String, String> {
    let control: ControlFile = serde_json::from_slice(
        &std::fs::read(state.join("control.json")).map_err(|e| format!("control.json: {e}"))?,
    )
    .map_err(|e| format!("control.json: {e}"))?;
    let mut ipc = open_ipc(state, &control.addr).await?;
    let line = vec![b'a'; waits.ipc_line_max + 1];
    // The helper may close while this is still being written.
    let _ = ipc.write_all(&line).await;
    Ok(match answer(&mut ipc, waits.close).await.as_str() {
        "closed" => "closed".into(),
        other => format!("answered {other:?}"),
    })
}

/// `pipe --profile` for a profile whose helper is not running:
/// `not_running` (exit 2).
pub async fn not_running(helper: &Path, scratch: &Path, waits: &Waits) -> Result<String, String> {
    let selector = "probeprobeprobeprobeprobe2";
    let home = scratch.join("mousse-home");
    let state = scratch.join("stopped-state");
    std::fs::create_dir_all(home.join("net-engine")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&state).map_err(|e| e.to_string())?;
    let dead = if cfg!(windows) {
        format!(
            r"\\.\pipe\mousse-check-stopped-{}",
            mousse_net_io::store::hex(&mousse_net_io::rng::random_bytes::<8>())
        )
    } else {
        "unix:control.sock".into()
    };
    std::fs::write(
        state.join("control.json"),
        serde_json::json!({"addr": dead, "token": "00", "pid": 1}).to_string(),
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        home.join("net-engine").join("endpoints.json"),
        serde_json::json!({"profiles": {selector: {"state": state, "networking": true}}})
            .to_string(),
    )
    .map_err(|e| e.to_string())?;
    let run = Command::new(helper)
        .args(["pipe", "--profile", selector])
        .env("MOUSSE_HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    let out = tokio::time::timeout(waits.close, run)
        .await
        .map_err(|_| "pipe did not exit".to_owned())?
        .map_err(|e| format!("{}: {e}", helper.display()))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    Ok(
        if out.status.code() == Some(2) && stderr.contains("not_running") {
            "not_running".into()
        } else {
            format!("exit {:?}: {}", out.status.code(), stderr.trim())
        },
    )
}
