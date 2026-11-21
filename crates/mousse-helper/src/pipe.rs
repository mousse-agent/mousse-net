//! `mousse-helper pipe --profile <selector>`: the remote end of an
//! `ssh-stdio` route (Phase 1b §3.3). SSH runs it; its stdin and stdout
//! are the pipe.
//!
//! - **Selector.** `$MOUSSE_HOME/net-engine/endpoints.json` (`MOUSSE_HOME`
//!   defaults to `~/.mousse`; the launcher sets it) maps each profile's
//!   selector, 26 characters of `[a-z2-7]`, to its state directory. The
//!   app writes it, owner-only:
//!
//!   ```json
//!   {"profiles": {"<selector>": {"state": "<absolute state dir>", "networking": true}}}
//!   ```
//!
//!   The selector is the only value from the other computer in the
//!   command, so no path is ever quoted.
//! - **Handover.** It reads the profile's `control.json`, connects to the
//!   running helper's owner-only IPC and sends `{"cmd": "pipe", token}`,
//!   then at once starts passing stdin on (the client's first TLS bytes
//!   may arrive behind the request). After `{"ok": true}`, within
//!   `PIPE_CONNECT_WAIT_MS`, it writes the `mousse-ssh/1` marker, then
//!   what its line reader already holds, then the rest of the IPC stream.
//!   stdout carries only the marker and pipe bytes. The keystore is never
//!   opened.
//! - **Ending.** When the helper closes the IPC stream, `pipe` exits at
//!   once, even while SSH still holds its stdin open, so the SSH session
//!   ends and the caller sees the pipe close. When stdin ends first, the
//!   IPC stream's write side is shut and `pipe` exits once the helper
//!   closes.
//! - **Errors:** one line on stderr, `mousse-pipe: <reason>`, and an exit
//!   code: `not_running` (2), `no_endpoint` (3), `refused` (4).

use std::path::PathBuf;

use mousse_net_io::pipe::ssh::{pipe_exit, MARKER};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncWriteExt, BufWriter};

use crate::ipc;

/// Characters in a selector.
const SELECTOR_LEN: usize = 26;

#[derive(Deserialize)]
struct Endpoints {
    #[serde(default)]
    profiles: std::collections::HashMap<String, EndpointEntry>,
}

#[derive(Deserialize)]
struct EndpointEntry {
    state: PathBuf,
    #[serde(default)]
    networking: bool,
}

/// Whether `text` is a selector: 26 characters of `[a-z2-7]`.
pub fn is_selector(text: &str) -> bool {
    text.len() == SELECTOR_LEN && text.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

/// `$MOUSSE_HOME`, else `.mousse` in the user's home.
fn mousse_home() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("MOUSSE_HOME").filter(|h| !h.is_empty()) {
        return Some(PathBuf::from(home));
    }
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })?;
    Some(PathBuf::from(home).join(".mousse"))
}

/// The state directory of the profile `selector` under the Mousse folder
/// `home`, if it has one with networking on.
fn state_dir(home: &std::path::Path, selector: &str) -> Option<PathBuf> {
    if !is_selector(selector) {
        return None;
    }
    let file = home.join("net-engine").join("endpoints.json");
    let bytes = std::fs::read(file).ok()?;
    let endpoints: Endpoints = serde_json::from_slice(&bytes).ok()?;
    let entry = endpoints.profiles.get(selector)?;
    (entry.networking && entry.state.is_absolute()).then(|| entry.state.clone())
}

fn stop(code: i32, reason: &str, detail: impl std::fmt::Display) -> i32 {
    eprintln!("mousse-pipe: {reason} ({detail})");
    code
}

/// Run the pipe; returns the exit code.
pub async fn run(selector: &str) -> i32 {
    let Some(dir) = mousse_home().and_then(|home| state_dir(&home, selector)) else {
        return stop(
            pipe_exit::NO_ENDPOINT,
            "no_endpoint",
            "no profile with networking on has that selector",
        );
    };
    let wait = crate::limits::ms(crate::limits::helper().pipe_connect_wait_ms());
    let deadline = tokio::time::Instant::now() + wait;
    let opened =
        tokio::time::timeout_at(deadline, ipc::request(&dir, json!({"cmd": "pipe"}))).await;
    let ch = match opened {
        Ok(Ok(Some(ch))) => ch,
        Ok(Ok(None)) => {
            return stop(
                pipe_exit::NOT_RUNNING,
                "not_running",
                "no helper runs for that profile",
            )
        }
        Ok(Err(e)) => return stop(pipe_exit::NOT_RUNNING, "not_running", e),
        Err(_) => {
            return stop(
                pipe_exit::NOT_RUNNING,
                "not_running",
                "the helper did not answer within PIPE_CONNECT_WAIT_MS",
            )
        }
    };
    let (mut lines, mut to_helper) = ch.into_halves();
    // stdin goes on at once: the helper's line reader keeps whatever
    // arrives behind the request.
    let feed = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let _ = tokio::io::copy(&mut stdin, &mut to_helper).await;
        // stdin ended: no more for the helper. Its side stays open until
        // the helper closes.
        let _ = to_helper.shutdown().await;
        to_helper
    });
    let reply = tokio::time::timeout_at(deadline, lines.recv()).await;
    match reply {
        Ok(Ok(Some(reply))) if reply.get("ok").and_then(Value::as_bool) == Some(true) => {}
        Ok(Ok(Some(reply))) => {
            feed.abort();
            let why = reply
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("refused")
                .to_owned();
            return stop(pipe_exit::REFUSED, "refused", why);
        }
        Ok(_) => {
            feed.abort();
            return stop(
                pipe_exit::REFUSED,
                "refused",
                "the helper closed the channel",
            );
        }
        Err(_) => {
            feed.abort();
            return stop(
                pipe_exit::NOT_RUNNING,
                "not_running",
                "the helper did not answer within PIPE_CONNECT_WAIT_MS",
            );
        }
    }
    let mut out = BufWriter::new(tokio::io::stdout());
    if out.write_all(MARKER).await.is_err() || out.flush().await.is_err() {
        return 1;
    }
    let mut out = out.into_inner();
    // What the line reader holds comes first, then the rest of the stream.
    let mut from_helper = lines.into_stream();
    let _ = tokio::io::copy(&mut from_helper, &mut out).await;
    let _ = out.flush().await;
    if cfg!(mousse_control = "pipe-outlives-helper") {
        // Control (tests only): wait for stdin to end after the helper
        // closed, so the SSH session stays up.
        let _ = feed.await;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_selector_is_26_base32_lowercase_characters() {
        assert!(is_selector("abcdefghijklmnopqrstuvwx23"));
        assert!(!is_selector("abcdefghijklmnopqrstuvwx2"));
        assert!(!is_selector("abcdefghijklmnopqrstuvwx18"));
        assert!(!is_selector("ABCDEFGHIJKLMNOPQRSTUVWX23"));
        assert!(!is_selector("../../../../../../../etc/x"));
    }

    #[test]
    fn an_unknown_selector_or_networking_off_has_no_endpoint() {
        let home = std::env::temp_dir().join(format!(
            "mousse-pipe-sel-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(home.join("net-engine")).unwrap();
        let state = std::env::temp_dir();
        let file = json!({"profiles": {
            "abcdefghijklmnopqrstuvwx23": {"state": state, "networking": true},
            "bbcdefghijklmnopqrstuvwx23": {"state": state, "networking": false},
            "cbcdefghijklmnopqrstuvwx23": {"state": "relative/dir", "networking": true},
        }});
        std::fs::write(
            home.join("net-engine").join("endpoints.json"),
            file.to_string(),
        )
        .unwrap();
        let read = |sel: &str| state_dir(&home, sel);
        assert_eq!(read("abcdefghijklmnopqrstuvwx23"), Some(state.clone()));
        assert_eq!(read("bbcdefghijklmnopqrstuvwx23"), None);
        assert_eq!(read("cbcdefghijklmnopqrstuvwx23"), None);
        assert_eq!(read("dbcdefghijklmnopqrstuvwx23"), None);
        let _ = std::fs::remove_dir_all(&home);
    }
}
