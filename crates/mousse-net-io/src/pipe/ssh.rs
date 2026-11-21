//! `ssh-stdio` pipes (Phase 1b §3): the system OpenSSH client, its stdin
//! and stdout carrying the session's TLS to `mousse-helper pipe` on the
//! other computer.
//!
//! - **The client** is the system `ssh` (`%WINDIR%\System32\OpenSSH\ssh.exe`
//!   on Windows), so the owner's keys and agent work as in a terminal.
//!   There is no Rust SSH client.
//! - **One constrained config per route.** Every call is `ssh -F <route
//!   conf> <per-call options> <fixed options> -- mousse-<route_id>
//!   [<command>]`. The route's config pins the host, port, user and host
//!   key (`StrictHostKeyChecking yes` against the route's own
//!   `known_hosts`); the owner's `~/.ssh/config` is read only once, by
//!   `ssh -G` when the route is made. `ssh` keeps the first value it sees
//!   for an option, and command-line options come before the file, so
//!   per-call options (the key probe's) go first.
//! - **Marker.** The remote command writes `mousse-ssh/1` and a newline
//!   before its own bytes. Everything before the first marker, anywhere in
//!   the first `SSH_PREAMBLE_MAX_BYTES` (a login shell's rc files may print
//!   text with no final newline), is discarded. Without it the try fails
//!   with `remote_failed`.
//! - **Reasons.** `ssh` stderr is kept up to `SSH_STDERR_MAX_BYTES` and
//!   mapped to an [`SshReason`]; it is never shown raw.
//! - **The connection window.** At most `SSH_TARGET_CONNECTS` connections
//!   per resolved host and port per `SSH_TARGET_WINDOW_MS`, shared by every
//!   route and alias for that server and by key fetches, setup sessions and
//!   pipe dials alike ([`SshWindow`]), so setup plus retries stay under
//!   `ufw limit`.
//! - **Lifetime.** The child is killed when the pipe drops.
//!
//! Every value here comes from the helper's limits through [`SshParams`].

use std::collections::{HashMap, VecDeque};
#[cfg(windows)]
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::error::NetError;

/// The line the remote command writes before anything else (fixed on
/// purpose, §13.3).
pub const MARKER: &[u8] = b"mousse-ssh/1\n";

/// The debug-only override of the `ssh` binary (§3.1). Release builds
/// never read it.
pub const SSH_BIN_VAR: &str = "MOUSSE_NET_SSH_BIN";

/// The debug-only "user's ssh config" for `ssh -G` (and nothing else):
/// tests point it at a test config, so the owner's own `~/.ssh/config` is
/// never read in a test. Release builds never read it.
pub const TEST_SSH_CONFIG_VAR: &str = "MOUSSE_NET_TEST_SSH_CONFIG";

/// `CREATE_NO_WINDOW`: no console window flashes up for `ssh` on Windows.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// What every `ssh` call runs with. The helper fills it from its limits.
#[derive(Clone, Debug)]
pub struct SshParams {
    /// The client binary.
    pub bin: PathBuf,
    /// `ConnectTimeout`, and the limit on `ssh -G`.
    pub connect_timeout_secs: u64,
    /// `ServerAliveInterval`.
    pub alive_interval_secs: u64,
    /// `ServerAliveCountMax`.
    pub alive_count: u64,
    /// `ssh` stderr kept for the reason.
    pub stderr_max_bytes: usize,
    /// Output skipped before the marker.
    pub preamble_max_bytes: usize,
    /// The ssh config `ssh -G` reads in place of the owner's own (`-F`):
    /// debug builds only, from [`TEST_SSH_CONFIG_VAR`]. `None` reads the
    /// owner's config and the system's `ssh_config`, as a terminal would.
    pub user_config: Option<PathBuf>,
}

/// The system's OpenSSH client: `ssh` on Unix (found on `PATH`), the
/// built-in OpenSSH on Windows.
pub fn system_ssh() -> PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("WINDIR"))
            .unwrap_or_else(|| OsString::from(r"C:\Windows"));
        PathBuf::from(root)
            .join("System32")
            .join("OpenSSH")
            .join("ssh.exe")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("ssh")
    }
}

/// `ssh-keygen` beside `ssh` (the same name on `PATH` on Unix).
pub fn keygen_beside(ssh: &Path) -> PathBuf {
    let name = if cfg!(windows) {
        "ssh-keygen.exe"
    } else {
        "ssh-keygen"
    };
    match ssh.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(name),
        _ => PathBuf::from(name),
    }
}

/// The fixed options of every call (§3.1).
pub fn fixed_options(params: &SshParams) -> Vec<String> {
    let mut out = vec!["-T".to_owned()];
    for opt in [
        "BatchMode=yes".to_owned(),
        "RemoteCommand=none".to_owned(),
        "RequestTTY=no".to_owned(),
        "UpdateHostKeys=no".to_owned(),
        "CheckHostIP=no".to_owned(),
        format!("ConnectTimeout={}", params.connect_timeout_secs),
        format!("ServerAliveInterval={}", params.alive_interval_secs),
        format!("ServerAliveCountMax={}", params.alive_count),
        "ControlMaster=no".to_owned(),
        "ControlPath=none".to_owned(),
        "ForwardAgent=no".to_owned(),
        "ForwardX11=no".to_owned(),
        "ClearAllForwardings=yes".to_owned(),
        "PermitLocalCommand=no".to_owned(),
        "LogLevel=ERROR".to_owned(),
    ] {
        out.push("-o".to_owned());
        out.push(opt);
    }
    out
}

/// A path as an ssh config value (S1): in double quotes, `%` written
/// `%%`. A space, an apostrophe and Windows backslashes need nothing more.
/// `None` for a path that cannot be written so (a double quote or a
/// control character in it).
pub fn config_path(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    if text.chars().any(|c| c == '"' || c.is_control()) {
        return None;
    }
    Some(format!("\"{}\"", text.replace('%', "%%")))
}

/// Whether `token` may go into a remote command unquoted: a launcher name,
/// a subcommand, a flag or a selector.
fn plain_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The remote command for a launcher in the remote's `~/.mousse/bin`
/// (§3.3): `exec /bin/sh -c '"$HOME"/.mousse/bin/<launcher> <args>'`, so a
/// login shell like fish or zsh never parses the inner command. Only
/// plain tokens are taken, so nothing needs quoting.
pub fn remote_command(launcher: &str, args: &[&str]) -> Result<String, NetError> {
    if !plain_token(launcher) || !args.iter().all(|a| plain_token(a)) {
        return Err(NetError::Refused(
            "a remote command takes plain words only".into(),
        ));
    }
    let mut inner = format!("\"$HOME\"/.mousse/bin/{launcher}");
    for arg in args {
        inner.push(' ');
        inner.push_str(arg);
    }
    Ok(format!("exec /bin/sh -c '{inner}'"))
}

/// One route's constrained config, and what the connection window counts
/// it under.
#[derive(Clone, Debug)]
pub struct SshTarget {
    /// `<state>/ssh/<route_id>.conf`.
    pub conf: PathBuf,
    /// `mousse-<route_id>`, the config's only `Host`.
    pub alias: String,
    /// The hostname `ssh -G` resolved.
    pub host: String,
    /// The port `ssh -G` resolved.
    pub port: u16,
    /// The target as the owner entered it. Only the `user-config-in-pipe`
    /// control build uses it.
    pub user_target: String,
}

impl SshTarget {
    /// The connection window's key: the resolved host and port, so two
    /// routes or aliases for one server share it.
    pub fn window_key(&self) -> String {
        // Control (tests only): the window is kept per route.
        if cfg!(mousse_control = "window-per-route") {
            return self.alias.clone();
        }
        format!("{}:{}", self.host.to_ascii_lowercase(), self.port)
    }
}

/// The command for one call through the route's config: `per_call`
/// options first, then the fixed ones, then the alias and the remote
/// command. Its stdio is piped and it is killed when dropped.
pub fn command(
    params: &SshParams,
    target: &SshTarget,
    per_call: &[String],
    remote: Option<&str>,
) -> Command {
    let mut cmd = Command::new(&params.bin);
    cmd.arg("-F")
        .arg(&target.conf)
        .args(per_call)
        .args(fixed_options(params))
        .arg("--")
        .arg(&target.alias);
    if let Some(remote) = remote {
        cmd.arg(remote);
    }
    prepare(&mut cmd);
    cmd
}

/// `ssh -G` for what the owner entered: the user's config (or the test
/// config in debug builds), never the route's.
pub fn resolve_command(
    params: &SshParams,
    user: Option<&str>,
    port: Option<u16>,
    target: &str,
) -> Command {
    let mut cmd = Command::new(&params.bin);
    cmd.arg("-G");
    if let Some(file) = &params.user_config {
        cmd.arg("-F").arg(file);
    }
    if let Some(user) = user {
        cmd.arg("-l").arg(user);
    }
    if let Some(port) = port {
        cmd.arg("-p").arg(port.to_string());
    }
    cmd.arg("--").arg(target);
    prepare(&mut cmd);
    cmd
}

/// No password is ever asked: the askpass helpers are stripped, and on
/// Windows no console window opens.
fn prepare(cmd: &mut Command) {
    for var in ["SSH_ASKPASS", "SSH_ASKPASS_REQUIRE"] {
        cmd.env_remove(var);
    }
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
}

/// Why an `ssh` try failed (§3.1, §3.5). Shown as one line; the stderr
/// text goes to the tooltip only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SshReason {
    /// The login was refused (keys or agent).
    AuthDenied,
    /// The server's key is not the pinned one.
    HostKeyChanged,
    /// No key is pinned for the route.
    HostKeyUnknown,
    /// Nothing answered at the host and port.
    Unreachable,
    /// The connection, the login or the remote end took too long.
    Timeout,
    /// No Mousse launcher on the remote.
    RemoteNotInstalled,
    /// Mousse is not running there (`pipe` exit 2).
    RemoteNotRunning,
    /// That profile is gone there, or its networking is off (`pipe`
    /// exit 3).
    RemoteNoEndpoint,
    /// Anything else, a missing marker or a refused `pipe` (exit 4)
    /// included.
    RemoteFailed,
    /// The remote runs `cmd` or PowerShell: not supported in 1b (§16, S1).
    WindowsRemoteUnsupported,
}

impl SshReason {
    /// The name the app sees.
    pub fn name(self) -> &'static str {
        match self {
            Self::AuthDenied => "auth_denied",
            Self::HostKeyChanged => "host_key_changed",
            Self::HostKeyUnknown => "host_key_unknown",
            Self::Unreachable => "unreachable",
            Self::Timeout => "timeout",
            Self::RemoteNotInstalled => "remote_not_installed",
            Self::RemoteNotRunning => "remote_not_running",
            Self::RemoteNoEndpoint => "remote_no_endpoint",
            Self::RemoteFailed => "remote_failed",
            Self::WindowsRemoteUnsupported => "windows_remote_unsupported",
        }
    }

    /// Whether only the owner can fix it, so keep-connected does not retry
    /// (§1.4): a repeated denied login trips fail2ban and `ufw limit`.
    pub fn needs_owner(self) -> bool {
        matches!(
            self,
            Self::AuthDenied | Self::HostKeyChanged | Self::HostKeyUnknown
        )
    }
}

impl fmt::Display for SshReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The exit codes of the remote `mousse-helper pipe` (fixed on purpose).
pub mod pipe_exit {
    /// No helper runs for that profile.
    pub const NOT_RUNNING: i32 = 2;
    /// Unknown selector, or the profile's networking is off.
    pub const NO_ENDPOINT: i32 = 3;
    /// The token, the pipe pool or the pause fence.
    pub const REFUSED: i32 = 4;
}

/// The reason for a call that ended with exit `code` (`None`: killed) and
/// this stderr (S1's texts, §16).
pub fn reason_of(code: Option<i32>, stderr: &str) -> SshReason {
    let has = |s: &str| stderr.contains(s);
    // The client's own failures (exit 255).
    if has("REMOTE HOST IDENTIFICATION HAS CHANGED")
        || has("has changed and you have requested strict checking")
    {
        return SshReason::HostKeyChanged;
    }
    if has("host key is known for") || has("Host key verification failed") {
        return SshReason::HostKeyUnknown;
    }
    if has("Permission denied (") || has("Too many authentication failures") {
        return SshReason::AuthDenied;
    }
    if has("timed out") {
        return SshReason::Timeout;
    }
    if has("Connection refused")
        || has("Could not resolve hostname")
        || has("No route to host")
        || has("Network is unreachable")
        || has("Name or service not known")
        || has("nodename nor servname")
        || has("Connection closed by")
        || has("Connection reset")
    {
        return SshReason::Unreachable;
    }
    // A Windows remote: `cmd` or PowerShell did not know `exec`.
    if has("is not recognized as an internal or external command")
        || has("is not recognized as the name of a cmdlet")
        || has("is not recognized as a name of a cmdlet")
    {
        return SshReason::WindowsRemoteUnsupported;
    }
    // The remote `pipe`.
    if has("mousse-pipe: not_running") {
        return SshReason::RemoteNotRunning;
    }
    if has("mousse-pipe: no_endpoint") {
        return SshReason::RemoteNoEndpoint;
    }
    match code {
        Some(127) => SshReason::RemoteNotInstalled,
        _ if has("not found") => SshReason::RemoteNotInstalled,
        Some(pipe_exit::NOT_RUNNING) => SshReason::RemoteNotRunning,
        Some(pipe_exit::NO_ENDPOINT) => SshReason::RemoteNoEndpoint,
        // Windows `ssh.exe` prints nothing for a refused port at
        // `LogLevel=ERROR` (S1).
        Some(255) if stderr.trim().is_empty() => SshReason::Unreachable,
        _ => SshReason::RemoteFailed,
    }
}

fn failed(reason: SshReason, detail: impl Into<String>) -> NetError {
    NetError::Ssh {
        reason,
        detail: detail.into(),
    }
}

/// Where the marker is in what was read so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerSearch {
    /// The pipe's own bytes start at this offset.
    After(usize),
    /// Not yet; read more.
    More,
    /// No marker within the preamble allowance.
    TooLong,
}

/// Find the first marker in `buf`: it must end within `preamble_max`
/// bytes plus the marker. It need not start a line.
pub fn find_marker(buf: &[u8], preamble_max: usize) -> MarkerSearch {
    let limit = preamble_max.saturating_add(MARKER.len());
    let end = buf.len().min(limit);
    if let Some(at) = buf[..end].windows(MARKER.len()).position(|w| w == MARKER) {
        return MarkerSearch::After(at + MARKER.len());
    }
    if buf.len() >= limit {
        MarkerSearch::TooLong
    } else {
        MarkerSearch::More
    }
}

/// The connection window (§3.1): at most `connects` ssh connections per
/// key in any `window`. A connection over it waits for the oldest to age
/// out.
pub struct SshWindow {
    connects: usize,
    window: Duration,
    seen: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl SshWindow {
    /// `SSH_TARGET_CONNECTS` per `SSH_TARGET_WINDOW_MS`.
    pub fn new(connects: u64, window_ms: u64) -> Self {
        Self {
            connects: usize::try_from(connects.max(1)).unwrap_or(usize::MAX),
            window: Duration::from_millis(window_ms),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Take a place for one connection to `key` now, or say how long until
    /// one frees.
    pub fn try_take(&self, key: &str) -> Result<(), Duration> {
        let now = Instant::now();
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        let times = seen.entry(key.to_owned()).or_default();
        while times
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= self.window)
        {
            times.pop_front();
        }
        if times.len() < self.connects {
            times.push_back(now);
            return Ok(());
        }
        let oldest = times.front().copied().unwrap_or(now);
        Err((oldest + self.window).saturating_duration_since(now))
    }

    /// Take a place for `key` by `deadline`, waiting as needed. `on_wait`
    /// hears each wait first (the dialog says "Waiting a few seconds so
    /// <host> doesn't block this computer"). A wait that cannot end by the
    /// deadline fails at once with `timeout`.
    pub async fn take(
        &self,
        key: &str,
        deadline: Instant,
        mut on_wait: impl FnMut(Duration),
    ) -> Result<(), NetError> {
        loop {
            match self.try_take(key) {
                Ok(()) => return Ok(()),
                Err(wait) => {
                    if Instant::now() + wait > deadline {
                        return Err(failed(
                            SshReason::Timeout,
                            format!(
                                "waiting for the connection window to {key} \
                                 (SSH_TARGET_CONNECTS per SSH_TARGET_WINDOW_MS) \
                                 would pass the deadline"
                            ),
                        ));
                    }
                    on_wait(wait);
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }
}

/// Keeps the first `max` bytes of stderr and drains the rest, so `ssh`
/// never blocks on a full stderr pipe.
struct Stderr {
    kept: Arc<Mutex<Vec<u8>>>,
    task: JoinHandle<()>,
}

impl Stderr {
    fn collect(from: Option<tokio::process::ChildStderr>, max: usize) -> Self {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let into = kept.clone();
        let task = tokio::spawn(async move {
            let Some(mut from) = from else { return };
            let mut buf = [0u8; 4096];
            loop {
                match from.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        let mut kept = into.lock().unwrap_or_else(|p| p.into_inner());
                        let room = max.saturating_sub(kept.len());
                        kept.extend_from_slice(&buf[..n.min(room)]);
                    }
                }
            }
        });
        Self { kept, task }
    }

    /// The text kept so far, once the stream ended or `by` passed.
    async fn text(&mut self, by: Instant) -> String {
        let _ = tokio::time::timeout_at(by, &mut self.task).await;
        let kept = self.kept.lock().unwrap_or_else(|p| p.into_inner());
        String::from_utf8_lossy(&kept).into_owned()
    }
}

impl Drop for Stderr {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// How a call ended: its exit code (`None` if killed), stderr and reason.
async fn ended(child: &mut Child, stderr: &mut Stderr, by: Instant) -> (Option<i32>, String) {
    let code = match tokio::time::timeout_at(by, child.wait()).await {
        Ok(Ok(status)) => status.code(),
        _ => {
            let _ = child.start_kill();
            None
        }
    };
    let text = stderr.text(by).await;
    (code, text)
}

fn spawn(mut cmd: Command) -> Result<Child, NetError> {
    cmd.spawn().map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            failed(
                SshReason::RemoteFailed,
                "no ssh client found on this computer",
            )
        } else {
            NetError::Io(e)
        }
    })
}

/// The end of one call run to completion ([`run`]).
#[derive(Debug)]
pub struct CallOutput {
    /// The exit code; `None` if it was killed.
    pub code: Option<i32>,
    /// What it wrote to stdout, at most the cap given.
    pub stdout: Vec<u8>,
    /// Stdout went past the cap (the call was killed).
    pub overflow: bool,
    /// Stderr, at most `SSH_STDERR_MAX_BYTES`.
    pub stderr: String,
}

impl CallOutput {
    /// The reason it failed, from its exit and stderr.
    pub fn reason(&self) -> SshReason {
        reason_of(self.code, &self.stderr)
    }
}

/// Run one call to its end with `input` on stdin, reading at most
/// `stdout_max` bytes of stdout, all by `deadline` (else `timeout`). The
/// window place is taken first.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    params: &SshParams,
    window: &SshWindow,
    target: &SshTarget,
    per_call: &[String],
    remote: Option<&str>,
    input: Vec<u8>,
    stdout_max: usize,
    deadline: Instant,
    on_wait: impl FnMut(Duration),
) -> Result<CallOutput, NetError> {
    window.take(&target.window_key(), deadline, on_wait).await?;
    let mut child = spawn(command(params, target, per_call, remote))?;
    let mut stderr = Stderr::collect(child.stderr.take(), params.stderr_max_bytes);
    let stdin = child.stdin.take();
    let feed = tokio::spawn(async move {
        if let Some(mut stdin) = stdin {
            let _ = stdin.write_all(&input).await;
            let _ = stdin.shutdown().await;
        }
    });
    let mut stdout = child.stdout.take();
    let mut out = Vec::new();
    let mut overflow = false;
    let read = async {
        let Some(stdout) = stdout.as_mut() else {
            return;
        };
        let mut buf = [0u8; 8192];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if out.len() + n > stdout_max {
                        overflow = true;
                        return;
                    }
                    out.extend_from_slice(&buf[..n]);
                }
            }
        }
    };
    let timed_out = tokio::time::timeout_at(deadline, read).await.is_err();
    feed.abort();
    if timed_out || overflow {
        let _ = child.start_kill();
    }
    if timed_out {
        let _ = child.wait().await;
        return Err(failed(SshReason::Timeout, "the ssh call took too long"));
    }
    let (code, text) = ended(&mut child, &mut stderr, deadline).await;
    Ok(CallOutput {
        code,
        stdout: out,
        overflow,
        stderr: text,
    })
}

/// Open a pipe: `ssh` runs `remote` through the route's config, and the
/// pipe starts after the marker. Fails with an [`SshReason`] if no marker
/// comes by `within` (the caller's `SSH_DIAL_TIMEOUT_MS` covers this and
/// step 1 on top). The window place is taken first.
pub async fn dial(
    params: &SshParams,
    window: &SshWindow,
    target: &SshTarget,
    remote: &str,
    within: Duration,
    on_wait: impl FnMut(Duration),
) -> Result<SshPipe, NetError> {
    let deadline = Instant::now() + within;
    window.take(&target.window_key(), deadline, on_wait).await?;
    let cmd = if cfg!(mousse_control = "user-config-in-pipe") {
        // Control (tests only): the dial reads the user's ssh config (the
        // test config) and the target as entered, not the route's config.
        let mut cmd = Command::new(&params.bin);
        if let Some(file) = &params.user_config {
            cmd.arg("-F").arg(file);
        }
        cmd.args(fixed_options(params))
            .arg("--")
            .arg(&target.user_target)
            .arg(remote);
        prepare(&mut cmd);
        cmd
    } else {
        command(params, target, &[], Some(remote))
    };
    let mut child = spawn(cmd)?;
    let mut stderr = Stderr::collect(child.stderr.take(), params.stderr_max_bytes);
    let (Some(stdin), Some(mut stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err(NetError::Io(io::Error::other("ssh stdio is not piped")));
    };
    let mut buf = Vec::new();
    // Control (tests only): everything ssh prints goes to TLS.
    let skip = !cfg!(mousse_control = "no-preamble-skip");
    loop {
        if !skip {
            break;
        }
        match find_marker(&buf, params.preamble_max_bytes) {
            MarkerSearch::After(at) => {
                buf.drain(..at);
                break;
            }
            MarkerSearch::TooLong => {
                let _ = child.start_kill();
                return Err(failed(
                    SshReason::RemoteFailed,
                    "the remote printed text before the Mousse marker \
                     (past SSH_PREAMBLE_MAX_BYTES)",
                ));
            }
            MarkerSearch::More => {}
        }
        let mut chunk = [0u8; 8192];
        match tokio::time::timeout_at(deadline, stdout.read(&mut chunk)).await {
            Err(_) => {
                let _ = child.start_kill();
                let text = stderr.text(Instant::now()).await;
                return Err(failed(
                    SshReason::Timeout,
                    format!("no answer from the remote in time {}", text.trim()),
                ));
            }
            Ok(Ok(0)) | Ok(Err(_)) => {
                let (code, text) = ended(&mut child, &mut stderr, deadline).await;
                let detail = if text.trim().is_empty() {
                    "the remote ended before the Mousse marker".to_owned()
                } else {
                    text.trim().to_owned()
                };
                return Err(failed(reason_of(code, &text), detail));
            }
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    Ok(SshPipe {
        child,
        stdin,
        stdout,
        leftover: buf,
        pos: 0,
        _stderr: stderr,
    })
}

/// The `ssh` child's stdin and stdout as one pipe. Bytes read after the
/// marker come first. Dropping it kills the child.
pub struct SshPipe {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    leftover: Vec<u8>,
    pos: usize,
    _stderr: Stderr,
}

impl SshPipe {
    /// The child's process id, while it runs.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }
}

impl fmt::Debug for SshPipe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshPipe")
            .field("pid", &self.child.id())
            .finish_non_exhaustive()
    }
}

impl AsyncRead for SshPipe {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.leftover.len() {
            let n = (this.leftover.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.leftover[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.leftover.len() {
                this.leftover = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for SshPipe {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stdin).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stdin).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stdin).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_is_found_anywhere_in_the_preamble_allowance() {
        assert_eq!(
            find_marker(b"mousse-ssh/1\nTLS", 0),
            MarkerSearch::After(13)
        );
        // Mid-line, after an rc file printed text with no final newline.
        let text = b"hi\r\nno newline at endmousse-ssh/1\nX";
        assert_eq!(find_marker(text, 64), MarkerSearch::After(text.len() - 1));
        // Not alone on its line, and not ended: not a marker.
        assert_eq!(
            find_marker(b"mousse-ssh/1 is not alone", 64),
            MarkerSearch::More
        );
        assert_eq!(find_marker(b"abc", 64), MarkerSearch::More);
        // Past the allowance.
        let long = [b'x'; 80];
        assert_eq!(find_marker(&long, 64), MarkerSearch::TooLong);
        let mut late = vec![b'x'; 65];
        late.extend_from_slice(MARKER);
        assert_eq!(find_marker(&late, 64), MarkerSearch::TooLong);
        let mut just = vec![b'x'; 64];
        just.extend_from_slice(MARKER);
        assert_eq!(find_marker(&just, 64), MarkerSearch::After(just.len()));
    }

    #[test]
    fn stderr_maps_to_a_reason() {
        let cases: [(Option<i32>, &str, SshReason); 13] = [
            (Some(255), "u@h: Permission denied (publickey).", SshReason::AuthDenied),
            (Some(255), "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key for mousse-x has changed and you have requested strict checking.\nHost key verification failed.", SshReason::HostKeyChanged),
            (Some(255), "No ED25519 host key is known for mousse-x and you have requested strict checking.\nHost key verification failed.", SshReason::HostKeyUnknown),
            (Some(255), "ssh: connect to host 127.0.0.1 port 9: Connection refused", SshReason::Unreachable),
            (Some(255), "", SshReason::Unreachable),
            (Some(255), "ssh: connect to host h port 22: Connection timed out", SshReason::Timeout),
            (Some(255), "Connection timed out during banner exchange", SshReason::Timeout),
            (Some(127), "/bin/sh: 1: /home/u/.mousse/bin/mousse-helper: not found", SshReason::RemoteNotInstalled),
            (Some(1), "'exec' is not recognized as an internal or external command,\r\noperable program or batch file.", SshReason::WindowsRemoteUnsupported),
            (Some(2), "mousse-pipe: not_running", SshReason::RemoteNotRunning),
            (Some(3), "mousse-pipe: no_endpoint", SshReason::RemoteNoEndpoint),
            (Some(4), "mousse-pipe: refused", SshReason::RemoteFailed),
            (Some(0), "", SshReason::RemoteFailed),
        ];
        for (code, text, want) in cases {
            assert_eq!(reason_of(code, text), want, "{code:?} {text:?}");
        }
    }

    #[test]
    fn config_paths_are_double_quoted_with_percent_doubled() {
        assert_eq!(
            config_path(Path::new("/x/state dir O'Brien/ssh/known_hosts")).unwrap(),
            "\"/x/state dir O'Brien/ssh/known_hosts\""
        );
        assert_eq!(
            config_path(Path::new("/a/100%/b")).unwrap(),
            "\"/a/100%%/b\""
        );
        assert!(config_path(Path::new("/a/\"b")).is_none());
        assert!(config_path(Path::new("/a/b\nc")).is_none());
    }

    #[test]
    fn remote_commands_take_plain_words_only() {
        assert_eq!(
            remote_command("mousse-helper", &["pipe", "--profile", "abcdefghijklmnopqrstuvwxyz"]).unwrap(),
            "exec /bin/sh -c '\"$HOME\"/.mousse/bin/mousse-helper pipe --profile abcdefghijklmnopqrstuvwxyz'"
        );
        for bad in ["a b", "a'b", "$(x)", "", "a;b"] {
            assert!(remote_command("mousse-helper", &[bad]).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn the_window_counts_per_key_and_frees_as_entries_age() {
        let w = SshWindow::new(2, 200);
        assert!(w.try_take("h:22").is_ok());
        assert!(w.try_take("h:22").is_ok());
        let wait = w.try_take("h:22").unwrap_err();
        assert!(wait <= Duration::from_millis(200));
        // Another server is not held up.
        assert!(w.try_take("other:22").is_ok());
        // A wait past the deadline fails at once.
        let soon = Instant::now() + Duration::from_millis(20);
        let err = w.take("h:22", soon, |_| {}).await.unwrap_err();
        assert!(
            matches!(
                err,
                NetError::Ssh {
                    reason: SshReason::Timeout,
                    ..
                }
            ),
            "{err}"
        );
        // A wait within it is heard and then taken.
        let mut heard = 0;
        let later = Instant::now() + Duration::from_secs(2);
        w.take("h:22", later, |_| heard += 1).await.unwrap();
        assert_eq!(heard, 1);
    }
}
