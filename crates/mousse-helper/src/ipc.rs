//! Local control channel between `serve` and the other commands.
//!
//! Only the OS user running `serve` can use it:
//! - Windows: a named pipe whose security allows only the current user,
//!   refusing remote clients. Another user cannot open it.
//! - Unix: a Unix-domain socket, `control.sock`, inside the owner-only
//!   state directory. Each side checks the other's user id from the socket
//!   (`SO_PEERCRED` or `getpeereid`): `serve` drops a connection from
//!   another user, and a command sends its token only to a listener run by
//!   its own user. A command always looks for the socket in the state
//!   directory, never at an address read from a file, so a control file
//!   left behind by a crash cannot send it anywhere else.
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
    AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf, WriteHalf,
};

const CONTROL_FILE: &str = "control.json";

/// The control socket's name in the state directory (Unix).
#[cfg(not(windows))]
const CONTROL_SOCKET: &str = "control.sock";

/// What `control.json` names as the address on Unix: the socket in the
/// same directory. A file naming anything else is in an older layout.
#[cfg(not(windows))]
const UNIX_ADDR: &str = "unix:control.sock";

#[derive(Serialize, Deserialize)]
struct ControlFile {
    /// The pipe name (Windows) or `unix:control.sock` (Unix).
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

/// The control file of `dir`, or `None` if there is none or it is not in
/// the current layout.
fn read_control_file(dir: &Path) -> Option<ControlFile> {
    let bytes = std::fs::read(control_path(dir)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Forget the control file, and on Unix the socket (on exit).
pub fn remove_control_file(dir: &Path) {
    let _ = std::fs::remove_file(control_path(dir));
    #[cfg(not(windows))]
    let _ = std::fs::remove_file(dir.join(CONTROL_SOCKET));
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
    unix: tokio::net::UnixListener,
    /// The user whose connections are taken: this process's.
    #[cfg(not(windows))]
    uid: u32,
}

impl ControlListener {
    /// Start listening: on Windows at a fresh, unguessable pipe name, on
    /// Unix at the control socket in the state directory `dir` (`serve`
    /// holds the endpoint's lock, so a socket already there was left by a
    /// `serve` that is gone, and is replaced).
    pub async fn bind(dir: &Path) -> Result<Self, String> {
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
            let _ = dir;
            Ok(Self { addr, next })
        }
        #[cfg(not(windows))]
        {
            let path = dir.join(CONTROL_SOCKET);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("control channel: {}: {e}", path.display())),
            }
            // A socket path has a short length limit (104 bytes on macOS,
            // 108 on Linux). Past it, the socket is bound by its name in
            // the state directory after changing to it (Phase 1b §3.3).
            // One helper runs per profile and every path it uses is
            // absolute, so that is safe.
            let unix = match tokio::net::UnixListener::bind(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                    std::env::set_current_dir(dir)
                        .and_then(|()| tokio::net::UnixListener::bind(CONTROL_SOCKET))
                }
                other => other,
            }
            .map_err(|e| format!("control channel: {}: {e}", path.display()))?;
            mousse_net_io::private::restrict_file(&path)
                .map_err(|e| format!("control channel: {}: {e}", path.display()))?;
            Ok(Self {
                addr: UNIX_ADDR.into(),
                unix,
                uid: mousse_net_io::private::current_uid(),
            })
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
            Ok(Channel::bounded(connected))
        }
        #[cfg(not(windows))]
        loop {
            let (stream, _) = self.unix.accept().await.map_err(|e| e.to_string())?;
            // Another user's connection is dropped unread. The folder is
            // owner-only, so this takes root or a socket passed on.
            match stream.peer_cred() {
                Ok(cred) if cred.uid() == self.uid => return Ok(Channel::bounded(stream)),
                _ => continue,
            }
        }
    }
}

type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// One line-delimited JSON connection.
pub struct Channel {
    rd: LineReader,
    wr: BoxWrite,
}

/// The read side of a [`Channel`]: lines through a buffered reader. As a
/// byte stream it gives what the reader already holds first, then the
/// rest of the stream, so nothing read ahead of a line is lost.
pub struct LineReader {
    rd: BufReader<BoxRead>,
    /// The longest line read, on a listener's side (`IPC_LINE_MAX_BYTES`).
    /// `None` on a command's side, which reads its own `serve`'s replies.
    max_line: Option<usize>,
}

/// A control connection turned into a raw byte stream after its request
/// and reply lines (the remote `pipe`, Phase 1b §3.3). Bytes the line
/// reader had already buffered come first.
pub struct IpcPipe {
    rd: BoxRead,
    wr: BoxWrite,
}

impl IpcPipe {
    /// Join a read side and a write side.
    pub fn new(rd: BoxRead, wr: BoxWrite) -> Self {
        Self { rd, wr }
    }
}

impl AsyncRead for IpcPipe {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().rd).poll_read(cx, buf)
    }
}

impl AsyncWrite for IpcPipe {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().wr).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().wr).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().wr).poll_shutdown(cx)
    }
}

impl AsyncRead for LineReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().rd).poll_read(cx, buf)
    }
}

impl LineReader {
    /// The byte stream from here on: what the reader holds, then the rest.
    /// Control (tests only): the held bytes are dropped.
    pub fn into_stream(self) -> BoxRead {
        if cfg!(mousse_control = "ipc-handoff-drops-buffer") {
            return self.rd.into_inner();
        }
        Box::new(self)
    }

    /// The next message; `None` when the other side closed.
    pub async fn recv(&mut self) -> Result<Option<Value>, String> {
        match self.read_line().await {
            Ok(None) => Ok(None),
            Ok(Some(mut line)) => {
                let parsed = serde_json::from_slice(&line)
                    .map(Some)
                    .map_err(|e| format!("bad control message: {e}"));
                // A line may carry a code: wiped once read.
                zeroize::Zeroize::zeroize(&mut line);
                parsed
            }
            // A pipe whose other end went away reads as an error on Windows.
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// One line without its end, within `max_line` bytes. `None` at the
    /// end of the stream with nothing read.
    async fn read_line(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let mut line = Vec::new();
        loop {
            let buf = self.rd.fill_buf().await?;
            if buf.is_empty() {
                return Ok((!line.is_empty()).then_some(line));
            }
            let (take, done) = match buf.iter().position(|b| *b == b'\n') {
                Some(i) => (i + 1, true),
                None => (buf.len(), false),
            };
            line.extend_from_slice(&buf[..take]);
            self.rd.consume(take);
            if let Some(max) = self.max_line {
                // The line end does not count.
                if line.len() - usize::from(done) > max {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "line longer than IPC_LINE_MAX_BYTES",
                    ));
                }
            }
            if done {
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }
        }
    }
}

impl Channel {
    /// Wrap a dialled stream.
    pub fn new<S: AsyncRead + AsyncWrite + Send + 'static>(stream: S) -> Self {
        let (rd, wr): (ReadHalf<S>, WriteHalf<S>) = tokio::io::split(stream);
        Self {
            rd: LineReader {
                rd: BufReader::new(Box::new(rd) as BoxRead),
                max_line: None,
            },
            wr: Box::new(wr),
        }
    }

    /// Wrap an accepted stream: every line at most `IPC_LINE_MAX_BYTES`
    /// (Phase 1b §6.2).
    pub fn bounded<S: AsyncRead + AsyncWrite + Send + 'static>(stream: S) -> Self {
        let mut ch = Self::new(stream);
        // Control (tests only): lines are read with no cap.
        if !cfg!(mousse_control = "ipc-unbounded-line") {
            ch.rd.max_line = usize::try_from(crate::limits::helper().ipc_line_max_bytes()).ok();
        }
        ch
    }

    /// The first message on an accepted stream: it must come within
    /// `IPC_FIRST_LINE_WAIT_MS`, else the channel counts as closed.
    pub async fn recv_first(&mut self) -> Result<Option<Value>, String> {
        if cfg!(mousse_control = "ipc-unbounded-line") {
            return self.recv().await;
        }
        let wait = crate::limits::ms(crate::limits::helper().ipc_first_line_wait_ms());
        match tokio::time::timeout(wait, self.recv()).await {
            Ok(got) => got,
            Err(_) => Err("no request in time".into()),
        }
    }

    /// Send one message.
    pub async fn send(&mut self, value: &Value) -> Result<(), String> {
        let mut line = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        line.push(b'\n');
        let written = self.wr.write_all(&line).await;
        // A line may carry a code: wiped once written.
        zeroize::Zeroize::zeroize(&mut line);
        written.map_err(|e| e.to_string())?;
        self.wr.flush().await.map_err(|e| e.to_string())
    }

    /// The next message; `None` when the other side closed.
    pub async fn recv(&mut self) -> Result<Option<Value>, String> {
        self.rd.recv().await
    }

    /// The two sides, for a caller that writes while it waits for a reply.
    pub fn into_halves(self) -> (LineReader, BoxWrite) {
        (self.rd, self.wr)
    }

    /// The raw byte stream after the lines so far (the helper's side of
    /// `pipe`). Bytes the line reader already holds, the first TLS bytes
    /// the client sent behind its request, come first (Phase 1b §3.3).
    pub fn into_pipe(self) -> IpcPipe {
        IpcPipe::new(self.rd.into_stream(), self.wr)
    }
}

/// Open the control channel of the state directory `dir`, whose control
/// file names `addr`. `Ok(None)` if nothing listens there.
async fn connect(dir: &Path, addr: &str) -> Result<Option<Channel>, String> {
    #[cfg(windows)]
    {
        let _ = dir;
        use tokio::net::windows::named_pipe::ClientOptions;
        const ERROR_PIPE_BUSY: i32 = 231;
        let limits = crate::limits::helper();
        let deadline = std::time::Instant::now() + crate::limits::ms(limits.pipe_busy_wait_ms());
        loop {
            match ClientOptions::new().open(addr) {
                Ok(client) => return Ok(Some(Channel::new(client))),
                Err(e)
                    if e.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && std::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(crate::limits::ms(limits.pipe_busy_retry_ms())).await;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(format!("control channel: {e}")),
            }
        }
    }
    #[cfg(not(windows))]
    {
        connect_as(dir, addr, mousse_net_io::private::current_uid()).await
    }
}

/// Open the control socket in `dir` if a listener run by user `uid`
/// answers there. Nothing is sent before that is checked.
#[cfg(not(windows))]
async fn connect_as(dir: &Path, addr: &str, uid: u32) -> Result<Option<Channel>, String> {
    if addr != UNIX_ADDR {
        return Ok(None);
    }
    // A path too long for a socket is reached by its name in the state
    // directory after changing to it, as the listener bound it.
    let stream = match tokio::net::UnixStream::connect(dir.join(CONTROL_SOCKET)).await {
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            match std::env::set_current_dir(dir) {
                Ok(()) => tokio::net::UnixStream::connect(CONTROL_SOCKET).await,
                Err(e) => Err(e),
            }
        }
        other => other,
    };
    let stream = match stream {
        Ok(stream) => stream,
        Err(_) => return Ok(None),
    };
    let cred = stream
        .peer_cred()
        .map_err(|e| format!("control channel: cannot tell who listens: {e}"))?;
    if cred.uid() != uid {
        return Err(format!(
            "control channel: the listener runs as user {}, not this user; nothing was sent",
            cred.uid()
        ));
    }
    Ok(Some(Channel::new(stream)))
}

/// Connect to the running `serve` of `dir` and send `request` (the token is
/// added). `Ok(None)` if no `serve` is running there.
///
/// A `control.json` this build cannot read (an older layout with `port`
/// instead of `addr`, or a torn file) names no `serve` this build could
/// reach, so it counts as stale like a file whose listener is gone: the
/// command takes its offline path. A starting `serve` rewrites the file in
/// the current layout.
pub async fn request(dir: &Path, mut request: Value) -> Result<Option<Channel>, String> {
    let Some(file) = read_control_file(dir) else {
        return Ok(None);
    };
    let Some(mut channel) = connect(dir, &file.addr).await? else {
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
    async fn a_control_file_in_an_older_layout_counts_as_no_serve_running() {
        let dir = std::env::temp_dir().join(format!(
            "mousse-helper-ipc-old-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for old in [
            &br#"{"port":49152,"token":"00","pid":1}"#[..],
            b"{\"addr\":",
        ] {
            std::fs::write(control_path(&dir), old).unwrap();
            let got = request(&dir, serde_json::json!({"cmd": "status"})).await;
            assert!(matches!(got, Ok(None)), "{:?}", got.err());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A fresh owner-only folder. On Unix it is under `/tmp`: a socket
    /// path must stay short, and the per-user temporary folder on macOS is
    /// already half the limit.
    fn temp_dir(tag: &str) -> PathBuf {
        let base = if cfg!(windows) {
            std::env::temp_dir()
        } else {
            PathBuf::from("/tmp")
        };
        let dir = base.join(format!(
            "mousse-helper-ipc-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        mousse_net_io::private::make_private_dir(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn a_request_reaches_the_listener_and_the_reply_comes_back() {
        let dir = temp_dir("echo");
        let mut listener = ControlListener::bind(&dir).await.unwrap();
        let addr = listener.addr().to_owned();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let mut ch = listener.accept().await.unwrap();
                let got = ch.recv().await.unwrap().unwrap();
                ch.send(&serde_json::json!({"echo": got})).await.unwrap();
            }
        });
        for n in 0..2 {
            let mut ch = connect(&dir, &addr).await.unwrap().unwrap();
            ch.send(&serde_json::json!({"n": n})).await.unwrap();
            let reply = ch.recv().await.unwrap().unwrap();
            assert_eq!(reply["echo"]["n"], n);
        }
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The socket is in the owner-only state folder and owner-only itself;
    /// one left by a `serve` that is gone is replaced.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn the_control_socket_is_owner_only_in_the_state_folder() {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let dir = temp_dir("sock");
        drop(ControlListener::bind(&dir).await.unwrap());
        let listener = ControlListener::bind(&dir).await.unwrap();
        assert_eq!(listener.addr(), UNIX_ADDR);
        let meta = std::fs::symlink_metadata(dir.join(CONTROL_SOCKET)).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        // A control file naming an address, as an older build wrote it, is
        // not followed.
        assert!(connect(&dir, "127.0.0.1:9").await.unwrap().is_none());
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A command sends nothing to a listener run by another user, and
    /// `serve` takes no connection from another user.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn each_side_refuses_a_peer_run_by_another_user() {
        use tokio::io::AsyncReadExt;
        let me = mousse_net_io::private::current_uid();
        let dir = temp_dir("peer");

        // The listener is not this user's: the command refuses it and the
        // listener reads nothing.
        let raw = tokio::net::UnixListener::bind(dir.join(CONTROL_SOCKET)).unwrap();
        let got = connect_as(&dir, UNIX_ADDR, me.wrapping_add(1)).await;
        assert!(
            got.as_ref().is_err_and(|e| e.contains("nothing was sent")),
            "{:?}",
            got.as_ref().err()
        );
        drop(got);
        let (mut accepted, _) = raw.accept().await.unwrap();
        let mut buf = Vec::new();
        accepted.read_to_end(&mut buf).await.unwrap();
        assert!(buf.is_empty(), "{buf:?}");
        drop(raw);

        // `serve` expects another user: this one's connection is dropped.
        let mut listener = ControlListener::bind(&dir).await.unwrap();
        listener.uid = me.wrapping_add(1);
        let server = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let mut ch = connect(&dir, UNIX_ADDR).await.unwrap().unwrap();
        let _ = ch.send(&serde_json::json!({"cmd": "status"})).await;
        assert!(!matches!(ch.recv().await, Ok(Some(_))));
        assert!(!server.is_finished());
        server.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
