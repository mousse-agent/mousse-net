//! The app channel tests' harness: helpers running `serve --app` on
//! loopback, each in its own state directory, driven over stdin and stdout
//! as the Mousse app would drive them.
//!
//! A reader thread decodes every frame the helper writes. It checks the
//! helper never sends DATA beyond the credit the test granted, nor anything
//! after a stream's FIN, and it sends queued app data as the helper grants
//! credit. Reading can be paused, which stalls the helper's writer once the
//! pipe is full: the app not reading.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

pub const WAIT: Duration = Duration::from_secs(20);

/// Most bytes in one DATA frame.
pub const MAX_DATA: usize = 1 << 16;

/// The helper under test: a private copy of the binary cargo built with
/// these tests, checked to be that build (see `tests/loopback.rs`: another
/// configuration sharing the target folder may replace the built one).
pub fn bin() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let built = Path::new(env!("CARGO_BIN_EXE_mousse-helper"));
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("helper-under-test-{}", env!("CARGO_CRATE_NAME")));
        std::fs::create_dir_all(&dir).unwrap();
        for old in std::fs::read_dir(&dir).unwrap().flatten() {
            let _ = std::fs::remove_file(old.path());
        }
        let copy = dir.join(format!(
            "mousse-helper-{}{}",
            std::process::id(),
            std::env::consts::EXE_SUFFIX
        ));
        std::fs::copy(built, &copy).unwrap();
        let out = Command::new(&copy).arg("--version").output().unwrap();
        let expected = format!(
            "mousse-helper {} build {} control {}",
            env!("CARGO_PKG_VERSION"),
            env!("MOUSSE_HELPER_BUILD"),
            env!("MOUSSE_HELPER_CONTROL")
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            expected,
            "{} is not the build these tests were compiled with; give each \
             configuration its own CARGO_TARGET_DIR",
            built.display()
        );
        copy
    })
}

fn temp_dir(tag: &str) -> PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    // On Unix the control socket goes in this folder, and a socket path
    // must stay short (104 bytes on macOS).
    if cfg!(windows) {
        std::env::temp_dir().join(format!("mousse-app-{tag}-{}-{n}", std::process::id()))
    } else {
        PathBuf::from("/tmp").join(format!(
            "ma-{tag}-{}-{}",
            std::process::id(),
            n % 1_000_000_000
        ))
    }
}

/// One endpoint's state directory, removed on drop.
pub struct Endpoint {
    pub dir: PathBuf,
}

impl Endpoint {
    pub fn init(tag: &str) -> Self {
        let endpoint = Endpoint { dir: temp_dir(tag) };
        let mut init = endpoint.cli(&["init"], false);
        let code = init.exit_within(WAIT);
        assert_eq!(code, Some(0), "init: {}", init.err());
        endpoint
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(bin());
        cmd.arg("--state")
            .arg(&self.dir)
            .arg("--insecure-file-key")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    /// A command-line run of the helper.
    pub fn cli(&self, args: &[&str], stdin: bool) -> Cli {
        let mut cmd = self.command(args);
        if stdin {
            cmd.stdin(Stdio::piped());
        }
        Cli::spawn(cmd)
    }

    /// Start `serve --app` with `MOUSSE_NET_<name>` overrides.
    pub fn app(&self, name: &str, env: &[(&str, &str)]) -> App {
        self.app_with(name, env, 0, None)
    }

    /// Start `serve --app` on `port` (0: any), with `MOUSSE_NET_<name>`
    /// overrides, reading hosts from `browse` (`MOUSSE_HELPER_BROWSE_FILE`)
    /// if given.
    pub fn app_with(
        &self,
        name: &str,
        env: &[(&str, &str)],
        port: u16,
        browse: Option<&Path>,
    ) -> App {
        let port = port.to_string();
        let mut cmd = self.command(&[
            "serve",
            "--app",
            "--no-mdns",
            "--port",
            &port,
            "--name",
            name,
        ]);
        cmd.stdin(Stdio::piped());
        for (k, v) in env {
            cmd.env(format!("MOUSSE_NET_{k}"), v);
        }
        if let Some(file) = browse {
            cmd.env("MOUSSE_HELPER_BROWSE_FILE", file);
        }
        App::spawn(cmd, self.dir.clone(), name)
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("helper.log")).unwrap_or_default()
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn collect(mut from: impl Read + Send + 'static, into: Arc<Mutex<Vec<u8>>>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = from.read(&mut buf) {
            if n == 0 {
                return;
            }
            into.lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(&buf[..n]);
        }
    });
}

/// A command-line helper process. Killed on drop.
pub struct Cli {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
}

impl Cli {
    fn spawn(mut cmd: Command) -> Self {
        let mut child = cmd.spawn().expect("start the helper");
        let stdout = Arc::new(Mutex::new(Vec::new()));
        let stderr = Arc::new(Mutex::new(Vec::new()));
        collect(child.stdout.take().unwrap(), stdout.clone());
        collect(child.stderr.take().unwrap(), stderr.clone());
        let stdin = child.stdin.take();
        Self {
            child,
            stdin,
            stdout,
            stderr,
        }
    }

    pub fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout.lock().unwrap_or_else(|e| e.into_inner())).into_owned()
    }

    pub fn err(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap_or_else(|e| e.into_inner())).into_owned()
    }

    /// Wait until stdout contains `needle`; return the line it is on.
    pub fn wait_for(&self, needle: &str) -> String {
        let start = Instant::now();
        loop {
            let out = self.out();
            if let Some(at) = out.find(needle) {
                let line_start = out[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
                let line_end = out[at..].find('\n').map(|i| at + i).unwrap_or(out.len());
                return out[line_start..line_end].trim().to_owned();
            }
            assert!(
                start.elapsed() < WAIT,
                "no {needle:?}\nstdout: {out}\nstderr: {}",
                self.err()
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    pub fn type_line(&mut self, text: &str) {
        let stdin = self.stdin.as_mut().expect("piped stdin");
        stdin.write_all(text.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    pub fn exit_within(&mut self, limit: Duration) -> Option<i32> {
        let start = Instant::now();
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                // Let the readers catch up.
                std::thread::sleep(Duration::from_millis(50));
                return Some(status.code().unwrap_or(-1));
            }
            if start.elapsed() > limit {
                return None;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What arrived on one stream, helper to app.
#[derive(Default)]
pub struct Rx {
    pub bytes: Vec<u8>,
    pub fin: bool,
    /// When each DATA frame arrived, with its size.
    pub arrivals: Vec<(Instant, usize)>,
}

/// One stream, app to helper: the credit granted and what is waiting for
/// it.
#[derive(Default)]
pub struct Tx {
    pub credit: u64,
    pub credit_total: u64,
    pub pending: VecDeque<u8>,
    pub fin: bool,
    pub sent: u64,
    pub fin_sent: bool,
}

/// What the test has seen of one helper.
#[derive(Default)]
pub struct St {
    stdin: Option<ChildStdin>,
    /// Every JSON frame, in order.
    pub messages: Vec<Value>,
    pub rx: HashMap<u32, Rx>,
    /// Credit the test granted, per handle.
    pub granted: HashMap<u32, u64>,
    pub tx: HashMap<u32, Tx>,
    /// Broken rules: DATA beyond credit, frames after FIN, bad frames.
    pub violations: Vec<String>,
    pub paused: bool,
    /// stdout ended.
    pub closed: bool,
    /// Every frame in order: `j` JSON, `c<h>` CREDIT, `d<h>` DATA,
    /// `f<h>` DATA with FIN.
    pub order: Vec<String>,
}

impl St {
    fn write(&mut self, bytes: &[u8]) {
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = stdin.write_all(bytes).and_then(|()| stdin.flush());
        }
    }

    /// Send what credit allows on `handle`; FIN rides on the last bytes.
    fn pump(&mut self, handle: u32) {
        loop {
            let Some(tx) = self.tx.get_mut(&handle) else {
                return;
            };
            if tx.fin_sent {
                return;
            }
            let n = tx.pending.len().min(tx.credit as usize).min(MAX_DATA);
            let last = tx.fin && n == tx.pending.len();
            if n == 0 && !last {
                return;
            }
            let chunk: Vec<u8> = tx.pending.drain(..n).collect();
            tx.credit -= n as u64;
            tx.sent += n as u64;
            tx.fin_sent = last;
            let frame = data_frame(handle, last, &chunk);
            self.write(&frame);
            if last {
                return;
            }
        }
    }
}

pub fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = ((body.len() + 1) as u32).to_be_bytes().to_vec();
    out.push(kind);
    out.extend_from_slice(body);
    out
}

pub fn data_frame(handle: u32, fin: bool, bytes: &[u8]) -> Vec<u8> {
    let mut body = handle.to_be_bytes().to_vec();
    body.push(u8::from(fin));
    body.extend_from_slice(bytes);
    frame(0x02, &body)
}

pub fn credit_frame(handle: u32, bytes: u32) -> Vec<u8> {
    let mut body = handle.to_be_bytes().to_vec();
    body.extend_from_slice(&bytes.to_be_bytes());
    frame(0x03, &body)
}

type Shared = Arc<(Mutex<St>, Condvar)>;

fn read_frames(mut out: ChildStdout, shared: Shared) {
    let (lock, cv) = &*shared;
    loop {
        {
            let mut st = lock.lock().unwrap_or_else(|e| e.into_inner());
            while st.paused {
                st = cv.wait(st).unwrap_or_else(|e| e.into_inner());
            }
        }
        let mut head = [0u8; 5];
        let ok = out.read_exact(&mut head).is_ok();
        let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
        let mut body = vec![0u8; len.saturating_sub(1)];
        let ok = ok && (1..=1 << 20).contains(&len) && out.read_exact(&mut body).is_ok();
        let now = Instant::now();
        let mut st = lock.lock().unwrap_or_else(|e| e.into_inner());
        if !ok {
            if len > 1 << 20 {
                st.violations.push(format!("frame length {len}"));
            }
            st.closed = true;
            cv.notify_all();
            return;
        }
        match head[4] {
            0x01 => match serde_json::from_slice::<Value>(&body) {
                Ok(v @ Value::Object(_)) => {
                    st.order.push("j".into());
                    st.messages.push(v);
                }
                _ => st
                    .violations
                    .push("a JSON frame that is not an object".into()),
            },
            0x02 if body.len() >= 5 => {
                let handle = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let fin = body[4] & 1 != 0;
                let bytes = &body[5..];
                let granted = st.granted.get(&handle).copied().unwrap_or(0);
                let rx = st.rx.entry(handle).or_default();
                let mut broke = Vec::new();
                if rx.fin {
                    broke.push(format!("DATA on handle {handle} after its FIN"));
                }
                if body[4] & !1 != 0 || bytes.len() > MAX_DATA {
                    broke.push(format!("malformed DATA on handle {handle}"));
                }
                rx.bytes.extend_from_slice(bytes);
                rx.fin |= fin;
                rx.arrivals.push((now, bytes.len()));
                if rx.bytes.len() as u64 > granted {
                    broke.push(format!(
                        "{} bytes on handle {handle} with {granted} granted",
                        rx.bytes.len()
                    ));
                }
                st.order
                    .push(format!("{}{handle}", if fin { "f" } else { "d" }));
                st.violations.extend(broke);
            }
            0x03 if body.len() == 8 => {
                let handle = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let n = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                if n == 0 {
                    st.violations.push("CREDIT of 0".into());
                }
                let tx = st.tx.entry(handle).or_default();
                tx.credit += u64::from(n);
                tx.credit_total += u64::from(n);
                st.order.push(format!("c{handle}"));
                st.pump(handle);
            }
            other => st.violations.push(format!("bad frame type {other:#04x}")),
        }
        cv.notify_all();
    }
}

/// A helper in `serve --app`, killed on drop.
pub struct App {
    child: Child,
    shared: Shared,
    stderr: Arc<Mutex<Vec<u8>>>,
    next_id: u64,
    pub dir: PathBuf,
    /// The device name it was started with.
    pub name: String,
    /// From the `hello` reply.
    pub identity: String,
}

impl App {
    fn spawn(mut cmd: Command, dir: PathBuf, name: &str) -> Self {
        let mut child = cmd.spawn().expect("start the helper");
        let stderr = Arc::new(Mutex::new(Vec::new()));
        collect(child.stderr.take().unwrap(), stderr.clone());
        let shared: Shared = Arc::new((
            Mutex::new(St {
                stdin: child.stdin.take(),
                ..St::default()
            }),
            Condvar::new(),
        ));
        let out = child.stdout.take().unwrap();
        let reader = shared.clone();
        std::thread::spawn(move || read_frames(out, reader));
        Self {
            child,
            shared,
            stderr,
            next_id: 1,
            dir,
            name: name.to_owned(),
            identity: String::new(),
        }
    }

    pub fn st(&self) -> MutexGuard<'_, St> {
        self.shared.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn err(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap_or_else(|e| e.into_inner())).into_owned()
    }

    /// Wait until `f` finds something.
    pub fn wait<T>(
        &self,
        what: &str,
        limit: Duration,
        mut f: impl FnMut(&mut St) -> Option<T>,
    ) -> T {
        let (lock, cv) = &*self.shared;
        let start = Instant::now();
        let mut st = lock.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(v) = f(&mut st) {
                return v;
            }
            let left = limit.saturating_sub(start.elapsed());
            if left.is_zero() {
                let last: Vec<&Value> = st.messages.iter().rev().take(8).collect();
                panic!(
                    "waited {limit:?} for {what}\nlast messages: {last:?}\nviolations: {:?}\nstdout closed: {}\nstderr: {}\nlog: {}",
                    st.violations,
                    st.closed,
                    self.err(),
                    std::fs::read_to_string(self.dir.join("helper.log")).unwrap_or_default()
                );
            }
            st = cv
                .wait_timeout(st, left.min(Duration::from_millis(100)))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    pub fn raw(&self, bytes: &[u8]) {
        self.st().write(bytes);
    }

    pub fn send_json(&self, value: &Value) {
        let body = serde_json::to_vec(value).unwrap();
        self.raw(&frame(0x01, &body));
    }

    /// A request; returns the reply.
    pub fn request(&mut self, op: &str, fields: Value) -> Value {
        let id = self.start(op, fields);
        self.reply(id)
    }

    /// Send a request without waiting: its id.
    pub fn start(&mut self, op: &str, mut fields: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        fields["id"] = json!(id);
        fields["op"] = json!(op);
        self.send_json(&fields);
        id
    }

    /// The reply to request `id`.
    pub fn reply(&self, id: u64) -> Value {
        self.wait(&format!("the reply to request {id}"), WAIT, |st| {
            st.messages
                .iter()
                .find(|m| m.get("re") == Some(&json!(id)))
                .cloned()
        })
    }

    /// A request that must succeed.
    pub fn call(&mut self, op: &str, fields: Value) -> Value {
        let reply = self.request(op, fields);
        assert!(reply.get("error").is_none(), "{op}: {reply}");
        reply
    }

    pub fn hello(&mut self) -> Value {
        let name = self.name.clone();
        let reply = self.call("hello", json!({"proto": [1, 0], "name": name}));
        self.identity = reply["identity"].as_str().unwrap().to_owned();
        reply
    }

    /// The first event `ev` that `pred` accepts.
    pub fn event(&self, ev: &str, pred: impl Fn(&Value) -> bool) -> Value {
        self.wait(&format!("event {ev}"), WAIT, |st| {
            st.messages
                .iter()
                .find(|m| m["ev"] == ev && pred(m))
                .cloned()
        })
    }

    /// Every event `ev` so far.
    pub fn events(&self, ev: &str) -> Vec<Value> {
        self.st()
            .messages
            .iter()
            .filter(|m| m["ev"] == ev)
            .cloned()
            .collect()
    }

    pub fn open(&mut self, conn: u64, label: &str, class: &str) -> u32 {
        let reply = self.call(
            "stream.open",
            json!({"conn": conn, "label": label, "class": class}),
        );
        reply["handle"].as_u64().unwrap() as u32
    }

    /// The `n`th (from 0) incoming stream on `conn`.
    pub fn incoming(&self, conn: u64, n: usize) -> u32 {
        self.wait(&format!("incoming stream {n} on conn {conn}"), WAIT, |st| {
            st.messages
                .iter()
                .filter(|m| m["ev"] == "stream.incoming" && m["conn"] == conn)
                .nth(n)
                .map(|m| m["handle"].as_u64().unwrap() as u32)
        })
    }

    pub fn accept(&mut self, handle: u32) {
        self.call("stream.accept", json!({"handle": handle}));
    }

    /// Grant `n` bytes of credit on `handle`.
    pub fn credit(&self, handle: u32, n: u32) {
        let mut st = self.st();
        *st.granted.entry(handle).or_default() += u64::from(n);
        st.write(&credit_frame(handle, n));
    }

    /// Queue bytes (and maybe FIN) for `handle`; they go as credit allows.
    pub fn send(&self, handle: u32, bytes: &[u8], fin: bool) {
        let mut st = self.st();
        let tx = st.tx.entry(handle).or_default();
        tx.pending.extend(bytes);
        tx.fin |= fin;
        st.pump(handle);
    }

    /// Bytes received on `handle` so far, and whether FIN came.
    pub fn received(&self, handle: u32) -> (usize, bool) {
        let st = self.st();
        st.rx
            .get(&handle)
            .map(|r| (r.bytes.len(), r.fin))
            .unwrap_or((0, false))
    }

    /// Wait for FIN on `handle`; return everything received on it.
    pub fn until_fin(&self, handle: u32, limit: Duration) -> Vec<u8> {
        self.wait(&format!("FIN on handle {handle}"), limit, |st| {
            st.rx
                .get(&handle)
                .filter(|r| r.fin)
                .map(|r| r.bytes.clone())
        })
    }

    /// Bytes this side's app sent on `handle` (as credit allowed).
    pub fn sent(&self, handle: u32) -> u64 {
        self.st().tx.get(&handle).map(|t| t.sent).unwrap_or(0)
    }

    pub fn pause(&self) {
        self.st().paused = true;
    }

    pub fn resume(&self) {
        self.st().paused = false;
        self.shared.1.notify_all();
    }

    pub fn stats(&mut self) -> Value {
        self.call("stats", json!({}))
    }

    pub fn close_stdin(&self) {
        self.st().stdin = None;
    }

    pub fn exit_within(&mut self, limit: Duration) -> Option<i32> {
        let start = Instant::now();
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                std::thread::sleep(Duration::from_millis(50));
                return Some(status.code().unwrap_or(-1));
            }
            if start.elapsed() > limit {
                return None;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// No DATA beyond credit, nothing after FIN, no bad frames.
    pub fn assert_clean(&self) {
        let st = self.st();
        assert!(st.violations.is_empty(), "{:?}", st.violations);
    }

    /// Wait until `f` holds and stays the same for `quiet`, polling `get`.
    pub fn settle<T: PartialEq + Copy + std::fmt::Debug>(
        &self,
        quiet: Duration,
        get: impl Fn(&App) -> T,
    ) -> T {
        let start = Instant::now();
        let mut last = get(self);
        let mut since = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(50));
            let now = get(self);
            if now != last {
                last = now;
                since = Instant::now();
            } else if since.elapsed() >= quiet {
                return now;
            }
            assert!(start.elapsed() < WAIT, "never settled: {last:?}");
        }
    }
}

impl App {
    /// Kill the helper, as a crash would: nothing is saved or closed.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Two helpers in app mode, B paired with A and connected to it. Apps
/// drop (and stop) before their state directories go.
pub struct Pair {
    pub a: App,
    pub b: App,
    /// The connection's number on A (inbound) and on B (outbound).
    pub a_conn: u64,
    pub b_conn: u64,
    pub a_end: Endpoint,
    pub b_end: Endpoint,
}

/// Start A, start B, and pair B with A through the apps. The pairing
/// connection stays up: it is the pair's connection.
pub fn pair_up(tag: &str, a_env: &[(&str, &str)], b_env: &[(&str, &str)]) -> Pair {
    let a_end = Endpoint::init(&format!("{tag}a"));
    let b_end = Endpoint::init(&format!("{tag}b"));
    let mut a = a_end.app("hostA", a_env);
    a.hello();
    let mut b = b_end.app("peerB", b_env);
    b.hello();
    let joined = pair_apps(&mut a, &mut b);
    Pair {
        a,
        b,
        a_conn: joined.a_conn,
        b_conn: joined.b_conn,
        a_end,
        b_end,
    }
}

/// What pairing two apps gave.
pub struct Joined {
    /// The `invite.create` reply on the host.
    pub invite: Value,
    /// The `approval` event on the host.
    pub approval: Value,
    /// The `enrolled` event on the host.
    pub enrolled: Value,
    /// The `join` reply on the joiner.
    pub join: Value,
    /// The pairing connection's number on the host (inbound) and on the
    /// joiner (outbound).
    pub a_conn: u64,
    pub b_conn: u64,
}

/// Pair `b` with `a` in person through the apps: A shows a ticket, B joins
/// it (`pinned`, as the app does after recording its consent), A says yes.
pub fn pair_apps(a: &mut App, b: &mut App) -> Joined {
    let invite = a.call("invite.create", json!({}));
    let invitation = invite["invitation"].as_str().unwrap().to_owned();
    let join_id = b.start("join", json!({"ticket": invite["uri"], "pinned": true}));
    let approval = a.event("approval", |m| m["invitation"] == invitation.as_str());
    a.call(
        "approval.answer",
        json!({"request": approval["request"], "yes": true}),
    );
    let join = b.reply(join_id);
    assert!(join.get("error").is_none(), "join: {join}");
    let enrolled = a.event("enrolled", |m| m["invitation"] == invitation.as_str());
    let identity = b.identity.clone();
    let a_conn = a.wait("the pairing connection on A", WAIT, |st| {
        st.messages
            .iter()
            .rev()
            .find(|m| {
                m["ev"] == "conn.up" && m["dir"] == "in" && m["identity"] == identity.as_str()
            })
            .map(|m| m["conn"].as_u64().unwrap())
    });
    Joined {
        invite,
        approval,
        enrolled,
        b_conn: join["conn"].as_u64().unwrap(),
        join,
        a_conn,
    }
}

/// Another peer, paired with A and connected to it: its state directory,
/// its app, and the connection's numbers on A and on it. Bind the result as
/// `(dir, app, ..)` so the app stops before its directory goes.
pub fn another_peer(a: &mut App, tag: &str, env: &[(&str, &str)]) -> (Endpoint, App, u64, u64) {
    let end = Endpoint::init(tag);
    let mut app = end.app(tag, env);
    app.hello();
    let joined = pair_apps(a, &mut app);
    (end, app, joined.a_conn, joined.b_conn)
}

/// The inbound connections A announced for `identity`.
fn inbound_of(st: &St, identity: &str) -> Vec<u64> {
    st.messages
        .iter()
        .filter(|m| m["ev"] == "conn.up" && m["dir"] == "in" && m["identity"] == identity)
        .map(|m| m["conn"].as_u64().unwrap())
        .collect()
}

/// B dials A: the new connection's numbers on A and B.
pub fn connect(a: &mut App, b: &mut App) -> (u64, u64) {
    let identity = b.identity.clone();
    let old = inbound_of(&a.st(), &identity);
    let reply = b.call("dial", json!({"identity": a.identity}));
    let b_conn = reply["conn"].as_u64().unwrap();
    let a_conn = a.wait("conn.up on A", WAIT, |st| {
        inbound_of(st, &identity)
            .into_iter()
            .find(|c| !old.contains(c))
    });
    (a_conn, b_conn)
}

/// `n` bytes that differ by position and by `seed`.
pub fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ ((i >> 8) as u8))
        .collect()
}
