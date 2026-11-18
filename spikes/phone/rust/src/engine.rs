//! Spike 4: the lifecycle engine. Rust owns the tokio runtime; Swift and Kotlin only
//! ever poll futures that are runtime-agnostic (join handles), so they never need a
//! tokio context of their own.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::bytepath;

/// A dial that hasn't connected and echoed by then fails with `Timeout`.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest echo frame either side accepts.
const MAX_ECHO_FRAME: u32 = 64 * 1024;
/// How long `stop` waits for tasks before dropping them.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, thiserror::Error, uniffi::Error)]
pub enum NetError {
    #[error("cancelled")]
    Cancelled,
    #[error("engine stopped")]
    Stopped,
    #[error("engine not running")]
    NotRunning,
    #[error("engine already running")]
    AlreadyRunning,
    #[error("unknown dial id")]
    UnknownDial,
    #[error("dial already awaited")]
    AlreadyAwaited,
    #[error("timed out")]
    Timeout,
    #[error("i/o: {msg}")]
    Io { msg: String },
    #[error("protocol: {msg}")]
    Protocol { msg: String },
}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        NetError::Io { msg: e.to_string() }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EngineConfig {
    /// Capacity of the event queue. Events past it are dropped and counted.
    pub event_capacity: u32,
    /// tokio worker threads (at least 1).
    pub worker_threads: u32,
    /// Must-fail controls: `"cancel"` (cancel is a no-op) or `"token"` (byte-path
    /// token check off). Anything else, or none, is a normal build.
    pub break_mode: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EchoResult {
    pub id: u64,
    pub bytes: u64,
    pub connect_ms: f64,
    pub echo_ms: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DialState {
    Pending,
    Finished,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EventKind {
    Started,
    Stopping,
    DialStarted,
    DialConnected,
    EchoOk,
    DialFailed,
    DialCancelled,
    DialStopped,
    ByteClientOpen,
    ByteClientRefused,
    ByteClientClosed,
    Test,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Event {
    /// Increases by one per event emitted, including dropped ones.
    pub seq: u64,
    pub kind: EventKind,
    /// Dial or connection id; 0 when not tied to one.
    pub id: u64,
    pub info: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EventBatch {
    pub events: Vec<Event>,
    /// Events dropped since the engine was created because the queue was full.
    pub dropped_total: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EngineStatus {
    pub running: bool,
    /// Dial tasks still alive (pending or finishing).
    pub live_dials: u64,
    /// Sockets the engine holds open (listeners, connections, pending connects).
    pub open_sockets: i64,
    /// Tasks alive on the engine's runtime.
    pub alive_tasks: u64,
    pub events_dropped: u64,
}

#[derive(Default)]
pub(crate) struct Shared {
    pub sockets: AtomicI64,
    pub live_dials: AtomicI64,
    pub events_dropped: AtomicU64,
    pub seq: AtomicU64,
    pub next_id: AtomicU64,
}

/// Counts one engine-held socket for as long as it lives.
pub(crate) struct SocketGuard(Arc<Shared>);

impl SocketGuard {
    pub fn new(shared: &Arc<Shared>) -> Self {
        shared.sockets.fetch_add(1, Ordering::SeqCst);
        SocketGuard(shared.clone())
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        self.0.sockets.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub(crate) struct Emitter {
    tx: mpsc::Sender<Event>,
    shared: Arc<Shared>,
}

impl Emitter {
    pub fn emit(&self, kind: EventKind, id: u64, info: impl Into<String>) {
        let seq = self.shared.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let ev = Event {
            seq,
            kind,
            id,
            info: info.into(),
        };
        if self.tx.try_send(ev).is_err() {
            self.shared.events_dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
}

type DialHandle = JoinHandle<Result<EchoResult, NetError>>;

struct DialSlot {
    token: CancellationToken,
    handle: Option<DialHandle>,
    live: Arc<AtomicBool>,
}

type Dials = Arc<Mutex<HashMap<u64, DialSlot>>>;

pub(crate) struct Running {
    rt: Runtime,
    pub root: CancellationToken,
    dials: Dials,
    pub emitter: Emitter,
    events_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Event>>>,
    pub byte_path: Option<Arc<bytepath::Server>>,
}

impl Running {
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.rt.handle().clone()
    }
}

#[derive(uniffi::Object)]
pub struct Engine {
    cfg: EngineConfig,
    pub(crate) shared: Arc<Shared>,
    pub(crate) state: Mutex<Option<Running>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Marks a dial finished however its task ends (completion, cancel or runtime drop).
struct LiveGuard {
    shared: Arc<Shared>,
    live: Arc<AtomicBool>,
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.live.store(false, Ordering::SeqCst);
        self.shared.live_dials.fetch_sub(1, Ordering::SeqCst);
    }
}

/// While a foreign caller awaits a dial: if the caller's task is cancelled (Swift
/// `Task.cancel`, Kotlin `Job.cancel`), the future is dropped and so is the dial.
struct WaitGuard {
    token: Option<CancellationToken>,
    dials: Dials,
    id: u64,
}

impl WaitGuard {
    fn disarm(&mut self) {
        self.token = None;
    }
}

impl Drop for WaitGuard {
    fn drop(&mut self) {
        if let Some(t) = self.token.take() {
            t.cancel();
        }
        lock(&self.dials).remove(&self.id);
    }
}

/// Aborts a spawned helper task when the foreign future awaiting it is dropped.
pub(crate) struct AbortOnDrop<T>(pub Option<JoinHandle<T>>);

impl<T> AbortOnDrop<T> {
    pub async fn join(mut self) -> Result<T, NetError> {
        let h = self.0.as_mut().expect("handle present until joined");
        let r = h.await;
        self.0 = None;
        r.map_err(|_| NetError::Stopped)
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
        }
    }
}

pub(crate) fn pattern_byte(i: u64) -> u8 {
    ((i.wrapping_mul(31).wrapping_add(7)) % 251) as u8
}

impl Engine {
    pub(crate) fn breaks(&self, what: &str) -> bool {
        self.cfg.break_mode.as_deref() == Some(what)
    }

    pub(crate) fn with_running<T>(
        &self,
        f: impl FnOnce(&mut Running) -> Result<T, NetError>,
    ) -> Result<T, NetError> {
        let mut g = lock(&self.state);
        let run = g.as_mut().ok_or(NetError::NotRunning)?;
        f(run)
    }

    fn shutdown(run: Running) {
        run.emitter.emit(EventKind::Stopping, 0, "");
        run.root.cancel();
        lock(&run.dials).clear();
        if tokio::runtime::Handle::try_current().is_ok() {
            // Dropped from inside some runtime: blocking here would panic.
            run.rt.shutdown_background();
        } else {
            run.rt.shutdown_timeout(SHUTDOWN_GRACE);
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if let Some(run) = lock(&self.state).take() {
            Engine::shutdown(run);
        }
    }
}

async fn read_frame(s: &mut TcpStream) -> Result<Option<Vec<u8>>, NetError> {
    let mut len = [0u8; 4];
    match s.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let n = u32::from_be_bytes(len);
    if n > MAX_ECHO_FRAME {
        return Err(NetError::Protocol {
            msg: format!("frame too large: {n}"),
        });
    }
    let mut buf = vec![0u8; n as usize];
    s.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

async fn write_frame(s: &mut TcpStream, payload: &[u8]) -> Result<(), NetError> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    s.write_all(&out).await?;
    Ok(())
}

async fn echo_conn(mut s: TcpStream) -> Result<(), NetError> {
    while let Some(frame) = read_frame(&mut s).await? {
        write_frame(&mut s, &frame).await?;
    }
    Ok(())
}

async fn dial_echo(
    addr: SocketAddr,
    shared: Arc<Shared>,
    id: u64,
    em: Emitter,
) -> Result<EchoResult, NetError> {
    let t0 = Instant::now();
    let _sock = SocketGuard::new(&shared);
    let sock = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    let mut s = sock.connect(addr).await?;
    s.set_nodelay(true)?;
    let connect_ms = t0.elapsed().as_secs_f64() * 1e3;
    em.emit(EventKind::DialConnected, id, addr.to_string());
    let payload: Vec<u8> = (0..1024u64).map(|i| pattern_byte(i + id)).collect();
    let t1 = Instant::now();
    write_frame(&mut s, &payload).await?;
    let back = read_frame(&mut s)
        .await?
        .ok_or_else(|| NetError::Protocol {
            msg: "echo closed early".into(),
        })?;
    if back != payload {
        return Err(NetError::Protocol {
            msg: "echo mismatch".into(),
        });
    }
    let echo_ms = t1.elapsed().as_secs_f64() * 1e3;
    em.emit(EventKind::EchoOk, id, format!("{} bytes", payload.len()));
    Ok(EchoResult {
        id,
        bytes: payload.len() as u64,
        connect_ms,
        echo_ms,
    })
}

#[uniffi::export]
impl Engine {
    #[uniffi::constructor]
    pub fn new(config: EngineConfig) -> Arc<Self> {
        Arc::new(Engine {
            cfg: config,
            shared: Arc::new(Shared::default()),
            state: Mutex::new(None),
        })
    }

    /// Builds the runtime. Fails with `AlreadyRunning` if started twice.
    pub fn start(&self) -> Result<(), NetError> {
        let mut g = lock(&self.state);
        if g.is_some() {
            return Err(NetError::AlreadyRunning);
        }
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(self.cfg.worker_threads.max(1) as usize)
            .thread_name("mousse-net")
            .enable_all()
            .build()?;
        let (tx, rx) = mpsc::channel(self.cfg.event_capacity.max(1) as usize);
        let emitter = Emitter {
            tx,
            shared: self.shared.clone(),
        };
        emitter.emit(EventKind::Started, 0, "");
        *g = Some(Running {
            rt,
            root: CancellationToken::new(),
            dials: Arc::new(Mutex::new(HashMap::new())),
            emitter,
            events_rx: Arc::new(tokio::sync::Mutex::new(rx)),
            byte_path: None,
        });
        Ok(())
    }

    /// Cancels every dial and server, then shuts the runtime down. Pending waits
    /// resolve with `Stopped`. Returns false if the engine wasn't running.
    pub fn stop(&self) -> bool {
        let run = lock(&self.state).take();
        match run {
            Some(run) => {
                Engine::shutdown(run);
                true
            }
            None => false,
        }
    }

    pub fn is_running(&self) -> bool {
        lock(&self.state).is_some()
    }

    /// Starts a loopback echo server for dials to reach; returns `127.0.0.1:<port>`.
    pub fn start_echo_server(&self) -> Result<String, NetError> {
        let shared = self.shared.clone();
        self.with_running(|run| {
            let std_l = std::net::TcpListener::bind("127.0.0.1:0")?;
            std_l.set_nonblocking(true)?;
            let addr = std_l.local_addr()?;
            let _enter = run.rt.enter();
            let listener = TcpListener::from_std(std_l)?;
            let root = run.root.clone();
            run.rt.spawn(async move {
                let _sock = SocketGuard::new(&shared);
                loop {
                    let accepted = tokio::select! {
                        _ = root.cancelled() => break,
                        a = listener.accept() => a,
                    };
                    let Ok((s, _)) = accepted else { continue };
                    let _ = s.set_nodelay(true);
                    let guard = SocketGuard::new(&shared);
                    let root = root.clone();
                    tokio::spawn(async move {
                        let _guard = guard;
                        tokio::select! {
                            _ = root.cancelled() => {}
                            _ = echo_conn(s) => {}
                        }
                    });
                }
            });
            Ok(addr.to_string())
        })
    }

    /// Starts a dial (TCP connect, then one 1 KiB echo round trip) and returns its id
    /// at once. Await it with `wait_dial`; cancel it with `cancel`.
    pub fn dial(&self, addr: String) -> Result<u64, NetError> {
        let sa: SocketAddr = addr.parse().map_err(|_| NetError::Protocol {
            msg: format!("bad address {addr}"),
        })?;
        let shared = self.shared.clone();
        self.with_running(|run| {
            let id = shared.next_id.fetch_add(1, Ordering::SeqCst) + 1;
            let token = run.root.child_token();
            let root = run.root.clone();
            let em = run.emitter.clone();
            let live = Arc::new(AtomicBool::new(true));
            shared.live_dials.fetch_add(1, Ordering::SeqCst);
            let guard = LiveGuard { shared: shared.clone(), live: live.clone() };
            let t = token.clone();
            let handle = run.rt.spawn(async move {
                let _guard = guard;
                em.emit(EventKind::DialStarted, id, sa.to_string());
                let r = tokio::select! {
                    biased;
                    _ = t.cancelled() => Err(if root.is_cancelled() { NetError::Stopped } else { NetError::Cancelled }),
                    r = tokio::time::timeout(DIAL_TIMEOUT, dial_echo(sa, shared, id, em.clone())) =>
                        r.unwrap_or(Err(NetError::Timeout)),
                };
                match &r {
                    Ok(_) => {}
                    Err(NetError::Cancelled) => em.emit(EventKind::DialCancelled, id, ""),
                    Err(NetError::Stopped) => em.emit(EventKind::DialStopped, id, ""),
                    Err(e) => em.emit(EventKind::DialFailed, id, e.to_string()),
                }
                r
            });
            lock(&run.dials).insert(id, DialSlot { token, handle: Some(handle), live });
            Ok(id)
        })
    }

    /// Waits for a dial. Resolves `Cancelled` after `cancel(id)` and `Stopped` after
    /// `stop()`. Cancelling the calling Swift task or Kotlin coroutine cancels the dial.
    pub async fn wait_dial(&self, id: u64) -> Result<EchoResult, NetError> {
        let break_cancel = self.breaks("cancel");
        let (handle, token, dials) = self.with_running(|run| {
            let mut d = lock(&run.dials);
            let slot = d.get_mut(&id).ok_or(NetError::UnknownDial)?;
            let h = slot.handle.take().ok_or(NetError::AlreadyAwaited)?;
            Ok((h, slot.token.clone(), run.dials.clone()))
        })?;
        let mut guard = WaitGuard {
            token: (!break_cancel).then_some(token),
            dials,
            id,
        };
        let r = handle.await;
        guard.disarm();
        drop(guard);
        match r {
            Ok(r) => r,
            Err(_) => Err(NetError::Stopped),
        }
    }

    /// Cancels a dial. Returns false if the id is unknown or already finished.
    pub fn cancel(&self, id: u64) -> bool {
        let break_cancel = self.breaks("cancel");
        self.with_running(|run| {
            let d = lock(&run.dials);
            let Some(slot) = d.get(&id) else {
                return Ok(false);
            };
            if !slot.live.load(Ordering::SeqCst) {
                return Ok(false);
            }
            if !break_cancel {
                slot.token.cancel();
            }
            Ok(true)
        })
        .unwrap_or(false)
    }

    pub fn dial_state(&self, id: u64) -> DialState {
        self.with_running(|run| {
            Ok(match lock(&run.dials).get(&id) {
                None => DialState::Unknown,
                Some(s) if s.live.load(Ordering::SeqCst) => DialState::Pending,
                Some(_) => DialState::Finished,
            })
        })
        .unwrap_or(DialState::Unknown)
    }

    pub fn status(&self) -> EngineStatus {
        let g = lock(&self.state);
        EngineStatus {
            running: g.is_some(),
            live_dials: self.shared.live_dials.load(Ordering::SeqCst).max(0) as u64,
            open_sockets: self.shared.sockets.load(Ordering::SeqCst),
            alive_tasks: g
                .as_ref()
                .map(|r| r.rt.metrics().num_alive_tasks() as u64)
                .unwrap_or(0),
            events_dropped: self.shared.events_dropped.load(Ordering::SeqCst),
        }
    }

    /// Returns up to `max` events (1..=1024). Waits up to `timeout_ms` for the first
    /// one; an empty batch means none arrived in time.
    pub async fn next_events(&self, max: u32, timeout_ms: u32) -> Result<EventBatch, NetError> {
        let max = max.clamp(1, 1024) as usize;
        let wait = Duration::from_millis(timeout_ms as u64);
        let task = self.with_running(|run| {
            let rx = run.events_rx.clone();
            Ok(run.rt.spawn(async move {
                let mut rx = rx.lock().await;
                let mut out = Vec::new();
                if let Ok(Some(e)) = tokio::time::timeout(wait, rx.recv()).await {
                    out.push(e);
                }
                while out.len() < max {
                    match rx.try_recv() {
                        Ok(e) => out.push(e),
                        Err(_) => break,
                    }
                }
                out
            }))
        })?;
        let events = AbortOnDrop(Some(task)).join().await?;
        Ok(EventBatch {
            events,
            dropped_total: self.shared.events_dropped.load(Ordering::SeqCst),
        })
    }

    /// Emits `n` test events, to check that the queue stays bounded.
    pub fn emit_test_events(&self, n: u32) -> Result<(), NetError> {
        self.with_running(|run| {
            for i in 0..n {
                run.emitter.emit(EventKind::Test, 0, i.to_string());
            }
            Ok(())
        })
    }
}
