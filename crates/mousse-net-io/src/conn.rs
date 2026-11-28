//! The session driver: one task per TLS connection.
//!
//! It runs the mux, the control stream and a traffic gate over the TLS byte
//! stream, and hands streams to the application:
//!
//! - Every inbound frame is decoded once here, classified, and checked
//!   against the gate **before** the mux sees it. On the host the gate is
//!   core's [`ConnectionGate`](mousse_net_core::authz::ConnectionGate), so an
//!   ungranted peer can never open a stream.
//! - `HELLO` is the first thing each side sends and must be the first control
//!   message received; core's `HelloState` decides the minor version
//!   or closes with `UNSUPPORTED_VERSION`; a later `HELLO` is ignored.
//! - The connection closes with `CERT_EXPIRED` after the effective deadline
//!   of the two certificates. The deadline is checked before every inbound
//!   frame, every stream open or send, and every write, not only when the
//!   timer fires: after it nothing but the closing `GOAWAY` goes out, and
//!   queued stream data is dropped. A write still waiting on the pipe when
//!   the deadline passes is abandoned with the pipe, so its bytes never
//!   leave after the deadline.
//! - The deadline is also kept on the monotonic clock from the start of the
//!   connection (wire.md 6), so setting the wall clock back never extends
//!   it. Both are checked again at least once a second, so a device that
//!   slept past either closes as soon as it resumes.
//! - A step that ends the connection (for example a joiner's last failed
//!   code attempt) sends the messages it produced, then one `GOAWAY`
//!   (wire.md 10.6, rule 9).
//! - Each stream half can wait for its connection to start closing
//!   ([`StreamWriter::closing`]), so a task serving a stream ends with the
//!   connection even after the peer finished its side of the stream.
//! - A separate writer task owns the write half, so a slow peer never stops
//!   us reading. It takes one frame at a time from the mux, only when the
//!   pipe has taken the previous one, so nothing queues between the mux and
//!   TLS: a `CREDIT` due when the peer's `FIN` arrives is dropped, not sent.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use mousse_net_core::authz::{Traffic, Verdict};
#[allow(unused_imports)] // Used by the debug-only test hook and docs.
use mousse_net_core::control::DIRECT_MINOR_VERSION;
use mousse_net_core::control::{ControlMessage, HelloOutcome, HelloState, VersionSupport};
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::{
    decode_frame, frame_type, Frame, Mux, MuxEvent, MuxRole, PriorityClass, StreamError, StreamId,
    MAX_CONTROL_PAYLOAD,
};
use mousse_net_core::pairing::{PairedHost, PairingCode};
use mousse_net_core::{ConnectionId, ErrorCode, Millis, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use tokio_rustls::TlsStream;

use crate::admission::{ConnStreams, HelloSeen, Room, StreamAdmission, StreamPermit};
use crate::clock::Clock;
use crate::error::NetError;
use crate::limits::{ms, CoreLimits, Limits};
use crate::pipe::Pipe;

/// The driver's limits, from [`Limits`], as the types it uses.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DriverLimits {
    /// Queued bytes per stream above which [`StreamWriter::write`] waits.
    write_high_water: usize,
    /// How long a closing connection may take to send its last frame and
    /// shut the pipe down before it is dropped.
    close_linger: Duration,
    /// How often a write still pending checks the deadline.
    deadline_poll: Duration,
    /// The longest the driver sleeps without reading both clocks again.
    /// Timers do not run while a device sleeps, so this is what notices, on
    /// resume, a deadline that passed meanwhile.
    recheck: Duration,
    /// Bytes read from the pipe at a time.
    read_buffer: usize,
    /// Size of the buffers small received DATA frames share.
    rx_chunk: usize,
}

/// The variable that makes a debug build speak another newest minor
/// version (tests only; release builds ignore it): an older one, as an
/// older peer does, or the minor that adds Pair with IP
/// ([`DIRECT_MINOR_VERSION`]) before the build's own minor reaches it.
pub const TEST_HELLO_MINOR_VAR: &str = "MOUSSE_NET_TEST_HELLO_MINOR";

/// The versions this side speaks: [`VersionSupport::LOCAL`], or in a debug
/// build with [`TEST_HELLO_MINOR_VAR`] set, what `test_version` makes of it.
fn local_version() -> VersionSupport {
    #[cfg(debug_assertions)]
    if let Some(version) = std::env::var(TEST_HELLO_MINOR_VAR)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .and_then(test_version)
    {
        return version;
    }
    VersionSupport::LOCAL
}

/// The versions a debug build speaks when a test asks for newest minor
/// `minor`: an older one than the build's own, or [`DIRECT_MINOR_VERSION`]
/// (never anything else newer), with the one before it. `None` keeps
/// [`VersionSupport::LOCAL`].
#[cfg(debug_assertions)]
fn test_version(minor: u64) -> Option<VersionSupport> {
    let local = VersionSupport::LOCAL;
    (minor < local.minor || minor == DIRECT_MINOR_VERSION).then_some(VersionSupport {
        major: local.major,
        minor,
        oldest_minor: minor.saturating_sub(1),
    })
}

/// The newest minor version this side sends in `HELLO`: the build's own, or
/// in a debug build the one [`TEST_HELLO_MINOR_VAR`] names.
pub fn local_minor() -> u64 {
    local_version().minor
}

impl DriverLimits {
    fn new(limits: &Limits) -> Self {
        let io = limits.io();
        Self {
            write_high_water: usize::try_from(io.write_high_water_bytes()).unwrap_or(usize::MAX),
            close_linger: ms(io.close_linger_ms()),
            deadline_poll: ms(io.deadline_poll_ms()),
            recheck: ms(io.clock_recheck_ms()),
            read_buffer: usize::try_from(io.read_buffer_bytes()).unwrap_or(usize::MAX),
            rx_chunk: usize::try_from(io.rx_chunk_bytes()).unwrap_or(usize::MAX),
        }
    }
}

/// The end of a connection: the effective deadline on the wall clock, and
/// the same span on the monotonic clock from when the connection started
/// (`mono_deadline`, wire.md 6). It ends at whichever comes first.
#[derive(Clone, Copy, Debug)]
struct Deadline {
    wall: UnixTime,
    mono: Millis,
}

impl Deadline {
    fn new(wall: UnixTime, clock: &dyn Clock) -> Self {
        let left = wall
            .secs()
            .saturating_add(1)
            .saturating_sub(clock.now().secs());
        Self {
            wall,
            mono: clock.mono().plus(left.saturating_mul(1000)),
        }
    }

    /// Past the wall deadline (the connection may run through that second
    /// and no further), or at the monotonic one.
    fn passed(&self, clock: &dyn Clock) -> bool {
        clock.now() > self.wall || clock.mono() >= self.mono
    }
}

/// Why a connection ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// We closed it with this code.
    Local(ErrorCode),
    /// The peer sent `GOAWAY` with this code.
    Peer(ErrorCode),
    /// The pipe ended without `GOAWAY`.
    PipeClosed,
    /// The pipe failed.
    Io(String),
}

impl CloseReason {
    /// The wire code, if there was one.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            CloseReason::Local(c) | CloseReason::Peer(c) => Some(*c),
            _ => None,
        }
    }
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloseReason::Local(c) => write!(f, "closed here ({})", c.name()),
            CloseReason::Peer(c) => write!(f, "closed by the peer ({})", c.name()),
            CloseReason::PipeClosed => f.write_str("the connection dropped"),
            CloseReason::Io(e) => write!(f, "the connection failed: {e}"),
        }
    }
}

/// Where a connection stands, as seen from this side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnStatus {
    /// Step 2 has not decided yet.
    Pending,
    /// Pairing messages only.
    JoinOnly,
    /// Send link: the host admitted this device; type the code shown on the
    /// host. `retry` is set after a wrong code.
    CodeNeeded {
        /// Code attempts left in this flow.
        attempts_left: u8,
        /// The previous code was wrong.
        retry: bool,
    },
    /// Normal channels.
    Live,
    /// Pairing finished on this connection; it is now live.
    Paired(PairedHost),
    /// The host already had a live grant for this device (pairing ended
    /// with "already paired"); the connection is live.
    AlreadyPaired,
    /// Closed.
    Closed(CloseReason),
}

impl ConnStatus {
    /// Whether streams may be used.
    pub fn is_live(&self) -> bool {
        matches!(
            self,
            ConnStatus::Live | ConnStatus::Paired(_) | ConnStatus::AlreadyPaired
        )
    }
}

/// Things a role asks the driver to do.
#[derive(Default)]
pub(crate) struct Outbox {
    pub control: Vec<ControlMessage>,
    pub close: Option<ErrorCode>,
    pub status: Option<ConnStatus>,
}

/// The side-specific part of a connection: step 2 on the host, the caller's
/// view of it, pairing.
pub(crate) trait Role: Send + 'static {
    /// The driver queued `HELLO`; queue whatever comes next.
    fn on_start(&mut self, out: &mut Outbox);
    /// The peer's first `HELLO` agreed on `minor`. A role that must not
    /// send before it knows the version (a Pair with IP joiner) starts
    /// here.
    fn on_hello(&mut self, _minor: u64, _out: &mut Outbox) {}
    /// Decide what to do with inbound traffic (`message` is the decoded
    /// control message, if it is one).
    fn check(&mut self, traffic: Traffic, message: Option<&ControlMessage>) -> Verdict;
    /// A control message (other than `HELLO`) passed the gate.
    fn on_control(&mut self, message: ControlMessage, out: &mut Outbox);
    /// Whether this side may open streams now.
    fn may_open(&self) -> bool;
    /// The connection ended.
    fn on_closed(&mut self, reason: &CloseReason);
    /// The peer's `GOAWAY` arrived, with this code; [`Role::on_closed`]
    /// follows once the connection is torn down.
    fn on_goaway(&mut self, _code: ErrorCode) {}
    /// The owner typed a pairing code (send link, joiner only).
    fn on_code(&mut self, _code: PairingCode, out: &mut Outbox) {
        out.close = Some(ErrorCode::ProtocolError);
    }
    /// When the role next needs [`Role::on_wake`], on the monotonic clock.
    fn wake_at(&self) -> Option<Millis> {
        None
    }
    /// A timer ran (at least at [`Role::wake_at`], maybe earlier).
    fn on_wake(&mut self, _mono: Millis, _out: &mut Outbox) {}
}

pub(crate) enum Cmd {
    Open {
        class: PriorityClass,
        label: String,
        reply: oneshot::Sender<Result<MuxStream, NetError>>,
    },
    Send {
        stream: StreamId,
        bytes: Vec<u8>,
        reply: oneshot::Sender<Result<(), NetError>>,
    },
    Finish(StreamId),
    Reset(StreamId, ErrorCode),
    Release(StreamId, u64),
    Control(ControlMessage),
    Close(ErrorCode),
    /// A role's step from outside the driver, applied as one: control
    /// messages that come with a close go out before its `GOAWAY`.
    Apply(Outbox),
    Status(ConnStatus),
    Code(PairingCode),
    /// Answered when the peer's next `PONG` arrives.
    Ping(oneshot::Sender<()>),
    /// Answered once nothing queued before this command can still leave:
    /// the connection is closing (closing drops the mux's queue) and the
    /// writer has finished the frame it held, or the driver ended. Sent
    /// after a [`Cmd::Close`].
    Fence(oneshot::Sender<()>),
}

/// How a stream's receive side ended.
enum StreamEnd {
    Fin,
    Reset(ErrorCode),
    ConnectionClosed(CloseReason),
}

/// What each receive buffer costs besides its bytes: the vector, its place
/// in the queue, and the allocator's share.
const RX_BUFFER_OVERHEAD: u64 = 64;

/// One stream's received bytes, not yet read, and how the stream ended.
/// Bytes from small DATA frames share a buffer of `RX_CHUNK_BYTES`, so a
/// peer sending many tiny frames leaves few allocations: what waits costs
/// at most its bytes twice over plus one buffer, and a buffer's overhead
/// for every `RX_CHUNK_BYTES`.
#[derive(Default)]
struct RxState {
    chunks: VecDeque<Vec<u8>>,
    end: Option<StreamEnd>,
    /// The reader is gone: nothing more is kept.
    gone: bool,
    /// This side reset the stream with this code ([`StreamWriter::reset`]).
    reset: Option<ErrorCode>,
}

struct RxQueue {
    state: std::sync::Mutex<RxState>,
    ready: tokio::sync::Notify,
    admission: Arc<StreamAdmission>,
}

impl RxQueue {
    fn lock(&self) -> std::sync::MutexGuard<'_, RxState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Keep `bytes` for the reader. False if the reader is gone.
    fn push(&self, bytes: Vec<u8>, chunk: usize) -> bool {
        let mut st = self.lock();
        if st.gone {
            return false;
        }
        let n = bytes.len();
        let admission = &self.admission;
        // Counted before the reader can take it.
        admission.add_queued(n as u64);
        match st.chunks.back_mut() {
            Some(last) if last.capacity() - last.len() >= n => last.extend_from_slice(&bytes),
            _ if n >= chunk => {
                admission.add_held(bytes.capacity() as u64 + RX_BUFFER_OVERHEAD);
                st.chunks.push_back(bytes);
            }
            _ => {
                let mut buf = Vec::with_capacity(chunk);
                buf.extend_from_slice(&bytes);
                admission.add_held(buf.capacity() as u64 + RX_BUFFER_OVERHEAD);
                st.chunks.push_back(buf);
            }
        }
        drop(st);
        self.ready.notify_one();
        true
    }

    /// The stream ended; the first end counts.
    fn end(&self, end: StreamEnd) {
        let mut st = self.lock();
        if st.end.is_none() {
            st.end = Some(end);
        }
        drop(st);
        self.ready.notify_one();
    }

    /// This side resets the stream with `code`; the first code counts.
    fn mark_reset(&self, code: ErrorCode) {
        self.lock().reset.get_or_insert(code);
    }

    /// The code this side reset the stream with, if it did.
    fn local_reset(&self) -> Option<ErrorCode> {
        self.lock().reset
    }

    /// The reader let go: drop what waits.
    fn close(&self) {
        let mut st = self.lock();
        st.gone = true;
        for chunk in st.chunks.drain(..) {
            self.admission.sub_queued(chunk.len() as u64);
            self.admission
                .sub_held(chunk.capacity() as u64 + RX_BUFFER_OVERHEAD);
        }
    }
}

/// The driver's end of one stream's receive side. A peer reset is also
/// posted on `reset`, so a reader that is holding back still learns of it
/// ([`StreamReader::reset_by_peer`]). Kept until the mux is done with the
/// stream: after the peer's FIN this side's half may still be open, and a
/// RESET may follow.
struct StreamTx {
    rx: Arc<RxQueue>,
    reset: watch::Sender<Option<ErrorCode>>,
    /// The peer finished its half.
    fin: bool,
}

impl StreamTx {
    fn end(&self, end: StreamEnd) {
        if let StreamEnd::Reset(code) = &end {
            self.reset.send_replace(Some(*code));
        }
        self.rx.end(end);
    }
}

/// The receiving half of a stream. It holds the stream's place (see
/// [`crate::admission`]) until it is dropped.
pub struct StreamReader {
    id: StreamId,
    rx: Arc<RxQueue>,
    cmd: mpsc::UnboundedSender<Cmd>,
    ended: Option<Result<(), NetError>>,
    closing: watch::Receiver<bool>,
    _permit: Arc<StreamPermit>,
    reset: watch::Receiver<Option<ErrorCode>>,
}

impl Drop for StreamReader {
    fn drop(&mut self) {
        // Bytes nobody will read leave the gauges.
        self.rx.close();
    }
}

impl StreamReader {
    /// The next bytes. `Ok(None)` after the peer finished the stream. A reset
    /// or a closed connection is an error. Reading returns credit to the
    /// peer.
    pub async fn read(&mut self) -> Result<Option<Vec<u8>>, NetError> {
        if let Some(end) = &self.ended {
            return match end {
                Ok(()) => Ok(None),
                Err(e) => Err(clone_err(e)),
            };
        }
        let result = loop {
            {
                let mut st = self.rx.lock();
                if let Some(bytes) = st.chunks.pop_front() {
                    drop(st);
                    let admission = &self.rx.admission;
                    admission.sub_queued(bytes.len() as u64);
                    admission.sub_held(bytes.capacity() as u64 + RX_BUFFER_OVERHEAD);
                    let _ = self.cmd.send(Cmd::Release(self.id, bytes.len() as u64));
                    return Ok(Some(bytes));
                }
                if let Some(end) = st.end.take() {
                    break match end {
                        StreamEnd::Fin => Ok(()),
                        StreamEnd::Reset(code) => Err(NetError::StreamReset(code)),
                        StreamEnd::ConnectionClosed(reason) => Err(NetError::Closed(reason)),
                    };
                }
            }
            // One reader: a wake sent before this wait is kept for it.
            self.rx.ready.notified().await;
        };
        let out = match &result {
            Ok(()) => Ok(None),
            Err(e) => Err(clone_err(e)),
        };
        self.ended = Some(result);
        out
    }

    /// Wait until the connection starts closing (see
    /// [`StreamWriter::closing`]).
    pub async fn closing(&self) {
        wait_closing(self.closing.clone()).await;
    }

    /// Wait until the peer resets the stream, and return its code. Unlike
    /// [`StreamReader::read`], this does not take bytes off the queue, so
    /// a reader that holds back (for example for want of credit further
    /// on) still learns of a reset at once. Never returns for a stream that
    /// ends any other way.
    pub async fn reset_by_peer(&self) -> ErrorCode {
        let mut rx = self.reset.clone();
        let code = match rx.wait_for(Option::is_some).await {
            Ok(code) => *code,
            Err(_) => None,
        };
        match code {
            Some(code) => code,
            None => std::future::pending().await,
        }
    }
}

async fn wait_closing(mut rx: watch::Receiver<bool>) {
    // An error means the driver is gone: closed as well.
    let _ = rx.wait_for(|closing| *closing).await;
}

fn clone_err(e: &NetError) -> NetError {
    match e {
        NetError::StreamReset(c) => NetError::StreamReset(*c),
        NetError::Closed(r) => NetError::Closed(r.clone()),
        other => NetError::Refused(other.to_string()),
    }
}

/// The sending half of a stream. Cheap to clone.
#[derive(Clone)]
pub struct StreamWriter {
    id: StreamId,
    rx: Arc<RxQueue>,
    cmd: mpsc::UnboundedSender<Cmd>,
    closing: watch::Receiver<bool>,
}

impl StreamWriter {
    /// Queue bytes. Waits while more than
    /// [`IoLimits::write_high_water_bytes`](crate::limits::IoLimits::write_high_water_bytes)
    /// are queued on this stream.
    pub async fn write(&self, bytes: &[u8]) -> Result<(), NetError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let (reply, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Send {
                stream: self.id,
                bytes: bytes.to_vec(),
                reply,
            })
            .map_err(|_| NetError::Closed(CloseReason::PipeClosed))?;
        rx.await
            .map_err(|_| NetError::Closed(CloseReason::PipeClosed))?
    }

    /// Finish sending (`FIN` after the queued bytes).
    pub fn finish(&self) {
        let _ = self.cmd.send(Cmd::Finish(self.id));
    }

    /// Abort the stream in both directions. The peer gets `code`, also when
    /// DATA it already sent arrives before the reset is sent and finds the
    /// reader gone.
    pub fn reset(&self, code: ErrorCode) {
        self.rx.mark_reset(code);
        let _ = self.cmd.send(Cmd::Reset(self.id, code));
    }

    /// Wait until the connection starts closing, for any reason: the grant
    /// was removed or expired, a certificate ran out, either side sent
    /// `GOAWAY`, or the pipe failed. Unlike reading, this keeps working
    /// after the peer finished its side of the stream, so a task serving
    /// the stream can stop its work (for example a running command) when
    /// access ends.
    pub async fn closing(&self) {
        wait_closing(self.closing.clone()).await;
    }
}

/// One mux stream.
pub struct MuxStream {
    /// Receiving half.
    pub reader: StreamReader,
    /// Sending half.
    pub writer: StreamWriter,
    label: String,
    class: PriorityClass,
}

impl MuxStream {
    /// The stream's label (for example `terminal`).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The stream's priority class.
    pub fn class(&self) -> PriorityClass {
        self.class
    }

    /// The stream id.
    pub fn id(&self) -> StreamId {
        self.writer.id
    }

    /// Split into halves for use from two tasks.
    pub fn split(self) -> (StreamReader, StreamWriter) {
        (self.reader, self.writer)
    }
}

/// Whether a connection has started to close, shared by its handle and its
/// driver. Marking it waits for any [`LivePermit`] to be dropped, so what
/// was done under a permit was done while the connection was live.
#[derive(Debug, Default)]
struct Liveness {
    closing: AtomicBool,
    gate: Mutex<()>,
}

impl Liveness {
    /// Mark closing, once every permit held now is dropped.
    fn mark(&self) {
        if self.is_set() {
            return;
        }
        // Must-fail control (tests only): closing does not wait for the
        // permits held.
        if cfg!(mousse_control = "live-permit-ignored") {
            self.closing.store(true, Ordering::SeqCst);
            return;
        }
        let _gate = self.gate.lock().unwrap_or_else(PoisonError::into_inner);
        self.closing.store(true, Ordering::SeqCst);
    }

    /// Whether it is marked; never waits.
    fn is_set(&self) -> bool {
        self.closing.load(Ordering::SeqCst)
    }
}

/// Proof that a connection was live when the permit was taken and stays
/// live while it is held: [`Connection::close`] and the driver's shutdown
/// wait for it before the connection reads as closing. Hold one only for
/// a short in-memory step, never across an `.await` or I/O.
pub struct LivePermit<'a> {
    _gate: MutexGuard<'a, ()>,
}

/// A handle to a running connection. Dropping it closes the connection with
/// `NO_ERROR`.
pub struct Connection {
    id: ConnectionId,
    peer: IdentityPublicKey,
    kx_group: String,
    deadline: UnixTime,
    cmd: mpsc::UnboundedSender<Cmd>,
    status: watch::Receiver<ConnStatus>,
    incoming: tokio::sync::Mutex<mpsc::UnboundedReceiver<MuxStream>>,
    /// The minor version both sides agreed, once the peer's `HELLO` came.
    minor: watch::Receiver<Option<u64>>,
    /// The newest minor version the peer's first `HELLO` named, whether or
    /// not it was accepted, and when that `HELLO` was read.
    peer_hello: Arc<OnceLock<(u64, Instant)>>,
    /// Set by [`Connection::close`] at once and by the driver when the
    /// connection starts to close for any reason.
    shutting: Arc<Liveness>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Connection({}, {:?})", self.id.0, self.peer)
    }
}

impl Connection {
    /// Local connection id.
    pub fn id(&self) -> ConnectionId {
        self.id
    }

    /// The peer identity proven in step 1.
    pub fn peer(&self) -> &IdentityPublicKey {
        &self.peer
    }

    /// The negotiated key exchange group.
    pub fn kx_group(&self) -> &str {
        &self.kx_group
    }

    /// The last second this connection may carry traffic: the earlier
    /// effective deadline of the two certificates.
    pub fn deadline(&self) -> UnixTime {
        self.deadline
    }

    /// The minor protocol version agreed from the peer's first `HELLO`,
    /// once it has arrived. Engine streams that need a later minor are
    /// opened only when this allows them. A peer's stream frames are
    /// accepted only after its `HELLO`, so it is known on any connection
    /// the peer has opened a stream on; a host may be live before its
    /// caller's `HELLO` arrives ([`Connection::hello_minor`] waits).
    pub fn minor(&self) -> Option<u64> {
        *self.minor.borrow()
    }

    /// The newest minor version the peer's first `HELLO` named, once it
    /// arrived, also when no version was agreed. Set before the connection
    /// reads as closed, so a connection that closed with
    /// `UNSUPPORTED_VERSION` after that `HELLO` always has it.
    pub fn peer_minor(&self) -> Option<u64> {
        self.peer_hello.get().map(|(minor, _)| *minor)
    }

    /// When the peer's first `HELLO` was read: on a connection that agreed
    /// a version, when that became known.
    pub fn hello_at(&self) -> Option<Instant> {
        self.peer_hello.get().map(|(_, at)| *at)
    }

    /// The error for a connection that closed with `reason` before it
    /// reached the state its caller waited for: [`NetError::Version`] when
    /// either side closed it with `UNSUPPORTED_VERSION` after the peer's
    /// `HELLO` was read, otherwise [`NetError::Closed`].
    pub fn closed_error(&self, reason: CloseReason) -> NetError {
        match (reason.code(), self.peer_minor()) {
            (Some(ErrorCode::UnsupportedVersion), Some(peer_minor)) => {
                NetError::Version { reason, peer_minor }
            }
            _ => NetError::Closed(reason),
        }
    }

    /// Wait for the peer's first `HELLO` and return the agreed minor
    /// version; `None` if the connection ends first. A host can be live
    /// before its caller's `HELLO` has arrived.
    pub async fn hello_minor(&self) -> Option<u64> {
        let mut rx = self.minor.clone();
        let mut status = self.status.clone();
        loop {
            if let Some(minor) = *rx.borrow_and_update() {
                return Some(minor);
            }
            if matches!(*status.borrow_and_update(), ConnStatus::Closed(_)) {
                return None;
            }
            tokio::select! {
                changed = rx.changed() => if changed.is_err() { return *rx.borrow() },
                changed = status.changed() => if changed.is_err() { return *rx.borrow() },
            }
        }
    }

    /// The current status.
    pub fn status(&self) -> ConnStatus {
        self.status.borrow().clone()
    }

    /// Wait until the status is no longer [`ConnStatus::Pending`] (or
    /// [`ConnStatus::JoinOnly`] when `past_join_only`), and return it.
    pub async fn settled(&self, past_join_only: bool) -> ConnStatus {
        let mut rx = self.status.clone();
        loop {
            let current = rx.borrow_and_update().clone();
            match current {
                ConnStatus::Pending => {}
                ConnStatus::JoinOnly if past_join_only => {}
                other => return other,
            }
            if rx.changed().await.is_err() {
                let last = rx.borrow().clone();
                return match last {
                    ConnStatus::Closed(_) => last,
                    _ => ConnStatus::Closed(CloseReason::PipeClosed),
                };
            }
        }
    }

    /// Wait until the status differs from `from`, and return it.
    pub async fn next_status(&self, from: &ConnStatus) -> ConnStatus {
        let mut rx = self.status.clone();
        loop {
            let current = rx.borrow_and_update().clone();
            if &current != from {
                return current;
            }
            if rx.changed().await.is_err() {
                return match rx.borrow().clone() {
                    closed @ ConnStatus::Closed(_) => closed,
                    _ => ConnStatus::Closed(CloseReason::PipeClosed),
                };
            }
        }
    }

    /// Send link: hand the code the owner typed to the pairing flow.
    pub fn submit_code(&self, code: PairingCode) -> Result<(), NetError> {
        self.cmd
            .send(Cmd::Code(code))
            .map_err(|_| NetError::Closed(CloseReason::PipeClosed))
    }

    /// Wait for the connection to close.
    pub async fn closed(&self) -> CloseReason {
        let mut rx = self.status.clone();
        loop {
            if let ConnStatus::Closed(reason) = rx.borrow_and_update().clone() {
                return reason;
            }
            if rx.changed().await.is_err() {
                return match rx.borrow().clone() {
                    ConnStatus::Closed(reason) => reason,
                    _ => CloseReason::PipeClosed,
                };
            }
        }
    }

    /// Open a stream of `class` with `label`.
    pub async fn open_stream(
        &self,
        class: PriorityClass,
        label: &str,
    ) -> Result<MuxStream, NetError> {
        let (reply, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Open {
                class,
                label: label.to_owned(),
                reply,
            })
            .map_err(|_| self.gone())?;
        rx.await.map_err(|_| self.gone())?
    }

    /// The error for a request the driver can no longer take: the reason
    /// the connection closed.
    fn gone(&self) -> NetError {
        NetError::Closed(match self.status.borrow().clone() {
            ConnStatus::Closed(reason) => reason,
            _ => CloseReason::PipeClosed,
        })
    }

    /// The next stream the peer opened. `None` once the connection closed.
    pub async fn accept_stream(&self) -> Option<MuxStream> {
        self.incoming.lock().await.recv().await
    }

    /// Whether the peer answers a `PING` within `within`: false when it
    /// does not, or the connection closed first.
    pub async fn ping(&self, within: Duration) -> bool {
        let (reply, rx) = oneshot::channel();
        if self.cmd.send(Cmd::Ping(reply)).is_err() {
            return false;
        }
        matches!(tokio::time::timeout(within, rx).await, Ok(Ok(())))
    }

    /// Close with `code`. [`Connection::is_closing`] is true from now on.
    /// Waits for a [`LivePermit`] held elsewhere to be dropped.
    pub fn close(&self, code: ErrorCode) {
        self.shutting.mark();
        let _ = self.cmd.send(Cmd::Close(code));
    }

    /// Whether the connection is closing or closed: [`Connection::close`]
    /// was called, or the driver started to shut down (the peer's
    /// `GOAWAY`, the certificate's deadline, a failed pipe, any close).
    /// Unlike [`Connection::status`], which reads
    /// [`ConnStatus::Closed`] only once the driver is done, this is true
    /// for the whole of the shutdown.
    pub fn is_closing(&self) -> bool {
        self.shutting.is_set() || matches!(*self.status.borrow(), ConnStatus::Closed(_))
    }

    /// A permit that holds off [`Connection::is_closing`] while it is
    /// held, or `None` if the connection is closing already. Work that
    /// must not land on a closing connection (a grant made for its peer)
    /// commits under it.
    pub fn live_permit(&self) -> Option<LivePermit<'_>> {
        let gate = self
            .shutting
            .gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        (!self.is_closing()).then_some(LivePermit { _gate: gate })
    }

    /// Wait until nothing queued on this connection before the call can
    /// still be sent. Call it after [`Connection::close`]: it returns once
    /// the close dropped the queue and the frame being written, if any,
    /// went out (or the connection ended).
    pub async fn fence(&self) {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Cmd::Fence(tx)).is_ok() {
            let _ = rx.await;
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.cmd.send(Cmd::Close(ErrorCode::NoError));
    }
}

/// Everything needed to start a driver.
pub(crate) struct Start<P: Pipe> {
    pub tls: TlsStream<P>,
    pub side: MuxRole,
    pub conn: ConnectionId,
    pub peer: IdentityPublicKey,
    pub kx_group: String,
    pub deadline: UnixTime,
    pub clock: Arc<dyn Clock>,
    pub limits: Limits,
    /// The endpoint's stream places, shared by all its connections.
    pub streams: Arc<StreamAdmission>,
}

/// A command sender for a driver that is about to start. The host registers
/// it before the driver runs, so pairing actions can reach the connection.
pub(crate) fn channel() -> (mpsc::UnboundedSender<Cmd>, mpsc::UnboundedReceiver<Cmd>) {
    mpsc::unbounded_channel()
}

/// Labels of engine-owned streams (wire.md 9.5). They have their own
/// places, apart from the app's stream caps.
pub const ENGINE_LABEL_PREFIX: &str = "mousse-";

/// The mux limits of a connection admitted by `streams`: `MAX_PEER_STREAMS`
/// raised, where it is lower, to every place `streams` gives a connection
/// (app, bot and engine), so the mux never refuses a peer's open before its
/// room's cap is looked at. A caller or host may take its admission from
/// another configuration ([`Caller::use_stream_admission`],
/// [`HostConfig::streams`]); this is where the two meet. Memory stays
/// bounded: those places are, and the mux holds no stream they refuse.
///
/// [`Caller::use_stream_admission`]: crate::Caller::use_stream_admission
/// [`HostConfig::streams`]: crate::HostConfig::streams
fn mux_limits(limits: &Limits, streams: &StreamAdmission) -> CoreLimits {
    let core = *limits.core();
    let spec_max = CoreLimits::SPECS
        .iter()
        .find(|s| s.name == "MAX_PEER_STREAMS")
        .map_or(u64::MAX, |s| s.max);
    let places = u64::try_from(streams.places_per_connection())
        .unwrap_or(u64::MAX)
        .min(spec_max);
    if core.max_peer_streams() >= places {
        return core;
    }
    core.with_overrides(&[("MAX_PEER_STREAMS", places)])
        .unwrap_or(core)
}

/// Start the driver task for one connection.
pub(crate) fn spawn<P: Pipe>(
    start: Start<P>,
    role: Box<dyn Role>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
) -> Connection {
    let (status_tx, status_rx) = watch::channel(ConnStatus::Pending);
    let (closing_tx, _) = watch::channel(false);
    let (accept_tx, accept_rx) = mpsc::unbounded_channel();
    let (minor, minor_rx) = watch::channel(None);
    let peer_hello = Arc::new(OnceLock::new());
    let shutting = Arc::new(Liveness::default());
    let connection = Connection {
        id: start.conn,
        peer: start.peer,
        kx_group: start.kx_group.clone(),
        deadline: start.deadline,
        cmd: cmd_tx.clone(),
        status: status_rx,
        incoming: tokio::sync::Mutex::new(accept_rx),
        minor: minor_rx,
        peer_hello: peer_hello.clone(),
        shutting: shutting.clone(),
    };
    let driver = Driver {
        mux: Mux::with_limits(
            start.side,
            start.clock.mono(),
            &mux_limits(&start.limits, &start.streams),
        ),
        limits: DriverLimits::new(&start.limits),
        admit: start.streams.connection(),
        permits: HashMap::new(),
        deadline: Deadline::new(start.deadline, &*start.clock),
        clock: start.clock,
        role,
        cmd_tx,
        status: status_tx,
        closing: closing_tx,
        shutting,
        accept: accept_tx,
        streams: HashMap::new(),
        finished: Vec::new(),
        blocked: Vec::new(),
        pings: Vec::new(),
        hello: HelloState::new(local_version()),
        minor,
        peer_hello,
        own_hello_out: false,
        peer: start.peer,
        inbound: start.side == MuxRole::Host,
        reason: None,
        before_close: VecDeque::new(),
        fences: Vec::new(),
    };
    tokio::spawn(driver.run(start.tls, cmd_rx));
    connection
}

struct Driver {
    mux: Mux,
    limits: DriverLimits,
    clock: Arc<dyn Clock>,
    deadline: Deadline,
    role: Box<dyn Role>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    status: watch::Sender<ConnStatus>,
    closing: watch::Sender<bool>,
    /// The handle's view of closing ([`Connection::is_closing`]).
    shutting: Arc<Liveness>,
    accept: mpsc::UnboundedSender<MuxStream>,
    streams: HashMap<u32, StreamTx>,
    /// Streams the peer finished whose receive side waits for the mux to
    /// be done with them.
    finished: Vec<u32>,
    /// This connection's stream places.
    admit: ConnStreams,
    /// The places of the streams the mux still has. A stream's reader
    /// holds its place too, so it frees once both are done.
    permits: HashMap<u32, Arc<StreamPermit>>,
    blocked: Vec<(StreamId, oneshot::Sender<Result<(), NetError>>)>,
    /// Who waits for the next `PONG`.
    pings: Vec<oneshot::Sender<()>>,
    /// The peer's `HELLO`s so far.
    hello: HelloState,
    /// Where the agreed minor version is published for the handle.
    minor: watch::Sender<Option<u64>>,
    /// Where the minor version the peer's first `HELLO` named, and when it
    /// was read, are kept for the handle.
    peer_hello: Arc<OnceLock<(u64, Instant)>>,
    /// This side's own `HELLO`, the mux's first frame, has gone to the
    /// writer. Closing drops what the mux still holds.
    own_hello_out: bool,
    /// The peer's identity, proven in step 1.
    peer: IdentityPublicKey,
    /// The peer dialled this endpoint.
    inbound: bool,
    reason: Option<CloseReason>,
    /// Encoded frames a closing step produced, sent before the GOAWAY.
    before_close: VecDeque<Vec<u8>>,
    /// Who waits for [`Cmd::Fence`]. Dropped (which answers too) when the
    /// driver ends.
    fences: Vec<oneshot::Sender<()>>,
}

fn classify(frame: &Frame) -> Result<(Traffic, Option<ControlMessage>), ErrorCode> {
    Ok(match frame {
        Frame::Ping { .. } | Frame::Pong { .. } => (Traffic::Keepalive, None),
        Frame::GoAway { .. } => (Traffic::GoAway, None),
        Frame::Control { payload } => {
            let message = ControlMessage::decode(payload).map_err(|_| ErrorCode::ProtocolError)?;
            (Traffic::of(&message), Some(message))
        }
        _ => (Traffic::Stream, None),
    })
}

impl Driver {
    async fn run<P: Pipe>(mut self, tls: TlsStream<P>, mut cmd_rx: mpsc::UnboundedReceiver<Cmd>) {
        let (mut rd, wr) = tokio::io::split(tls);
        // The writer asks for each frame when it can send it, so a frame is
        // chosen at send time: nothing waits in a queue between the mux and
        // TLS (where a credit could go stale after a FIN, or data outlive
        // the deadline).
        let (ask_tx, mut ask_rx) = mpsc::channel::<oneshot::Sender<Vec<u8>>>(1);
        let mut writer = tokio::spawn(writer_task(
            wr,
            ask_tx,
            self.clock.clone(),
            self.deadline,
            self.limits,
        ));
        let mut slot: Option<oneshot::Sender<Vec<u8>>> = None;

        let hello = ControlMessage::Hello {
            major_version: local_version().major,
            minor_version: local_version().minor,
        };
        let _ = self.mux.send_control(hello.encode());
        let mut out = Outbox::default();
        self.role.on_start(&mut out);
        self.apply(out);

        let mut buf = vec![0u8; self.limits.read_buffer];
        let mut inbuf: Vec<u8> = Vec::new();
        // Once closing, the writer has this long to take the GOAWAY.
        let mut give_up: Option<Instant> = None;
        loop {
            if self.expired() {
                self.close(ErrorCode::CertExpired);
                self.before_close.clear();
            }
            if self.reason.is_some() || self.mux.is_closing() {
                self.mark_closing();
            }
            if self.mux.is_closing() && give_up.is_none() {
                give_up = Some(Instant::now() + self.limits.close_linger);
            }
            // The writer asks again only after its last frame went out, and
            // a closing mux has dropped its queue: nothing from before can
            // leave any more.
            if slot.is_some() && self.mux.is_closing() {
                for fence in self.fences.drain(..) {
                    let _ = fence.send(());
                }
            }
            if slot.is_some() {
                if let Some(frame) = self.next_frame() {
                    if let Some(tx) = slot.take() {
                        let _ = tx.send(frame);
                    }
                }
            }
            self.release_blocked();
            self.sweep_permits();
            self.sweep_finished();
            if self.before_close.is_empty() && self.mux.is_closed() {
                break;
            }
            let wake = self.next_wake();
            tokio::select! {
                ask = ask_rx.recv(), if slot.is_none() => match ask {
                    Some(tx) => slot = Some(tx),
                    // The writer stopped: the pipe failed, or a write was
                    // still pending at the deadline.
                    None => {
                        let reason = if self.expired() {
                            CloseReason::Local(ErrorCode::CertExpired)
                        } else {
                            CloseReason::PipeClosed
                        };
                        self.reason.get_or_insert(reason);
                        break;
                    }
                },
                cmd = cmd_rx.recv() => {
                    if let Some(cmd) = cmd {
                        self.handle_cmd(cmd);
                    }
                }
                read = rd.read(&mut buf) => {
                    match read {
                        Ok(0) => {
                            self.reason.get_or_insert(CloseReason::PipeClosed);
                            break;
                        }
                        Ok(n) => {
                            inbuf.extend_from_slice(&buf[..n]);
                            // A read can win the race with a timer that is
                            // already due: the deadlines bound what is read.
                            self.enforce_deadlines();
                            self.process_inbound(&mut inbuf);
                        }
                        Err(e) => {
                            self.reason.get_or_insert(CloseReason::Io(e.to_string()));
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep_until(wake) => self.on_timer(),
                // A writer stuck on a pipe that takes nothing.
                _ = sleep_until_some(give_up) => break,
            }
        }

        self.mark_closing();
        let reason = self.reason.clone().unwrap_or(CloseReason::PipeClosed);
        for (_, tx) in self.streams.drain() {
            tx.end(StreamEnd::ConnectionClosed(reason.clone()));
        }
        for (_, reply) in self.blocked.drain(..) {
            let _ = reply.send(Err(NetError::Closed(reason.clone())));
        }
        self.role.on_closed(&reason);
        let _ = self.status.send(ConnStatus::Closed(reason));
        // The writer sends what it holds (the closing GOAWAY) and shuts the
        // pipe down when it asks for more. One that cannot finish in time is
        // stopped, so the pipe does not stay open.
        drop(slot);
        drop(ask_rx);
        // Meanwhile, what the peer still sends is read and dropped until it
        // closes too, within the same linger. A socket closed with unread
        // data resets the connection, and the reset can destroy what the
        // peer has not read yet: the GOAWAY that says why.
        let drain = async { while matches!(rd.read(&mut buf).await, Ok(n) if n > 0) {} };
        let linger = async { tokio::join!(&mut writer, drain) };
        if tokio::time::timeout(self.limits.close_linger, linger)
            .await
            .is_err()
        {
            writer.abort();
        }
    }

    /// The next frame to send: the messages a closing step produced, then
    /// the mux's frames.
    fn next_frame(&mut self) -> Option<Vec<u8>> {
        if let Some(frame) = self.before_close.pop_front() {
            return Some(frame);
        }
        let frame = self.mux.poll_transmit(self.clock.mono());
        // The first `HELLO` is queued before anything else.
        self.own_hello_out |= frame.is_some();
        frame
    }

    /// Close with `UNSUPPORTED_VERSION`. The peer learns this side's newest
    /// minor from its `HELLO`; if that still waits in the mux, which
    /// closing empties, it goes out ahead of the `GOAWAY` instead.
    fn refuse_version(&mut self) -> Verdict {
        if !self.own_hello_out && !self.mux.is_closing() {
            let local = local_version();
            let hello = ControlMessage::Hello {
                major_version: local.major,
                minor_version: local.minor,
            };
            self.before_close.push_back(
                Frame::Control {
                    payload: hello.encode(),
                }
                .encode(),
            );
        }
        Verdict::Close(ErrorCode::UnsupportedVersion)
    }

    fn next_wake(&self) -> Instant {
        let now = Instant::now();
        let mono = self.clock.mono();
        // Never later than the recheck.
        let mut wake = now + self.limits.recheck;
        if let Some(t) = self.mux.poll_timeout() {
            wake = wake.min(now + Duration::from_millis(t.since(mono)));
        }
        if let Some(t) = self.role.wake_at() {
            wake = wake.min(now + Duration::from_millis(t.since(mono)));
        }
        let wall = self.clock.now();
        let until_deadline = self
            .deadline
            .wall
            .secs()
            .saturating_add(1)
            .saturating_sub(wall.secs());
        wake.min(now + Duration::from_secs(until_deadline))
            .min(now + Duration::from_millis(self.deadline.mono.since(mono)))
    }

    fn on_timer(&mut self) {
        let mono = self.clock.mono();
        // The deadline first: after a long sleep the idle timer is due too,
        // and the connection ended because its certificates did.
        if self.expired() {
            self.close(ErrorCode::CertExpired);
            return;
        }
        if let Err(e) = self.mux.on_timeout(mono) {
            self.reason.get_or_insert(CloseReason::Local(e.code));
        }
        if !self.mux.is_closing() {
            let mut out = Outbox::default();
            self.role.on_wake(mono, &mut out);
            self.apply(out);
        }
    }

    /// Act on the deadlines that have passed before handling more traffic:
    /// the certificate deadline, then the role's own (a proof or answer
    /// wait), as the timer would have.
    fn enforce_deadlines(&mut self) {
        if self.expired() {
            self.close(ErrorCode::CertExpired);
            return;
        }
        let mono = self.clock.mono();
        if !self.mux.is_closing() && self.role.wake_at().is_some_and(|t| t <= mono) {
            let mut out = Outbox::default();
            self.role.on_wake(mono, &mut out);
            self.apply(out);
        }
    }

    /// Past the effective deadline: the connection may run through that
    /// second and no further.
    fn expired(&self) -> bool {
        self.deadline.passed(&*self.clock)
    }

    fn mark_closing(&self) {
        self.shutting.mark();
        self.closing
            .send_if_modified(|closing| !std::mem::replace(closing, true));
    }

    /// At or past the deadline: close, and return the error for a refused
    /// open or send.
    fn refuse_if_expired(&mut self) -> Option<NetError> {
        if !self.expired() {
            return None;
        }
        self.close(ErrorCode::CertExpired);
        self.mark_closing();
        Some(NetError::Closed(
            self.reason
                .clone()
                .unwrap_or(CloseReason::Local(ErrorCode::CertExpired)),
        ))
    }

    fn close(&mut self, code: ErrorCode) {
        if !self.mux.is_closing() {
            self.mux.close(code);
            self.reason.get_or_insert(CloseReason::Local(code));
        }
    }

    fn apply(&mut self, out: Outbox) {
        match out.close {
            // A step that ends the connection sends its own messages first,
            // then one GOAWAY (wire.md 10.6, rule 9). Closing the mux drops
            // what it has queued, so these wait outside it.
            Some(_) if !self.mux.is_closing() => {
                for message in out.control {
                    let payload = message.encode();
                    if !payload.is_empty() && payload.len() <= MAX_CONTROL_PAYLOAD {
                        self.before_close
                            .push_back(Frame::Control { payload }.encode());
                    }
                }
            }
            Some(_) => {}
            None => {
                for message in out.control {
                    let _ = self.mux.send_control(message.encode());
                }
            }
        }
        if let Some(status) = out.status {
            let _ = self.status.send(status);
        }
        if let Some(code) = out.close {
            self.close(code);
        }
    }

    fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Open {
                class,
                label,
                reply,
            } => {
                let result = if let Some(e) = self.refuse_if_expired() {
                    Err(e)
                } else if self.mux.is_closing() {
                    Err(NetError::Closed(
                        self.reason.clone().unwrap_or(CloseReason::PipeClosed),
                    ))
                } else if !self.role.may_open() {
                    Err(NetError::Refused("the connection is not authorized".into()))
                } else if let Some(permit) = self.admit.try_admit_in(Room::of(&label)) {
                    self.mux
                        .open_stream(class, &label)
                        .map(|id| self.new_stream(id, class, label, permit))
                        .map_err(stream_err)
                } else {
                    Err(NetError::StreamLimit)
                };
                let _ = reply.send(result);
            }
            Cmd::Send {
                stream,
                bytes,
                reply,
            } => {
                if let Some(e) = self.refuse_if_expired() {
                    let _ = reply.send(Err(e));
                    return;
                }
                match self.mux.send(stream, &bytes) {
                    Ok(()) => self.blocked.push((stream, reply)),
                    Err(e) => {
                        let _ = reply.send(Err(stream_err(e)));
                    }
                }
            }
            Cmd::Finish(stream) => {
                let _ = self.mux.finish(stream);
            }
            Cmd::Reset(stream, code) => {
                let _ = self.mux.reset(stream, code);
                self.streams.remove(&stream.0);
            }
            Cmd::Release(stream, n) => self.mux.release(stream, n),
            Cmd::Control(message) => {
                if self.refuse_if_expired().is_none() {
                    let _ = self.mux.send_control(message.encode());
                }
            }
            Cmd::Close(code) => self.close(code),
            Cmd::Apply(out) => {
                if self.refuse_if_expired().is_none() {
                    self.apply(out);
                }
            }
            Cmd::Status(status) => {
                let _ = self.status.send(status);
            }
            Cmd::Code(code) => {
                let mut out = Outbox::default();
                self.role.on_code(code, &mut out);
                self.apply(out);
            }
            Cmd::Ping(reply) => {
                // Closing: the reply drops, which answers false.
                if !self.mux.is_closing() {
                    self.mux.ping();
                    self.pings.push(reply);
                }
            }
            Cmd::Fence(reply) => {
                // Must-fail control (tests only): the fence is answered at
                // once, while queued data can still go out.
                if cfg!(mousse_control = "role-edit-unfenced") {
                    let _ = reply.send(());
                } else {
                    self.fences.push(reply);
                }
            }
        }
    }

    /// A place for a stream the peer opened, if the caps allow one.
    fn admit_peer_stream(&self) -> Option<Arc<StreamPermit>> {
        #[cfg(mousse_control = "no-stream-cap")]
        {
            Some(self.admit.admit_anyway())
        }
        #[cfg(not(mousse_control = "no-stream-cap"))]
        {
            self.admit.try_admit()
        }
    }

    /// Let go of the places of streams the mux is done with. Their readers
    /// may still hold them.
    fn sweep_permits(&mut self) {
        if self.permits.is_empty() {
            return;
        }
        let mux = &self.mux;
        self.permits.retain(|id, _| mux.has_stream(StreamId(*id)));
    }

    /// Let go of the receive sides of streams the peer finished, once the
    /// mux is done with them (both halves ended).
    fn sweep_finished(&mut self) {
        if self.finished.is_empty() {
            return;
        }
        let (mux, streams) = (&self.mux, &mut self.streams);
        self.finished.retain(|id| {
            if mux.has_stream(StreamId(*id)) {
                return true;
            }
            if streams.get(id).is_some_and(|tx| tx.fin) {
                streams.remove(id);
            }
            false
        });
    }

    fn release_blocked(&mut self) {
        if self.blocked.is_empty() {
            return;
        }
        let closing = self.mux.is_closing();
        let mut still = Vec::new();
        for (stream, reply) in self.blocked.drain(..) {
            if closing {
                let reason = self.reason.clone().unwrap_or(CloseReason::PipeClosed);
                let _ = reply.send(Err(NetError::Closed(reason)));
                continue;
            }
            match self.mux.queued(stream) {
                Some(queued) if queued > self.limits.write_high_water => {
                    still.push((stream, reply))
                }
                // Below the mark, or the stream already completed.
                _ => {
                    let _ = reply.send(Ok(()));
                }
            }
        }
        self.blocked = still;
    }

    fn new_stream(
        &mut self,
        id: StreamId,
        class: PriorityClass,
        label: String,
        permit: Arc<StreamPermit>,
    ) -> MuxStream {
        let rx = Arc::new(RxQueue {
            state: std::sync::Mutex::new(RxState::default()),
            ready: tokio::sync::Notify::new(),
            admission: self.admit.admission().clone(),
        });
        let (reset, reset_rx) = watch::channel(None);
        self.streams.insert(
            id.0,
            StreamTx {
                rx: rx.clone(),
                reset,
                fin: false,
            },
        );
        self.permits.insert(id.0, permit.clone());
        MuxStream {
            reader: StreamReader {
                id,
                rx: rx.clone(),
                cmd: self.cmd_tx.clone(),
                ended: None,
                closing: self.closing.subscribe(),
                _permit: permit,
                reset: reset_rx,
            },
            writer: StreamWriter {
                id,
                rx,
                cmd: self.cmd_tx.clone(),
                closing: self.closing.subscribe(),
            },
            label,
            class,
        }
    }

    fn process_inbound(&mut self, inbuf: &mut Vec<u8>) {
        loop {
            if self.mux.is_closing() {
                inbuf.clear();
                return;
            }
            // Nothing is accepted after the deadline, even if the timer has
            // not fired yet.
            if self.expired() {
                self.close(ErrorCode::CertExpired);
                inbuf.clear();
                return;
            }
            let (frame, used) = match decode_frame(inbuf) {
                Ok(Some(parsed)) => parsed,
                Ok(None) => return,
                Err(e) => {
                    self.close(e.code());
                    inbuf.clear();
                    return;
                }
            };
            // A peer's GOAWAY counts where it is read: the role acts on its
            // code now, in the same step as the gate, before anything else
            // the role does can come between (a Pair with IP cancel).
            if let Frame::GoAway { code } = &frame {
                self.role.on_goaway(*code);
            }
            let verdict = match classify(&frame) {
                Err(code) => Verdict::Close(code),
                Ok((traffic, message)) => self.gate(traffic, message.as_ref()),
            };
            match verdict {
                Verdict::Allow => match self.mux.receive(&inbuf[..used], self.clock.mono()) {
                    Ok(events) => {
                        for event in events {
                            self.on_event(event);
                        }
                    }
                    Err(e) => {
                        self.reason.get_or_insert(CloseReason::Local(e.code));
                    }
                },
                Verdict::Ignore => {}
                // Only Pair with IP binds a connection to a provisional
                // grant, and io does not run it yet: nothing commits here,
                // so the frame is refused.
                Verdict::Commit(_) => self.close(ErrorCode::GrantRevoked),
                Verdict::Close(code) => self.close(code),
            }
            inbuf.drain(..used);
        }
    }

    /// The `HELLO` rule (core's [`HelloState`]: the peer's first `HELLO`
    /// fixes the version or closes, later ones are ignored), then the
    /// role's gate.
    fn gate(&mut self, traffic: Traffic, message: Option<&ControlMessage>) -> Verdict {
        match traffic {
            Traffic::Hello => {
                let Some(ControlMessage::Hello {
                    major_version,
                    minor_version,
                }) = message
                else {
                    return Verdict::Close(ErrorCode::ProtocolError);
                };
                // Kept before the verdict, so whoever sees the close can
                // tell how new the peer is. Only the first `HELLO` sets it.
                let at = Instant::now();
                let _ = self.peer_hello.set((*minor_version, at));
                let outcome = self.hello.on_hello(*major_version, *minor_version);
                if outcome != HelloOutcome::Ignored {
                    // Reported whatever follows: authorization, publication.
                    self.admit.admission().hello_seen(HelloSeen {
                        peer: self.peer,
                        peer_minor: *minor_version,
                        agreed: self.hello.agreed(),
                        at,
                        inbound: self.inbound,
                    });
                }
                match outcome {
                    HelloOutcome::Agreed(minor) => {
                        self.minor.send_if_modified(|m| {
                            let first = m.is_none();
                            if first {
                                *m = Some(minor);
                            }
                            first
                        });
                    }
                    HelloOutcome::Ignored => return Verdict::Ignore,
                    // No common version, or one the peer refuses (wire.md
                    // 2): refused here, before any step-2 answer counts.
                    HelloOutcome::Close(_) => return self.refuse_version(),
                }
            }
            Traffic::Keepalive | Traffic::GoAway => {}
            _ => match self.hello.agreed() {
                None => return Verdict::Close(ErrorCode::ProtocolError),
                // A message the agreed minor version does not define
                // (JOIN_DIRECT and AUTHORIZED key 2 before minor 4).
                Some(agreed) if message.is_some_and(|m| !m.defined_at(agreed)) => {
                    return Verdict::Close(ErrorCode::ProtocolError)
                }
                Some(_) => {}
            },
        }
        self.role.check(traffic, message)
    }

    fn on_event(&mut self, event: MuxEvent) {
        match event {
            MuxEvent::StreamOpened {
                stream,
                class,
                label,
            } => {
                // Admission: a stream past either cap of its room is
                // refused before anything is queued for it (Phase 1a §2.2).
                let permit = match Room::of(&label) {
                    Room::App => self.admit_peer_stream(),
                    room => self.admit.try_admit_in(room),
                };
                let Some(permit) = permit else {
                    self.admit.refused();
                    let _ = self.mux.reset(stream, ErrorCode::RefusedStream);
                    return;
                };
                let s = self.new_stream(stream, class, label, permit);
                if self.accept.send(s).is_err() {
                    self.streams.remove(&stream.0);
                    let _ = self.mux.reset(stream, ErrorCode::RefusedStream);
                }
            }
            MuxEvent::Data { stream, bytes } => {
                let chunk = self.limits.rx_chunk;
                let delivered = self
                    .streams
                    .get(&stream.0)
                    .is_some_and(|tx| tx.rx.push(bytes, chunk));
                if !delivered {
                    if let Some(tx) = self.streams.remove(&stream.0) {
                        // A reset this side asked for may still wait in the
                        // command queue: send its code, not ours.
                        let code = tx.rx.local_reset().unwrap_or(ErrorCode::Cancelled);
                        let _ = self.mux.reset(stream, code);
                    }
                }
            }
            MuxEvent::Finished { stream } => {
                // Kept: the peer may still reset the stream while this
                // side's half is open (see `sweep_finished`).
                if let Some(tx) = self.streams.get_mut(&stream.0) {
                    tx.fin = true;
                    tx.end(StreamEnd::Fin);
                    self.finished.push(stream.0);
                }
            }
            MuxEvent::Reset { stream, code } => {
                if let Some(tx) = self.streams.remove(&stream.0) {
                    tx.end(StreamEnd::Reset(code));
                }
            }
            MuxEvent::Control(bytes) => {
                let Ok(message) = ControlMessage::decode(&bytes) else {
                    self.close(ErrorCode::ProtocolError);
                    return;
                };
                if matches!(message, ControlMessage::Hello { .. }) {
                    // Only the peer's first HELLO gets here: the gate
                    // ignores a repeat.
                    if let Some(minor) = self.hello.agreed() {
                        let mut out = Outbox::default();
                        self.role.on_hello(minor, &mut out);
                        self.apply(out);
                    }
                    return;
                }
                let mut out = Outbox::default();
                self.role.on_control(message, &mut out);
                self.apply(out);
            }
            MuxEvent::Pong { .. } => {
                for reply in self.pings.drain(..) {
                    let _ = reply.send(());
                }
            }
            MuxEvent::GoAway { code } => {
                self.reason.get_or_insert(CloseReason::Peer(code));
            }
        }
    }
}

fn stream_err(e: StreamError) -> NetError {
    match e {
        StreamError::Closing => NetError::Closed(CloseReason::PipeClosed),
        other => NetError::Refused(other.to_string()),
    }
}

fn is_goaway(frame: &[u8]) -> bool {
    frame.get(4) == Some(&frame_type::GOAWAY)
}

/// Sends frames one at a time. It asks the driver for the next frame only
/// once the previous one has left TLS for the pipe (written and flushed), so
/// each frame is chosen when it can go out.
///
/// The deadline bounds every write: past it only `GOAWAY` goes out, and if
/// the write or flush of any other frame is still pending when the deadline
/// passes, the writer gives up the pipe, so those bytes never leave after
/// it. After `GOAWAY`, or when the driver has nothing more, it shuts the
/// pipe down.
async fn writer_task<P: Pipe>(
    mut wr: WriteHalf<TlsStream<P>>,
    ask: mpsc::Sender<oneshot::Sender<Vec<u8>>>,
    clock: Arc<dyn Clock>,
    deadline: Deadline,
    limits: DriverLimits,
) {
    loop {
        let (tx, rx) = oneshot::channel();
        if ask.send(tx).await.is_err() {
            break;
        }
        let Ok(frame) = rx.await else {
            break;
        };
        let goaway = is_goaway(&frame);
        if !goaway && deadline.passed(&*clock) {
            continue;
        }
        let send = async {
            wr.write_all(&frame).await?;
            wr.flush().await
        };
        let sent = if goaway {
            matches!(
                tokio::time::timeout(limits.close_linger, send).await,
                Ok(Ok(()))
            )
        } else {
            // The deadline is checked first on every poll, so the pipe can
            // take more of the frame only while the deadline has not passed.
            tokio::select! {
                biased;
                () = past(&*clock, deadline, limits.deadline_poll) => return,
                result = send => result.is_ok(),
            }
        };
        if !sent {
            return;
        }
        if goaway {
            break;
        }
    }
    let _ = tokio::time::timeout(limits.close_linger, wr.shutdown()).await;
}

async fn sleep_until_some(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Ready once `clock` is past `deadline`. The clock is read on every poll
/// (also when whatever it races against wakes the task) and at least every
/// `poll`.
fn past(
    clock: &dyn Clock,
    deadline: Deadline,
    poll: Duration,
) -> impl std::future::Future<Output = ()> + '_ {
    let mut tick = tokio::time::interval(poll);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    std::future::poll_fn(move |cx| {
        if deadline.passed(clock) {
            return std::task::Poll::Ready(());
        }
        while tick.poll_tick(cx).is_ready() {}
        std::task::Poll::Pending
    })
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll, Waker};

    use mousse_net_core::identity::SoftwareKey;
    use mousse_net_core::pairing::AttemptId;
    use mousse_net_core::Millis;
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

    use super::*;
    use crate::certs::CertManager;
    use crate::clock::ManualClock;
    use crate::rng::os_rng;
    use crate::tls::{self, TlsPolicy};

    const WAIT: Duration = Duration::from_secs(5);

    async fn within<T>(what: &str, fut: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(WAIT, fut)
            .await
            .unwrap_or_else(|_| panic!("timed out: {what}"))
    }

    /// The test hook speaks an older minor, or the Pair with IP minor
    /// before the build's own reaches it (with the one before it), and
    /// nothing else newer.
    #[cfg(debug_assertions)]
    #[test]
    fn the_test_hook_speaks_older_minors_and_the_pair_with_ip_minor_only() {
        let local = VersionSupport::LOCAL;
        let direct = test_version(DIRECT_MINOR_VERSION).expect("pair with ip minor");
        assert_eq!(
            (direct.major, direct.minor, direct.oldest_minor),
            (local.major, DIRECT_MINOR_VERSION, DIRECT_MINOR_VERSION - 1)
        );
        assert_eq!(test_version(DIRECT_MINOR_VERSION + 1), None);
        assert_eq!(test_version(u64::MAX), None);
        let older = test_version(2).expect("older minor");
        assert_eq!((older.minor, older.oldest_minor), (2, 1));
    }

    /// A sleep moves the wall clock and the monotonic clock (which counts
    /// sleep, see `clock.rs`) together. A sleep past the cap ends the
    /// session whether the wall clock is set back before the sleep or
    /// after it.
    #[test]
    fn a_suspend_and_a_wall_clock_set_back_cannot_extend_the_cap() {
        const CAP: u64 = 3_600;
        for set_back_first in [false, true] {
            let clock = ManualClock::new();
            clock.freeze_mono();
            let deadline = Deadline::new(UnixTime(clock.now().secs() + CAP), &clock);
            assert!(!deadline.passed(&clock));
            let back = || clock.advance(-(CAP as i64) - 600);
            if set_back_first {
                back();
            }
            // Asleep past the cap.
            clock.advance(CAP as i64 + 60);
            clock.advance_mono((CAP + 60) * 1_000);
            if !set_back_first {
                back();
            }
            // The wall clock alone would not end it.
            assert!(clock.now() <= deadline.wall);
            assert!(deadline.passed(&clock), "set back first: {set_back_first}");
        }
    }

    /// Holds back everything our side writes while closed.
    #[derive(Clone, Default)]
    struct Valve(Arc<Mutex<(bool, Option<Waker>)>>);

    impl Valve {
        fn close(&self) {
            self.0.lock().unwrap().0 = true;
        }

        fn open(&self) {
            let waker = {
                let mut state = self.0.lock().unwrap();
                state.0 = false;
                state.1.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }

        /// `Pending` while closed.
        fn wait(&self, cx: &Context<'_>) -> Poll<()> {
            let mut state = self.0.lock().unwrap();
            if state.0 {
                state.1 = Some(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }
    }

    struct HeldPipe {
        io: DuplexStream,
        valve: Valve,
    }

    impl AsyncRead for HeldPipe {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for HeldPipe {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            std::task::ready!(self.valve.wait(cx));
            Pin::new(&mut self.io).poll_write(cx, data)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            std::task::ready!(self.valve.wait(cx));
            Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    /// Lets everything through. A `CODE_EXCHANGE` ends the flow the way a
    /// joiner's third failed attempt does: `CODE_ABORT`, then close.
    struct OpenRole;

    impl Role for OpenRole {
        fn on_start(&mut self, _out: &mut Outbox) {}

        fn check(&mut self, _traffic: Traffic, _message: Option<&ControlMessage>) -> Verdict {
            Verdict::Allow
        }

        fn on_control(&mut self, message: ControlMessage, out: &mut Outbox) {
            if let ControlMessage::CodeExchange { attempt, .. } = message {
                out.control.push(ControlMessage::CodeAbort {
                    attempt,
                    code: ErrorCode::PairingFailed,
                });
                out.close = Some(ErrorCode::AttemptsExhausted);
            }
        }

        fn may_open(&self) -> bool {
            true
        }

        fn on_closed(&mut self, _reason: &CloseReason) {}
    }

    /// The other end, writing and reading raw frames. Every frame received
    /// is kept, in order.
    struct Peer {
        tls: TlsStream<DuplexStream>,
        mux: Mux,
        inbuf: Vec<u8>,
        frames: Vec<Frame>,
    }

    impl Peer {
        async fn flush(&mut self) {
            while let Some(bytes) = self.mux.poll_transmit(Millis(0)) {
                self.tls.write_all(&bytes).await.unwrap();
            }
            self.tls.flush().await.unwrap();
        }

        /// Read until a received frame matches `until` (true) or the pipe
        /// ends (false).
        async fn read_until(&mut self, until: impl Fn(&Frame) -> bool) -> bool {
            let mut buf = [0u8; 16 * 1024];
            loop {
                while let Ok(Some((frame, used))) = decode_frame(&self.inbuf) {
                    let _ = self.mux.receive(&self.inbuf[..used], Millis(0));
                    self.inbuf.drain(..used);
                    let hit = until(&frame);
                    self.frames.push(frame);
                    if hit {
                        return true;
                    }
                }
                match self.tls.read(&mut buf).await {
                    Ok(0) | Err(_) => return false,
                    Ok(n) => self.inbuf.extend_from_slice(&buf[..n]),
                }
            }
        }
    }

    /// Our driver (caller side) and a raw peer over TLS on an in-memory
    /// pipe. Our deadline is `deadline_in` seconds from now.
    async fn connected(deadline_in: u64) -> (Connection, Peer, Valve, Arc<ManualClock>) {
        connected_with(deadline_in, StreamAdmission::new(&Limits::DEFAULT)).await
    }

    /// [`connected`], counting streams and received bytes in `streams`.
    async fn connected_with(
        deadline_in: u64,
        streams: Arc<StreamAdmission>,
    ) -> (Connection, Peer, Valve, Arc<ManualClock>) {
        connected_limits(deadline_in, Limits::DEFAULT, streams).await
    }

    /// [`connected_with`], with the connection's own `limits`.
    async fn connected_limits(
        deadline_in: u64,
        limits: Limits,
        streams: Arc<StreamAdmission>,
    ) -> (Connection, Peer, Valve, Arc<ManualClock>) {
        let clock = Arc::new(ManualClock::new());
        let cert = |clock: Arc<ManualClock>| {
            CertManager::new(Arc::new(SoftwareKey::generate(&mut os_rng())), clock)
                .current()
                .unwrap()
        };
        let (ours, theirs) = (cert(clock.clone()), cert(clock.clone()));
        let (a, b) = tokio::io::duplex(1 << 20);
        let valve = Valve::default();
        let pipe = HeldPipe {
            io: a,
            valve: valve.clone(),
        };
        let (connected, accepted) = tokio::join!(
            tls::connect(
                pipe,
                &ours,
                *theirs.identity(),
                clock.clone(),
                TlsPolicy::default()
            ),
            tls::accept(b, &theirs, clock.clone(), TlsPolicy::default()),
        );
        let (tls, handshake) = connected.unwrap();
        let (peer_tls, _) = accepted.unwrap();
        let (cmd_tx, cmd_rx) = channel();
        let conn = spawn(
            Start {
                tls,
                side: MuxRole::Caller,
                conn: ConnectionId(1),
                peer: handshake.peer.identity,
                kx_group: handshake.kx_group,
                deadline: UnixTime(clock.now().0 + deadline_in),
                clock: clock.clone(),
                limits,
                streams,
            },
            Box::new(OpenRole),
            cmd_tx,
            cmd_rx,
        );
        let mut peer = Peer {
            tls: peer_tls,
            mux: Mux::new(MuxRole::Host, Millis(0)),
            inbuf: Vec::new(),
            frames: Vec::new(),
        };
        let hello = ControlMessage::Hello {
            major_version: VersionSupport::LOCAL.major,
            minor_version: VersionSupport::LOCAL.minor,
        };
        peer.mux.send_control(hello.encode()).unwrap();
        peer.flush().await;
        assert!(
            within(
                "our HELLO",
                peer.read_until(|f| matches!(f, Frame::Control { .. }))
            )
            .await
        );
        (conn, peer, valve, clock)
    }

    fn data_of(frames: &[Frame]) -> Vec<&[u8]> {
        frames
            .iter()
            .filter_map(|f| match f {
                Frame::Data { payload, .. } => Some(payload.as_slice()),
                _ => None,
            })
            .collect()
    }

    /// A clock that jumps past either deadline while nothing is due, as
    /// after a sleep: the connection closes with `CERT_EXPIRED` at the next
    /// recheck, with no traffic and no timer set for that moment.
    #[tokio::test]
    async fn a_jump_past_either_deadline_closes_at_the_next_recheck() {
        for wall in [true, false] {
            let (conn, mut peer, _valve, clock) = connected(3_600).await;
            if wall {
                clock.advance(3_602);
            } else {
                // Setting the wall clock back does not help either.
                clock.advance(-7_200);
                clock.advance_mono(3_601_000);
            }
            assert!(
                within(
                    "GOAWAY",
                    peer.read_until(|f| matches!(f, Frame::GoAway { .. }))
                )
                .await,
                "wall: {wall}"
            );
            assert_eq!(
                within("closed", conn.closed()).await,
                CloseReason::Local(ErrorCode::CertExpired),
                "wall: {wall}"
            );
        }
    }

    #[tokio::test]
    async fn a_ping_is_true_only_when_the_peer_answers_in_time() {
        let (conn, mut peer, _valve, _clock) = connected(3_600).await;
        let asked = conn.ping(Duration::from_secs(5));
        let answer = async {
            assert!(peer.read_until(|f| matches!(f, Frame::Ping { .. })).await);
            // Reading the PING queued the PONG.
            peer.flush().await;
        };
        let (answered, ()) = within("the ping", async { tokio::join!(asked, answer) }).await;
        assert!(answered);

        // The peer reads the next PING and never answers.
        let asked = conn.ping(Duration::from_millis(200));
        let ignore = async {
            assert!(peer.read_until(|f| matches!(f, Frame::Ping { .. })).await);
        };
        let (answered, ()) = within("the ping", async { tokio::join!(asked, ignore) }).await;
        assert!(!answered);

        conn.close(ErrorCode::NoError);
        assert!(
            !within(
                "a ping on a closed connection",
                conn.ping(Duration::from_secs(5))
            )
            .await
        );
    }

    #[tokio::test]
    async fn a_later_hello_is_ignored_whatever_it_holds() {
        let (conn, mut peer, _valve, _clock) = connected(3_600).await;
        // The peer's first HELLO was accepted; these must change nothing,
        // not even one naming another major version.
        for (major_version, minor_version) in [
            (VersionSupport::LOCAL.major, VersionSupport::LOCAL.minor),
            (VersionSupport::LOCAL.major + 1, 0),
        ] {
            let hello = ControlMessage::Hello {
                major_version,
                minor_version,
            };
            peer.mux.send_control(hello.encode()).unwrap();
        }
        peer.flush().await;
        // The connection still carries streams afterwards.
        let stream = within(
            "open",
            conn.open_stream(PriorityClass::Interactive, "terminal"),
        )
        .await
        .unwrap();
        stream.writer.write(b"after").await.unwrap();
        assert!(within("data", peer.read_until(|f| matches!(f, Frame::Data { .. }))).await);
        assert!(
            !peer
                .frames
                .iter()
                .any(|f| matches!(f, Frame::GoAway { .. })),
            "{:?}",
            peer.frames
        );
        assert!(!matches!(conn.status(), ConnStatus::Closed(_)));
    }

    #[tokio::test]
    async fn a_closing_step_sends_its_message_then_one_goaway() {
        let (conn, mut peer, _valve, _clock) = connected(3_600).await;
        let attempt = AttemptId([7; 16]);
        let exchange = ControlMessage::CodeExchange {
            attempt,
            payload: vec![1; 32],
        };
        peer.mux.send_control(exchange.encode()).unwrap();
        peer.flush().await;
        let from = peer.frames.len();
        assert!(
            within(
                "GOAWAY",
                peer.read_until(|f| matches!(f, Frame::GoAway { .. }))
            )
            .await
        );
        let abort = ControlMessage::CodeAbort {
            attempt,
            code: ErrorCode::PairingFailed,
        };
        assert_eq!(
            peer.frames[from..],
            [
                Frame::Control {
                    payload: abort.encode()
                },
                Frame::GoAway {
                    code: ErrorCode::AttemptsExhausted
                },
            ]
        );
        assert!(!within("the end", peer.read_until(|_| true)).await);
        assert_eq!(
            within("closed", conn.closed()).await,
            CloseReason::Local(ErrorCode::AttemptsExhausted)
        );
    }

    #[tokio::test]
    async fn a_write_still_waiting_on_the_pipe_at_the_deadline_never_sends_its_data() {
        let (conn, mut peer, valve, clock) = connected(60).await;
        let stream = conn
            .open_stream(PriorityClass::Interactive, "terminal")
            .await
            .unwrap();
        stream.writer.write(b"early").await.unwrap();
        assert!(
            within(
                "early data",
                peer.read_until(|f| matches!(f, Frame::Data { .. }))
            )
            .await
        );

        // In the deadline second the app writes, but the pipe takes nothing:
        // the write waits.
        clock.freeze_at(conn.deadline());
        valve.close();
        stream.writer.write(b"late").await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!matches!(conn.status(), ConnStatus::Closed(_)));

        // The deadline passes while it waits; then the pipe would take it.
        clock.freeze_at(UnixTime(conn.deadline().0 + 1));
        assert_eq!(
            within("closed", conn.closed()).await,
            CloseReason::Local(ErrorCode::CertExpired)
        );
        valve.open();
        let from = peer.frames.len();
        assert!(!within("the end", peer.read_until(|_| false)).await);
        assert!(
            data_of(&peer.frames[from..]).is_empty(),
            "data went out after the deadline: {:?}",
            &peer.frames[from..]
        );
    }

    #[tokio::test]
    async fn credit_due_while_the_pipe_is_full_is_not_sent_after_the_peers_fin() {
        let (conn, mut peer, valve, _clock) = connected(3_600).await;
        let mut stream = conn
            .open_stream(PriorityClass::Interactive, "terminal")
            .await
            .unwrap();
        let id = stream.id();
        stream.writer.write(b"open").await.unwrap();
        assert!(
            within(
                "the open",
                peer.read_until(|f| matches!(f, Frame::Data { .. }))
            )
            .await
        );

        // Our writer waits on the pipe with a frame of its own.
        valve.close();
        stream.writer.write(b"held").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The app reads more than a credit batch, so a CREDIT is due...
        let sent = vec![0u8; 70_000];
        peer.mux.send(id, &sent).unwrap();
        peer.flush().await;
        let mut read = 0;
        while read < sent.len() {
            read += within("the peer's data", stream.reader.read())
                .await
                .unwrap()
                .unwrap()
                .len();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        // ...and the peer finishes the stream before it could go out.
        peer.mux.finish(id).unwrap();
        peer.flush().await;
        assert_eq!(within("the FIN", stream.reader.read()).await.unwrap(), None);

        valve.open();
        stream.writer.finish();
        let from = peer.frames.len();
        assert!(
            within(
                "our FIN",
                peer.read_until(|f| matches!(f, Frame::Fin { .. }))
            )
            .await
        );
        let after = &peer.frames[from..];
        assert_eq!(data_of(after), [b"held".as_slice()]);
        assert!(
            !after
                .iter()
                .any(|f| matches!(f, Frame::Credit { stream, .. } if *stream == id)),
            "credit after the FIN: {after:?}"
        );
    }

    /// A fence asked for after a close is answered only once nothing
    /// queued before the close can leave: while the writer holds a frame
    /// on a full pipe it waits, and after it only that frame goes out;
    /// what was still queued behind it never does. The handle reads closing
    /// from the moment the close is asked for.
    #[tokio::test]
    async fn a_fence_after_a_close_waits_for_the_frame_in_flight_and_nothing_queued_leaves() {
        let (conn, mut peer, valve, _clock) = connected(3_600).await;
        let stream = conn
            .open_stream(PriorityClass::Interactive, "terminal")
            .await
            .unwrap();
        stream.writer.write(b"open").await.unwrap();
        assert!(
            within(
                "the open",
                peer.read_until(|f| matches!(f, Frame::Data { .. }))
            )
            .await
        );
        assert!(!conn.is_closing());

        // The writer waits on the pipe with "held"; "queued" waits in the
        // mux behind it.
        valve.close();
        stream.writer.write(b"held").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        stream.writer.write(b"queued").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        conn.close(ErrorCode::Cancelled);
        assert!(conn.is_closing());
        let fence = conn.fence();
        tokio::pin!(fence);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut fence)
                .await
                .is_err(),
            "the fence was answered while a frame was still held"
        );
        valve.open();
        within("the fence", fence).await;

        let from = peer.frames.len();
        assert!(
            within(
                "the GOAWAY",
                peer.read_until(|f| matches!(f, Frame::GoAway { .. }))
            )
            .await
        );
        assert_eq!(data_of(&peer.frames[from..]), [b"held".as_slice()]);
    }

    /// The peer's `GOAWAY` makes the handle read closing: nobody here
    /// called [`Connection::close`].
    #[tokio::test]
    async fn the_peers_goaway_reads_as_closing_at_once() {
        let (conn, mut peer, _valve, _clock) = connected(3_600).await;
        assert!(!conn.is_closing());
        peer.mux.close(ErrorCode::NoError);
        peer.flush().await;
        within("closing", async {
            while !conn.is_closing() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
    }

    /// A close waits for a live permit held elsewhere: until the permit
    /// is dropped the connection reads as live, and afterwards no permit
    /// is given.
    #[tokio::test]
    async fn a_close_waits_for_the_live_permit_held() {
        let (conn, _peer, _valve, _clock) = connected(3_600).await;
        let conn = Arc::new(conn);
        let permit = conn.live_permit().expect("live");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let closer = {
            let conn = conn.clone();
            std::thread::spawn(move || {
                conn.close(ErrorCode::Cancelled);
                let _ = done_tx.send(());
            })
        };
        assert!(
            done_rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "the close went through while a permit was held"
        );
        assert!(!conn.is_closing());
        drop(permit);
        closer.join().unwrap();
        assert!(conn.is_closing());
        assert!(conn.live_permit().is_none());
    }

    /// The peer finishes its half, then resets the stream while this side's
    /// half is open and idle: the reader still learns of the reset, so
    /// whoever holds the stream can let it and its credit go.
    #[tokio::test]
    async fn a_reset_after_the_peers_fin_reaches_the_reader() {
        let (conn, mut peer, _valve, _clock) = connected(3_600).await;
        let mut stream = conn
            .open_stream(PriorityClass::Interactive, "terminal")
            .await
            .unwrap();
        let id = stream.id();
        stream.writer.write(b"open").await.unwrap();
        assert!(
            within(
                "the open",
                peer.read_until(|f| matches!(f, Frame::Data { .. }))
            )
            .await
        );
        peer.mux.finish(id).unwrap();
        peer.flush().await;
        assert_eq!(within("the FIN", stream.reader.read()).await.unwrap(), None);
        // The driver runs on with the stream half open.
        tokio::time::sleep(Duration::from_millis(100)).await;

        peer.mux.reset(id, ErrorCode::Cancelled).unwrap();
        peer.flush().await;
        assert_eq!(
            within("the reset", stream.reader.reset_by_peer()).await,
            ErrorCode::Cancelled
        );
    }

    /// This side resets a stream with a code and lets its reader go while
    /// DATA from the peer is in flight. Whichever the driver takes first,
    /// the reset or the DATA, the peer gets that code, never `CANCELLED`.
    /// The driver picks between them at random, so the race is run on many
    /// streams.
    #[tokio::test]
    async fn data_in_flight_at_a_local_reset_gets_the_resets_code() {
        let (conn, mut peer, _valve, _clock) = connected(3_600).await;
        for _ in 0..32 {
            let stream = conn
                .open_stream(PriorityClass::Interactive, "terminal")
                .await
                .unwrap();
            let id = stream.id();
            stream.writer.write(b"open").await.unwrap();
            assert!(
                within(
                    "the open",
                    peer.read_until(|f| matches!(f, Frame::Data { stream, .. } if *stream == id))
                )
                .await
            );
            // The peer's DATA waits in the pipe while, before the driver
            // runs again (one thread), this side resets and drops the stream.
            peer.mux.send(id, b"late").unwrap();
            peer.flush().await;
            stream.writer.reset(ErrorCode::GrantRevoked);
            drop(stream);
            assert!(
                within(
                    "the reset",
                    peer.read_until(|f| matches!(f, Frame::Reset { stream, .. } if *stream == id))
                )
                .await
            );
            let codes: Vec<ErrorCode> = peer
                .frames
                .iter()
                .filter_map(|f| match f {
                    Frame::Reset { stream, code } if *stream == id => Some(*code),
                    _ => None,
                })
                .collect();
            assert_eq!(
                codes,
                [ErrorCode::GrantRevoked],
                "late DATA changed the reset's code"
            );
        }
    }

    /// A connection whose stream admission comes from another configuration
    /// than its own limits (as `Caller::use_stream_admission` and
    /// `HostConfig::streams` allow): its mux keeps room for every place the
    /// admission gives, so a peer filling the app's places still opens bot
    /// streams, and the admission's caps still refuse the rest.
    #[tokio::test]
    async fn the_mux_keeps_room_for_every_place_of_a_shared_admission() {
        let own = |pairs: &[(&str, u64)]| Limits::DEFAULT.with_overrides(pairs).unwrap();
        // The connection's own limits: 1 app + 1 bot + 1 engine place, and
        // a mux that keeps 3 peer streams.
        let limits = own(&[
            ("STREAMS_PER_CONNECTION", 1),
            ("BOT_STREAMS_PER_CONNECTION", 1),
            ("OWN_STREAMS_PER_CONNECTION", 1),
            ("MAX_PEER_STREAMS", 3),
        ]);
        // The admission it is given: 2 app + 2 bot + 1 engine place.
        let admission = StreamAdmission::new(&own(&[
            ("STREAMS_PER_CONNECTION", 2),
            ("BOT_STREAMS_PER_CONNECTION", 2),
            ("OWN_STREAMS_PER_CONNECTION", 1),
        ]));
        let (conn, mut peer, _valve, _clock) =
            connected_limits(3_600, limits, admission.clone()).await;
        for label in [
            "mousse.sub",
            "mousse.sub",
            "mousse.botsub",
            "mousse.botview",
        ] {
            peer.mux
                .open_stream(PriorityClass::Interactive, label)
                .unwrap();
        }
        peer.flush().await;
        for n in 0..4 {
            let s = within(&format!("stream {n}"), conn.accept_stream())
                .await
                .unwrap();
            assert_eq!(
                s.label(),
                [
                    "mousse.sub",
                    "mousse.sub",
                    "mousse.botsub",
                    "mousse.botview"
                ][n]
            );
        }
        assert_eq!(admission.open_streams(), 2);
        assert_eq!(admission.bot_streams(), 2);
        // Past the admission's own caps, opens are still refused.
        let extra = peer
            .mux
            .open_stream(PriorityClass::Interactive, "mousse.botrpc")
            .unwrap();
        peer.flush().await;
        assert!(
            within(
                "the refusal",
                peer.read_until(|f| matches!(
                    f,
                    Frame::Reset { stream, code: ErrorCode::RefusedStream } if *stream == extra
                ))
            )
            .await
        );
    }

    /// A peer splitting its data into one-byte DATA frames while nobody
    /// reads: the frames share receive buffers, so what waits costs about
    /// its bytes, not an allocation per frame. Every byte still arrives in
    /// order.
    #[tokio::test]
    async fn tiny_data_frames_share_receive_buffers() {
        const FRAMES: usize = 100_000;
        let admission = StreamAdmission::new(&Limits::DEFAULT);
        let (conn, mut peer, _valve, _clock) = connected_with(3_600, admission.clone()).await;
        let mut stream = conn
            .open_stream(PriorityClass::Interactive, "terminal")
            .await
            .unwrap();
        let id = stream.id();
        stream.writer.write(b"open").await.unwrap();
        assert!(
            within(
                "the open",
                peer.read_until(|f| matches!(f, Frame::Data { .. }))
            )
            .await
        );
        let mut wire = Vec::new();
        for i in 0..FRAMES {
            peer.mux.send(id, &[i as u8]).unwrap();
            while let Some(frame) = peer.mux.poll_transmit(Millis(0)) {
                wire.extend_from_slice(&frame);
            }
        }
        peer.tls.write_all(&wire).await.unwrap();
        peer.tls.flush().await.unwrap();
        within("every byte queued", async {
            while admission.queued_bytes() < FRAMES as u64 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;

        let chunk = Limits::DEFAULT.io().rx_chunk_bytes();
        let held = admission.held_bytes();
        let bound = FRAMES as u64 + 2 * chunk;
        assert!(
            held <= bound,
            "{held} bytes held for {FRAMES} bytes, bound {bound}"
        );
        assert!(admission.peak_held_bytes() <= bound);

        let mut got = Vec::new();
        while got.len() < FRAMES {
            got.extend(
                within("a read", stream.reader.read())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        let want: Vec<u8> = (0..FRAMES).map(|i| i as u8).collect();
        assert!(got == want, "the bytes differ");
        assert_eq!(admission.queued_bytes(), 0);
        assert_eq!(admission.held_bytes(), 0);
    }
}
