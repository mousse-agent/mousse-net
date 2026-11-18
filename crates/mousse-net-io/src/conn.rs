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
use std::sync::Arc;
use std::time::Duration;

use mousse_net_core::authz::{Traffic, Verdict};
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

use crate::admission::{ConnStreams, StreamAdmission, StreamPermit};
use crate::clock::Clock;
use crate::error::NetError;
use crate::limits::{ms, Limits};
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
    /// Decide what to do with inbound traffic (`message` is the decoded
    /// control message, if it is one).
    fn check(&mut self, traffic: Traffic, message: Option<&ControlMessage>) -> Verdict;
    /// A control message (other than `HELLO`) passed the gate.
    fn on_control(&mut self, message: ControlMessage, out: &mut Outbox);
    /// Whether this side may open streams now.
    fn may_open(&self) -> bool;
    /// The connection ended.
    fn on_closed(&mut self, reason: &CloseReason);
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
    Status(ConnStatus),
    Code(PairingCode),
    /// Answered when the peer's next `PONG` arrives.
    Ping(oneshot::Sender<()>),
}

enum StreamEvent {
    Data(Vec<u8>),
    Fin,
    Reset(ErrorCode),
    ConnectionClosed(CloseReason),
}

/// The driver's end of one stream's receive side. A peer reset is also
/// posted on `reset`, so a reader that is holding back still learns of it
/// ([`StreamReader::reset_by_peer`]).
struct StreamTx {
    events: mpsc::UnboundedSender<StreamEvent>,
    reset: watch::Sender<Option<ErrorCode>>,
}

impl StreamTx {
    fn send(&self, event: StreamEvent) -> Result<(), ()> {
        if let StreamEvent::Reset(code) = &event {
            self.reset.send_replace(Some(*code));
        }
        self.events.send(event).map_err(|_| ())
    }
}

/// The receiving half of a stream. It holds the stream's place (see
/// [`crate::admission`]) until it is dropped.
pub struct StreamReader {
    id: StreamId,
    rx: mpsc::UnboundedReceiver<StreamEvent>,
    cmd: mpsc::UnboundedSender<Cmd>,
    ended: Option<Result<(), NetError>>,
    closing: watch::Receiver<bool>,
    admission: Arc<StreamAdmission>,
    _permit: Arc<StreamPermit>,
    reset: watch::Receiver<Option<ErrorCode>>,
}

impl Drop for StreamReader {
    fn drop(&mut self) {
        // Bytes nobody will read leave the queue gauge.
        self.rx.close();
        while let Ok(event) = self.rx.try_recv() {
            if let StreamEvent::Data(bytes) = event {
                self.admission.sub_queued(bytes.len() as u64);
            }
        }
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
        let event = self.rx.recv().await;
        let result = match event {
            Some(StreamEvent::Data(bytes)) => {
                self.admission.sub_queued(bytes.len() as u64);
                let _ = self.cmd.send(Cmd::Release(self.id, bytes.len() as u64));
                return Ok(Some(bytes));
            }
            Some(StreamEvent::Fin) => Ok(()),
            Some(StreamEvent::Reset(code)) => Err(NetError::StreamReset(code)),
            Some(StreamEvent::ConnectionClosed(reason)) => Err(NetError::Closed(reason)),
            None => Err(NetError::Closed(CloseReason::PipeClosed)),
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

    /// Abort the stream in both directions.
    pub fn reset(&self, code: ErrorCode) {
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

    /// Close with `code`.
    pub fn close(&self, code: ErrorCode) {
        let _ = self.cmd.send(Cmd::Close(code));
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
    let connection = Connection {
        id: start.conn,
        peer: start.peer,
        kx_group: start.kx_group.clone(),
        deadline: start.deadline,
        cmd: cmd_tx.clone(),
        status: status_rx,
        incoming: tokio::sync::Mutex::new(accept_rx),
    };
    let driver = Driver {
        mux: Mux::with_limits(start.side, start.clock.mono(), start.limits.core()),
        limits: DriverLimits::new(&start.limits),
        admit: start.streams.connection(),
        permits: HashMap::new(),
        deadline: Deadline::new(start.deadline, &*start.clock),
        clock: start.clock,
        role,
        cmd_tx,
        status: status_tx,
        closing: closing_tx,
        accept: accept_tx,
        streams: HashMap::new(),
        blocked: Vec::new(),
        pings: Vec::new(),
        hello: HelloState::new(VersionSupport::LOCAL),
        reason: None,
        before_close: VecDeque::new(),
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
    accept: mpsc::UnboundedSender<MuxStream>,
    streams: HashMap<u32, StreamTx>,
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
    reason: Option<CloseReason>,
    /// Encoded frames a closing step produced, sent before the GOAWAY.
    before_close: VecDeque<Vec<u8>>,
}

fn classify(frame: &Frame) -> Result<(Traffic, Option<ControlMessage>), ErrorCode> {
    Ok(match frame {
        Frame::Ping { .. } | Frame::Pong { .. } => (Traffic::Keepalive, None),
        Frame::GoAway { .. } => (Traffic::GoAway, None),
        Frame::Control { payload } => {
            let message = ControlMessage::decode(payload).map_err(|_| ErrorCode::ProtocolError)?;
            let traffic = match &message {
                ControlMessage::Hello { .. } => Traffic::Hello,
                ControlMessage::JoinProof { .. } => Traffic::JoinProof,
                ControlMessage::CodeExchange { .. } | ControlMessage::CodeAbort { .. } => {
                    Traffic::Pairing
                }
                ControlMessage::Authorized { .. } | ControlMessage::Paired { .. } => {
                    Traffic::HostOnly
                }
            };
            (traffic, Some(message))
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
            major_version: VersionSupport::LOCAL.major,
            minor_version: VersionSupport::LOCAL.minor,
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
            if slot.is_some() {
                if let Some(frame) = self.next_frame() {
                    if let Some(tx) = slot.take() {
                        let _ = tx.send(frame);
                    }
                }
            }
            self.release_blocked();
            self.sweep_permits();
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
            let _ = tx.send(StreamEvent::ConnectionClosed(reason.clone()));
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
        self.before_close
            .pop_front()
            .or_else(|| self.mux.poll_transmit(self.clock.mono()))
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
                } else if let Some(permit) = self.admit.try_admit() {
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
        let (tx, rx) = mpsc::unbounded_channel();
        let (reset, reset_rx) = watch::channel(None);
        self.streams.insert(id.0, StreamTx { events: tx, reset });
        self.permits.insert(id.0, permit.clone());
        MuxStream {
            reader: StreamReader {
                id,
                rx,
                cmd: self.cmd_tx.clone(),
                ended: None,
                closing: self.closing.subscribe(),
                admission: self.admit.admission().clone(),
                _permit: permit,
                reset: reset_rx,
            },
            writer: StreamWriter {
                id,
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
                match self.hello.on_hello(*major_version, *minor_version) {
                    HelloOutcome::Agreed(_) => {}
                    HelloOutcome::Ignored => return Verdict::Ignore,
                    HelloOutcome::Close(code) => return Verdict::Close(code),
                }
            }
            Traffic::Keepalive | Traffic::GoAway => {}
            _ if self.hello.agreed().is_none() => return Verdict::Close(ErrorCode::ProtocolError),
            _ => {}
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
                // Admission: a stream past either cap is refused before
                // anything is queued for it (Phase 1a §2.2).
                let Some(permit) = self.admit_peer_stream() else {
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
                let n = bytes.len() as u64;
                let admission = self.admit.admission();
                // Counted before the reader can take it.
                admission.add_queued(n);
                let delivered = self
                    .streams
                    .get(&stream.0)
                    .is_some_and(|tx| tx.send(StreamEvent::Data(bytes)).is_ok());
                if !delivered {
                    admission.sub_queued(n);
                }
                if !delivered && self.streams.remove(&stream.0).is_some() {
                    let _ = self.mux.reset(stream, ErrorCode::Cancelled);
                }
            }
            MuxEvent::Finished { stream } => {
                if let Some(tx) = self.streams.remove(&stream.0) {
                    let _ = tx.send(StreamEvent::Fin);
                }
            }
            MuxEvent::Reset { stream, code } => {
                if let Some(tx) = self.streams.remove(&stream.0) {
                    let _ = tx.send(StreamEvent::Reset(code));
                }
            }
            MuxEvent::Control(bytes) => {
                let Ok(message) = ControlMessage::decode(&bytes) else {
                    self.close(ErrorCode::ProtocolError);
                    return;
                };
                if matches!(message, ControlMessage::Hello { .. }) {
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
                limits: Limits::DEFAULT,
                streams: StreamAdmission::new(&Limits::DEFAULT),
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
}
