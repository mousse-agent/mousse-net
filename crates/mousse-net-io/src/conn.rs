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
//!   message received.
//! - The connection closes with `CERT_EXPIRED` after the effective deadline
//!   of the two certificates.
//! - A separate writer task owns the write half, so a slow peer never stops
//!   us reading.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use mousse_net_core::authz::{Traffic, Verdict};
use mousse_net_core::control::ControlMessage;
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::{
    decode_frame, Frame, Mux, MuxEvent, MuxRole, PriorityClass, StreamError, StreamId,
};
use mousse_net_core::pairing::PairedHost;
use mousse_net_core::{ConnectionId, ErrorCode, UnixTime, PROTOCOL_MINOR_VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use tokio_rustls::TlsStream;

use crate::clock::Clock;
use crate::error::NetError;
use crate::pipe::Pipe;

/// Queued bytes per stream above which [`StreamWriter::write`] waits.
pub const WRITE_HIGH_WATER: usize = 256 * 1024;

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
    /// Decide what to do with inbound traffic.
    fn check(&mut self, traffic: Traffic) -> Verdict;
    /// A control message (other than `HELLO`) passed the gate.
    fn on_control(&mut self, message: ControlMessage, out: &mut Outbox);
    /// Whether this side may open streams now.
    fn may_open(&self) -> bool;
    /// The connection ended.
    fn on_closed(&mut self, reason: &CloseReason);
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
}

enum StreamEvent {
    Data(Vec<u8>),
    Fin,
    Reset(ErrorCode),
    ConnectionClosed(CloseReason),
}

/// The receiving half of a stream.
pub struct StreamReader {
    id: StreamId,
    rx: mpsc::UnboundedReceiver<StreamEvent>,
    cmd: mpsc::UnboundedSender<Cmd>,
    ended: Option<Result<(), NetError>>,
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
}

impl StreamWriter {
    /// Queue bytes. Waits while more than [`WRITE_HIGH_WATER`] bytes are
    /// queued on this stream.
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
            .map_err(|_| NetError::Closed(CloseReason::PipeClosed))?;
        rx.await
            .map_err(|_| NetError::Closed(CloseReason::PipeClosed))?
    }

    /// The next stream the peer opened. `None` once the connection closed.
    pub async fn accept_stream(&self) -> Option<MuxStream> {
        self.incoming.lock().await.recv().await
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
    let (accept_tx, accept_rx) = mpsc::unbounded_channel();
    let connection = Connection {
        id: start.conn,
        peer: start.peer,
        kx_group: start.kx_group.clone(),
        cmd: cmd_tx.clone(),
        status: status_rx,
        incoming: tokio::sync::Mutex::new(accept_rx),
    };
    let driver = Driver {
        mux: Mux::new(start.side, start.clock.mono()),
        clock: start.clock,
        deadline: start.deadline,
        role,
        cmd_tx,
        status: status_tx,
        accept: accept_tx,
        streams: HashMap::new(),
        blocked: Vec::new(),
        peer_hello: None,
        reason: None,
    };
    tokio::spawn(driver.run(start.tls, cmd_rx));
    connection
}

struct Driver {
    mux: Mux,
    clock: Arc<dyn Clock>,
    deadline: UnixTime,
    role: Box<dyn Role>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    status: watch::Sender<ConnStatus>,
    accept: mpsc::UnboundedSender<MuxStream>,
    streams: HashMap<u32, mpsc::UnboundedSender<StreamEvent>>,
    blocked: Vec<(StreamId, oneshot::Sender<Result<(), NetError>>)>,
    peer_hello: Option<u64>,
    reason: Option<CloseReason>,
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
        let (wtx, wrx) = mpsc::channel::<Vec<u8>>(16);
        let writer = tokio::spawn(writer_task(wr, wrx));

        let hello = ControlMessage::Hello {
            minor_version: PROTOCOL_MINOR_VERSION,
        };
        let _ = self.mux.send_control(hello.encode());
        let mut out = Outbox::default();
        self.role.on_start(&mut out);
        self.apply(out);

        let mut buf = vec![0u8; 32 * 1024];
        let mut inbuf: Vec<u8> = Vec::new();
        let mut pending: Option<Vec<u8>> = None;
        loop {
            if pending.is_none() {
                pending = self.mux.poll_transmit(self.clock.mono());
            }
            self.release_blocked();
            if pending.is_none() && self.mux.is_closed() {
                break;
            }
            let wake = self.next_wake();
            tokio::select! {
                permit = wtx.reserve(), if pending.is_some() => {
                    match permit {
                        Ok(permit) => {
                            if let Some(frame) = pending.take() {
                                permit.send(frame);
                            }
                        }
                        Err(_) => {
                            self.reason.get_or_insert(CloseReason::PipeClosed);
                            break;
                        }
                    }
                }
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
                            self.process_inbound(&mut inbuf);
                        }
                        Err(e) => {
                            self.reason.get_or_insert(CloseReason::Io(e.to_string()));
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep_until(wake) => self.on_timer(),
            }
        }

        let reason = self.reason.clone().unwrap_or(CloseReason::PipeClosed);
        for (_, tx) in self.streams.drain() {
            let _ = tx.send(StreamEvent::ConnectionClosed(reason.clone()));
        }
        for (_, reply) in self.blocked.drain(..) {
            let _ = reply.send(Err(NetError::Closed(reason.clone())));
        }
        self.role.on_closed(&reason);
        let _ = self.status.send(ConnStatus::Closed(reason));
        drop(wtx);
        let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    }

    fn next_wake(&self) -> Instant {
        let now = Instant::now();
        let mono = self.clock.mono();
        let mut wake = now + Duration::from_secs(3600);
        if let Some(t) = self.mux.poll_timeout() {
            wake = wake.min(now + Duration::from_millis(t.since(mono)));
        }
        let wall = self.clock.now();
        let until_deadline = self
            .deadline
            .secs()
            .saturating_add(1)
            .saturating_sub(wall.secs());
        wake.min(now + Duration::from_secs(until_deadline))
    }

    fn on_timer(&mut self) {
        if let Err(e) = self.mux.on_timeout(self.clock.mono()) {
            self.reason.get_or_insert(CloseReason::Local(e.code));
        }
        if self.clock.now() > self.deadline {
            self.close(ErrorCode::CertExpired);
        }
    }

    fn close(&mut self, code: ErrorCode) {
        if !self.mux.is_closing() {
            self.mux.close(code);
            self.reason.get_or_insert(CloseReason::Local(code));
        }
    }

    fn apply(&mut self, out: Outbox) {
        for message in out.control {
            let _ = self.mux.send_control(message.encode());
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
                let result = if self.mux.is_closing() {
                    Err(NetError::Closed(
                        self.reason.clone().unwrap_or(CloseReason::PipeClosed),
                    ))
                } else if !self.role.may_open() {
                    Err(NetError::Refused("the connection is not authorized".into()))
                } else {
                    self.mux
                        .open_stream(class, &label)
                        .map(|id| self.new_stream(id, class, label))
                        .map_err(stream_err)
                };
                let _ = reply.send(result);
            }
            Cmd::Send {
                stream,
                bytes,
                reply,
            } => match self.mux.send(stream, &bytes) {
                Ok(()) => self.blocked.push((stream, reply)),
                Err(e) => {
                    let _ = reply.send(Err(stream_err(e)));
                }
            },
            Cmd::Finish(stream) => {
                let _ = self.mux.finish(stream);
            }
            Cmd::Reset(stream, code) => {
                let _ = self.mux.reset(stream, code);
                self.streams.remove(&stream.0);
            }
            Cmd::Release(stream, n) => self.mux.release(stream, n),
            Cmd::Control(message) => {
                let _ = self.mux.send_control(message.encode());
            }
            Cmd::Close(code) => self.close(code),
            Cmd::Status(status) => {
                let _ = self.status.send(status);
            }
        }
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
                Some(queued) if queued > WRITE_HIGH_WATER => still.push((stream, reply)),
                // Below the mark, or the stream already completed.
                _ => {
                    let _ = reply.send(Ok(()));
                }
            }
        }
        self.blocked = still;
    }

    fn new_stream(&mut self, id: StreamId, class: PriorityClass, label: String) -> MuxStream {
        let (tx, rx) = mpsc::unbounded_channel();
        self.streams.insert(id.0, tx);
        MuxStream {
            reader: StreamReader {
                id,
                rx,
                cmd: self.cmd_tx.clone(),
                ended: None,
            },
            writer: StreamWriter {
                id,
                cmd: self.cmd_tx.clone(),
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

    /// The `HELLO` rule, then the role's gate.
    fn gate(&mut self, traffic: Traffic, message: Option<&ControlMessage>) -> Verdict {
        match (self.peer_hello, traffic) {
            (None, Traffic::Hello) => {
                if let Some(ControlMessage::Hello { minor_version }) = message {
                    // Every minor version of protocol 1 is accepted; the peer's
                    // is kept for features that later minors add.
                    self.peer_hello = Some(*minor_version);
                }
            }
            (Some(_), Traffic::Hello) => return Verdict::Close(ErrorCode::ProtocolError),
            (None, Traffic::Keepalive | Traffic::GoAway) => {}
            (None, _) => return Verdict::Close(ErrorCode::ProtocolError),
            (Some(_), _) => {}
        }
        self.role.check(traffic)
    }

    fn on_event(&mut self, event: MuxEvent) {
        match event {
            MuxEvent::StreamOpened {
                stream,
                class,
                label,
            } => {
                let s = self.new_stream(stream, class, label);
                if self.accept.send(s).is_err() {
                    self.streams.remove(&stream.0);
                    let _ = self.mux.reset(stream, ErrorCode::RefusedStream);
                }
            }
            MuxEvent::Data { stream, bytes } => {
                let delivered = self
                    .streams
                    .get(&stream.0)
                    .is_some_and(|tx| tx.send(StreamEvent::Data(bytes)).is_ok());
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
            MuxEvent::Pong { .. } => {}
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

async fn writer_task<P: Pipe>(mut wr: WriteHalf<TlsStream<P>>, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(frame) = rx.recv().await {
        if wr.write_all(&frame).await.is_err() {
            return;
        }
        if rx.is_empty() && wr.flush().await.is_err() {
            return;
        }
    }
    let _ = wr.flush().await;
    let _ = wr.shutdown().await;
}
