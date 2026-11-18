//! The stream multiplexer: frames over one TLS byte stream, with per-stream
//! credit, strict priority (control > interactive > bulk) and keepalive.
//!
//! [`Mux`] is a pure state machine. The I/O layer:
//! - feeds received bytes to [`Mux::receive`] and handles the events;
//! - writes whatever [`Mux::poll_transmit`] returns, one frame at a time;
//! - calls [`Mux::on_timeout`] at [`Mux::poll_timeout`].

mod frame;

use std::collections::{BTreeMap, VecDeque};
use std::ops::Bound;
use std::fmt;

pub use frame::{
    decode as decode_frame, frame_type, Frame, FrameError, PriorityClass, StreamId, HEADER_LEN, MAX_CONTROL_PAYLOAD,
    MAX_LABEL_LEN, MAX_OPEN_PAYLOAD, MAX_PAYLOAD,
};

use crate::time::Millis;
use crate::ErrorCode;

/// Send a `PING` after this long without sending anything (15 s).
pub const KEEPALIVE_MS: u64 = 15_000;

/// Close after this long without receiving anything (45 s).
pub const IDLE_TIMEOUT_MS: u64 = 45_000;

/// Each direction of each stream starts with this much credit (256 KiB).
pub const INITIAL_CREDIT: u32 = 262_144;

/// A stream's available send credit may never exceed this (1 GiB).
pub const MAX_CREDIT: u64 = 1 << 30;

/// Most streams a peer may have open at once; more are refused.
pub const MAX_PEER_STREAMS: usize = 1_024;

/// Largest `DATA` payload this sender produces. Keeps interactive latency
/// low behind bulk: an interactive frame waits for at most one such chunk.
pub const SEND_CHUNK: usize = 16_384;

/// Which end of the connection this is. Decides stream id parity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MuxRole {
    /// The TLS client (the caller): opens odd stream ids, from 1.
    Caller,
    /// The TLS server (the host): opens even stream ids, from 2.
    Host,
}

/// Something that happened on the connection.
#[derive(Clone, PartialEq, Eq)]
pub enum MuxEvent {
    /// The peer opened a stream.
    StreamOpened {
        /// Stream.
        stream: StreamId,
        /// Its class.
        class: PriorityClass,
        /// Its label.
        label: String,
    },
    /// Stream bytes arrived. Call [`Mux::release`] once they are consumed.
    Data {
        /// Stream.
        stream: StreamId,
        /// Bytes.
        bytes: Vec<u8>,
    },
    /// The peer finished sending on a stream.
    Finished {
        /// Stream.
        stream: StreamId,
    },
    /// The peer aborted a stream.
    Reset {
        /// Stream.
        stream: StreamId,
        /// Why.
        code: ErrorCode,
    },
    /// A control message arrived (decode with
    /// [`crate::control::ControlMessage::decode`]).
    Control(Vec<u8>),
    /// A keepalive round trip completed.
    Pong {
        /// Round-trip time in milliseconds.
        rtt_ms: u64,
    },
    /// The peer closed the connection.
    GoAway {
        /// Why.
        code: ErrorCode,
    },
}

impl fmt::Debug for MuxEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MuxEvent::StreamOpened { stream, class, label } => {
                write!(f, "StreamOpened({}, {class:?}, {label:?})", stream.0)
            }
            MuxEvent::Data { stream, bytes } => write!(f, "Data({}, {} bytes)", stream.0, bytes.len()),
            MuxEvent::Finished { stream } => write!(f, "Finished({})", stream.0),
            MuxEvent::Reset { stream, code } => write!(f, "Reset({}, {code:?})", stream.0),
            MuxEvent::Control(bytes) => write!(f, "Control({} bytes)", bytes.len()),
            MuxEvent::Pong { rtt_ms } => write!(f, "Pong({rtt_ms} ms)"),
            MuxEvent::GoAway { code } => write!(f, "GoAway({code:?})"),
        }
    }
}

/// A connection-level failure. The mux has queued `GOAWAY(code)` and is
/// closing; flush [`Mux::poll_transmit`] and close the pipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MuxError {
    /// The code sent in `GOAWAY`.
    pub code: ErrorCode,
}

impl fmt::Display for MuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mux connection error: {}", self.code.name())
    }
}

impl std::error::Error for MuxError {}

/// Why a local stream operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// No such open stream.
    UnknownStream,
    /// This side already finished or reset the stream.
    Finished,
    /// The connection is closing.
    Closing,
    /// The label is empty or longer than 64 bytes.
    BadLabel,
    /// Stream ids are used up; open a new connection.
    IdsExhausted,
    /// A control message is larger than the limit.
    TooLarge,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StreamError::UnknownStream => "no such stream",
            StreamError::Finished => "stream already finished",
            StreamError::Closing => "connection is closing",
            StreamError::BadLabel => "bad stream label",
            StreamError::IdsExhausted => "stream ids exhausted",
            StreamError::TooLarge => "message too large",
        })
    }
}

impl std::error::Error for StreamError {}

struct Stream {
    class: PriorityClass,
    /// Bytes we may still send.
    send_credit: u64,
    /// Queued outgoing bytes.
    out: VecDeque<u8>,
    fin_queued: bool,
    fin_sent: bool,
    /// Bytes the peer may still send before we grant more.
    recv_window: u64,
    /// Bytes delivered to the app and not yet released.
    recv_unreleased: u64,
    /// Released bytes not yet returned as credit.
    recv_to_credit: u64,
    peer_fin: bool,
    peer_initiated: bool,
}

impl Stream {
    fn new(class: PriorityClass, peer_initiated: bool) -> Self {
        Self {
            class,
            send_credit: u64::from(INITIAL_CREDIT),
            out: VecDeque::new(),
            fin_queued: false,
            fin_sent: false,
            recv_window: u64::from(INITIAL_CREDIT),
            recv_unreleased: 0,
            recv_to_credit: 0,
            peer_fin: false,
            peer_initiated,
        }
    }

    fn ready(&self) -> bool {
        (!self.out.is_empty() && self.send_credit > 0) || (self.out.is_empty() && self.fin_queued && !self.fin_sent)
    }

    fn done(&self) -> bool {
        self.fin_sent && self.peer_fin && self.out.is_empty()
    }
}

/// One connection's multiplexer.
pub struct Mux {
    role: MuxRole,
    next_local_id: u32,
    highest_peer_id: u32,
    streams: BTreeMap<u32, Stream>,
    control: VecDeque<Frame>,
    rx: Vec<u8>,
    last_sent: Millis,
    last_received: Millis,
    ping_counter: u64,
    outstanding_ping: Option<([u8; 8], Millis)>,
    cursor: [u32; 2],
    closing: Option<ErrorCode>,
    goaway_sent: bool,
}

impl Mux {
    /// A new mux; `now` starts both timers.
    pub fn new(role: MuxRole, now: Millis) -> Self {
        Self {
            role,
            next_local_id: match role {
                MuxRole::Caller => 1,
                MuxRole::Host => 2,
            },
            highest_peer_id: 0,
            streams: BTreeMap::new(),
            control: VecDeque::new(),
            rx: Vec::new(),
            last_sent: now,
            last_received: now,
            ping_counter: 0,
            outstanding_ping: None,
            cursor: [0, 0],
            closing: None,
            goaway_sent: false,
        }
    }

    fn is_peer_id(&self, id: u32) -> bool {
        let odd = id % 2 == 1;
        match self.role {
            MuxRole::Caller => !odd,
            MuxRole::Host => odd,
        }
    }

    /// Whether the connection is closing (a `GOAWAY` was queued or received).
    pub fn is_closing(&self) -> bool {
        self.closing.is_some()
    }

    /// Whether the closing `GOAWAY` has been handed to the pipe (or the peer
    /// closed). The I/O layer can drop the connection.
    pub fn is_closed(&self) -> bool {
        self.closing.is_some() && (self.goaway_sent || self.control.is_empty())
    }

    /// Open a stream. The `OPEN` frame is queued ahead of its data.
    pub fn open_stream(&mut self, class: PriorityClass, label: &str) -> Result<StreamId, StreamError> {
        if self.closing.is_some() {
            return Err(StreamError::Closing);
        }
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(StreamError::BadLabel);
        }
        let id = self.next_local_id;
        self.next_local_id = id.checked_add(2).ok_or(StreamError::IdsExhausted)?;
        self.streams.insert(id, Stream::new(class, false));
        self.control.push_back(Frame::Open {
            stream: StreamId(id),
            class,
            label: label.to_owned(),
        });
        Ok(StreamId(id))
    }

    /// Queue bytes on a stream. They go out as credit allows.
    pub fn send(&mut self, stream: StreamId, bytes: &[u8]) -> Result<(), StreamError> {
        if self.closing.is_some() {
            return Err(StreamError::Closing);
        }
        let s = self.streams.get_mut(&stream.0).ok_or(StreamError::UnknownStream)?;
        if s.fin_queued {
            return Err(StreamError::Finished);
        }
        s.out.extend(bytes);
        Ok(())
    }

    /// Finish sending on a stream (`FIN` after all queued bytes).
    pub fn finish(&mut self, stream: StreamId) -> Result<(), StreamError> {
        let s = self.streams.get_mut(&stream.0).ok_or(StreamError::UnknownStream)?;
        if s.fin_queued {
            return Err(StreamError::Finished);
        }
        s.fin_queued = true;
        Ok(())
    }

    /// Abort a stream in both directions. Queued bytes are dropped.
    pub fn reset(&mut self, stream: StreamId, code: ErrorCode) -> Result<(), StreamError> {
        self.streams.remove(&stream.0).ok_or(StreamError::UnknownStream)?;
        self.control.push_back(Frame::Reset { stream, code });
        Ok(())
    }

    /// The app consumed `n` received bytes on `stream`; return them to the
    /// peer as credit. Credit is batched: a `CREDIT` frame goes out once a
    /// quarter of the initial window is released.
    pub fn release(&mut self, stream: StreamId, n: u64) {
        let Some(s) = self.streams.get_mut(&stream.0) else {
            return;
        };
        let n = n.min(s.recv_unreleased);
        s.recv_unreleased -= n;
        s.recv_to_credit += n;
        if s.recv_to_credit >= u64::from(INITIAL_CREDIT / 4) && !s.peer_fin {
            let increment = s.recv_to_credit.min(u64::from(u32::MAX)) as u32;
            s.recv_to_credit -= u64::from(increment);
            s.recv_window += u64::from(increment);
            self.control.push_back(Frame::Credit { stream, increment });
        }
    }

    /// Bytes that may be sent on `stream` right now without waiting.
    pub fn send_credit(&self, stream: StreamId) -> Option<u64> {
        self.streams.get(&stream.0).map(|s| s.send_credit)
    }

    /// Bytes queued and not yet sent on `stream`.
    pub fn queued(&self, stream: StreamId) -> Option<usize> {
        self.streams.get(&stream.0).map(|s| s.out.len())
    }

    /// Queue a control message (encoded [`crate::control::ControlMessage`]).
    pub fn send_control(&mut self, payload: Vec<u8>) -> Result<(), StreamError> {
        if self.closing.is_some() {
            return Err(StreamError::Closing);
        }
        if payload.is_empty() || payload.len() > MAX_CONTROL_PAYLOAD {
            return Err(StreamError::TooLarge);
        }
        self.control.push_back(Frame::Control { payload });
        Ok(())
    }

    /// Close the connection: drop queued work and send `GOAWAY(code)`.
    pub fn close(&mut self, code: ErrorCode) {
        if self.closing.is_some() {
            return;
        }
        self.closing = Some(code);
        self.streams.clear();
        self.control.clear();
        self.control.push_back(Frame::GoAway { code });
    }

    fn fail(&mut self, code: ErrorCode) -> MuxError {
        self.close(code);
        MuxError { code }
    }

    /// Feed bytes received from the pipe.
    pub fn receive(&mut self, bytes: &[u8], now: Millis) -> Result<Vec<MuxEvent>, MuxError> {
        if self.closing.is_some() {
            return Ok(Vec::new());
        }
        self.rx.extend_from_slice(bytes);
        let mut events = Vec::new();
        loop {
            let (frame, used) = match decode_frame(&self.rx) {
                Ok(Some(parsed)) => parsed,
                Ok(None) => break,
                Err(e) => return Err(self.fail(e.code())),
            };
            self.rx.drain(..used);
            self.last_received = now;
            self.handle(frame, now, &mut events)?;
            if self.closing.is_some() {
                break;
            }
        }
        Ok(events)
    }

    fn handle(&mut self, frame: Frame, now: Millis, events: &mut Vec<MuxEvent>) -> Result<(), MuxError> {
        match frame {
            Frame::Open { stream, class, label } => {
                if !self.is_peer_id(stream.0) || stream.0 <= self.highest_peer_id {
                    return Err(self.fail(ErrorCode::ProtocolError));
                }
                self.highest_peer_id = stream.0;
                let open_by_peer = self.streams.values().filter(|s| s.peer_initiated).count();
                if open_by_peer >= MAX_PEER_STREAMS {
                    self.control.push_back(Frame::Reset { stream, code: ErrorCode::RefusedStream });
                    return Ok(());
                }
                self.streams.insert(stream.0, Stream::new(class, true));
                events.push(MuxEvent::StreamOpened { stream, class, label });
            }
            Frame::Data { stream, payload } => {
                self.check_known(stream)?;
                let Some(s) = self.streams.get_mut(&stream.0) else {
                    return Ok(()); // closed locally; late data is dropped
                };
                if s.peer_fin {
                    return Err(self.fail(ErrorCode::StreamClosed));
                }
                let len = payload.len() as u64;
                if len > s.recv_window {
                    return Err(self.fail(ErrorCode::FlowControl));
                }
                s.recv_window -= len;
                s.recv_unreleased += len;
                events.push(MuxEvent::Data { stream, bytes: payload });
            }
            Frame::Credit { stream, increment } => {
                self.check_known(stream)?;
                if let Some(s) = self.streams.get_mut(&stream.0) {
                    s.send_credit += u64::from(increment);
                    if s.send_credit > MAX_CREDIT {
                        return Err(self.fail(ErrorCode::FlowControl));
                    }
                }
            }
            Frame::Fin { stream } => {
                self.check_known(stream)?;
                if let Some(s) = self.streams.get_mut(&stream.0) {
                    if s.peer_fin {
                        return Err(self.fail(ErrorCode::StreamClosed));
                    }
                    s.peer_fin = true;
                    let done = s.done();
                    events.push(MuxEvent::Finished { stream });
                    if done {
                        self.streams.remove(&stream.0);
                    }
                }
            }
            Frame::Reset { stream, code } => {
                self.check_known(stream)?;
                if self.streams.remove(&stream.0).is_some() {
                    events.push(MuxEvent::Reset { stream, code });
                }
            }
            Frame::Ping { opaque } => self.control.push_back(Frame::Pong { opaque }),
            Frame::Pong { opaque } => {
                if let Some((expected, sent_at)) = self.outstanding_ping {
                    if expected == opaque {
                        self.outstanding_ping = None;
                        events.push(MuxEvent::Pong { rtt_ms: now.since(sent_at) });
                    }
                }
            }
            Frame::Control { payload } => events.push(MuxEvent::Control(payload)),
            Frame::GoAway { code } => {
                self.closing = Some(code);
                self.goaway_sent = true; // nothing more to send
                self.streams.clear();
                self.control.clear();
                events.push(MuxEvent::GoAway { code });
            }
        }
        Ok(())
    }

    /// A frame for a stream that was never opened is a protocol error. A
    /// frame for a stream that existed and is gone is a harmless race.
    fn check_known(&mut self, stream: StreamId) -> Result<(), MuxError> {
        let id = stream.0;
        let ever_opened = if self.is_peer_id(id) {
            id <= self.highest_peer_id
        } else {
            id < self.next_local_id
        };
        if ever_opened {
            Ok(())
        } else {
            Err(self.fail(ErrorCode::ProtocolError))
        }
    }

    /// The next frame to write, if any. Control frames first, then
    /// interactive streams, then bulk; round-robin within a class.
    pub fn poll_transmit(&mut self, now: Millis) -> Option<Vec<u8>> {
        if self.goaway_sent {
            return None;
        }
        let frame = match self.control.pop_front() {
            Some(frame) => Some(frame),
            None => self.next_stream_frame(PriorityClass::Interactive)
                .or_else(|| self.next_stream_frame(PriorityClass::Bulk)),
        }?;
        if matches!(frame, Frame::GoAway { .. }) {
            self.goaway_sent = true;
        }
        if let Frame::Ping { opaque } = frame {
            self.outstanding_ping = Some((opaque, now));
        }
        self.last_sent = now;
        Some(frame.encode())
    }

    fn next_stream_frame(&mut self, class: PriorityClass) -> Option<Frame> {
        let slot = class as usize;
        let after = self.cursor[slot];
        let pick = self
            .streams
            .range((Bound::Excluded(after), Bound::Unbounded))
            .chain(self.streams.range(..=after))
            .find(|(_, s)| s.class == class && s.ready())
            .map(|(id, _)| *id)?;
        self.cursor[slot] = pick;
        let s = self.streams.get_mut(&pick)?;
        let stream = StreamId(pick);
        if !s.out.is_empty() {
            let n = s.out.len().min(SEND_CHUNK).min(s.send_credit as usize);
            let payload: Vec<u8> = s.out.drain(..n).collect();
            s.send_credit -= n as u64;
            return Some(Frame::Data { stream, payload });
        }
        s.fin_sent = true;
        if s.done() {
            self.streams.remove(&pick);
        }
        Some(Frame::Fin { stream })
    }

    /// When [`Mux::on_timeout`] must next run.
    pub fn poll_timeout(&self) -> Option<Millis> {
        if self.closing.is_some() {
            return None;
        }
        Some(
            self.last_sent
                .plus(KEEPALIVE_MS)
                .min(self.last_received.plus(IDLE_TIMEOUT_MS)),
        )
    }

    /// Run timers: close after 45 s of silence from the peer; queue a `PING`
    /// after 15 s without sending.
    pub fn on_timeout(&mut self, now: Millis) -> Result<(), MuxError> {
        if self.closing.is_some() {
            return Ok(());
        }
        if now.since(self.last_received) >= IDLE_TIMEOUT_MS {
            return Err(self.fail(ErrorCode::IdleTimeout));
        }
        if now.since(self.last_sent) >= KEEPALIVE_MS && !self.control.iter().any(|f| matches!(f, Frame::Ping { .. })) {
            self.ping_counter += 1;
            self.control.push_back(Frame::Ping {
                opaque: self.ping_counter.to_be_bytes(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pump(from: &mut Mux, to: &mut Mux, now: Millis) -> Vec<MuxEvent> {
        let mut events = Vec::new();
        while let Some(bytes) = from.poll_transmit(now) {
            events.extend(to.receive(&bytes, now).unwrap());
        }
        events
    }

    fn pair() -> (Mux, Mux) {
        (Mux::new(MuxRole::Caller, Millis(0)), Mux::new(MuxRole::Host, Millis(0)))
    }

    #[test]
    fn stream_ids_follow_role_parity() {
        let (mut c, mut h) = pair();
        assert_eq!(c.open_stream(PriorityClass::Interactive, "a").unwrap(), StreamId(1));
        assert_eq!(c.open_stream(PriorityClass::Interactive, "b").unwrap(), StreamId(3));
        assert_eq!(h.open_stream(PriorityClass::Interactive, "c").unwrap(), StreamId(2));
    }

    #[test]
    fn data_flows_and_credit_limits_the_sender() {
        let (mut c, mut h) = pair();
        let s = c.open_stream(PriorityClass::Bulk, "file").unwrap();
        let big = vec![7u8; INITIAL_CREDIT as usize + 1000];
        c.send(s, &big).unwrap();
        let events = pump(&mut c, &mut h, Millis(1));
        let received: usize = events
            .iter()
            .map(|e| match e {
                MuxEvent::Data { bytes, .. } => bytes.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(received, INITIAL_CREDIT as usize);
        assert_eq!(c.send_credit(s), Some(0));
        assert_eq!(c.queued(s), Some(1000));
        // Releasing returns credit and the rest flows.
        h.release(s, u64::from(INITIAL_CREDIT));
        pump(&mut h, &mut c, Millis(2));
        let events = pump(&mut c, &mut h, Millis(3));
        assert!(matches!(&events[..], [MuxEvent::Data { bytes, .. }] if bytes.len() == 1000));
    }

    #[test]
    fn sending_beyond_credit_is_a_flow_control_error() {
        let (mut c, mut h) = pair();
        let s = c.open_stream(PriorityClass::Bulk, "x").unwrap();
        let open = c.poll_transmit(Millis(0)).unwrap();
        h.receive(&open, Millis(0)).unwrap();
        let chunk = Frame::Data { stream: s, payload: vec![0; MAX_PAYLOAD] }.encode();
        for _ in 0..(INITIAL_CREDIT as usize / MAX_PAYLOAD) {
            h.receive(&chunk, Millis(0)).unwrap();
        }
        assert_eq!(h.receive(&chunk, Millis(0)), Err(MuxError { code: ErrorCode::FlowControl }));
        assert!(h.is_closing());
        assert_eq!(h.poll_transmit(Millis(0)), Some(Frame::GoAway { code: ErrorCode::FlowControl }.encode()));
    }

    #[test]
    fn interactive_goes_before_bulk_and_bulk_is_chunked() {
        let (mut c, mut h) = pair();
        let bulk = c.open_stream(PriorityClass::Bulk, "file").unwrap();
        let typing = c.open_stream(PriorityClass::Interactive, "term").unwrap();
        // Deliver the two OPEN frames.
        pump(&mut c, &mut h, Millis(0));
        c.send(bulk, &vec![1u8; 3 * SEND_CHUNK]).unwrap();
        let first = c.poll_transmit(Millis(0)).unwrap();
        assert_eq!(first.len(), HEADER_LEN + SEND_CHUNK);
        c.send(typing, b"ls\n").unwrap();
        let next = c.poll_transmit(Millis(0)).unwrap();
        assert_eq!(decode_frame(&next).unwrap().unwrap().0, Frame::Data { stream: typing, payload: b"ls\n".to_vec() });
    }

    #[test]
    fn fin_follows_queued_data_and_both_fins_free_the_stream() {
        let (mut c, mut h) = pair();
        let s = c.open_stream(PriorityClass::Interactive, "rpc").unwrap();
        c.send(s, b"req").unwrap();
        c.finish(s).unwrap();
        let events = pump(&mut c, &mut h, Millis(0));
        assert_eq!(events.len(), 3);
        assert!(matches!(events[2], MuxEvent::Finished { .. }));
        h.finish(s).unwrap();
        pump(&mut h, &mut c, Millis(0));
        assert_eq!(c.queued(s), None);
        assert_eq!(h.queued(s), None);
    }

    #[test]
    fn opening_with_the_wrong_parity_or_reusing_an_id_is_rejected() {
        let (_, mut h) = pair();
        let even = Frame::Open { stream: StreamId(2), class: PriorityClass::Bulk, label: "x".into() }.encode();
        assert_eq!(h.receive(&even, Millis(0)), Err(MuxError { code: ErrorCode::ProtocolError }));
        let (_, mut h) = pair();
        let five = Frame::Open { stream: StreamId(5), class: PriorityClass::Bulk, label: "x".into() }.encode();
        let three = Frame::Open { stream: StreamId(3), class: PriorityClass::Bulk, label: "x".into() }.encode();
        h.receive(&five, Millis(0)).unwrap();
        assert_eq!(h.receive(&three, Millis(0)), Err(MuxError { code: ErrorCode::ProtocolError }));
    }

    #[test]
    fn data_on_a_never_opened_stream_is_rejected() {
        let (_, mut h) = pair();
        let data = Frame::Data { stream: StreamId(1), payload: vec![1] }.encode();
        assert_eq!(h.receive(&data, Millis(0)), Err(MuxError { code: ErrorCode::ProtocolError }));
    }

    #[test]
    fn keepalive_after_15s_and_idle_close_after_45s() {
        let mut m = Mux::new(MuxRole::Caller, Millis(0));
        assert_eq!(m.poll_timeout(), Some(Millis(KEEPALIVE_MS)));
        m.on_timeout(Millis(KEEPALIVE_MS - 1)).unwrap();
        assert_eq!(m.poll_transmit(Millis(KEEPALIVE_MS - 1)), None);
        m.on_timeout(Millis(KEEPALIVE_MS)).unwrap();
        let ping = m.poll_transmit(Millis(KEEPALIVE_MS)).unwrap();
        assert!(matches!(decode_frame(&ping).unwrap().unwrap().0, Frame::Ping { .. }));
        // The peer answers; round-trip is measured.
        let pong = Frame::Pong { opaque: 1u64.to_be_bytes() }.encode();
        assert_eq!(m.receive(&pong, Millis(KEEPALIVE_MS + 40)).unwrap(), vec![MuxEvent::Pong { rtt_ms: 40 }]);
        // Nothing more from the peer: idle close 45 s after the last receive.
        let last = KEEPALIVE_MS + 40;
        assert!(m.on_timeout(Millis(last + IDLE_TIMEOUT_MS - 1)).is_ok());
        assert_eq!(m.on_timeout(Millis(last + IDLE_TIMEOUT_MS)), Err(MuxError { code: ErrorCode::IdleTimeout }));
    }

    #[test]
    fn ping_is_answered_with_the_same_bytes() {
        let mut m = Mux::new(MuxRole::Host, Millis(0));
        m.receive(&Frame::Ping { opaque: [9; 8] }.encode(), Millis(5)).unwrap();
        assert_eq!(m.poll_transmit(Millis(5)), Some(Frame::Pong { opaque: [9; 8] }.encode()));
    }

    #[test]
    fn bytes_split_across_reads_are_reassembled() {
        let (mut c, mut h) = pair();
        let s = c.open_stream(PriorityClass::Interactive, "t").unwrap();
        c.send(s, b"hello").unwrap();
        let mut wire = Vec::new();
        while let Some(b) = c.poll_transmit(Millis(0)) {
            wire.extend(b);
        }
        let mut events = Vec::new();
        for byte in wire {
            events.extend(h.receive(&[byte], Millis(0)).unwrap());
        }
        assert_eq!(events.len(), 2);
        assert_eq!(events[1], MuxEvent::Data { stream: s, bytes: b"hello".to_vec() });
    }
}
