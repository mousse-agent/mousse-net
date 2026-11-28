//! Stream admission: how many streams may be open, and how many received
//! bytes wait in the engine's receive queues.
//!
//! Every stream gets 256 KiB of initial credit when it opens (wire.md 9.3),
//! and the driver queues what arrives before anyone reads it. Bounding the
//! open streams therefore bounds that queue: at most
//! `STREAMS_PER_CONNECTION` streams on one connection and
//! `STREAMS_PER_ENDPOINT` on all connections of one endpoint, both
//! directions counted. A peer's open beyond either is refused with
//! `RESET REFUSED_STREAM`; a local open beyond either fails with
//! [`NetError::StreamLimit`](crate::NetError::StreamLimit).
//!
//! A stream holds its place until the mux is done with it **and** its
//! reader is gone, so bytes still waiting in a finished stream's queue keep
//! counting.
//!
//! Shared by every connection of the endpoint, it also carries each
//! connection's version decision ([`HelloSeen`]) to whoever watches them.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use mousse_net_core::identity::IdentityPublicKey;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::limits::Limits;

/// What one connection decided on its peer's first `HELLO`, whatever came
/// after it (authorization, publication).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloSeen {
    /// The peer's identity, proven in step 1.
    pub peer: IdentityPublicKey,
    /// The newest minor version its `HELLO` named.
    pub peer_minor: u64,
    /// The minor version the connection uses; `None`: it closed with
    /// `UNSUPPORTED_VERSION`.
    pub agreed: Option<u64>,
    /// When the `HELLO` was read.
    pub at: Instant,
    /// The peer dialled this endpoint.
    pub inbound: bool,
}

/// One endpoint's stream places and receive-queue gauge. A host and a
/// caller of the same endpoint share one (see
/// [`HostConfig::streams`](crate::HostConfig::streams) and
/// [`Caller::use_stream_admission`](crate::Caller::use_stream_admission)).
#[derive(Debug)]
pub struct StreamAdmission {
    per_connection: usize,
    per_endpoint: usize,
    /// Engine streams per connection, apart from the two caps.
    engine_per_connection: usize,
    open: Mutex<usize>,
    queued: AtomicU64,
    peak_queued: AtomicU64,
    held: AtomicU64,
    peak_held: AtomicU64,
    refused: AtomicU64,
    /// Where version decisions go, once someone watches.
    hellos: Mutex<Option<mpsc::UnboundedSender<HelloSeen>>>,
}

impl StreamAdmission {
    /// Places from `limits` (`STREAMS_PER_CONNECTION`,
    /// `STREAMS_PER_ENDPOINT`).
    pub fn new(limits: &Limits) -> Arc<Self> {
        let io = limits.io();
        Arc::new(Self {
            per_connection: usize::try_from(io.streams_per_connection()).unwrap_or(usize::MAX),
            per_endpoint: usize::try_from(io.streams_per_endpoint()).unwrap_or(usize::MAX),
            engine_per_connection: usize::try_from(io.engine_streams_per_connection())
                .unwrap_or(usize::MAX),
            open: Mutex::new(0),
            queued: AtomicU64::new(0),
            peak_queued: AtomicU64::new(0),
            held: AtomicU64::new(0),
            peak_held: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            hellos: Mutex::new(None),
        })
    }

    /// Every connection's version decision from now on, in the order they
    /// were made. A second watcher replaces the first.
    pub fn watch_hellos(&self) -> mpsc::UnboundedReceiver<HelloSeen> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.hellos.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        rx
    }

    pub(crate) fn hello_seen(&self, seen: HelloSeen) {
        if let Some(tx) = &*self.hellos.lock().unwrap_or_else(|e| e.into_inner()) {
            let _ = tx.send(seen);
        }
    }

    /// Streams open now on all connections.
    pub fn open_streams(&self) -> usize {
        *self.open.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Received stream bytes waiting in the engine's receive queues: arrived
    /// and not yet read.
    pub fn queued_bytes(&self) -> u64 {
        self.queued.load(Ordering::Relaxed)
    }

    /// The most [`StreamAdmission::queued_bytes`] has been.
    pub fn peak_queued_bytes(&self) -> u64 {
        self.peak_queued.load(Ordering::Relaxed)
    }

    /// Memory the receive queues hold for those bytes: their buffers'
    /// sizes and overhead. Many tiny DATA frames share buffers, so this
    /// stays near [`StreamAdmission::queued_bytes`] however the peer
    /// splits its data.
    pub fn held_bytes(&self) -> u64 {
        self.held.load(Ordering::Relaxed)
    }

    /// The most [`StreamAdmission::held_bytes`] has been.
    pub fn peak_held_bytes(&self) -> u64 {
        self.peak_held.load(Ordering::Relaxed)
    }

    /// Peer opens refused for want of a place.
    pub fn refused_streams(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// A new connection's share.
    pub(crate) fn connection(self: &Arc<Self>) -> ConnStreams {
        ConnStreams {
            admission: self.clone(),
            open: Arc::new(AtomicUsize::new(0)),
            engine_open: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn add_queued(&self, n: u64) {
        let now = self.queued.fetch_add(n, Ordering::Relaxed) + n;
        self.peak_queued.fetch_max(now, Ordering::Relaxed);
    }

    pub(crate) fn sub_queued(&self, n: u64) {
        let _ = self
            .queued
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |q| {
                Some(q.saturating_sub(n))
            });
    }

    pub(crate) fn add_held(&self, n: u64) {
        let now = self.held.fetch_add(n, Ordering::Relaxed) + n;
        self.peak_held.fetch_max(now, Ordering::Relaxed);
    }

    pub(crate) fn sub_held(&self, n: u64) {
        let _ = self
            .held
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |q| {
                Some(q.saturating_sub(n))
            });
    }
}

/// One connection's places.
pub(crate) struct ConnStreams {
    admission: Arc<StreamAdmission>,
    /// Changed only under the admission's lock.
    open: Arc<AtomicUsize>,
    /// Engine streams open on this connection.
    engine_open: Arc<AtomicUsize>,
}

impl ConnStreams {
    /// A place for one more stream, if both caps allow it.
    pub(crate) fn try_admit(&self) -> Option<Arc<StreamPermit>> {
        let mut open = self
            .admission
            .open
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if *open >= self.admission.per_endpoint
            || self.open.load(Ordering::Relaxed) >= self.admission.per_connection
        {
            return None;
        }
        *open += 1;
        self.open.fetch_add(1, Ordering::Relaxed);
        Some(self.permit())
    }

    /// A place for an engine stream (label `mousse-`), counted apart from
    /// the app's caps.
    pub(crate) fn try_admit_engine(&self) -> Option<Arc<StreamPermit>> {
        let _guard = self
            .admission
            .open
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.engine_open.load(Ordering::Relaxed) >= self.admission.engine_per_connection {
            return None;
        }
        self.engine_open.fetch_add(1, Ordering::Relaxed);
        Some(Arc::new(StreamPermit {
            admission: self.admission.clone(),
            conn: self.engine_open.clone(),
            engine: true,
        }))
    }

    /// The `no-stream-cap` control: a place whatever the caps say.
    #[cfg(mousse_control = "no-stream-cap")]
    pub(crate) fn admit_anyway(&self) -> Arc<StreamPermit> {
        let mut open = self
            .admission
            .open
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *open += 1;
        self.open.fetch_add(1, Ordering::Relaxed);
        self.permit()
    }

    fn permit(&self) -> Arc<StreamPermit> {
        Arc::new(StreamPermit {
            admission: self.admission.clone(),
            conn: self.open.clone(),
            engine: false,
        })
    }

    pub(crate) fn refused(&self) {
        self.admission.refused.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn admission(&self) -> &Arc<StreamAdmission> {
        &self.admission
    }
}

/// One stream's place. Shared by the driver (while the mux has the stream)
/// and the stream's reader; the place frees when both let go.
#[derive(Debug)]
pub(crate) struct StreamPermit {
    admission: Arc<StreamAdmission>,
    conn: Arc<AtomicUsize>,
    /// An engine stream's place: not counted in the endpoint's total.
    engine: bool,
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        let mut open = self
            .admission
            .open
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !self.engine {
            *open = open.saturating_sub(1);
        }
        let _ = self
            .conn
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(1))
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(per_conn: u64, per_endpoint: u64) -> Limits {
        Limits::DEFAULT
            .with_overrides(&[
                ("STREAMS_PER_CONNECTION", per_conn),
                ("STREAMS_PER_ENDPOINT", per_endpoint),
            ])
            .unwrap()
    }

    #[test]
    fn both_caps_apply_and_places_free_when_every_holder_lets_go() {
        let admission = StreamAdmission::new(&limits(2, 3));
        let a = admission.connection();
        let b = admission.connection();
        let a1 = a.try_admit().unwrap();
        let _a2 = a.try_admit().unwrap();
        assert!(a.try_admit().is_none(), "connection cap");
        let _b1 = b.try_admit().unwrap();
        assert!(b.try_admit().is_none(), "endpoint cap");
        assert_eq!(admission.open_streams(), 3);
        let held = a1.clone();
        drop(a1);
        assert!(b.try_admit().is_none(), "still held by the reader");
        drop(held);
        assert!(b.try_admit().is_some());
    }

    #[test]
    fn engine_streams_have_their_own_places() {
        let admission = StreamAdmission::new(&limits(1, 1));
        let a = admission.connection();
        let _app = a.try_admit().unwrap();
        assert!(a.try_admit().is_none());
        let engine: Vec<_> = (0..4).map(|_| a.try_admit_engine().unwrap()).collect();
        assert!(a.try_admit_engine().is_none(), "engine cap");
        assert_eq!(
            admission.open_streams(),
            1,
            "engine streams leave the app's count"
        );
        drop(engine);
        assert!(a.try_admit_engine().is_some());
    }

    #[test]
    fn the_queue_gauge_keeps_its_peak() {
        let admission = StreamAdmission::new(&Limits::DEFAULT);
        admission.add_queued(10);
        admission.add_queued(5);
        admission.sub_queued(12);
        assert_eq!(admission.queued_bytes(), 3);
        assert_eq!(admission.peak_queued_bytes(), 15);
        admission.sub_queued(100);
        assert_eq!(admission.queued_bytes(), 0);
    }
}
