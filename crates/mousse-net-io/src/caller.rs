//! The caller side: dial a paired host with its stored pin, or join a new
//! host with a ticket.
//!
//! - Every connection pins the host in step 1: the stored pin for a paired
//!   host, the ticket's host identity on first contact.
//! - Core's [`CallerGate`] decides what the host may send: nothing on
//!   streams before the host said `AUTHORIZED {live}` (or `PAIRED`).
//! - A "send link" ticket pairs with the 6-digit code the host shows, over
//!   CPace; the owner types it through a [`CodeEntry`].
//! - A [`PeerSession`] per pinned host tracks the current path. Every
//!   switch from one live path to another follows one rule: the new path
//!   stays a candidate until the app reopened its channels on it and called
//!   [`Caller::reopened`]; then it becomes current and the old one closes
//!   with `PATH_REPLACED`. Only a host's first path (none current, also
//!   after the last one closed) is current at once. A dial or join while a
//!   path is current is such a switch.
//! - Renewal: [`Caller::start_renewals`] runs each session's timer. When a
//!   path nears its deadline the caller dials the host again (over the
//!   routes it last used, with a fresh certificate if ours runs out),
//!   retrying on the session's schedule. The new path stays a candidate
//!   until the app reopened its channels on it and called
//!   [`Caller::reopened`]; only then does it become current and the old one
//!   close with `PATH_REPLACED`.
//! - A join keeps one [`JoinerPairing`] across connections. If the
//!   connection drops after this side confirmed the code and before
//!   `PAIRED` arrived, the join reconnects with the same joiner to learn the
//!   outcome before it reports anything.
//! - The joiner believes an "in person" ticket only from the app's own
//!   scanner: the app says how the ticket arrived ([`Arrival`]).
//! - The joiner's flow record (code attempts left, outcome pending) is kept
//!   in [`FlowRecords`] by ticket hash: loaded when a join starts and
//!   written whenever the pairing state machine asks, as a compare-and-swap
//!   that lands before anything that depends on it goes out (wire.md
//!   10.7): the debit before the attempt's first message, the pending mark
//!   before this side's confirmation. Reopening a link or restarting the
//!   app therefore resets nothing, and a crash after the confirmation still
//!   learns the outcome. The mark is cleared once the app has stored the
//!   pin and called [`Caller::pin_stored`].
//! - One join per ticket at a time: a join holds its ticket
//!   ([`FlowRecords::hold`]) from loading the record until the outcome is
//!   settled and the pin stored, so another join of the same link, in this
//!   process or another, cannot clear a pending mark the first still needs.
//!   It is refused at once instead.
//! - A caller that sent a `JOIN_PROOF` and has no answer 10 s later closes
//!   the connection with `NOT_AUTHORIZED` (wire.md 8.2), and the join ends
//!   without reconnecting.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use mousse_net_core::authz::CallerGateState;
use mousse_net_core::authz::{CallerGate, CallerTraffic, Traffic, Verdict};
use mousse_net_core::control::{AuthorizedState, ControlMessage};
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::MuxRole;
use mousse_net_core::pairing::{
    Arrival, CodeExchangeFactory, CpaceExchangeFactory, InvitationKind, JoinerAction, JoinerName,
    JoinerPairing, JoinerRecord, JoinerState, PairedHost, PairingCode, Ticket,
};
use mousse_net_core::session::{CandidatePhase, PeerSession, SessionEvent};
use mousse_net_core::session_cert::CertError;
use mousse_net_core::{ConnectionId, ErrorCode, Millis};
use tokio::sync::mpsc;

use crate::admission::StreamAdmission;
use crate::certs::CertManager;
use crate::clock::Clock;
use crate::conn::{self, CloseReason, Cmd, ConnStatus, Connection, Outbox, Role as ConnRole};
use crate::error::NetError;
use crate::limits::{ms, Limits};
use crate::pipe::{connect_tcp_within, route_uri, Pipe, Route};
use crate::rng::os_rng;
use crate::store::{FlowHold, FlowRecords, MemoryFlowRecords};
use crate::tls::{self, Handshake, TlsPolicy};
use crate::SharedSigner;

/// How pairing ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinOutcome {
    /// The host enrolled this device. Store the pin.
    Paired(PairedHost),
    /// The host grants this device access now. That says nothing about
    /// which invitation the grant came from: it may be this one (its
    /// `PAIRED` was lost), another one, or an earlier pairing.
    AlreadyPaired,
}

/// Where the owner types the code a "send link" host shows.
pub trait CodeEntry: Send {
    /// Ask for the code. `retry` is `Some(attempts left)` after a wrong
    /// code. `None` gives up.
    fn code(&mut self, retry: Option<u8>) -> impl Future<Output = Option<String>> + Send;

    /// [`CodeEntry::code`] with the attempts left also on the first ask:
    /// `retry` says a code was wrong. By default it asks [`CodeEntry::code`].
    fn ask(
        &mut self,
        attempts_left: u8,
        retry: bool,
    ) -> impl Future<Output = Option<String>> + Send {
        self.code(retry.then_some(attempts_left))
    }
}

/// For in-person tickets: there is never a code to type.
pub struct NoCode;

impl CodeEntry for NoCode {
    async fn code(&mut self, _retry: Option<u8>) -> Option<String> {
        None
    }
}

/// A path change the app must act on (see [`Caller::start_renewals`]).
#[derive(Debug)]
pub enum PathEvent {
    /// A renewal brought up `conn` to the host pinned as `pin`: live and
    /// authorized, but not current yet. Reopen the app's channels on it
    /// from their cursors, then call [`Caller::reopened`]. Until then the
    /// old path `from` stays current.
    Reopen {
        /// The host.
        pin: IdentityPublicKey,
        /// The path being replaced.
        from: ConnectionId,
        /// The new path.
        conn: Connection,
    },
    /// A renewal try failed. The session asks again later (after 30 s,
    /// doubling up to 5 min) until the old path's deadline.
    RenewFailed {
        /// The host.
        pin: IdentityPublicKey,
        /// Why.
        error: NetError,
    },
}

#[derive(Default)]
struct Paths {
    sessions: HashMap<IdentityPublicKey, PeerSession>,
    conns: HashMap<ConnectionId, mpsc::UnboundedSender<Cmd>>,
    /// Where each pinned host was last reached, best first.
    routes: HashMap<IdentityPublicKey, Vec<Route>>,
}

impl Paths {
    fn run(&mut self, events: Vec<SessionEvent>) {
        for event in events {
            if let SessionEvent::Close { conn, code } = event {
                if let Some(tx) = self.conns.get(&conn) {
                    let _ = tx.send(Cmd::Close(code));
                }
            }
        }
    }
}

/// The caller side of the session.
pub struct Caller<F: CodeExchangeFactory + Clone = CpaceExchangeFactory> {
    certs: Arc<CertManager>,
    clock: Arc<dyn Clock>,
    policy: TlsPolicy,
    limits: Limits,
    factory: F,
    paths: Arc<Mutex<Paths>>,
    next_conn: AtomicU64,
    records: Arc<dyn FlowRecords>,
    streams: Arc<StreamAdmission>,
    /// Joins that ended paired with their outcome still marked pending,
    /// by ticket hash, until the app says the pin is stored. Each still
    /// holds its ticket.
    settling: Mutex<HashMap<[u8; 32], SharedJoiner<F>>>,
}

fn lock(paths: &Mutex<Paths>) -> MutexGuard<'_, Paths> {
    paths.lock().unwrap_or_else(|e| e.into_inner())
}

/// One join's pairing state and where its flow record is kept.
struct Flow<F: CodeExchangeFactory> {
    pairing: JoinerPairing<F>,
    records: Arc<dyn FlowRecords>,
    /// The last write that failed, reported if the join fails.
    save_failed: Option<String>,
    /// This flow's hold on its ticket. Released as soon as the join is
    /// settled: when it returns with nothing pending, or once the app has
    /// stored the pin ([`Caller::pin_stored`]). The live connection keeps
    /// the flow, but not the hold.
    hold: Option<FlowHold>,
}

impl<F: CodeExchangeFactory> Flow<F> {
    /// Carry out the record writes among `actions`, in order, each a
    /// compare-and-swap (wire.md 10.7). The one place a record is written.
    /// Returns the other actions; what a write held back comes out only
    /// after it landed, and is dropped if it failed (the flow then ends).
    fn run(&mut self, actions: Vec<JoinerAction>) -> Vec<JoinerAction> {
        let mut queue: VecDeque<JoinerAction> = actions.into();
        let mut out = Vec::new();
        while let Some(action) = queue.pop_front() {
            let JoinerAction::Persist { expected, record } = action else {
                out.push(action);
                continue;
            };
            let more = match self.records.swap(expected.as_ref(), &record) {
                Ok(()) => self.pairing.on_persisted(),
                Err(e) => {
                    self.save_failed = Some(e.to_string());
                    self.pairing.on_persist_failed()
                }
            };
            for m in more.into_iter().rev() {
                queue.push_front(m);
            }
        }
        out
    }
}

/// One join's flow, shared by every connection the join uses.
type SharedJoiner<F> = Arc<Mutex<Flow<F>>>;

fn lock_joiner<F: CodeExchangeFactory>(joiner: &Mutex<Flow<F>>) -> MutexGuard<'_, Flow<F>> {
    joiner.lock().unwrap_or_else(|e| e.into_inner())
}

impl Caller<CpaceExchangeFactory> {
    /// A caller that pairs in person or with a send link (CPace).
    /// `limits` is always within the allowed ranges
    /// ([`Limits::with_overrides`] is the only way to change it).
    pub fn new(signer: SharedSigner, clock: Arc<dyn Clock>, limits: Limits) -> Self {
        Self::with_factory(signer, clock, limits, CpaceExchangeFactory)
    }
}

impl<F> Caller<F>
where
    F: CodeExchangeFactory + Clone + Send + 'static,
    F::Exchange: Send,
{
    /// A caller with another code exchange for "send link" tickets.
    pub fn with_factory(
        signer: SharedSigner,
        clock: Arc<dyn Clock>,
        limits: Limits,
        factory: F,
    ) -> Self {
        Self {
            certs: Arc::new(CertManager::with_limits(signer, clock.clone(), &limits)),
            clock,
            policy: TlsPolicy::from_limits(&limits),
            limits,
            factory,
            paths: Arc::new(Mutex::new(Paths::default())),
            next_conn: AtomicU64::new(1),
            records: Arc::new(MemoryFlowRecords::default()),
            streams: StreamAdmission::new(&limits),
            settling: Mutex::new(HashMap::new()),
        }
    }

    /// Keep joiner flow records in `records` (by default they are kept in
    /// memory, for as long as the process runs). An app keeps them in its
    /// endpoint state ([`crate::Endpoint::flow_records`]).
    pub fn use_flow_records(&mut self, records: Arc<dyn FlowRecords>) {
        self.records = records;
    }

    /// Share the stream places of `streams` (by default the caller has its
    /// own, from its limits). A host and a caller of the same endpoint
    /// share one, so its caps count every connection of the endpoint.
    pub fn use_stream_admission(&mut self, streams: Arc<StreamAdmission>) {
        self.streams = streams;
    }

    /// The stream places this caller's connections use.
    pub fn stream_admission(&self) -> Arc<StreamAdmission> {
        self.streams.clone()
    }

    /// The app has durably stored the pin for the host of `ticket`, after a
    /// join with it returned. Clears the join's outcome-pending mark, which
    /// may go only once the result is stored (wire.md 10.7). Until this is
    /// called the mark stays, so opening the ticket again asks the host
    /// again; that is safe, only slower.
    pub fn pin_stored(&self, ticket: &Ticket) -> Result<(), NetError> {
        let flow = self
            .settling
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&ticket.hash());
        let Some(flow) = flow else {
            return Ok(());
        };
        let mut flow = lock_joiner(&flow);
        let actions = flow.pairing.on_pin_stored();
        flow.run(actions);
        // The pin is stored: another join of this ticket can only learn
        // what is already kept, so the ticket is free again, also while
        // this join's connection stays open.
        flow.hold = None;
        match flow.save_failed.take() {
            Some(e) => Err(NetError::Store(format!(
                "the pairing record could not be saved: {e}"
            ))),
            None => Ok(()),
        }
    }

    /// Clear the durable outcome-pending mark kept for `ticket_hash` once
    /// the app has stored what the join learned, whether or not the join
    /// is still in memory (after a restart it is not). Settles the flow in
    /// memory first, as [`Caller::pin_stored`] does, then takes the
    /// ticket's hold and clears the stored mark. A join of the same ticket
    /// running now keeps its hold, and settles its own record.
    pub fn settle_stored(&self, ticket_hash: &[u8; 32]) -> Result<(), NetError> {
        let flow = self
            .settling
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(ticket_hash);
        if let Some(flow) = flow {
            let mut flow = lock_joiner(&flow);
            let actions = flow.pairing.on_pin_stored();
            flow.run(actions);
            flow.hold = None;
            if let Some(e) = flow.save_failed.take() {
                return Err(NetError::Store(format!(
                    "the pairing record could not be saved: {e}"
                )));
            }
        }
        // Must-fail control: only the flow in memory is settled.
        if cfg!(mousse_control = "pin-stored-memory-only") {
            return Ok(());
        }
        let _hold = match self.records.hold(ticket_hash) {
            Ok(hold) => hold,
            // Another join of this ticket holds it: that join settles it.
            Err(NetError::Refused(_)) => return Ok(()),
            Err(e) => return Err(e),
        };
        match self.records.load(ticket_hash)? {
            Some(stored) if stored.outcome_pending => self.records.swap(
                Some(&stored),
                &JoinerRecord {
                    outcome_pending: false,
                    ..stored
                },
            ),
            _ => Ok(()),
        }
    }

    /// The flow record kept for `ticket_hash` (wire.md 10.7), if any.
    pub fn flow_record(&self, ticket_hash: &[u8; 32]) -> Result<Option<JoinerRecord>, NetError> {
        self.records.load(ticket_hash)
    }

    /// The code attempts a flow with nothing stored starts with.
    pub fn attempts_per_flow(&self) -> u8 {
        u8::try_from(self.limits.core().joiner_attempts_per_flow())
            .unwrap_or(u8::MAX)
            .min(mousse_net_core::pairing::JOINER_ATTEMPTS_PER_FLOW)
    }

    /// The time on this caller's clock.
    pub fn now(&self) -> mousse_net_core::UnixTime {
        self.clock.now()
    }

    /// The refusals a join of `ticket` would give before dialling, from
    /// the ticket and its stored flow record: an in-person ticket that did
    /// not come from the in-app scanner, this device's own ticket, a name
    /// that cannot be sent, an expired ticket or no attempts left. A join
    /// with `resume` (a consented one, Phase 1a §5.1) may go past the
    /// ticket's expiry to learn a lost outcome, as the join itself does.
    pub fn check_join(
        &self,
        ticket: &Ticket,
        arrival: Arrival,
        name: &str,
        resume: bool,
    ) -> Result<(), NetError> {
        let mut stored = self.records.load(&ticket.hash())?;
        if resume {
            let core = self.limits.core();
            let fresh = ticket
                .check_fresh_for_joiner_with_skew(self.clock.now(), core.clock_skew_secs())
                .is_ok();
            if !fresh && !stored.is_some_and(|r| r.outcome_pending) {
                // What the join would store before it dials.
                stored = Some(JoinerRecord {
                    ticket_hash: ticket.hash(),
                    attempts_left: stored.map_or(self.attempts_per_flow(), |r| r.attempts_left),
                    outcome_pending: true,
                });
            }
        }
        JoinerPairing::with_limits(
            ticket.clone(),
            arrival,
            self.identity(),
            JoinerName {
                computer: name.to_owned(),
                profile: None,
            },
            self.factory.clone(),
            stored.as_ref(),
            self.clock.now(),
            self.limits.core(),
        )
        .map(|_| ())
        .map_err(NetError::Join)
    }

    /// This device's identity.
    pub fn identity(&self) -> IdentityPublicKey {
        self.certs.identity()
    }

    /// Where to reach the host pinned as `pin` when a path must be
    /// renewed, best first. [`Caller::dial_candidates`] keeps this up to
    /// date; call it after a join or a dial over a pipe of your own.
    pub fn remember_routes(&self, pin: IdentityPublicKey, routes: Vec<Route>) {
        lock(&self.paths).routes.insert(pin, routes);
    }

    /// The app reopened its channels on a renewed path: make it current.
    /// The old path closes with `PATH_REPLACED`.
    pub fn reopened(&self, conn: &Connection) -> Result<(), NetError> {
        let mut paths = lock(&self.paths);
        let session = paths
            .sessions
            .get_mut(conn.peer())
            .ok_or_else(|| NetError::Refused("no session with this host".into()))?;
        let events = session
            .on_reopened(conn.id())
            .map_err(|e| NetError::Refused(format!("not a renewed path: {e:?}")))?;
        paths.run(events);
        Ok(())
    }

    /// Whether `conn` is its host's candidate path, live and waiting for
    /// [`Caller::reopened`]: a renewed path, or one dialled while another
    /// was current.
    pub fn is_reopening(&self, conn: &Connection) -> bool {
        lock(&self.paths)
            .sessions
            .get(conn.peer())
            .and_then(|session| session.candidate())
            .is_some_and(|c| c.conn == conn.id() && c.phase == CandidatePhase::Reopening)
    }

    /// Bring up a new path to `pin` for a renewal: live, not yet current.
    async fn renew(&self, pin: IdentityPublicKey) -> Result<Connection, NetError> {
        let routes = lock(&self.paths)
            .routes
            .get(&pin)
            .cloned()
            .unwrap_or_default();
        self.race(&routes, pin).await.map(|(conn, _)| conn)
    }

    /// A connection that passed step 1 with `pin` becomes the host's
    /// candidate path. Nothing in the session changes before step 1
    /// passed, so tries that fail or lose a race leave no trace.
    fn admit(
        &self,
        pin: IdentityPublicKey,
        handshake: &Handshake,
    ) -> Result<ConnectionId, NetError> {
        let conn = ConnectionId(self.next_conn.fetch_add(1, Ordering::Relaxed));
        let mut paths = lock(&self.paths);
        let session = paths
            .sessions
            .entry(pin)
            .or_insert_with(|| PeerSession::with_limits(pin, self.limits.core()));
        let mut events = session.begin_path(conn);
        let checked = session.on_authenticated(
            conn,
            &handshake.peer,
            handshake.local_window,
            self.clock.now(),
            self.clock.mono(),
        );
        let refused = match checked {
            Ok(more) => {
                events.extend(more);
                None
            }
            // The control build lets a different identity through.
            Err(_) if cfg!(mousse_control = "skip-pin-check") => None,
            Err(e) => Some(NetError::Refused(format!("new path refused: {e:?}"))),
        };
        paths.run(events);
        match refused {
            Some(e) => Err(e),
            None => Ok(conn),
        }
    }

    async fn handshake<P: Pipe>(
        &self,
        pipe: P,
        pin: IdentityPublicKey,
    ) -> Result<(ConnectionId, tokio_rustls::TlsStream<P>, Handshake), NetError> {
        let own = self.certs.current()?;
        let (stream, handshake) =
            tls::connect(pipe, &own, pin, self.clock.clone(), self.policy).await?;
        let conn = self.admit(pin, &handshake)?;
        Ok((conn, stream, handshake))
    }

    fn start<P: Pipe>(
        &self,
        conn: ConnectionId,
        stream: tokio_rustls::TlsStream<P>,
        handshake: Handshake,
        pin: IdentityPublicKey,
        joiner: Option<(SharedJoiner<F>, ControlMessage)>,
    ) -> Connection {
        let (cmd_tx, cmd_rx) = conn::channel();
        lock(&self.paths).conns.insert(conn, cmd_tx.clone());
        let skew = self.limits.core().clock_skew_secs();
        let deadline = handshake
            .local_window
            .deadline_with_skew(skew)
            .min(handshake.peer.window.deadline_with_skew(skew));
        let (joiner, proof) = match joiner {
            Some((j, p)) => (Some(j), Some(p)),
            None => (None, None),
        };
        let role = CallerRole {
            gate: CallerGate::new(),
            joiner,
            proof,
            answer_due: None,
            answer_wait_ms: self.limits.io().proof_answer_wait_ms(),
            clock: self.clock.clone(),
            paths: self.paths.clone(),
            conn,
            pin,
        };
        conn::spawn(
            conn::Start {
                tls: stream,
                side: MuxRole::Caller,
                conn,
                peer: handshake.peer.identity,
                kx_group: handshake.kx_group,
                deadline,
                clock: self.clock.clone(),
                limits: self.limits,
                streams: self.streams.clone(),
            },
            Box::new(role),
            cmd_tx,
            cmd_rx,
        )
    }

    /// Make a host's first path current at once. With a path current
    /// already, `conn` stays the candidate, as a renewed path does: the app
    /// moves its channels and calls [`Caller::reopened`].
    fn promote_first(&self, conn: &Connection) {
        let mut paths = lock(&self.paths);
        if let Some(session) = paths.sessions.get_mut(conn.peer()) {
            if session.current().is_some() {
                return;
            }
            if let Ok(events) = session.on_reopened(conn.id()) {
                paths.run(events);
            }
        }
    }

    /// Step 1 with `pin`, then `HELLO`. Returns at once; the host's step 2
    /// answer arrives later (see [`Connection::settled`]).
    pub async fn connect<P: Pipe>(
        &self,
        pipe: P,
        pin: IdentityPublicKey,
    ) -> Result<Connection, NetError> {
        let (conn, stream, handshake) = self.handshake(pipe, pin).await?;
        Ok(self.start(conn, stream, handshake, pin, None))
    }

    /// Connect to a paired host and wait until it authorizes the connection.
    /// A host without a live grant for us closes it (`NOT_AUTHORIZED`,
    /// after its join-proof wait).
    ///
    /// The first path to the host is current at once. If one is current
    /// already, the new connection is live but only a candidate: the old
    /// path stays current until the app reopened its channels on the new
    /// one and called [`Caller::reopened`]. A later dial before that
    /// replaces the candidate.
    pub async fn dial<P: Pipe>(
        &self,
        pipe: P,
        pin: IdentityPublicKey,
    ) -> Result<Connection, NetError> {
        let conn = self.connect(pipe, pin).await?;
        match conn.settled(false).await {
            status if status.is_live() => {
                self.promote_first(&conn);
                Ok(conn)
            }
            ConnStatus::Closed(reason) => Err(NetError::Closed(reason)),
            other => Err(NetError::Refused(format!("unexpected state {other:?}"))),
        }
    }

    /// Dial the host pinned as `pin` at whichever of `routes` answers as
    /// that host first, over TCP (Phase 1a §6).
    ///
    /// Up to [`IoLimits::dial_parallel`](crate::limits::IoLimits::dial_parallel)
    /// candidates are tried at once, in order, each given
    /// [`IoLimits::dial_timeout_ms`](crate::limits::IoLimits::dial_timeout_ms)
    /// to connect and pass step 1, so a slow or silent address never holds
    /// up the rest.
    ///
    /// Any step 1 failure on a candidate means "not this host here": a
    /// candidate whose identity is not the pin is another endpoint (for
    /// example another profile on the same computer, or a device that took
    /// the address), and it is skipped without a warning and never
    /// re-pinned; the same goes for any other certificate failure. Only when
    /// no candidate passed is a certificate failure reported, the window
    /// one (a clock problem) first. The first candidate to pass step 1 is
    /// the pinned host: the other tries end, and if the host then refuses
    /// (for example `NOT_AUTHORIZED`) the refusal is returned and no
    /// further candidate is tried.
    pub async fn dial_candidates(
        &self,
        routes: &[Route],
        pin: IdentityPublicKey,
    ) -> Result<(Connection, Route), NetError> {
        let (conn, route) = self.race(routes, pin).await?;
        self.promote_first(&conn);
        let mut order = vec![route.clone()];
        order.extend(routes.iter().filter(|r| **r != route).cloned());
        self.remember_routes(pin, order);
        Ok((conn, route))
    }

    /// [`Caller::dial_candidates`] without making the path current: the
    /// live connection and the route it used.
    async fn race(
        &self,
        routes: &[Route],
        pin: IdentityPublicKey,
    ) -> Result<(Connection, Route), NetError> {
        let io = self.limits.io();
        let parallel = usize::try_from(io.dial_parallel()).unwrap_or(1).max(1);
        let within = ms(io.dial_timeout_ms());
        let connect_within = ms(io.connect_timeout_ms()).min(within);
        let own = self.certs.current()?;
        let mut queue = routes.iter().cloned();
        let mut tries = tokio::task::JoinSet::new();
        let mut last = None;
        let mut step1 = Step1Failures::default();
        loop {
            while tries.len() < parallel {
                let Some(route) = queue.next() else {
                    break;
                };
                let (own, clock, policy) = (own.clone(), self.clock.clone(), self.policy);
                tries.spawn(async move {
                    let attempt = async {
                        let pipe = connect_tcp_within(&route, connect_within).await?;
                        tls::connect(pipe, &own, pin, clock, policy).await
                    };
                    let result = tokio::time::timeout(within, attempt)
                        .await
                        .unwrap_or(Err(NetError::Timeout("candidate address")));
                    (route, result)
                });
            }
            let Some(joined) = tries.join_next().await else {
                break;
            };
            // A try that panicked is a candidate that failed.
            let Ok((route, result)) = joined else {
                continue;
            };
            match result {
                Ok((stream, handshake)) => {
                    // Step 1 passed: this is the pinned host. The other
                    // tries end here.
                    tries.abort_all();
                    let id = self.admit(pin, &handshake)?;
                    let conn = self.start(id, stream, handshake, pin, None);
                    return match conn.settled(false).await {
                        status if status.is_live() => Ok((conn, route)),
                        ConnStatus::Closed(reason) => Err(NetError::Closed(reason)),
                        other => Err(NetError::Refused(format!("unexpected state {other:?}"))),
                    };
                }
                // The control build stops at the first other identity.
                Err(NetError::PeerCertificate(CertError::PinMismatch))
                    if cfg!(mousse_control = "stop-on-mismatch") =>
                {
                    return Err(NetError::PeerCertificate(CertError::PinMismatch));
                }
                Err(NetError::PeerCertificate(e)) => step1.note(e),
                Err(e) => last = Some(e),
            }
        }
        if let Some(e) = step1.report() {
            return Err(e);
        }
        Err(last.unwrap_or_else(|| {
            NetError::Refused(format!(
                "no candidate answered as this host ({})",
                routes.iter().map(route_uri).collect::<Vec<_>>().join(", ")
            ))
        }))
    }

    /// Pair with the host in an in-person `ticket` over `pipe`. Waits for
    /// the host owner's approval. `arrival` says how the ticket reached
    /// this device: an in-person ticket is accepted only from
    /// [`Arrival::InAppScan`].
    pub async fn join<P: Pipe>(
        &self,
        pipe: P,
        ticket: &Ticket,
        arrival: Arrival,
        name: &str,
    ) -> Result<(Connection, JoinOutcome), NetError> {
        self.join_with_code(pipe, ticket, arrival, name, &mut NoCode)
            .await
    }

    /// Pair with the host in `ticket` over `pipe`. In person, wait for the
    /// host owner's approval. With a send link, ask `codes` for the code the
    /// host shows, and again after each wrong code until the attempts run
    /// out. Treats the host as never pinned and cannot reconnect; see
    /// [`Caller::join_with_redial`].
    pub async fn join_with_code<P: Pipe, C: CodeEntry>(
        &self,
        pipe: P,
        ticket: &Ticket,
        arrival: Arrival,
        name: &str,
        codes: &mut C,
    ) -> Result<(Connection, JoinOutcome), NetError> {
        let no_redial = || {
            std::future::ready(Err::<P, _>(NetError::Refused(
                "no address to reconnect to".into(),
            )))
        };
        self.join_with_redial(pipe, ticket, arrival, name, codes, false, no_redial)
            .await
    }

    /// [`Caller::join_with_code`], plus:
    /// - `host_pinned`: this device already holds a pin for the ticket's
    ///   host (paired before). Only then may a "send link" join end as
    ///   "already paired" without a code exchange.
    /// - `redial`: opens a new pipe to the host. If the connection drops
    ///   after this side confirmed the code and before `PAIRED` arrived,
    ///   the join reconnects through it (a few times, with short waits) and
    ///   keeps the same pairing state, so the host's answer settles the
    ///   outcome: `PAIRED` means this invitation enrolled the device, and
    ///   `AUTHORIZED {live}` means it has access that this invitation did
    ///   not give (its role is not in effect), reported as
    ///   [`JoinOutcome::AlreadyPaired`].
    ///
    /// After storing the pin for a successful join, call
    /// [`Caller::pin_stored`].
    ///
    /// A refusal before dialing (an in-person ticket that did not come from
    /// the in-app scanner, this device's own ticket, an expired ticket, no
    /// attempts left) is [`NetError::Join`]; its `code()` is the error the
    /// app reports.
    #[allow(clippy::too_many_arguments)]
    pub async fn join_with_redial<P, C, D, Fut>(
        &self,
        pipe: P,
        ticket: &Ticket,
        arrival: Arrival,
        name: &str,
        codes: &mut C,
        host_pinned: bool,
        redial: D,
    ) -> Result<(Connection, JoinOutcome), NetError>
    where
        P: Pipe,
        C: CodeEntry,
        D: FnMut() -> Fut,
        Fut: Future<Output = Result<P, NetError>>,
    {
        self.join_flow(
            pipe,
            ticket,
            arrival,
            name,
            codes,
            host_pinned,
            false,
            redial,
        )
        .await
    }

    /// [`Caller::join_with_redial`] for a join the app consented to and
    /// recorded before it started (Phase 1a §5.1): the ticket's host is
    /// trusted as pinned, and a join that may have lost its `PAIRED` can
    /// learn the outcome. If the ticket is past its joiner-side expiry, the
    /// flow is marked "outcome pending" (stored like any pending mark)
    /// before it dials, so it reconnects with the same ticket as wire.md
    /// 10.6 rule 7 says: `PAIRED` means this invitation enrolled the
    /// device, `AUTHORIZED {live}` that it is already paired, and a host
    /// with no grant for it ends the flow.
    pub async fn join_pinned_with_redial<P, C, D, Fut>(
        &self,
        pipe: P,
        ticket: &Ticket,
        arrival: Arrival,
        name: &str,
        codes: &mut C,
        redial: D,
    ) -> Result<(Connection, JoinOutcome), NetError>
    where
        P: Pipe,
        C: CodeEntry,
        D: FnMut() -> Fut,
        Fut: Future<Output = Result<P, NetError>>,
    {
        self.join_flow(pipe, ticket, arrival, name, codes, true, true, redial)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn join_flow<P, C, D, Fut>(
        &self,
        pipe: P,
        ticket: &Ticket,
        arrival: Arrival,
        name: &str,
        codes: &mut C,
        host_pinned: bool,
        resume: bool,
        redial: D,
    ) -> Result<(Connection, JoinOutcome), NetError>
    where
        P: Pipe,
        C: CodeEntry,
        D: FnMut() -> Fut,
        Fut: Future<Output = Result<P, NetError>>,
    {
        // A join of this ticket that ended paired and was never settled
        // gives way: its pending mark stays stored, and this join learns
        // the outcome again.
        let unsettled = self
            .settling
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&ticket.hash());
        if let Some(unsettled) = unsettled {
            lock_joiner(&unsettled).hold = None;
        }
        let hold = self.records.hold(&ticket.hash())?;
        let mut stored = self.records.load(&ticket.hash())?;
        if resume {
            stored = self.mark_outcome_pending_if_expired(ticket, stored)?;
        }
        let mut pairing = JoinerPairing::with_limits(
            ticket.clone(),
            arrival,
            self.identity(),
            // The app composes the name for the ticket's kind (wire.md
            // 10.3), so it is passed through as is.
            JoinerName {
                computer: name.to_owned(),
                profile: None,
            },
            self.factory.clone(),
            stored.as_ref(),
            self.clock.now(),
            self.limits.core(),
        )
        .map_err(NetError::Join)?;
        pairing.set_host_pinned(host_pinned);
        let joiner: SharedJoiner<F> = Arc::new(Mutex::new(Flow {
            pairing,
            records: self.records.clone(),
            save_failed: None,
            hold: Some(hold),
        }));
        let result = self
            .join_redialling(pipe, ticket, &joiner, codes, redial)
            .await;
        let mut flow = lock_joiner(&joiner);
        if result.is_ok() && flow.pairing.outcome_pending() {
            // Held until the app stores the pin.
            self.settling
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(ticket.hash(), joiner.clone());
        } else {
            // Nothing for this join to settle: a failed join left its
            // record as the next one needs it.
            flow.hold = None;
        }
        match (result, flow.save_failed.take()) {
            (Err(_), Some(e)) => Err(NetError::Store(format!(
                "the pairing record could not be saved: {e}"
            ))),
            (result, _) => result,
        }
    }

    /// A consented join of a ticket past its joiner-side expiry can only
    /// be learning whether a lost `PAIRED` enrolled it: store that as a
    /// pending outcome, so the flow may dial (wire.md 10.6 rule 7).
    fn mark_outcome_pending_if_expired(
        &self,
        ticket: &Ticket,
        stored: Option<JoinerRecord>,
    ) -> Result<Option<JoinerRecord>, NetError> {
        let core = self.limits.core();
        let fresh = ticket
            .check_fresh_for_joiner_with_skew(self.clock.now(), core.clock_skew_secs())
            .is_ok();
        if fresh || stored.is_some_and(|r| r.outcome_pending) {
            return Ok(stored);
        }
        let attempts = u8::try_from(core.joiner_attempts_per_flow()).unwrap_or(u8::MAX);
        let record = JoinerRecord {
            ticket_hash: ticket.hash(),
            attempts_left: stored.map_or(attempts, |r| r.attempts_left),
            outcome_pending: true,
        };
        self.records.swap(stored.as_ref(), &record)?;
        Ok(Some(record))
    }

    async fn join_redialling<P, C, D, Fut>(
        &self,
        pipe: P,
        ticket: &Ticket,
        joiner: &SharedJoiner<F>,
        codes: &mut C,
        mut redial: D,
    ) -> Result<(Connection, JoinOutcome), NetError>
    where
        P: Pipe,
        C: CodeEntry,
        D: FnMut() -> Fut,
        Fut: Future<Output = Result<P, NetError>>,
    {
        let mut result = self.join_once(pipe, ticket, joiner, codes).await;
        let mut retries = self.limits.outcome_retry_waits().into_iter();
        // Reconnect only while the outcome is unknown. A refusal the host
        // gave (or the joiner reached) on a reconnect is the answer: the
        // flow has failed, and that refusal is what the join reports.
        while result.is_err() && lock_joiner(joiner).pairing.outcome_pending() {
            if matches!(lock_joiner(joiner).pairing.state(), JoinerState::Failed(_)) {
                break;
            }
            let Some(wait) = retries.next() else {
                // A step 1 failure stays one, so the caller can try another
                // address of the host.
                if let Err(e) = result {
                    if e.is_step1() {
                        return Err(e);
                    }
                }
                return Err(NetError::Refused(
                    "the connection dropped while the host was enrolling this device, \
                     and reconnecting did not tell whether it did"
                        .into(),
                ));
            };
            tokio::time::sleep(wait).await;
            result = match redial().await {
                Ok(pipe) => self.join_once(pipe, ticket, joiner, codes).await,
                Err(e) => Err(e),
            };
        }
        result
    }

    /// One connection of a join.
    async fn join_once<P: Pipe, C: CodeEntry>(
        &self,
        pipe: P,
        ticket: &Ticket,
        joiner: &SharedJoiner<F>,
        codes: &mut C,
    ) -> Result<(Connection, JoinOutcome), NetError> {
        let pin = ticket.host_identity;
        let (conn, stream, handshake) = self.handshake(pipe, pin).await?;
        let proof = {
            let mut flow = lock_joiner(joiner);
            flow.pairing
                .on_connected(handshake.exporters, self.clock.now())
        };
        let proof = match proof {
            Ok(proof) => proof,
            Err(e) => {
                lock(&self.paths)
                    .sessions
                    .entry(pin)
                    .or_insert_with(|| PeerSession::with_limits(pin, self.limits.core()))
                    .on_path_closed(conn);
                return Err(NetError::Join(e));
            }
        };
        let connection = self.start(conn, stream, handshake, pin, Some((joiner.clone(), proof)));
        let mut status = connection.settled(true).await;
        loop {
            match status {
                ConnStatus::CodeNeeded {
                    attempts_left,
                    retry,
                } => {
                    let asked = status.clone();
                    let Some(typed) = codes.ask(attempts_left, retry).await else {
                        connection.close(ErrorCode::Cancelled);
                        return Err(NetError::Refused("pairing cancelled".into()));
                    };
                    match PairingCode::parse(typed.trim()) {
                        Some(code) => {
                            connection.submit_code(code)?;
                            status = connection.next_status(&asked).await;
                        }
                        // Not six digits: ask again without using an attempt.
                        None => status = asked,
                    }
                }
                ConnStatus::Paired(host) => {
                    self.promote_first(&connection);
                    return Ok((connection, JoinOutcome::Paired(host)));
                }
                ConnStatus::AlreadyPaired | ConnStatus::Live => {
                    self.promote_first(&connection);
                    return Ok((connection, JoinOutcome::AlreadyPaired));
                }
                ConnStatus::Closed(reason) => return Err(NetError::Closed(reason)),
                other => {
                    return Err(NetError::Refused(format!("unexpected state {other:?}")));
                }
            }
        }
    }
}

impl<F> Caller<F>
where
    F: CodeExchangeFactory + Clone + Send + Sync + 'static,
    F::Exchange: Send,
{
    /// Run every session's timer, once a second, for as long as the caller
    /// and the returned receiver live: renew paths before their deadline
    /// and close paths past it. Must be called inside a tokio runtime.
    pub fn start_renewals(self: &Arc<Self>) -> mpsc::UnboundedReceiver<PathEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(renewal_ticker(Arc::downgrade(self), tx));
        rx
    }
}

async fn renewal_ticker<F>(caller: Weak<Caller<F>>, tx: mpsc::UnboundedSender<PathEvent>)
where
    F: CodeExchangeFactory + Clone + Send + Sync + 'static,
    F::Exchange: Send,
{
    let Some(recheck) = caller
        .upgrade()
        .map(|caller| ms(caller.limits.io().clock_recheck_ms()))
    else {
        return;
    };
    let mut interval = tokio::time::interval(recheck);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let Some(caller) = caller.upgrade() else {
            return;
        };
        if tx.is_closed() {
            return;
        }
        let now = caller.clock.now();
        let mono = caller.clock.mono();
        let due: Vec<(IdentityPublicKey, ConnectionId)> = {
            let mut paths = lock(&caller.paths);
            let mut due = Vec::new();
            let mut other = Vec::new();
            for (pin, session) in paths.sessions.iter_mut() {
                for event in session.tick(now, mono) {
                    match event {
                        SessionEvent::RenewDue { conn } => due.push((*pin, conn)),
                        event => other.push(event),
                    }
                }
            }
            paths.run(other);
            due
        };
        for (pin, from) in due {
            let (caller, tx) = (caller.clone(), tx.clone());
            tokio::spawn(async move {
                let event = match caller.renew(pin).await {
                    Ok(conn) => PathEvent::Reopen { pin, from, conn },
                    Err(error) => PathEvent::RenewFailed { pin, error },
                };
                // Nobody takes paths any more: close the new one rather than
                // leave it a candidate no one will reopen.
                if let Err(mpsc::error::SendError(PathEvent::Reopen { conn, .. })) = tx.send(event)
                {
                    conn.close(ErrorCode::NoError);
                }
            });
        }
    }
}

/// Step 1 failures on candidate addresses, reported only when no candidate
/// passed (wire.md 5.4). Note each one and try the next address.
#[derive(Clone, Copy, Debug, Default)]
pub struct Step1Failures {
    window: Option<CertError>,
    other: Option<CertError>,
}

impl Step1Failures {
    /// A candidate failed step 1 with `e`.
    pub fn note(&mut self, e: CertError) {
        match e {
            CertError::OutsideWindow => self.window = Some(e),
            e => self.other = Some(e),
        }
    }

    /// The failure to show: the window one (the clock message) first. A
    /// pin mismatch alone is no failure of this host, so it is not shown.
    pub fn report(&self) -> Option<NetError> {
        self.window
            .or(self.other.filter(|e| *e != CertError::PinMismatch))
            .map(NetError::PeerCertificate)
    }
}

struct CallerRole<F: CodeExchangeFactory> {
    gate: CallerGate,
    joiner: Option<SharedJoiner<F>>,
    proof: Option<ControlMessage>,
    /// When the answer to our `JOIN_PROOF` is due, once it is sent.
    answer_due: Option<Millis>,
    /// How long the answer may take
    /// ([`IoLimits::proof_answer_wait_ms`](crate::limits::IoLimits::proof_answer_wait_ms)).
    answer_wait_ms: u64,
    clock: Arc<dyn Clock>,
    paths: Arc<Mutex<Paths>>,
    conn: ConnectionId,
    pin: IdentityPublicKey,
}

impl<F: CodeExchangeFactory> CallerRole<F> {
    /// Our `JOIN_PROOF` went out and the host has not answered it: no
    /// `AUTHORIZED` yet, or only step 2's `live` notice.
    fn awaiting_answer(&self) -> bool {
        matches!(
            self.gate.state(),
            CallerGateState::AwaitingAuthorization | CallerGateState::AwaitingProofAnswer
        )
    }

    fn joiner_actions(&mut self, actions: Vec<JoinerAction>, out: &mut Outbox) {
        for action in actions {
            match action {
                JoinerAction::Send(message) => out.control.push(message),
                // `Flow::run` carries out every write first.
                JoinerAction::Persist { .. } => {}
                JoinerAction::Paired(host) => {
                    self.gate.promote();
                    out.status = Some(ConnStatus::Paired(host));
                }
                JoinerAction::AlreadyPaired => out.status = Some(ConnStatus::AlreadyPaired),
                JoinerAction::CodeRejected { attempts_left } => {
                    out.status = Some(ConnStatus::CodeNeeded {
                        attempts_left,
                        retry: true,
                    });
                }
                JoinerAction::Failed(code) => {
                    self.gate.close(code);
                    out.close = Some(code);
                }
            }
        }
    }
}

impl<F> ConnRole for CallerRole<F>
where
    F: CodeExchangeFactory + Send + 'static,
    F::Exchange: Send,
{
    fn on_start(&mut self, out: &mut Outbox) {
        if let Some(proof) = self.proof.take() {
            out.control.push(proof);
            self.gate.sent_join_proof();
            self.answer_due = Some(self.clock.mono().plus(self.answer_wait_ms));
        }
    }

    fn wake_at(&self) -> Option<Millis> {
        self.answer_due.filter(|_| self.awaiting_answer())
    }

    fn on_wake(&mut self, mono: Millis, out: &mut Outbox) {
        if self.awaiting_answer() && self.answer_due.is_some_and(|due| mono >= due) {
            // The flow ends here, also while it learns a pending outcome:
            // the join does not reconnect (wire.md 10.6 rule 7).
            if let Some(joiner) = self.joiner.clone() {
                let mut flow = lock_joiner(&joiner);
                let actions = flow.pairing.on_proof_timeout();
                let actions = flow.run(actions);
                drop(flow);
                self.joiner_actions(actions, out);
            }
            self.gate.close(ErrorCode::NotAuthorized);
            out.close = Some(ErrorCode::NotAuthorized);
        }
    }

    fn check(&mut self, traffic: Traffic, message: Option<&ControlMessage>) -> Verdict {
        let traffic = match (traffic, message) {
            (_, Some(message)) => CallerTraffic::of(message),
            (Traffic::Keepalive, None) => CallerTraffic::Keepalive,
            (Traffic::GoAway, None) => CallerTraffic::GoAway,
            (_, None) => CallerTraffic::Stream,
        };
        self.gate.check(traffic)
    }

    fn on_control(&mut self, message: ControlMessage, out: &mut Outbox) {
        // The gate already let this through, and moved on `AUTHORIZED`.
        let Some(joiner) = self.joiner.clone() else {
            match message {
                ControlMessage::Authorized {
                    state: AuthorizedState::Live,
                } => out.status = Some(ConnStatus::Live),
                // We sent no join proof, so there is nothing to pair.
                _ => {
                    self.gate.close(ErrorCode::ProtocolError);
                    out.close = Some(ErrorCode::ProtocolError);
                }
            }
            return;
        };
        let mut flow = lock_joiner(&joiner);
        let joiner = &mut flow.pairing;
        let actions = match message {
            ControlMessage::Authorized { state } => {
                let actions = joiner.on_authorized(state);
                if state == AuthorizedState::JoinOnly {
                    out.status = Some(match joiner.ticket().kind {
                        InvitationKind::InPerson => ConnStatus::JoinOnly,
                        InvitationKind::SendLink => ConnStatus::CodeNeeded {
                            attempts_left: joiner.attempts_left(),
                            retry: false,
                        },
                    });
                }
                actions
            }
            ControlMessage::Paired { host_name, role } => joiner.on_paired(host_name, role),
            ControlMessage::CodeExchange { attempt, payload } => {
                joiner.on_code_exchange(attempt, &payload)
            }
            ControlMessage::CodeAbort { attempt, .. } => joiner.on_code_abort(attempt),
            _ => vec![JoinerAction::Failed(ErrorCode::ProtocolError)],
        };
        // Writes land before what they hold; a failed one ends the flow.
        let actions = flow.run(actions);
        drop(flow);
        self.joiner_actions(actions, out);
    }

    fn on_code(&mut self, code: PairingCode, out: &mut Outbox) {
        let actions = match &self.joiner {
            Some(joiner) => {
                let mut flow = lock_joiner(joiner);
                match flow.pairing.submit_code(&code, &mut os_rng()) {
                    // The debit is saved before the attempt's first message
                    // goes out; without that save the message never does.
                    Ok(actions) => flow.run(actions),
                    Err(e) => vec![JoinerAction::Failed(
                        e.code().unwrap_or(ErrorCode::ProtocolError),
                    )],
                }
            }
            None => vec![JoinerAction::Failed(ErrorCode::ProtocolError)],
        };
        self.joiner_actions(actions, out);
    }

    fn may_open(&self) -> bool {
        self.gate.is_live()
    }

    fn on_closed(&mut self, reason: &CloseReason) {
        if let Some(joiner) = &self.joiner {
            let mut flow = lock_joiner(joiner);
            let actions = flow.pairing.on_closed(reason.code());
            flow.run(actions);
        }
        self.gate.close(reason.code().unwrap_or(ErrorCode::NoError));
        let mut paths = lock(&self.paths);
        paths.conns.remove(&self.conn);
        if let Some(session) = paths.sessions.get_mut(&self.pin) {
            session.on_path_closed(self.conn);
        }
    }
}
