//! Pair with IP, the joiner side (wire.md 10.9, "Joiner"): the I/O around
//! [`DirectJoinerPairing`].
//!
//! - A Connect dials the typed address with no pin
//!   ([`tls::connect_unpinned`]); the connection is pairing only (8.2) from
//!   the start. A recovery is dialled pinned to the stored host key.
//! - The joiner waits for the host's `HELLO`, then sends `JOIN_DIRECT`, and
//!   waits up to the proof answer wait (10 s, 8.2) for the answer.
//! - The typed lookup's hold is taken before the records are loaded and
//!   given back after the flow's last write ([`DirectRecords::hold`]).
//!   Every write is a compare and swap, durable before what waits for it
//!   goes out.
//! - The host's pin is stored ([`DirectPins`]) only after the host's
//!   confirmation verified and `PAIRED` arrived; then the gate goes live.
//! - A kept pending record is recovered with backoff while the flow runs,
//!   and at startup ([`Caller::resume_direct`]).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use mousse_net_core::authz::{CallerGate, CallerTraffic, Traffic, Verdict};
use mousse_net_core::control::ControlMessage;
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::MuxRole;
use mousse_net_core::pairing::{
    CodeExchangeFactory, DirectAddress, DirectEnd, DirectJoinError, DirectJoinerAction,
    DirectJoinerPairing, DirectJoinerState, DirectLookup, DirectPaired, EXPORTER_LEN,
};
use mousse_net_core::{ConnectionId, ErrorCode, Millis};
use tokio::sync::{mpsc, watch};

use super::{lock, Caller, Paths};
use crate::clock::Clock;
use crate::conn::{self, CloseReason, Cmd, ConnStatus, Connection, Outbox, Role as ConnRole};
use crate::direct_records::DirectRecords;
use crate::error::NetError;
use crate::limits::ms;
use crate::pipe::connect_addr;
use crate::rng::os_rng;
use crate::store::FlowHold;
use crate::tls::{self, DeniedCheck, UnpinnedRefusal};

/// Where a joiner stores what a Pair with IP pairing gives it.
pub trait DirectPins: Send + Sync {
    /// Store, durably and before returning, the host's pin, the typed
    /// address as an owner route and the completion record keyed by the
    /// invitation. Called only after the host's confirmation verified and
    /// its `PAIRED` arrived. An error ends the flow: the pending record
    /// stays, and a later recovery learns the outcome again.
    fn store(&self, paired: &DirectPaired) -> Result<(), NetError>;
}

/// What a Pair with IP join uses on this device.
#[derive(Clone)]
pub struct DirectSetup {
    /// The ledger, the pending records and the lookup holds.
    pub records: Arc<dyn DirectRecords>,
    /// Where the pairing is stored.
    pub pins: Arc<dyn DirectPins>,
    /// Identities this profile denied: an unpinned dial refuses them
    /// before this device's certificate goes out.
    pub denied: DeniedCheck,
}

/// What a Pair with IP join tells its UI, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectEvent {
    /// The code passed: show "Waiting for Allow".
    CodePassed,
    /// The host allowed this device; its pin is stored.
    Paired(DirectPaired),
    /// The connection ended with the outcome unknown; the pending record
    /// is kept and recovered later.
    Away,
    /// The flow ended.
    Ended(DirectEnd),
}

/// How a Pair with IP join ended.
pub struct DirectJoined {
    /// The flow's end.
    pub end: DirectEnd,
    /// The live connection when it ended paired. Its first stream commits
    /// the host's provisional grant (wire.md 8.1).
    pub connection: Option<Connection>,
}

impl std::fmt::Debug for DirectJoined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectJoined")
            .field("end", &self.end)
            .field("connection", &self.connection.as_ref().map(|c| c.id()))
            .finish()
    }
}

/// A running Pair with IP join.
pub struct DirectJoin {
    events: mpsc::UnboundedReceiver<DirectEvent>,
    cancel: Box<dyn Fn() -> Result<(), DirectJoinError> + Send + Sync>,
    stop: Box<dyn Fn() + Send + Sync>,
    task: tokio::task::JoinHandle<Result<DirectJoined, NetError>>,
}

impl DirectJoin {
    /// The next event, or `None` once the flow has ended and every event
    /// was read.
    pub async fn event(&mut self) -> Option<DirectEvent> {
        self.events.recv().await
    }

    /// The person cancelled (wire.md 10.9): before the code passed this
    /// ends the flow; after, the pending record is marked cancelled first,
    /// and the cancel reaches the host now (connected) or with the next
    /// recovery (away).
    pub fn cancel(&self) -> Result<(), DirectJoinError> {
        (self.cancel)()
    }

    /// Wait for the flow to end.
    pub async fn finish(self) -> Result<DirectJoined, NetError> {
        self.task
            .await
            .unwrap_or_else(|e| Err(NetError::Refused(format!("the join stopped: {e}"))))
    }

    /// Stop the flow where it is, as when the app quits: its connection
    /// closes, its hold goes, and what it stored stays for the next start
    /// ([`Caller::resume_direct`]).
    pub fn stop(self) {
        self.task.abort();
        (self.stop)();
    }
}

/// One flow, shared by its driver task, its connection's role and the
/// handle's cancel.
struct DirectFlow<F: CodeExchangeFactory> {
    pairing: DirectJoinerPairing<F>,
    setup: DirectSetup,
    hold: Option<FlowHold>,
    events: mpsc::UnboundedSender<DirectEvent>,
    state: watch::Sender<DirectJoinerState>,
    /// The live connection's commands, while one is up.
    conn: Option<mpsc::UnboundedSender<Cmd>>,
    /// A store failure that ended the flow.
    failed: Option<NetError>,
    clock: Arc<dyn Clock>,
}

type SharedDirect<F> = Arc<Mutex<DirectFlow<F>>>;

fn lock_flow<F: CodeExchangeFactory>(flow: &Mutex<DirectFlow<F>>) -> MutexGuard<'_, DirectFlow<F>> {
    flow.lock().unwrap_or_else(|e| e.into_inner())
}

/// What a flow asks of its connection.
enum Wire {
    Send(ControlMessage),
    Close(ErrorCode),
    /// The pin is stored: the connection's gate goes live.
    Live,
}

impl<F: CodeExchangeFactory> DirectFlow<F> {
    /// Carry out `actions` in order: the hold, the loads, every write (each
    /// a compare and swap, acknowledged before what waits for it is
    /// released) and the pin; report the UI's events. Returns what the
    /// connection must do.
    fn run(&mut self, actions: Vec<DirectJoinerAction>) -> Vec<Wire> {
        let mut queue: std::collections::VecDeque<DirectJoinerAction> = actions.into();
        let mut out = Vec::new();
        while let Some(action) = queue.pop_front() {
            let more = match action {
                DirectJoinerAction::AcquireHold(lookup) => self.acquire(&lookup),
                DirectJoinerAction::ReleaseHold(_) => {
                    self.hold = None;
                    Vec::new()
                }
                DirectJoinerAction::PersistLedger { expected, record } => {
                    match self.setup.records.swap_ledger(expected.as_ref(), &record) {
                        Ok(()) => self.pairing.on_persisted(),
                        Err(_) => self.pairing.on_persist_failed(),
                    }
                }
                DirectJoinerAction::PersistPending { expected, record } => {
                    let lookup = self.pairing.lookup().clone();
                    let address = self.pairing.address();
                    match self.setup.records.swap_pending(
                        &lookup,
                        &address,
                        expected.as_ref(),
                        record.as_ref(),
                    ) {
                        Ok(()) => self.pairing.on_persisted(),
                        Err(_) => self.pairing.on_persist_failed(),
                    }
                }
                DirectJoinerAction::Paired(paired) => match self.setup.pins.store(&paired) {
                    Ok(()) => {
                        let _ = self.events.send(DirectEvent::Paired(paired));
                        out.push(Wire::Live);
                        self.pairing.on_pin_stored()
                    }
                    Err(_) => self.pairing.on_persist_failed(),
                },
                DirectJoinerAction::Send(message) => {
                    out.push(Wire::Send(message));
                    Vec::new()
                }
                DirectJoinerAction::Close(code) => {
                    out.push(Wire::Close(code));
                    Vec::new()
                }
                DirectJoinerAction::CodePassed => {
                    let _ = self.events.send(DirectEvent::CodePassed);
                    Vec::new()
                }
                DirectJoinerAction::Away => {
                    let _ = self.events.send(DirectEvent::Away);
                    Vec::new()
                }
                DirectJoinerAction::Ended(end) => {
                    let _ = self.events.send(DirectEvent::Ended(end));
                    Vec::new()
                }
            };
            for m in more.into_iter().rev() {
                queue.push_front(m);
            }
        }
        self.state.send_replace(self.pairing.state());
        out
    }

    /// The hold, then the records loaded under it.
    fn acquire(&mut self, lookup: &DirectLookup) -> Vec<DirectJoinerAction> {
        match self.setup.records.hold(lookup) {
            Ok(Some(hold)) => match self.setup.records.load(lookup) {
                Ok((ledger, pending)) => {
                    self.hold = Some(hold);
                    let now = self.clock.now();
                    self.pairing.on_records(ledger.as_ref(), &pending, now)
                }
                // A record that cannot be read never reads as "none": the
                // flow stops here, its hold given back.
                Err(e) => {
                    self.failed = Some(e);
                    Vec::new()
                }
            },
            Ok(None) => self.pairing.on_hold_refused(),
            Err(e) => {
                self.failed = Some(e);
                Vec::new()
            }
        }
    }

    /// Hand `wire` to the live connection (a cancel from the handle).
    fn to_connection(&self, wire: Vec<Wire>) {
        let Some(tx) = &self.conn else {
            return;
        };
        for w in wire {
            match w {
                Wire::Send(m) => {
                    let _ = tx.send(Cmd::Control(m));
                }
                Wire::Close(code) => {
                    let _ = tx.send(Cmd::Close(code));
                }
                Wire::Live => {}
            }
        }
    }
}

/// The connection role of a Pair with IP joiner.
struct DirectRole<F: CodeExchangeFactory> {
    flow: SharedDirect<F>,
    gate: CallerGate,
    answer_due: Option<Millis>,
    answer_wait_ms: u64,
    clock: Arc<dyn Clock>,
    paths: Arc<Mutex<Paths>>,
    conn: ConnectionId,
    peer: IdentityPublicKey,
}

impl<F: CodeExchangeFactory> DirectRole<F> {
    fn apply(&mut self, wire: Vec<Wire>, out: &mut Outbox) {
        for w in wire {
            match w {
                Wire::Send(message) => {
                    let join = matches!(message, ControlMessage::JoinDirect { .. });
                    out.control.push(message);
                    if join {
                        // Either form is the proof the host answers within
                        // the wait (wire.md 8.2).
                        self.gate.sent_join_proof();
                        self.answer_due = Some(self.clock.mono().plus(self.answer_wait_ms));
                    }
                }
                Wire::Close(code) => {
                    self.gate.close(code);
                    out.close = Some(code);
                }
                Wire::Live => {
                    self.gate.promote_direct();
                    self.gate.promote();
                    if self.gate.is_live() {
                        out.status = Some(ConnStatus::Live);
                    }
                }
            }
        }
    }

    fn step(
        &mut self,
        f: impl FnOnce(&mut DirectJoinerPairing<F>) -> Vec<DirectJoinerAction>,
        out: &mut Outbox,
    ) {
        let wire = {
            let mut flow = lock_flow(&self.flow);
            let actions = f(&mut flow.pairing);
            flow.run(actions)
        };
        self.apply(wire, out);
    }
}

impl<F> ConnRole for DirectRole<F>
where
    F: CodeExchangeFactory + Send + 'static,
    F::Exchange: Send,
{
    fn on_start(&mut self, _out: &mut Outbox) {
        // Nothing goes out before the host's HELLO: JOIN_DIRECT needs the
        // agreed minor.
    }

    fn on_hello(&mut self, minor: u64, out: &mut Outbox) {
        self.step(|p| p.on_hello(minor), out);
    }

    fn wake_at(&self) -> Option<Millis> {
        self.answer_due
    }

    fn on_wake(&mut self, mono: Millis, out: &mut Outbox) {
        if self.answer_due.is_some_and(|due| mono >= due) {
            self.answer_due = None;
            // Nothing happens unless the answer is still awaited.
            self.step(|p| p.on_answer_timeout(), out);
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
        let now = self.clock.now();
        match message {
            ControlMessage::Authorized { state } => self.step(|p| p.on_authorized(state), out),
            ControlMessage::AuthorizedDirect {
                invitation,
                not_received,
            } => self.step(
                |p| p.on_authorized_direct(invitation, not_received, now, &mut os_rng()),
                out,
            ),
            ControlMessage::CodeExchange { attempt, payload } => {
                self.step(|p| p.on_code_exchange(attempt, &payload, now), out)
            }
            ControlMessage::CodeAbort { attempt, .. } => {
                self.step(|p| p.on_code_abort(attempt), out)
            }
            ControlMessage::Paired { host_name, role } => {
                self.step(|p| p.on_paired(host_name, role), out)
            }
            _ => {
                self.gate.close(ErrorCode::ProtocolError);
                out.close = Some(ErrorCode::ProtocolError);
            }
        }
    }

    fn may_open(&self) -> bool {
        self.gate.is_live()
    }

    fn on_closed(&mut self, reason: &CloseReason) {
        {
            let mut flow = lock_flow(&self.flow);
            flow.conn = None;
            let actions = flow.pairing.on_closed(reason.code());
            flow.run(actions);
        }
        self.gate.close(reason.code().unwrap_or(ErrorCode::NoError));
        let mut paths = lock(&self.paths);
        paths.conns.remove(&self.conn);
        if let Some(session) = paths.sessions.get_mut(&self.peer) {
            session.on_path_closed(self.conn);
        }
    }
}

/// The waits between recoveries: the first, doubling up to the longest,
/// then the longest again and again.
struct Backoff {
    next: u64,
    max: u64,
}

impl Backoff {
    fn wait(&mut self) -> std::time::Duration {
        let this = self.next;
        self.next = self.next.saturating_mul(2).min(self.max);
        ms(this)
    }
}

impl<F> Caller<F>
where
    F: CodeExchangeFactory + Clone + Send + Sync + 'static,
    F::Exchange: Send,
{
    /// Start a Pair with IP Connect from what the person typed: `address`
    /// (`<IPv4>:<port>` or `[<IPv6>]:<port>`) and `code`. A bad address,
    /// code or name is refused here, before anything is loaded or dialled.
    /// The flow then runs on its own task: it takes the lookup's hold,
    /// dials, pairs, and recovers a kept pending record with backoff until
    /// it ends ([`DirectJoin::finish`]).
    pub fn join_direct(
        self: &Arc<Self>,
        setup: &DirectSetup,
        address: &str,
        code: &str,
        name: &str,
    ) -> Result<DirectJoin, DirectJoinError> {
        let pairing = DirectJoinerPairing::with_limits(
            address,
            code,
            self.identity(),
            name,
            self.factory.clone(),
            self.limits.core(),
        )?;
        Ok(self.spawn_direct(pairing, setup.clone(), None))
    }

    /// Recover every kept pending record (at startup): one flow each, as a
    /// pinned recovery with no code. A flow whose lookup another flow holds
    /// tries again with backoff.
    pub fn resume_direct(
        self: &Arc<Self>,
        setup: &DirectSetup,
        name: &str,
    ) -> Result<Vec<DirectJoin>, NetError> {
        let mut joins = Vec::new();
        for pending in setup.records.all_pending()? {
            let resume = Resume {
                address: pending.address,
                lookup: pending.lookup.clone(),
                name: name.to_owned(),
            };
            let pairing = resume
                .pairing(self)
                .map_err(|e| NetError::Refused(format!("pair with ip: {}", e.name())))?;
            joins.push(self.spawn_direct(pairing, setup.clone(), Some(resume)));
        }
        Ok(joins)
    }

    fn spawn_direct(
        self: &Arc<Self>,
        pairing: DirectJoinerPairing<F>,
        setup: DirectSetup,
        resume: Option<Resume>,
    ) -> DirectJoin {
        let (events_tx, events) = mpsc::unbounded_channel();
        let (state_tx, state) = watch::channel(pairing.state());
        let flow: SharedDirect<F> = Arc::new(Mutex::new(DirectFlow {
            pairing,
            setup,
            hold: None,
            events: events_tx,
            state: state_tx,
            conn: None,
            failed: None,
            clock: self.clock.clone(),
        }));
        let cancelling = flow.clone();
        let cancel = Box::new(move || {
            let mut f = lock_flow(&cancelling);
            let actions = f.pairing.cancel()?;
            let wire = f.run(actions);
            f.to_connection(wire);
            Ok(())
        });
        let stopping = flow.clone();
        let stop = Box::new(move || {
            let mut f = lock_flow(&stopping);
            f.hold = None;
            f.to_connection(vec![Wire::Close(ErrorCode::NoError)]);
        });
        let caller = self.clone();
        let task = tokio::spawn(async move { caller.drive_direct(flow, state, resume).await });
        DirectJoin {
            events,
            cancel,
            stop,
            task,
        }
    }

    async fn drive_direct(
        self: Arc<Self>,
        flow: SharedDirect<F>,
        mut state: watch::Receiver<DirectJoinerState>,
        resume: Option<Resume>,
    ) -> Result<DirectJoined, NetError> {
        let io = *self.limits.io();
        let mut backoff = Backoff {
            next: io.direct_retry_first_ms(),
            max: io.direct_retry_max_ms(),
        };
        {
            let mut f = lock_flow(&flow);
            let actions = f.pairing.start();
            f.run(actions);
        }
        loop {
            let current = {
                let mut f = lock_flow(&flow);
                if let Some(e) = f.failed.take() {
                    f.hold = None;
                    return Err(e);
                }
                f.pairing.state()
            };
            match current {
                // A recovery at startup whose lookup another flow has:
                // try again later, from the records as they are then.
                DirectJoinerState::Ended(DirectEnd::Busy) if resume.is_some() => {
                    tokio::time::sleep(backoff.wait()).await;
                    let Some(resume) = &resume else {
                        unreachable!("checked above");
                    };
                    let pairing = resume
                        .pairing(&self)
                        .map_err(|e| NetError::Refused(format!("pair with ip: {}", e.name())))?;
                    // The same shared flow goes on, so the handle's cancel
                    // and stop reach the new try.
                    let mut f = lock_flow(&flow);
                    f.pairing = pairing;
                    let actions = f.pairing.start();
                    f.run(actions);
                }
                DirectJoinerState::Ended(end) => {
                    return Ok(DirectJoined {
                        end,
                        connection: None,
                    })
                }
                DirectJoinerState::Away => {
                    let wait = backoff.wait();
                    state.borrow_and_update();
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {
                            let mut f = lock_flow(&flow);
                            let actions = f.pairing.start();
                            f.run(actions);
                        }
                        // A cancel while away may end the flow.
                        _ = state.changed() => {}
                    }
                }
                DirectJoinerState::Connecting => {
                    if let Some(connection) = self.dial_direct(&flow).await {
                        if let Some(joined) =
                            self.follow_direct(&flow, &mut state, connection).await
                        {
                            return Ok(joined);
                        }
                    }
                }
                // Waiting for something the flow's own steps settle.
                _ => {
                    if state.changed().await.is_err() {
                        return Err(NetError::Refused("the join stopped".into()));
                    }
                }
            }
        }
    }

    /// Dial the typed address: unpinned on a first contact, pinned to the
    /// stored host key on a recovery. Returns the started connection, or
    /// `None` when the flow moved on without one.
    async fn dial_direct(&self, flow: &SharedDirect<F>) -> Option<Connection> {
        let (address, pin, denied) = {
            let f = lock_flow(flow);
            (
                f.pairing.address(),
                f.pairing.pinned_host(),
                f.setup.denied.clone(),
            )
        };
        let failed = |flow: &SharedDirect<F>| {
            let mut f = lock_flow(flow);
            let actions = f.pairing.on_dial_failed();
            f.run(actions);
            None
        };
        let own = match self.certs.current() {
            Ok(own) => own,
            Err(e) => {
                lock_flow(flow).failed = Some(e);
                return None;
            }
        };
        let addr = SocketAddr::new(address.ip, address.port);
        let Ok(pipe) = connect_addr(addr, ms(self.limits.io().connect_timeout_ms())).await else {
            return failed(flow);
        };
        let shook = match pin {
            Some(pin) => tls::connect(pipe, &own, pin, self.clock.clone(), self.policy).await,
            None => {
                tls::connect_unpinned(pipe, &own, denied, self.clock.clone(), self.policy).await
            }
        };
        let (stream, handshake) = match shook {
            Ok(done) => done,
            // The far end is this device: refused before this side's
            // certificate went out. The flow ends as "own device".
            Err(NetError::PairPeer(UnpinnedRefusal::OwnEndpoint)) => {
                let mut f = lock_flow(flow);
                let own_key = self.identity();
                let actions = f.pairing.on_connected(own_key, [0u8; EXPORTER_LEN]);
                f.run(actions);
                return None;
            }
            Err(_) => return failed(flow),
        };
        let peer = handshake.peer.identity;
        {
            let mut f = lock_flow(flow);
            let actions = f.pairing.on_connected(peer, handshake.exporters.pair);
            f.run(actions);
            // A cancel while the dial was outstanding, or a far end the
            // flow refuses: the connection goes unused.
            if f.pairing.state() != DirectJoinerState::AwaitingHello {
                return None;
            }
        }
        let conn = match self.admit(peer, &handshake) {
            Ok(conn) => conn,
            Err(_) => {
                let mut f = lock_flow(flow);
                let actions = f.pairing.on_closed(None);
                f.run(actions);
                return None;
            }
        };
        let (cmd_tx, cmd_rx) = conn::channel();
        lock(&self.paths).conns.insert(conn, cmd_tx.clone());
        lock_flow(flow).conn = Some(cmd_tx.clone());
        let skew = self.limits.core().clock_skew_secs();
        let deadline = handshake
            .local_window
            .deadline_with_skew(skew)
            .min(handshake.peer.window.deadline_with_skew(skew));
        let role = DirectRole {
            flow: flow.clone(),
            // A first contact is pairing only from the start (8.2); a
            // recovery is pinned, and its JOIN_DIRECT counts as the proof.
            gate: if pin.is_some() {
                CallerGate::new()
            } else {
                CallerGate::pairing_only()
            },
            answer_due: None,
            answer_wait_ms: self.limits.io().proof_answer_wait_ms(),
            clock: self.clock.clone(),
            paths: self.paths.clone(),
            conn,
            peer,
        };
        Some(conn::spawn(
            conn::Start {
                tls: stream,
                side: MuxRole::Caller,
                conn,
                peer,
                kx_group: handshake.kx_group,
                deadline,
                clock: self.clock.clone(),
                limits: self.limits,
                streams: self.streams.clone(),
            },
            Box::new(role),
            cmd_tx,
            cmd_rx,
        ))
    }

    /// Follow the flow on `connection` until it ends paired (the
    /// connection is returned live), ends otherwise, or goes away.
    async fn follow_direct(
        &self,
        flow: &SharedDirect<F>,
        state: &mut watch::Receiver<DirectJoinerState>,
        connection: Connection,
    ) -> Option<DirectJoined> {
        let mut closed_seen = false;
        loop {
            let now = *state.borrow_and_update();
            match now {
                DirectJoinerState::Ended(DirectEnd::Paired) => {
                    self.promote_first(&connection);
                    return Some(DirectJoined {
                        end: DirectEnd::Paired,
                        connection: Some(connection),
                    });
                }
                DirectJoinerState::Ended(_) | DirectJoinerState::Away => return None,
                _ if closed_seen => return None,
                _ => {}
            }
            tokio::select! {
                changed = state.changed() => {
                    if changed.is_err() {
                        return None;
                    }
                }
                reason = connection.closed(), if !closed_seen => {
                    closed_seen = true;
                    let mut f = lock_flow(flow);
                    f.conn = None;
                    let actions = f.pairing.on_closed(reason.code());
                    f.run(actions);
                }
            }
        }
    }
}

/// What a recovery at startup needs to start again.
struct Resume {
    address: DirectAddress,
    lookup: DirectLookup,
    name: String,
}

impl Resume {
    fn pairing<F>(&self, caller: &Caller<F>) -> Result<DirectJoinerPairing<F>, DirectJoinError>
    where
        F: CodeExchangeFactory + Clone + Send + 'static,
        F::Exchange: Send,
    {
        DirectJoinerPairing::resume(
            self.address,
            self.lookup.clone(),
            caller.identity(),
            &self.name,
            caller.factory.clone(),
            caller.limits.core(),
        )
    }
}
