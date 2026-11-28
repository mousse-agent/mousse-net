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
//!   confirmation verified and `PAIRED` arrived; the gate goes live, and
//!   only then is the pending record deleted and the flow over.
//! - Only the connection the flow is on reaches the pairing: a connection
//!   the flow left (a cancel, a timeout) closes on its own.
//! - A kept pending record is recovered with backoff while the flow runs,
//!   and at startup ([`Caller::resume_direct`]).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use mousse_net_core::authz::{CallerGate, CallerTraffic, Traffic, Verdict};
use mousse_net_core::control::{AuthorizedState, ControlMessage};
use mousse_net_core::mux::MuxRole;
use mousse_net_core::pairing::{
    AttemptId, CodeExchangeFactory, DirectEnd, DirectJoinError, DirectJoinerAction,
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
use crate::tls::{self, DeniedCheck, Handshake, UnpinnedRefusal};

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
    /// The next event, or `None` once the flow has ended (or failed, or
    /// stopped) and every event was read.
    pub async fn event(&mut self) -> Option<DirectEvent> {
        self.events.recv().await
    }

    /// The person cancelled (wire.md 10.9): before the code passed this
    /// ends the flow; after, the pending record is marked cancelled first,
    /// and the cancel reaches the host now (connected) or with the next
    /// recovery (away). A recovery at startup waiting for its lookup's hold
    /// marks its record once it has the hold.
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
    /// ([`Caller::resume_direct`]). Nothing the connection still receives
    /// reaches the flow.
    pub fn stop(self) {
        (self.stop)();
        self.task.abort();
    }
}

/// One flow, shared by its driver task, its connection's role and the
/// handle.
struct DirectFlow<F: CodeExchangeFactory> {
    pairing: DirectJoinerPairing<F>,
    setup: DirectSetup,
    hold: Option<FlowHold>,
    /// The UI's events; gone once the flow is over.
    events: Option<mpsc::UnboundedSender<DirectEvent>>,
    state: watch::Sender<DirectJoinerState>,
    /// The connection the flow is on, and its commands. Only that
    /// connection's role reaches the pairing.
    active: Option<(ConnectionId, mpsc::UnboundedSender<Cmd>)>,
    /// A store failure that ended the flow.
    failed: Option<NetError>,
    clock: Arc<dyn Clock>,
    /// The handle stopped the flow: nothing more reaches the pairing.
    stopped: bool,
    /// A recovery at startup that has not loaded its records yet: the
    /// attempt whose record it recovers (`None` when that record did not
    /// read at startup).
    startup: Option<Option<AttemptId>>,
    /// A recovery at startup whose lookup another flow holds: it asks
    /// again later.
    waiting_hold: bool,
    /// The handle cancelled while [`Self::waiting_hold`].
    cancel_wanted: bool,
}

type SharedDirect<F> = Arc<Mutex<DirectFlow<F>>>;

fn lock_flow<F: CodeExchangeFactory>(flow: &Mutex<DirectFlow<F>>) -> MutexGuard<'_, DirectFlow<F>> {
    flow.lock().unwrap_or_else(|e| e.into_inner())
}

/// What a flow asks of its connection.
enum Wire {
    Send(ControlMessage),
    Close(ErrorCode),
    /// The pin is stored: the connection's gate goes live, then the pin is
    /// acknowledged to the pairing.
    Live,
}

/// The pairing is on a connection in `state`.
fn on_connection(state: DirectJoinerState) -> bool {
    matches!(
        state,
        DirectJoinerState::AwaitingHello
            | DirectJoinerState::AwaitingAnswer
            | DirectJoinerState::Exchanging
            | DirectJoinerState::AwaitingAllow
            | DirectJoinerState::Paired
    )
}

/// A close code that settles a pending record (as core's joiner reads
/// them). Only the host's `GOAWAY` may carry one to the pairing: this
/// side's own close says nothing about the host's answer.
fn settles(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::PairingDeclined
            | ErrorCode::Cancelled
            | ErrorCode::InvitationInvalid
            | ErrorCode::AttemptsExhausted
    )
}

impl<F: CodeExchangeFactory> DirectFlow<F> {
    fn emit(&self, event: DirectEvent) {
        if let Some(events) = &self.events {
            let _ = events.send(event);
        }
    }

    /// Run `f` on the pairing and carry out what it asks, unless the flow
    /// was stopped.
    fn step(
        &mut self,
        f: impl FnOnce(&mut DirectJoinerPairing<F>) -> Vec<DirectJoinerAction>,
    ) -> Vec<Wire> {
        if self.stopped {
            return Vec::new();
        }
        let actions = f(&mut self.pairing);
        self.run(actions)
    }

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
                // The pin is acknowledged to the pairing (which deletes
                // the pending record and ends the flow) only once the
                // connection is live: `Wire::Live`.
                DirectJoinerAction::Paired(paired) => match self.setup.pins.store(&paired) {
                    Ok(()) => {
                        self.emit(DirectEvent::Paired(paired));
                        out.push(Wire::Live);
                        Vec::new()
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
                    self.emit(DirectEvent::CodePassed);
                    Vec::new()
                }
                DirectJoinerAction::Away => {
                    self.emit(DirectEvent::Away);
                    Vec::new()
                }
                DirectJoinerAction::Ended(end) => {
                    self.emit(DirectEvent::Ended(end));
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
                Ok((ledger, mut pending)) => {
                    self.hold = Some(hold);
                    self.waiting_hold = false;
                    // A recovery at startup takes only the record of the
                    // attempt it was started for: a record written since
                    // at the same address belongs to the flow that wrote
                    // it, and without its own the recovery is settled.
                    if let Some(attempt) = self.startup.take() {
                        let address = self.pairing.address();
                        pending.retain(|p| p.address != address || Some(p.attempt) == attempt);
                    }
                    let now = self.clock.now();
                    let mut actions = self.pairing.on_records(ledger.as_ref(), &pending, now);
                    if std::mem::take(&mut self.cancel_wanted)
                        && self.pairing.state() == DirectJoinerState::Connecting
                    {
                        actions.extend(self.pairing.cancel().unwrap_or_default());
                    }
                    actions
                }
                // A record that cannot be read never reads as "none": the
                // flow stops here, its hold given back.
                Err(e) => {
                    self.failed = Some(e);
                    Vec::new()
                }
            },
            // Another flow has the lookup. A recovery at startup is not
            // over: it asks again later.
            Ok(None) if self.startup.is_some() => {
                self.waiting_hold = true;
                Vec::new()
            }
            Ok(None) => self.pairing.on_hold_refused(),
            Err(e) => {
                self.failed = Some(e);
                Vec::new()
            }
        }
    }

    /// A recovery at startup asks for its lookup's hold again.
    fn retry_hold(&mut self) {
        if std::mem::take(&mut self.waiting_hold) {
            self.step(|p| p.start());
        }
    }

    /// `conn` is the connection the flow is on.
    fn owns(&self, conn: ConnectionId) -> bool {
        !self.stopped && self.active.as_ref().is_some_and(|(id, _)| *id == conn)
    }

    /// The pairing left its connection (away, ended, or ended paired with
    /// the connection handed over): nothing more from it reaches the
    /// pairing.
    fn leave_connection_if_done(&mut self) {
        if !on_connection(self.pairing.state()) {
            self.active = None;
        }
    }

    /// The handle's cancel.
    fn cancel(&mut self) -> Result<(), DirectJoinError> {
        if self.stopped {
            return Err(DirectJoinError::WrongState);
        }
        if self.waiting_hold {
            self.cancel_wanted = true;
            return Ok(());
        }
        let actions = self.pairing.cancel()?;
        let wire = self.run(actions);
        self.to_connection(wire);
        self.leave_connection_if_done();
        Ok(())
    }

    /// The handle's stop: from here nothing reaches the pairing, the
    /// connection closes, then the hold goes.
    fn stop(&mut self) {
        self.stopped = true;
        if let Some((_, tx)) = self.active.take() {
            let _ = tx.send(Cmd::Close(ErrorCode::NoError));
        }
        self.hold = None;
        self.events = None;
    }

    /// Hand `wire` to the connection the flow is on (a cancel from the
    /// handle), as one step: messages that come with a close go out before
    /// its `GOAWAY`.
    fn to_connection(&self, wire: Vec<Wire>) {
        let Some((_, tx)) = &self.active else {
            return;
        };
        let mut out = Outbox::default();
        for w in wire {
            match w {
                Wire::Send(m) => out.control.push(m),
                Wire::Close(code) => out.close = Some(code),
                Wire::Live => {}
            }
        }
        if !out.control.is_empty() || out.close.is_some() {
            let _ = tx.send(Cmd::Apply(out));
        }
    }
}

/// The connection role of a Pair with IP joiner.
struct DirectRole<F: CodeExchangeFactory> {
    flow: SharedDirect<F>,
    gate: CallerGate,
    answer_due: Option<Millis>,
    /// The gate went live with the pin stored: acknowledge the pin to the
    /// pairing on the next wake.
    ack_due: bool,
    answer_wait_ms: u64,
    clock: Arc<dyn Clock>,
    paths: Arc<Mutex<Paths>>,
    conn: ConnectionId,
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
                    self.ack_due = true;
                }
            }
        }
    }

    /// Run `f` on the pairing if this is the flow's connection.
    fn step(
        &mut self,
        f: impl FnOnce(&mut DirectJoinerPairing<F>) -> Vec<DirectJoinerAction>,
        out: &mut Outbox,
    ) -> bool {
        let wire = {
            let mut flow = lock_flow(&self.flow);
            if !flow.owns(self.conn) {
                return false;
            }
            let wire = flow.step(f);
            flow.leave_connection_if_done();
            wire
        };
        self.apply(wire, out);
        true
    }

    /// The pin is stored and the gate is live: the pairing deletes the
    /// pending record and ends paired.
    fn ack_pin(&mut self, out: &mut Outbox) {
        if std::mem::take(&mut self.ack_due) {
            self.step(|p| p.on_pin_stored(), out);
        }
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
        if self.ack_due {
            return Some(Millis(0));
        }
        self.answer_due
    }

    fn on_wake(&mut self, mono: Millis, out: &mut Outbox) {
        self.ack_pin(out);
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
        let live_notice = matches!(
            message,
            ControlMessage::Authorized {
                state: AuthorizedState::Live
            }
        );
        let handled = match message {
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
            _ => false,
        };
        if handled {
            return;
        }
        // Not the flow's connection (any more), or a message the joiner
        // never takes. A paired connection may still hear the host's
        // `AUTHORIZED live`; anything else ends this connection only.
        if !(live_notice && self.gate.is_live()) {
            self.gate.close(ErrorCode::ProtocolError);
            out.close = Some(ErrorCode::ProtocolError);
        }
    }

    fn may_open(&self) -> bool {
        self.gate.is_live()
    }

    fn on_closed(&mut self, reason: &CloseReason) {
        // A pin already stored is acknowledged first: the outcome stands.
        let mut out = Outbox::default();
        self.ack_pin(&mut out);
        {
            let mut flow = lock_flow(&self.flow);
            if flow.owns(self.conn) {
                flow.active = None;
                // Only the host's GOAWAY settles a pending record.
                let code = match reason {
                    CloseReason::Peer(code) => Some(*code),
                    CloseReason::Local(code) if !settles(*code) => Some(*code),
                    _ => None,
                };
                flow.step(|p| p.on_closed(code));
            }
        }
        self.gate.close(reason.code().unwrap_or(ErrorCode::NoError));
        let mut paths = lock(&self.paths);
        paths.conns.remove(&self.conn);
        for session in paths.sessions.values_mut() {
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

/// A started connection and its step 1, kept to admit it into the host's
/// session once the pairing succeeds.
struct Dialled {
    connection: Connection,
    handshake: Handshake,
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
    /// pinned recovery with no code. Only where the records are is read
    /// here; each flow loads and checks its own under its lookup's hold, so
    /// a damaged record ends only its own flow. A flow whose lookup another
    /// flow holds asks again with backoff.
    pub fn resume_direct(
        self: &Arc<Self>,
        setup: &DirectSetup,
        name: &str,
    ) -> Result<Vec<DirectJoin>, NetError> {
        let mut joins = Vec::new();
        for slot in setup.records.pending_slots()? {
            let pairing = DirectJoinerPairing::resume(
                slot.address,
                slot.lookup,
                self.identity(),
                name,
                self.factory.clone(),
                self.limits.core(),
            )
            .map_err(|e| NetError::Refused(format!("pair with ip: {}", e.name())))?;
            joins.push(self.spawn_direct(pairing, setup.clone(), Some(slot.attempt)));
        }
        Ok(joins)
    }

    fn spawn_direct(
        self: &Arc<Self>,
        pairing: DirectJoinerPairing<F>,
        setup: DirectSetup,
        startup: Option<Option<AttemptId>>,
    ) -> DirectJoin {
        let (events_tx, events) = mpsc::unbounded_channel();
        let (state_tx, state) = watch::channel(pairing.state());
        let flow: SharedDirect<F> = Arc::new(Mutex::new(DirectFlow {
            pairing,
            setup,
            hold: None,
            events: Some(events_tx),
            state: state_tx,
            active: None,
            failed: None,
            clock: self.clock.clone(),
            stopped: false,
            startup,
            waiting_hold: false,
            cancel_wanted: false,
        }));
        let cancelling = flow.clone();
        let cancel = Box::new(move || lock_flow(&cancelling).cancel());
        let stopping = flow.clone();
        let stop = Box::new(move || lock_flow(&stopping).stop());
        let caller = self.clone();
        let task = tokio::spawn(async move {
            let result = caller.drive_direct(&flow, state).await;
            // The flow is over: the event stream ends, whatever the end.
            let mut f = lock_flow(&flow);
            f.events = None;
            f.hold = None;
            result
        });
        DirectJoin {
            events,
            cancel,
            stop,
            task,
        }
    }

    async fn drive_direct(
        &self,
        flow: &SharedDirect<F>,
        mut state: watch::Receiver<DirectJoinerState>,
    ) -> Result<DirectJoined, NetError> {
        let io = *self.limits.io();
        let mut backoff = Backoff {
            next: io.direct_retry_first_ms(),
            max: io.direct_retry_max_ms(),
        };
        lock_flow(flow).step(|p| p.start());
        loop {
            let (current, waiting) = {
                let mut f = lock_flow(flow);
                if f.stopped {
                    return Err(NetError::Refused("the join was stopped".into()));
                }
                if let Some(e) = f.failed.take() {
                    return Err(e);
                }
                (f.pairing.state(), f.waiting_hold)
            };
            match current {
                // A recovery at startup whose lookup another flow has:
                // ask again later, and load the records as they are then.
                DirectJoinerState::Holding if waiting => {
                    tokio::time::sleep(backoff.wait()).await;
                    lock_flow(flow).retry_hold();
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
                            lock_flow(flow).step(|p| p.start());
                        }
                        // A cancel while away may end the flow.
                        _ = state.changed() => {}
                    }
                }
                DirectJoinerState::Connecting => {
                    if let Some(dialled) = self.dial_direct(flow).await {
                        if let Some(joined) = self.follow_direct(&mut state, dialled).await {
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
    async fn dial_direct(&self, flow: &SharedDirect<F>) -> Option<Dialled> {
        let (address, pin, denied) = {
            let f = lock_flow(flow);
            if f.stopped {
                return None;
            }
            (
                f.pairing.address(),
                f.pairing.pinned_host(),
                f.setup.denied.clone(),
            )
        };
        let failed = |flow: &SharedDirect<F>| {
            lock_flow(flow).step(|p| p.on_dial_failed());
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
                let own_key = self.identity();
                lock_flow(flow).step(|p| p.on_connected(own_key, [0u8; EXPORTER_LEN]));
                return None;
            }
            Err(_) => return failed(flow),
        };
        let peer = handshake.peer.identity;
        let conn = self.next_conn_id();
        let (cmd_tx, cmd_rx) = conn::channel();
        {
            let mut f = lock_flow(flow);
            f.step(|p| p.on_connected(peer, handshake.exporters.pair));
            // Stopped, a cancel while the dial was outstanding, or a far
            // end the flow refuses: the connection goes unused.
            if f.stopped || f.pairing.state() != DirectJoinerState::AwaitingHello {
                return None;
            }
            // The connection is not admitted into the host's session until
            // the pairing succeeds: an unconfirmed identity displaces no
            // path of a host already paired.
            lock(&self.paths).conns.insert(conn, cmd_tx.clone());
            f.active = Some((conn, cmd_tx.clone()));
        }
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
            ack_due: false,
            answer_wait_ms: self.limits.io().proof_answer_wait_ms(),
            clock: self.clock.clone(),
            paths: self.paths.clone(),
            conn,
        };
        let connection = conn::spawn(
            conn::Start {
                tls: stream,
                side: MuxRole::Caller,
                conn,
                peer,
                kx_group: handshake.kx_group.clone(),
                deadline,
                clock: self.clock.clone(),
                limits: self.limits,
                streams: self.streams.clone(),
            },
            Box::new(role),
            cmd_tx,
            cmd_rx,
        );
        Some(Dialled {
            connection,
            handshake,
        })
    }

    /// Follow the flow on its connection until it ends paired (the
    /// connection, now admitted into the host's session, is returned
    /// live), ends otherwise, or goes away. The connection's role delivers
    /// its close to the flow.
    async fn follow_direct(
        &self,
        state: &mut watch::Receiver<DirectJoinerState>,
        dialled: Dialled,
    ) -> Option<DirectJoined> {
        loop {
            let now = *state.borrow_and_update();
            match now {
                DirectJoinerState::Ended(DirectEnd::Paired) => {
                    let Dialled {
                        connection,
                        handshake,
                    } = dialled;
                    let peer = *connection.peer();
                    if self.admit_as(connection.id(), peer, &handshake).is_err() {
                        connection.close(ErrorCode::InternalError);
                        return Some(DirectJoined {
                            end: DirectEnd::Paired,
                            connection: None,
                        });
                    }
                    self.promote_first(&connection);
                    return Some(DirectJoined {
                        end: DirectEnd::Paired,
                        connection: Some(connection),
                    });
                }
                DirectJoinerState::Ended(_) | DirectJoinerState::Away => return None,
                _ => {}
            }
            if state.changed().await.is_err() {
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::direct_records::MemoryDirectRecords;
    use mousse_net_core::grants::Role;
    use mousse_net_core::identity::{IdentityPublicKey, SoftwareKey};
    use mousse_net_core::pairing::{
        CpaceExchangeFactory, DirectAddress, DirectPending, InvitationId,
    };
    use mousse_net_core::{Limits, UnixTime};

    const ADDRESS: &str = "192.168.1.20:47100";

    fn key() -> IdentityPublicKey {
        SoftwareKey::generate(&mut os_rng()).public_key()
    }

    fn k7qm() -> DirectLookup {
        DirectLookup::from_canonical("K7QM").unwrap()
    }

    fn record(host: IdentityPublicKey, attempt: u8) -> DirectPending {
        DirectPending {
            lookup: k7qm(),
            host,
            invitation: InvitationId([7; 16]),
            address: DirectAddress::parse(ADDRESS).unwrap(),
            verified_at: UnixTime(1_790_000_000),
            cancelled: false,
            attempt: AttemptId([attempt; 16]),
        }
    }

    #[derive(Default)]
    struct Pins(Mutex<Vec<DirectPaired>>);

    impl DirectPins for Pins {
        fn store(&self, paired: &DirectPaired) -> Result<(), NetError> {
            self.0.lock().unwrap().push(paired.clone());
            Ok(())
        }
    }

    struct Rig {
        flow: SharedDirect<CpaceExchangeFactory>,
        records: Arc<MemoryDirectRecords>,
        pins: Arc<Pins>,
        events: mpsc::UnboundedReceiver<DirectEvent>,
        host: IdentityPublicKey,
        clock: Arc<ManualClock>,
        paths: Arc<Mutex<Paths>>,
    }

    /// A recovery at startup of `stored` (the record kept at startup),
    /// over a store holding `now`.
    fn rig(stored: &DirectPending, now: &[DirectPending]) -> Rig {
        let records = Arc::new(MemoryDirectRecords::default());
        for p in now {
            records
                .swap_pending(&p.lookup, &p.address, None, Some(p))
                .unwrap();
        }
        let pins = Arc::new(Pins::default());
        let clock = Arc::new(ManualClock::new());
        let pairing = DirectJoinerPairing::resume(
            stored.address,
            stored.lookup.clone(),
            key(),
            "laptop",
            CpaceExchangeFactory,
            &Limits::DEFAULT,
        )
        .unwrap();
        let (events_tx, events) = mpsc::unbounded_channel();
        let (state, _) = watch::channel(pairing.state());
        let flow = Arc::new(Mutex::new(DirectFlow {
            pairing,
            setup: DirectSetup {
                records: records.clone(),
                pins: pins.clone(),
                denied: Arc::new(|_| false),
            },
            hold: None,
            events: Some(events_tx),
            state,
            active: None,
            failed: None,
            clock: clock.clone(),
            stopped: false,
            startup: Some(Some(stored.attempt)),
            waiting_hold: false,
            cancel_wanted: false,
        }));
        Rig {
            flow,
            records,
            pins,
            events,
            host: stored.host,
            clock,
            paths: Arc::new(Mutex::new(Paths::default())),
        }
    }

    impl Rig {
        fn state(&self) -> DirectJoinerState {
            lock_flow(&self.flow).pairing.state()
        }

        fn stored(&self) -> Vec<DirectPending> {
            self.records.load(&k7qm()).unwrap().1
        }

        fn drained(&mut self) -> Vec<DirectEvent> {
            let mut out = Vec::new();
            while let Ok(e) = self.events.try_recv() {
                out.push(e);
            }
            out
        }

        /// The flow takes its hold and loads, then is on connection `id`
        /// (its role returned), with the host's `HELLO` heard.
        fn connect(&self, id: u64) -> DirectRole<CpaceExchangeFactory> {
            let mut f = lock_flow(&self.flow);
            if f.pairing.state() != DirectJoinerState::Connecting {
                f.step(|p| p.start());
            }
            assert_eq!(f.pairing.state(), DirectJoinerState::Connecting);
            f.step(|p| p.on_connected(self.host, [1; EXPORTER_LEN]));
            let (tx, _rx) = mpsc::unbounded_channel();
            f.active = Some((ConnectionId(id), tx));
            drop(f);
            let mut role = self.role(id);
            let mut out = Outbox::default();
            role.on_hello(4, &mut out);
            assert!(matches!(
                out.control.as_slice(),
                [ControlMessage::JoinDirect { .. }]
            ));
            role
        }

        fn role(&self, id: u64) -> DirectRole<CpaceExchangeFactory> {
            DirectRole {
                flow: self.flow.clone(),
                gate: CallerGate::new(),
                answer_due: None,
                ack_due: false,
                answer_wait_ms: 10_000,
                clock: self.clock.clone(),
                paths: self.paths.clone(),
                conn: ConnectionId(id),
            }
        }
    }

    /// Deliver `message` to `role` as the connection driver would: through
    /// the gate first.
    fn deliver(
        role: &mut DirectRole<CpaceExchangeFactory>,
        message: ControlMessage,
        out: &mut Outbox,
    ) {
        let traffic = match &message {
            ControlMessage::Paired { .. } | ControlMessage::Authorized { .. } => Traffic::JoinProof,
            _ => Traffic::Pairing,
        };
        if role.check(traffic, Some(&message)) == Verdict::Allow {
            role.on_control(message, out);
        }
    }

    fn paired() -> ControlMessage {
        ControlMessage::Paired {
            host_name: "Studio".into(),
            role: Role::owner(),
        }
    }

    fn live() -> ControlMessage {
        ControlMessage::Authorized {
            state: AuthorizedState::Live,
        }
    }

    /// A connection the flow left reaches nothing: its late local close
    /// (`CANCELLED` from a cancel) and a late `PAIRED` arrive while the
    /// next recovery waits for its answer, and the pending record, the
    /// recovery and its connection stay as they were. On the flow's own
    /// connection, only the host's `GOAWAY` settles the record, never this
    /// side's own close code.
    #[test]
    fn a_connection_the_flow_left_never_reaches_it() {
        let stored = record(key(), 1);
        let mut rig = rig(&stored, std::slice::from_ref(&stored));
        let mut old = rig.connect(1);
        lock_flow(&rig.flow).cancel().unwrap();
        assert_eq!(rig.state(), DirectJoinerState::Away);
        // The recovery carrying the cancel is on connection 2 and waits
        // for the host's answer.
        let _new = rig.connect(2);
        assert_eq!(rig.state(), DirectJoinerState::AwaitingAnswer);
        let kept = rig.stored();
        assert_eq!(kept.len(), 1);
        assert!(kept[0].cancelled);
        let mut out = Outbox::default();
        old.on_control(paired(), &mut out);
        old.on_closed(&CloseReason::Local(ErrorCode::Cancelled));
        assert_eq!(rig.state(), DirectJoinerState::AwaitingAnswer);
        assert_eq!(rig.stored(), kept);
        assert!(rig.pins.0.lock().unwrap().is_empty());
        assert!(lock_flow(&rig.flow).owns(ConnectionId(2)));

        // This side's own CANCELLED on its own connection keeps the record.
        let mut current = rig.role(2);
        current.on_closed(&CloseReason::Local(ErrorCode::Cancelled));
        assert_eq!(rig.state(), DirectJoinerState::Away);
        assert_eq!(rig.stored(), kept);
        rig.drained();
    }

    /// After the handle stopped the flow, a `PAIRED` its connection still
    /// reads stores no pin and changes no record: the hold is gone, and
    /// another process may own the lookup.
    #[test]
    fn a_stopped_flow_takes_nothing_from_its_connection() {
        let stored = record(key(), 1);
        let rig = rig(&stored, std::slice::from_ref(&stored));
        let mut role = rig.connect(1);
        let mut out = Outbox::default();
        deliver(&mut role, live(), &mut out);
        lock_flow(&rig.flow).stop();
        assert!(lock_flow(&rig.flow).hold.is_none());
        deliver(&mut role, paired(), &mut out);
        role.on_wake(rig.clock.mono(), &mut out);
        role.on_closed(&CloseReason::Local(ErrorCode::NoError));
        assert!(rig.pins.0.lock().unwrap().is_empty());
        assert_eq!(rig.stored(), vec![stored]);
        assert_eq!(rig.state(), DirectJoinerState::AwaitingAnswer);
    }

    /// The gate goes live before the pin is acknowledged: when `PAIRED`
    /// lands the connection is live, while the pending record stays and
    /// the flow is not over until the next wake.
    #[test]
    fn the_connection_is_live_before_the_flow_ends_paired() {
        let stored = record(key(), 1);
        let mut rig = rig(&stored, std::slice::from_ref(&stored));
        let mut role = rig.connect(1);
        let mut out = Outbox::default();
        deliver(&mut role, live(), &mut out);
        let mut out = Outbox::default();
        deliver(&mut role, paired(), &mut out);
        assert!(matches!(out.status, Some(ConnStatus::Live)));
        assert_eq!(rig.pins.0.lock().unwrap().len(), 1);
        assert_eq!(rig.state(), DirectJoinerState::Paired);
        assert_eq!(rig.stored(), vec![stored]);
        assert_eq!(role.wake_at(), Some(Millis(0)));
        let mut out = Outbox::default();
        role.on_wake(rig.clock.mono(), &mut out);
        assert_eq!(rig.state(), DirectJoinerState::Ended(DirectEnd::Paired));
        assert!(rig.stored().is_empty());
        assert_eq!(
            rig.drained().last(),
            Some(&DirectEvent::Ended(DirectEnd::Paired))
        );
    }

    /// A recovery at startup takes only the record of the attempt it was
    /// started for: a newer record at the same lookup and address belongs
    /// to another flow, and the recovery ends settled without touching it.
    #[test]
    fn a_startup_recovery_never_takes_a_newer_attempts_record() {
        let host = key();
        let old = record(host, 1);
        let newer = record(host, 2);
        let mut rig = rig(&old, std::slice::from_ref(&newer));
        lock_flow(&rig.flow).step(|p| p.start());
        assert_eq!(rig.state(), DirectJoinerState::Ended(DirectEnd::Settled));
        assert_eq!(rig.stored(), vec![newer]);
        assert_eq!(rig.drained(), vec![DirectEvent::Ended(DirectEnd::Settled)]);
        assert!(lock_flow(&rig.flow).cancel().is_err());
    }

    /// A recovery at startup whose lookup another flow holds is not over:
    /// no `Ended(Busy)`, a cancel is taken while it waits, and once it has
    /// the hold the cancel marks its own record.
    #[test]
    fn a_startup_recovery_waits_for_its_hold_and_keeps_a_cancel() {
        let stored = record(key(), 1);
        let mut rig = rig(&stored, std::slice::from_ref(&stored));
        let other = rig.records.hold(&k7qm()).unwrap().unwrap();
        lock_flow(&rig.flow).step(|p| p.start());
        assert_eq!(rig.state(), DirectJoinerState::Holding);
        assert!(lock_flow(&rig.flow).waiting_hold);
        assert_eq!(rig.drained(), Vec::new());
        lock_flow(&rig.flow).cancel().unwrap();
        // Still held: it waits on.
        lock_flow(&rig.flow).retry_hold();
        assert_eq!(rig.state(), DirectJoinerState::Holding);
        assert_eq!(rig.drained(), Vec::new());
        drop(other);
        lock_flow(&rig.flow).retry_hold();
        assert_eq!(rig.state(), DirectJoinerState::Away);
        let kept = rig.stored();
        assert_eq!(kept.len(), 1);
        assert!(kept[0].cancelled);
        assert_eq!(kept[0].attempt, stored.attempt);
        assert_eq!(rig.drained(), vec![DirectEvent::Away]);
    }

    /// A cancel while connected goes to the connection as one step: the
    /// abort and then the close, so closing cannot drop the abort.
    #[test]
    fn a_connected_cancel_is_one_step_for_the_connection() {
        let stored = record(key(), 1);
        let rig = rig(&stored, std::slice::from_ref(&stored));
        let _role = rig.connect(1);
        let (tx, mut rx) = mpsc::unbounded_channel();
        lock_flow(&rig.flow).active = Some((ConnectionId(1), tx));
        lock_flow(&rig.flow).cancel().unwrap();
        let Ok(Cmd::Apply(out)) = rx.try_recv() else {
            panic!("not one step");
        };
        assert_eq!(out.close, Some(ErrorCode::Cancelled));
        assert!(rx.try_recv().is_err());
    }
}
