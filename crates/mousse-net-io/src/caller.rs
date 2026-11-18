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

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use mousse_net_core::authz::{CallerGate, CallerTraffic, Traffic, Verdict};
use mousse_net_core::control::{AuthorizedState, ControlMessage};
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::MuxRole;
use mousse_net_core::pairing::{
    Arrival, CodeExchangeFactory, CpaceExchangeFactory, InvitationKind, JoinerAction,
    JoinerPairing, JoinerState, PairedHost, PairingCode, Ticket,
};
use mousse_net_core::session::{PeerSession, SessionEvent};
use mousse_net_core::session_cert::CertError;
use mousse_net_core::{ConnectionId, ErrorCode};
use tokio::sync::mpsc;

use crate::certs::CertManager;
use crate::clock::Clock;
use crate::conn::{self, CloseReason, Cmd, ConnStatus, Connection, Outbox, Role as ConnRole};
use crate::error::NetError;
use crate::pipe::{connect_tcp, route_uri, Pipe, Route};
use crate::rng::os_rng;
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
    factory: F,
    paths: Arc<Mutex<Paths>>,
    next_conn: AtomicU64,
}

fn lock(paths: &Mutex<Paths>) -> MutexGuard<'_, Paths> {
    paths.lock().unwrap_or_else(|e| e.into_inner())
}

/// One join's pairing state, shared by every connection the join uses.
type SharedJoiner<F> = Arc<Mutex<JoinerPairing<F>>>;

fn lock_joiner<F: CodeExchangeFactory>(
    joiner: &Mutex<JoinerPairing<F>>,
) -> MutexGuard<'_, JoinerPairing<F>> {
    joiner.lock().unwrap_or_else(|e| e.into_inner())
}

/// How often a join reconnects to learn a pending outcome, and the waits
/// before each try.
const OUTCOME_RETRIES: [Duration; 4] = [
    Duration::from_millis(200),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
];

impl Caller<CpaceExchangeFactory> {
    /// A caller that pairs in person or with a send link (CPace).
    pub fn new(signer: SharedSigner, clock: Arc<dyn Clock>, policy: TlsPolicy) -> Self {
        Self::with_factory(signer, clock, policy, CpaceExchangeFactory)
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
        policy: TlsPolicy,
        factory: F,
    ) -> Self {
        Self {
            certs: Arc::new(CertManager::new(signer, clock.clone())),
            clock,
            policy,
            factory,
            paths: Arc::new(Mutex::new(Paths::default())),
            next_conn: AtomicU64::new(1),
        }
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

    /// Bring up a new path to `pin` for a renewal: live, not yet current.
    async fn renew(&self, pin: IdentityPublicKey) -> Result<Connection, NetError> {
        let routes = lock(&self.paths)
            .routes
            .get(&pin)
            .cloned()
            .unwrap_or_default();
        let mut last = NetError::Refused("no known route to this host".into());
        for route in &routes {
            let pipe = match connect_tcp(route).await {
                Ok(pipe) => pipe,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            let conn = match self.connect(pipe, pin).await {
                Ok(conn) => conn,
                Err(NetError::PeerCertificate(CertError::PinMismatch)) => continue,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            return match conn.settled(false).await {
                status if status.is_live() => Ok(conn),
                ConnStatus::Closed(reason) => Err(NetError::Closed(reason)),
                other => Err(NetError::Refused(format!("unexpected state {other:?}"))),
            };
        }
        Err(last)
    }

    async fn handshake<P: Pipe>(
        &self,
        pipe: P,
        pin: IdentityPublicKey,
    ) -> Result<(ConnectionId, tokio_rustls::TlsStream<P>, Handshake), NetError> {
        let own = self.certs.current()?;
        let conn = ConnectionId(self.next_conn.fetch_add(1, Ordering::Relaxed));
        {
            let mut paths = lock(&self.paths);
            let events = paths
                .sessions
                .entry(pin)
                .or_insert_with(|| PeerSession::new(pin))
                .begin_path(conn);
            paths.run(events);
        }
        let result = tls::connect(pipe, &own, pin, self.clock.clone(), self.policy).await;
        let mut paths = lock(&self.paths);
        let session = paths
            .sessions
            .entry(pin)
            .or_insert_with(|| PeerSession::new(pin));
        match result {
            Ok((stream, handshake)) => {
                match session.on_authenticated(
                    conn,
                    &handshake.peer,
                    handshake.local_window,
                    self.clock.now(),
                    self.clock.mono(),
                ) {
                    Ok(events) => paths.run(events),
                    // The control build lets a different identity through.
                    Err(_) if cfg!(mousse_control = "skip-pin-check") => {}
                    Err(e) => {
                        return Err(NetError::Refused(format!("new path refused: {e:?}")));
                    }
                }
                Ok((conn, stream, handshake))
            }
            Err(e) => {
                session.on_path_closed(conn);
                Err(e)
            }
        }
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
        let deadline = handshake
            .local_window
            .effective_deadline()
            .min(handshake.peer.window.effective_deadline());
        let (joiner, proof) = match joiner {
            Some((j, p)) => (Some(j), Some(p)),
            None => (None, None),
        };
        let role = CallerRole {
            gate: CallerGate::new(),
            joiner,
            proof,
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

    /// Dial the host pinned as `pin` at the first of `routes` that answers
    /// as that host, over TCP.
    ///
    /// A candidate whose identity is not the pin is another endpoint (for
    /// example another profile on the same computer, or a device that took
    /// the address): it is skipped without a warning and never re-pinned.
    /// Once the pinned host itself refuses (for example `NOT_AUTHORIZED`),
    /// the refusal is returned and no further candidate is tried.
    pub async fn dial_candidates(
        &self,
        routes: &[Route],
        pin: IdentityPublicKey,
    ) -> Result<(Connection, Route), NetError> {
        let mut last = None;
        for route in routes {
            let pipe = match connect_tcp(route).await {
                Ok(pipe) => pipe,
                Err(e) => {
                    last = Some(e);
                    continue;
                }
            };
            match self.dial(pipe, pin).await {
                Ok(conn) => {
                    let mut order = vec![route.clone()];
                    order.extend(routes.iter().filter(|r| *r != route).cloned());
                    self.remember_routes(pin, order);
                    return Ok((conn, route.clone()));
                }
                Err(NetError::PeerCertificate(CertError::PinMismatch)) => continue,
                Err(e @ NetError::Closed(_)) => return Err(e),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            NetError::Refused(format!(
                "no candidate answered as this host ({})",
                routes.iter().map(route_uri).collect::<Vec<_>>().join(", ")
            ))
        }))
    }

    /// Pair with the host in an in-person `ticket` over `pipe`. Waits for
    /// the host owner's approval.
    pub async fn join<P: Pipe>(
        &self,
        pipe: P,
        ticket: &Ticket,
        name: &str,
    ) -> Result<(Connection, JoinOutcome), NetError> {
        self.join_with_code(pipe, ticket, name, &mut NoCode).await
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
        name: &str,
        codes: &mut C,
    ) -> Result<(Connection, JoinOutcome), NetError> {
        let no_redial = || {
            std::future::ready(Err::<P, _>(NetError::Refused(
                "no address to reconnect to".into(),
            )))
        };
        self.join_with_redial(pipe, ticket, name, codes, false, no_redial)
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
    ///   outcome: `AUTHORIZED {live}` means the device has access now,
    ///   reported as [`JoinOutcome::AlreadyPaired`].
    pub async fn join_with_redial<P, C, D, Fut>(
        &self,
        pipe: P,
        ticket: &Ticket,
        name: &str,
        codes: &mut C,
        host_pinned: bool,
        mut redial: D,
    ) -> Result<(Connection, JoinOutcome), NetError>
    where
        P: Pipe,
        C: CodeEntry,
        D: FnMut() -> Fut,
        Fut: Future<Output = Result<P, NetError>>,
    {
        // How the ticket arrived and its stored flow record are not passed
        // in yet: an in-person ticket is taken as scanned in the app, and
        // each join starts with no record.
        let arrival = match ticket.kind {
            InvitationKind::InPerson => Arrival::InAppScan,
            InvitationKind::SendLink => Arrival::Link,
        };
        let mut joiner = JoinerPairing::new(
            ticket.clone(),
            arrival,
            self.identity(),
            name.to_owned(),
            self.factory.clone(),
            None,
            self.clock.now(),
        )
        .map_err(|e| NetError::Ticket(e.to_string()))?;
        joiner.set_host_pinned(host_pinned);
        let joiner: SharedJoiner<F> = Arc::new(Mutex::new(joiner));
        let mut result = self.join_once(pipe, ticket, &joiner, codes).await;
        let mut retries = OUTCOME_RETRIES.iter();
        // Reconnect only while the outcome is unknown. A refusal the host
        // gave (or the joiner reached) on a reconnect is the answer: the
        // flow has failed, and that refusal is what the join reports.
        while result.is_err() && lock_joiner(&joiner).outcome_pending() {
            if matches!(lock_joiner(&joiner).state(), JoinerState::Failed(_)) {
                break;
            }
            let Some(wait) = retries.next() else {
                return Err(NetError::Refused(
                    "the connection dropped while the host was enrolling this device, \
                     and reconnecting did not tell whether it did"
                        .into(),
                ));
            };
            tokio::time::sleep(*wait).await;
            result = match redial().await {
                Ok(pipe) => self.join_once(pipe, ticket, &joiner, codes).await,
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
        let proof = lock_joiner(joiner).on_connected(handshake.exporters, self.clock.now());
        let proof = match proof {
            Ok(proof) => proof,
            Err(e) => {
                lock(&self.paths)
                    .sessions
                    .entry(pin)
                    .or_insert_with(|| PeerSession::new(pin))
                    .on_path_closed(conn);
                return Err(NetError::Ticket(e.to_string()));
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
                    let Some(typed) = codes.code(retry.then_some(attempts_left)).await else {
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
    let mut interval = tokio::time::interval(Duration::from_secs(1));
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

struct CallerRole<F: CodeExchangeFactory> {
    gate: CallerGate,
    joiner: Option<SharedJoiner<F>>,
    proof: Option<ControlMessage>,
    paths: Arc<Mutex<Paths>>,
    conn: ConnectionId,
    pin: IdentityPublicKey,
}

impl<F: CodeExchangeFactory> CallerRole<F> {
    fn joiner_actions(&mut self, actions: Vec<JoinerAction>, out: &mut Outbox) {
        for action in actions {
            match action {
                JoinerAction::Send(message) => out.control.push(message),
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
        let mut joiner = lock_joiner(&joiner);
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
        drop(joiner);
        self.joiner_actions(actions, out);
    }

    fn on_code(&mut self, code: PairingCode, out: &mut Outbox) {
        let actions = match &self.joiner {
            Some(joiner) => lock_joiner(joiner)
                .submit_code(&code, &mut os_rng())
                .unwrap_or_else(|_| vec![JoinerAction::Failed(ErrorCode::ProtocolError)]),
            None => vec![JoinerAction::Failed(ErrorCode::ProtocolError)],
        };
        self.joiner_actions(actions, out);
    }

    fn may_open(&self) -> bool {
        self.gate.is_live()
    }

    fn on_closed(&mut self, reason: &CloseReason) {
        if let Some(joiner) = &self.joiner {
            let _ = lock_joiner(joiner).on_closed(reason.code());
        }
        self.gate.close(reason.code().unwrap_or(ErrorCode::NoError));
        let mut paths = lock(&self.paths);
        paths.conns.remove(&self.conn);
        if let Some(session) = paths.sessions.get_mut(&self.pin) {
            session.on_path_closed(self.conn);
        }
    }
}
