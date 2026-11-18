//! The caller side: dial a paired host with its stored pin, or join a new
//! host with a ticket.
//!
//! - Every connection pins the host in step 1: the stored pin for a paired
//!   host, the ticket's host identity on first contact.
//! - Core's [`CallerGate`] decides what the host may send: nothing on
//!   streams before the host said `AUTHORIZED {live}` (or `PAIRED`).
//! - A "send link" ticket pairs with the 6-digit code the host shows, over
//!   CPace; the owner types it through a [`CodeEntry`].
//! - A [`PeerSession`] per pinned host tracks the current path. A new live
//!   connection to the same host replaces the old one, which closes with
//!   `PATH_REPLACED`.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use mousse_net_core::authz::{CallerGate, CallerTraffic, Traffic, Verdict};
use mousse_net_core::control::{AuthorizedState, ControlMessage};
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::MuxRole;
use mousse_net_core::pairing::{
    CodeExchangeFactory, CpaceExchangeFactory, InvitationKind, JoinerAction, JoinerPairing,
    PairedHost, PairingCode, Ticket,
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
    /// The host already had a live grant for this device.
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

#[derive(Default)]
struct Paths {
    sessions: HashMap<IdentityPublicKey, PeerSession>,
    conns: HashMap<ConnectionId, mpsc::UnboundedSender<Cmd>>,
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
        joiner: Option<(JoinerPairing<F>, ControlMessage)>,
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

    fn promote(&self, conn: &Connection) {
        let mut paths = lock(&self.paths);
        if let Some(session) = paths.sessions.get_mut(conn.peer()) {
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
    pub async fn dial<P: Pipe>(
        &self,
        pipe: P,
        pin: IdentityPublicKey,
    ) -> Result<Connection, NetError> {
        let conn = self.connect(pipe, pin).await?;
        match conn.settled(false).await {
            status if status.is_live() => {
                self.promote(&conn);
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
                Ok(conn) => return Ok((conn, route.clone())),
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
    /// out.
    pub async fn join_with_code<P: Pipe, C: CodeEntry>(
        &self,
        pipe: P,
        ticket: &Ticket,
        name: &str,
        codes: &mut C,
    ) -> Result<(Connection, JoinOutcome), NetError> {
        let mut joiner = JoinerPairing::new(
            ticket.clone(),
            self.identity(),
            name.to_owned(),
            self.factory.clone(),
            self.clock.now(),
        )
        .map_err(|e| NetError::Ticket(e.to_string()))?;
        let pin = ticket.host_identity;
        let (conn, stream, handshake) = self.handshake(pipe, pin).await?;
        let proof = joiner
            .on_connected(handshake.exporters, self.clock.now())
            .map_err(|e| NetError::Ticket(e.to_string()))?;
        let connection = self.start(conn, stream, handshake, pin, Some((joiner, proof)));
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
                    self.promote(&connection);
                    return Ok((connection, JoinOutcome::Paired(host)));
                }
                ConnStatus::AlreadyPaired | ConnStatus::Live => {
                    self.promote(&connection);
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

struct CallerRole<F: CodeExchangeFactory> {
    gate: CallerGate,
    joiner: Option<JoinerPairing<F>>,
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
        let Some(joiner) = self.joiner.as_mut() else {
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
        self.joiner_actions(actions, out);
    }

    fn on_code(&mut self, code: PairingCode, out: &mut Outbox) {
        let actions = match self.joiner.as_mut() {
            Some(joiner) => joiner
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
        if let Some(joiner) = self.joiner.as_mut() {
            let _ = joiner.on_closed(reason.code());
        }
        self.gate.close(reason.code().unwrap_or(ErrorCode::NoError));
        let mut paths = lock(&self.paths);
        paths.conns.remove(&self.conn);
        if let Some(session) = paths.sessions.get_mut(&self.pin) {
            session.on_path_closed(self.conn);
        }
    }
}
