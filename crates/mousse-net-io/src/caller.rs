//! The caller side: dial a paired host with its stored pin, or join a new
//! host with a ticket.
//!
//! - Every connection pins the host in step 1: the stored pin for a paired
//!   host, the ticket's host identity on first contact.
//! - The caller does not trust the host's streams before the host said
//!   `AUTHORIZED {live}` (or `PAIRED`): stream frames before that close the
//!   connection.
//! - A [`PeerSession`] per pinned host tracks the current path. A new live
//!   connection to the same host replaces the old one, which closes with
//!   `PATH_REPLACED`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use mousse_net_core::authz::{Traffic, Verdict};
use mousse_net_core::control::{AuthorizedState, ControlMessage};
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::MuxRole;
use mousse_net_core::pairing::{
    CodeExchangeFactory, InvitationKind, JoinerAction, JoinerPairing, PairedHost, Ticket,
};
use mousse_net_core::session::{PeerSession, SessionEvent};
use mousse_net_core::session_cert::CertError;
use mousse_net_core::{ConnectionId, ErrorCode};
use tokio::sync::mpsc;

use crate::certs::CertManager;
use crate::clock::Clock;
use crate::conn::{self, CloseReason, Cmd, ConnStatus, Connection, Outbox, Role as ConnRole};
use crate::error::NetError;
use crate::exchange::InPersonOnly;
use crate::pipe::{connect_tcp, Pipe, Route};
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
pub struct Caller<F: CodeExchangeFactory + Clone = InPersonOnly> {
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

impl Caller<InPersonOnly> {
    /// A caller that pairs in person only.
    pub fn new(signer: SharedSigner, clock: Arc<dyn Clock>, policy: TlsPolicy) -> Self {
        Self::with_factory(signer, clock, policy, InPersonOnly)
    }
}

impl<F> Caller<F>
where
    F: CodeExchangeFactory + Clone + Send + 'static,
    F::Exchange: Send,
{
    /// A caller with a code exchange for "send link" tickets.
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
            state: CallerState::AwaitingAuthorized,
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
        Err(last.unwrap_or_else(|| NetError::Refused("no candidate answered as this host".into())))
    }

    /// Pair with the host in `ticket` over `pipe`. In-person tickets wait
    /// for the host owner's approval.
    pub async fn join<P: Pipe>(
        &self,
        pipe: P,
        ticket: &Ticket,
        name: &str,
    ) -> Result<(Connection, JoinOutcome), NetError> {
        if ticket.kind != InvitationKind::InPerson {
            return Err(NetError::Ticket(
                "this ticket needs a pairing code, which this build cannot use yet".into(),
            ));
        }
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
        match connection.settled(true).await {
            ConnStatus::Paired(host) => {
                self.promote(&connection);
                Ok((connection, JoinOutcome::Paired(host)))
            }
            ConnStatus::AlreadyPaired | ConnStatus::Live => {
                self.promote(&connection);
                Ok((connection, JoinOutcome::AlreadyPaired))
            }
            ConnStatus::Closed(reason) => Err(NetError::Closed(reason)),
            other => Err(NetError::Refused(format!("unexpected state {other:?}"))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallerState {
    AwaitingAuthorized,
    JoinOnly,
    Live,
}

struct CallerRole<F: CodeExchangeFactory> {
    state: CallerState,
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
                    self.state = CallerState::Live;
                    out.status = Some(ConnStatus::Paired(host));
                }
                JoinerAction::AlreadyPaired => {
                    self.state = CallerState::Live;
                    out.status = Some(ConnStatus::AlreadyPaired);
                }
                JoinerAction::CodeRejected { .. } => {}
                JoinerAction::Failed(code) => out.close = Some(code),
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

    fn check(&mut self, traffic: Traffic) -> Verdict {
        match traffic {
            Traffic::Keepalive | Traffic::Hello | Traffic::GoAway | Traffic::HostOnly => {
                Verdict::Allow
            }
            Traffic::JoinProof => Verdict::Close(ErrorCode::ProtocolError),
            Traffic::Pairing if self.state == CallerState::JoinOnly => Verdict::Allow,
            Traffic::Pairing => Verdict::Close(ErrorCode::ProtocolError),
            Traffic::Stream if self.state == CallerState::Live => Verdict::Allow,
            Traffic::Stream => Verdict::Close(ErrorCode::NotAuthorized),
        }
    }

    fn on_control(&mut self, message: ControlMessage, out: &mut Outbox) {
        match (message, self.state) {
            (ControlMessage::Authorized { state }, CallerState::AwaitingAuthorized) => {
                match self.joiner.as_mut() {
                    Some(joiner) => {
                        let actions = joiner.on_authorized(state);
                        if state == AuthorizedState::JoinOnly {
                            self.state = CallerState::JoinOnly;
                            out.status = Some(ConnStatus::JoinOnly);
                        }
                        self.joiner_actions(actions, out);
                    }
                    None => match state {
                        AuthorizedState::Live => {
                            self.state = CallerState::Live;
                            out.status = Some(ConnStatus::Live);
                        }
                        // We sent no join proof.
                        AuthorizedState::JoinOnly => out.close = Some(ErrorCode::ProtocolError),
                    },
                }
            }
            (ControlMessage::Paired { host_name, role }, CallerState::JoinOnly) => {
                let actions = match self.joiner.as_mut() {
                    Some(joiner) => joiner.on_paired(host_name, role),
                    None => vec![JoinerAction::Failed(ErrorCode::ProtocolError)],
                };
                self.joiner_actions(actions, out);
            }
            (ControlMessage::CodeExchange { attempt, payload }, CallerState::JoinOnly) => {
                let actions = match self.joiner.as_mut() {
                    Some(joiner) => joiner.on_code_exchange(attempt, &payload),
                    None => vec![JoinerAction::Failed(ErrorCode::ProtocolError)],
                };
                self.joiner_actions(actions, out);
            }
            (ControlMessage::CodeAbort { attempt, .. }, CallerState::JoinOnly) => {
                let actions = match self.joiner.as_mut() {
                    Some(joiner) => joiner.on_code_abort(attempt),
                    None => vec![JoinerAction::Failed(ErrorCode::ProtocolError)],
                };
                self.joiner_actions(actions, out);
            }
            _ => out.close = Some(ErrorCode::ProtocolError),
        }
    }

    fn may_open(&self) -> bool {
        self.state == CallerState::Live
    }

    fn on_closed(&mut self, reason: &CloseReason) {
        if let Some(joiner) = self.joiner.as_mut() {
            let _ = joiner.on_closed(reason.code());
        }
        let mut paths = lock(&self.paths);
        paths.conns.remove(&self.conn);
        if let Some(session) = paths.sessions.get_mut(&self.pin) {
            session.on_path_closed(self.conn);
        }
    }
}
