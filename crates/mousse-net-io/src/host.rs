//! The host side: accepts connections, runs step 2 and pairing, and owns the
//! grant table.
//!
//! All host state (grants, pairing, every connection's gate) sits behind one
//! lock, so a pairing or grant change and the gates it affects move together.
//! Removing a grant closes every connection bound to it with
//! `GRANT_REVOKED` before the call returns: their gates refuse further
//! traffic at once and their drivers are told to send `GOAWAY`.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use mousse_net_core::authz::{ConnectionGate, GateState, Traffic, Verdict};
use mousse_net_core::control::{AuthorizedState, ControlMessage};
use mousse_net_core::grants::{Denial, Grant, GrantEvent, GrantId, GrantTable, OwnerRef, Role};
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::MuxRole;
use mousse_net_core::pairing::{
    CodeExchangeFactory, CpaceExchangeFactory, CreatedInvitation, HostAction, HostPairing,
    InvitationId, InvitationKind, InvitationParams, InvitationStatus, PairingCode,
    SessionExporters,
};
use mousse_net_core::{ConnectionId, ErrorCode};
use tokio::sync::mpsc;

use crate::certs::CertManager;
use crate::clock::Clock;
use crate::conn::{self, CloseReason, Cmd, ConnStatus, Connection, Outbox, Role as ConnRole};
use crate::endpoint::Endpoint;
use crate::error::NetError;
use crate::pipe::Pipe;
use crate::rng::os_rng;
use crate::store::GrantStore;
use crate::tls::{self, TlsPolicy};
use crate::SharedSigner;

/// Host settings.
#[derive(Clone, Debug)]
pub struct HostConfig {
    /// The name sent to paired devices in `PAIRED` (1 to 64 bytes).
    pub name: String,
    /// Where `grants.json` lives. `None` keeps grants in memory only.
    pub state_dir: Option<PathBuf>,
    /// The local owner or profile that authorizes grants made here.
    pub owner: OwnerRef,
    /// TLS policy.
    pub policy: TlsPolicy,
    /// Clock.
    pub clock: Arc<dyn Clock>,
}

impl HostConfig {
    /// Settings for `endpoint`: its own grant table and its profile as the
    /// authorizing owner.
    pub fn for_endpoint(
        endpoint: &Endpoint,
        name: String,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, NetError> {
        Ok(Self {
            name,
            state_dir: Some(endpoint.grants_dir()),
            owner: endpoint.owner()?,
            policy: TlsPolicy::default(),
            clock,
        })
    }
}

/// An in-person join waiting for the owner's answer to "Is the device next
/// to you?".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// The invitation.
    pub invitation: InvitationId,
    /// The joining connection.
    pub conn: ConnectionId,
    /// The joining device.
    pub joiner: IdentityPublicKey,
    /// The name the device gave.
    pub name: String,
}

/// Something the host application should know about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostEvent {
    /// Ask the owner, then call [`Host::approve`] or [`Host::decline`].
    ApprovalRequested(ApprovalRequest),
    /// Send link: show this code to the owner, replacing any code shown
    /// before for the invitation. Each attempt uses a fresh code.
    ShowCode {
        /// The invitation.
        invitation: InvitationId,
        /// The code.
        code: PairingCode,
    },
    /// A device was paired.
    Enrolled {
        /// The invitation it used.
        invitation: InvitationId,
        /// Its new grant.
        grant: GrantId,
        /// The device.
        identity: IdentityPublicKey,
    },
    /// An invitation ended without pairing.
    InvitationEnded {
        /// The invitation.
        invitation: InvitationId,
        /// Why.
        reason: ErrorCode,
    },
    /// Grant channels were closed (removed, expired or denied grant).
    ChannelsClosed {
        /// The grant.
        grant: GrantId,
        /// How many connections closed.
        connections: usize,
    },
    /// Saving the grant table failed. The change is live in memory.
    StoreFailed(String),
}

struct Inner<F: CodeExchangeFactory> {
    grants: GrantTable,
    pairing: HostPairing<F>,
    gates: HashMap<ConnectionId, ConnectionGate>,
    conns: HashMap<ConnectionId, mpsc::UnboundedSender<Cmd>>,
    store: Option<GrantStore>,
    approve_next: bool,
    events: mpsc::UnboundedSender<HostEvent>,
}

struct Shared<F: CodeExchangeFactory> {
    inner: Mutex<Inner<F>>,
    certs: CertManager,
    clock: Arc<dyn Clock>,
    policy: TlsPolicy,
    owner: OwnerRef,
    next_conn: AtomicU64,
}

/// A host. Cheap to clone; all clones share state.
pub struct Host<F: CodeExchangeFactory = CpaceExchangeFactory> {
    shared: Arc<Shared<F>>,
}

impl<F: CodeExchangeFactory> Clone for Host<F> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

fn lock<F: CodeExchangeFactory>(shared: &Shared<F>) -> MutexGuard<'_, Inner<F>> {
    shared.inner.lock().unwrap_or_else(|e| e.into_inner())
}

impl<F> Inner<F>
where
    F: CodeExchangeFactory,
{
    fn send(&self, conn: ConnectionId, cmd: Cmd) {
        if let Some(tx) = self.conns.get(&conn) {
            let _ = tx.send(cmd);
        }
    }

    fn close_conn(&mut self, conn: ConnectionId, code: ErrorCode) {
        if let Some(gate) = self.gates.get_mut(&conn) {
            gate.close(code);
        }
        self.send(conn, Cmd::Close(code));
    }

    fn persist(&self) {
        if let Some(store) = &self.store {
            if let Err(e) = store.save(&self.grants) {
                let _ = self.events.send(HostEvent::StoreFailed(e.to_string()));
            }
        }
    }

    fn apply_grant_events(&mut self, events: Vec<GrantEvent>) {
        for event in events {
            let GrantEvent::CloseChannels {
                grant,
                channels,
                code,
            } = event;
            for conn in &channels {
                self.close_conn(*conn, code);
            }
            let _ = self.events.send(HostEvent::ChannelsClosed {
                grant,
                connections: channels.len(),
            });
        }
    }

    fn apply(&mut self, actions: Vec<HostAction>, clock: &dyn Clock) {
        let mut queue: VecDeque<HostAction> = actions.into();
        let mut persist = false;
        while let Some(action) = queue.pop_front() {
            match action {
                HostAction::Send { conn, message } => self.send(conn, Cmd::Control(message)),
                HostAction::Close { conn, code } => self.close_conn(conn, code),
                HostAction::AdmittedJoinOnly { conn, invitation } => {
                    if let Some(gate) = self.gates.get_mut(&conn) {
                        gate.admit_join_only(invitation);
                    }
                    self.send(conn, Cmd::Status(ConnStatus::JoinOnly));
                }
                HostAction::AskApproval {
                    invitation,
                    conn,
                    joiner,
                    name,
                } => {
                    if self.approve_next {
                        self.approve_next = false;
                        if let Ok(more) =
                            self.pairing
                                .approve(&invitation, conn, &mut self.grants, clock.now())
                        {
                            queue.extend(more);
                        }
                    } else {
                        let _ = self
                            .events
                            .send(HostEvent::ApprovalRequested(ApprovalRequest {
                                invitation,
                                conn,
                                joiner,
                                name,
                            }));
                    }
                }
                HostAction::ShowCode { invitation, code } => {
                    let _ = self.events.send(HostEvent::ShowCode { invitation, code });
                }
                HostAction::Enrolled {
                    invitation,
                    conn,
                    grant,
                    identity,
                } => {
                    if let Some(gate) = self.gates.get_mut(&conn) {
                        gate.promote(grant);
                    }
                    self.send(conn, Cmd::Status(ConnStatus::Live));
                    persist = true;
                    let _ = self.events.send(HostEvent::Enrolled {
                        invitation,
                        grant,
                        identity,
                    });
                }
                HostAction::InvitationEnded { invitation, reason } => {
                    let _ = self
                        .events
                        .send(HostEvent::InvitationEnded { invitation, reason });
                }
                HostAction::Grant(event) => {
                    persist = true;
                    self.apply_grant_events(vec![event]);
                }
            }
        }
        if persist {
            self.persist();
        }
    }
}

impl<F> Host<F>
where
    F: CodeExchangeFactory + Send + 'static,
    F::Exchange: Send,
{
    /// A host for `signer`. Loads the grant table from the state directory.
    /// Must be called inside a tokio runtime (it starts a timer task).
    pub fn new(
        signer: SharedSigner,
        config: HostConfig,
        factory: F,
    ) -> Result<(Self, mpsc::UnboundedReceiver<HostEvent>), NetError> {
        let store = config.state_dir.as_deref().map(GrantStore::in_dir);
        let grants = match &store {
            Some(store) => store.load()?,
            None => GrantTable::new(),
        };
        let identity = signer.public_key();
        let (events, events_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            inner: Mutex::new(Inner {
                grants,
                pairing: HostPairing::new(identity, config.name.clone(), factory),
                gates: HashMap::new(),
                conns: HashMap::new(),
                store,
                approve_next: false,
                events,
            }),
            certs: CertManager::new(signer, config.clock.clone()),
            clock: config.clock,
            policy: config.policy,
            owner: config.owner,
            next_conn: AtomicU64::new(1),
        });
        tokio::spawn(ticker(Arc::downgrade(&shared)));
        Ok((Self { shared }, events_rx))
    }

    /// This host's identity.
    pub fn identity(&self) -> IdentityPublicKey {
        self.shared.certs.identity()
    }

    /// Run step 1 and step 2 on a new pipe and start its driver. A peer
    /// without a grant gets a connection that waits for a join proof.
    pub async fn accept<P: Pipe>(&self, pipe: P) -> Result<Connection, NetError> {
        let own = self.shared.certs.current()?;
        let (stream, handshake) =
            tls::accept(pipe, &own, self.shared.clock.clone(), self.shared.policy).await?;
        let conn = ConnectionId(self.shared.next_conn.fetch_add(1, Ordering::Relaxed));
        let peer = handshake.peer.identity;
        let (cmd_tx, cmd_rx) = conn::channel();
        {
            let mut inner = lock(&self.shared);
            let inner = &mut *inner;
            let gate = ConnectionGate::open(
                conn,
                peer,
                &mut inner.grants,
                self.shared.clock.now(),
                self.shared.clock.mono(),
            );
            inner.gates.insert(conn, gate);
            inner.conns.insert(conn, cmd_tx.clone());
        }
        let deadline = handshake
            .local_window
            .effective_deadline()
            .min(handshake.peer.window.effective_deadline());
        let role = HostRole {
            shared: self.shared.clone(),
            conn,
            peer,
            exporters: handshake.exporters,
        };
        Ok(conn::spawn(
            conn::Start {
                tls: stream,
                side: MuxRole::Host,
                conn,
                peer,
                kx_group: handshake.kx_group,
                deadline,
                clock: self.shared.clock.clone(),
            },
            Box::new(role),
            cmd_tx,
            cmd_rx,
        ))
    }

    /// Create an invitation of `kind` with these route hints. In person,
    /// the owner confirms the device is next to them; a send link asks the
    /// joiner for the code the host shows ([`HostEvent::ShowCode`]).
    pub fn invite(
        &self,
        kind: InvitationKind,
        routes: Vec<String>,
    ) -> Result<CreatedInvitation, NetError> {
        let params = InvitationParams {
            kind,
            role: Role::owner(),
            authorizing_owner: self.shared.owner,
            routes,
            grant_expires_at: None,
        };
        lock(&self.shared)
            .pairing
            .create(params, self.shared.clock.now(), &mut os_rng())
            .map_err(|e| NetError::Refused(e.to_string()))
    }

    /// Where an invitation stands.
    pub fn invitation_status(&self, invitation: &InvitationId) -> Option<InvitationStatus> {
        lock(&self.shared).pairing.status(invitation)
    }

    /// The owner said yes.
    pub fn approve(&self, request: &ApprovalRequest) -> Result<(), NetError> {
        let mut inner = lock(&self.shared);
        let inner = &mut *inner;
        let actions = inner
            .pairing
            .approve(
                &request.invitation,
                request.conn,
                &mut inner.grants,
                self.shared.clock.now(),
            )
            .map_err(|e| NetError::Refused(e.to_string()))?;
        inner.apply(actions, &*self.shared.clock);
        Ok(())
    }

    /// The owner said no. The invitation ends.
    pub fn decline(&self, invitation: &InvitationId) {
        let mut inner = lock(&self.shared);
        let actions = inner.pairing.decline(invitation);
        inner.apply(actions, &*self.shared.clock);
    }

    /// Cancel an open invitation.
    pub fn cancel(&self, invitation: &InvitationId) {
        let mut inner = lock(&self.shared);
        let actions = inner.pairing.cancel(invitation);
        inner.apply(actions, &*self.shared.clock);
    }

    /// Approve the next in-person request without asking (scripted runs).
    pub fn set_approve_next(&self, on: bool) {
        lock(&self.shared).approve_next = on;
    }

    /// All grants.
    pub fn grants(&self) -> Vec<Grant> {
        lock(&self.shared).grants.grants().cloned().collect()
    }

    /// All local denials.
    pub fn denials(&self) -> Vec<Denial> {
        lock(&self.shared).grants.denials().collect()
    }

    /// How many live connections are bound to `grant`.
    pub fn connections_for(&self, grant: GrantId) -> usize {
        let inner = lock(&self.shared);
        inner
            .gates
            .values()
            .filter(|g| matches!(g.state(), GateState::Live { grant: bound } if *bound == grant))
            .count()
    }

    /// Remove a grant. Its connections close at once with `GRANT_REVOKED`.
    /// Returns false if there was no such grant.
    pub fn remove_grant(&self, grant: GrantId) -> bool {
        let mut inner = lock(&self.shared);
        if inner.grants.get(grant).is_none() {
            return false;
        }
        if cfg!(mousse_control = "keep-removed-grant") {
            // The control build (tests only) reports success and changes
            // nothing.
            return true;
        }
        let events = inner.grants.remove(grant);
        inner.apply_grant_events(events);
        inner.persist();
        true
    }

    /// Deny an identity host-wide: its grant goes, its connections close and
    /// it cannot be granted again until the denial is lifted.
    pub fn deny(&self, identity: IdentityPublicKey) {
        let mut inner = lock(&self.shared);
        let events = inner.grants.deny(identity, self.shared.clock.now());
        inner.apply_grant_events(events);
        inner.persist();
    }

    /// Lift a denial. Grants nothing.
    pub fn undeny(&self, identity: &IdentityPublicKey) -> bool {
        let mut inner = lock(&self.shared);
        let lifted = inner.grants.undeny(identity);
        inner.persist();
        lifted
    }

    /// Close every connection with `code`.
    pub fn close_all(&self, code: ErrorCode) {
        let mut inner = lock(&self.shared);
        let conns: Vec<ConnectionId> = inner.conns.keys().copied().collect();
        for conn in conns {
            inner.close_conn(conn, code);
        }
    }
}

/// Grant expiry, invitation expiry and the join-proof wait, once a second.
async fn ticker<F: CodeExchangeFactory>(shared: Weak<Shared<F>>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let Some(shared) = shared.upgrade() else {
            return;
        };
        let now = shared.clock.now();
        let mono = shared.clock.mono();
        let mut inner = lock(&shared);
        let events = inner.grants.tick(now);
        if !events.is_empty() {
            inner.apply_grant_events(events);
            inner.persist();
        }
        let actions = inner.pairing.tick(now);
        inner.apply(actions, &*shared.clock);
        let overdue: Vec<(ConnectionId, ErrorCode)> = inner
            .gates
            .iter_mut()
            .filter_map(|(conn, gate)| gate.on_timeout(mono).map(|code| (*conn, code)))
            .collect();
        for (conn, code) in overdue {
            inner.send(conn, Cmd::Close(code));
        }
    }
}

struct HostRole<F: CodeExchangeFactory> {
    shared: Arc<Shared<F>>,
    conn: ConnectionId,
    peer: IdentityPublicKey,
    exporters: SessionExporters,
}

impl<F> ConnRole for HostRole<F>
where
    F: CodeExchangeFactory + Send + 'static,
    F::Exchange: Send,
{
    fn on_start(&mut self, out: &mut Outbox) {
        let inner = lock(&self.shared);
        match inner.gates.get(&self.conn).map(|g| g.state()) {
            Some(GateState::Live { .. }) => {
                out.control.push(ControlMessage::Authorized {
                    state: AuthorizedState::Live,
                });
                out.status = Some(ConnStatus::Live);
            }
            Some(GateState::Closed(code)) => out.close = Some(*code),
            Some(_) => {}
            None => out.close = Some(ErrorCode::InternalError),
        }
    }

    fn check(&mut self, traffic: Traffic, _message: Option<&ControlMessage>) -> Verdict {
        let mut inner = lock(&self.shared);
        match inner.gates.get_mut(&self.conn) {
            Some(gate) => gate.check(traffic),
            None => Verdict::Close(ErrorCode::InternalError),
        }
    }

    fn on_control(&mut self, message: ControlMessage, _out: &mut Outbox) {
        let shared = self.shared.clone();
        let clock = &*shared.clock;
        let mut guard = lock(&shared);
        let inner = &mut *guard;
        let actions = match message {
            ControlMessage::JoinProof {
                invitation,
                mac,
                name,
            } => inner.pairing.on_join_proof(
                self.conn,
                &self.peer,
                &self.exporters,
                &invitation,
                &mac,
                &name,
                &inner.grants,
                clock.now(),
            ),
            ControlMessage::CodeExchange { attempt, payload } => inner.pairing.on_code_exchange(
                self.conn,
                attempt,
                &payload,
                &mut inner.grants,
                clock.now(),
                &mut os_rng(),
            ),
            ControlMessage::CodeAbort { attempt, .. } => {
                inner.pairing.on_code_abort(self.conn, attempt)
            }
            // HELLO is handled by the driver; host-only messages never pass
            // the gate.
            _ => Vec::new(),
        };
        inner.apply(actions, clock);
    }

    fn may_open(&self) -> bool {
        let inner = lock(&self.shared);
        matches!(
            inner.gates.get(&self.conn).map(|g| g.state()),
            Some(GateState::Live { .. })
        )
    }

    fn on_closed(&mut self, _reason: &CloseReason) {
        let shared = self.shared.clone();
        let mut inner = lock(&shared);
        inner.gates.remove(&self.conn);
        inner.conns.remove(&self.conn);
        inner.grants.unbind(self.conn);
        let actions = inner.pairing.on_connection_closed(self.conn);
        inner.apply(actions, &*shared.clock);
    }
}
