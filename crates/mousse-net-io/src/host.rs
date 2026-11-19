//! The host side: accepts connections, runs step 2 and pairing, and owns the
//! grant table.
//!
//! All host state (grants, pairing, every connection's gate) sits behind one
//! lock, so a pairing or grant change and the gates it affects move together.
//! Removing a grant closes every connection bound to it with
//! `GRANT_REVOKED` before the call returns: their gates refuse further
//! traffic at once and their drivers are told to send `GOAWAY`.
//!
//! The grant table is saved after every change. A change whose save fails
//! still takes effect in memory (access ends at once) but the call reports
//! the failure, and the host retries the save every second until it works.
//! Enrollment is the exception: a new grant is saved before the
//! connection is promoted or `PAIRED` is sent, and if that save fails the
//! grant is dropped and the pairing fails with `INTERNAL_ERROR`, so a
//! device is never told it is paired under a grant a restart would lose.
//! A save that failed after its rename (the folder sync) may have left the
//! new grant on disk, where a restart would load it: the host writes the
//! table without it again at once, and until such a save works it serves no
//! grant at all (every connection closes with `INTERNAL_ERROR`).
//!
//! A pairing message and the owner's approval act only if the connection's
//! gate still admits them under the same lock as the pairing step, so a
//! removal or denial that closed the connection in between wins. Deadlines
//! are checked before the traffic they bound: a join proof that arrives
//! after the join-proof wait is refused even before the ticker runs.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use mousse_net_core::authz::{ConnectionGate, GateState, Traffic, Verdict};
use mousse_net_core::control::{AuthorizedState, ControlMessage};
use mousse_net_core::grants::{
    validate_name, Denial, Grant, GrantEvent, GrantId, GrantTable, NewGrant, OwnerRef, Role,
};
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::MuxRole;
use mousse_net_core::pairing::{
    CodeExchangeFactory, CpaceExchangeFactory, CreatedInvitation, HostAction, HostPairing,
    InvitationId, InvitationKind, InvitationParams, InvitationStatus, PairingCode,
    SessionExporters,
};
use mousse_net_core::removal::{self, Decision, Journaled, RemovalId, SignedRemoval};
use mousse_net_core::{ConnectionId, ErrorCode, Millis, UnixTime};
use tokio::sync::{mpsc, watch};

use crate::admission::StreamAdmission;
use crate::certs::CertManager;
use crate::clock::Clock;
use crate::conn::{self, CloseReason, Cmd, ConnStatus, Connection, Outbox, Role as ConnRole};
use crate::endpoint::Endpoint;
use crate::error::NetError;
use crate::limits::{ms, Limits};
use crate::pipe::Pipe;
use crate::rng::os_rng;
use crate::store::{EnrollmentSaveError, GrantStore, PendingEnrollment};
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
    /// Limits ([`Limits::DEFAULT`] unless the app overrides some).
    /// A [`Limits`] is always within the allowed ranges.
    pub limits: Limits,
    /// Clock.
    pub clock: Arc<dyn Clock>,
    /// The identity tickets and pairing name, when it differs from the
    /// identity TLS presents. Only the `allow-break-env` control build (tests
    /// only) may set it; [`Host::new`] refuses it otherwise.
    pub ticket_identity: Option<IdentityPublicKey>,
    /// The endpoint's stream places, when a caller of the same endpoint
    /// shares them. `None` gives the host its own, from `limits`.
    pub streams: Option<Arc<StreamAdmission>>,
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
            limits: Limits::DEFAULT,
            clock,
            ticket_identity: None,
            streams: None,
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

/// What [`Host::apply_removal`] did.
#[derive(Debug)]
pub struct AppliedRemoval {
    /// The decision, journaled when it had to be.
    pub decision: Decision,
    /// For an applied removal: whether the grant table was saved.
    pub saved: Result<(), NetError>,
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
    /// The last save failed; the ticker retries it.
    unsaved: bool,
    /// An enrollment is in force but its save could not be made durable
    /// (see [`EnrollmentSaveError::Unsettled`]). No grant is served until a
    /// save works.
    reconcile: bool,
    /// [`Host::pause`]: no connection is served until [`Host::resume`].
    paused: bool,
    events: mpsc::UnboundedSender<HostEvent>,
    /// Bumped on every change to the grant table ([`Host::grants_changed`]).
    grants_gen: watch::Sender<u64>,
}

struct Shared<F: CodeExchangeFactory> {
    inner: Mutex<Inner<F>>,
    certs: CertManager,
    clock: Arc<dyn Clock>,
    policy: TlsPolicy,
    limits: Limits,
    owner: OwnerRef,
    next_conn: AtomicU64,
    streams: Arc<StreamAdmission>,
    /// Tests stop the ticker to show what holds without it.
    #[cfg(test)]
    ticker_paused: std::sync::atomic::AtomicBool,
    /// Tests run this after a pairing message passed the gate and before
    /// it is handled; it stays until it returns true.
    #[cfg(test)]
    after_pairing_check: Mutex<Option<PairingHook>>,
}

#[cfg(test)]
type PairingHook = Box<dyn FnMut() -> bool + Send>;

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

    /// Save the grant table. On failure the change stays in effect in
    /// memory, the host reports [`HostEvent::StoreFailed`] and retries.
    fn persist(&mut self) -> Result<(), NetError> {
        self.grants_gen.send_modify(|g| *g += 1);
        let Some(store) = &self.store else {
            return Ok(());
        };
        match store.save(&self.grants) {
            Ok(()) => {
                self.unsaved = false;
                self.reconcile = false;
                Ok(())
            }
            Err(e) => {
                self.unsaved = true;
                let _ = self.events.send(HostEvent::StoreFailed(e.to_string()));
                Err(e)
            }
        }
    }

    /// Whether grants may be served: not paused, and no rolled-back
    /// enrollment is waiting to be saved away.
    fn serving(&self) -> bool {
        !self.reconcile && !self.paused
    }

    /// Remove the grants past their expiry, close their connections and
    /// save.
    fn expire_grants(&mut self, now: UnixTime) {
        let before = self.grants.grants().count();
        let events = self.grants.tick(now);
        let changed = self.grants.grants().count() != before;
        self.apply_grant_events(events);
        if changed || self.unsaved {
            // A failure is reported as an event and retried by the ticker.
            let _ = self.persist();
        }
    }

    /// Whether `conn` is live under a grant that is still live at `now`.
    /// A grant found past its expiry is removed here and its connections
    /// closed with `GRANT_REVOKED`, without waiting for the ticker.
    fn live_now(&mut self, conn: ConnectionId, now: UnixTime) -> bool {
        let Some(GateState::Live { grant }) = self.gates.get(&conn).map(|g| g.state().clone())
        else {
            return false;
        };
        let live = self
            .grants
            .get(grant)
            .is_some_and(|g| g.expires_at.is_none_or(|at| now < at));
        if !live {
            self.expire_grants(now);
            // Gone some other way: the connection must not stay live.
            if matches!(
                self.gates.get(&conn).map(|g| g.state()),
                Some(GateState::Live { .. })
            ) {
                self.close_conn(conn, ErrorCode::GrantRevoked);
            }
        }
        live
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

    /// Save an enrollment before anything acts on it. `actions` came from a
    /// pairing call that ran on the grant table as it was in `before`. When
    /// they enroll a device, the new grant is saved first, so the gate is
    /// promoted and `PAIRED` sent only for a grant that survives a restart.
    ///
    /// If the save fails with `before` in force (on disk too), the table
    /// goes back to it and the pairing fails: the enrolling connection
    /// closes with `INTERNAL_ERROR`, no `PAIRED` is sent and the invitation
    /// ends. If it fails with the enrollment in force but not durable, the
    /// host keeps it, as a restart would: it reports the enrollment, sends
    /// no `PAIRED` (the device learns the outcome when it reconnects),
    /// closes every connection with `INTERNAL_ERROR` and serves nothing
    /// until a save works.
    fn commit_enrollment(
        &mut self,
        before: GrantTable,
        actions: Vec<HostAction>,
    ) -> Vec<HostAction> {
        let (enrolling, pending): (Vec<ConnectionId>, Vec<PendingEnrollment>) = actions
            .iter()
            .filter_map(|a| match a {
                HostAction::Enrolled {
                    invitation,
                    conn,
                    grant,
                    identity,
                } => Some((
                    *conn,
                    PendingEnrollment {
                        grant: *grant,
                        identity: *identity,
                        invitation: *invitation,
                    },
                )),
                _ => None,
            })
            .unzip();
        if enrolling.is_empty() {
            return actions;
        }
        let Some(store) = self.store.clone() else {
            return actions;
        };
        self.grants_gen.send_modify(|g| *g += 1);
        let failure = match store.save_enrollment(&before, &self.grants, &pending) {
            Ok(()) => return actions,
            Err(f) => f,
        };
        let _ = self
            .events
            .send(HostEvent::StoreFailed(failure.error().to_string()));
        if let EnrollmentSaveError::Unsettled(_) = failure {
            self.unsaved = true;
            self.reconcile = true;
            let conns: Vec<ConnectionId> = self.conns.keys().copied().collect();
            for conn in conns {
                self.close_conn(conn, ErrorCode::InternalError);
            }
            return actions
                .into_iter()
                .filter_map(|action| match action {
                    HostAction::Enrolled {
                        invitation,
                        conn,
                        grant,
                        identity,
                    } => {
                        let _ = self.events.send(HostEvent::Enrolled {
                            invitation,
                            grant,
                            identity,
                        });
                        Some(HostAction::Close {
                            conn,
                            code: ErrorCode::InternalError,
                        })
                    }
                    HostAction::Send {
                        conn,
                        message: ControlMessage::Paired { .. },
                    } if enrolling.contains(&conn) => None,
                    other => Some(other),
                })
                .collect();
        }
        self.grants = before;
        actions
            .into_iter()
            .flat_map(|action| match action {
                HostAction::Enrolled {
                    invitation, conn, ..
                } => vec![
                    HostAction::Close {
                        conn,
                        code: ErrorCode::InternalError,
                    },
                    HostAction::InvitationEnded {
                        invitation,
                        reason: ErrorCode::InternalError,
                    },
                ],
                // The grant table is back as it was: nothing it reported
                // happened.
                HostAction::Grant(_) => Vec::new(),
                HostAction::Send {
                    conn,
                    message: ControlMessage::Paired { .. },
                } if enrolling.contains(&conn) => Vec::new(),
                other => vec![other],
            })
            .collect()
    }

    fn apply(&mut self, actions: Vec<HostAction>) {
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
                    let _ = self
                        .events
                        .send(HostEvent::ApprovalRequested(ApprovalRequest {
                            invitation,
                            conn,
                            joiner,
                            name,
                        }));
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
                    // Already saved by `commit_enrollment`.
                    if let Some(gate) = self.gates.get_mut(&conn) {
                        gate.promote(grant);
                    }
                    self.send(conn, Cmd::Status(ConnStatus::Live));
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
            // A failure is reported as an event and retried by the ticker.
            let _ = self.persist();
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
        let identity = match config.ticket_identity {
            None => signer.public_key(),
            Some(other) if crate::CONTROL == Some("allow-break-env") => other,
            Some(_) => {
                return Err(NetError::Refused(
                    "a separate ticket identity needs the allow-break-env control build".into(),
                ))
            }
        };
        let (events, events_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            inner: Mutex::new(Inner {
                grants,
                pairing: HostPairing::with_limits(
                    identity,
                    config.name.clone(),
                    factory,
                    config.limits.core(),
                ),
                gates: HashMap::new(),
                conns: HashMap::new(),
                store,
                unsaved: false,
                reconcile: false,
                paused: false,
                events,
                grants_gen: watch::channel(0).0,
            }),
            certs: CertManager::with_limits(signer, config.clock.clone(), &config.limits),
            clock: config.clock,
            policy: TlsPolicy::from_limits(&config.limits),
            streams: config
                .streams
                .unwrap_or_else(|| StreamAdmission::new(&config.limits)),
            limits: config.limits,
            owner: config.owner,
            next_conn: AtomicU64::new(1),
            #[cfg(test)]
            ticker_paused: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            after_pairing_check: Mutex::new(None),
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
            let mut gate = ConnectionGate::open_with_limits(
                conn,
                peer,
                &mut inner.grants,
                self.shared.clock.now(),
                self.shared.clock.mono(),
                self.shared.limits.core(),
            );
            if !inner.serving() {
                gate.close(ErrorCode::InternalError);
            }
            inner.gates.insert(conn, gate);
            inner.conns.insert(conn, cmd_tx.clone());
        }
        let skew = self.shared.limits.core().clock_skew_secs();
        let deadline = handshake
            .local_window
            .deadline_with_skew(skew)
            .min(handshake.peer.window.deadline_with_skew(skew));
        let role = HostRole {
            shared: self.shared.clone(),
            conn,
            peer,
            exporters: handshake.exporters,
            caller_opened: false,
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
                limits: self.shared.limits,
                streams: self.shared.streams.clone(),
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
        // Under the same lock as the enrollment: a removal, denial or close
        // that reached this connection first wins.
        let waiting = matches!(
            inner.gates.get(&request.conn).map(|g| g.state()),
            Some(GateState::JoinOnly { invitation }) if *invitation == request.invitation
        );
        if !waiting || !inner.serving() {
            return Err(NetError::Refused(
                "the device's connection is no longer waiting for an answer".into(),
            ));
        }
        let before = inner.grants.clone();
        let actions = inner
            .pairing
            .approve(
                &request.invitation,
                request.conn,
                &mut inner.grants,
                self.shared.clock.now(),
            )
            .map_err(|e| NetError::Refused(e.to_string()))?;
        let actions = inner.commit_enrollment(before, actions);
        inner.apply(actions);
        Ok(())
    }

    /// The owner said no. The invitation ends.
    pub fn decline(&self, invitation: &InvitationId) {
        let mut inner = lock(&self.shared);
        let actions = inner.pairing.decline(invitation);
        inner.apply(actions);
    }

    /// Cancel an open invitation.
    pub fn cancel(&self, invitation: &InvitationId) {
        let mut inner = lock(&self.shared);
        let actions = inner.pairing.cancel(invitation);
        inner.apply(actions);
    }

    /// This host's stream places (shared with a caller of the same
    /// endpoint when [`HostConfig::streams`] named one).
    pub fn stream_admission(&self) -> Arc<StreamAdmission> {
        self.shared.streams.clone()
    }

    /// The grant `conn` is live under, if it is live.
    pub fn grant_of(&self, conn: ConnectionId) -> Option<Grant> {
        let inner = lock(&self.shared);
        match inner.gates.get(&conn).map(|g| g.state()) {
            Some(GateState::Live { grant }) => inner.grants.get(*grant).cloned(),
            _ => None,
        }
    }

    /// All grants.
    pub fn grants(&self) -> Vec<Grant> {
        lock(&self.shared).grants.grants().cloned().collect()
    }

    /// Changes to the grant table: the value grows on every change (a
    /// grant added, replaced, removed, expired or denied).
    pub fn grants_changed(&self) -> watch::Receiver<u64> {
        lock(&self.shared).grants_gen.subscribe()
    }

    /// Apply a signed removal from an owner-role device (Phase 4, design
    /// D.4), under the lock connections are admitted and devices enrolled
    /// under.
    ///
    /// Runs [`removal::decide`] with `journaled` (the removal journal's
    /// entry for this id, if any). A decision that must be journaled is
    /// passed to `record`, which must make it durable before it returns;
    /// if it fails, nothing changes and the error is returned. Then, for
    /// `applied`, the grant is removed (its connections close with
    /// `GRANT_REVOKED`) and the table saved; a failed save is reported in
    /// [`AppliedRemoval::saved`], and the caller pauses networking until a
    /// save works, as for any removal (Phase 1a §5.4). While the host is
    /// paused nothing is decided.
    pub fn apply_removal(
        &self,
        signed: &SignedRemoval,
        max_age_secs: u64,
        journaled: impl FnOnce(&RemovalId) -> Option<Journaled>,
        record: impl FnOnce(&Decision) -> Result<(), String>,
    ) -> Result<AppliedRemoval, String> {
        let now = self.shared.clock.now();
        let mut inner = lock(&self.shared);
        if !inner.serving() {
            return Err("networking is paused".into());
        }
        let decision = removal::decide(
            signed,
            &self.identity(),
            &inner.grants,
            journaled(&signed.removal().id),
            now,
            max_age_secs,
            self.shared.limits.core().clock_skew_secs(),
        );
        if let Decision::Journal { .. } = decision {
            record(&decision)?;
        }
        let mut saved = Ok(());
        if let Decision::Journal {
            grant: Some(grant), ..
        } = decision
        {
            let events = inner.grants.remove(grant);
            inner.apply_grant_events(events);
            saved = inner.persist();
        }
        Ok(AppliedRemoval { decision, saved })
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

    /// Remove a grant. Its connections close at once with `GRANT_REVOKED`,
    /// before the save. `Ok(false)` if there was no such grant. An error
    /// means the removal is in effect now but was not saved: the host keeps
    /// retrying, and if it stops before a retry works the grant is back on
    /// the next start.
    pub fn remove_grant(&self, grant: GrantId) -> Result<bool, NetError> {
        let mut inner = lock(&self.shared);
        if inner.grants.get(grant).is_none() {
            return Ok(false);
        }
        if cfg!(mousse_control = "keep-removed-grant") {
            // The control build (tests only) reports success and changes
            // nothing.
            return Ok(true);
        }
        let events = inner.grants.remove(grant);
        inner.apply_grant_events(events);
        inner.persist()?;
        Ok(true)
    }

    /// Deny an identity host-wide: its grant goes, its connections close and
    /// it cannot be granted again until the denial is lifted. Access ends
    /// before the save; an error means the denial was not saved (see
    /// [`Host::remove_grant`]).
    pub fn deny(&self, identity: IdentityPublicKey) -> Result<(), NetError> {
        let mut inner = lock(&self.shared);
        let events = inner.grants.deny(identity, self.shared.clock.now());
        inner.apply_grant_events(events);
        inner.persist()
    }

    /// Lift a denial. Grants nothing. An error means the change was not
    /// saved.
    pub fn undeny(&self, identity: &IdentityPublicKey) -> Result<bool, NetError> {
        let mut inner = lock(&self.shared);
        let lifted = inner.grants.undeny(identity);
        inner.persist()?;
        Ok(lifted)
    }

    /// Grant `identity` the owner role on this endpoint, named `name`, as
    /// the joiner's half of pairing both ways (Phase 1a §5.1). `receipt` is
    /// the invitation of the pairing this answers, kept as the grant's
    /// enrollment receipt.
    ///
    /// Idempotent: if the identity already holds a live grant, that grant
    /// is returned with `true` and nothing changes (its connections stay
    /// up), apart from saving a table whose last save failed. An error
    /// after the grant was added means it is in effect now but was not
    /// saved: the host keeps retrying, and the caller may repeat the call.
    pub fn add_grant(
        &self,
        identity: IdentityPublicKey,
        name: String,
        receipt: Option<InvitationId>,
    ) -> Result<(Grant, bool), NetError> {
        let now = self.shared.clock.now();
        let mut inner = lock(&self.shared);
        if let Some(grant) = inner.grants.live_grant(&identity, now).cloned() {
            if inner.unsaved {
                inner.persist()?;
            }
            return Ok((grant, true));
        }
        let new = NewGrant {
            identity,
            name,
            role: Role::owner(),
            authorizing_owner: self.shared.owner,
            expires_at: None,
            enrolled_by: receipt,
        };
        let (id, events) = inner
            .grants
            .add(new, now)
            .map_err(|e| NetError::Refused(e.to_string()))?;
        inner.apply_grant_events(events);
        let grant = inner
            .grants
            .get(id)
            .cloned()
            .ok_or_else(|| NetError::Refused("the new grant is missing".into()))?;
        inner.persist()?;
        Ok((grant, false))
    }

    /// Save the grant table now. A failure is reported as
    /// [`HostEvent::StoreFailed`] too.
    pub fn save(&self) -> Result<(), NetError> {
        lock(&self.shared).persist()
    }

    /// The name `PAIRED` sends from now on (1 to 128 bytes).
    pub fn set_name(&self, name: &str) -> Result<(), NetError> {
        validate_name(name).map_err(|e| NetError::Refused(e.to_string()))?;
        lock(&self.shared).pairing.set_host_name(name.to_owned());
        Ok(())
    }

    /// Whether the grant table has changes that are not saved yet.
    pub fn has_unsaved_changes(&self) -> bool {
        lock(&self.shared).unsaved
    }

    /// Stop serving: close every connection with `code`, and close every
    /// connection that registers until [`Host::resume`], also one whose
    /// handshake began before. Both happen under the lock connections
    /// register under, so none slips between them.
    pub fn pause(&self, code: ErrorCode) {
        let mut inner = lock(&self.shared);
        inner.paused = true;
        let conns: Vec<ConnectionId> = inner.conns.keys().copied().collect();
        for conn in conns {
            inner.close_conn(conn, code);
        }
    }

    /// Serve again after [`Host::pause`].
    pub fn resume(&self) {
        lock(&self.shared).paused = false;
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

/// Grant expiry, invitation expiry and the join-proof wait, every
/// [`IoLimits::clock_recheck_ms`](crate::limits::IoLimits::clock_recheck_ms).
async fn ticker<F: CodeExchangeFactory>(shared: Weak<Shared<F>>) {
    let Some(recheck) = shared
        .upgrade()
        .map(|shared| ms(shared.limits.io().clock_recheck_ms()))
    else {
        return;
    };
    let mut interval = tokio::time::interval(recheck);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let Some(shared) = shared.upgrade() else {
            return;
        };
        #[cfg(test)]
        if shared.ticker_paused.load(Ordering::SeqCst) {
            continue;
        }
        let now = shared.clock.now();
        let mono = shared.clock.mono();
        let mut inner = lock(&shared);
        inner.expire_grants(now);
        let actions = inner.pairing.tick(now);
        inner.apply(actions);
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
    /// The caller has opened a stream (a stream frame passed the gate).
    /// The host opens none before that (wire.md 8, step 4).
    caller_opened: bool,
}

impl<F: CodeExchangeFactory> HostRole<F> {
    fn check_locked(&mut self, traffic: Traffic) -> Verdict {
        let now = self.shared.clock.now();
        let mono = self.shared.clock.mono();
        let mut inner = lock(&self.shared);
        // The join-proof wait first: a proof that arrives after it is
        // refused even if the ticker has not run yet.
        if let Some(code) = inner
            .gates
            .get_mut(&self.conn)
            .and_then(|g| g.on_timeout(mono))
        {
            return Verdict::Close(code);
        }
        if !inner.serving() && !matches!(traffic, Traffic::Keepalive | Traffic::GoAway) {
            return Verdict::Close(ErrorCode::InternalError);
        }
        // Stream traffic needs the bound grant to be live now, not only when
        // the ticker last looked.
        if matches!(traffic, Traffic::Stream) && !inner.live_now(self.conn, now) {
            if let Some(GateState::Closed(code)) = inner.gates.get(&self.conn).map(|g| g.state()) {
                return Verdict::Close(*code);
            }
        }
        match inner.gates.get_mut(&self.conn) {
            Some(gate) => gate.check(traffic),
            None => Verdict::Close(ErrorCode::InternalError),
        }
    }
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
        let verdict = self.check_locked(traffic);
        if verdict == Verdict::Allow && matches!(traffic, Traffic::Stream) {
            self.caller_opened = true;
        }
        #[cfg(test)]
        if verdict == Verdict::Allow && matches!(traffic, Traffic::Pairing) {
            let hook = self
                .shared
                .after_pairing_check
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(mut hook) = hook {
                if !hook() {
                    *self
                        .shared
                        .after_pairing_check
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = Some(hook);
                }
            }
        }
        verdict
    }

    fn on_control(&mut self, message: ControlMessage, _out: &mut Outbox) {
        let shared = self.shared.clone();
        let clock = &*shared.clock;
        let mut guard = lock(&shared);
        let inner = &mut *guard;
        // The gate passed this message, but the lock was let go since: act
        // only if the gate still admits it now, under the lock the pairing
        // step runs under. A removal or denial that closed the connection
        // in between wins.
        let admitted = matches!(
            (inner.gates.get(&self.conn).map(|g| g.state()), &message),
            (
                Some(GateState::AwaitingJoinProof { .. } | GateState::Live { .. }),
                ControlMessage::JoinProof { .. }
            ) | (
                Some(GateState::JoinOnly { .. }),
                ControlMessage::CodeExchange { .. } | ControlMessage::CodeAbort { .. }
            )
        );
        if !admitted || !inner.serving() {
            return;
        }
        let before = inner.grants.clone();
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
        let actions = inner.commit_enrollment(before, actions);
        inner.apply(actions);
    }

    fn may_open(&self) -> bool {
        if !self.caller_opened {
            return false;
        }
        let now = self.shared.clock.now();
        let mut inner = lock(&self.shared);
        inner.serving() && inner.live_now(self.conn, now)
    }

    /// The join-proof deadline, so the driver checks it before it reads
    /// on, not only when the ticker runs.
    fn wake_at(&self) -> Option<Millis> {
        match lock(&self.shared).gates.get(&self.conn).map(|g| g.state()) {
            Some(GateState::AwaitingJoinProof { deadline }) => Some(*deadline),
            _ => None,
        }
    }

    fn on_wake(&mut self, mono: Millis, out: &mut Outbox) {
        let mut inner = lock(&self.shared);
        if let Some(code) = inner
            .gates
            .get_mut(&self.conn)
            .and_then(|g| g.on_timeout(mono))
        {
            out.close = Some(code);
        }
    }

    fn on_closed(&mut self, _reason: &CloseReason) {
        let shared = self.shared.clone();
        let mut inner = lock(&shared);
        inner.gates.remove(&self.conn);
        inner.conns.remove(&self.conn);
        inner.grants.unbind(self.conn);
        let actions = inner.pairing.on_connection_closed(self.conn);
        inner.apply(actions);
    }
}

#[cfg(test)]
mod tests {
    use mousse_net_core::grants::NewGrant;
    use mousse_net_core::identity::SoftwareKey;
    use mousse_net_core::mux::PriorityClass;
    use mousse_net_core::pairing::{Arrival, CpaceExchangeFactory, Ticket};

    use super::*;
    use crate::caller::Caller;
    use crate::clock::ManualClock;

    async fn within<T>(what: &str, fut: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(5), fut)
            .await
            .unwrap_or_else(|_| panic!("timed out: {what}"))
    }

    struct Live {
        host: Host,
        clock: Arc<ManualClock>,
        expires_at: UnixTime,
        hosted: Connection,
        dialled: Connection,
    }

    /// A caller with a grant that expires in a minute, connected to the
    /// host over an in-memory pipe.
    async fn live() -> Live {
        let clock = Arc::new(ManualClock::new());
        let owner = OwnerRef([1; OwnerRef::LEN]);
        let config = HostConfig {
            name: "desk".into(),
            state_dir: None,
            owner,
            limits: Limits::DEFAULT,
            clock: clock.clone(),
            ticket_identity: None,
            streams: None,
        };
        let key = Arc::new(SoftwareKey::generate(&mut os_rng()));
        let (host, _events) = Host::new(key, config, CpaceExchangeFactory).unwrap();
        let caller = Caller::new(
            Arc::new(SoftwareKey::generate(&mut os_rng())),
            Arc::new(ManualClock::new()),
            Limits::DEFAULT,
        );
        let now = clock.now();
        let expires_at = UnixTime(now.0 + 60);
        let grant = NewGrant {
            identity: caller.identity(),
            name: "laptop".into(),
            role: Role::owner(),
            authorizing_owner: owner,
            expires_at: Some(expires_at),
            enrolled_by: None,
        };
        lock(&host.shared).grants.add(grant, now).unwrap();
        let (a, b) = tokio::io::duplex(1 << 16);
        let (hosted, dialled) = tokio::join!(host.accept(a), caller.dial(b, host.identity()));
        Live {
            host,
            clock,
            expires_at,
            hosted: hosted.unwrap(),
            dialled: dialled.unwrap(),
        }
    }

    impl Live {
        /// The grant's expiry second arrives while the ticker is stopped.
        fn expire_without_the_ticker(&self) {
            self.host.shared.ticker_paused.store(true, Ordering::SeqCst);
            self.clock.freeze_at(self.expires_at);
        }
    }

    #[tokio::test]
    async fn a_stream_after_the_grant_expired_is_refused_without_the_ticker() {
        let live = live().await;
        let before = live
            .dialled
            .open_stream(PriorityClass::Interactive, "terminal")
            .await
            .unwrap();
        before.writer.write(b"in time").await.unwrap();
        assert!(within("the first stream", live.hosted.accept_stream())
            .await
            .is_some());

        live.expire_without_the_ticker();
        let after = live
            .dialled
            .open_stream(PriorityClass::Interactive, "terminal")
            .await
            .unwrap();
        let _ = after.writer.write(b"too late").await;
        assert!(
            within("no second stream", live.hosted.accept_stream())
                .await
                .is_none(),
            "a stream was admitted under an expired grant"
        );
        assert_eq!(
            within("closed", live.hosted.closed()).await,
            CloseReason::Local(ErrorCode::GrantRevoked)
        );
        assert_eq!(
            within("closed", live.dialled.closed()).await,
            CloseReason::Peer(ErrorCode::GrantRevoked)
        );
        assert!(live.host.grants().is_empty());
    }

    impl Live {
        /// The caller opens a stream and the host takes it.
        async fn caller_opens_one(&self) {
            let stream = self
                .dialled
                .open_stream(PriorityClass::Interactive, "terminal")
                .await
                .unwrap();
            stream.writer.write(b"first").await.unwrap();
            assert!(within("the caller's stream", self.hosted.accept_stream())
                .await
                .is_some());
        }
    }

    #[tokio::test]
    async fn the_host_opens_no_stream_before_the_caller_opened_one() {
        let live = live().await;
        assert!(live
            .hosted
            .open_stream(PriorityClass::Interactive, "terminal")
            .await
            .is_err());
        live.caller_opens_one().await;
        let stream = live
            .hosted
            .open_stream(PriorityClass::Interactive, "terminal")
            .await
            .unwrap();
        stream.writer.write(b"from the host").await.unwrap();
        assert!(within("the host's stream", live.dialled.accept_stream())
            .await
            .is_some());
    }

    #[tokio::test]
    async fn the_host_opens_no_stream_under_an_expired_grant() {
        let live = live().await;
        live.caller_opens_one().await;
        live.expire_without_the_ticker();
        assert!(live
            .hosted
            .open_stream(PriorityClass::Interactive, "terminal")
            .await
            .is_err());
        assert_eq!(
            within("closed", live.dialled.closed()).await,
            CloseReason::Peer(ErrorCode::GrantRevoked)
        );
        assert!(live.host.grants().is_empty());
    }

    /// A host whose grants live in `state_dir`, and its events.
    fn host_in(state_dir: Option<PathBuf>) -> (Host, mpsc::UnboundedReceiver<HostEvent>) {
        let config = HostConfig {
            name: "desk".into(),
            state_dir,
            owner: OwnerRef([1; OwnerRef::LEN]),
            limits: Limits::DEFAULT,
            clock: Arc::new(ManualClock::new()),
            ticket_identity: None,
            streams: None,
        };
        let key = Arc::new(SoftwareKey::generate(&mut os_rng()));
        Host::new(key, config, CpaceExchangeFactory).unwrap()
    }

    fn fresh_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mousse-host-{tag}-{}",
            crate::store::hex(&crate::rng::random_bytes::<6>())
        ))
    }

    fn new_caller() -> Caller {
        Caller::new(
            Arc::new(SoftwareKey::generate(&mut os_rng())),
            Arc::new(ManualClock::new()),
            Limits::DEFAULT,
        )
    }

    /// Grant `identity` in memory, as an earlier pairing would have.
    fn grant(host: &Host, identity: IdentityPublicKey) -> GrantId {
        let mut inner = lock(&host.shared);
        let now = host.shared.clock.now();
        let new = NewGrant {
            identity,
            name: "laptop".into(),
            role: Role::owner(),
            authorizing_owner: host.shared.owner,
            expires_at: None,
            enrolled_by: None,
        };
        inner.grants.add(new, now).unwrap().0
    }

    fn ticket(host: &Host, kind: InvitationKind) -> Ticket {
        let created = host.invite(kind, vec!["tcp://127.0.0.1:1".into()]).unwrap();
        Ticket::from_fragment(&created.fragment).unwrap()
    }

    fn granted(host: &Host, identity: &IdentityPublicKey) -> bool {
        host.grants().iter().any(|g| g.identity == *identity)
    }

    async fn next_request(events: &mut mpsc::UnboundedReceiver<HostEvent>) -> ApprovalRequest {
        loop {
            match within("approval request", events.recv()).await {
                Some(HostEvent::ApprovalRequested(request)) => return request,
                Some(_) => continue,
                None => panic!("host events ended"),
            }
        }
    }

    type Joined = Result<(Connection, crate::caller::JoinOutcome), NetError>;

    /// Join `host` in person over an in-memory pipe; `on_request` runs
    /// when the owner is asked. Returns how the join ended.
    async fn join_in_person(
        host: &Host,
        events: &mut mpsc::UnboundedReceiver<HostEvent>,
        caller: &Caller,
        on_request: impl FnOnce(ApprovalRequest),
    ) -> Joined {
        let ticket = ticket(host, InvitationKind::InPerson);
        let (a, b) = tokio::io::duplex(1 << 16);
        let accepting = host.clone();
        let accept = tokio::spawn(async move { accepting.accept(a).await });
        let join = caller.join(b, &ticket, Arrival::InAppScan, "laptop");
        tokio::pin!(join);
        let request = tokio::select! {
            request = next_request(events) => request,
            _ = &mut join => panic!("the join ended before the owner was asked"),
        };
        on_request(request);
        let result = within("join", join).await;
        accept.abort();
        result
    }

    fn refused_with(result: &Joined, code: ErrorCode) -> bool {
        matches!(result, Err(NetError::Closed(CloseReason::Peer(c))) if *c == code)
    }

    /// Approve an in-person join of `host` while saves fail as `table` and
    /// `pending` plan, with the host's ticker stopped so nothing retries a
    /// save. Returns how the join ended and the joining device.
    async fn enroll_failing(
        host: &Host,
        events: &mut mpsc::UnboundedReceiver<HostEvent>,
        dir: &std::path::Path,
        table: &[crate::private::faults::Fault],
        pending: &[crate::private::faults::Fault],
    ) -> (Joined, IdentityPublicKey) {
        host.shared.ticker_paused.store(true, Ordering::SeqCst);
        let caller = new_caller();
        let store = GrantStore::in_dir(dir);
        let result = join_in_person(host, events, &caller, |request| {
            crate::private::faults::plan_replaces(store.path(), table);
            crate::private::faults::plan_replaces(store.pending_path(), pending);
            host.approve(&request).unwrap();
        })
        .await;
        (result, caller.identity())
    }

    /// A device granted earlier and saved.
    fn saved_grant(host: &Host) -> IdentityPublicKey {
        let other = SoftwareKey::generate(&mut os_rng()).public_key();
        grant(host, other);
        lock(&host.shared).persist().unwrap();
        other
    }

    /// The enrollment's save fails with the table before it in force: the
    /// record not written, or landed without its sync; the table not
    /// written, or landed without its sync; the clear not written. The
    /// pairing fails, the host keeps serving the grants it had, and a
    /// restart honors none of the failed enrollment.
    #[tokio::test]
    async fn a_failed_enrollment_is_honored_neither_now_nor_after_a_restart() {
        use crate::private::faults::Fault;
        let cases: [(&[Fault], &[Fault]); 5] = [
            (&[Fault::BeforeRename], &[]),
            (&[Fault::AfterRename], &[]),
            (&[Fault::None], &[Fault::BeforeRename]),
            (&[Fault::None], &[Fault::AfterRename]),
            (&[Fault::None, Fault::BeforeRename], &[]),
        ];
        for (pending, table) in cases {
            let dir = fresh_dir("failed");
            let (host, mut events) = host_in(Some(dir.clone()));
            let other = saved_grant(&host);
            let (result, identity) = enroll_failing(&host, &mut events, &dir, table, pending).await;
            assert!(
                refused_with(&result, ErrorCode::InternalError),
                "{pending:?} {table:?}: {:?}",
                result.err()
            );
            assert!(!granted(&host, &identity));
            assert!(lock(&host.shared).serving());
            drop(host);
            let (host, _events) = host_in(Some(dir.clone()));
            assert!(!granted(&host, &identity), "{pending:?} {table:?}");
            assert!(granted(&host, &other));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// The clear landed but its sync failed: the enrollment is in force, as
    /// it would be after a restart, so the host keeps it but sends no
    /// `PAIRED` and serves nothing until a save works. Once the ticker
    /// saved, it serves again, and a restart keeps the enrollment.
    #[tokio::test]
    async fn an_unsettled_enrollment_is_kept_and_served_once_saved() {
        use crate::private::faults::Fault;
        let dir = fresh_dir("unsettled");
        let (host, mut events) = host_in(Some(dir.clone()));
        let other = new_caller();
        grant(&host, other.identity());
        lock(&host.shared).persist().unwrap();
        let (result, identity) = enroll_failing(
            &host,
            &mut events,
            &dir,
            &[],
            &[Fault::None, Fault::AfterRename],
        )
        .await;
        assert!(
            refused_with(&result, ErrorCode::InternalError),
            "{:?}",
            result.err()
        );
        assert!(granted(&host, &identity));
        assert!(!lock(&host.shared).serving());
        let (a, b) = tokio::io::duplex(1 << 16);
        let (hosted, _dialled) = tokio::join!(host.accept(a), other.dial(b, host.identity()));
        assert_eq!(
            within("refused", hosted.unwrap().closed()).await,
            CloseReason::Local(ErrorCode::InternalError)
        );

        host.shared.ticker_paused.store(false, Ordering::SeqCst);
        within("saved", async {
            while host.has_unsaved_changes() {
                tokio::time::sleep(ms(Limits::DEFAULT.io().clock_recheck_ms())).await;
            }
        })
        .await;
        assert!(lock(&host.shared).serving());
        let (a, b) = tokio::io::duplex(1 << 16);
        let (hosted, dialled) = tokio::join!(host.accept(a), other.dial(b, host.identity()));
        let (hosted, dialled) = (hosted.unwrap(), dialled.unwrap());
        let stream = dialled
            .open_stream(PriorityClass::Interactive, "terminal")
            .await
            .unwrap();
        stream.writer.write(b"back").await.unwrap();
        assert!(within("served again", hosted.accept_stream())
            .await
            .is_some());

        drop((hosted, dialled, stream));
        drop(host);
        let (host, _events) = host_in(Some(dir.clone()));
        assert!(granted(&host, &identity));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The clear landed unsynced and the host stopped before any save
    /// worked: the restarted host has the enrollment, as the stopped one
    /// did, and serves.
    #[tokio::test]
    async fn an_unsettled_enrollment_is_in_force_after_a_restart() {
        use crate::private::faults::Fault;
        let dir = fresh_dir("unsettled-restart");
        let (host, mut events) = host_in(Some(dir.clone()));
        let (_, identity) = enroll_failing(
            &host,
            &mut events,
            &dir,
            &[Fault::None, Fault::BeforeRename],
            &[Fault::None, Fault::AfterRename],
        )
        .await;
        assert!(granted(&host, &identity));
        // The retry fails too.
        assert!(lock(&host.shared).persist().is_err());
        drop(host);
        let (host, _events) = host_in(Some(dir.clone()));
        assert!(granted(&host, &identity));
        assert!(lock(&host.shared).serving());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// In person: the owner says yes after the device's grant was removed
    /// (which closed its connection). The approval is refused and no grant
    /// comes back.
    #[tokio::test]
    async fn an_approval_after_the_grant_was_removed_enrolls_nothing() {
        let (host, mut events) = host_in(None);
        let caller = new_caller();
        let old = grant(&host, caller.identity());
        let result = join_in_person(&host, &mut events, &caller, |request| {
            assert!(host.remove_grant(old).unwrap());
            assert!(host.approve(&request).is_err());
        })
        .await;
        assert!(result.is_err());
        assert!(!granted(&host, &caller.identity()));
    }

    /// The code the host shows, typed as soon as it is shown.
    struct ShownCode(mpsc::UnboundedReceiver<HostEvent>);

    impl crate::caller::CodeEntry for ShownCode {
        async fn code(&mut self, _retry: Option<u8>) -> Option<String> {
            loop {
                if let HostEvent::ShowCode { code, .. } = self.0.recv().await? {
                    return Some(code.as_str().to_owned());
                }
            }
        }
    }

    /// With a send link: the device's final code confirmation passes the
    /// gate, then its grant is removed before the message is handled. The
    /// removal wins: no grant is made again.
    #[tokio::test]
    async fn a_code_confirmation_racing_the_grant_removal_enrolls_nothing() {
        let (host, events) = host_in(None);
        let caller = new_caller();
        let old = grant(&host, caller.identity());
        let ticket = ticket(&host, InvitationKind::SendLink);
        // The joiner's second pairing message is its confirmation.
        let removing = host.clone();
        let mut seen = 0;
        *host.shared.after_pairing_check.lock().unwrap() = Some(Box::new(move || {
            seen += 1;
            if seen < 2 {
                return false;
            }
            assert!(removing.remove_grant(old).unwrap());
            true
        }));
        let (a, b) = tokio::io::duplex(1 << 16);
        let accepting = host.clone();
        let accept = tokio::spawn(async move { accepting.accept(a).await });
        let mut codes = ShownCode(events);
        let result = within(
            "join",
            caller.join_with_code(b, &ticket, Arrival::Link, "laptop", &mut codes),
        )
        .await;
        accept.abort();
        assert!(result.is_err());
        assert!(host.shared.after_pairing_check.lock().unwrap().is_none());
        assert!(!granted(&host, &caller.identity()));
    }
}
