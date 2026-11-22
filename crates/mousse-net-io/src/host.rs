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
//! Pre-auth admission (Phase 1b §6.2): a listener takes a place in its
//! kind's pool at accept ([`Host::admit`]) and hands it to
//! [`Host::accept_admitted`]; the host holds it until the connection is
//! live or closed, through join-only until the invitation ends. A granted
//! device's re-pair proof on a live connection takes a new place. The
//! admission fence ([`Host::set_fence`]) is checked under the lock at gate
//! registration, at enrollment and at a re-pair; setting it closes every
//! connection that is not live.
//!
//! A pairing message and the owner's approval act only if the connection's
//! gate still admits them under the same lock as the pairing step, so a
//! removal or denial that closed the connection in between wins. Deadlines
//! are checked before the traffic they bound: a join proof that arrives
//! after the join-proof wait is refused even before the ticker runs.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use mousse_net_core::authz::{ConnectionGate, GateState, Traffic, Verdict};
use mousse_net_core::control::{AuthorizedState, ControlMessage};
use mousse_net_core::grants::{
    validate_name, Denial, Grant, GrantError, GrantEvent, GrantId, GrantTable, NewGrant, OwnerRef,
    Role,
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
use tokio::sync::{mpsc, oneshot, watch};

use crate::admission::StreamAdmission;
use crate::certs::CertManager;
use crate::clock::Clock;
use crate::conn::{self, CloseReason, Cmd, ConnStatus, Connection, Outbox, Role as ConnRole};
use crate::endpoint::Endpoint;
use crate::error::NetError;
use crate::limits::{ms, Limits};
use crate::pipe::Pipe;
use crate::preauth::{ListenerKind, PreAuth, PreAuthFull, PreAuthSlot, PreAuthStats};
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
        /// Code attempts the invitation has left, this one's included.
        attempts_left: u8,
    },
    /// A device was paired.
    Enrolled {
        /// The invitation it used.
        invitation: InvitationId,
        /// Its new grant.
        grant: GrantId,
        /// The device.
        identity: IdentityPublicKey,
        /// The new grant's role.
        role: Role,
    },
    /// A grant's role was changed in place and saved ([`Host::set_role`]),
    /// or a role edit whose save had an unknown outcome was settled: the
    /// grant is served again, with this role and revision.
    RoleChanged {
        /// The grant.
        grant: GrantId,
        /// Its role now.
        role: Role,
        /// Its revision now.
        revision: u64,
    },
    /// An invitation ended without pairing.
    InvitationEnded {
        /// The invitation.
        invitation: InvitationId,
        /// Why.
        reason: ErrorCode,
    },
    /// Grant channels were closed (removed, expired or denied grant, or a
    /// role edit).
    ChannelsClosed {
        /// The grant.
        grant: GrantId,
        /// How many connections closed.
        connections: usize,
    },
    /// Saving the grant table failed. The change is live in memory.
    StoreFailed(String),
}

/// Why [`Host::admit`] gave no place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The admission fence is set.
    Fenced,
    /// The pool or the source's share is full.
    Full(PreAuthFull),
}

/// Why [`Host::set_role`] changed nothing, or did not settle.
#[derive(Debug)]
pub enum RoleEditError {
    /// No live grant has that id.
    NoGrant,
    /// The grant's revision is not the one the edit was made against.
    RevisionConflict,
    /// The edit cannot be made (a denied identity, or a revision that
    /// cannot grow).
    Refused(String),
    /// The host serves no grant until a save works.
    NotServing,
    /// Networking is paused: a removal failed to save.
    Paused,
    /// The save failed with the table as it was, on disk and in memory:
    /// nothing changed.
    NotSaved(NetError),
    /// The save failed after the new table may have reached the disk: the
    /// edit is in memory, and the grant is served under neither role until
    /// the stored table is read back or saved again
    /// ([`HostEvent::RoleChanged`] says when).
    Unsettled(NetError),
}

/// A role edit made by [`Host::edit_role`] whose closed connections may
/// still send what was queued before the edit.
#[must_use = "finish() waits until nothing queued under the old role can leave"]
pub struct RoleEditing {
    #[allow(clippy::type_complexity)]
    result: Result<(Grant, bool, Option<HostEvent>), RoleEditError>,
    fences: Vec<oneshot::Receiver<()>>,
    events: mpsc::UnboundedSender<HostEvent>,
}

impl RoleEditing {
    /// The grant as it is now and whether it changed, or the error, as
    /// [`RoleEditing::finish`] will return it.
    pub fn outcome(&self) -> Result<(&Grant, bool), &RoleEditError> {
        match &self.result {
            Ok((grant, changed, _)) => Ok((grant, *changed)),
            Err(e) => Err(e),
        }
    }

    /// Wait until every connection the edit closed has dropped its queue
    /// and finished the frame it was writing, then send
    /// [`HostEvent::RoleChanged`] and return the result.
    pub async fn finish(self) -> Result<(Grant, bool), RoleEditError> {
        for fence in self.fences {
            let _ = fence.await;
        }
        let (current, changed, event) = self.result?;
        if let Some(event) = event {
            let _ = self.events.send(event);
        }
        Ok((current, changed))
    }
}

impl std::fmt::Display for RoleEditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoGrant => f.write_str("no such grant"),
            Self::RevisionConflict => f.write_str("the grant changed since that revision"),
            Self::Refused(why) => f.write_str(why),
            Self::NotServing => f.write_str("grants are not served until a save works"),
            Self::Paused => f.write_str("networking is paused"),
            Self::NotSaved(e) => write!(f, "the change was not saved: {e}"),
            Self::Unsettled(e) => write!(f, "the change may not have been saved: {e}"),
        }
    }
}

/// Why [`Host::add_grant_connected`] did not answer with a saved grant.
#[derive(Debug)]
pub enum ConnectedGrantError {
    /// Networking is paused: a removal failed to save.
    Paused,
    /// The connection is closing, or (inbound) no grant of this computer
    /// serves it any more.
    Closing,
    /// The grant table refused the grant (the identity is denied).
    Refused(String),
    /// The grant is in effect but the table could not be saved; the host
    /// keeps retrying, and the call may be repeated.
    NotSaved(NetError),
}

impl std::fmt::Display for ConnectedGrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paused => f.write_str("networking is paused"),
            Self::Closing => f.write_str("the connection is closing"),
            Self::Refused(why) => f.write_str(why),
            Self::NotSaved(e) => write!(f, "the grant is in effect but saving it failed ({e})"),
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fenced => f.write_str("networking is paused"),
            Self::Full(full) => full.fmt(f),
        }
    }
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
    /// The admission fence ([`Host::set_fence`]): nothing new is admitted,
    /// enrolled or re-paired until it is cleared.
    paused: bool,
    /// Grants whose role edit was saved with an unknown outcome: neither
    /// role is served (no connection is live under them) until the stored
    /// table is read back or saved again.
    suspended: HashSet<GrantId>,
    /// Pre-auth places held by connections that are not live yet.
    slots: HashMap<ConnectionId, PreAuthSlot>,
    /// The listener kind of every registered connection.
    kinds: HashMap<ConnectionId, ListenerKind>,
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
    preauth: Arc<PreAuth>,
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

    /// Ask each of `conns`, closed already, to answer once nothing queued
    /// before the close can still leave ([`Cmd::Fence`]).
    fn fence_conns(&self, conns: &[ConnectionId], fences: &mut Vec<oneshot::Receiver<()>>) {
        for conn in conns {
            let (tx, rx) = oneshot::channel();
            self.send(*conn, Cmd::Fence(tx));
            fences.push(rx);
        }
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
                // The table in memory is the one on disk now.
                self.settle_roles();
                Ok(())
            }
            Err(e) => {
                self.unsaved = true;
                let _ = self.events.send(HostEvent::StoreFailed(e.to_string()));
                Err(e)
            }
        }
    }

    /// Whether grants may be served: no rolled-back enrollment is waiting
    /// to be saved away.
    fn serving(&self) -> bool {
        !self.reconcile
    }

    /// Serve the suspended grants again: the table in memory is known to
    /// be the stored one. Each gets [`HostEvent::RoleChanged`] with the
    /// role it is served under from now on.
    fn settle_roles(&mut self) {
        if self.suspended.is_empty() {
            return;
        }
        for id in std::mem::take(&mut self.suspended) {
            if let Some(g) = self.grants.get(id) {
                let _ = self.events.send(HostEvent::RoleChanged {
                    grant: id,
                    role: g.role.clone(),
                    revision: g.revision,
                });
            }
        }
        self.grants_gen.send_modify(|g| *g += 1);
    }

    /// For suspended grants: read the stored table back. Where it holds
    /// what is in memory, the edit is on disk (a load makes it durable
    /// first), and the grants are served again. Run by the ticker.
    fn reread_suspended(&mut self) {
        if self.suspended.is_empty() {
            return;
        }
        let Some(store) = &self.store else {
            self.settle_roles();
            return;
        };
        let Ok(stored) = store.load() else {
            return;
        };
        let same = self
            .suspended
            .iter()
            .all(|id| match (stored.get(*id), self.grants.get(*id)) {
                (Some(s), Some(m)) => s.role == m.role && s.revision == m.revision,
                (None, None) => true,
                _ => false,
            });
        if same {
            self.settle_roles();
        }
    }

    /// Whether `grant` waits for its role edit to settle.
    fn is_suspended(&self, grant: GrantId) -> bool {
        self.suspended.contains(&grant)
    }

    /// The grant `conn` is live under at `now`, if it is served
    /// ([`Host::grant_of`]).
    fn grant_of(&self, conn: ConnectionId, now: UnixTime) -> Option<&Grant> {
        let Some(GateState::Live { grant }) = self.gates.get(&conn).map(|g| g.state()) else {
            return None;
        };
        // Must-fail control (tests only): the gate alone decides.
        if cfg!(mousse_control = "grant-served-while-not-serving") {
            return (!self.is_suspended(*grant))
                .then(|| self.grants.get(*grant))
                .flatten();
        }
        let held = self.grants.get(*grant)?;
        self.grants
            .live_grant(&held.identity, now)
            .filter(|g| g.id == *grant && self.serving() && !self.is_suspended(g.id))
    }

    /// Whether the admission fence stops connections of `kind`.
    fn fenced(&self, kind: ListenerKind) -> bool {
        // Control (tests only): the fence covers TCP alone.
        self.paused && !(cfg!(mousse_control = "fence-tcp-only") && kind != ListenerKind::Tcp)
    }

    fn kind_of(&self, conn: ConnectionId) -> ListenerKind {
        self.kinds.get(&conn).copied().unwrap_or(ListenerKind::Tcp)
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
        if self.is_suspended(grant) {
            self.close_conn(conn, ErrorCode::InternalError);
            return false;
        }
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
                    ..
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
                        role,
                    } => {
                        let _ = self.events.send(HostEvent::Enrolled {
                            invitation,
                            grant,
                            identity,
                            role,
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

    fn set_fence(&mut self, on: bool) {
        self.paused = on;
        if !on {
            return;
        }
        let waiting: Vec<ConnectionId> = self
            .gates
            .iter()
            .filter(|(_, gate)| match gate.state() {
                GateState::Live { .. } | GateState::Closed(_) => false,
                // Control (tests only): join-only connections stay, so
                // only the check at enrollment could stop them.
                GateState::JoinOnly { .. } => !cfg!(mousse_control = "enroll-while-paused"),
                _ => true,
            })
            .map(|(conn, _)| *conn)
            .collect();
        for conn in waiting {
            self.close_conn(conn, ErrorCode::InternalError);
        }
    }

    fn apply(&mut self, actions: Vec<HostAction>) {
        let mut queue: VecDeque<HostAction> = actions.into();
        let mut persist = false;
        while let Some(action) = queue.pop_front() {
            match action {
                HostAction::Send { conn, message } => self.send(conn, Cmd::Control(message)),
                HostAction::Close { conn, code } => {
                    // Control (tests only): a join-only connection stays
                    // when its invitation ends.
                    let ended = matches!(
                        code,
                        ErrorCode::Cancelled
                            | ErrorCode::PairingDeclined
                            | ErrorCode::InvitationInvalid
                            | ErrorCode::AttemptsExhausted
                    );
                    let join_only = matches!(
                        self.gates.get(&conn).map(|g| g.state()),
                        Some(GateState::JoinOnly { .. })
                    );
                    if !(cfg!(mousse_control = "join-only-outlives-invitation")
                        && ended
                        && join_only)
                    {
                        self.close_conn(conn, code);
                    }
                }
                HostAction::AdmittedJoinOnly { conn, invitation } => {
                    if let Some(gate) = self.gates.get_mut(&conn) {
                        gate.admit_join_only(invitation);
                    }
                    if cfg!(mousse_control = "join-only-frees-slot") {
                        // Control (tests only): the place goes at join-only.
                        self.slots.remove(&conn);
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
                    let attempts_left = self.pairing.attempts_left(&invitation).unwrap_or(0);
                    let _ = self.events.send(HostEvent::ShowCode {
                        invitation,
                        code,
                        attempts_left,
                    });
                }
                HostAction::Enrolled {
                    invitation,
                    conn,
                    grant,
                    identity,
                    role,
                } => {
                    // Already saved by `commit_enrollment`.
                    if let Some(gate) = self.gates.get_mut(&conn) {
                        gate.promote(grant);
                    }
                    // Live: its pre-auth place is free again.
                    self.slots.remove(&conn);
                    self.send(conn, Cmd::Status(ConnStatus::Live));
                    let _ = self.events.send(HostEvent::Enrolled {
                        invitation,
                        grant,
                        identity,
                        role,
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
                suspended: HashSet::new(),
                slots: HashMap::new(),
                kinds: HashMap::new(),
                events,
                grants_gen: watch::channel(0).0,
            }),
            certs: CertManager::with_limits(signer, config.clock.clone(), &config.limits),
            clock: config.clock,
            policy: TlsPolicy::from_limits(&config.limits),
            streams: config
                .streams
                .unwrap_or_else(|| StreamAdmission::new(&config.limits)),
            preauth: PreAuth::new(config.limits.io()),
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

    /// A pre-auth place for a connection a listener of `kind` just
    /// accepted, before anything is read from it; `source` is the peer's
    /// address on TCP. Refused while the admission fence is set or the
    /// pool (or the source's share) is full.
    pub fn admit(
        &self,
        kind: ListenerKind,
        source: Option<IpAddr>,
    ) -> Result<PreAuthSlot, Refusal> {
        if lock(&self.shared).fenced(kind) {
            return Err(Refusal::Fenced);
        }
        self.shared
            .preauth
            .try_take(kind, source)
            .map_err(Refusal::Full)
    }

    /// Pre-auth places held and refused, per listener kind.
    pub fn preauth_stats(&self) -> PreAuthStats {
        self.shared.preauth.stats()
    }

    /// Run step 1 and step 2 on a new pipe and start its driver. A peer
    /// without a grant gets a connection that waits for a join proof. The
    /// connection counts as TCP and holds no pre-auth place; listeners use
    /// [`Host::accept_admitted`].
    pub async fn accept<P: Pipe>(&self, pipe: P) -> Result<Connection, NetError> {
        self.register(pipe, ListenerKind::Tcp, None).await
    }

    /// [`Host::accept`] for a connection that holds `slot`, taken by
    /// [`Host::admit`]. The place is held until the connection is live or
    /// closed.
    pub async fn accept_admitted<P: Pipe>(
        &self,
        pipe: P,
        slot: PreAuthSlot,
    ) -> Result<Connection, NetError> {
        let kind = slot.kind();
        self.register(pipe, kind, Some(slot)).await
    }

    async fn register<P: Pipe>(
        &self,
        pipe: P,
        kind: ListenerKind,
        slot: Option<PreAuthSlot>,
    ) -> Result<Connection, NetError> {
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
            // The fence at gate registration: a handshake that finished
            // after the fence was set is closed here, whenever its
            // listener let it in. Control (tests only): the listener's
            // check at accept is the only one.
            let fenced = inner.fenced(kind) && !cfg!(mousse_control = "fence-at-accept-only");
            // A grant whose role edit has not settled serves under neither
            // role.
            let suspended =
                matches!(gate.state(), GateState::Live { grant } if inner.is_suspended(*grant));
            if !inner.serving() || fenced || suspended {
                gate.close(ErrorCode::InternalError);
            }
            // A live connection's place is free at once; any other holds
            // it until it is live or closed.
            if let Some(slot) = slot {
                if !matches!(gate.state(), GateState::Live { .. }) {
                    inner.slots.insert(conn, slot);
                }
            }
            inner.kinds.insert(conn, kind);
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
    /// The device is granted the owner role.
    pub fn invite(
        &self,
        kind: InvitationKind,
        routes: Vec<String>,
    ) -> Result<CreatedInvitation, NetError> {
        self.invite_as(kind, routes, Role::owner())
    }

    /// [`Host::invite`], granting `role`. An in-person answer may choose
    /// another role for its device ([`Host::approve_as`]).
    pub fn invite_as(
        &self,
        kind: InvitationKind,
        routes: Vec<String>,
        role: Role,
    ) -> Result<CreatedInvitation, NetError> {
        let params = InvitationParams {
            kind,
            role,
            authorizing_owner: self.shared.owner,
            routes,
            grant_expires_at: None,
        };
        lock(&self.shared)
            .pairing
            .create(params, self.shared.clock.now(), &mut os_rng())
            .map_err(|e| NetError::Refused(e.to_string()))
    }

    /// A send-link invitation's code on show now and the attempts it has
    /// left; `None` once it is no longer open (or for an in-person one).
    pub fn invitation_code(&self, invitation: &InvitationId) -> Option<(PairingCode, u8)> {
        let inner = lock(&self.shared);
        let code = inner.pairing.code(invitation)?.clone();
        Some((code, inner.pairing.attempts_left(invitation)?))
    }

    /// Where an invitation stands.
    pub fn invitation_status(&self, invitation: &InvitationId) -> Option<InvitationStatus> {
        lock(&self.shared).pairing.status(invitation)
    }

    /// The owner said yes. The device gets the invitation's role.
    pub fn approve(&self, request: &ApprovalRequest) -> Result<(), NetError> {
        self.approve_as(request, None)
    }

    /// The owner said yes and chose `role` for the device (`None`: the
    /// invitation's role). The role goes to this enrollment only.
    pub fn approve_as(
        &self,
        request: &ApprovalRequest,
        role: Option<Role>,
    ) -> Result<(), NetError> {
        let mut inner = lock(&self.shared);
        let inner = &mut *inner;
        // Under the same lock as the enrollment: a removal, denial or close
        // that reached this connection first wins.
        let waiting = matches!(
            inner.gates.get(&request.conn).map(|g| g.state()),
            Some(GateState::JoinOnly { invitation }) if *invitation == request.invitation
        );
        // The fence at enrollment. Control (tests only): not checked.
        let fenced = inner.fenced(inner.kind_of(request.conn))
            && !cfg!(mousse_control = "enroll-while-paused");
        if !waiting || !inner.serving() || fenced {
            return Err(NetError::Refused(
                "the device's connection is no longer waiting for an answer".into(),
            ));
        }
        let before = inner.grants.clone();
        let actions = inner
            .pairing
            .approve_as(
                &request.invitation,
                request.conn,
                role,
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

    /// The grant `conn` is live under, if it is live, not expired and
    /// served: the host serves grants (no enrollment waits for a save to
    /// settle) and this one is not waiting for a role edit to settle.
    pub fn grant_of(&self, conn: ConnectionId) -> Option<Grant> {
        let now = self.shared.clock.now();
        lock(&self.shared).grant_of(conn, now).cloned()
    }

    /// Grant `identity`, the authenticated peer of `conn`, access to this
    /// computer with `role`, for `grant.add_connected`. Returns the grant
    /// and whether it existed; an existing grant is returned as it is,
    /// never widened or narrowed.
    ///
    /// Under the host's lock: refused while networking is paused; the
    /// grant is committed under a [`crate::LivePermit`] of `conn`, so never
    /// on a connection that started to close; an inbound connection is
    /// answered with the grant it is live under, if this computer still
    /// serves it. The table is saved before success is returned, also when
    /// the grant existed and an earlier save failed.
    pub fn add_grant_connected(
        &self,
        conn: &Connection,
        inbound: bool,
        identity: IdentityPublicKey,
        name: String,
        role: Role,
    ) -> Result<(Grant, bool), ConnectedGrantError> {
        let now = self.shared.clock.now();
        let mut inner = lock(&self.shared);
        // Must-fail controls (tests only): the commit ignores the pause,
        // the connection's liveness, or an earlier failed save.
        if inner.paused && !cfg!(mousse_control = "connected-grant-while-paused") {
            return Err(ConnectedGrantError::Paused);
        }
        let any_conn = cfg!(mousse_control = "grant-from-stale-connection");
        let permit = conn.live_permit();
        if permit.is_none() && !any_conn {
            return Err(ConnectedGrantError::Closing);
        }
        let existing = if inbound {
            // Live only under a grant of this computer: that grant is the
            // answer, and no grant means the connection is ending.
            match inner.grant_of(conn.id(), now) {
                Some(grant) if grant.identity == identity => Some(grant.clone()),
                _ if !any_conn => return Err(ConnectedGrantError::Closing),
                _ => None,
            }
        } else {
            inner.grants.live_grant(&identity, now).cloned()
        };
        if let Some(grant) = existing {
            drop(permit);
            if inner.unsaved && !cfg!(mousse_control = "connected-grant-answers-unsaved") {
                inner.persist().map_err(ConnectedGrantError::NotSaved)?;
            }
            return Ok((grant, true));
        }
        let new = NewGrant {
            identity,
            name,
            role,
            authorizing_owner: self.shared.owner,
            expires_at: None,
            enrolled_by: None,
        };
        let (id, events) = inner
            .grants
            .add(new, now)
            .map_err(|e| ConnectedGrantError::Refused(e.to_string()))?;
        inner.apply_grant_events(events);
        // The grant is in effect: the connection may close from here on.
        drop(permit);
        let grant = inner
            .grants
            .get(id)
            .cloned()
            .ok_or_else(|| ConnectedGrantError::Refused("the new grant is missing".into()))?;
        inner.persist().map_err(ConnectedGrantError::NotSaved)?;
        Ok((grant, false))
    }

    /// The live grant `identity` holds on this endpoint, if any and if it
    /// is served: the host serves grants (no enrollment waits for a save
    /// to settle) and this one is not waiting for a role edit to settle.
    pub fn live_grant(&self, identity: &IdentityPublicKey) -> Option<Grant> {
        let now = self.shared.clock.now();
        let inner = lock(&self.shared);
        let serving = inner.serving() || cfg!(mousse_control = "grant-served-while-not-serving");
        inner
            .grants
            .live_grant(identity, now)
            .filter(|g| serving && !inner.is_suspended(g.id))
            .cloned()
    }

    /// Whether `grant` waits for its last role edit to settle (a save
    /// whose outcome is unknown): it exists, and is served under neither
    /// role until the stored table is read back or saved again.
    pub fn is_suspended(&self, grant: GrantId) -> bool {
        lock(&self.shared).is_suspended(grant)
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
        // A signer whose grant waits for its role edit to settle holds no
        // served owner grant: refused like one without a grant, before the
        // journal is looked at.
        let signer = signed.removal().signer;
        if inner
            .grants
            .live_grant(&signer, now)
            .is_some_and(|g| inner.is_suspended(g.id))
        {
            return Ok(AppliedRemoval {
                decision: Decision::Refuse,
                saved: Ok(()),
            });
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
            if saved.is_err() {
                // The caller pauses networking; the fence goes up under
                // this lock already, so no role edit commits between.
                inner.set_fence(true);
            }
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
        self.add_grant_as(identity, name, receipt, None)
    }

    /// [`Host::add_grant`] with the role of a new grant (`None`: owner, as
    /// [`Host::add_grant`]). An existing live grant is returned as it is,
    /// with its own role: it is never widened or narrowed here.
    pub fn add_grant_as(
        &self,
        identity: IdentityPublicKey,
        name: String,
        receipt: Option<InvitationId>,
        role: Option<Role>,
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
            role: role.unwrap_or_else(Role::owner),
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

    /// Change the role of grant `grant` in place, if its revision is still
    /// `expected_revision`. Returns the grant as it is now and whether it
    /// changed; the same role at the current revision changes nothing.
    ///
    /// The check, the save and admission run under one lock. The edit is
    /// saved before it takes effect: only after the save works are the
    /// grant's connections closed with `CANCELLED`
    /// ([`HostEvent::ChannelsClosed`]) and [`HostEvent::RoleChanged`]
    /// sent. A save that failed with the old table in place changes
    /// nothing. A save whose outcome is unknown keeps the edit in memory,
    /// closes the grant's connections and serves the grant under neither
    /// role until the stored table is read back or saved again; the caller
    /// is told [`RoleEditError::Unsettled`], never that the edit is done.
    /// A grant waiting so is saved again first on the next edit.
    ///
    /// Before it returns, every connection the edit closed has dropped
    /// what was queued on it: nothing queued under the old role (a
    /// `mousse-grants` list, say) is sent after the caller hears the
    /// result. While the admission fence is set (a removal failed to
    /// save) nothing is edited: [`RoleEditError::Paused`].
    pub async fn set_role(
        &self,
        grant: GrantId,
        expected_revision: u64,
        role: Role,
    ) -> Result<(Grant, bool), RoleEditError> {
        self.edit_role(grant, expected_revision, role)
            .finish()
            .await
    }

    /// [`Host::set_role`] in two steps, for a caller that cuts paths of its
    /// own between them: this one commits (or not) and closes the
    /// connections, [`RoleEditing::finish`] waits for their fences and
    /// gives the result. [`RoleEditing::outcome`] reads it before.
    pub fn edit_role(&self, grant: GrantId, expected_revision: u64, role: Role) -> RoleEditing {
        let mut fences = Vec::new();
        let result = self.set_role_locked(grant, expected_revision, role, &mut fences);
        RoleEditing {
            result,
            fences,
            events: lock(&self.shared).events.clone(),
        }
    }

    /// [`Host::set_role`] under the lock. `fences` gets one receiver per
    /// connection closed; [`HostEvent::RoleChanged`] comes back to send
    /// once they are answered.
    #[allow(clippy::type_complexity)]
    fn set_role_locked(
        &self,
        grant: GrantId,
        expected_revision: u64,
        role: Role,
        fences: &mut Vec<oneshot::Receiver<()>>,
    ) -> Result<(Grant, bool, Option<HostEvent>), RoleEditError> {
        let now = self.shared.clock.now();
        let mut guard = lock(&self.shared);
        let inner = &mut *guard;
        if !inner.serving() {
            return Err(RoleEditError::NotServing);
        }
        // Must-fail control (tests only): an edit commits while a removal
        // that failed to save holds networking paused.
        if inner.paused && !cfg!(mousse_control = "role-edit-while-paused") {
            return Err(RoleEditError::Paused);
        }
        if inner.is_suspended(grant) {
            // Nothing is acknowledged about this grant until its last edit
            // is known to be on disk.
            inner.persist().map_err(RoleEditError::Unsettled)?;
        }
        let mut table = inner.grants.clone();
        let edit = table
            .set_role(grant, expected_revision, role, now)
            .map_err(|e| match e {
                GrantError::UnknownGrant => RoleEditError::NoGrant,
                GrantError::RevisionConflict => RoleEditError::RevisionConflict,
                other => RoleEditError::Refused(other.to_string()),
            })?;
        let current = |table: &GrantTable| table.get(grant).cloned().ok_or(RoleEditError::NoGrant);
        if !edit.changed {
            return Ok((current(&inner.grants)?, false, None));
        }
        let events = edit.events;
        let saved = match &inner.store {
            Some(store) => store.save_checked(&table),
            None => Ok(()),
        };
        let closed: Vec<ConnectionId> = events
            .iter()
            .flat_map(|GrantEvent::CloseChannels { channels, .. }| channels.iter().copied())
            .collect();
        match saved {
            Ok(()) => {
                inner.grants = table;
                inner.unsaved = false;
                inner.apply_grant_events(events);
                inner.fence_conns(&closed, fences);
                inner.grants_gen.send_modify(|g| *g += 1);
                // The whole table is on disk: earlier unsettled edits too.
                inner.settle_roles();
                let event = HostEvent::RoleChanged {
                    grant,
                    role: edit.role,
                    revision: edit.revision,
                };
                Ok((current(&inner.grants)?, true, Some(event)))
            }
            Err(failure) if !failure.in_place => {
                let _ = inner
                    .events
                    .send(HostEvent::StoreFailed(failure.error.to_string()));
                Err(RoleEditError::NotSaved(failure.error))
            }
            Err(failure) => {
                // The new table may be on disk, or not: a restart could
                // come back with either role, so neither is served.
                let _ = inner
                    .events
                    .send(HostEvent::StoreFailed(failure.error.to_string()));
                inner.grants = table;
                inner.unsaved = true;
                inner.suspended.insert(grant);
                inner.apply_grant_events(events);
                let bound: Vec<ConnectionId> = inner
                    .gates
                    .iter()
                    .filter(
                        |(_, g)| matches!(g.state(), GateState::Live { grant: b } if *b == grant),
                    )
                    .map(|(c, _)| *c)
                    .collect();
                for conn in &bound {
                    inner.close_conn(*conn, ErrorCode::InternalError);
                }
                inner.fence_conns(&closed, fences);
                inner.fence_conns(&bound, fences);
                inner.grants_gen.send_modify(|g| *g += 1);
                Err(RoleEditError::Unsettled(failure.error))
            }
        }
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

    /// Set or clear the admission fence. While it is set, listeners get no
    /// place ([`Host::admit`]), a connection registering after its
    /// handshake is closed, no grant is enrolled and no live connection
    /// re-pairs. Setting it closes every registered connection that is not
    /// live, join-only ones included, under the lock connections register
    /// under, so none slips between. Live connections stay.
    pub fn set_fence(&self, on: bool) {
        let mut inner = lock(&self.shared);
        inner.set_fence(on);
    }

    /// Whether the admission fence is set.
    pub fn fence_set(&self) -> bool {
        lock(&self.shared).paused
    }

    /// Whether the admission fence stops connections of `kind` now: the
    /// `ws` upgrade answers 503 when it does (Phase 1b §4.1).
    pub fn fence_covers(&self, kind: ListenerKind) -> bool {
        lock(&self.shared).fenced(kind)
    }

    /// Stop serving: set the admission fence and close every connection
    /// with `code`, under one lock.
    pub fn pause(&self, code: ErrorCode) {
        let mut inner = lock(&self.shared);
        inner.set_fence(true);
        let conns: Vec<ConnectionId> = inner.conns.keys().copied().collect();
        for conn in conns {
            inner.close_conn(conn, code);
        }
    }

    /// Serve again after [`Host::pause`]: clear the fence.
    pub fn resume(&self) {
        self.set_fence(false);
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
        inner.reread_suspended();
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
        let kind = inner.kind_of(self.conn);
        let from_live = matches!(
            inner.gates.get(&self.conn).map(|g| g.state()),
            Some(GateState::Live { .. })
        );
        let mut repair_slot = None;
        match &message {
            // A re-pair from live (§6.2): the fence, then a new place from
            // the kind's pool. Without either the proof opens nothing and
            // the connection stays live under its grant.
            ControlMessage::JoinProof { .. } if from_live => {
                let fenced = inner.fenced(kind) && !cfg!(mousse_control = "repair-skips-fence");
                let slot = if fenced {
                    None
                } else if cfg!(mousse_control = "repair-skips-slot") {
                    Some(None)
                } else {
                    self.shared.preauth.try_take_again(kind).ok().map(Some)
                };
                match slot {
                    Some(slot) => repair_slot = slot,
                    None => {
                        inner.send(
                            self.conn,
                            Cmd::Control(ControlMessage::Authorized {
                                state: AuthorizedState::Live,
                            }),
                        );
                        return;
                    }
                }
            }
            // A connection still waiting for its proof was closed when the
            // fence was set; this covers one that was not.
            ControlMessage::JoinProof { .. } if inner.fenced(kind) => return,
            // A finished code exchange enrolls: the fence at enrollment.
            // Control (tests only): not checked.
            ControlMessage::CodeExchange { .. }
                if inner.fenced(kind) && !cfg!(mousse_control = "enroll-while-paused") =>
            {
                return
            }
            _ => {}
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
        if let Some(slot) = repair_slot {
            let admitted = actions.iter().any(
                |a| matches!(a, HostAction::AdmittedJoinOnly { conn, .. } if *conn == self.conn),
            );
            if admitted {
                inner.slots.insert(self.conn, slot);
            }
        }
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
        inner.slots.remove(&self.conn);
        inner.kinds.remove(&self.conn);
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

    /// Once the grant expired, the connection it is live under reads no
    /// grant, though nothing swept the gate yet (the ticker is stopped): a
    /// stream accepted just before the expiry is not served after it.
    #[tokio::test]
    async fn an_expired_grant_is_not_the_grant_of_its_connection() {
        let live = live().await;
        let grant = live.host.grant_of(live.hosted.id());
        assert!(grant.is_some());
        live.expire_without_the_ticker();
        assert_eq!(live.host.grant_of(live.hosted.id()), None);
        assert!(live.host.live_grant(&grant.unwrap().identity).is_none());
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
        // Nothing is served meanwhile: no grant reads as live, for a
        // stream on a connection of this computer's own either.
        assert!(host.live_grant(&other.identity()).is_none());
        assert!(host.live_grant(&identity).is_none());
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
        assert!(host.live_grant(&other.identity()).is_some());
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

    fn role(name: &str) -> Role {
        Role::new(name).unwrap()
    }

    /// The role and revision `identity`'s grant has in `host`.
    fn role_of(host: &Host, identity: &IdentityPublicKey) -> Option<(String, u64)> {
        host.grants()
            .into_iter()
            .find(|g| g.identity == *identity)
            .map(|g| (g.role.as_str().to_owned(), g.revision))
    }

    /// A caller granted in `host` (saved) and connected live to it.
    async fn connected(host: &Host) -> (Caller, GrantId, Connection, Connection) {
        let caller = new_caller();
        let id = grant(host, caller.identity());
        lock(&host.shared).persist().unwrap();
        let (a, b) = tokio::io::duplex(1 << 16);
        let (hosted, dialled) = tokio::join!(host.accept(a), caller.dial(b, host.identity()));
        (caller, id, hosted.unwrap(), dialled.unwrap())
    }

    /// The next event that is not about approvals, codes or closed
    /// channels.
    async fn next_role_event(events: &mut mpsc::UnboundedReceiver<HostEvent>) -> HostEvent {
        loop {
            match within("host event", events.recv()).await {
                Some(e @ (HostEvent::RoleChanged { .. } | HostEvent::Enrolled { .. })) => return e,
                Some(_) => continue,
                None => panic!("host events ended"),
            }
        }
    }

    /// In person, the owner's answer chooses the role: the grant, the
    /// `PAIRED` the device gets and the enrollment event all carry it, not
    /// the invitation's.
    #[tokio::test]
    async fn an_in_person_answer_chooses_the_role_of_its_grant() {
        let (host, mut events) = host_in(None);
        let caller = new_caller();
        let created = host
            .invite_as(
                InvitationKind::InPerson,
                vec!["tcp://127.0.0.1:1".into()],
                role("client"),
            )
            .unwrap();
        let ticket = Ticket::from_fragment(&created.fragment).unwrap();
        let (a, b) = tokio::io::duplex(1 << 16);
        let accepting = host.clone();
        let accept = tokio::spawn(async move { accepting.accept(a).await });
        let join = caller.join(b, &ticket, Arrival::InAppScan, "laptop");
        tokio::pin!(join);
        let request = tokio::select! {
            request = next_request(&mut events) => request,
            _ = &mut join => panic!("the join ended before the owner was asked"),
        };
        host.approve_as(&request, Some(role("member"))).unwrap();
        let (_conn, outcome) = within("join", join).await.unwrap();
        accept.abort();
        match outcome {
            crate::caller::JoinOutcome::Paired(paired) => {
                assert_eq!(paired.role.as_str(), "member")
            }
            other => panic!("not paired: {other:?}"),
        }
        assert_eq!(
            role_of(&host, &caller.identity()),
            Some(("member".into(), 1))
        );
        match next_role_event(&mut events).await {
            HostEvent::Enrolled { role, .. } => assert_eq!(role.as_str(), "member"),
            other => panic!("{other:?}"),
        }
    }

    /// `grant.add` with a role makes a grant with it; an existing grant is
    /// returned with its own role, never widened.
    #[tokio::test]
    async fn adding_a_grant_takes_its_role_and_never_changes_an_existing_one() {
        let (host, _events) = host_in(None);
        let device = SoftwareKey::generate(&mut os_rng()).public_key();
        let (made, already) = host
            .add_grant_as(device, "phone".into(), None, Some(role("viewer")))
            .unwrap();
        assert!(!already);
        assert_eq!(made.role.as_str(), "viewer");
        let (again, already) = host
            .add_grant_as(device, "phone".into(), None, Some(Role::owner()))
            .unwrap();
        assert!(already);
        assert_eq!((again.id, again.role.as_str()), (made.id, "viewer"));
        let (plain, _) = host.add_grant(device, "phone".into(), None).unwrap();
        assert_eq!(plain.role.as_str(), "viewer");
    }

    /// A role edit is saved, then takes effect in place: same grant id,
    /// revision 2, its connection closed with `CANCELLED` (not
    /// `GRANT_REVOKED`), and a restart keeps it.
    #[tokio::test]
    async fn a_role_edit_is_saved_kept_in_place_and_closes_with_cancelled() {
        let dir = fresh_dir("role-edit");
        let (host, mut events) = host_in(Some(dir.clone()));
        let (caller, id, hosted, dialled) = connected(&host).await;
        let (now, changed) = host.set_role(id, 1, role("viewer")).await.unwrap();
        assert!(changed);
        assert_eq!((now.id, now.role.as_str(), now.revision), (id, "viewer", 2));
        assert_eq!(
            within("closed", dialled.closed()).await,
            CloseReason::Peer(ErrorCode::Cancelled)
        );
        drop(hosted);
        assert_eq!(
            next_role_event(&mut events).await,
            HostEvent::RoleChanged {
                grant: id,
                role: role("viewer"),
                revision: 2
            }
        );
        drop(host);
        let (host, _events) = host_in(Some(dir.clone()));
        assert_eq!(
            role_of(&host, &caller.identity()),
            Some(("viewer".into(), 2))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stale revision changes nothing and closes nothing; the same role
    /// at the current revision is no change.
    #[tokio::test]
    async fn a_stale_role_edit_changes_nothing() {
        let (host, _events) = host_in(None);
        let (caller, id, _hosted, dialled) = connected(&host).await;
        assert!(host.set_role(id, 1, role("viewer")).await.unwrap().1);
        assert!(matches!(
            host.set_role(id, 1, Role::owner()).await,
            Err(RoleEditError::RevisionConflict)
        ));
        assert_eq!(
            role_of(&host, &caller.identity()),
            Some(("viewer".into(), 2))
        );
        let (now, changed) = host.set_role(id, 2, role("viewer")).await.unwrap();
        assert!(!changed);
        assert_eq!(now.revision, 2);
        assert!(matches!(
            host.set_role(GrantId(999), 1, role("viewer")).await,
            Err(RoleEditError::NoGrant)
        ));
        drop(dialled);
    }

    /// The save fails with the old table in place: nothing changes, in
    /// memory, on disk or on the wire.
    #[tokio::test]
    async fn a_role_edit_whose_save_failed_changes_nothing() {
        use crate::private::faults::{plan_replaces, Fault};
        let dir = fresh_dir("role-not-saved");
        let (host, _events) = host_in(Some(dir.clone()));
        let (caller, id, hosted, dialled) = connected(&host).await;
        plan_replaces(GrantStore::in_dir(&dir).path(), &[Fault::BeforeRename]);
        assert!(matches!(
            host.set_role(id, 1, role("viewer")).await,
            Err(RoleEditError::NotSaved(_))
        ));
        assert_eq!(
            role_of(&host, &caller.identity()),
            Some(("owner".into(), 1))
        );
        let stream = dialled
            .open_stream(PriorityClass::Interactive, "terminal")
            .await
            .unwrap();
        stream.writer.write(b"still").await.unwrap();
        assert!(within("still served", hosted.accept_stream())
            .await
            .is_some());
        drop(host);
        let (host, _events) = host_in(Some(dir.clone()));
        assert_eq!(
            role_of(&host, &caller.identity()),
            Some(("owner".into(), 1))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The save's outcome is unknown (the rename landed, its sync failed):
    /// the edit is not acknowledged, the grant is served under neither role
    /// (its connection closes, a new one is refused, it has no served
    /// grant) until the stored table is read back, and then under the
    /// stored role.
    #[tokio::test]
    async fn a_role_edit_with_an_unknown_outcome_serves_neither_role_until_read_back() {
        use crate::private::faults::{plan_replaces, Fault};
        let dir = fresh_dir("role-unsettled");
        let (host, mut events) = host_in(Some(dir.clone()));
        host.shared.ticker_paused.store(true, Ordering::SeqCst);
        let (caller, id, _hosted, dialled) = connected(&host).await;
        plan_replaces(GrantStore::in_dir(&dir).path(), &[Fault::AfterRename]);
        assert!(matches!(
            host.set_role(id, 1, role("viewer")).await,
            Err(RoleEditError::Unsettled(_))
        ));
        assert!(within("closed", dialled.closed()).await != CloseReason::PipeClosed);
        assert!(host.live_grant(&caller.identity()).is_none());
        let (a, b) = tokio::io::duplex(1 << 16);
        let (hosted, _dialled) = tokio::join!(host.accept(a), caller.dial(b, host.identity()));
        let hosted = hosted.unwrap();
        assert_eq!(host.grant_of(hosted.id()), None);
        assert_eq!(
            within("refused", hosted.closed()).await,
            CloseReason::Local(ErrorCode::InternalError)
        );

        host.shared.ticker_paused.store(false, Ordering::SeqCst);
        assert_eq!(
            next_role_event(&mut events).await,
            HostEvent::RoleChanged {
                grant: id,
                role: role("viewer"),
                revision: 2
            }
        );
        let served = host.live_grant(&caller.identity()).unwrap();
        assert_eq!((served.role.as_str(), served.revision), ("viewer", 2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A removal signed by a device whose owner grant was narrowed is
    /// refused: a fresh one, one signed before the edit, and a resend of a
    /// journaled one, which is refused before the journal is looked at.
    #[tokio::test]
    async fn a_demoted_signer_cannot_remove() {
        use mousse_net_core::removal::{Removal, RemovalId, RemovalResult};
        let (host, _events) = host_in(None);
        let admin = SoftwareKey::generate(&mut os_rng());
        let admin_grant = grant(&host, admin.public_key());
        let target = new_caller();
        let target_grant = grant(&host, target.identity());
        let signed = |id: u8| {
            let record = Removal {
                signer: admin.public_key(),
                recipient: host.identity(),
                removed: target.identity(),
                grant: target_grant,
                id: RemovalId([id; 16]),
                issued_at: host.shared.clock.now(),
            };
            SignedRemoval::sign(record, &admin).unwrap()
        };
        let earlier = signed(1);
        let journaled = Journaled {
            record_hash: earlier.record_hash(),
            result: RemovalResult::Applied,
        };
        assert!(
            host.set_role(admin_grant, 1, role("member"))
                .await
                .unwrap()
                .1
        );
        for (removal, known) in [
            (signed(2), None),
            (earlier.clone(), None),
            (earlier, Some(journaled)),
        ] {
            let applied = host
                .apply_removal(&removal, 3600, |_| known, |_| Ok(()))
                .unwrap();
            assert_eq!(applied.decision, Decision::Refuse);
        }
        assert!(granted(&host, &target.identity()));
    }

    /// A signer promoted to owner by an edit whose save's outcome is
    /// unknown holds no served owner grant: its removal is refused although
    /// the table in memory says owner.
    #[tokio::test]
    async fn a_signer_whose_promotion_has_not_settled_cannot_remove() {
        use crate::private::faults::{plan_replaces, Fault};
        use mousse_net_core::removal::{Removal, RemovalId};
        let dir = fresh_dir("role-unsettled-signer");
        let (host, _events) = host_in(Some(dir.clone()));
        host.shared.ticker_paused.store(true, Ordering::SeqCst);
        let admin = SoftwareKey::generate(&mut os_rng());
        let (admin_grant, _) = host
            .add_grant_as(
                admin.public_key(),
                "tablet".into(),
                None,
                Some(role("member")),
            )
            .unwrap();
        let target = new_caller();
        let target_grant = grant(&host, target.identity());
        lock(&host.shared).persist().unwrap();
        plan_replaces(GrantStore::in_dir(&dir).path(), &[Fault::AfterRename]);
        assert!(matches!(
            host.set_role(admin_grant.id, 1, Role::owner()).await,
            Err(RoleEditError::Unsettled(_))
        ));
        assert_eq!(
            role_of(&host, &admin.public_key()),
            Some(("owner".into(), 2))
        );
        let record = Removal {
            signer: admin.public_key(),
            recipient: host.identity(),
            removed: target.identity(),
            grant: target_grant,
            id: RemovalId([3; 16]),
            issued_at: host.shared.clock.now(),
        };
        let removal = SignedRemoval::sign(record, &admin).unwrap();
        let applied = host
            .apply_removal(&removal, 3600, |_| None, |_| Ok(()))
            .unwrap();
        assert_eq!(applied.decision, Decision::Refuse);
        assert!(granted(&host, &target.identity()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A signed removal whose save fails sets the admission fence under
    /// the lock it saved under: a role edit after it is refused as paused,
    /// before the caller pauses networking, and changes nothing.
    #[tokio::test]
    async fn a_role_edit_after_a_removal_failed_to_save_is_paused() {
        use crate::private::faults::{plan_replaces, Fault};
        use mousse_net_core::removal::{Removal, RemovalId, RemovalResult};
        let dir = fresh_dir("role-edit-paused");
        let (host, _events) = host_in(Some(dir.clone()));
        host.shared.ticker_paused.store(true, Ordering::SeqCst);
        let admin = SoftwareKey::generate(&mut os_rng());
        host.add_grant_as(admin.public_key(), "tablet".into(), None, None)
            .unwrap();
        let target = new_caller();
        let target_grant = grant(&host, target.identity());
        let other = new_caller();
        let other_grant = grant(&host, other.identity());
        lock(&host.shared).persist().unwrap();
        let record = Removal {
            signer: admin.public_key(),
            recipient: host.identity(),
            removed: target.identity(),
            grant: target_grant,
            id: RemovalId([4; 16]),
            issued_at: host.shared.clock.now(),
        };
        let removal = SignedRemoval::sign(record, &admin).unwrap();
        plan_replaces(GrantStore::in_dir(&dir).path(), &[Fault::BeforeRename]);
        let applied = host
            .apply_removal(&removal, 3600, |_| None, |_| Ok(()))
            .unwrap();
        assert_eq!(applied.decision.result(), RemovalResult::Applied);
        assert!(applied.saved.is_err());
        assert!(host.fence_set());
        assert!(matches!(
            host.set_role(other_grant, 1, role("viewer")).await,
            Err(RoleEditError::Paused)
        ));
        assert_eq!(role_of(&host, &other.identity()), Some(("owner".into(), 1)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A grant for a connection's peer is refused while networking is
    /// paused, checked under the lock a failed removal sets the fence
    /// under; the connection stays live and nothing is granted.
    #[tokio::test]
    async fn a_connected_grant_is_refused_while_paused() {
        let (host, _events) = host_in(None);
        let (_caller, _id, hosted, _dialled) = connected(&host).await;
        let other = new_caller();
        host.set_fence(true);
        assert!(matches!(
            host.add_grant_connected(&hosted, false, other.identity(), "x".into(), role("viewer")),
            Err(ConnectedGrantError::Paused)
        ));
        assert!(host.live_grant(&other.identity()).is_none());
    }

    /// The peer's `GOAWAY` makes its connection closing at once, before the
    /// driver is done and while the gate still reads live: no grant is
    /// committed on it, nor is the grant it is live under answered.
    #[tokio::test]
    async fn no_grant_is_made_or_answered_on_a_connection_the_peer_is_closing() {
        let (host, _events) = host_in(None);
        let (caller, _id, hosted, dialled) = connected(&host).await;
        dialled.close(ErrorCode::NoError);
        within("closing", async {
            while !hosted.is_closing() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        let other = new_caller();
        assert!(matches!(
            host.add_grant_connected(&hosted, false, other.identity(), "x".into(), role("viewer")),
            Err(ConnectedGrantError::Closing)
        ));
        assert!(host.live_grant(&other.identity()).is_none());
        assert!(matches!(
            host.add_grant_connected(&hosted, true, caller.identity(), "x".into(), role("viewer")),
            Err(ConnectedGrantError::Closing)
        ));
    }

    /// The grant an inbound connection is live under is answered only once
    /// the table is saved: after an earlier save failed, a failing save
    /// answers `NotSaved`, and the next one saves what was pending.
    #[tokio::test]
    async fn an_existing_grant_is_answered_only_once_the_table_is_saved() {
        use crate::private::faults::{plan_replaces, Fault};
        let dir = fresh_dir("connected-unsaved");
        let (host, _events) = host_in(Some(dir.clone()));
        host.shared.ticker_paused.store(true, Ordering::SeqCst);
        let (caller, id, hosted, _dialled) = connected(&host).await;
        let store = GrantStore::in_dir(&dir);
        let other = new_caller();
        plan_replaces(store.path(), &[Fault::BeforeRename]);
        assert!(host
            .add_grant_as(other.identity(), "other".into(), None, None)
            .is_err());
        plan_replaces(store.path(), &[Fault::BeforeRename]);
        assert!(matches!(
            host.add_grant_connected(&hosted, true, caller.identity(), "x".into(), role("viewer")),
            Err(ConnectedGrantError::NotSaved(_))
        ));
        let (grant, already) = host
            .add_grant_connected(&hosted, true, caller.identity(), "x".into(), role("viewer"))
            .unwrap();
        assert_eq!((grant.id, already), (id, true));
        let stored = store.load().unwrap();
        assert!(stored
            .live_grant(&other.identity(), host.shared.clock.now())
            .is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
