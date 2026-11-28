//! Step 2: what a connection may do, decided after TLS (step 1) on the host
//! endpoint, from that endpoint's grant table.
//!
//! A connection gets one of:
//! - **live** — the peer identity has a live grant and no local denial. The
//!   connection is bound to that grant and may open channels;
//! - **join-only** — no grant, but the peer showed a valid ticket proof.
//!   Pairing messages only, no streams, no RPC;
//! - **closed** — anything else.
//!
//! A peer with no grant has [`Limits::join_proof_wait_ms`] to send a
//! `JOIN_PROOF`.
//! Until then only `HELLO`, keepalive, `GOAWAY` and `JOIN_PROOF` are allowed.
//!
//! A granted peer may still send one `JOIN_PROOF`, before any stream: the
//! host answers it, and a valid proof for an open invitation makes the
//! connection join-only until enrollment replaces the grant.
//!
//! The caller has its own gate, [`CallerGate`]: it accepts nothing from the
//! host on streams until the host has said `AUTHORIZED {live}` (or `PAIRED`
//! has made a join-only connection live). A caller that sent a `JOIN_PROOF`
//! takes a first `AUTHORIZED {live}` as step 2's notice and waits for the
//! host's answer to the proof: the next `AUTHORIZED`, or `PAIRED` when the
//! host's grant came from that proof's invitation. On the host, `JOIN_DIRECT`
//! (Pair with IP) follows the `JOIN_PROOF` rows; on a pinned caller it counts
//! as the proof.
//!
//! An unpinned Pair with IP connection starts the caller gate in its own
//! **pairing-only** state ([`CallerGate::pairing_only`]): no stream ever,
//! and live only when the pairing layer says so after it verified the
//! host's confirmation and `PAIRED`.
//!
//! **Grants point one way.** The host's grant lets the caller use the host;
//! it says nothing about what the host may do on the caller. A live caller
//! accepts streams the host opens, but before it dispatches any privileged
//! operation on one it asks its own endpoint's grant table
//! ([`CallerGate::host_stream_authority`]). The caller opening the first
//! stream is an ordering rule only.

use crate::control::{AuthorizedState, ControlMessage};
use crate::grants::{GrantId, GrantTable, Role};
use crate::identity::IdentityPublicKey;
use crate::limits::Limits;
use crate::pairing::InvitationId;
use crate::time::{Millis, UnixTime};
use crate::{ConnectionId, ErrorCode};

/// The step 2 decision at connection time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step2 {
    /// A live grant.
    Live {
        /// The grant.
        grant: GrantId,
        /// Its role.
        role: Role,
    },
    /// No grant: wait for a join proof.
    AwaitJoinProof,
    /// Refuse now.
    Close(ErrorCode),
}

/// Decide step 2 for a verified peer identity.
pub fn decide(grants: &GrantTable, peer: &IdentityPublicKey, now: UnixTime) -> Step2 {
    if grants.is_denied(peer) {
        return Step2::Close(ErrorCode::NotAuthorized);
    }
    match grants.live_grant(peer, now) {
        Some(grant) => Step2::Live {
            grant: grant.id,
            role: grant.role.clone(),
        },
        None => Step2::AwaitJoinProof,
    }
}

/// The kind of inbound traffic, as the gate sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Traffic {
    /// `PING` or `PONG`.
    Keepalive,
    /// `HELLO`.
    Hello,
    /// `GOAWAY`.
    GoAway,
    /// `JOIN_PROOF` or `JOIN_DIRECT`: both follow the same rows (wire.md 8).
    JoinProof,
    /// `CODE_EXCHANGE` or `CODE_ABORT`.
    Pairing,
    /// Any stream frame: `OPEN`, `DATA`, `CREDIT`, `FIN`, `RESET`. This is
    /// where RPC and every other channel lives.
    Stream,
    /// A control message the host never accepts from a caller
    /// (`AUTHORIZED`, `PAIRED`).
    HostOnly,
}

impl Traffic {
    /// The class of a control message received by the host.
    pub fn of(message: &ControlMessage) -> Traffic {
        match message {
            ControlMessage::Hello { .. } => Traffic::Hello,
            ControlMessage::JoinProof { .. } | ControlMessage::JoinDirect { .. } => {
                Traffic::JoinProof
            }
            ControlMessage::CodeExchange { .. } | ControlMessage::CodeAbort { .. } => {
                Traffic::Pairing
            }
            ControlMessage::Authorized { .. }
            | ControlMessage::AuthorizedDirect { .. }
            | ControlMessage::Paired { .. } => Traffic::HostOnly,
        }
    }
}

/// What to do with inbound traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Process it.
    Allow,
    /// Drop it silently.
    Ignore,
    /// Close the connection with this code.
    Close(ErrorCode),
}

/// A connection's step 2 state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateState {
    /// No grant yet; a join proof is due by `deadline`.
    AwaitingJoinProof {
        /// Monotonic deadline.
        deadline: Millis,
    },
    /// Pairing only, for this invitation.
    JoinOnly {
        /// The invitation the proof was for.
        invitation: InvitationId,
    },
    /// Normal channels under this grant.
    Live {
        /// The grant this connection is bound to.
        grant: GrantId,
    },
    /// Closed with this code.
    Closed(ErrorCode),
}

/// The host-side gate for one connection.
#[derive(Clone, Debug)]
pub struct ConnectionGate {
    conn: ConnectionId,
    peer: IdentityPublicKey,
    state: GateState,
    /// A `JOIN_PROOF` was let through on this connection.
    proof_seen: bool,
    /// A stream frame was let through on this connection.
    stream_seen: bool,
}

impl ConnectionGate {
    /// Run step 2 for a new connection whose certificate passed step 1. A
    /// live result binds the connection to its grant in `grants`. Uses the
    /// default limits; see [`ConnectionGate::open_with_limits`].
    pub fn open(
        conn: ConnectionId,
        peer: IdentityPublicKey,
        grants: &mut GrantTable,
        now: UnixTime,
        mono: Millis,
    ) -> Self {
        Self::open_with_limits(conn, peer, grants, now, mono, &Limits::DEFAULT)
    }

    /// [`ConnectionGate::open`] with other limits.
    pub fn open_with_limits(
        conn: ConnectionId,
        peer: IdentityPublicKey,
        grants: &mut GrantTable,
        now: UnixTime,
        mono: Millis,
        limits: &Limits,
    ) -> Self {
        let state = match decide(grants, &peer, now) {
            Step2::Live { grant, .. } => match grants.bind(conn, grant, now) {
                Ok(()) => GateState::Live { grant },
                Err(_) => GateState::Closed(ErrorCode::NotAuthorized),
            },
            Step2::AwaitJoinProof => GateState::AwaitingJoinProof {
                deadline: mono.plus(limits.join_proof_wait_ms()),
            },
            Step2::Close(code) => GateState::Closed(code),
        };
        Self {
            conn,
            peer,
            state,
            proof_seen: false,
            stream_seen: false,
        }
    }

    /// The connection.
    pub fn conn(&self) -> ConnectionId {
        self.conn
    }

    /// The peer identity from step 1.
    pub fn peer(&self) -> &IdentityPublicKey {
        &self.peer
    }

    /// The current state.
    pub fn state(&self) -> &GateState {
        &self.state
    }

    /// Check inbound traffic. A `Close` verdict also closes the gate.
    pub fn check(&mut self, traffic: Traffic) -> Verdict {
        use Traffic::*;
        let verdict = match (&self.state, traffic) {
            (GateState::Closed(_), _) => Verdict::Ignore,
            (_, Keepalive | Hello | GoAway) => Verdict::Allow,
            (_, HostOnly) => Verdict::Close(ErrorCode::ProtocolError),
            (GateState::AwaitingJoinProof { .. }, JoinProof) => Verdict::Allow,
            #[cfg(not(any(mousse_control = "break-authz", mousse_control = "admit-ungranted")))]
            (GateState::AwaitingJoinProof { .. }, Pairing | Stream) => {
                Verdict::Close(ErrorCode::NotAuthorized)
            }
            // Must-fail controls: a connection with no grant, awaiting a
            // proof, may open streams.
            #[cfg(any(mousse_control = "break-authz", mousse_control = "admit-ungranted"))]
            (GateState::AwaitingJoinProof { .. }, Stream) => Verdict::Allow,
            #[cfg(any(mousse_control = "break-authz", mousse_control = "admit-ungranted"))]
            (GateState::AwaitingJoinProof { .. }, Pairing) => {
                Verdict::Close(ErrorCode::NotAuthorized)
            }
            (GateState::JoinOnly { .. }, Pairing) => Verdict::Allow,
            (GateState::JoinOnly { .. }, JoinProof) => Verdict::Close(ErrorCode::ProtocolError),
            #[cfg(not(mousse_control = "join-only-streams"))]
            (GateState::JoinOnly { .. }, Stream) => Verdict::Close(ErrorCode::NotAuthorized),
            // Must-fail control: a join-only connection may open streams.
            #[cfg(mousse_control = "join-only-streams")]
            (GateState::JoinOnly { .. }, Stream) => Verdict::Allow,
            // A granted device may send one proof, before any stream: the
            // host answers it, and a valid one starts a pairing that
            // replaces the grant (wire.md 8).
            (GateState::Live { .. }, JoinProof) if !self.proof_seen && !self.stream_seen => {
                Verdict::Allow
            }
            (GateState::Live { .. }, JoinProof) => Verdict::Close(ErrorCode::ProtocolError),
            // A late pairing message means nothing on a live connection.
            (GateState::Live { .. }, Pairing) => Verdict::Ignore,
            (GateState::Live { .. }, Stream) => Verdict::Allow,
        };
        match (verdict, traffic) {
            (Verdict::Allow, JoinProof) => self.proof_seen = true,
            (Verdict::Allow, Stream) => self.stream_seen = true,
            _ => {}
        }
        if let Verdict::Close(code) = verdict {
            self.state = GateState::Closed(code);
        }
        verdict
    }

    /// The pairing state machine admitted this connection
    /// ([`crate::pairing::HostAction::AdmittedJoinOnly`]), from awaiting a
    /// proof or from live (a granted device pairing again).
    pub fn admit_join_only(&mut self, invitation: InvitationId) {
        if matches!(
            self.state,
            GateState::AwaitingJoinProof { .. } | GateState::Live { .. }
        ) {
            self.state = GateState::JoinOnly { invitation };
        }
    }

    /// Pairing enrolled the device and bound this connection to `grant`
    /// ([`crate::pairing::HostAction::Enrolled`]).
    pub fn promote(&mut self, grant: GrantId) {
        if matches!(self.state, GateState::JoinOnly { .. }) {
            self.state = GateState::Live { grant };
        }
    }

    /// The bound grant ended ([`crate::grants::GrantEvent::CloseChannels`]),
    /// or the connection must close for another reason.
    pub fn close(&mut self, code: ErrorCode) {
        if !matches!(self.state, GateState::Closed(_)) {
            self.state = GateState::Closed(code);
        }
    }

    /// When [`ConnectionGate::on_timeout`] must next run.
    pub fn poll_timeout(&self) -> Option<Millis> {
        match self.state {
            GateState::AwaitingJoinProof { deadline } => Some(deadline),
            _ => None,
        }
    }

    /// Close a connection whose join proof is overdue.
    pub fn on_timeout(&mut self, mono: Millis) -> Option<ErrorCode> {
        match self.state {
            GateState::AwaitingJoinProof { deadline } if mono >= deadline => {
                self.state = GateState::Closed(ErrorCode::NotAuthorized);
                Some(ErrorCode::NotAuthorized)
            }
            _ => None,
        }
    }
}

/// Inbound traffic on the caller, from the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerTraffic {
    /// `PING` or `PONG`.
    Keepalive,
    /// `HELLO`.
    Hello,
    /// `GOAWAY`.
    GoAway,
    /// `AUTHORIZED` with this state.
    Authorized(AuthorizedState),
    /// `CODE_EXCHANGE` or `CODE_ABORT`.
    Pairing,
    /// `PAIRED`.
    Paired,
    /// Any stream frame: `OPEN`, `DATA`, `CREDIT`, `FIN`, `RESET`.
    Stream,
    /// A control message the caller never accepts from a host
    /// (`JOIN_PROOF`, `JOIN_DIRECT`).
    CallerOnly,
}

impl CallerTraffic {
    /// The class of a control message received by the caller.
    pub fn of(message: &ControlMessage) -> CallerTraffic {
        match message {
            ControlMessage::Hello { .. } => CallerTraffic::Hello,
            ControlMessage::Authorized { state } => CallerTraffic::Authorized(*state),
            ControlMessage::AuthorizedDirect { .. } => {
                CallerTraffic::Authorized(AuthorizedState::JoinOnly)
            }
            ControlMessage::CodeExchange { .. } | ControlMessage::CodeAbort { .. } => {
                CallerTraffic::Pairing
            }
            ControlMessage::Paired { .. } => CallerTraffic::Paired,
            ControlMessage::JoinProof { .. } | ControlMessage::JoinDirect { .. } => {
                CallerTraffic::CallerOnly
            }
        }
    }
}

/// The caller's view of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerGateState {
    /// Waiting for the host's `AUTHORIZED`.
    AwaitingAuthorization,
    /// This side sent a `JOIN_PROOF` and the host said `AUTHORIZED {live}`
    /// from step 2; the host's answer to the proof is the next
    /// `AUTHORIZED` or a `PAIRED`. Nothing else but keepalive, `HELLO` and
    /// `GOAWAY` yet.
    AwaitingProofAnswer,
    /// The host said join-only: pairing messages only.
    JoinOnly,
    /// The host said live, or pairing finished: normal channels.
    Live,
    /// An unpinned Pair with IP connection (wire.md 8.2): pairing messages
    /// only, no streams, until the pairing layer has verified the host's
    /// confirmation and `PAIRED` ([`CallerGate::promote_direct`]).
    PairingOnly(PairingOnlyStep),
    /// Closed with this code.
    Closed(ErrorCode),
}

/// Where a pairing-only connection is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingOnlyStep {
    /// Waiting for the host's answer to `JOIN_DIRECT`.
    AwaitingAnswer,
    /// The host said `AUTHORIZED {live}` (step 2's notice for a device it
    /// already grants); its answer to `JOIN_DIRECT` is still due.
    NoticeSeen,
    /// The host said `AUTHORIZED {join_only}`: the code exchange may run.
    JoinOnly,
    /// `PAIRED` arrived; the connection waits for the pairing layer.
    Paired,
}

/// The caller-side gate for one connection. Until the host has authorized
/// the connection as live, the caller opens no streams and accepts none:
/// any stream frame from the host closes the connection.
#[derive(Clone, Debug)]
pub struct CallerGate {
    state: CallerGateState,
    /// This side sent a `JOIN_PROOF` on this connection.
    proof_sent: bool,
}

impl Default for CallerGate {
    fn default() -> Self {
        Self::new()
    }
}

impl CallerGate {
    /// A new connection, after TLS.
    pub fn new() -> Self {
        Self {
            state: CallerGateState::AwaitingAuthorization,
            proof_sent: false,
        }
    }

    /// A Pair with IP first contact: an unpinned connection (wire.md 5.4)
    /// that can do nothing but this pairing. It accepts `HELLO`,
    /// `AUTHORIZED`, `CODE_EXCHANGE`, `CODE_ABORT`, `PAIRED`, `GOAWAY` and
    /// keepalive, and refuses every stream. A second `AUTHORIZED {live}`,
    /// and a code-exchange message before `AUTHORIZED {join_only}`, close
    /// it. Only [`CallerGate::promote_direct`] makes it live.
    pub fn pairing_only() -> Self {
        Self {
            state: CallerGateState::PairingOnly(PairingOnlyStep::AwaitingAnswer),
            proof_sent: true,
        }
    }

    /// This side sent a `JOIN_PROOF`, or a `JOIN_DIRECT` on a pinned
    /// connection (recovery), which counts as the proof. Call it when the
    /// message is queued, before reading anything else from the host. A
    /// host that already grants this device says `AUTHORIZED {live}` first
    /// and then answers the proof with a second `AUTHORIZED`, so the
    /// connection is not live until that answer.
    pub fn sent_join_proof(&mut self) {
        self.proof_sent = true;
        // A `live` that was read before the proof went out is the notice.
        if self.state == CallerGateState::Live {
            self.state = CallerGateState::AwaitingProofAnswer;
        }
    }

    /// The current state.
    pub fn state(&self) -> CallerGateState {
        self.state
    }

    /// True once the caller may open streams.
    pub fn is_live(&self) -> bool {
        self.state == CallerGateState::Live
    }

    /// Check inbound traffic from the host. `AUTHORIZED` moves the gate on;
    /// a `Close` verdict also closes the gate.
    pub fn check(&mut self, traffic: CallerTraffic) -> Verdict {
        use CallerGateState as S;
        use CallerTraffic as T;
        let verdict = match (self.state, traffic) {
            (S::Closed(_), _) => Verdict::Ignore,
            (_, T::Keepalive | T::Hello | T::GoAway) => Verdict::Allow,
            (_, T::CallerOnly) => Verdict::Close(ErrorCode::ProtocolError),
            (S::PairingOnly(step), traffic) => self.check_pairing_only(step, traffic),
            (S::AwaitingAuthorization, T::Authorized(state)) => {
                self.state = match state {
                    AuthorizedState::Live if self.proof_sent => S::AwaitingProofAnswer,
                    AuthorizedState::Live => S::Live,
                    AuthorizedState::JoinOnly => S::JoinOnly,
                };
                Verdict::Allow
            }
            (S::AwaitingProofAnswer, T::Authorized(state)) => {
                self.state = match state {
                    AuthorizedState::Live => S::Live,
                    AuthorizedState::JoinOnly => S::JoinOnly,
                };
                Verdict::Allow
            }
            // The answer to a proof whose invitation made the host's grant
            // (its enrollment receipt): the connection stays live under it.
            (S::AwaitingProofAnswer, T::Paired) => {
                self.state = S::Live;
                Verdict::Allow
            }
            (_, T::Authorized(_)) => Verdict::Close(ErrorCode::ProtocolError),
            (S::JoinOnly, T::Pairing | T::Paired) => Verdict::Allow,
            // A late pairing message after enrollment means nothing.
            (S::Live, T::Pairing) => Verdict::Ignore,
            (S::Live, T::Stream) => Verdict::Allow,
            (
                S::AwaitingAuthorization | S::AwaitingProofAnswer,
                T::Pairing | T::Paired | T::Stream,
            )
            | (S::JoinOnly, T::Stream)
            | (S::Live, T::Paired) => Verdict::Close(ErrorCode::ProtocolError),
        };
        if let Verdict::Close(code) = verdict {
            self.state = S::Closed(code);
        }
        verdict
    }

    /// The rows of a pairing-only connection (wire.md 8.2), after
    /// keepalive, `HELLO`, `GOAWAY` and caller-only messages.
    fn check_pairing_only(&mut self, step: PairingOnlyStep, traffic: CallerTraffic) -> Verdict {
        use CallerTraffic as T;
        use PairingOnlyStep as P;
        let next = match (step, traffic) {
            (P::AwaitingAnswer, T::Authorized(AuthorizedState::Live)) => P::NoticeSeen,
            (P::AwaitingAnswer | P::NoticeSeen, T::Authorized(AuthorizedState::JoinOnly)) => {
                P::JoinOnly
            }
            (P::JoinOnly, T::Pairing) => P::JoinOnly,
            (P::JoinOnly, T::Paired) => P::Paired,
            // A late code-exchange message after `PAIRED` means nothing.
            (P::Paired, T::Pairing) => return Verdict::Ignore,
            _ => return Verdict::Close(ErrorCode::ProtocolError),
        };
        self.state = CallerGateState::PairingOnly(next);
        Verdict::Allow
    }

    /// The pairing layer verified the host's confirmation and accepted
    /// `PAIRED` on a pairing-only connection: it is live. Does nothing
    /// before `PAIRED` has passed this gate, or on any other connection.
    pub fn promote_direct(&mut self) {
        if self.state == CallerGateState::PairingOnly(PairingOnlyStep::Paired) {
            self.state = CallerGateState::Live;
        }
    }

    /// The joiner's pairing accepted `PAIRED`
    /// ([`crate::pairing::JoinerAction::Paired`]): the connection is live.
    pub fn promote(&mut self) {
        if self.state == CallerGateState::JoinOnly {
            self.state = CallerGateState::Live;
        }
    }

    /// The connection closed, or must close, for another reason.
    pub fn close(&mut self, code: ErrorCode) {
        if !matches!(self.state, CallerGateState::Closed(_)) {
            self.state = CallerGateState::Closed(code);
        }
    }

    /// What the host may do on a stream it opened (wire.md 8.2), decided
    /// by this caller, before it dispatches any privileged operation there.
    ///
    /// The host's `AUTHORIZED` grants this caller access to the host, never
    /// the reverse. The answer comes from `local`, this caller endpoint's
    /// own grant table: the role of its live grant for `host` (the host
    /// identity from step 1), and only while this gate is live. `None`
    /// means no privileged operation; the stream may still carry what the
    /// application allows without a grant, such as replies on a channel the
    /// caller asked for.
    pub fn host_stream_authority(
        &self,
        local: &GrantTable,
        host: &IdentityPublicKey,
        now: UnixTime,
    ) -> Option<Role> {
        if !self.is_live() {
            return None;
        }
        local.live_grant(host, now).map(|g| g.role.clone())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::grants::{NewGrant, OwnerRef};
    use crate::identity::SoftwareKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn id(seed: u8) -> IdentityPublicKey {
        SoftwareKey::generate(&mut ChaCha20Rng::from_seed([seed; 32])).public_key()
    }

    const NOW: UnixTime = UnixTime(1_000);

    fn table_with(seed: u8) -> GrantTable {
        let mut t = GrantTable::new();
        t.add(
            NewGrant {
                identity: id(seed),
                name: "phone".into(),
                role: Role::owner(),
                authorizing_owner: OwnerRef::from_bytes([0x51; 16]),
                expires_at: None,
                enrolled_by: None,
            },
            NOW,
        )
        .unwrap();
        t
    }

    #[test]
    fn valid_identity_without_grant_attempting_rpc_is_closed() {
        let mut grants = table_with(1);
        let mut gate = ConnectionGate::open(ConnectionId(1), id(2), &mut grants, NOW, Millis(0));
        assert!(matches!(gate.state(), GateState::AwaitingJoinProof { .. }));
        assert_eq!(gate.check(Traffic::Hello), Verdict::Allow);
        assert_eq!(
            gate.check(Traffic::Stream),
            Verdict::Close(ErrorCode::NotAuthorized)
        );
        assert_eq!(gate.state(), &GateState::Closed(ErrorCode::NotAuthorized));
    }

    #[test]
    fn granted_identity_is_live_and_bound() {
        let mut grants = table_with(1);
        let mut gate = ConnectionGate::open(ConnectionId(7), id(1), &mut grants, NOW, Millis(0));
        assert!(matches!(gate.state(), GateState::Live { .. }));
        assert_eq!(gate.check(Traffic::Stream), Verdict::Allow);
        assert!(grants.binding(ConnectionId(7)).is_some());
    }

    #[test]
    fn join_only_allows_pairing_but_not_streams() {
        let mut grants = GrantTable::new();
        let mut gate = ConnectionGate::open(ConnectionId(1), id(2), &mut grants, NOW, Millis(0));
        assert_eq!(gate.check(Traffic::JoinProof), Verdict::Allow);
        gate.admit_join_only(InvitationId([0; 16]));
        assert_eq!(gate.check(Traffic::Pairing), Verdict::Allow);
        assert_eq!(
            gate.check(Traffic::Stream),
            Verdict::Close(ErrorCode::NotAuthorized)
        );
    }

    #[test]
    fn denied_identity_is_closed_even_with_a_grant() {
        let mut grants = table_with(1);
        grants.deny(id(1), NOW);
        let gate = ConnectionGate::open(ConnectionId(1), id(1), &mut grants, NOW, Millis(0));
        assert_eq!(gate.state(), &GateState::Closed(ErrorCode::NotAuthorized));
    }

    #[test]
    fn caller_refuses_host_streams_until_authorized_live() {
        let mut gate = CallerGate::new();
        assert_eq!(gate.check(CallerTraffic::Hello), Verdict::Allow);
        assert_eq!(
            gate.check(CallerTraffic::Stream),
            Verdict::Close(ErrorCode::ProtocolError)
        );
        assert_eq!(gate.check(CallerTraffic::Stream), Verdict::Ignore);

        let mut gate = CallerGate::new();
        let live = CallerTraffic::Authorized(AuthorizedState::Live);
        assert_eq!(gate.check(live), Verdict::Allow);
        assert!(gate.is_live());
        assert_eq!(gate.check(CallerTraffic::Stream), Verdict::Allow);
        assert_eq!(gate.check(live), Verdict::Close(ErrorCode::ProtocolError));
    }

    #[test]
    fn caller_join_only_allows_pairing_until_paired_is_accepted() {
        let mut gate = CallerGate::new();
        assert_eq!(
            gate.check(CallerTraffic::Authorized(AuthorizedState::JoinOnly)),
            Verdict::Allow
        );
        assert_eq!(gate.check(CallerTraffic::Pairing), Verdict::Allow);
        assert_eq!(gate.check(CallerTraffic::Paired), Verdict::Allow);
        assert!(!gate.is_live());
        gate.promote();
        assert_eq!(gate.check(CallerTraffic::Stream), Verdict::Allow);
        assert_eq!(gate.check(CallerTraffic::Pairing), Verdict::Ignore);
        assert_eq!(
            gate.check(CallerTraffic::Paired),
            Verdict::Close(ErrorCode::ProtocolError)
        );

        let mut gate = CallerGate::new();
        gate.check(CallerTraffic::Authorized(AuthorizedState::JoinOnly));
        assert_eq!(
            gate.check(CallerTraffic::Stream),
            Verdict::Close(ErrorCode::ProtocolError)
        );
    }

    #[test]
    fn a_granted_device_may_send_one_proof_before_any_stream() {
        let mut grants = table_with(1);
        let mut gate = ConnectionGate::open(ConnectionId(7), id(1), &mut grants, NOW, Millis(0));
        assert_eq!(gate.check(Traffic::JoinProof), Verdict::Allow);
        assert_eq!(
            gate.check(Traffic::JoinProof),
            Verdict::Close(ErrorCode::ProtocolError)
        );

        let mut gate = ConnectionGate::open(ConnectionId(8), id(1), &mut grants, NOW, Millis(0));
        assert_eq!(gate.check(Traffic::Stream), Verdict::Allow);
        assert_eq!(
            gate.check(Traffic::JoinProof),
            Verdict::Close(ErrorCode::ProtocolError)
        );

        // A valid proof for an open invitation: the live connection becomes
        // pairing only until enrollment.
        let mut gate = ConnectionGate::open(ConnectionId(9), id(1), &mut grants, NOW, Millis(0));
        assert_eq!(gate.check(Traffic::JoinProof), Verdict::Allow);
        gate.admit_join_only(InvitationId([0; 16]));
        assert!(matches!(gate.state(), GateState::JoinOnly { .. }));
        assert_eq!(
            gate.check(Traffic::Stream),
            Verdict::Close(ErrorCode::NotAuthorized)
        );
    }

    #[test]
    fn a_caller_that_sent_a_proof_waits_for_its_answer() {
        let live = CallerTraffic::Authorized(AuthorizedState::Live);
        let join_only = CallerTraffic::Authorized(AuthorizedState::JoinOnly);
        // Step 2's live, then the answer.
        for answer in [live, join_only] {
            let mut gate = CallerGate::new();
            gate.sent_join_proof();
            assert_eq!(gate.check(live), Verdict::Allow);
            assert_eq!(gate.state(), CallerGateState::AwaitingProofAnswer);
            assert!(!gate.is_live());
            assert_eq!(gate.check(answer), Verdict::Allow);
            assert_eq!(gate.is_live(), answer == live);
        }
        // Read before the proof went out: still only the notice.
        let mut gate = CallerGate::new();
        assert_eq!(gate.check(live), Verdict::Allow);
        gate.sent_join_proof();
        assert_eq!(gate.state(), CallerGateState::AwaitingProofAnswer);
        // `PAIRED` as the answer: the proof's invitation made the grant.
        let mut gate = CallerGate::new();
        gate.sent_join_proof();
        gate.check(live);
        assert_eq!(gate.check(CallerTraffic::Paired), Verdict::Allow);
        assert!(gate.is_live());
        // The host opens nothing before the answer.
        for traffic in [CallerTraffic::Stream, CallerTraffic::Pairing] {
            let mut gate = CallerGate::new();
            gate.sent_join_proof();
            gate.check(live);
            assert_eq!(
                gate.check(traffic),
                Verdict::Close(ErrorCode::ProtocolError)
            );
        }
    }

    /// Nothing but [`CallerGate::promote_direct`] after `PAIRED` makes a
    /// pairing-only connection live: not the join-only promotion, not a
    /// proof, not `AUTHORIZED {live}`.
    #[test]
    fn only_promote_direct_after_paired_makes_a_pairing_only_connection_live() {
        let mut gate = CallerGate::pairing_only();
        gate.sent_join_proof();
        assert_eq!(
            gate.check(CallerTraffic::Authorized(AuthorizedState::Live)),
            Verdict::Allow
        );
        gate.promote();
        gate.promote_direct();
        assert!(!gate.is_live());
        gate.check(CallerTraffic::Authorized(AuthorizedState::JoinOnly));
        gate.promote();
        gate.promote_direct();
        assert!(!gate.is_live());
        assert_eq!(gate.check(CallerTraffic::Paired), Verdict::Allow);
        gate.promote();
        gate.sent_join_proof();
        assert!(!gate.is_live());
        assert_eq!(
            gate.host_stream_authority(&table_with(9), &id(9), NOW),
            None
        );
        gate.promote_direct();
        assert!(gate.is_live());
    }

    /// The host's `AUTHORIZED {live}` lets the caller use the host. It
    /// gives the host nothing on the caller: privileged work on a stream the
    /// host opened needs the caller's own grant for the host.
    #[test]
    fn a_host_stream_gets_only_what_the_caller_grants_the_host() {
        let host = id(9);
        let mut gate = CallerGate::new();
        gate.check(CallerTraffic::Authorized(AuthorizedState::Live));
        assert_eq!(gate.check(CallerTraffic::Stream), Verdict::Allow);
        // The caller has no grant for the host: nothing privileged.
        assert_eq!(gate.host_stream_authority(&table_with(1), &host, NOW), None);
        // With one, the role comes from the caller's own table.
        let mut local = table_with(9);
        assert_eq!(
            gate.host_stream_authority(&local, &host, NOW),
            Some(Role::owner())
        );
        // A local denial wins.
        local.deny(host, NOW);
        assert_eq!(gate.host_stream_authority(&local, &host, NOW), None);
        // Not live yet: nothing, whatever the table says.
        let mut gate = CallerGate::new();
        gate.sent_join_proof();
        gate.check(CallerTraffic::Authorized(AuthorizedState::Live));
        assert_eq!(gate.host_stream_authority(&table_with(9), &host, NOW), None);
    }

    #[test]
    fn join_proof_wait_times_out() {
        let mut grants = GrantTable::new();
        let mut gate = ConnectionGate::open(ConnectionId(1), id(2), &mut grants, NOW, Millis(100));
        assert_eq!(
            gate.poll_timeout(),
            Some(Millis(100 + Limits::DEFAULT.join_proof_wait_ms()))
        );
        assert_eq!(
            gate.on_timeout(Millis(100 + Limits::DEFAULT.join_proof_wait_ms() - 1)),
            None
        );
        assert_eq!(
            gate.on_timeout(Millis(100 + Limits::DEFAULT.join_proof_wait_ms())),
            Some(ErrorCode::NotAuthorized)
        );
    }

    #[test]
    fn a_tightened_join_proof_wait_is_used() {
        let limits = Limits::DEFAULT
            .with_overrides(&[("JOIN_PROOF_WAIT_MS", 2_000)])
            .unwrap();
        let mut grants = GrantTable::new();
        let mut gate = ConnectionGate::open_with_limits(
            ConnectionId(1),
            id(2),
            &mut grants,
            NOW,
            Millis(100),
            &limits,
        );
        assert_eq!(gate.poll_timeout(), Some(Millis(2_100)));
        assert_eq!(
            gate.on_timeout(Millis(2_100)),
            Some(ErrorCode::NotAuthorized)
        );
    }
}
