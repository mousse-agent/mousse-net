//! Step 2: what a connection may do, decided after TLS (step 1) on the host.
//!
//! A connection gets one of:
//! - **live** — the peer identity has a live grant and no local denial. The
//!   connection is bound to that grant and may open channels;
//! - **join-only** — no grant, but the peer showed a valid ticket proof.
//!   Pairing messages only, no streams, no RPC;
//! - **closed** — anything else.
//!
//! A peer with no grant has [`JOIN_PROOF_WAIT_MS`] to send a `JOIN_PROOF`.
//! Until then only `HELLO`, keepalive, `GOAWAY` and `JOIN_PROOF` are allowed.

use crate::grants::{GrantId, GrantTable, Role};
use crate::identity::IdentityPublicKey;
use crate::pairing::InvitationId;
use crate::time::{Millis, UnixTime};
use crate::{ConnectionId, ErrorCode};

/// How long a connection without a grant may wait before sending its join
/// proof, in milliseconds.
pub const JOIN_PROOF_WAIT_MS: u64 = 10_000;

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
    /// `JOIN_PROOF`.
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
}

impl ConnectionGate {
    /// Run step 2 for a new connection whose certificate passed step 1. A
    /// live result binds the connection to its grant in `grants`.
    pub fn open(
        conn: ConnectionId,
        peer: IdentityPublicKey,
        grants: &mut GrantTable,
        now: UnixTime,
        mono: Millis,
    ) -> Self {
        let state = match decide(grants, &peer, now) {
            Step2::Live { grant, .. } => match grants.bind(conn, grant, now) {
                Ok(()) => GateState::Live { grant },
                Err(_) => GateState::Closed(ErrorCode::NotAuthorized),
            },
            Step2::AwaitJoinProof => GateState::AwaitingJoinProof {
                deadline: mono.plus(JOIN_PROOF_WAIT_MS),
            },
            Step2::Close(code) => GateState::Closed(code),
        };
        Self { conn, peer, state }
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
            (GateState::AwaitingJoinProof { .. }, Pairing | Stream) => {
                Verdict::Close(ErrorCode::NotAuthorized)
            }
            (GateState::JoinOnly { .. }, Pairing) => Verdict::Allow,
            (GateState::JoinOnly { .. }, JoinProof) => Verdict::Close(ErrorCode::ProtocolError),
            (GateState::JoinOnly { .. }, Stream) => Verdict::Close(ErrorCode::NotAuthorized),
            // A device that is already granted may still send a proof or a
            // late pairing message; they mean nothing on a live connection.
            (GateState::Live { .. }, JoinProof | Pairing) => Verdict::Ignore,
            (GateState::Live { .. }, Stream) => Verdict::Allow,
        };
        if let Verdict::Close(code) = verdict {
            self.state = GateState::Closed(code);
        }
        verdict
    }

    /// The pairing state machine admitted this connection
    /// ([`crate::pairing::HostAction::AdmittedJoinOnly`]).
    pub fn admit_join_only(&mut self, invitation: InvitationId) {
        if matches!(self.state, GateState::AwaitingJoinProof { .. }) {
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

#[cfg(test)]
mod tests {
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
                authorizing_owner: OwnerRef::new("p").unwrap(),
                expires_at: None,
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
    fn join_proof_wait_times_out() {
        let mut grants = GrantTable::new();
        let mut gate = ConnectionGate::open(ConnectionId(1), id(2), &mut grants, NOW, Millis(100));
        assert_eq!(gate.poll_timeout(), Some(Millis(100 + JOIN_PROOF_WAIT_MS)));
        assert_eq!(gate.on_timeout(Millis(100 + JOIN_PROOF_WAIT_MS - 1)), None);
        assert_eq!(
            gate.on_timeout(Millis(100 + JOIN_PROOF_WAIT_MS)),
            Some(ErrorCode::NotAuthorized)
        );
    }
}
