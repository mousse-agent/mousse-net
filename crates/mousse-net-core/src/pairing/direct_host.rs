//! The host side of Pair with IP (spec `wire.md` 10.9): invitations of kind
//! 3, found by the code's lookup and paired by the code exchange over its
//! secret, then allowed by the host owner.
//!
//! Kinds 1 and 2 stay in [`super::HostPairing`]; the I/O layer routes a
//! connection that sent `JOIN_DIRECT` here for the rest of its pairing.
//!
//! An approval request belongs to an (invitation, identity) pair, not to a
//! connection: a device that passed the code keeps its request when its
//! connection drops, and the owner can still allow it until the request's
//! Allow window ends. Enrollment always happens on a connection of that
//! identity, and makes a provisional grant that commits on the first stream
//! frame under it; until then the joiner's cancel wins over a crossing
//! Allow, and removes only that provisional grant.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use rand_core::CryptoRng;

use super::direct_code::{DirectCode, DirectLookup};
use super::exchange::{CodeExchange, CodeExchangeFactory, ExchangeRole};
use super::proof::{attempt_sid, direct_binding_transcript, EXPORTER_LEN};
use super::{AttemptId, InvitationId};
use crate::control::{AuthorizedState, ControlMessage, DirectRecovery};
use crate::grants::{Grant, GrantError, GrantEvent, GrantId, GrantTable, NewGrant, OwnerRef, Role};
use crate::identity::IdentityPublicKey;
use crate::limits::Limits;
use crate::time::UnixTime;
use crate::{ConnectionId, ErrorCode};

/// What the host owner chose when creating a Pair with IP invitation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectInvitationParams {
    /// The role an approval request offers until the owner picks another
    /// with the answer.
    pub role: Role,
    /// The owner or profile authorizing the grant.
    pub authorizing_owner: OwnerRef,
    /// Optional expiry for the resulting grant.
    pub grant_expires_at: Option<UnixTime>,
}

/// A new Pair with IP invitation, ready to show.
#[derive(Clone, Debug)]
pub struct CreatedDirectInvitation {
    /// The invitation id `I`.
    pub invitation: InvitationId,
    /// The code to show (zeroized on drop).
    pub code: DirectCode,
    /// When it stops taking new attempts.
    pub expires_at: UnixTime,
    /// Code attempts it allows.
    pub attempts_left: u8,
}

/// Where a Pair with IP invitation stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectInvitationStatus {
    /// Takes lookups and new attempts until it expires; requests of devices
    /// that passed the code may be answered within their Allow window.
    Open,
    /// The owner allowed a device whose connection had dropped. Nothing else
    /// is looked up or attempted; the invitation waits for that device's
    /// recovery connection, within its Allow window.
    Allowed {
        /// The allowed device.
        identity: IdentityPublicKey,
    },
    /// One device was enrolled; the invitation is spent. Its grant may
    /// still be provisional ([`GrantTable::is_provisional`]).
    Consumed {
        /// The grant it created.
        grant: GrantId,
    },
    /// Ended without enrollment: `Cancelled` (the owner, or the allowed
    /// device), `PairingDeclined`, `AttemptsExhausted` or
    /// `InvitationInvalid` (expired, or the allowed device never came back).
    Ended(ErrorCode),
}

/// An approval request: one per (invitation, identity that passed the code).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DirectRequestId {
    /// The invitation.
    pub invitation: InvitationId,
    /// The device that passed the code.
    pub identity: IdentityPublicKey,
}

/// Whether the requesting device has a connection here now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestPresence {
    /// Its connection is up.
    Connected,
    /// Its connection dropped; it may come back by recovery.
    Away,
}

/// What the owner has said so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestDecision {
    /// No answer yet.
    Pending,
    /// Allowed while the device was away: it is enrolled when it reconnects.
    Allowed,
}

/// The approval prompt for one request, sent again with the same id
/// whenever its presence or decision changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectApproval {
    /// The request.
    pub request: DirectRequestId,
    /// The name the device sent in `JOIN_DIRECT` when it passed the code.
    pub name: String,
    /// The role it would get: the invitation's until the owner allows with
    /// another.
    pub role: Role,
    /// Connected or away.
    pub presence: RequestPresence,
    /// Pending or allowed.
    pub decision: RequestDecision,
    /// The end of its Allow window: it may be allowed and claimed before
    /// this second.
    pub answer_by: UnixTime,
}

/// Why an approval prompt went away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalEnd {
    /// The device was enrolled.
    Enrolled,
    /// The device cancelled.
    Cancelled,
    /// The owner declined it.
    Declined,
    /// Another device was allowed, or the invitation ended.
    Dismissed,
    /// Its Allow window ended unanswered or unclaimed.
    WindowEnded,
}

/// Something the I/O layer or UI must do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectHostAction {
    /// Send a control message on this connection.
    Send {
        /// Connection.
        conn: ConnectionId,
        /// Message.
        message: ControlMessage,
    },
    /// Send `GOAWAY(code)` and close this connection.
    Close {
        /// Connection.
        conn: ConnectionId,
        /// Code.
        code: ErrorCode,
    },
    /// The `JOIN_DIRECT` found nothing to answer. Keep the connection open,
    /// and with it its pre-authorization place, for `hold_ms`, then close it
    /// with `INVITATION_INVALID`. Every "no open invitation" looks the same.
    MissHold {
        /// Connection.
        conn: ConnectionId,
        /// How long to hold it.
        hold_ms: u64,
    },
    /// The connection found an invitation: set its gate to join-only.
    AdmittedJoinOnly {
        /// Connection.
        conn: ConnectionId,
        /// Invitation.
        invitation: InvitationId,
    },
    /// An attempt was debited. The code stays the same; show this many
    /// attempts left.
    AttemptsLeft {
        /// Invitation.
        invitation: InvitationId,
        /// Attempts left.
        attempts_left: u8,
    },
    /// Show, or update, the owner's approval prompt for this request.
    Approval(DirectApproval),
    /// Take the request's prompt away.
    ApprovalEnded {
        /// The request.
        request: DirectRequestId,
        /// Why.
        reason: ApprovalEnd,
    },
    /// A device was enrolled: `grant` is a provisional grant and its
    /// connection is bound to it. Set its gate live with
    /// [`crate::authz::ConnectionGate::bind_direct`]`(grant, true,
    /// attempt)`.
    Enrolled {
        /// Invitation.
        invitation: InvitationId,
        /// Connection.
        conn: ConnectionId,
        /// The new provisional grant.
        grant: GrantId,
        /// The device.
        identity: IdentityPublicKey,
        /// The new grant's role, as `PAIRED` carries it.
        role: Role,
        /// The attempt that passed on this connection; `None` on a recovery
        /// connection, which ran none.
        attempt: Option<AttemptId>,
    },
    /// A recovery connection is now bound to the direct grant it asked
    /// about. Set its gate live with
    /// [`crate::authz::ConnectionGate::bind_direct`]`(grant, provisional,
    /// None)`.
    Bound {
        /// Connection.
        conn: ConnectionId,
        /// The grant.
        grant: GrantId,
        /// The grant has not committed yet.
        provisional: bool,
    },
    /// A provisional grant committed on the first stream frame of `conn`:
    /// it is the device's grant now. Call
    /// [`crate::authz::ConnectionGate::committed`] on the gate of every
    /// connection in `bound` (`conn` among them), then release the frame.
    Committed {
        /// The connection whose stream committed it.
        conn: ConnectionId,
        /// The grant.
        grant: GrantId,
        /// The device.
        identity: IdentityPublicKey,
        /// Every connection bound to the grant.
        bound: Vec<ConnectionId>,
    },
    /// A provisional grant this invitation made for the device was removed:
    /// by its cancel across the Allow, a failed commit, its expiry
    /// ([`DirectHostPairing::expire_grants`]) or a newer provisional grant
    /// for the device. Its earlier grant, if any, stays. Reported after the
    /// closes of its connections, also when none was bound.
    EnrollmentUndone {
        /// Invitation.
        invitation: InvitationId,
        /// The removed grant.
        grant: GrantId,
        /// The device.
        identity: IdentityPublicKey,
    },
    /// The invitation ended without enrollment.
    InvitationEnded {
        /// Invitation.
        invitation: InvitationId,
        /// Why.
        reason: ErrorCode,
    },
    /// A grant-table event: a commit replaced an older grant, a cancel or a
    /// failed commit removed a provisional one, or a new provisional grant
    /// replaced an older one.
    Grant(GrantEvent),
}

/// Why an owner action was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectHostError {
    /// As many invitations as `DIRECT_MAX_OPEN` are open already.
    TooManyOpen,
    /// No such invitation.
    UnknownInvitation,
    /// The invitation is no longer open.
    NotOpen,
    /// No such request, or its Allow window has ended.
    UnknownRequest,
    /// The invitation's grant expiry is not ahead: the grant would be born
    /// expired. Nothing changed.
    GrantExpired,
    /// The device is denied on this endpoint. Nothing changed.
    Denied,
}

impl fmt::Display for DirectHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DirectHostError::TooManyOpen => "too many Pair with IP invitations are open",
            DirectHostError::UnknownInvitation => "no such invitation",
            DirectHostError::NotOpen => "invitation is not open",
            DirectHostError::UnknownRequest => "no such approval request",
            DirectHostError::GrantExpired => "the grant would already be expired",
            DirectHostError::Denied => "the device is denied here",
        })
    }
}

impl std::error::Error for DirectHostError {}

/// A connection that found an invitation.
struct DirectJoiner {
    identity: IdentityPublicKey,
    name: String,
    pair_exporter: [u8; EXPORTER_LEN],
    /// The one attempt this connection may run.
    attempt: Option<AttemptId>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttemptState {
    Running,
    Failed,
    Succeeded,
}

struct DirectAttempt<E> {
    exchange: Option<E>,
    state: AttemptState,
}

struct Request {
    name: String,
    passed_at: UnixTime,
    conn: Option<ConnectionId>,
    /// The attempt that passed last for it; only a `CANCELLED` for this
    /// attempt, on the request's connection, ends it.
    attempt: Option<AttemptId>,
    /// Set when the owner allowed it while it was away.
    allowed_role: Option<Role>,
}

/// A declined or cancelled request's outcome, kept for its recovery until
/// its Allow window ends.
struct Outcome {
    code: ErrorCode,
    until: UnixTime,
}

struct DirectInvitation<E> {
    code: DirectCode,
    lookup: DirectLookup,
    params: DirectInvitationParams,
    expires_at: UnixTime,
    status: DirectInvitationStatus,
    /// The timer has handled the expiry (requests kept it open).
    expiry_handled: bool,
    attempts_left: u8,
    joiners: BTreeMap<ConnectionId, DirectJoiner>,
    attempts: BTreeMap<(ConnectionId, AttemptId), DirectAttempt<E>>,
    requests: BTreeMap<IdentityPublicKey, Request>,
    outcomes: BTreeMap<IdentityPublicKey, Outcome>,
    /// Every identity that passed the code, until the invitation is
    /// forgotten: a recovery of one whose outcome is gone is a miss, never
    /// `not_received`.
    passed: BTreeSet<IdentityPublicKey>,
}

impl<E> DirectInvitation<E> {
    fn is_live(&self) -> bool {
        matches!(
            self.status,
            DirectInvitationStatus::Open | DirectInvitationStatus::Allowed { .. }
        )
    }

    /// Takes lookups and new attempts.
    fn takes_attempts(&self, now: UnixTime) -> bool {
        self.status == DirectInvitationStatus::Open && now < self.expires_at
    }

    /// Takes anything at `now`, whether or not the timer has run: allowed,
    /// or open with its own deadline ahead or a request inside its Allow
    /// window.
    fn takes_anything(&self, now: UnixTime, window: u64) -> bool {
        match self.status {
            DirectInvitationStatus::Allowed { .. } => true,
            DirectInvitationStatus::Open => {
                now < self.expires_at
                    || self
                        .requests
                        .values()
                        .any(|r| now < r.passed_at.plus(window))
            }
            _ => false,
        }
    }
}

/// A connection this machine enrolled on.
#[derive(Clone, Copy)]
struct EnrolledConn {
    invitation: InvitationId,
    grant: GrantId,
    /// The attempt that passed there (`None` on a recovery connection).
    attempt: Option<AttemptId>,
}

/// The per-connection records of [`DirectHostPairing`] that a grant-table
/// change goes with: which invitation each pairing connection belongs to,
/// and which connections were enrolled (and may still cancel). An I/O layer
/// that cannot store a change takes these with the grant table before the
/// change and puts both back together.
#[derive(Clone)]
pub struct DirectRecords {
    by_conn: BTreeMap<ConnectionId, InvitationId>,
    enrolled: BTreeMap<ConnectionId, EnrolledConn>,
}

/// The host side of Pair with IP.
pub struct DirectHostPairing<F: CodeExchangeFactory> {
    host_identity: IdentityPublicKey,
    host_name: String,
    factory: F,
    invitations: BTreeMap<InvitationId, DirectInvitation<F::Exchange>>,
    by_conn: BTreeMap<ConnectionId, InvitationId>,
    /// Connections this machine enrolled on. While their grant is
    /// provisional, the joiner's cancel there removes it.
    enrolled: BTreeMap<ConnectionId, EnrolledConn>,
    lifetime_secs: u64,
    attempts_per_invitation: u8,
    allow_window_secs: u64,
    max_open: usize,
    miss_hold_ms: u64,
}

impl<F: CodeExchangeFactory> DirectHostPairing<F> {
    /// A host with no invitations, with the default limits.
    pub fn new(host_identity: IdentityPublicKey, host_name: String, factory: F) -> Self {
        Self::with_limits(host_identity, host_name, factory, &Limits::DEFAULT)
    }

    /// [`DirectHostPairing::new`] with other limits (`DIRECT_*`).
    pub fn with_limits(
        host_identity: IdentityPublicKey,
        host_name: String,
        factory: F,
        limits: &Limits,
    ) -> Self {
        Self {
            host_identity,
            host_name,
            factory,
            invitations: BTreeMap::new(),
            by_conn: BTreeMap::new(),
            enrolled: BTreeMap::new(),
            lifetime_secs: limits.direct_invite_lifetime_secs(),
            attempts_per_invitation: u8::try_from(limits.direct_host_attempts()).unwrap_or(u8::MAX),
            allow_window_secs: limits.direct_allow_window_secs(),
            max_open: usize::try_from(limits.direct_max_open()).unwrap_or(usize::MAX),
            miss_hold_ms: limits.direct_miss_hold_ms(),
        }
    }

    /// Change the name `PAIRED` sends from now on.
    pub fn set_host_name(&mut self, host_name: String) {
        self.host_name = host_name;
    }

    /// Create an invitation that takes attempts for
    /// [`Limits::direct_invite_lifetime_secs`] from `now`. Draws the
    /// invitation id (16 bytes), then the code (12 bytes, drawn again while
    /// its lookup equals that of another open invitation here).
    pub fn create<R: CryptoRng + ?Sized>(
        &mut self,
        params: DirectInvitationParams,
        now: UnixTime,
        rng: &mut R,
    ) -> Result<CreatedDirectInvitation, DirectHostError> {
        if self.invitations.values().filter(|i| i.is_live()).count() >= self.max_open {
            return Err(DirectHostError::TooManyOpen);
        }
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let invitation = InvitationId(id);
        let taken: Vec<DirectLookup> = self
            .invitations
            .values()
            .filter(|i| i.is_live())
            .map(|i| i.lookup.clone())
            .collect();
        let code = DirectCode::generate_avoiding(rng, |l| taken.contains(l));
        let expires_at = now.plus(self.lifetime_secs);
        self.invitations.insert(
            invitation,
            DirectInvitation {
                lookup: code.lookup(),
                code: code.clone(),
                params,
                expires_at,
                status: DirectInvitationStatus::Open,
                expiry_handled: false,
                attempts_left: self.attempts_per_invitation,
                joiners: BTreeMap::new(),
                attempts: BTreeMap::new(),
                requests: BTreeMap::new(),
                outcomes: BTreeMap::new(),
                passed: BTreeSet::new(),
            },
        );
        Ok(CreatedDirectInvitation {
            invitation,
            code,
            expires_at,
            attempts_left: self.attempts_per_invitation,
        })
    }

    /// The invitation's status, while the host still keeps it.
    pub fn status(&self, invitation: &InvitationId) -> Option<DirectInvitationStatus> {
        self.invitations.get(invitation).map(|i| i.status)
    }

    /// Code attempts left on the invitation.
    pub fn attempts_left(&self, invitation: &InvitationId) -> Option<u8> {
        self.invitations.get(invitation).map(|i| i.attempts_left)
    }

    /// The code to show, while the invitation is open.
    pub fn code(&self, invitation: &InvitationId) -> Option<&DirectCode> {
        self.invitations
            .get(invitation)
            .filter(|i| i.status == DirectInvitationStatus::Open)
            .map(|i| &i.code)
    }

    /// The invitation a pairing connection belongs to.
    pub fn invitation_for(&self, conn: ConnectionId) -> Option<InvitationId> {
        self.by_conn.get(&conn).copied()
    }

    /// The invitation's approval prompts that are still answerable at `now`.
    pub fn approvals(&self, invitation: &InvitationId, now: UnixTime) -> Vec<DirectApproval> {
        let Some(inv) = self.invitations.get(invitation) else {
            return Vec::new();
        };
        inv.requests
            .iter()
            .filter(|(_, r)| now < self.window_end(r))
            .map(|(identity, _)| self.approval(invitation, inv, identity))
            .collect()
    }

    /// The owner cancelled the invitation. Grants nothing.
    pub fn cancel(&mut self, invitation: &InvitationId) -> Vec<DirectHostAction> {
        self.end(invitation, ErrorCode::Cancelled, None)
    }

    /// A `JOIN_DIRECT` arrived on `conn` from `joiner` (the identity of
    /// step 1), on a connection the TCP listener accepted (any other closes
    /// with `INVITATION_INVALID` before this; the I/O layer's job, as is
    /// the pre-authorization place a live connection takes first).
    ///
    /// Without a receipt it looks the lookup up among invitations that take
    /// attempts: a match admits the connection join-only and answers
    /// `AUTHORIZED {join_only, I}`; anything else is a [`MissHold`]. With a
    /// receipt it answers the recovery of wire.md 10.9.
    ///
    /// [`MissHold`]: DirectHostAction::MissHold
    #[allow(clippy::too_many_arguments)]
    pub fn on_join_direct(
        &mut self,
        conn: ConnectionId,
        joiner: &IdentityPublicKey,
        pair_exporter: &[u8; EXPORTER_LEN],
        lookup: &DirectLookup,
        name: &str,
        recovery: Option<DirectRecovery>,
        grants: &mut GrantTable,
        now: UnixTime,
    ) -> Vec<DirectHostAction> {
        let close = |code| vec![DirectHostAction::Close { conn, code }];
        if self.by_conn.contains_key(&conn) || self.enrolled.contains_key(&conn) {
            return close(ErrorCode::ProtocolError);
        }
        // A device never pairs with itself, and a denied one never pairs.
        if grants.is_denied(joiner) || *joiner == self.host_identity {
            return close(ErrorCode::NotAuthorized);
        }
        let Some(recovery) = recovery else {
            let found = self
                .invitations
                .iter()
                .find(|(_, i)| i.takes_attempts(now) && i.lookup == *lookup)
                .map(|(id, _)| *id);
            return match found {
                Some(id) => self.admit(conn, id, joiner, name, pair_exporter, false),
                None => self.miss(conn),
            };
        };
        self.recover(
            conn,
            joiner,
            pair_exporter,
            lookup,
            name,
            recovery,
            grants,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn recover(
        &mut self,
        conn: ConnectionId,
        joiner: &IdentityPublicKey,
        pair_exporter: &[u8; EXPORTER_LEN],
        lookup: &DirectLookup,
        name: &str,
        recovery: DirectRecovery,
        grants: &mut GrantTable,
        now: UnixTime,
    ) -> Vec<DirectHostAction> {
        let id = recovery.receipt;
        // A grant the direct invitation `I` made for this identity,
        // provisional or committed (also after a restart). A ticket's
        // receipt never matches.
        let made_here = |g: &&Grant| g.direct && g.enrolled_by == Some(id);
        let found = grants
            .provisional_grant(joiner, now)
            .filter(made_here)
            .map(|g| (g.id, g.role.clone(), true))
            .or_else(|| {
                grants
                    .live_grant(joiner, now)
                    .filter(made_here)
                    .map(|g| (g.id, g.role.clone(), false))
            });
        if let Some((grant, role, provisional)) = found {
            // A committed grant is never cancelled: the cancel came too
            // late, and the answer is the one without it.
            if recovery.cancel && provisional {
                let mut actions = self.undo(id, grant, conn, grants);
                actions.push(DirectHostAction::Close {
                    conn,
                    code: ErrorCode::Cancelled,
                });
                return actions;
            }
            return self.answer_by_receipt(conn, grant, role, provisional, grants, now);
        }
        let window = self.allow_window_secs;
        if !self
            .invitations
            .get(&id)
            .is_some_and(|i| i.lookup == *lookup)
        {
            return self.miss(conn);
        }
        // A recovery's cancel retires every attempt and connection of this
        // identity first, whatever it is answered, so a confirmation still
        // on its way opens no request after the cancel was answered.
        let mut retired = if recovery.cancel {
            self.retire(&id, joiner)
        } else {
            Vec::new()
        };
        let Some(inv) = self.invitations.get(&id) else {
            return self.miss(conn);
        };
        if let Some(outcome) = inv.outcomes.get(joiner).filter(|o| now < o.until) {
            retired.push(DirectHostAction::Close {
                conn,
                code: outcome.code,
            });
            // A cancel that retired the last running attempt may leave the
            // invitation with nothing to take.
            retired.extend(self.end_if_exhausted(&id, now));
            return retired;
        }
        // (allowed role, connection) of this identity's live request.
        let request = inv
            .requests
            .get(joiner)
            .filter(|r| now < r.passed_at.plus(window))
            .map(|r| (r.allowed_role.clone(), r.conn));
        let live = inv.takes_anything(now, window);
        let takes_attempts = inv.takes_attempts(now);
        let passed_before = inv.passed.contains(joiner);
        if recovery.cancel {
            if !live {
                retired.extend(self.miss(conn));
                return retired;
            }
            let mut actions = retired;
            if request.is_some() {
                actions.extend(self.drop_request(&id, joiner, ApprovalEnd::Cancelled));
            }
            actions.push(DirectHostAction::Close {
                conn,
                code: ErrorCode::Cancelled,
            });
            actions.extend(self.end_if_exhausted(&id, now));
            return actions;
        }
        match request {
            Some((Some(role), _)) => {
                // Allowed while it was away: enroll on this connection. A
                // grant that would be born expired is refused before
                // anything is sent.
                let expired = self
                    .invitations
                    .get(&id)
                    .and_then(|i| i.params.grant_expires_at)
                    .is_some_and(|t| now >= t);
                if expired {
                    let mut actions = vec![DirectHostAction::Close {
                        conn,
                        code: ErrorCode::InvitationInvalid,
                    }];
                    actions.extend(self.end(&id, ErrorCode::InvitationInvalid, None));
                    return actions;
                }
                let mut actions = self.admit(conn, id, joiner, name, pair_exporter, false);
                actions.extend(self.enroll(&id, conn, role, grants, now));
                actions
            }
            Some((None, old)) => {
                // Still waiting for Allow: the request (same id, same
                // prompt) now points at this connection.
                let mut actions = Vec::new();
                if let Some(old) = old {
                    self.forget_conn(&id, old);
                    actions.push(DirectHostAction::Close {
                        conn: old,
                        code: ErrorCode::PathReplaced,
                    });
                }
                actions.extend(self.admit(conn, id, joiner, name, pair_exporter, false));
                if let Some(r) = self
                    .invitations
                    .get_mut(&id)
                    .and_then(|i| i.requests.get_mut(joiner))
                {
                    r.conn = Some(conn);
                }
                actions.extend(self.approval_action(&id, joiner));
                actions
            }
            // The host never had this identity's confirmation.
            None if takes_attempts && !passed_before => {
                self.admit(conn, id, joiner, name, pair_exporter, true)
            }
            None => self.miss(conn),
        }
    }

    /// Answer a recovery by its receipt: `PAIRED` with the grant's role,
    /// after binding the connection to that grant when step 2 did not (and
    /// `AUTHORIZED {live}` first when step 2 sent none).
    fn answer_by_receipt(
        &mut self,
        conn: ConnectionId,
        grant: GrantId,
        role: Role,
        provisional: bool,
        grants: &mut GrantTable,
        now: UnixTime,
    ) -> Vec<DirectHostAction> {
        let mut actions = Vec::new();
        let bound = grants.binding(conn);
        if bound != Some(grant) {
            grants.unbind(conn);
            if grants.bind(conn, grant, now).is_err() {
                return vec![DirectHostAction::Close {
                    conn,
                    code: ErrorCode::InternalError,
                }];
            }
            actions.push(DirectHostAction::Bound {
                conn,
                grant,
                provisional,
            });
            if bound.is_none() {
                // A pinned caller needs an `AUTHORIZED` before `PAIRED`
                // (wire.md 8.2), and step 2 sent none.
                actions.push(DirectHostAction::Send {
                    conn,
                    message: ControlMessage::Authorized {
                        state: AuthorizedState::Live,
                    },
                });
            }
        }
        actions.push(DirectHostAction::Send {
            conn,
            message: ControlMessage::Paired {
                host_name: self.host_name.clone(),
                role,
            },
        });
        actions
    }

    /// A `CODE_EXCHANGE` arrived on a connection this machine admitted.
    pub fn on_code_exchange<R: CryptoRng + ?Sized>(
        &mut self,
        conn: ConnectionId,
        attempt: AttemptId,
        payload: &[u8],
        now: UnixTime,
        rng: &mut R,
    ) -> Vec<DirectHostAction> {
        let close = |code| vec![DirectHostAction::Close { conn, code }];
        let Some(id) = self.by_conn.get(&conn).copied() else {
            return close(ErrorCode::NotAuthorized);
        };
        let host = self.host_identity;
        let Some(inv) = self.invitations.get_mut(&id) else {
            return close(ErrorCode::InvitationInvalid);
        };
        let key = (conn, attempt);
        // No attempt starts or goes on once the invitation stops taking
        // attempts: a code passes only before its expiry.
        if !inv.takes_attempts(now) {
            if let Some(a) = inv.attempts.get_mut(&key) {
                a.state = AttemptState::Failed;
                a.exchange = None;
            }
            self.forget_conn(&id, conn);
            return close(ErrorCode::InvitationInvalid);
        }
        let mut actions = Vec::new();
        if let Some(existing) = inv.attempts.get(&key) {
            if existing.state != AttemptState::Running {
                return vec![DirectHostAction::Send {
                    conn,
                    message: ControlMessage::CodeAbort {
                        attempt,
                        code: ErrorCode::PairingFailed,
                    },
                }];
            }
        } else {
            let Some(joiner) = inv.joiners.get_mut(&conn) else {
                return close(ErrorCode::InternalError);
            };
            // One attempt per connection: the next try is a new Connect.
            if joiner.attempt.is_some() {
                self.forget_conn(&id, conn);
                return close(ErrorCode::ProtocolError);
            }
            if inv.attempts_left == 0 {
                self.forget_conn(&id, conn);
                return close(ErrorCode::AttemptsExhausted);
            }
            // Debit first. Nothing below runs on an undebited attempt.
            // Must-fail control: the attempt is not debited.
            if !cfg!(mousse_control = "direct-attempt-not-debited") {
                inv.attempts_left -= 1;
            }
            joiner.attempt = Some(attempt);
            actions.push(DirectHostAction::AttemptsLeft {
                invitation: id,
                attempts_left: inv.attempts_left,
            });
            let binding = direct_binding_transcript(
                &inv.lookup,
                &id,
                &host,
                &joiner.identity,
                &joiner.pair_exporter,
            );
            let sid = attempt_sid(&attempt, &joiner.pair_exporter);
            let secret = inv.code.secret();
            let exchange = self.factory.start(
                ExchangeRole::Responder,
                secret.as_bytes(),
                &binding,
                &sid,
                rng,
            );
            inv.attempts.insert(
                key,
                DirectAttempt {
                    exchange: Some(exchange),
                    state: AttemptState::Running,
                },
            );
        }
        let Some(record) = inv.attempts.get_mut(&key) else {
            return actions;
        };
        let result = match record.exchange.as_mut() {
            Some(exchange) => exchange.step(Some(payload)),
            None => return actions,
        };
        match result {
            Ok(step) => {
                actions.extend(step.send.map(|payload| DirectHostAction::Send {
                    conn,
                    message: ControlMessage::CodeExchange { attempt, payload },
                }));
                if step.peer_confirmed {
                    record.state = AttemptState::Succeeded;
                    record.exchange = None;
                    actions.extend(self.passed(&id, conn, now));
                }
                actions
            }
            Err(_) => {
                record.state = AttemptState::Failed;
                record.exchange = None;
                actions.push(DirectHostAction::Send {
                    conn,
                    message: ControlMessage::CodeAbort {
                        attempt,
                        code: ErrorCode::PairingFailed,
                    },
                });
                actions.extend(self.end_if_exhausted(&id, now));
                actions
            }
        }
    }

    /// A `CODE_ABORT` arrived. It ends a running attempt (its debit stays).
    /// With `CANCELLED` from a device waiting for Allow on this connection,
    /// its request goes. On a connection this machine enrolled, only the
    /// joiner's `CANCELLED` for the attempt that passed there counts (the
    /// gate lets that one through, wire.md 8.1): it removes the provisional
    /// grant, and the connection closes with `CANCELLED`. Once the grant
    /// committed it is ignored.
    pub fn on_code_abort(
        &mut self,
        conn: ConnectionId,
        attempt: AttemptId,
        code: ErrorCode,
        grants: &mut GrantTable,
        now: UnixTime,
    ) -> Vec<DirectHostAction> {
        if let Some(enrolled) = self.enrolled.get(&conn).copied() {
            if code != ErrorCode::Cancelled
                || enrolled.attempt != Some(attempt)
                || !grants.is_provisional(enrolled.grant)
            {
                return Vec::new();
            }
            self.enrolled.remove(&conn);
            let mut actions = self.undo(enrolled.invitation, enrolled.grant, conn, grants);
            actions.push(DirectHostAction::Close {
                conn,
                code: ErrorCode::Cancelled,
            });
            return actions;
        }
        let Some(id) = self.by_conn.get(&conn).copied() else {
            return Vec::new();
        };
        let mut actions = Vec::new();
        if let Some(inv) = self.invitations.get_mut(&id) {
            if let Some(record) = inv.attempts.get_mut(&(conn, attempt)) {
                if record.state == AttemptState::Running {
                    record.state = AttemptState::Failed;
                    record.exchange = None;
                }
            }
            // Only the attempt that passed counts: not one merely running
            // on the connection a recovery moved the request to.
            let passed = waiting_on(inv, conn).filter(|identity| {
                inv.requests
                    .get(identity)
                    .is_some_and(|r| r.attempt == Some(attempt))
            });
            if code == ErrorCode::Cancelled {
                if let Some(identity) = passed {
                    actions.extend(self.drop_request(&id, &identity, ApprovalEnd::Cancelled));
                }
            }
        }
        actions.extend(self.end_if_exhausted(&id, now));
        actions
    }

    /// A connection closed, with the code of the peer's `GOAWAY` if it sent
    /// one. Its running attempt counts as failed. A device waiting for Allow
    /// keeps its request (now away) unless it closed with `CANCELLED`; on a
    /// connection this machine enrolled, `CANCELLED` removes the grant while
    /// it is provisional.
    pub fn on_connection_closed(
        &mut self,
        conn: ConnectionId,
        code: Option<ErrorCode>,
        grants: &mut GrantTable,
        now: UnixTime,
    ) -> Vec<DirectHostAction> {
        if let Some(enrolled) = self.enrolled.remove(&conn) {
            return if code == Some(ErrorCode::Cancelled) && grants.is_provisional(enrolled.grant) {
                self.undo(enrolled.invitation, enrolled.grant, conn, grants)
            } else {
                Vec::new()
            };
        }
        let Some(id) = self.by_conn.get(&conn).copied() else {
            return Vec::new();
        };
        let waiting = self
            .invitations
            .get(&id)
            .and_then(|inv| waiting_on(inv, conn));
        self.forget_conn(&id, conn);
        let mut actions = Vec::new();
        if let Some(identity) = waiting {
            if code == Some(ErrorCode::Cancelled) {
                actions.extend(self.drop_request(&id, &identity, ApprovalEnd::Cancelled));
            } else {
                if let Some(r) = self
                    .invitations
                    .get_mut(&id)
                    .and_then(|i| i.requests.get_mut(&identity))
                {
                    r.conn = None;
                }
                actions.extend(self.approval_action(&id, &identity));
            }
        }
        actions.extend(self.end_if_exhausted(&id, now));
        actions
    }

    /// The gate held the first stream frame of `conn`, bound to the
    /// provisional `grant` ([`crate::authz::Verdict::Commit`]): commit it
    /// (wire.md 10.9) before the frame is released. On success the device
    /// holds `grant` now, its older grant's connections close, and the
    /// frame goes on ([`crate::authz::ConnectionGate::committed`]). When
    /// the commit fails (the grant expired, or the device was denied), the
    /// provisional grant is removed, `conn` closes with `GRANT_REVOKED`, and
    /// the older grant and its connections stay. A grant that already
    /// committed has nothing more to do.
    pub fn on_first_stream(
        &mut self,
        conn: ConnectionId,
        grant: GrantId,
        grants: &mut GrantTable,
        now: UnixTime,
    ) -> Vec<DirectHostAction> {
        let identity = grants
            .provisional(grant)
            .or_else(|| grants.get(grant))
            .map(|g| g.identity);
        match grants.commit(grant, now) {
            Ok(events) => {
                // Committed: nothing cancels it now. An I/O layer that
                // cannot store the commit puts these records back with the
                // grant table ([`DirectHostPairing::records`]).
                self.enrolled.retain(|_, e| e.grant != grant);
                let mut actions: Vec<DirectHostAction> =
                    events.into_iter().map(DirectHostAction::Grant).collect();
                if let Some(identity) = identity {
                    actions.push(DirectHostAction::Committed {
                        conn,
                        grant,
                        identity,
                        bound: grants.channels(grant),
                    });
                }
                actions
            }
            Err(_) => {
                self.enrolled.retain(|_, e| e.grant != grant);
                let undone = grants.provisional(grant).and_then(|g| removal(g, grant));
                grants.unbind(conn);
                let mut actions: Vec<DirectHostAction> = grants
                    .remove(grant)
                    .into_iter()
                    .map(DirectHostAction::Grant)
                    .collect();
                actions.extend(undone);
                actions.push(DirectHostAction::Close {
                    conn,
                    code: ErrorCode::GrantRevoked,
                });
                actions
            }
        }
    }

    /// The owner allowed `request`, with the role chosen with the answer
    /// (`None`: the invitation's role). A connected device is enrolled now;
    /// one that is away is marked allowed and enrolled when it reconnects.
    /// Either way every other request ends.
    pub fn allow(
        &mut self,
        request: &DirectRequestId,
        role: Option<Role>,
        grants: &mut GrantTable,
        now: UnixTime,
    ) -> Result<Vec<DirectHostAction>, DirectHostError> {
        let window = self.allow_window_secs;
        let id = request.invitation;
        let inv = self
            .invitations
            .get_mut(&id)
            .ok_or(DirectHostError::UnknownInvitation)?;
        if inv.status != DirectInvitationStatus::Open {
            return Err(DirectHostError::NotOpen);
        }
        let r = inv
            .requests
            .get_mut(&request.identity)
            .filter(|r| now < r.passed_at.plus(window))
            .ok_or(DirectHostError::UnknownRequest)?;
        // What can fail is checked before anything changes.
        if grants.is_denied(&request.identity) {
            return Err(DirectHostError::Denied);
        }
        if inv.params.grant_expires_at.is_some_and(|t| now >= t) {
            return Err(DirectHostError::GrantExpired);
        }
        let role = role.unwrap_or_else(|| inv.params.role.clone());
        if let Some(conn) = r.conn {
            return Ok(self.enroll(&id, conn, role, grants, now));
        }
        r.allowed_role = Some(role.clone());
        // Must-fail control (tests only): the grant is made at once, with no
        // connection of that identity.
        if cfg!(mousse_control = "direct-enroll-without-connection") {
            let _ = grants.add(
                NewGrant {
                    identity: request.identity,
                    name: r.name.clone(),
                    role,
                    authorizing_owner: inv.params.authorizing_owner,
                    expires_at: inv.params.grant_expires_at,
                    enrolled_by: Some(id),
                },
                now,
            );
        }
        inv.status = DirectInvitationStatus::Allowed {
            identity: request.identity,
        };
        let mut actions = self.dismiss_others(&id, Some(&request.identity));
        actions.extend(self.approval_action(&id, &request.identity));
        Ok(actions)
    }

    /// The I/O layer could not store the enrollment this invitation made,
    /// and put the grant table back as it was: no grant was made. The
    /// invitation ends with `INTERNAL_ERROR` instead of being consumed, as
    /// a restart would find it; the I/O layer reports the end and closes
    /// the device's connection.
    pub fn enrollment_not_stored(&mut self, invitation: &InvitationId) {
        let Some(inv) = self.invitations.get_mut(invitation) else {
            return;
        };
        if let DirectInvitationStatus::Consumed { .. } = inv.status {
            inv.status = DirectInvitationStatus::Ended(ErrorCode::InternalError);
        }
    }

    /// The connection records a grant-table change goes with
    /// ([`DirectRecords`]).
    pub fn records(&self) -> DirectRecords {
        DirectRecords {
            by_conn: self.by_conn.clone(),
            enrolled: self.enrolled.clone(),
        }
    }

    /// Put back the records taken by [`DirectHostPairing::records`], when
    /// the grant table goes back to what it was then.
    pub fn restore_records(&mut self, records: DirectRecords) {
        self.by_conn = records.by_conn;
        self.enrolled = records.enrolled;
    }

    /// The owner declined `request`. Its device's connection closes with
    /// `PAIRING_DECLINED`, which its recovery also gets until the Allow
    /// window ends, and the invitation ends.
    pub fn decline(
        &mut self,
        request: &DirectRequestId,
        now: UnixTime,
    ) -> Result<Vec<DirectHostAction>, DirectHostError> {
        let window = self.allow_window_secs;
        let id = request.invitation;
        let inv = self
            .invitations
            .get(&id)
            .ok_or(DirectHostError::UnknownInvitation)?;
        if !inv.is_live() {
            return Err(DirectHostError::NotOpen);
        }
        if !inv
            .requests
            .get(&request.identity)
            .is_some_and(|r| now < r.passed_at.plus(window))
        {
            return Err(DirectHostError::UnknownRequest);
        }
        let mut actions = self.drop_request(&id, &request.identity, ApprovalEnd::Declined);
        actions.extend(self.end(&id, ErrorCode::PairingDeclined, None));
        Ok(actions)
    }

    /// End what time has ended: requests past their Allow window (an
    /// allowed one that was never claimed ends its invitation), kept
    /// outcomes, invitations past their expiry with no request left, and
    /// invitations out of attempts. Forgets ended invitations that keep
    /// nothing.
    pub fn tick(&mut self, now: UnixTime) -> Vec<DirectHostAction> {
        let window = self.allow_window_secs;
        let ids: Vec<InvitationId> = self.invitations.keys().copied().collect();
        let mut actions = Vec::new();
        for id in ids {
            let Some(inv) = self.invitations.get_mut(&id) else {
                continue;
            };
            inv.outcomes.retain(|_, o| now < o.until);
            let ended: Vec<IdentityPublicKey> = inv
                .requests
                .iter()
                .filter(|(_, r)| now >= r.passed_at.plus(window))
                .map(|(k, _)| *k)
                .collect();
            for identity in ended {
                actions.extend(self.drop_request(&id, &identity, ApprovalEnd::WindowEnded));
            }
            let Some(inv) = self.invitations.get_mut(&id) else {
                continue;
            };
            if inv.status == DirectInvitationStatus::Open && now >= inv.expires_at {
                inv.expiry_handled = true;
                if inv.requests.is_empty() {
                    actions.extend(self.end(&id, ErrorCode::InvitationInvalid, None));
                } else {
                    // Only the devices waiting for Allow stay.
                    let idle: Vec<ConnectionId> = inv
                        .joiners
                        .iter()
                        .filter(|(c, j)| {
                            inv.requests
                                .get(&j.identity)
                                .is_none_or(|r| r.conn != Some(**c))
                        })
                        .map(|(c, _)| *c)
                        .collect();
                    for conn in idle {
                        self.forget_conn(&id, conn);
                        actions.push(DirectHostAction::Close {
                            conn,
                            code: ErrorCode::InvitationInvalid,
                        });
                    }
                }
            }
            actions.extend(self.end_if_exhausted(&id, now));
        }
        self.invitations
            .retain(|_, i| i.is_live() || !i.outcomes.is_empty() || !i.joiners.is_empty());
        actions
    }

    /// The grant table's expiry ([`GrantTable::tick`], at
    /// [`GrantTable::next_expiry`]): every expired grant's connections close,
    /// then each expired provisional grant a direct invitation made is
    /// reported removed ([`DirectHostAction::EnrollmentUndone`], in grant id
    /// order), also when no connection was bound to it.
    pub fn expire_grants(
        &mut self,
        grants: &mut GrantTable,
        now: UnixTime,
    ) -> Vec<DirectHostAction> {
        let undone: Vec<DirectHostAction> = grants
            .provisional_grants()
            .filter(|g| g.expires_at.is_some_and(|t| now >= t))
            .filter_map(|g| removal(g, g.id))
            .collect();
        for a in &undone {
            if let DirectHostAction::EnrollmentUndone { grant, .. } = a {
                self.enrolled.retain(|_, e| e.grant != *grant);
            }
        }
        let mut actions: Vec<DirectHostAction> = grants
            .tick(now)
            .into_iter()
            .map(DirectHostAction::Grant)
            .collect();
        actions.extend(undone);
        actions
    }

    /// When [`DirectHostPairing::tick`] next has something to do.
    pub fn next_deadline(&self) -> Option<UnixTime> {
        let window = self.allow_window_secs;
        self.invitations
            .values()
            .flat_map(|i| {
                let expiry = (i.status == DirectInvitationStatus::Open && !i.expiry_handled)
                    .then_some(i.expires_at);
                expiry
                    .into_iter()
                    .chain(i.requests.values().map(move |r| r.passed_at.plus(window)))
                    .chain(i.outcomes.values().map(|o| o.until))
            })
            .min()
    }

    fn window_end(&self, r: &Request) -> UnixTime {
        r.passed_at.plus(self.allow_window_secs)
    }

    fn miss(&self, conn: ConnectionId) -> Vec<DirectHostAction> {
        vec![DirectHostAction::MissHold {
            conn,
            hold_ms: self.miss_hold_ms,
        }]
    }

    fn admit(
        &mut self,
        conn: ConnectionId,
        id: InvitationId,
        joiner: &IdentityPublicKey,
        name: &str,
        pair_exporter: &[u8; EXPORTER_LEN],
        not_received: bool,
    ) -> Vec<DirectHostAction> {
        let Some(inv) = self.invitations.get_mut(&id) else {
            return self.miss(conn);
        };
        inv.joiners.insert(
            conn,
            DirectJoiner {
                identity: *joiner,
                name: name.to_owned(),
                pair_exporter: *pair_exporter,
                attempt: None,
            },
        );
        self.by_conn.insert(conn, id);
        vec![
            DirectHostAction::AdmittedJoinOnly {
                conn,
                invitation: id,
            },
            DirectHostAction::Send {
                conn,
                message: ControlMessage::AuthorizedDirect {
                    invitation: id,
                    not_received,
                },
            },
        ]
    }

    /// The device on `conn` passed the code: open its request, or keep the
    /// one it has and point it at this connection.
    fn passed(
        &mut self,
        id: &InvitationId,
        conn: ConnectionId,
        now: UnixTime,
    ) -> Vec<DirectHostAction> {
        let window = self.allow_window_secs;
        let Some(inv) = self.invitations.get_mut(id) else {
            return Vec::new();
        };
        let Some(joiner) = inv.joiners.get(&conn) else {
            return Vec::new();
        };
        let identity = joiner.identity;
        let name = joiner.name.clone();
        let attempt = joiner.attempt;
        inv.passed.insert(identity);
        let mut actions = Vec::new();
        match inv
            .requests
            .get_mut(&identity)
            .filter(|r| now < r.passed_at.plus(window))
        {
            Some(r) => {
                // One request per identity: same id, no second prompt.
                r.attempt = attempt;
                if let Some(old) = r.conn.replace(conn).filter(|old| *old != conn) {
                    self.forget_conn(id, old);
                    actions.push(DirectHostAction::Close {
                        conn: old,
                        code: ErrorCode::PathReplaced,
                    });
                }
            }
            None => {
                inv.outcomes.remove(&identity);
                inv.requests.insert(
                    identity,
                    Request {
                        name,
                        passed_at: now,
                        conn: Some(conn),
                        attempt,
                        allowed_role: None,
                    },
                );
            }
        }
        // Must-fail control (tests only): the code alone pairs.
        if cfg!(mousse_control = "direct-skip-allow") {
            if let Some(role) = self.invitations.get(id).map(|i| i.params.role.clone()) {
                let mut grants = GrantTable::new();
                actions.extend(self.enroll(id, conn, role, &mut grants, now));
                return actions;
            }
        }
        actions.extend(self.approval_action(id, &identity));
        actions
    }

    fn approval(
        &self,
        id: &InvitationId,
        inv: &DirectInvitation<F::Exchange>,
        identity: &IdentityPublicKey,
    ) -> DirectApproval {
        let r = &inv.requests[identity];
        DirectApproval {
            request: DirectRequestId {
                invitation: *id,
                identity: *identity,
            },
            name: r.name.clone(),
            role: r
                .allowed_role
                .clone()
                .unwrap_or_else(|| inv.params.role.clone()),
            presence: if r.conn.is_some() {
                RequestPresence::Connected
            } else {
                RequestPresence::Away
            },
            decision: if r.allowed_role.is_some() {
                RequestDecision::Allowed
            } else {
                RequestDecision::Pending
            },
            answer_by: self.window_end(r),
        }
    }

    fn approval_action(
        &self,
        id: &InvitationId,
        identity: &IdentityPublicKey,
    ) -> Option<DirectHostAction> {
        let inv = self.invitations.get(id)?;
        inv.requests
            .contains_key(identity)
            .then(|| DirectHostAction::Approval(self.approval(id, inv, identity)))
    }

    /// Every pairing connection of `identity` on the invitation closes with
    /// `CANCELLED`, and its running attempt fails.
    fn retire(&mut self, id: &InvitationId, identity: &IdentityPublicKey) -> Vec<DirectHostAction> {
        let conns: Vec<ConnectionId> = self
            .invitations
            .get(id)
            .map(|inv| {
                inv.joiners
                    .iter()
                    .filter(|(_, j)| j.identity == *identity)
                    .map(|(c, _)| *c)
                    .collect()
            })
            .unwrap_or_default();
        conns
            .into_iter()
            .map(|conn| {
                self.forget_conn(id, conn);
                DirectHostAction::Close {
                    conn,
                    code: ErrorCode::Cancelled,
                }
            })
            .collect()
    }

    /// Forget `conn` as a pairing connection: its running attempt fails.
    /// The caller closes it.
    fn forget_conn(&mut self, id: &InvitationId, conn: ConnectionId) {
        self.by_conn.remove(&conn);
        if let Some(inv) = self.invitations.get_mut(id) {
            inv.joiners.remove(&conn);
            for ((c, _), a) in inv.attempts.iter_mut() {
                if *c == conn && a.state == AttemptState::Running {
                    a.state = AttemptState::Failed;
                    a.exchange = None;
                }
            }
            for r in inv.requests.values_mut() {
                if r.conn == Some(conn) {
                    r.conn = None;
                }
            }
        }
    }

    /// End `identity`'s request. A declined or cancelled one keeps its
    /// outcome for its recovery until its Allow window ends, and its
    /// connection closes with that code. An allowed request that goes ends
    /// the invitation.
    fn drop_request(
        &mut self,
        id: &InvitationId,
        identity: &IdentityPublicKey,
        reason: ApprovalEnd,
    ) -> Vec<DirectHostAction> {
        let window = self.allow_window_secs;
        let Some(inv) = self.invitations.get_mut(id) else {
            return Vec::new();
        };
        let Some(r) = inv.requests.remove(identity) else {
            return Vec::new();
        };
        let kept = match reason {
            ApprovalEnd::Declined => Some(ErrorCode::PairingDeclined),
            ApprovalEnd::Cancelled => Some(ErrorCode::Cancelled),
            _ => None,
        };
        if let Some(code) = kept {
            inv.outcomes.insert(
                *identity,
                Outcome {
                    code,
                    until: r.passed_at.plus(window),
                },
            );
        }
        let was_allowed = inv.status
            == DirectInvitationStatus::Allowed {
                identity: *identity,
            };
        let mut actions = vec![DirectHostAction::ApprovalEnded {
            request: DirectRequestId {
                invitation: *id,
                identity: *identity,
            },
            reason,
        }];
        if let Some(conn) = r.conn {
            self.forget_conn(id, conn);
            actions.push(DirectHostAction::Close {
                conn,
                code: kept.unwrap_or(ErrorCode::InvitationInvalid),
            });
        }
        if was_allowed {
            // Nothing else may be enrolled now: the invitation ends as the
            // request did (declined, cancelled), or as invalid.
            let reason = kept.unwrap_or(ErrorCode::InvitationInvalid);
            actions.extend(self.end(id, reason, None));
        }
        actions
    }

    /// End every request but `keep`'s and close every pairing connection
    /// that is not `keep`'s, with `INVITATION_INVALID`.
    fn dismiss_others(
        &mut self,
        id: &InvitationId,
        keep: Option<&IdentityPublicKey>,
    ) -> Vec<DirectHostAction> {
        let Some(inv) = self.invitations.get_mut(id) else {
            return Vec::new();
        };
        let others: Vec<IdentityPublicKey> = inv
            .requests
            .keys()
            .filter(|k| Some(*k) != keep)
            .copied()
            .collect();
        let mut actions = Vec::new();
        for identity in others {
            actions.extend(self.drop_request(id, &identity, ApprovalEnd::Dismissed));
        }
        let Some(inv) = self.invitations.get_mut(id) else {
            return actions;
        };
        inv.attempts.clear();
        let conns: Vec<ConnectionId> = inv.joiners.keys().copied().collect();
        for conn in conns {
            self.forget_conn(id, conn);
            actions.push(DirectHostAction::Close {
                conn,
                code: ErrorCode::InvitationInvalid,
            });
        }
        actions
    }

    /// End a live invitation without enrollment: every request ends, every
    /// pairing connection closes (`code`, or the reason when `None`; a
    /// decline closes the others with `INVITATION_INVALID`).
    fn end(
        &mut self,
        id: &InvitationId,
        reason: ErrorCode,
        code: Option<ErrorCode>,
    ) -> Vec<DirectHostAction> {
        let Some(inv) = self.invitations.get_mut(id) else {
            return Vec::new();
        };
        if !inv.is_live() {
            return Vec::new();
        }
        inv.status = DirectInvitationStatus::Ended(reason);
        inv.attempts.clear();
        let close_with = code.unwrap_or(match reason {
            ErrorCode::PairingDeclined => ErrorCode::InvitationInvalid,
            other => other,
        });
        let requests: Vec<IdentityPublicKey> = inv.requests.keys().copied().collect();
        let mut actions = Vec::new();
        for identity in requests {
            let Some(r) = self
                .invitations
                .get_mut(id)
                .and_then(|i| i.requests.remove(&identity))
            else {
                continue;
            };
            actions.push(DirectHostAction::ApprovalEnded {
                request: DirectRequestId {
                    invitation: *id,
                    identity,
                },
                reason: ApprovalEnd::Dismissed,
            });
            if let Some(conn) = r.conn {
                self.forget_conn(id, conn);
                actions.push(DirectHostAction::Close {
                    conn,
                    code: close_with,
                });
            }
        }
        let conns: Vec<ConnectionId> = self
            .invitations
            .get(id)
            .map(|i| i.joiners.keys().copied().collect())
            .unwrap_or_default();
        for conn in conns {
            self.forget_conn(id, conn);
            actions.push(DirectHostAction::Close {
                conn,
                code: close_with,
            });
        }
        actions.push(DirectHostAction::InvitationEnded {
            invitation: *id,
            reason,
        });
        actions
    }

    fn end_if_exhausted(&mut self, id: &InvitationId, now: UnixTime) -> Vec<DirectHostAction> {
        let window = self.allow_window_secs;
        let exhausted = self.invitations.get(id).is_some_and(|inv| {
            inv.status == DirectInvitationStatus::Open
                && inv.attempts_left == 0
                && !inv
                    .attempts
                    .values()
                    .any(|a| a.state == AttemptState::Running)
                // A request inside its Allow window keeps the invitation.
                && !inv
                    .requests
                    .values()
                    .any(|r| now < r.passed_at.plus(window))
        });
        if exhausted {
            self.end(id, ErrorCode::AttemptsExhausted, None)
        } else {
            Vec::new()
        }
    }

    /// Enrollment (wire.md 10.8, 10.9) with receipt `I`, on `conn`, a
    /// connection of the requesting identity: a provisional grant bound to
    /// `conn`, the invitation consumed, `PAIRED`, then every other request
    /// and pairing connection ends. The identity's older grant stays until
    /// the new one commits. When the grant cannot be made (it would be born
    /// expired, or the device is denied) nothing in the table changes; the
    /// connection closes, and the invitation ends as invalid.
    fn enroll(
        &mut self,
        id: &InvitationId,
        conn: ConnectionId,
        role: Role,
        grants: &mut GrantTable,
        now: UnixTime,
    ) -> Vec<DirectHostAction> {
        let Some(inv) = self.invitations.get_mut(id) else {
            return Vec::new();
        };
        let Some((identity, attempt)) = inv.joiners.get(&conn).map(|j| (j.identity, j.attempt))
        else {
            return Vec::new();
        };
        let Some(request) = inv.requests.get(&identity) else {
            return Vec::new();
        };
        let new_grant = NewGrant {
            identity,
            name: request.name.clone(),
            role: role.clone(),
            authorizing_owner: inv.params.authorizing_owner,
            expires_at: inv.params.grant_expires_at,
            enrolled_by: Some(*id),
        };
        let replaced = grants
            .provisional_grants()
            .find(|g| g.identity == identity)
            .and_then(|g| removal(g, g.id));
        let (grant, events) = match grants.add_provisional(new_grant, conn, now) {
            Ok(added) => added,
            Err(e) => {
                let code = if e == GrantError::Denied {
                    ErrorCode::NotAuthorized
                } else {
                    ErrorCode::InvitationInvalid
                };
                self.forget_conn(id, conn);
                let mut actions = vec![DirectHostAction::Close { conn, code }];
                actions.extend(self.end(id, ErrorCode::InvitationInvalid, None));
                return actions;
            }
        };
        if let Some(inv) = self.invitations.get_mut(id) {
            inv.status = DirectInvitationStatus::Consumed { grant };
            inv.requests.remove(&identity);
            inv.joiners.remove(&conn);
        }
        self.by_conn.remove(&conn);
        self.enrolled.insert(
            conn,
            EnrolledConn {
                invitation: *id,
                grant,
                attempt,
            },
        );
        let mut actions: Vec<DirectHostAction> =
            events.into_iter().map(DirectHostAction::Grant).collect();
        if let Some(undone) = replaced {
            if let DirectHostAction::EnrollmentUndone { grant: old, .. } = undone {
                self.enrolled.retain(|_, e| e.grant != old);
            }
            actions.push(undone);
        }
        actions.push(DirectHostAction::ApprovalEnded {
            request: DirectRequestId {
                invitation: *id,
                identity,
            },
            reason: ApprovalEnd::Enrolled,
        });
        actions.push(DirectHostAction::Enrolled {
            invitation: *id,
            conn,
            grant,
            identity,
            role: role.clone(),
            attempt,
        });
        actions.push(DirectHostAction::Send {
            conn,
            message: ControlMessage::Paired {
                host_name: self.host_name.clone(),
                role,
            },
        });
        // wire.md 10.8 step 5: then every other request and connection.
        actions.extend(self.dismiss_others(id, None));
        actions
    }

    /// The device cancelled across the Allow: remove the provisional grant
    /// this invitation made for it, if it is still that grant.
    fn undo(
        &mut self,
        id: InvitationId,
        grant: GrantId,
        conn: ConnectionId,
        grants: &mut GrantTable,
    ) -> Vec<DirectHostAction> {
        // Must-fail control (tests only): the Allow wins over the cancel.
        if cfg!(mousse_control = "direct-allow-beats-cancel") {
            return Vec::new();
        }
        let Some(identity) = grants
            .provisional(grant)
            .filter(|g| g.direct && g.enrolled_by == Some(id))
            .map(|g| g.identity)
        else {
            return Vec::new();
        };
        self.enrolled.retain(|_, e| e.grant != grant);
        grants.unbind(conn);
        let mut actions: Vec<DirectHostAction> = grants
            .remove(grant)
            .into_iter()
            .map(DirectHostAction::Grant)
            .collect();
        actions.push(DirectHostAction::EnrollmentUndone {
            invitation: id,
            grant,
            identity,
        });
        actions
    }
}

/// The removal report of provisional grant `id`, made by a direct
/// invitation.
fn removal(g: &Grant, id: GrantId) -> Option<DirectHostAction> {
    g.enrolled_by
        .filter(|_| g.direct)
        .map(|invitation| DirectHostAction::EnrollmentUndone {
            invitation,
            grant: id,
            identity: g.identity,
        })
}

/// The identity whose request waits on `conn`, if any.
fn waiting_on<E>(inv: &DirectInvitation<E>, conn: ConnectionId) -> Option<IdentityPublicKey> {
    let joiner = inv.joiners.get(&conn)?;
    inv.requests
        .get(&joiner.identity)
        .filter(|r| r.conn == Some(conn))
        .map(|_| joiner.identity)
}

#[cfg(test)]
#[path = "direct_host_tests.rs"]
mod tests;
