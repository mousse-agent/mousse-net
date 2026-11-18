//! The host's pairing state machine.
//!
//! The host keeps one pending record per invitation. The record fixes the
//! kind, holds the ticket secret and (for "send link") the code, counts code
//! attempts across every route, and is consumed atomically by the first
//! enrollment.

use std::collections::BTreeMap;
use std::fmt;

use rand_core::CryptoRng;

use super::exchange::{CodeExchange, CodeExchangeFactory, ExchangeRole, PairingCode};
use super::proof::{
    attempt_sid, binding_transcript, verify_join_proof, SessionExporters, EXPORTER_LEN,
};
use super::ticket::{
    Ticket, TicketSecret, MAX_ROUTES, MAX_ROUTE_LEN, TICKET_LIFETIME_SECS, TICKET_VERSION,
};
use super::{AttemptId, InvitationId, InvitationKind};
use crate::control::{AuthorizedState, ControlMessage};
use crate::grants::{GrantError, GrantEvent, GrantId, GrantTable, NewGrant, OwnerRef, Role};
use crate::identity::IdentityPublicKey;
use crate::time::UnixTime;
use crate::{ConnectionId, ErrorCode};

/// Code attempts the host allows per invitation, across all routes.
pub const HOST_ATTEMPTS_PER_INVITATION: u8 = 3;

/// What the host owner chose when creating an invitation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationParams {
    /// In person or send link. Fixed for the invitation's life.
    pub kind: InvitationKind,
    /// The role the new grant will carry.
    pub role: Role,
    /// The owner or profile authorizing the grant.
    pub authorizing_owner: OwnerRef,
    /// Route hints for the ticket.
    pub routes: Vec<String>,
    /// Optional expiry for the resulting grant.
    pub grant_expires_at: Option<UnixTime>,
}

/// A new invitation, ready to show as a QR code or link.
#[derive(Clone, Debug)]
pub struct CreatedInvitation {
    /// The ticket.
    pub ticket: Ticket,
    /// The ticket's URL-fragment form.
    pub fragment: String,
}

/// Where an invitation stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationStatus {
    /// Waiting for a joiner.
    Open,
    /// One device was enrolled; the invitation is spent.
    Consumed {
        /// The grant it created.
        grant: GrantId,
    },
    /// Ended without enrollment: `Cancelled`, `PairingDeclined`,
    /// `AttemptsExhausted`, or `InvitationInvalid` (expired).
    Ended(ErrorCode),
}

/// Something the I/O layer or UI must do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostAction {
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
    /// The connection showed a valid ticket proof: set its gate to join-only.
    AdmittedJoinOnly {
        /// Connection.
        conn: ConnectionId,
        /// Invitation.
        invitation: InvitationId,
    },
    /// In person: ask the owner "Is the device next to you?".
    AskApproval {
        /// Invitation.
        invitation: InvitationId,
        /// Connection of the requesting device.
        conn: ConnectionId,
        /// Its identity.
        joiner: IdentityPublicKey,
        /// Its display name.
        name: String,
    },
    /// Send link: show this code on the host's screen, replacing any code
    /// shown before for the invitation. Emitted when a joiner is admitted and
    /// whenever an attempt starts (the next attempt uses a fresh code).
    ShowCode {
        /// Invitation.
        invitation: InvitationId,
        /// The code to display.
        code: PairingCode,
    },
    /// A device was enrolled. Its connection is bound to `grant`; set its
    /// gate to live.
    Enrolled {
        /// Invitation.
        invitation: InvitationId,
        /// Connection.
        conn: ConnectionId,
        /// New grant.
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
    /// A grant-table event (enrolling replaced an older grant).
    Grant(GrantEvent),
}

/// Why a host-side call was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPairingError {
    /// Too many routes, or a route is empty or too long.
    InvalidRoutes,
    /// No such invitation.
    UnknownInvitation,
    /// The invitation is not open.
    NotOpen,
    /// The call does not fit the invitation's kind.
    WrongKind,
    /// No joiner with a valid proof on that connection.
    UnknownJoiner,
}

impl fmt::Display for HostPairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HostPairingError::InvalidRoutes => "invalid route hints",
            HostPairingError::UnknownInvitation => "no such invitation",
            HostPairingError::NotOpen => "invitation is not open",
            HostPairingError::WrongKind => "wrong invitation kind for this action",
            HostPairingError::UnknownJoiner => "no admitted joiner on that connection",
        })
    }
}

impl std::error::Error for HostPairingError {}

struct PresentJoiner {
    identity: IdentityPublicKey,
    name: String,
    pair_exporter: [u8; EXPORTER_LEN],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttemptState {
    Running,
    Failed,
    Succeeded,
}

struct HostAttempt<E> {
    exchange: Option<E>,
    state: AttemptState,
}

struct Invitation<E> {
    ticket: Ticket,
    ticket_hash: [u8; 32],
    params: InvitationParams,
    code: Option<PairingCode>,
    status: InvitationStatus,
    attempts_left: u8,
    joiners: BTreeMap<ConnectionId, PresentJoiner>,
    attempts: BTreeMap<(ConnectionId, AttemptId), HostAttempt<E>>,
}

impl<E> Invitation<E> {
    fn is_open(&self, now: UnixTime) -> bool {
        self.status == InvitationStatus::Open && now < self.ticket.expires_at
    }
}

/// The host side of pairing.
pub struct HostPairing<F: CodeExchangeFactory> {
    host_identity: IdentityPublicKey,
    host_name: String,
    factory: F,
    invitations: BTreeMap<InvitationId, Invitation<F::Exchange>>,
    by_conn: BTreeMap<ConnectionId, InvitationId>,
}

impl<F: CodeExchangeFactory> HostPairing<F> {
    /// A host with no invitations.
    pub fn new(host_identity: IdentityPublicKey, host_name: String, factory: F) -> Self {
        Self {
            host_identity,
            host_name,
            factory,
            invitations: BTreeMap::new(),
            by_conn: BTreeMap::new(),
        }
    }

    /// Create an invitation that expires 10 minutes from `now`.
    pub fn create<R: CryptoRng + ?Sized>(
        &mut self,
        params: InvitationParams,
        now: UnixTime,
        rng: &mut R,
    ) -> Result<CreatedInvitation, HostPairingError> {
        if params.routes.len() > MAX_ROUTES
            || params
                .routes
                .iter()
                .any(|r| r.is_empty() || r.len() > MAX_ROUTE_LEN)
        {
            return Err(HostPairingError::InvalidRoutes);
        }
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let invitation = InvitationId(id);
        let secret = TicketSecret::generate(rng);
        let code = match params.kind {
            InvitationKind::SendLink => Some(PairingCode::generate(rng)),
            InvitationKind::InPerson => None,
        };
        let ticket = Ticket {
            version: TICKET_VERSION,
            kind: params.kind,
            host_identity: self.host_identity,
            invitation,
            secret,
            expires_at: now.plus(TICKET_LIFETIME_SECS),
            routes: params.routes.clone(),
        };
        let created = CreatedInvitation {
            fragment: ticket.to_fragment(),
            ticket: ticket.clone(),
        };
        self.invitations.insert(
            invitation,
            Invitation {
                ticket_hash: ticket.hash(),
                ticket,
                params,
                code,
                status: InvitationStatus::Open,
                attempts_left: HOST_ATTEMPTS_PER_INVITATION,
                joiners: BTreeMap::new(),
                attempts: BTreeMap::new(),
            },
        );
        Ok(created)
    }

    /// The invitation's status.
    pub fn status(&self, invitation: &InvitationId) -> Option<InvitationStatus> {
        self.invitations.get(invitation).map(|i| i.status)
    }

    /// Code attempts left on the invitation.
    pub fn attempts_left(&self, invitation: &InvitationId) -> Option<u8> {
        self.invitations.get(invitation).map(|i| i.attempts_left)
    }

    /// The code to show now for a send-link invitation: the one the next
    /// attempt will use. Each attempt replaces it with a fresh code (see
    /// [`HostAction::ShowCode`]); `None` once no attempts are left or the
    /// invitation is no longer open.
    pub fn code(&self, invitation: &InvitationId) -> Option<&PairingCode> {
        self.invitations
            .get(invitation)
            .filter(|i| i.status == InvitationStatus::Open)
            .and_then(|i| i.code.as_ref())
    }

    /// The invitation a pairing connection belongs to.
    pub fn invitation_for(&self, conn: ConnectionId) -> Option<InvitationId> {
        self.by_conn.get(&conn).copied()
    }

    /// Cancel an open invitation. Cancelling grants nothing.
    pub fn cancel(&mut self, invitation: &InvitationId) -> Vec<HostAction> {
        self.end_if_open(invitation, ErrorCode::Cancelled)
    }

    /// In person: the owner said no.
    pub fn decline(&mut self, invitation: &InvitationId) -> Vec<HostAction> {
        self.end_if_open(invitation, ErrorCode::PairingDeclined)
    }

    /// End invitations whose time is up.
    pub fn tick(&mut self, now: UnixTime) -> Vec<HostAction> {
        let expired: Vec<InvitationId> = self
            .invitations
            .iter()
            .filter(|(_, i)| i.status == InvitationStatus::Open && now >= i.ticket.expires_at)
            .map(|(id, _)| *id)
            .collect();
        expired
            .iter()
            .flat_map(|id| self.end_if_open(id, ErrorCode::InvitationInvalid))
            .collect()
    }

    /// The earliest expiry among open invitations, so the caller knows when
    /// to call [`HostPairing::tick`].
    pub fn next_expiry(&self) -> Option<UnixTime> {
        self.invitations
            .values()
            .filter(|i| i.status == InvitationStatus::Open)
            .map(|i| i.ticket.expires_at)
            .min()
    }

    /// A `JOIN_PROOF` arrived.
    ///
    /// On a connection waiting for a proof, a valid proof for an open
    /// invitation admits it (join-only); anything else closes it. On a
    /// **live** connection (bound to the peer's grant in `grants`), the host
    /// already said `AUTHORIZED {live}` and now answers the proof once
    /// more: `AUTHORIZED {join_only}` if the proof is valid for an open
    /// invitation (the pairing that follows replaces the grant); `PAIRED`
    /// again if the bound grant's enrollment receipt names the proof's
    /// invitation (that pairing took effect, and its `PAIRED` may have been
    /// lost); else `AUTHORIZED {live}` (current access, which this
    /// invitation did not create). Either way a live connection is never
    /// closed here.
    #[allow(clippy::too_many_arguments)]
    pub fn on_join_proof(
        &mut self,
        conn: ConnectionId,
        joiner: &IdentityPublicKey,
        exporters: &SessionExporters,
        invitation: &InvitationId,
        mac: &[u8; 32],
        name: &str,
        grants: &GrantTable,
        now: UnixTime,
    ) -> Vec<HostAction> {
        let close = |code| vec![HostAction::Close { conn, code }];
        if self.by_conn.contains_key(&conn) {
            return close(ErrorCode::ProtocolError);
        }
        // A device never pairs with itself.
        if grants.is_denied(joiner) || *joiner == self.host_identity {
            return close(ErrorCode::NotAuthorized);
        }
        let bound = grants.binding(conn).and_then(|id| grants.get(id));
        let refuse = || {
            if let Some(grant) = bound {
                // The proof opens nothing. If this invitation's pairing made
                // the grant, say so again: the joiner may have lost its
                // `PAIRED`. Otherwise current access stands. The connection
                // is already authenticated as the grant's identity, so the
                // receipt needs no MAC (the invitation's secret may be gone).
                let message = if grant.enrolled_by == Some(*invitation) {
                    ControlMessage::Paired {
                        host_name: self.host_name.clone(),
                        role: grant.role.clone(),
                    }
                } else {
                    ControlMessage::Authorized {
                        state: AuthorizedState::Live,
                    }
                };
                vec![HostAction::Send { conn, message }]
            } else {
                vec![HostAction::Close {
                    conn,
                    code: ErrorCode::InvitationInvalid,
                }]
            }
        };
        let Some(inv) = self.invitations.get_mut(invitation) else {
            return refuse();
        };
        if !inv.is_open(now)
            || !verify_join_proof(
                &inv.ticket.secret,
                invitation,
                &self.host_identity,
                joiner,
                &exporters.join,
                mac,
            )
        {
            return refuse();
        }
        inv.joiners.insert(
            conn,
            PresentJoiner {
                identity: *joiner,
                name: name.to_owned(),
                pair_exporter: exporters.pair,
            },
        );
        self.by_conn.insert(conn, *invitation);
        let mut actions = vec![
            HostAction::AdmittedJoinOnly {
                conn,
                invitation: *invitation,
            },
            HostAction::Send {
                conn,
                message: ControlMessage::Authorized {
                    state: AuthorizedState::JoinOnly,
                },
            },
        ];
        match inv.params.kind {
            InvitationKind::SendLink => {
                // The code is already on screen; show it again for this
                // joiner. A send-link invitation never asks for approval.
                if let Some(code) = &inv.code {
                    actions.push(HostAction::ShowCode {
                        invitation: *invitation,
                        code: code.clone(),
                    });
                }
            }
            InvitationKind::InPerson => actions.push(HostAction::AskApproval {
                invitation: *invitation,
                conn,
                joiner: *joiner,
                name: name.to_owned(),
            }),
        }
        actions
    }

    /// In person: the owner tapped "yes" for the device on `conn`.
    pub fn approve(
        &mut self,
        invitation: &InvitationId,
        conn: ConnectionId,
        grants: &mut GrantTable,
        now: UnixTime,
    ) -> Result<Vec<HostAction>, HostPairingError> {
        let inv = self
            .invitations
            .get(invitation)
            .ok_or(HostPairingError::UnknownInvitation)?;
        if inv.params.kind != InvitationKind::InPerson {
            return Err(HostPairingError::WrongKind);
        }
        if !inv.is_open(now) {
            return Err(HostPairingError::NotOpen);
        }
        if !inv.joiners.contains_key(&conn) {
            return Err(HostPairingError::UnknownJoiner);
        }
        Ok(self.enroll(invitation, conn, grants, now))
    }

    /// A `CODE_EXCHANGE` arrived on a join-only connection.
    pub fn on_code_exchange<R: CryptoRng + ?Sized>(
        &mut self,
        conn: ConnectionId,
        attempt: AttemptId,
        payload: &[u8],
        grants: &mut GrantTable,
        now: UnixTime,
        rng: &mut R,
    ) -> Vec<HostAction> {
        let Some(invitation) = self.by_conn.get(&conn).copied() else {
            return vec![HostAction::Close {
                conn,
                code: ErrorCode::NotAuthorized,
            }];
        };
        let Some(inv) = self.invitations.get_mut(&invitation) else {
            return vec![HostAction::Close {
                conn,
                code: ErrorCode::InvitationInvalid,
            }];
        };
        if inv.params.kind != InvitationKind::SendLink {
            return vec![HostAction::Close {
                conn,
                code: ErrorCode::ProtocolError,
            }];
        }
        if !inv.is_open(now) {
            return self.end_if_open(&invitation, ErrorCode::InvitationInvalid);
        }

        let key = (conn, attempt);
        let mut actions = Vec::new();
        if let Some(existing) = inv.attempts.get(&key) {
            // A message for an attempt that already ended, including a
            // repeat, gets an abort and no work. A repeat while it runs
            // does not fit the next step and fails it below.
            if existing.state != AttemptState::Running {
                return vec![HostAction::Send {
                    conn,
                    message: ControlMessage::CodeAbort {
                        attempt,
                        code: ErrorCode::PairingFailed,
                    },
                }];
            }
        } else {
            // A new attempt on this connection. (An id seen on another
            // connection is new here: its binding holds the other session's
            // exporter, so it is debited and then fails.)
            if inv.attempts_left == 0 {
                return vec![HostAction::Close {
                    conn,
                    code: ErrorCode::AttemptsExhausted,
                }];
            }
            // Debit first. Nothing below runs on an undebited attempt.
            inv.attempts_left -= 1;
            let (Some(joiner), Some(code)) = (inv.joiners.get(&conn), inv.code.take()) else {
                return vec![HostAction::Close {
                    conn,
                    code: ErrorCode::InternalError,
                }];
            };
            // This attempt uses the code shown until now. The next attempt
            // gets a fresh code, shown from now on; none once no attempts
            // are left.
            if inv.attempts_left > 0 {
                let next = PairingCode::generate(rng);
                actions.push(HostAction::ShowCode {
                    invitation,
                    code: next.clone(),
                });
                inv.code = Some(next);
            }
            let binding = binding_transcript(
                &inv.ticket_hash,
                inv.ticket.kind,
                inv.ticket.version,
                &self.host_identity,
                &joiner.identity,
                &joiner.pair_exporter,
            );
            let sid = attempt_sid(&attempt, &joiner.pair_exporter);
            let exchange = self
                .factory
                .start(ExchangeRole::Responder, &code, &binding, &sid, rng);
            inv.attempts.insert(
                key,
                HostAttempt {
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
                actions.extend(step.send.map(|payload| HostAction::Send {
                    conn,
                    message: ControlMessage::CodeExchange { attempt, payload },
                }));
                if step.peer_confirmed {
                    record.state = AttemptState::Succeeded;
                    record.exchange = None;
                    actions.extend(self.enroll(&invitation, conn, grants, now));
                }
                actions
            }
            Err(_) => {
                let abort = ControlMessage::CodeAbort {
                    attempt,
                    code: ErrorCode::PairingFailed,
                };
                record.state = AttemptState::Failed;
                record.exchange = None;
                actions.push(HostAction::Send {
                    conn,
                    message: abort,
                });
                actions.extend(self.end_if_exhausted(&invitation));
                actions
            }
        }
    }

    /// A `CODE_ABORT` arrived: the joiner ended an attempt. Its debit stays.
    pub fn on_code_abort(&mut self, conn: ConnectionId, attempt: AttemptId) -> Vec<HostAction> {
        let Some(invitation) = self.by_conn.get(&conn).copied() else {
            return Vec::new();
        };
        if let Some(record) = self
            .invitations
            .get_mut(&invitation)
            .and_then(|i| i.attempts.get_mut(&(conn, attempt)))
        {
            if record.state == AttemptState::Running {
                record.state = AttemptState::Failed;
                record.exchange = None;
            }
        }
        self.end_if_exhausted(&invitation)
    }

    /// A pairing connection closed. Its running attempts count as failed.
    pub fn on_connection_closed(&mut self, conn: ConnectionId) -> Vec<HostAction> {
        let Some(invitation) = self.by_conn.remove(&conn) else {
            return Vec::new();
        };
        if let Some(inv) = self.invitations.get_mut(&invitation) {
            inv.joiners.remove(&conn);
            for ((c, _), record) in inv.attempts.iter_mut() {
                if *c == conn && record.state == AttemptState::Running {
                    record.state = AttemptState::Failed;
                    record.exchange = None;
                }
            }
        }
        self.end_if_exhausted(&invitation)
    }

    /// Atomic consumption: grant, bind, mark consumed, dismiss other joiners.
    fn enroll(
        &mut self,
        invitation: &InvitationId,
        conn: ConnectionId,
        grants: &mut GrantTable,
        now: UnixTime,
    ) -> Vec<HostAction> {
        let Some(inv) = self.invitations.get_mut(invitation) else {
            return Vec::new();
        };
        if !inv.is_open(now) {
            return vec![HostAction::Close {
                conn,
                code: ErrorCode::InvitationInvalid,
            }];
        }
        let Some(joiner) = inv.joiners.remove(&conn) else {
            return Vec::new();
        };
        // A pairing on a connection that was live under the device's old
        // grant: the new grant replaces the old one (section 7), whose other
        // connections close, while this one moves to the new grant.
        grants.unbind(conn);
        let new_grant = NewGrant {
            identity: joiner.identity,
            name: joiner.name,
            role: inv.params.role.clone(),
            authorizing_owner: inv.params.authorizing_owner,
            expires_at: inv.params.grant_expires_at,
            enrolled_by: Some(*invitation),
        };
        let (grant, events) = match grants.add(new_grant, now) {
            Ok(added) => added,
            Err(GrantError::Denied) => {
                self.by_conn.remove(&conn);
                return vec![HostAction::Close {
                    conn,
                    code: ErrorCode::NotAuthorized,
                }];
            }
            Err(_) => {
                self.by_conn.remove(&conn);
                return vec![HostAction::Close {
                    conn,
                    code: ErrorCode::InternalError,
                }];
            }
        };
        if grants.bind(conn, grant, now).is_err() {
            self.by_conn.remove(&conn);
            return vec![HostAction::Close {
                conn,
                code: ErrorCode::InternalError,
            }];
        }
        inv.status = InvitationStatus::Consumed { grant };
        inv.attempts.clear();
        let others: Vec<ConnectionId> = std::mem::take(&mut inv.joiners).into_keys().collect();
        let role = inv.params.role.clone();
        self.by_conn.remove(&conn);
        let mut actions: Vec<HostAction> = events.into_iter().map(HostAction::Grant).collect();
        actions.push(HostAction::Enrolled {
            invitation: *invitation,
            conn,
            grant,
            identity: joiner.identity,
        });
        actions.push(HostAction::Send {
            conn,
            message: ControlMessage::Paired {
                host_name: self.host_name.clone(),
                role,
            },
        });
        for other in others {
            self.by_conn.remove(&other);
            actions.push(HostAction::Close {
                conn: other,
                code: ErrorCode::InvitationInvalid,
            });
        }
        actions
    }

    fn end_if_exhausted(&mut self, invitation: &InvitationId) -> Vec<HostAction> {
        let exhausted = self.invitations.get(invitation).is_some_and(|inv| {
            inv.attempts_left == 0
                && !inv
                    .attempts
                    .values()
                    .any(|a| a.state == AttemptState::Running)
        });
        if exhausted {
            self.end_if_open(invitation, ErrorCode::AttemptsExhausted)
        } else {
            Vec::new()
        }
    }

    fn end_if_open(&mut self, invitation: &InvitationId, reason: ErrorCode) -> Vec<HostAction> {
        let Some(inv) = self.invitations.get_mut(invitation) else {
            return Vec::new();
        };
        if inv.status != InvitationStatus::Open {
            return Vec::new();
        }
        inv.status = InvitationStatus::Ended(reason);
        inv.attempts.clear();
        let mut actions = Vec::new();
        for conn in std::mem::take(&mut inv.joiners).into_keys() {
            self.by_conn.remove(&conn);
            actions.push(HostAction::Close { conn, code: reason });
        }
        actions.push(HostAction::InvitationEnded {
            invitation: *invitation,
            reason,
        });
        actions
    }
}
