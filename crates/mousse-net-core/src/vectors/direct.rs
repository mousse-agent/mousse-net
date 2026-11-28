//! `direct-host.json`: the host side of Pair with IP (wire.md 10.9), replayed
//! byte for byte from listed random draws.
//!
//! The joiners here are scripted: each sends what wire.md 10.9 says a joiner
//! sends and runs the real CPace initiator, so the host machine is exercised
//! with the real code exchange.

use serde_json::{json, Value as J};

use super::{checked_in, hex, identity, unhex, Draws, IDENTITY_A, T};
use crate::control::{AuthorizedState, ControlMessage, DirectRecovery};
use crate::grants::{GrantEvent, GrantTable, OwnerRef, Role};
use crate::identity::IdentityPublicKey;
use crate::pairing::{
    attempt_sid, direct_binding_transcript, ApprovalEnd, AttemptId, CodeExchange,
    CodeExchangeFactory, CpaceExchange, CpaceExchangeFactory, DirectCode, DirectHostAction,
    DirectHostError, DirectHostPairing, DirectInvitationParams, DirectInvitationStatus,
    DirectLookup, DirectRequestId, ExchangeRole, InvitationId, RequestDecision, RequestPresence,
};
use crate::time::UnixTime;
use crate::{ConnectionId, ErrorCode};

const HOST_NAME: &str = "Desk";

fn pair_exporter(conn: u64) -> [u8; 32] {
    [conn as u8 + 100; 32]
}

/// `msg_a` whose share is the identity element: refused before any group
/// work.
fn identity_point_msg_a() -> Vec<u8> {
    let mut m = vec![0x20];
    m.extend_from_slice(&[0u8; 32]);
    m.push(0x00);
    m
}

fn sequences() -> Vec<J> {
    let bad_share = hex(&identity_point_msg_a());
    let first = hex(&[0x0a; 16]);
    let second = hex(&[0x0b; 16]);
    vec![
        json!({
            "name": "success_with_allow",
            "description": "The lookup finds the invitation, the code passes and the owner is asked. Allow enrolls on the connection with receipt I and sends PAIRED.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1, "host_attempts_left": 5, "host_status": "open" },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 4, "requests": [["a", "connected", "pending"]], "granted": [] },
                { "op": "allow", "joiner": "a", "result": "ok", "host_status": "consumed", "requests": [], "granted": ["a"] },
            ],
        }),
        json!({
            "name": "wrong_secret",
            "description": "The right lookup with a wrong secret: the attempt is debited and fails at the joiner, which aborts and closes (one attempt per connection). The code stays the same; the next Connect with it passes.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "wrong", "host_attempts_left": 4, "host_status": "open", "requests": [] },
                { "op": "connect", "joiner": "a", "conn": 2 },
                { "op": "submit", "joiner": "a", "conn": 2, "code": "right", "host_attempts_left": 3, "requests": [["a", "connected", "pending"]] },
            ],
        }),
        json!({
            "name": "wrong_lookup_is_not_debited",
            "description": "A lookup that finds nothing is held, then closed with invitation_invalid by the I/O layer. Nothing is debited, and a device that already holds a grant gets the same answer.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1, "lookup": "wrong", "held": [1], "host_attempts_left": 5, "host_status": "open" },
                { "op": "drop", "conn": 1, "host_attempts_left": 5 },
                { "op": "connect", "joiner": "a", "conn": 2 },
                { "op": "submit", "joiner": "a", "conn": 2, "code": "right" },
                { "op": "allow", "joiner": "a", "result": "ok", "granted": ["a"] },
                { "op": "connect", "joiner": "a", "conn": 3, "lookup": "wrong", "held": [3] },
            ],
        }),
        json!({
            "name": "decline",
            "description": "Decline closes the device's connection with pairing_declined and ends the invitation. Its recovery hears pairing_declined until the Allow window ends; then, and for anyone else, there is no open invitation.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "decline", "joiner": "a", "result": "ok", "closed": [[1, "pairing_declined"]], "host_status": "ended:pairing_declined", "requests": [] },
                { "op": "recover", "joiner": "a", "conn": 2, "closed": [[2, "pairing_declined"]] },
                { "op": "connect", "joiner": "b", "conn": 3, "held": [3] },
                { "op": "recover", "joiner": "b", "conn": 4, "held": [4] },
                { "op": "tick", "at": 300 },
                { "op": "recover", "joiner": "a", "conn": 5, "held": [5] },
            ],
        }),
        json!({
            "name": "exhausted",
            "description": "Five wrong secrets on five connections. The fifth failure ends the invitation; afterwards the lookup finds nothing.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "wrong", "host_attempts_left": 4 },
                { "op": "connect", "joiner": "a", "conn": 2 },
                { "op": "submit", "joiner": "a", "conn": 2, "code": "wrong", "host_attempts_left": 3 },
                { "op": "connect", "joiner": "a", "conn": 3 },
                { "op": "submit", "joiner": "a", "conn": 3, "code": "wrong", "host_attempts_left": 2 },
                { "op": "connect", "joiner": "a", "conn": 4 },
                { "op": "submit", "joiner": "a", "conn": 4, "code": "wrong", "host_attempts_left": 1 },
                { "op": "connect", "joiner": "a", "conn": 5 },
                { "op": "submit", "joiner": "a", "conn": 5, "code": "wrong", "host_attempts_left": 0, "host_status": "ended:attempts_exhausted", "closed": [[5, "attempts_exhausted"]] },
                { "op": "connect", "joiner": "a", "conn": 6, "held": [6] },
            ],
        }),
        json!({
            "name": "a_waiting_request_keeps_an_invitation_without_attempts",
            "description": "a passes; b then uses up the other four attempts. The invitation stays open while a's request is inside its Allow window: a new attempt closes with attempts_exhausted, and Allow still enrolls a.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 4 },
                { "op": "connect", "joiner": "b", "conn": 2 },
                { "op": "submit", "joiner": "b", "conn": 2, "code": "wrong" },
                { "op": "connect", "joiner": "b", "conn": 3 },
                { "op": "submit", "joiner": "b", "conn": 3, "code": "wrong" },
                { "op": "connect", "joiner": "b", "conn": 4 },
                { "op": "submit", "joiner": "b", "conn": 4, "code": "wrong" },
                { "op": "connect", "joiner": "b", "conn": 5 },
                { "op": "submit", "joiner": "b", "conn": 5, "code": "wrong", "host_attempts_left": 0, "host_status": "open" },
                { "op": "connect", "joiner": "c", "conn": 6 },
                { "op": "submit", "joiner": "c", "conn": 6, "code": "right", "closed": [[6, "attempts_exhausted"]], "host_status": "open" },
                { "op": "allow", "joiner": "a", "result": "ok", "host_status": "consumed", "granted": ["a"] },
            ],
        }),
        json!({
            "name": "allow_while_away_then_recovery",
            "description": "The device's connection drops after the code passed; its request stays, away. Allow marks it allowed and ends every other request. Its recovery connection is answered AUTHORIZED {join_only, I}, enrolled and sent PAIRED.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "drop", "conn": 1, "requests": [["a", "away", "pending"]] },
                { "op": "allow", "joiner": "a", "result": "ok", "host_status": "allowed", "requests": [["a", "away", "allowed"]], "granted": [] },
                { "op": "connect", "joiner": "b", "conn": 2, "held": [2] },
                { "op": "recover", "joiner": "a", "conn": 3, "host_status": "consumed", "requests": [], "granted": ["a"] },
            ],
        }),
        json!({
            "name": "recovery_while_waiting_for_allow",
            "description": "A recovery while the request still waits: AUTHORIZED {join_only, I}, and the same request now points at the new connection.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "drop", "conn": 1 },
                { "op": "recover", "joiner": "a", "conn": 2, "requests": [["a", "connected", "pending"]] },
                { "op": "allow", "joiner": "a", "result": "ok", "granted": ["a"] },
            ],
        }),
        json!({
            "name": "the_same_identity_passing_again_keeps_its_request",
            "description": "A device whose connection dropped types the code again on a new Connect: its request (same id) points at the new connection; no second request.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 4 },
                { "op": "drop", "conn": 1 },
                { "op": "connect", "joiner": "a", "conn": 2 },
                { "op": "submit", "joiner": "a", "conn": 2, "code": "right", "host_attempts_left": 3, "requests": [["a", "connected", "pending"]] },
            ],
        }),
        json!({
            "name": "joiner_cancel_while_waiting",
            "description": "Connected, the device cancels: CODE_ABORT {A, cancelled}, then its close with cancelled. The request goes; the invitation stays open. Its recovery hears cancelled until the window ends.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "cancel", "joiner": "a", "conn": 1, "closed": [[1, "cancelled"]], "requests": [], "host_status": "open", "host_attempts_left": 4 },
                { "op": "allow", "joiner": "a", "result": "unknown_request" },
                { "op": "recover", "joiner": "a", "conn": 2, "closed": [[2, "cancelled"]] },
            ],
        }),
        json!({
            "name": "joiner_cancel_while_away",
            "description": "The device's connection dropped while it waited; it delivers its cancel on its next connection. The request goes and the connection closes with cancelled.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "drop", "conn": 1 },
                { "op": "recover", "joiner": "a", "conn": 2, "cancel": true, "closed": [[2, "cancelled"]], "requests": [], "host_status": "open" },
            ],
        }),
        json!({
            "name": "joiner_cancel_after_allow_while_away",
            "description": "Allowed while away, the device comes back only to cancel: nothing is granted, and the invitation ends.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "drop", "conn": 1 },
                { "op": "allow", "joiner": "a", "result": "ok" },
                { "op": "recover", "joiner": "a", "conn": 2, "cancel": true, "closed": [[2, "cancelled"]], "host_status": "ended:cancelled", "granted": [] },
            ],
        }),
        json!({
            "name": "cancel_crossing_allow",
            "description": "The owner allows while the device's cancel is on its way. The cancel arrives on the connection the host just enrolled: the grant with receipt I is removed and the connection closes with cancelled.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "result": "ok", "granted": ["a"] },
                { "op": "cancel", "joiner": "a", "conn": 1, "closed": [[1, "cancelled"]], "granted": [] },
            ],
        }),
        json!({
            "name": "cancel_by_recovery_after_allow",
            "description": "The owner allowed; the connection broke before the device saw PAIRED, and the device cancelled meanwhile. Its recovery (step 2 says AUTHORIZED {live} for the new grant) carries the cancel: the grant with receipt I is removed.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "result": "ok", "granted": ["a"] },
                { "op": "drop", "conn": 1, "granted": ["a"] },
                { "op": "recover", "joiner": "a", "conn": 2, "cancel": true, "closed": [[2, "cancelled"]], "granted": [] },
            ],
        }),
        json!({
            "name": "lost_paired_answered_by_receipt",
            "description": "The owner allowed; PAIRED was lost with the connection. The recovery gets step 2's AUTHORIZED {live} and then PAIRED from the grant's receipt.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "result": "ok" },
                { "op": "drop", "conn": 1 },
                { "op": "recover", "joiner": "a", "conn": 2, "granted": ["a"] },
            ],
        }),
        json!({
            "name": "two_identities_pass",
            "description": "Two devices pass the code, each with its own request. Allowing one enrolls it, ends the other request and closes its connection with invitation_invalid.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "connect", "joiner": "b", "conn": 2 },
                { "op": "submit", "joiner": "b", "conn": 2, "code": "right", "requests": [["a", "connected", "pending"], ["b", "connected", "pending"]] },
                { "op": "allow", "joiner": "b", "result": "ok", "closed": [[1, "invitation_invalid"]], "requests": [], "granted": ["b"] },
                { "op": "allow", "joiner": "a", "result": "not_open" },
                { "op": "recover", "joiner": "a", "conn": 3, "held": [3] },
            ],
        }),
        json!({
            "name": "code_passed_in_the_last_second",
            "description": "The code passes one second before the invitation expires. At expiry the lookup finds nothing, but the request stays answerable for its whole Allow window, past the expiry.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1, "at": 598 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "at": 599 },
                { "op": "tick", "at": 600, "host_status": "open", "requests": [["a", "connected", "pending"]] },
                { "op": "connect", "joiner": "b", "conn": 2, "held": [2] },
                { "op": "allow", "joiner": "a", "result": "ok", "at": 898, "granted": ["a"] },
            ],
        }),
        json!({
            "name": "no_attempt_at_expiry",
            "description": "A connection admitted before expiry starts no attempt at or after it.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1, "at": 599 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "at": 600, "closed": [[1, "invitation_invalid"]], "host_attempts_left": 5 },
                { "op": "tick", "host_status": "gone" },
            ],
        }),
        json!({
            "name": "allow_window_ends",
            "description": "An unanswered request ends when its Allow window does, and its connection closes with invitation_invalid. The invitation, not yet expired, stays open.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "at": 10 },
                { "op": "tick", "at": 309, "requests": [["a", "connected", "pending"]] },
                { "op": "tick", "at": 310, "closed": [[1, "invitation_invalid"]], "requests": [], "host_status": "open" },
                { "op": "allow", "joiner": "a", "result": "unknown_request" },
            ],
        }),
        json!({
            "name": "recovery_not_received",
            "description": "The connection drops after the device verified the host's confirmation but before its own reached the host. Its recovery hears AUTHORIZED {join_only, I, not_received}.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "lose": "msg_c", "requests": [], "host_attempts_left": 4 },
                { "op": "recover", "joiner": "a", "conn": 2, "requests": [] },
            ],
        }),
        json!({
            "name": "one_attempt_per_connection",
            "description": "A second attempt on a connection closes it with protocol_error and is not debited.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "inject", "joiner": "a", "conn": 1, "attempt": first, "payload": bad_share, "host_attempts_left": 4 },
                { "op": "inject", "joiner": "a", "conn": 1, "attempt": second, "payload": bad_share, "closed": [[1, "protocol_error"]], "host_attempts_left": 4 },
            ],
        }),
        json!({
            "name": "own_identity",
            "description": "A JOIN_DIRECT from the host's own identity key closes with not_authorized: a device never pairs with itself.",
            "steps": [
                { "op": "connect", "joiner": "host", "conn": 1, "closed": [[1, "not_authorized"]], "host_attempts_left": 5 },
            ],
        }),
        json!({
            "name": "owner_cancels",
            "description": "The owner cancels while a device waits: its request ends, its connection closes with cancelled and its recovery finds no open invitation.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "owner_cancel", "closed": [[1, "cancelled"]], "host_status": "ended:cancelled", "requests": [] },
                { "op": "recover", "joiner": "a", "conn": 2, "held": [2] },
            ],
        }),
    ]
}

fn status_name(s: Option<DirectInvitationStatus>) -> String {
    match s {
        None => "gone".into(),
        Some(DirectInvitationStatus::Open) => "open".into(),
        Some(DirectInvitationStatus::Allowed { .. }) => "allowed".into(),
        Some(DirectInvitationStatus::Consumed { .. }) => "consumed".into(),
        Some(DirectInvitationStatus::Ended(code)) => format!("ended:{}", code.name()),
    }
}

fn end_name(e: ApprovalEnd) -> &'static str {
    match e {
        ApprovalEnd::Enrolled => "enrolled",
        ApprovalEnd::Cancelled => "cancelled",
        ApprovalEnd::Declined => "declined",
        ApprovalEnd::Dismissed => "dismissed",
        ApprovalEnd::WindowEnded => "window_ended",
    }
}

fn error_name(e: DirectHostError) -> &'static str {
    match e {
        DirectHostError::TooManyOpen => "too_many_open",
        DirectHostError::UnknownInvitation => "unknown_invitation",
        DirectHostError::NotOpen => "not_open",
        DirectHostError::UnknownRequest => "unknown_request",
    }
}

struct VJoiner {
    name: String,
    key: IdentityPublicKey,
    rng: Draws,
    /// The attempt this joiner ran last, and its exchange while it runs.
    attempt: Option<AttemptId>,
}

struct Replay {
    host: DirectHostPairing<CpaceExchangeFactory>,
    host_rng: Draws,
    host_key: IdentityPublicKey,
    grants: GrantTable,
    invitation: InvitationId,
    code: DirectCode,
    joiners: Vec<VJoiner>,
    listed: Option<J>,
    now: UnixTime,
    out: Vec<J>,
    closed: Vec<(u64, String)>,
    held: Vec<u64>,
}

impl Replay {
    fn new(listed: Option<&J>) -> Self {
        let mut host_rng = match listed {
            Some(draws) => Draws::scripted(&draws["host"]),
            None => Draws::recording(8),
        };
        let host_key = identity(&IDENTITY_A).public_key();
        let mut host = DirectHostPairing::new(host_key, HOST_NAME.into(), CpaceExchangeFactory);
        let created = host
            .create(
                DirectInvitationParams {
                    role: Role::owner(),
                    authorizing_owner: OwnerRef::from_bytes([0x51; 16]),
                    grant_expires_at: None,
                },
                UnixTime(T),
                &mut host_rng,
            )
            .expect("create");
        Self {
            host,
            host_rng,
            host_key,
            grants: GrantTable::new(),
            invitation: created.invitation,
            code: created.code,
            joiners: Vec::new(),
            listed: listed.cloned(),
            now: UnixTime(T),
            out: Vec::new(),
            closed: Vec::new(),
            held: Vec::new(),
        }
    }

    fn joiner(&mut self, name: &str) -> &mut VJoiner {
        if !self.joiners.iter().any(|j| j.name == name) {
            let index = self.joiners.len() as u8;
            let rng = match &self.listed {
                Some(draws) => Draws::scripted(&draws[name]),
                None => Draws::recording(0x70 + index),
            };
            self.joiners.push(VJoiner {
                name: name.into(),
                key: identity(&[0x50 + index; 32]).public_key(),
                rng,
                attempt: None,
            });
        }
        self.joiners
            .iter_mut()
            .find(|j| j.name == name)
            .expect("present")
    }

    fn key_of(&mut self, name: &str) -> IdentityPublicKey {
        if name == "host" {
            self.host_key
        } else {
            self.joiner(name).key
        }
    }

    fn name_of(&self, key: &IdentityPublicKey) -> String {
        self.joiners
            .iter()
            .find(|j| j.key == *key)
            .map(|j| j.name.clone())
            .unwrap_or_else(|| "?".into())
    }

    fn sent(&mut self, from: &str, conn: u64, m: &ControlMessage) {
        self.out
            .push(json!({ "send": { "from": from, "conn": conn, "control": hex(&m.encode()) } }));
    }

    /// Log the host's actions; return the messages it sent on `conn`.
    fn host_did(&mut self, actions: &[DirectHostAction], conn: u64) -> Vec<ControlMessage> {
        let mut on_conn = Vec::new();
        for a in actions {
            match a {
                DirectHostAction::Send { conn: c, message } => {
                    self.sent("host", c.0, message);
                    if c.0 == conn {
                        on_conn.push(message.clone());
                    }
                }
                DirectHostAction::Close { conn: c, code } => {
                    self.out.push(
                        json!({ "close": { "from": "host", "conn": c.0, "code": code.name() } }),
                    );
                    self.closed.push((c.0, code.name().to_owned()));
                }
                DirectHostAction::MissHold { conn: c, hold_ms } => {
                    self.out
                        .push(json!({ "miss_hold": { "conn": c.0, "hold_ms": hold_ms } }));
                    self.held.push(c.0);
                }
                DirectHostAction::AdmittedJoinOnly { conn: c, .. } => {
                    self.out.push(json!({ "admitted": { "conn": c.0 } }));
                }
                DirectHostAction::AttemptsLeft { attempts_left, .. } => {
                    self.out.push(json!({ "attempts_left": attempts_left }));
                }
                DirectHostAction::Approval(a) => {
                    let who = self.name_of(&a.request.identity);
                    self.out.push(json!({ "approval": {
                        "joiner": who,
                        "name": a.name,
                        "role": a.role.as_str(),
                        "presence": presence_name(a.presence),
                        "decision": decision_name(a.decision),
                        "answer_by": a.answer_by.0,
                    } }));
                }
                DirectHostAction::ApprovalEnded { request, reason } => {
                    let who = self.name_of(&request.identity);
                    self.out.push(
                        json!({ "approval_ended": { "joiner": who, "reason": end_name(*reason) } }),
                    );
                }
                DirectHostAction::Enrolled {
                    conn: c,
                    grant,
                    identity,
                    role,
                    ..
                } => {
                    let who = self.name_of(identity);
                    self.out.push(json!({ "enrolled": {
                        "joiner": who, "conn": c.0, "grant": grant.0, "role": role.as_str(),
                    } }));
                }
                DirectHostAction::EnrollmentUndone {
                    grant, identity, ..
                } => {
                    let who = self.name_of(identity);
                    self.out
                        .push(json!({ "enrollment_undone": { "joiner": who, "grant": grant.0 } }));
                }
                DirectHostAction::InvitationEnded { reason, .. } => {
                    self.out.push(json!({ "invitation_ended": reason.name() }));
                }
                DirectHostAction::Grant(GrantEvent::CloseChannels {
                    grant,
                    channels,
                    code,
                }) => {
                    let channels: Vec<u64> = channels.iter().map(|c| c.0).collect();
                    self.out.push(json!({ "grant_closes": {
                        "grant": grant.0, "conns": channels, "code": code.name(),
                    } }));
                }
            }
        }
        on_conn
    }

    /// Step 2 for a new connection from `key`: a live grant binds it and the
    /// host says `AUTHORIZED {live}`.
    fn step_two(&mut self, conn: u64, key: &IdentityPublicKey) {
        let live = self.grants.live_grant(key, self.now).map(|g| g.id);
        if let Some(grant) = live {
            self.grants
                .bind(ConnectionId(conn), grant, self.now)
                .expect("bind");
            self.sent(
                "host",
                conn,
                &ControlMessage::Authorized {
                    state: AuthorizedState::Live,
                },
            );
        }
    }

    fn join_direct(
        &mut self,
        who: &str,
        conn: u64,
        lookup: DirectLookup,
        recovery: Option<DirectRecovery>,
    ) {
        let key = self.key_of(who);
        self.step_two(conn, &key);
        let m = ControlMessage::JoinDirect {
            lookup: lookup.clone(),
            name: who.to_owned(),
            recovery,
        };
        self.sent(who, conn, &m);
        let actions = self.host.on_join_direct(
            ConnectionId(conn),
            &key,
            &pair_exporter(conn),
            &lookup,
            who,
            recovery,
            &mut self.grants,
            self.now,
        );
        self.host_did(&actions, conn);
    }

    /// The joiner's side closed `conn` with `code`.
    fn joiner_closes(&mut self, who: &str, conn: u64, code: Option<ErrorCode>) {
        if let Some(code) = code {
            self.out
                .push(json!({ "close": { "from": who, "conn": conn, "code": code.name() } }));
        }
        self.grants.unbind(ConnectionId(conn));
        let actions =
            self.host
                .on_connection_closed(ConnectionId(conn), code, &mut self.grants, self.now);
        self.host_did(&actions, conn);
    }

    fn send_to_host(&mut self, who: &str, conn: u64, m: &ControlMessage) -> Vec<ControlMessage> {
        self.sent(who, conn, m);
        let actions = match m {
            ControlMessage::CodeExchange { attempt, payload } => self.host.on_code_exchange(
                ConnectionId(conn),
                *attempt,
                payload,
                self.now,
                &mut self.host_rng,
            ),
            ControlMessage::CodeAbort { attempt, code } => self.host.on_code_abort(
                ConnectionId(conn),
                *attempt,
                *code,
                &mut self.grants,
                self.now,
            ),
            other => panic!("unexpected {other:?}"),
        };
        self.host_did(&actions, conn)
    }

    fn submit(&mut self, who: &str, conn: u64, right: bool, lose: Option<&str>) {
        let password = if right {
            self.code.secret().as_bytes().to_vec()
        } else {
            let wrong = b"00000000".to_vec();
            if wrong == self.code.secret().as_bytes().to_vec() {
                b"00000001".to_vec()
            } else {
                wrong
            }
        };
        let host_key = self.host_key;
        let invitation = self.invitation;
        let lookup = self.code.lookup();
        let j = self.joiner(who);
        let mut id = [0u8; 16];
        rand_core::Rng::fill_bytes(&mut j.rng, &mut id);
        let attempt = AttemptId(id);
        j.attempt = Some(attempt);
        let exporter = pair_exporter(conn);
        let binding = direct_binding_transcript(&lookup, &invitation, &host_key, &j.key, &exporter);
        let sid = attempt_sid(&attempt, &exporter);
        let mut exchange: CpaceExchange = CpaceExchangeFactory.start(
            ExchangeRole::Initiator,
            &password,
            &binding,
            &sid,
            &mut j.rng,
        );
        let msg_a = exchange
            .step(None)
            .expect("msg_a")
            .send
            .expect("msg_a bytes");
        let reply = self.send_to_host(
            who,
            conn,
            &ControlMessage::CodeExchange {
                attempt,
                payload: msg_a,
            },
        );
        let Some(ControlMessage::CodeExchange { payload: msg_b, .. }) = reply
            .into_iter()
            .find(|m| matches!(m, ControlMessage::CodeExchange { .. }))
        else {
            // The host refused the attempt and closed.
            return;
        };
        match exchange.step(Some(&msg_b)) {
            Ok(step) => {
                let msg_c = step.send.expect("msg_c");
                if lose == Some("msg_c") {
                    // The connection breaks before msg_c reaches the host.
                    self.joiner_closes(who, conn, None);
                    return;
                }
                self.send_to_host(
                    who,
                    conn,
                    &ControlMessage::CodeExchange {
                        attempt,
                        payload: msg_c,
                    },
                );
            }
            Err(_) => {
                // Wrong code: abort the attempt and close; the next try is
                // a new Connect.
                self.send_to_host(
                    who,
                    conn,
                    &ControlMessage::CodeAbort {
                        attempt,
                        code: ErrorCode::PairingFailed,
                    },
                );
                if !self.closed.iter().any(|(c, _)| *c == conn) {
                    self.joiner_closes(who, conn, Some(ErrorCode::PairingFailed));
                }
            }
        }
    }

    fn request(&mut self, who: &str) -> DirectRequestId {
        DirectRequestId {
            invitation: self.invitation,
            identity: self.key_of(who),
        }
    }

    fn result(
        step: &J,
        r: Result<Vec<DirectHostAction>, DirectHostError>,
    ) -> Vec<DirectHostAction> {
        match r {
            Ok(actions) => {
                assert_eq!(step["result"], "ok");
                actions
            }
            Err(e) => {
                assert_eq!(step["result"], error_name(e));
                Vec::new()
            }
        }
    }

    fn step(&mut self, step: &J) {
        if let Some(at) = step["at"].as_u64() {
            assert!(T + at >= self.now.0, "time goes forward");
            self.now = UnixTime(T + at);
        }
        let op = step["op"].as_str().expect("op");
        let conn = step["conn"].as_u64().unwrap_or(0);
        let who = step["joiner"].as_str().unwrap_or("").to_owned();
        match op {
            "connect" => {
                let lookup = match step["lookup"].as_str() {
                    Some("wrong") => {
                        let mine = self.code.lookup();
                        ["0000", "0001"]
                            .iter()
                            .filter_map(|l| DirectLookup::from_canonical(l))
                            .find(|l| *l != mine)
                            .expect("another lookup")
                    }
                    _ => self.code.lookup(),
                };
                self.join_direct(&who, conn, lookup, None);
            }
            "recover" => {
                let recovery = DirectRecovery {
                    receipt: self.invitation,
                    cancel: step["cancel"].as_bool().unwrap_or(false),
                };
                let lookup = self.code.lookup();
                self.join_direct(&who, conn, lookup, Some(recovery));
            }
            "submit" => {
                let right = step["code"] == "right";
                self.submit(&who, conn, right, step["lose"].as_str());
            }
            "inject" => {
                let attempt = AttemptId(
                    unhex(step["attempt"].as_str().expect("attempt"))
                        .try_into()
                        .expect("16"),
                );
                let payload = unhex(step["payload"].as_str().expect("payload"));
                self.send_to_host(
                    &who,
                    conn,
                    &ControlMessage::CodeExchange { attempt, payload },
                );
            }
            "cancel" => {
                let attempt = self.joiner(&who).attempt.expect("an attempt");
                self.send_to_host(
                    &who,
                    conn,
                    &ControlMessage::CodeAbort {
                        attempt,
                        code: ErrorCode::Cancelled,
                    },
                );
                if !self.closed.iter().any(|(c, _)| *c == conn) {
                    self.joiner_closes(&who, conn, Some(ErrorCode::Cancelled));
                }
            }
            "drop" => {
                let joiner = self
                    .joiners
                    .first()
                    .map(|j| j.name.clone())
                    .unwrap_or_default();
                self.joiner_closes(&joiner, conn, None);
            }
            "allow" => {
                let request = self.request(&who);
                let role = step["role"].as_str().map(|r| Role::new(r).expect("role"));
                let r = self.host.allow(&request, role, &mut self.grants, self.now);
                let actions = Self::result(step, r);
                self.host_did(&actions, 0);
            }
            "decline" => {
                let request = self.request(&who);
                let r = self.host.decline(&request, self.now);
                let actions = Self::result(step, r);
                self.host_did(&actions, 0);
            }
            "owner_cancel" => {
                let invitation = self.invitation;
                let actions = self.host.cancel(&invitation);
                self.host_did(&actions, 0);
            }
            "tick" => {
                let actions = self.host.tick(self.now);
                self.host_did(&actions, 0);
            }
            other => panic!("unknown op {other}"),
        }
    }
}

fn presence_name(p: RequestPresence) -> &'static str {
    match p {
        RequestPresence::Connected => "connected",
        RequestPresence::Away => "away",
    }
}

fn decision_name(d: RequestDecision) -> &'static str {
    match d {
        RequestDecision::Pending => "pending",
        RequestDecision::Allowed => "allowed",
    }
}

fn pairs(list: &J) -> Vec<(u64, String)> {
    list.as_array()
        .map(|l| {
            l.iter()
                .map(|c| {
                    (
                        c[0].as_u64().expect("conn"),
                        c[1].as_str().expect("code").to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Run one sequence and check every expectation in its steps. With
/// `listed`, the random values come from that list.
fn run_sequence(seq: &J, listed: Option<&J>) -> J {
    let name = seq["name"].as_str().expect("name");
    let mut r = Replay::new(listed);
    let mut steps = Vec::new();
    for (i, step) in seq["steps"].as_array().expect("steps").iter().enumerate() {
        let ctx = format!("{name} step {i}");
        r.out.clear();
        r.closed.clear();
        r.held.clear();
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| r.step(step)))
            .unwrap_or_else(|_| panic!("{ctx}"));
        if let Some(n) = step["host_attempts_left"].as_u64() {
            assert_eq!(
                r.host.attempts_left(&r.invitation).map(u64::from),
                Some(n),
                "{ctx}"
            );
        }
        if let Some(s) = step["host_status"].as_str() {
            assert_eq!(status_name(r.host.status(&r.invitation)), s, "{ctx}");
        }
        let mut closed = r.closed.clone();
        let mut expected = pairs(&step["closed"]);
        closed.sort();
        closed.dedup();
        expected.sort();
        assert_eq!(closed, expected, "{ctx}: closed");
        let expected_held: Vec<u64> = step["held"]
            .as_array()
            .map(|l| l.iter().map(|c| c.as_u64().expect("conn")).collect())
            .unwrap_or_default();
        assert_eq!(r.held, expected_held, "{ctx}: held");
        if let Some(list) = step["requests"].as_array() {
            let now = r.now;
            let invitation = r.invitation;
            let got: Vec<J> = r
                .host
                .approvals(&invitation, now)
                .iter()
                .map(|a| {
                    json!([
                        r.name_of(&a.request.identity),
                        presence_name(a.presence),
                        decision_name(a.decision)
                    ])
                })
                .collect();
            assert_eq!(&got, list, "{ctx}: requests");
        }
        if let Some(list) = step["granted"].as_array() {
            let invitation = r.invitation;
            let mut got: Vec<String> = r
                .grants
                .grants()
                .filter(|g| g.enrolled_by == Some(invitation))
                .map(|g| r.name_of(&g.identity))
                .collect();
            got.sort();
            let want: Vec<String> = list
                .iter()
                .map(|v| v.as_str().expect("name").to_owned())
                .collect();
            assert_eq!(got, want, "{ctx}: granted");
        }
        let mut recorded = step.clone();
        recorded["out"] = J::Array(std::mem::take(&mut r.out));
        steps.push(recorded);
    }
    let mut draws = serde_json::Map::new();
    draws.insert("host".into(), J::Array(r.host_rng.log.clone()));
    assert!(r.host_rng.script.is_empty(), "{name}: unused host draws");
    for j in &r.joiners {
        assert!(
            j.rng.script.is_empty(),
            "{name}: unused draws of {}",
            j.name
        );
        draws.insert(j.name.clone(), J::Array(j.rng.log.clone()));
    }
    let mut out = seq.clone();
    out["invitation"] = json!(hex(&r.invitation.0));
    out["code"] = json!(r.code.to_display().as_str());
    out["draws"] = J::Object(draws);
    out["steps"] = J::Array(steps);
    out
}

/// Two invitations with the same id and lookup and different secrets: every
/// byte up to and including `AUTHORIZED {join_only, I}` is the same, and the
/// first `msg_a` is not.
fn before_msg_a(listed: Option<&J>) -> J {
    // The drawn bytes are alphabet positions, so these are the codes.
    let draw = |code: &str| -> Vec<u8> {
        code.bytes()
            .map(|c| {
                crate::pairing::DIRECT_CODE_ALPHABET
                    .iter()
                    .position(|a| *a == c)
                    .expect("alphabet") as u8
            })
            .collect()
    };
    let codes = [draw("K7QM2XPA9RTE"), draw("K7QMZZZZ0000")];
    let mut runs = Vec::new();
    for (n, code) in codes.iter().enumerate() {
        // Host draws: the invitation id, then the 12 code bytes; joiner
        // draws: the attempt id, then its scalar.
        let host_draws = json!([{ "bytes": hex(&[0x49; 16]) }, { "bytes": hex(code) }]);
        let joiner_draws = match listed {
            Some(l) => l["joiner_draws"].clone(),
            None => json!([
                { "bytes": hex(&[0xa7; 16]) },
                { "bytes": hex(&[0x0f; 32]) },
            ]),
        };
        let mut r = Replay::new(Some(&json!({ "host": host_draws, "a": joiner_draws })));
        r.joiner("a");
        r.join_direct("a", 1, r.code.lookup(), None);
        let host_key = r.host_key;
        let invitation = r.invitation;
        let lookup = r.code.lookup();
        let password = r.code.secret().as_bytes().to_vec();
        let j = r.joiner("a");
        let mut id = [0u8; 16];
        rand_core::Rng::fill_bytes(&mut j.rng, &mut id);
        let attempt = AttemptId(id);
        let exporter = pair_exporter(1);
        let binding = direct_binding_transcript(&lookup, &invitation, &host_key, &j.key, &exporter);
        let sid = attempt_sid(&attempt, &exporter);
        let mut exchange = CpaceExchangeFactory.start(
            ExchangeRole::Initiator,
            &password,
            &binding,
            &sid,
            &mut j.rng,
        );
        let msg_a = exchange.step(None).expect("msg_a").send.expect("bytes");
        let log = j.rng.log.clone();
        runs.push((n, std::mem::take(&mut r.out), msg_a, log));
    }
    let (first, second) = (&runs[0], &runs[1]);
    assert_eq!(
        first.1, second.1,
        "the wire before msg_a depends on the secret"
    );
    assert_ne!(first.2, second.2, "msg_a must depend on the secret");
    json!({
        "description": "Two invitations with the same invitation id (0x49 repeated) and lookup and different secrets (codes K7QM-2XPA-9RTE and K7QM-ZZZZ-0000), host draws listed in `codes`. Joiner a connects on connection 1 with the same draws. Everything on the wire up to and including AUTHORIZED {join_only, I} (`out`) is the same for both; the first msg_a differs.",
        "codes": codes.iter().map(|c| hex(c)).collect::<Vec<_>>(),
        "invitation": hex(&[0x49; 16]),
        "joiner_draws": J::Array(first.3.clone()),
        "out": J::Array(first.1.clone()),
        "msg_a": [hex(&first.2), hex(&second.2)],
    })
}

pub(super) fn direct_host_vectors() -> J {
    let sequences: Vec<J> = sequences().iter().map(|s| run_sequence(s, None)).collect();
    json!({
        "description": "The host side of Pair with IP (wire.md 10.9) with the real code exchange. Each sequence starts with one invitation created at `conventions.time`; each step runs one operation, then its expectations hold. Ops: connect (step 2, then the joiner sends JOIN_DIRECT {lookup, name} on conn; `lookup` wrong means another lookup), recover (step 2, then JOIN_DIRECT with receipt I and, with `cancel`, the cancel flag), submit (the joiner runs one attempt with the right or a wrong secret: it draws an attempt id and its scalar, sends msg_a, checks msg_b; on a failed check it sends CODE_ABORT {A, pairing_failed} and closes with pairing_failed; otherwise it sends msg_c, unless `lose` is msg_c: then the connection breaks first), inject (the joiner sends CODE_EXCHANGE with `attempt` and `payload`), cancel (the joiner sends CODE_ABORT {its last attempt, cancelled} and closes with cancelled), drop (conn breaks with no GOAWAY), allow and decline (the owner answers the joiner's request; `result` ok or the refusal), owner_cancel, tick (the host's timer). A joiner's close is listed, and reaches the host, only when the host has not closed the connection during the step. A wrong lookup is `0000` (`0001` if that is the invitation's), a wrong secret `00000000` (`00000001` if that is the code's). `at` sets the time, in seconds after `conventions.time`, before the op. Step 2: a connection from an identity with a live grant is bound to it and the host sends AUTHORIZED {live} first. Expectations: `host_status` (`gone` once the host has forgotten the invitation), `host_attempts_left`, `closed` (connections the host closed during the step, with the code), `held` (JOIN_DIRECTs answered by a miss hold: the I/O layer holds the connection for hold_ms, then closes it with invitation_invalid; that close is not listed), `requests` (answerable requests: joiner, presence, decision), `granted` (devices holding a grant whose receipt is the invitation). `out` lists in order every control message each side sent (except the two HELLOs), host closes, and what the host told its I/O layer and UI: admitted (join-only gate), miss_hold, attempts_left (after each debit; the code stays the same), approval (the prompt, sent again with the same id when its presence or decision changes), approval_ended, enrolled and enrollment_undone (with the grant table's id, counting from 0), invitation_ended and grant_closes (grant-table events).",
        "conventions": {
            "time": T,
            "host": { "identity_secret": hex(&IDENTITY_A), "name": HOST_NAME },
            "invitation": { "role": "owner", "authorizing_owner": hex(&[0x51; 16]), "grant_expires_at": null },
            "limits": "The defaults: 600 s lifetime, 5 attempts, a 300 s Allow window, a 1000 ms miss hold.",
            "joiners": "Each joiner's identity secret is one byte repeated 32 times: 0x50 for the first joiner a sequence names, 0x51 for the second, and so on. Its JOIN_DIRECT name is its letter. `host` means the host's own identity key.",
            "exporters": "On connection n both ends see the pair exporter n + 100 repeated 32 times.",
            "draws": "`draws` lists each party's random values in the order it takes them; a `bytes` draw fills a request of exactly that length. Host: the invitation id (16), the code (12; drawn again while its lookup is another open invitation's), then for each new attempt, after the debit and before reading its first message, its CPace scalar yb (32). Joiner: for each attempt the attempt id (16) and its CPace scalar ya (32).",
        },
        "sequences": sequences,
        "before_msg_a": before_msg_a(None),
    })
}

#[test]
fn direct_host_sequences_hold() {
    let text = checked_in("direct-host.json")
        .unwrap_or_else(|| serde_json::to_string(&direct_host_vectors()).expect("json"));
    let doc: J = serde_json::from_str(&text).expect("json");
    for seq in doc["sequences"].as_array().expect("sequences") {
        let replayed = run_sequence(seq, Some(&seq["draws"]));
        assert_eq!(&replayed, seq, "{}", seq["name"]);
    }
    assert_eq!(
        before_msg_a(Some(&doc["before_msg_a"])),
        doc["before_msg_a"]
    );
}
