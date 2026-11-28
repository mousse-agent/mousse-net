//! `direct-host.json`: the host side of Pair with IP (wire.md 10.9), replayed
//! byte for byte from listed random draws.
//!
//! The joiners here are scripted: each sends what wire.md 10.9 says a joiner
//! sends and runs the real CPace initiator, so the host machine is exercised
//! with the real code exchange. Every message passes the host's gate
//! (wire.md 8.1) first, as it does in the I/O layer.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value as J};

use super::{checked_in, hex, identity, unhex, Draws, IDENTITY_A, T};
use crate::authz::{ConnectionGate, GateState, Traffic, Verdict};
use crate::control::{AuthorizedState, ControlMessage, DirectRecovery};
use crate::grants::{GrantEvent, GrantTable, NewGrant, OwnerRef, Role};
use crate::identity::IdentityPublicKey;
use crate::pairing::{
    attempt_sid, direct_binding_transcript, ApprovalEnd, AttemptId, CodeExchange,
    CodeExchangeFactory, CpaceExchange, CpaceExchangeFactory, DirectCode, DirectHostAction,
    DirectHostError, DirectHostPairing, DirectInvitationParams, DirectInvitationStatus,
    DirectLookup, DirectRequestId, ExchangeRole, InvitationId, RequestDecision, RequestPresence,
};
use crate::time::{Millis, UnixTime};
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
            "description": "The lookup finds the invitation, the code passes and the owner is asked. Allow makes a provisional grant with receipt I bound to the connection and sends PAIRED. The first stream frame there commits it.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1, "host_attempts_left": 5, "host_status": "open" },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 4, "requests": [["a", "connected", "pending"]], "grants": [] },
                { "op": "allow", "joiner": "a", "result": "ok", "host_status": "consumed", "requests": [], "grants": [["a", "a", "owner", "provisional"]], "paired": [[1, "owner"]] },
                { "op": "stream", "conn": 1, "grants": [["a", "a", "owner", "direct"]] },
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
                { "op": "allow", "joiner": "a", "result": "ok" },
                { "op": "stream", "conn": 2, "grants": [["a", "a", "owner", "direct"]] },
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
                { "op": "allow", "joiner": "a", "result": "ok", "host_status": "consumed", "grants": [["a", "a", "owner", "provisional"]] },
            ],
        }),
        json!({
            "name": "allow_while_away_then_recovery",
            "description": "The device's connection drops after the code passed; its request stays, away. Allow, with the role viewer, marks it allowed and ends every other request. Its recovery connection is answered AUTHORIZED {join_only, I}, enrolled with that role and sent PAIRED; its first stream frame commits the grant.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "drop", "conn": 1, "requests": [["a", "away", "pending"]] },
                { "op": "allow", "joiner": "a", "role": "viewer", "result": "ok", "host_status": "allowed", "requests": [["a", "away", "allowed"]], "grants": [] },
                { "op": "connect", "joiner": "b", "conn": 2, "held": [2] },
                { "op": "recover", "joiner": "a", "conn": 3, "host_status": "consumed", "requests": [], "grants": [["a", "a", "viewer", "provisional"]], "paired": [[3, "viewer"]] },
                { "op": "stream", "conn": 3, "grants": [["a", "a", "viewer", "direct"]] },
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
                { "op": "allow", "joiner": "a", "result": "ok", "grants": [["a", "a", "owner", "provisional"]], "paired": [[2, "owner"]] },
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
                { "op": "recover", "joiner": "a", "conn": 2, "cancel": true, "closed": [[2, "cancelled"]], "host_status": "ended:cancelled", "grants": [] },
            ],
        }),
        json!({
            "name": "cancel_crossing_allow_goaway_lost",
            "description": "The owner allows while the device's cancel is on its way. Its CODE_ABORT {A, cancelled} for the attempt that passed goes through the live gate of the connection the host just enrolled; the provisional grant is removed and the host closes with cancelled. The device's own GOAWAY is lost.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "result": "ok", "grants": [["a", "a", "owner", "provisional"]] },
                { "op": "cancel", "joiner": "a", "conn": 1, "goaway": "lost", "closed": [[1, "cancelled"]], "grants": [] },
            ],
        }),
        json!({
            "name": "cancel_crossing_allow_abort_lost",
            "description": "As before, but the CODE_ABORT is lost and only the device's close with cancelled reaches the host: that removes the provisional grant too.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "result": "ok", "grants": [["a", "a", "owner", "provisional"]] },
                { "op": "cancel", "joiner": "a", "conn": 1, "abort": "lost", "grants": [] },
            ],
        }),
        json!({
            "name": "a_cancel_after_the_commit_is_too_late",
            "description": "Once a stream frame committed the grant, the device's CODE_ABORT is ignored by the live gate and its close with cancelled is an ordinary close. A recovery that cancels is answered PAIRED: the grant stays.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "result": "ok" },
                { "op": "stream", "conn": 1, "grants": [["a", "a", "owner", "direct"]] },
                { "op": "cancel", "joiner": "a", "conn": 1, "grants": [["a", "a", "owner", "direct"]] },
                { "op": "recover", "joiner": "a", "conn": 2, "cancel": true, "paired": [[2, "owner"]], "grants": [["a", "a", "owner", "direct"]] },
            ],
        }),
        json!({
            "name": "cancel_by_recovery_after_allow",
            "description": "The owner allowed; the connection broke before the device saw PAIRED, and the device cancelled meanwhile. Step 2 binds its next connections to the provisional grant (AUTHORIZED {live}); its recovery carries the cancel, which removes that grant. The other connection bound to it closes with grant_revoked before the host reports the removal.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "result": "ok" },
                { "op": "drop", "conn": 1, "grants": [["a", "a", "owner", "provisional"]] },
                { "op": "dial", "joiner": "a", "conn": 2 },
                { "op": "recover", "joiner": "a", "conn": 3, "cancel": true, "closed": [[3, "cancelled"]], "grants": [] },
            ],
        }),
        json!({
            "name": "lost_paired_answered_by_receipt",
            "description": "The owner allowed; PAIRED was lost with the connection. Step 2 binds the recovery to the provisional grant (AUTHORIZED {live}), and the host answers PAIRED from its receipt. The first stream frame commits it.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "result": "ok" },
                { "op": "drop", "conn": 1 },
                { "op": "recover", "joiner": "a", "conn": 2, "paired": [[2, "owner"]], "grants": [["a", "a", "owner", "provisional"]] },
                { "op": "stream", "conn": 2, "grants": [["a", "a", "owner", "direct"]] },
            ],
        }),
        json!({
            "name": "the_first_ordinary_connection_commits",
            "description": "The pairing connection closes before any stream. The device's next ordinary connection is bound to the provisional grant by step 2 (AUTHORIZED {live}); its first stream frame commits it.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "result": "ok" },
                { "op": "drop", "conn": 1 },
                { "op": "dial", "joiner": "a", "conn": 2, "grants": [["a", "a", "owner", "provisional"]] },
                { "op": "stream", "conn": 2, "grants": [["a", "a", "owner", "direct"]] },
            ],
        }),
        json!({
            "name": "a_recovery_bound_after_a_late_allow",
            "description": "The device's recovery connection ran step 2 before the owner allowed on the original connection, so step 2 bound nothing and sent nothing. When its JOIN_DIRECT arrives, the host binds it to the provisional grant and sends AUTHORIZED {live} before PAIRED.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "dial", "joiner": "a", "conn": 2 },
                { "op": "allow", "joiner": "a", "result": "ok", "paired": [[1, "owner"]] },
                { "op": "recover", "joiner": "a", "conn": 2, "paired": [[2, "owner"]], "grants": [["a", "a", "owner", "provisional"]] },
                { "op": "stream", "conn": 2, "grants": [["a", "a", "owner", "direct"]] },
            ],
        }),
        json!({
            "name": "a_re_pair_cancelled_across_allow_keeps_the_old_grant",
            "description": "a already holds a grant (from a ticket whose invitation id has the same bytes as I) and pairs again on connection 2. Allow, with the role viewer, makes a provisional grant: the old grant stays, and connection 1, live under it, opens a stream without committing anything. The cancel crossing Allow removes only the provisional grant; the old one and connection 1 stay.",
            "steps": [
                { "op": "old_grant", "joiner": "a", "grants": [["a", "a (old)", "owner", "ticket"]] },
                { "op": "dial", "joiner": "a", "conn": 1 },
                { "op": "connect", "joiner": "a", "conn": 2 },
                { "op": "submit", "joiner": "a", "conn": 2, "code": "right" },
                { "op": "allow", "joiner": "a", "role": "viewer", "result": "ok", "paired": [[2, "viewer"]], "grants": [["a", "a", "viewer", "provisional"], ["a", "a (old)", "owner", "ticket"]] },
                { "op": "stream", "conn": 1, "grants": [["a", "a", "viewer", "provisional"], ["a", "a (old)", "owner", "ticket"]] },
                { "op": "cancel", "joiner": "a", "conn": 2, "goaway": "lost", "closed": [[2, "cancelled"]], "grants": [["a", "a (old)", "owner", "ticket"]] },
                { "op": "stream", "conn": 1 },
            ],
        }),
        json!({
            "name": "a_re_pair_commit_replaces_the_old_grant",
            "description": "As before, but the device takes PAIRED and opens a stream on connection 2: the provisional grant commits, replaces the old grant, and connection 1, bound to the old one, closes with grant_revoked.",
            "steps": [
                { "op": "old_grant", "joiner": "a" },
                { "op": "dial", "joiner": "a", "conn": 1 },
                { "op": "connect", "joiner": "a", "conn": 2 },
                { "op": "submit", "joiner": "a", "conn": 2, "code": "right" },
                { "op": "allow", "joiner": "a", "role": "viewer", "result": "ok" },
                { "op": "stream", "conn": 2, "grants": [["a", "a", "viewer", "direct"]] },
            ],
        }),
        json!({
            "name": "a_ticket_receipt_never_answers_a_direct_recovery",
            "description": "a holds a grant from a ticket whose invitation id has the same bytes as I. A direct recovery with that receipt neither removes it (with the cancel flag) nor is answered PAIRED (without): a never passed this invitation's code, so the second recovery hears not_received.",
            "steps": [
                { "op": "old_grant", "joiner": "a" },
                { "op": "recover", "joiner": "a", "conn": 1, "cancel": true, "closed": [[1, "cancelled"]], "grants": [["a", "a (old)", "owner", "ticket"]] },
                { "op": "recover", "joiner": "a", "conn": 2, "paired": [], "grants": [["a", "a (old)", "owner", "ticket"]] },
            ],
        }),
        json!({
            "name": "two_identities_pass",
            "description": "Two devices pass the code, each with its own request. Allowing b with the role viewer enrolls b with its own name and that role, ends a's request and closes its connection with invitation_invalid.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "connect", "joiner": "b", "conn": 2 },
                { "op": "submit", "joiner": "b", "conn": 2, "code": "right", "requests": [["a", "connected", "pending"], ["b", "connected", "pending"]] },
                { "op": "allow", "joiner": "b", "role": "viewer", "result": "ok", "closed": [[1, "invitation_invalid"]], "requests": [], "grants": [["b", "b", "viewer", "provisional"]], "paired": [[2, "viewer"]] },
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
                { "op": "allow", "joiner": "a", "result": "ok", "at": 898, "grants": [["a", "a", "owner", "provisional"]] },
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
            "name": "answers_at_the_window_end_before_the_timer",
            "description": "At the end of the Allow window, before the host's timer has run, the request can no longer be allowed or declined.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "at": 10 },
                { "op": "allow", "joiner": "a", "at": 310, "result": "unknown_request", "grants": [] },
                { "op": "decline", "joiner": "a", "result": "unknown_request", "host_status": "open" },
                { "op": "tick", "closed": [[1, "invitation_invalid"]] },
            ],
        }),
        json!({
            "name": "a_claim_at_the_window_end_before_the_timer",
            "description": "Allowed while away, the device recovers at the end of the Allow window, before the host's timer has run: nothing is enrolled and the recovery gets the miss hold.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "at": 10 },
                { "op": "drop", "conn": 1 },
                { "op": "allow", "joiner": "a", "at": 309, "result": "ok", "host_status": "allowed" },
                { "op": "recover", "joiner": "a", "conn": 2, "at": 310, "held": [2], "grants": [] },
                { "op": "tick", "host_status": "gone" },
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
            "name": "a_forgotten_outcome_is_never_not_received",
            "description": "The device passed the code and cancelled; its outcome is kept until its Allow window ends. A recovery after that, while the invitation is still open, gets the miss hold, never not_received.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "cancel", "joiner": "a", "conn": 1, "closed": [[1, "cancelled"]] },
                { "op": "tick", "at": 300, "host_status": "open" },
                { "op": "recover", "joiner": "a", "conn": 2, "held": [2] },
            ],
        }),
        json!({
            "name": "a_recovery_cancel_before_the_confirmation_arrives",
            "description": "The device's confirmation (msg_c) is still on its way on connection 1 when its recovery with the cancel flag arrives. The host retires connection 1 and its attempt before it answers cancelled, so the confirmation, which then never arrives, opens no request.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "hold": "msg_c", "requests": [] },
                { "op": "recover", "joiner": "a", "conn": 2, "cancel": true, "closed": [[1, "cancelled"], [2, "cancelled"]] },
                { "op": "deliver", "joiner": "a", "conn": 1, "requests": [] },
                { "op": "allow", "joiner": "a", "result": "unknown_request", "grants": [] },
            ],
        }),
        json!({
            "name": "a_recovery_cancel_ends_an_exhausted_invitation",
            "description": "a passes and goes away; b uses up the other four attempts, so only a's request keeps the invitation open. a's recovery cancels: the invitation ends at once, the next lookup gets the miss hold, and a's next recovery still hears cancelled.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "drop", "conn": 1 },
                { "op": "connect", "joiner": "b", "conn": 2 },
                { "op": "submit", "joiner": "b", "conn": 2, "code": "wrong" },
                { "op": "connect", "joiner": "b", "conn": 3 },
                { "op": "submit", "joiner": "b", "conn": 3, "code": "wrong" },
                { "op": "connect", "joiner": "b", "conn": 4 },
                { "op": "submit", "joiner": "b", "conn": 4, "code": "wrong" },
                { "op": "connect", "joiner": "b", "conn": 5 },
                { "op": "submit", "joiner": "b", "conn": 5, "code": "wrong", "host_attempts_left": 0, "host_status": "open" },
                { "op": "recover", "joiner": "a", "conn": 6, "cancel": true, "closed": [[6, "cancelled"]], "host_status": "ended:attempts_exhausted" },
                { "op": "connect", "joiner": "c", "conn": 7, "held": [7] },
                { "op": "recover", "joiner": "a", "conn": 8, "closed": [[8, "cancelled"]] },
            ],
        }),
        json!({
            "name": "a_provisional_grant_survives_a_restart",
            "description": "The owner allowed and the connection broke before any stream; then the host restarted. The invitation is gone, but the provisional grant was stored: step 2 binds the recovery to it, the receipt answers PAIRED, and the first stream frame commits it.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "result": "ok" },
                { "op": "drop", "conn": 1 },
                { "op": "restart", "host_status": "gone", "grants": [["a", "a", "owner", "provisional"]] },
                { "op": "recover", "joiner": "a", "conn": 2, "paired": [[2, "owner"]] },
                { "op": "stream", "conn": 2, "grants": [["a", "a", "owner", "direct"]] },
            ],
        }),
        json!({
            "name": "a_commit_elsewhere_ends_the_cancel_exception",
            "description": "The device's next connection commits the grant while the enrolled connection is still up. Every connection bound to the grant learns of the commit, so the enrolled connection's gate now ignores the late CODE_ABORT of the attempt that passed, and the grant stays.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "result": "ok" },
                { "op": "dial", "joiner": "a", "conn": 2 },
                { "op": "stream", "conn": 2, "grants": [["a", "a", "owner", "direct"]] },
                { "op": "cancel", "joiner": "a", "conn": 1, "goaway": "lost", "grants": [["a", "a", "owner", "direct"]] },
            ],
        }),
        json!({
            "name": "a_recovery_cancel_with_a_kept_outcome_still_retires",
            "description": "The device cancelled once and its outcome is kept; it types the code again and its confirmation is still on its way when its recovery cancels. The host retires that connection before it answers with the kept outcome, so the confirmation opens no request.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "cancel", "joiner": "a", "conn": 1, "closed": [[1, "cancelled"]] },
                { "op": "connect", "joiner": "a", "conn": 2 },
                { "op": "submit", "joiner": "a", "conn": 2, "code": "right", "hold": "msg_c" },
                { "op": "recover", "joiner": "a", "conn": 3, "cancel": true, "closed": [[2, "cancelled"], [3, "cancelled"]] },
                { "op": "deliver", "joiner": "a", "conn": 2, "requests": [] },
            ],
        }),
        json!({
            "name": "an_abort_for_another_attempt_keeps_the_request",
            "description": "A CODE_ABORT with cancelled that names an attempt other than the one that passed on the connection ends nothing: the request stays.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "abort", "joiner": "a", "conn": 1, "attempt": first, "code": "cancelled", "requests": [["a", "connected", "pending"]], "closed": [] },
            ],
        }),
        json!({
            "name": "a_held_connection_commits_nothing",
            "description": "The device holds a provisional grant; its next connection is bound to it by step 2, then sends a lookup that finds nothing. While the host holds that connection, its stream frame is ignored and commits nothing.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "result": "ok" },
                { "op": "drop", "conn": 1 },
                { "op": "connect", "joiner": "a", "conn": 2, "lookup": "wrong", "held": [2] },
                { "op": "stream", "conn": 2, "grants": [["a", "a", "owner", "provisional"]] },
            ],
        }),
        json!({
            "name": "an_expired_request_does_not_keep_an_exhausted_invitation",
            "description": "a passes at 0 and b at 100; c uses up the last attempts. At 310 a's request is past its window but the timer has not run. b's recovery cancels: no request inside its window is left, so the invitation ends as exhausted and the next lookup gets the miss hold.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 4 },
                { "op": "connect", "joiner": "b", "conn": 2, "at": 100 },
                { "op": "submit", "joiner": "b", "conn": 2, "code": "right", "host_attempts_left": 3 },
                { "op": "connect", "joiner": "c", "conn": 3 },
                { "op": "submit", "joiner": "c", "conn": 3, "code": "wrong" },
                { "op": "connect", "joiner": "c", "conn": 4 },
                { "op": "submit", "joiner": "c", "conn": 4, "code": "wrong" },
                { "op": "connect", "joiner": "c", "conn": 5 },
                { "op": "submit", "joiner": "c", "conn": 5, "code": "wrong", "host_attempts_left": 0, "host_status": "open" },
                { "op": "recover", "joiner": "b", "conn": 6, "at": 310, "cancel": true, "closed": [[1, "attempts_exhausted"], [2, "cancelled"], [6, "cancelled"]], "host_status": "ended:attempts_exhausted" },
                { "op": "connect", "joiner": "d", "conn": 7, "held": [7] },
            ],
        }),
        json!({
            "name": "a_claim_after_the_grant_expiry_sends_nothing",
            "grant_expires_at": 100,
            "description": "The invitation's grants expire at 100. Allowed while away at 50, the device recovers at 100: the grant would be born expired, so nothing is sent but the close, the invitation ends as invalid, and nothing is granted.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "drop", "conn": 1 },
                { "op": "allow", "joiner": "a", "at": 50, "result": "ok" },
                { "op": "recover", "joiner": "a", "conn": 2, "at": 100, "closed": [[2, "invitation_invalid"]], "host_status": "ended:invitation_invalid", "grants": [] },
            ],
        }),
        json!({
            "name": "allow_after_the_grant_expiry_is_refused",
            "grant_expires_at": 100,
            "description": "An Allow at the grant expiry is refused and changes nothing.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "at": 100, "result": "grant_expired", "requests": [["a", "connected", "pending"]], "grants": [], "host_status": "open" },
            ],
        }),
        json!({
            "name": "a_commit_after_the_grant_expiry_fails",
            "grant_expires_at": 100,
            "description": "Allowed at 50, the device opens its first stream at 100: the commit fails, the provisional grant is removed and the connection closes with grant_revoked.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "at": 50, "result": "ok" },
                { "op": "stream", "conn": 1, "at": 100, "closed": [[1, "grant_revoked"]], "grants": [] },
            ],
        }),
        json!({
            "name": "a_failed_commit_with_another_bound_connection",
            "grant_expires_at": 100,
            "description": "Allowed at 50; the device's next connection is bound to the provisional grant at 60. At 100 the enrolled connection's first stream frame finds the grant expired: the other connection closes with grant_revoked, then the enrolled one.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "at": 50, "result": "ok" },
                { "op": "dial", "joiner": "a", "conn": 2, "at": 60 },
                { "op": "stream", "conn": 1, "at": 100, "closed": [[1, "grant_revoked"]], "grants": [] },
            ],
        }),
        json!({
            "name": "a_cancel_for_a_running_attempt_keeps_a_moved_request",
            "description": "a's code passed on connection 1, which then broke; its recovery moved the request to connection 2, where a second attempt runs (its confirmation still on its way). A CODE_ABORT with cancelled for that running attempt ends nothing: only the attempt that passed counts.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "drop", "conn": 1, "requests": [["a", "away", "pending"]] },
                { "op": "recover", "joiner": "a", "conn": 2, "requests": [["a", "connected", "pending"]] },
                { "op": "submit", "joiner": "a", "conn": 2, "code": "right", "hold": "msg_c" },
                { "op": "abort", "joiner": "a", "conn": 2, "attempt": "last", "code": "cancelled", "requests": [["a", "connected", "pending"]], "closed": [] },
            ],
        }),
        json!({
            "name": "a_kept_outcome_after_the_final_attempt_ends_the_invitation",
            "description": "a cancelled once and its outcome is kept; b's wrong codes leave one attempt, which a's retry uses, its confirmation still on its way. a's recovery cancels: the host retires that attempt, answers with the kept outcome, and the invitation, with nothing left to take, ends as exhausted; the next lookup gets the miss hold.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "cancel", "joiner": "a", "conn": 1, "closed": [[1, "cancelled"]] },
                { "op": "connect", "joiner": "b", "conn": 2 },
                { "op": "submit", "joiner": "b", "conn": 2, "code": "wrong" },
                { "op": "connect", "joiner": "b", "conn": 3 },
                { "op": "submit", "joiner": "b", "conn": 3, "code": "wrong" },
                { "op": "connect", "joiner": "b", "conn": 4 },
                { "op": "submit", "joiner": "b", "conn": 4, "code": "wrong", "host_attempts_left": 1 },
                { "op": "connect", "joiner": "a", "conn": 5 },
                { "op": "submit", "joiner": "a", "conn": 5, "code": "right", "hold": "msg_c", "host_attempts_left": 0 },
                { "op": "recover", "joiner": "a", "conn": 6, "cancel": true, "closed": [[5, "cancelled"], [6, "cancelled"]], "host_status": "ended:attempts_exhausted" },
                { "op": "connect", "joiner": "c", "conn": 7, "held": [7] },
            ],
        }),
        json!({
            "name": "a_miss_hold_outlasts_the_join_proof_timer",
            "description": "Connection 1's lookup finds nothing just before its join-proof deadline. The host holds it: the join-proof timer no longer fires, so the only close is the hold's invitation_invalid after the full hold. Connection 2, which sent nothing, is closed by its timer.",
            "steps": [
                { "op": "dial", "joiner": "a", "conn": 1 },
                { "op": "dial", "joiner": "b", "conn": 2 },
                { "op": "connect", "joiner": "a", "conn": 1, "lookup": "wrong", "held": [1] },
                { "op": "gate_timer", "ms": 10000, "closed": [[2, "not_authorized"]] },
            ],
        }),
        json!({
            "name": "a_recovery_cancel_after_both_deadlines_gets_the_miss_hold",
            "description": "a passes at 599, just before the invitation's deadline at 600, and goes away; at 899 its Allow window has ended too, and the timer has not run. Its recovery cancels: the invitation takes nothing any more, so the answer is the miss hold, not cancelled.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1, "at": 598 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "at": 599 },
                { "op": "drop", "conn": 1 },
                { "op": "recover", "joiner": "a", "conn": 2, "at": 899, "cancel": true, "held": [2], "closed": [] },
            ],
        }),
        json!({
            "name": "a_provisional_grant_expires_with_no_connection",
            "grant_expires_at": 100,
            "description": "Allowed at 50; the device's connection breaks before any stream. At 100 the timer removes the provisional grant and reports it, though no connection was bound to it.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "at": 50, "result": "ok" },
                { "op": "drop", "conn": 1 },
                { "op": "tick", "at": 100, "grants": [] },
            ],
        }),
        json!({
            "name": "a_newer_provisional_grant_replaces_an_unbound_one",
            "description": "a passes the code of two invitations, on connections 1 and 2. Invitation 0 allows it on connection 1, which then breaks before any stream. Invitation 1 allows it on connection 2: the newer provisional grant replaces the older one, which is reported removed though no connection was bound to it.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "invite" },
                { "op": "connect", "joiner": "a", "conn": 2 },
                { "op": "submit", "joiner": "a", "conn": 2, "code": "right" },
                { "op": "use", "invitation": 0 },
                { "op": "allow", "joiner": "a", "at": 50, "result": "ok", "grants": [["a", "a", "owner", "provisional"]] },
                { "op": "drop", "conn": 1 },
                { "op": "use", "invitation": 1 },
                { "op": "allow", "joiner": "a", "at": 60, "result": "ok", "grants": [["a", "a", "owner", "provisional"]] },
            ],
        }),
        json!({
            "name": "a_provisional_grant_expires",
            "grant_expires_at": 100,
            "description": "Allowed at 50, the device opens no stream; at 100 the timer removes the provisional grant and closes its connection with grant_revoked.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "at": 50, "result": "ok" },
                { "op": "tick", "at": 100, "grants": [] },
                { "op": "stream", "conn": 1 },
            ],
        }),
        json!({
            "name": "a_committed_grant_expires",
            "grant_expires_at": 100,
            "description": "The grant committed at 10; at 100 the timer removes it and closes its connection with grant_revoked, after which nothing on that connection passes the gate.",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right" },
                { "op": "allow", "joiner": "a", "result": "ok" },
                { "op": "stream", "conn": 1, "at": 10, "grants": [["a", "a", "owner", "direct"]] },
                { "op": "tick", "at": 100, "grants": [] },
                { "op": "stream", "conn": 1 },
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
        DirectHostError::GrantExpired => "grant_expired",
        DirectHostError::Denied => "denied",
    }
}

fn verdict_name(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Ignore => "ignore",
        Verdict::Commit(_) => "commit",
        Verdict::Close(_) => "close",
    }
}

struct VJoiner {
    name: String,
    key: IdentityPublicKey,
    rng: Draws,
    /// The attempt this joiner ran last.
    attempt: Option<AttemptId>,
    /// A confirmation still on its way: (connection, message).
    held: Option<(u64, ControlMessage)>,
}

struct Replay {
    host: DirectHostPairing<CpaceExchangeFactory>,
    host_rng: Draws,
    host_key: IdentityPublicKey,
    grants: GrantTable,
    /// The host's gate of each connection (wire.md 8.1).
    gates: BTreeMap<u64, ConnectionGate>,
    invitation: InvitationId,
    code: DirectCode,
    /// Every invitation the sequence made, in order: (id, code).
    invitations: Vec<(InvitationId, DirectCode)>,
    grant_expires_at: Option<UnixTime>,
    joiners: Vec<VJoiner>,
    listed: Option<J>,
    now: UnixTime,
    out: Vec<J>,
    /// Connections the host closed during the step.
    closed: Vec<(u64, String)>,
    /// Connections either side has closed so far.
    gone: BTreeSet<u64>,
    held: Vec<u64>,
    /// `PAIRED` messages the host sent during the step: (connection, role).
    paired: Vec<(u64, String)>,
}

impl Replay {
    fn new(listed: Option<&J>, grant_expires_at: Option<UnixTime>) -> Self {
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
                    grant_expires_at,
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
            gates: BTreeMap::new(),
            invitation: created.invitation,
            invitations: vec![(created.invitation, created.code.clone())],
            code: created.code,
            grant_expires_at,
            joiners: Vec::new(),
            listed: listed.cloned(),
            now: UnixTime(T),
            out: Vec::new(),
            closed: Vec::new(),
            gone: BTreeSet::new(),
            held: Vec::new(),
            paired: Vec::new(),
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
                held: None,
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

    /// The host closes `conn` with `code`.
    fn host_closes(&mut self, conn: u64, code: ErrorCode) {
        self.out
            .push(json!({ "close": { "from": "host", "conn": conn, "code": code.name() } }));
        self.closed.push((conn, code.name().to_owned()));
        self.gone.insert(conn);
        if let Some(gate) = self.gates.get_mut(&conn) {
            gate.close(code);
        }
    }

    /// Log the host's actions and apply them to the gates; return the
    /// messages it sent on `conn`.
    fn host_did(&mut self, actions: &[DirectHostAction], conn: u64) -> Vec<ControlMessage> {
        let mut on_conn = Vec::new();
        for a in actions {
            match a {
                DirectHostAction::Send { conn: c, message } => {
                    self.sent("host", c.0, message);
                    if let ControlMessage::Paired { role, .. } = message {
                        self.paired.push((c.0, role.as_str().to_owned()));
                    }
                    if c.0 == conn {
                        on_conn.push(message.clone());
                    }
                }
                DirectHostAction::Close { conn: c, code } => self.host_closes(c.0, *code),
                DirectHostAction::MissHold { conn: c, hold_ms } => {
                    if let Some(gate) = self.gates.get_mut(&c.0) {
                        gate.hold();
                    }
                    self.out
                        .push(json!({ "miss_hold": { "conn": c.0, "hold_ms": hold_ms } }));
                    self.held.push(c.0);
                }
                DirectHostAction::AdmittedJoinOnly {
                    conn: c,
                    invitation,
                } => {
                    self.out.push(json!({ "admitted": { "conn": c.0 } }));
                    if let Some(gate) = self.gates.get_mut(&c.0) {
                        gate.admit_join_only(*invitation);
                    }
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
                    attempt,
                    ..
                } => {
                    let who = self.name_of(identity);
                    self.out.push(json!({ "enrolled": {
                        "joiner": who, "conn": c.0, "grant": grant.0, "role": role.as_str(),
                    } }));
                    if let Some(gate) = self.gates.get_mut(&c.0) {
                        gate.bind_direct(*grant, true, *attempt);
                    }
                }
                DirectHostAction::Bound {
                    conn: c,
                    grant,
                    provisional,
                } => {
                    self.out.push(json!({ "bound": {
                        "conn": c.0, "grant": grant.0, "provisional": provisional,
                    } }));
                    if let Some(gate) = self.gates.get_mut(&c.0) {
                        gate.bind_direct(*grant, *provisional, None);
                    }
                }
                DirectHostAction::Committed {
                    conn: c,
                    grant,
                    identity,
                    bound,
                } => {
                    let who = self.name_of(identity);
                    let list: Vec<u64> = bound.iter().map(|b| b.0).collect();
                    self.out.push(json!({ "committed": {
                        "joiner": who, "conn": c.0, "grant": grant.0, "bound": list,
                    } }));
                    for b in bound {
                        if let Some(gate) = self.gates.get_mut(&b.0) {
                            gate.committed();
                        }
                    }
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
                    let list: Vec<u64> = channels.iter().map(|c| c.0).collect();
                    self.out.push(json!({ "grant_closes": {
                        "grant": grant.0, "conns": list, "code": code.name(),
                    } }));
                    for c in channels {
                        self.gone.insert(c.0);
                        if let Some(gate) = self.gates.get_mut(&c.0) {
                            gate.close(*code);
                        }
                    }
                }
            }
        }
        on_conn
    }

    /// A new connection from `who`: the host runs step 2 with its gate. A
    /// live result is bound and the host says `AUTHORIZED {live}`.
    fn dial(&mut self, who: &str, conn: u64) {
        let key = self.key_of(who);
        let gate = ConnectionGate::open(
            ConnectionId(conn),
            key,
            &mut self.grants,
            self.now,
            Millis(0),
        );
        let state = gate.state().clone();
        self.gates.insert(conn, gate);
        match state {
            GateState::Live { .. } => self.sent(
                "host",
                conn,
                &ControlMessage::Authorized {
                    state: AuthorizedState::Live,
                },
            ),
            GateState::Closed(code) => self.host_closes(conn, code),
            _ => {}
        }
    }

    /// The message passes the host's gate, then reaches the host machine.
    fn deliver(&mut self, who: &str, conn: u64, m: &ControlMessage) -> Vec<ControlMessage> {
        self.sent(who, conn, m);
        let verdict = self
            .gates
            .get_mut(&conn)
            .expect("a dialled connection")
            .check_message(m);
        match verdict {
            Verdict::Allow => {}
            Verdict::Close(code) => {
                self.host_closes(conn, code);
                return Vec::new();
            }
            other => {
                self.out
                    .push(json!({ "gate": { "conn": conn, "verdict": verdict_name(other) } }));
                return Vec::new();
            }
        }
        let actions = match m {
            ControlMessage::JoinDirect {
                lookup,
                name,
                recovery,
            } => {
                let key = *self.gates[&conn].peer();
                self.host.on_join_direct(
                    ConnectionId(conn),
                    &key,
                    &pair_exporter(conn),
                    lookup,
                    name,
                    *recovery,
                    &mut self.grants,
                    self.now,
                )
            }
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

    fn join_direct(
        &mut self,
        who: &str,
        conn: u64,
        lookup: DirectLookup,
        recovery: Option<DirectRecovery>,
    ) {
        if !self.gates.contains_key(&conn) {
            self.dial(who, conn);
        }
        if self.gone.contains(&conn) {
            return;
        }
        let m = ControlMessage::JoinDirect {
            lookup,
            name: who.to_owned(),
            recovery,
        };
        self.deliver(who, conn, &m);
    }

    /// The joiner's side closed `conn`: with `code` in its `GOAWAY`, or with
    /// none when the connection broke.
    fn joiner_closes(&mut self, who: &str, conn: u64, code: Option<ErrorCode>) {
        if let Some(code) = code {
            self.out
                .push(json!({ "close": { "from": who, "conn": conn, "code": code.name() } }));
        }
        self.gates.remove(&conn);
        self.gone.insert(conn);
        self.grants.unbind(ConnectionId(conn));
        let actions =
            self.host
                .on_connection_closed(ConnectionId(conn), code, &mut self.grants, self.now);
        self.host_did(&actions, conn);
    }

    fn submit(&mut self, who: &str, conn: u64, right: bool, keep: Option<&str>) {
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
        let reply = self.deliver(
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
                let msg_c = ControlMessage::CodeExchange {
                    attempt,
                    payload: step.send.expect("msg_c"),
                };
                match keep {
                    // The connection breaks before msg_c reaches the host.
                    Some("lose") => self.joiner_closes(who, conn, None),
                    // msg_c is still on its way.
                    Some("hold") => self.joiner(who).held = Some((conn, msg_c)),
                    _ => {
                        self.deliver(who, conn, &msg_c);
                    }
                }
            }
            Err(_) => {
                // Wrong code: abort the attempt and close; the next try is
                // a new Connect.
                self.deliver(
                    who,
                    conn,
                    &ControlMessage::CodeAbort {
                        attempt,
                        code: ErrorCode::PairingFailed,
                    },
                );
                if !self.gone.contains(&conn) {
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

    /// Every grant in the table, provisional ones too:
    /// `[joiner, name, role, kind]`, kind `provisional`, `direct` (a
    /// committed grant a direct invitation made) or `ticket`.
    fn grant_list(&self) -> Vec<J> {
        let mut list: Vec<Vec<String>> = self
            .grants
            .grants()
            .map(|g| (g, false))
            .chain(self.grants.provisional_grants().map(|g| (g, true)))
            .map(|(g, provisional)| {
                let kind = match (provisional, g.direct) {
                    (true, _) => "provisional",
                    (false, true) => "direct",
                    (false, false) => "ticket",
                };
                vec![
                    self.name_of(&g.identity),
                    g.name.clone(),
                    g.role.as_str().to_owned(),
                    kind.to_owned(),
                ]
            })
            .collect();
        list.sort();
        list.into_iter().map(|g| json!(g)).collect()
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
            "dial" => self.dial(&who, conn),
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
                let keep = match (step["lose"].as_str(), step["hold"].as_str()) {
                    (Some("msg_c"), _) => Some("lose"),
                    (_, Some("msg_c")) => Some("hold"),
                    _ => None,
                };
                self.submit(&who, conn, right, keep);
            }
            "deliver" => {
                let (c, m) = self.joiner(&who).held.take().expect("a held message");
                assert_eq!(c, conn);
                if self.gone.contains(&conn) {
                    // The connection closed first: the message never
                    // arrives.
                    self.out.push(json!({ "undelivered": { "conn": conn } }));
                } else {
                    self.deliver(&who, conn, &m);
                }
            }
            "abort" => {
                let attempt = match step["attempt"].as_str().expect("attempt") {
                    "last" => self.joiner(&who).attempt.expect("an attempt"),
                    h => AttemptId(unhex(h).try_into().expect("16")),
                };
                let code = match step["code"].as_str() {
                    Some("cancelled") => ErrorCode::Cancelled,
                    other => panic!("abort code {other:?}"),
                };
                self.deliver(&who, conn, &ControlMessage::CodeAbort { attempt, code });
            }
            "inject" => {
                let attempt = AttemptId(
                    unhex(step["attempt"].as_str().expect("attempt"))
                        .try_into()
                        .expect("16"),
                );
                let payload = unhex(step["payload"].as_str().expect("payload"));
                self.deliver(
                    &who,
                    conn,
                    &ControlMessage::CodeExchange { attempt, payload },
                );
            }
            "cancel" => {
                let attempt = self.joiner(&who).attempt.expect("an attempt");
                let abort = ControlMessage::CodeAbort {
                    attempt,
                    code: ErrorCode::Cancelled,
                };
                if step["abort"] == "lost" {
                    self.out.push(json!({ "lost": {
                        "from": who, "conn": conn, "control": hex(&abort.encode()),
                    } }));
                } else {
                    self.deliver(&who, conn, &abort);
                }
                if !self.gone.contains(&conn) {
                    let code = (step["goaway"] != "lost").then_some(ErrorCode::Cancelled);
                    self.joiner_closes(&who, conn, code);
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
            "stream" => {
                let verdict = self
                    .gates
                    .get_mut(&conn)
                    .expect("a dialled connection")
                    .check(Traffic::Stream);
                self.out
                    .push(json!({ "stream": { "conn": conn, "verdict": verdict_name(verdict) } }));
                match verdict {
                    Verdict::Commit(grant) => {
                        let actions = self.host.on_first_stream(
                            ConnectionId(conn),
                            grant,
                            &mut self.grants,
                            self.now,
                        );
                        self.host_did(&actions, conn);
                        if !self.gone.contains(&conn) {
                            // Committed: the frame passes the gate now.
                            let again = self
                                .gates
                                .get_mut(&conn)
                                .expect("gate")
                                .check(Traffic::Stream);
                            assert_eq!(again, Verdict::Allow);
                        }
                    }
                    Verdict::Close(code) => self.host_closes(conn, code),
                    Verdict::Allow | Verdict::Ignore => {}
                }
            }
            "old_grant" => {
                // A grant from a ticket pairing whose invitation id has the
                // same bytes as this invitation's.
                let identity = self.key_of(&who);
                let (_, events) = self
                    .grants
                    .add(
                        NewGrant {
                            identity,
                            name: format!("{who} (old)"),
                            role: Role::owner(),
                            authorizing_owner: OwnerRef::from_bytes([0x51; 16]),
                            expires_at: None,
                            enrolled_by: Some(self.invitation),
                        },
                        self.now,
                    )
                    .expect("grant");
                assert!(events.is_empty());
            }
            "restart" => {
                // Invitations live in memory only; the grant table is
                // stored, provisional grants too. Every connection is gone.
                let grants: Vec<_> = self.grants.grants().cloned().collect();
                let provisional: Vec<_> = self.grants.provisional_grants().cloned().collect();
                let denials: Vec<_> = self.grants.denials().collect();
                let mut table = GrantTable::restore(grants, denials, self.grants.next_grant_id())
                    .expect("restore");
                table.restore_provisional(provisional).expect("restore");
                self.grants = table;
                self.host =
                    DirectHostPairing::new(self.host_key, HOST_NAME.into(), CpaceExchangeFactory);
                let conns: Vec<u64> = self.gates.keys().copied().collect();
                self.gone.extend(conns);
                self.gates.clear();
                self.out.push(json!({ "restart": true }));
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
                // The host's timer runs both the direct invitations and the
                // grant table's expiry.
                let mut actions = self.host.tick(self.now);
                actions.extend(self.host.expire_grants(&mut self.grants, self.now));
                self.host_did(&actions, 0);
            }
            "invite" => {
                // A new invitation, with the same parameters; later ops act
                // on it.
                let created = self
                    .host
                    .create(
                        DirectInvitationParams {
                            role: Role::owner(),
                            authorizing_owner: OwnerRef::from_bytes([0x51; 16]),
                            grant_expires_at: self.grant_expires_at,
                        },
                        self.now,
                        &mut self.host_rng,
                    )
                    .expect("create");
                self.out.push(json!({ "invited": self.invitations.len() }));
                self.invitation = created.invitation;
                self.code = created.code.clone();
                self.invitations.push((created.invitation, created.code));
            }
            "use" => {
                let n = step["invitation"].as_u64().expect("invitation") as usize;
                let (invitation, code) = self.invitations[n].clone();
                self.invitation = invitation;
                self.code = code;
            }
            "gate_timer" => {
                // Every open gate's join-proof timer, `ms` after the gates
                // opened.
                let mono = Millis(step["ms"].as_u64().expect("ms"));
                let conns: Vec<u64> = self.gates.keys().copied().collect();
                for c in conns {
                    if self.gone.contains(&c) {
                        continue;
                    }
                    let gate = self.gates.get_mut(&c).expect("gate");
                    if gate.poll_timeout().is_some_and(|d| d <= mono) {
                        if let Some(code) = gate.on_timeout(mono) {
                            self.out.push(json!({ "proof_timeout": c }));
                            let actions = self.host.on_connection_closed(
                                ConnectionId(c),
                                None,
                                &mut self.grants,
                                self.now,
                            );
                            self.host_closes(c, code);
                            self.host_did(&actions, 0);
                        }
                    }
                }
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
    let expires = seq["grant_expires_at"].as_u64().map(|at| UnixTime(T + at));
    let mut r = Replay::new(listed, expires);
    let mut steps = Vec::new();
    for (i, step) in seq["steps"].as_array().expect("steps").iter().enumerate() {
        let ctx = format!("{name} step {i}");
        r.out.clear();
        r.closed.clear();
        r.held.clear();
        r.paired.clear();
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
        if let Some(list) = step["grants"].as_array() {
            assert_eq!(&r.grant_list(), list, "{ctx}: grants");
        }
        if let Some(list) = step["paired"].as_array() {
            let got: Vec<J> = r.paired.iter().map(|(c, role)| json!([c, role])).collect();
            assert_eq!(&got, list, "{ctx}: paired");
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
        let mut r = Replay::new(
            Some(&json!({ "host": host_draws, "a": joiner_draws })),
            None,
        );
        r.joiner("a");
        let lookup = r.code.lookup();
        r.join_direct("a", 1, lookup, None);
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
        "description": "The host side of Pair with IP (wire.md 10.9) with the real code exchange, behind the host's gate (wire.md 8.1). Each sequence starts with one invitation created at `conventions.time`; each step runs one operation, then its expectations hold. Every message from a joiner passes the host's gate first: let through, it reaches the host machine; otherwise `out` lists the gate's verdict (`gate`: ignore) or the host's close. Ops: dial (a new connection from the joiner: step 2 runs with the gate; a provisional or live grant binds it and the host sends AUTHORIZED {live}), connect (dial unless the connection exists, then the joiner sends JOIN_DIRECT {lookup, name}; `lookup` wrong means another lookup), recover (the same with receipt I and, with `cancel`, the cancel flag), submit (the joiner runs one attempt with the right or a wrong secret: it draws an attempt id and its scalar, sends msg_a, checks msg_b; on a failed check it sends CODE_ABORT {A, pairing_failed} and closes with pairing_failed; otherwise it sends msg_c, unless `lose` is msg_c, when the connection breaks first, or `hold` is msg_c, when msg_c stays on its way), deliver (the held msg_c arrives, unless its connection has closed: then `undelivered`), inject (the joiner sends CODE_EXCHANGE with `attempt` and `payload`), cancel (the joiner sends CODE_ABORT {its last attempt, cancelled}, `lost` with `abort` lost, and closes with cancelled, or breaks the connection with `goaway` lost), drop (conn breaks with no GOAWAY), stream (the joiner opens a stream on conn: the gate's verdict, and on commit the host commits the provisional grant before the frame goes on), allow and decline (the owner answers the joiner's request, allow with `role` when given; `result` ok or the refusal), owner_cancel, tick (the host's timer), old_grant (the joiner already holds an owner grant named \"<joiner> (old)\" made by a ticket pairing whose invitation id has the bytes of I), restart (the host restarts: invitations are gone, the grant table, provisional grants included, is restored, and every connection is gone), abort (the joiner sends CODE_ABORT with `attempt`, `last` for its last attempt, and `code`), invite (the host creates another invitation with the same parameters, drawing from the host's draws; later ops act on it; listed as invited with its index, the first being 0), use (later ops act on invitation `invitation`, by index), gate_timer (every gate's join-proof timer runs `ms` milliseconds after the gates opened; a gate it closes is listed as proof_timeout, then the host's close). A sequence's `invitation` and `code` are those of the invitation current at its end (with invite and use, the last one used). A sequence with `grant_expires_at` (seconds after `conventions.time`) creates its invitation with that grant expiry. tick runs the host's timer for the invitations and then the grant table's expiry (not the gates' join-proof timers, which only gate_timer runs) (committed grants, then provisional ones, each in grant id order; each expired grant's connections close in one grant_closes with grant_revoked), then enrollment_undone for each expired provisional grant, in grant id order, also when no connection was bound to it. A new provisional grant that replaces an older one reports the older one's grant_closes, then its enrollment_undone, before approval_ended. A failed commit reports the grant's other connections' grant_closes first, then enrollment_undone, then the host's close of the connection whose frame asked for it; a cancel reports the other connections' grant_closes, then enrollment_undone, then the cancelling connection's close. A miss hold holds the connection's gate: until the I/O layer closes it, only keepalive, HELLO and GOAWAY pass. On committed, every gate in `bound` drops its provisional state and the cancel exception; the frame that asked for the commit then passes the gate. A joiner's close is listed, and reaches the host, only when the connection is still up. A wrong lookup is `0000` (`0001` if that is the invitation's), a wrong secret `00000000` (`00000001` if that is the code's). `at` sets the time, in seconds after `conventions.time`, before the op. Expectations: `host_status` (`gone` once the host has forgotten the invitation), `host_attempts_left`, `closed` (connections the host closed during the step with a close of its own, with the code, sorted by connection; connections a grant-table change closes are in `grant_closes` instead, listed only when there are any), `held` (JOIN_DIRECTs answered by a miss hold: the I/O layer holds the connection for hold_ms, then closes it with invitation_invalid; that close is not listed), `requests` (answerable requests: joiner, presence, decision), `grants` (every grant in the table: joiner, name, role, and provisional, direct for a committed grant a direct invitation made, or ticket), `paired` (the PAIRED messages the host sent during the step: connection, role). `out` lists in order every control message each side sent (except the two HELLOs), closes, and what the host told its I/O layer and UI: admitted (join-only gate), miss_hold, attempts_left (after each debit; the code stays the same), approval (the prompt, sent again with the same id when its presence or decision changes), approval_ended, enrolled (a provisional grant, with the grant table's id, counting from 0), bound (a recovery connection bound to a direct grant), committed, enrollment_undone, invitation_ended and grant_closes (grant-table events).",
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
    let text = checked_in("direct-host.json").expect("spec/vectors/direct-host.json");
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
