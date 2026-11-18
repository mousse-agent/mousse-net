//! Host and joiner pairing flows, driven message by message.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, SeedableRng};

use super::*;
use crate::control::{AuthorizedState, ControlMessage};
use crate::grants::{GrantEvent, GrantTable, OwnerRef, Role};
use crate::identity::{IdentityPublicKey, SoftwareKey};
use crate::time::UnixTime;
use crate::{ConnectionId, ErrorCode};

const NOW: UnixTime = UnixTime(1_790_000_000);

fn key(seed: u8) -> IdentityPublicKey {
    SoftwareKey::generate(&mut ChaCha20Rng::from_seed([seed; 32])).public_key()
}

fn name(computer: &str) -> JoinerName {
    JoinerName {
        computer: computer.into(),
        profile: None,
    }
}

/// A well-behaved app: every write the flow asks for lands at once, and
/// every reported pin is stored at once. The writes themselves are left out
/// of what it returns.
trait Settle {
    fn settle(&mut self, actions: Vec<JoinerAction>) -> Vec<JoinerAction>;
    fn submit<R: CryptoRng + ?Sized>(
        &mut self,
        code: &PairingCode,
        rng: &mut R,
    ) -> Result<Vec<JoinerAction>, JoinerError>;
    fn exchange_in(&mut self, attempt: AttemptId, payload: &[u8]) -> Vec<JoinerAction>;
    fn authorized(&mut self, state: AuthorizedState) -> Vec<JoinerAction>;
    fn closed(&mut self, code: Option<ErrorCode>) -> Vec<JoinerAction>;
    fn abort(&mut self, attempt: AttemptId) -> Vec<JoinerAction>;
    fn paired(&mut self, host_name: String, role: Role) -> Vec<JoinerAction>;
}

impl<F: CodeExchangeFactory> Settle for JoinerPairing<F> {
    fn settle(&mut self, actions: Vec<JoinerAction>) -> Vec<JoinerAction> {
        let mut queue: std::collections::VecDeque<JoinerAction> = actions.into();
        let mut out = Vec::new();
        while let Some(a) = queue.pop_front() {
            let more = match &a {
                JoinerAction::Persist { .. } => self.on_persisted(),
                JoinerAction::Paired(_) | JoinerAction::AlreadyPaired => {
                    out.push(a);
                    self.on_pin_stored()
                }
                _ => {
                    out.push(a);
                    Vec::new()
                }
            };
            for m in more.into_iter().rev() {
                queue.push_front(m);
            }
        }
        out
    }
    fn submit<R: CryptoRng + ?Sized>(
        &mut self,
        code: &PairingCode,
        rng: &mut R,
    ) -> Result<Vec<JoinerAction>, JoinerError> {
        let a = self.submit_code(code, rng)?;
        Ok(self.settle(a))
    }
    fn exchange_in(&mut self, attempt: AttemptId, payload: &[u8]) -> Vec<JoinerAction> {
        let a = self.on_code_exchange(attempt, payload);
        self.settle(a)
    }
    fn authorized(&mut self, state: AuthorizedState) -> Vec<JoinerAction> {
        let a = self.on_authorized(state);
        self.settle(a)
    }
    fn closed(&mut self, code: Option<ErrorCode>) -> Vec<JoinerAction> {
        let a = self.on_closed(code);
        self.settle(a)
    }
    fn abort(&mut self, attempt: AttemptId) -> Vec<JoinerAction> {
        let a = self.on_code_abort(attempt);
        self.settle(a)
    }
    fn paired(&mut self, host_name: String, role: Role) -> Vec<JoinerAction> {
        let a = self.on_paired(host_name, role);
        self.settle(a)
    }
}

fn exporters(seed: u8) -> SessionExporters {
    SessionExporters {
        join: [seed; 32],
        pair: [seed.wrapping_add(1); 32],
    }
}

struct World<F: CodeExchangeFactory + Clone> {
    rng: ChaCha20Rng,
    host: HostPairing<F>,
    grants: GrantTable,
    factory: F,
}

impl<F: CodeExchangeFactory + Clone> World<F> {
    fn new(factory: F) -> Self {
        Self {
            rng: ChaCha20Rng::from_seed([42; 32]),
            host: HostPairing::new(key(1), "Desk".into(), factory.clone()),
            grants: GrantTable::new(),
            factory,
        }
    }

    fn invite(&mut self, kind: InvitationKind) -> Ticket {
        self.invite_as(kind, Role::owner(), OwnerRef::from_bytes([0x51; 16]))
    }

    /// A ticket from a separate host world, for joiner-only tests.
    fn invite_ticket_only(&self, kind: InvitationKind) -> Ticket {
        let mut other = World::new(self.factory.clone());
        other.invite(kind)
    }

    fn invite_as(&mut self, kind: InvitationKind, role: Role, owner: OwnerRef) -> Ticket {
        let params = InvitationParams {
            kind,
            role,
            authorizing_owner: owner,
            routes: vec!["tcp://192.168.1.20:7443".into()],
            grant_expires_at: None,
        };
        self.host.create(params, NOW, &mut self.rng).unwrap().ticket
    }

    fn joiner(&self, ticket: &Ticket, seed: u8) -> JoinerPairing<F> {
        JoinerPairing::new(
            ticket.clone(),
            arrival_for(ticket),
            key(seed),
            name(&format!("phone {seed}")),
            self.factory.clone(),
            None,
            NOW,
        )
        .unwrap()
    }

    /// Connect a joiner on `conn` and deliver its proof. Returns host actions.
    fn connect(
        &mut self,
        joiner: &mut JoinerPairing<F>,
        conn: u64,
        joiner_seed: u8,
    ) -> Vec<HostAction> {
        let exp = exporters(conn as u8);
        let proof = joiner.on_connected(exp, NOW).unwrap();
        let ControlMessage::JoinProof {
            invitation,
            mac,
            name,
        } = proof
        else {
            panic!("not a proof")
        };
        let actions = self.host.on_join_proof(
            ConnectionId(conn),
            &key(joiner_seed),
            &exp,
            &invitation,
            &mac,
            &name,
            &self.grants,
            NOW,
        );
        if actions.contains(&HostAction::Send {
            conn: ConnectionId(conn),
            message: ControlMessage::Authorized {
                state: AuthorizedState::JoinOnly,
            },
        }) {
            assert!(joiner.authorized(AuthorizedState::JoinOnly).is_empty());
        }
        actions
    }

    /// Pass messages between joiner and host until neither has more to say.
    fn exchange(
        &mut self,
        joiner: &mut JoinerPairing<F>,
        conn: u64,
        first: Vec<JoinerAction>,
    ) -> (Vec<HostAction>, Vec<JoinerAction>) {
        let mut host_log = Vec::new();
        let mut joiner_log = Vec::new();
        let mut to_host: Vec<ControlMessage> = Vec::new();
        for a in first {
            match a {
                JoinerAction::Send(m) => to_host.push(m),
                other => joiner_log.push(other),
            }
        }
        while !to_host.is_empty() {
            let mut to_joiner = Vec::new();
            for m in to_host.drain(..) {
                let actions = match m {
                    ControlMessage::CodeExchange { attempt, payload } => {
                        self.host.on_code_exchange(
                            ConnectionId(conn),
                            attempt,
                            &payload,
                            &mut self.grants,
                            NOW,
                            &mut self.rng,
                        )
                    }
                    ControlMessage::CodeAbort { attempt, .. } => {
                        self.host.on_code_abort(ConnectionId(conn), attempt)
                    }
                    other => panic!("unexpected {other:?}"),
                };
                for a in actions {
                    if let HostAction::Send { message, .. } = &a {
                        to_joiner.push(message.clone());
                    }
                    host_log.push(a);
                }
            }
            for m in to_joiner {
                let actions = match m {
                    ControlMessage::CodeExchange { attempt, payload } => {
                        joiner.exchange_in(attempt, &payload)
                    }
                    ControlMessage::CodeAbort { attempt, .. } => joiner.abort(attempt),
                    ControlMessage::Paired { host_name, role } => joiner.paired(host_name, role),
                    other => panic!("unexpected {other:?}"),
                };
                for a in actions {
                    match a {
                        JoinerAction::Send(m) => to_host.push(m),
                        other => joiner_log.push(other),
                    }
                }
            }
        }
        (host_log, joiner_log)
    }
}

fn world() -> World<CpaceExchangeFactory> {
    World::new(CpaceExchangeFactory)
}

/// How a well-behaved app gets each kind: in person by its own scanner,
/// send link as a link.
fn arrival_for(ticket: &Ticket) -> Arrival {
    match ticket.kind {
        InvitationKind::InPerson => Arrival::InAppScan,
        InvitationKind::SendLink => Arrival::Link,
    }
}

fn new_joiner(
    ticket: Ticket,
    seed: u8,
    stored: Option<&JoinerRecord>,
) -> Result<JoinerPairing<CpaceExchangeFactory>, JoinerError> {
    let arrival = arrival_for(&ticket);
    JoinerPairing::new(
        ticket,
        arrival,
        key(seed),
        name("phone"),
        CpaceExchangeFactory,
        stored,
        NOW,
    )
}

fn shown_codes(actions: &[HostAction]) -> Vec<PairingCode> {
    actions
        .iter()
        .filter_map(|a| match a {
            HostAction::ShowCode { code, .. } => Some(code.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn in_person_pairing_needs_a_proof_and_one_tap() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::InPerson);
    let mut j = w.joiner(&ticket, 2);
    assert_eq!(j.expected_host(), &key(1));
    let actions = w.connect(&mut j, 10, 2);
    assert!(actions.contains(&HostAction::AdmittedJoinOnly {
        conn: ConnectionId(10),
        invitation: ticket.invitation
    }));
    assert!(actions
        .iter()
        .any(|a| matches!(a, HostAction::AskApproval { .. })));
    assert_eq!(j.state(), JoinerState::AwaitingApproval);

    let actions = w
        .host
        .approve(&ticket.invitation, ConnectionId(10), &mut w.grants, NOW)
        .unwrap();
    let grant = actions
        .iter()
        .find_map(|a| match a {
            HostAction::Enrolled { grant, .. } => Some(*grant),
            _ => None,
        })
        .unwrap();
    assert_eq!(w.grants.binding(ConnectionId(10)), Some(grant));
    assert_eq!(
        w.grants.live_grant(&key(2), NOW).unwrap().role,
        Role::owner()
    );
    assert_eq!(
        w.host.status(&ticket.invitation),
        Some(InvitationStatus::Consumed { grant })
    );

    let paired = j.paired("Desk".into(), Role::owner());
    assert!(matches!(&paired[..], [JoinerAction::Paired(p)] if p.identity == key(1)));
    // The invitation is spent: approving again is refused.
    assert_eq!(
        w.host
            .approve(&ticket.invitation, ConnectionId(10), &mut w.grants, NOW),
        Err(HostPairingError::NotOpen)
    );
}

/// Current behaviour, kept on purpose: pairing an identity that already
/// holds a grant on this endpoint replaces the grant, so the newer role and
/// authorizing owner win and the old grant's channels close. An endpoint has
/// one owner profile, so the authorizing owner normally stays the same.
#[test]
fn re_pairing_the_same_identity_replaces_role_and_authorizing_owner() {
    let mut w = world();
    let first_owner = OwnerRef::from_bytes([0x51; 16]);
    let second_owner = OwnerRef::from_bytes([0x52; 16]);
    let client = Role::new(Role::CLIENT).unwrap();

    let ticket = w.invite_as(InvitationKind::InPerson, Role::owner(), first_owner);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    w.host
        .approve(&ticket.invitation, ConnectionId(10), &mut w.grants, NOW)
        .unwrap();
    let first = w.grants.live_grant(&key(2), NOW).unwrap().id;

    let ticket = w.invite_as(InvitationKind::InPerson, client.clone(), second_owner);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 11, 2);
    let actions = w
        .host
        .approve(&ticket.invitation, ConnectionId(11), &mut w.grants, NOW)
        .unwrap();

    let grant = w.grants.live_grant(&key(2), NOW).unwrap();
    assert_ne!(grant.id, first);
    assert_eq!(grant.role, client);
    assert_eq!(grant.authorizing_owner, second_owner);
    assert_eq!(w.grants.grants().count(), 1);
    assert_eq!(w.grants.get(first), None);
    assert_eq!(w.grants.binding(ConnectionId(10)), None);
    assert_eq!(w.grants.binding(ConnectionId(11)), Some(grant.id));
    assert!(
        actions.contains(&HostAction::Grant(GrantEvent::CloseChannels {
            grant: first,
            channels: vec![ConnectionId(10)],
            code: ErrorCode::GrantRevoked
        }))
    );
}

#[test]
fn proof_with_a_wrong_secret_or_another_session_is_refused() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::InPerson);
    let mut forged = ticket.clone();
    forged.secret = TicketSecret::from_bytes([0; 16]);
    let mut j = new_joiner(forged, 2, None).unwrap();
    let actions = w.connect(&mut j, 10, 2);
    assert_eq!(
        actions,
        vec![HostAction::Close {
            conn: ConnectionId(10),
            code: ErrorCode::InvitationInvalid
        }]
    );

    // A proof made for one TLS session does not work on another.
    let mut j = w.joiner(&ticket, 2);
    let proof = j.on_connected(exporters(1), NOW).unwrap();
    let ControlMessage::JoinProof {
        invitation,
        mac,
        name,
    } = proof
    else {
        panic!()
    };
    let actions = w.host.on_join_proof(
        ConnectionId(11),
        &key(2),
        &exporters(2),
        &invitation,
        &mac,
        &name,
        &w.grants,
        NOW,
    );
    assert_eq!(
        actions,
        vec![HostAction::Close {
            conn: ConnectionId(11),
            code: ErrorCode::InvitationInvalid
        }]
    );
    // Nor for another identity on the same session.
    let actions = w.host.on_join_proof(
        ConnectionId(12),
        &key(3),
        &exporters(1),
        &invitation,
        &mac,
        &name,
        &w.grants,
        NOW,
    );
    assert_eq!(
        actions,
        vec![HostAction::Close {
            conn: ConnectionId(12),
            code: ErrorCode::InvitationInvalid
        }]
    );
}

#[test]
fn one_enrollment_per_invitation_dismisses_other_joiners() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::InPerson);
    let mut a = w.joiner(&ticket, 2);
    let mut b = w.joiner(&ticket, 3);
    w.connect(&mut a, 10, 2);
    w.connect(&mut b, 11, 3);
    let actions = w
        .host
        .approve(&ticket.invitation, ConnectionId(11), &mut w.grants, NOW)
        .unwrap();
    assert!(actions.contains(&HostAction::Close {
        conn: ConnectionId(10),
        code: ErrorCode::InvitationInvalid
    }));
    assert!(w.grants.live_grant(&key(3), NOW).is_some());
    assert!(w.grants.live_grant(&key(2), NOW).is_none());
    assert_eq!(
        w.host
            .approve(&ticket.invitation, ConnectionId(10), &mut w.grants, NOW),
        Err(HostPairingError::NotOpen)
    );
}

#[test]
fn send_link_pairs_after_both_confirmations() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    let actions = w.connect(&mut j, 10, 2);
    let code = actions
        .iter()
        .find_map(|a| match a {
            HostAction::ShowCode { code, .. } => Some(code.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(j.state(), JoinerState::AwaitingCode);
    let first = j
        .submit(&code, &mut ChaCha20Rng::from_seed([5; 32]))
        .unwrap();
    let (host_log, joiner_log) = w.exchange(&mut j, 10, first);
    assert!(host_log
        .iter()
        .any(|a| matches!(a, HostAction::Enrolled { .. })));
    assert!(matches!(&joiner_log[..], [JoinerAction::Paired(_)]));
    assert_eq!(j.state(), JoinerState::Paired);
    assert_eq!(w.host.attempts_left(&ticket.invitation), Some(2));
}

#[test]
fn three_wrong_codes_end_the_invitation_on_both_sides() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    let wrong = PairingCode::parse("000000").unwrap();
    assert_ne!(w.host.code(&ticket.invitation), Some(&wrong));
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    for left in [2u8, 1] {
        let first = j.submit(&wrong, &mut rng).unwrap();
        let (_, joiner_log) = w.exchange(&mut j, 10, first);
        assert_eq!(
            joiner_log,
            vec![JoinerAction::CodeRejected {
                attempts_left: left
            }]
        );
        assert_eq!(w.host.attempts_left(&ticket.invitation), Some(left));
        assert_eq!(
            w.host.status(&ticket.invitation),
            Some(InvitationStatus::Open)
        );
    }
    let first = j.submit(&wrong, &mut rng).unwrap();
    let (host_log, joiner_log) = w.exchange(&mut j, 10, first);
    assert_eq!(
        joiner_log,
        vec![JoinerAction::Failed(ErrorCode::AttemptsExhausted)]
    );
    assert!(host_log.contains(&HostAction::Close {
        conn: ConnectionId(10),
        code: ErrorCode::AttemptsExhausted
    }));
    assert_eq!(
        w.host.status(&ticket.invitation),
        Some(InvitationStatus::Ended(ErrorCode::AttemptsExhausted))
    );
    assert_eq!(j.submit(&wrong, &mut rng), Err(JoinerError::WrongState));
}

impl World<CpaceExchangeFactory> {
    /// Run one attempt with `code` on `conn` up to the joiner's confirmation
    /// (`msg_c`), which is returned undelivered.
    fn attempt_until_confirmation(
        &mut self,
        j: &mut JoinerPairing<CpaceExchangeFactory>,
        conn: u64,
        code: &PairingCode,
        rng: &mut ChaCha20Rng,
    ) -> (AttemptId, Vec<u8>) {
        let first = j.submit(code, rng).unwrap();
        let [JoinerAction::Send(ControlMessage::CodeExchange { attempt, payload })] = &first[..]
        else {
            panic!("no msg_a")
        };
        let reply = self.host.on_code_exchange(
            ConnectionId(conn),
            *attempt,
            payload,
            &mut self.grants,
            NOW,
            &mut self.rng,
        );
        let msg_b = reply
            .iter()
            .find_map(|a| match a {
                HostAction::Send {
                    message: ControlMessage::CodeExchange { payload, .. },
                    ..
                } => Some(payload.clone()),
                _ => None,
            })
            .expect("msg_b");
        let out = j.exchange_in(*attempt, &msg_b);
        let [JoinerAction::Send(ControlMessage::CodeExchange { payload: msg_c, .. })] = &out[..]
        else {
            panic!("no msg_c")
        };
        assert_eq!(j.state(), JoinerState::AwaitingPaired);
        (*attempt, msg_c.clone())
    }
}

/// The third attempt succeeds and the host enrolls the joiner, but `PAIRED`
/// is lost with the connection. The joiner has no attempts left, yet it
/// reconnects, even after its ticket ran out. Step 2 says live, and the
/// grant's enrollment receipt names this invitation, so the host answers
/// the proof with `PAIRED` again: paired, with the invitation's role.
#[test]
fn a_lost_paired_on_the_last_attempt_is_learned_on_reconnect() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    let wrong = PairingCode::parse("000000").unwrap();
    for _ in 0..2 {
        let first = j.submit(&wrong, &mut rng).unwrap();
        w.exchange(&mut j, 10, first);
    }
    let right = w.host.code(&ticket.invitation).unwrap().clone();
    let (attempt, msg_c) = w.attempt_until_confirmation(&mut j, 10, &right, &mut rng);
    let enrolled = w.host.on_code_exchange(
        ConnectionId(10),
        attempt,
        &msg_c,
        &mut w.grants,
        NOW,
        &mut w.rng,
    );
    assert!(enrolled
        .iter()
        .any(|a| matches!(a, HostAction::Enrolled { .. })));
    // PAIRED never arrives.
    w.host.on_connection_closed(ConnectionId(10));
    assert_eq!(j.closed(None), vec![]);
    assert_eq!(j.attempts_left(), 0);
    assert!(j.outcome_pending());
    assert_eq!(j.state(), JoinerState::Connecting);

    let later = NOW.plus(1_300);
    let ControlMessage::JoinProof { mac, name, .. } = j.on_connected(exporters(11), later).unwrap()
    else {
        panic!("not a proof")
    };
    let mut grants = w.grants.clone();
    let mut gate = crate::authz::ConnectionGate::open(
        ConnectionId(11),
        key(2),
        &mut grants,
        later,
        crate::time::Millis(0),
    );
    assert!(gate.check(crate::authz::Traffic::JoinProof) == crate::authz::Verdict::Allow);
    // Step 2's notice, then the answer to the proof.
    assert_eq!(j.authorized(AuthorizedState::Live), vec![]);
    let answer = w.host.on_join_proof(
        ConnectionId(11),
        &key(2),
        &exporters(11),
        &ticket.invitation,
        &mac,
        &name,
        &grants,
        later,
    );
    let [HostAction::Send {
        message: ControlMessage::Paired { host_name, role },
        ..
    }] = &answer[..]
    else {
        panic!("expected PAIRED as the answer, got {answer:?}")
    };
    let out = j.on_paired(host_name.clone(), role.clone());
    assert!(matches!(&out[..], [JoinerAction::Paired(p)] if p.role == Role::owner()));
    assert_eq!(j.state(), JoinerState::Paired);
    // The pending mark goes only once the pin is stored.
    assert!(j.outcome_pending());
    let clear = j.on_pin_stored();
    assert!(matches!(
        &clear[..],
        [JoinerAction::Persist { record, .. }] if !record.outcome_pending
    ));
    j.on_persisted();
    assert!(!j.outcome_pending());
}

/// The joiner's confirmation is lost with the connection, so the host never
/// enrolled it. On reconnect the host admits it join-only again, and a
/// joiner with no attempts left ends the flow instead of waiting for a code.
#[test]
fn a_lost_confirmation_on_the_last_attempt_ends_after_reconnect() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    let any = PairingCode::parse("111111").unwrap();
    // Two attempts are lost before they reach the host.
    for round in 0..2u8 {
        j.on_connected(exporters(20 + round), NOW).unwrap();
        j.authorized(AuthorizedState::JoinOnly);
        j.submit(&any, &mut rng).unwrap();
        j.closed(None);
    }
    w.connect(&mut j, 10, 2);
    let right = w.host.code(&ticket.invitation).unwrap().clone();
    w.attempt_until_confirmation(&mut j, 10, &right, &mut rng);
    w.host.on_connection_closed(ConnectionId(10));
    j.closed(None);
    assert!(j.outcome_pending());
    assert_eq!(w.host.attempts_left(&ticket.invitation), Some(2));

    let ControlMessage::JoinProof { mac, name, .. } = j.on_connected(exporters(11), NOW).unwrap()
    else {
        panic!("not a proof")
    };
    let actions = w.host.on_join_proof(
        ConnectionId(11),
        &key(2),
        &exporters(11),
        &ticket.invitation,
        &mac,
        &name,
        &w.grants,
        NOW,
    );
    assert!(actions.contains(&HostAction::AdmittedJoinOnly {
        conn: ConnectionId(11),
        invitation: ticket.invitation
    }));
    assert_eq!(
        j.authorized(AuthorizedState::JoinOnly),
        vec![JoinerAction::Failed(ErrorCode::AttemptsExhausted)]
    );
    assert!(w.grants.live_grant(&key(2), NOW).is_none());
}

#[test]
fn each_attempt_uses_a_fresh_code() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    let first_code = shown_codes(&w.connect(&mut j, 10, 2)).remove(0);
    assert_eq!(w.host.code(&ticket.invitation), Some(&first_code));
    let mut rng = ChaCha20Rng::from_seed([5; 32]);

    // A wrong guess: the attempt fails and a new code is shown.
    let wrong = PairingCode::parse("000000").unwrap();
    assert_ne!(wrong, first_code);
    let first = j.submit(&wrong, &mut rng).unwrap();
    let (host_log, _) = w.exchange(&mut j, 10, first);
    let second_code = shown_codes(&host_log).remove(0);
    assert_ne!(second_code, first_code);
    assert_eq!(w.host.code(&ticket.invitation), Some(&second_code));

    // The code shown before is no longer accepted.
    let first = j.submit(&first_code, &mut rng).unwrap();
    let (host_log, joiner_log) = w.exchange(&mut j, 10, first);
    assert_eq!(
        joiner_log,
        vec![JoinerAction::CodeRejected { attempts_left: 1 }]
    );
    let third_code = shown_codes(&host_log).remove(0);

    // The last attempt shows no further code, and the current one works.
    let first = j.submit(&third_code, &mut rng).unwrap();
    let (host_log, joiner_log) = w.exchange(&mut j, 10, first);
    assert!(shown_codes(&host_log).is_empty());
    assert_eq!(w.host.code(&ticket.invitation), None);
    assert!(matches!(&joiner_log[..], [JoinerAction::Paired(_)]));
}

#[test]
fn attempts_are_counted_across_routes_on_the_host() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let wrong = PairingCode::parse("000000").unwrap();
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    // Three different joiner flows on three connections share the host's 3.
    for (i, conn) in [10u64, 11, 12].into_iter().enumerate() {
        let mut j = w.joiner(&ticket, 2);
        w.connect(&mut j, conn, 2);
        let first = j.submit(&wrong, &mut rng).unwrap();
        w.exchange(&mut j, conn, first);
        assert_eq!(w.host.attempts_left(&ticket.invitation), Some(2 - i as u8));
    }
    assert_eq!(
        w.host.status(&ticket.invitation),
        Some(InvitationStatus::Ended(ErrorCode::AttemptsExhausted))
    );
}

fn is_abort(actions: &[HostAction]) -> bool {
    matches!(
        actions,
        [HostAction::Send {
            message: ControlMessage::CodeAbort {
                code: ErrorCode::PairingFailed,
                ..
            },
            ..
        }]
    )
}

#[test]
fn a_repeated_message_fails_the_attempt_and_is_not_a_new_debit() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    let code = w.host.code(&ticket.invitation).unwrap().clone();
    let first = j
        .submit(&code, &mut ChaCha20Rng::from_seed([5; 32]))
        .unwrap();
    let [JoinerAction::Send(ControlMessage::CodeExchange { attempt, payload })] = &first[..] else {
        panic!()
    };
    let deliver = |w: &mut World<CpaceExchangeFactory>, conn: u64, payload: &[u8]| {
        w.host.on_code_exchange(
            ConnectionId(conn),
            *attempt,
            payload,
            &mut w.grants,
            NOW,
            &mut w.rng,
        )
    };
    let reply = deliver(&mut w, 10, payload);
    assert_eq!(shown_codes(&reply).len(), 1);
    assert_eq!(w.host.attempts_left(&ticket.invitation), Some(2));
    // The same message again does not fit the next step: the attempt fails,
    // with no new debit and no new code.
    assert!(is_abort(&deliver(&mut w, 10, payload)));
    assert_eq!(w.host.attempts_left(&ticket.invitation), Some(2));
    // Anything more for the ended attempt gets an abort and no work.
    assert!(is_abort(&deliver(&mut w, 10, payload)));
    assert_eq!(w.host.attempts_left(&ticket.invitation), Some(2));

    // The same attempt id on another connection is a new attempt there:
    // debited first. Its binding holds the other session's exporter, so it
    // can never succeed.
    let mut j2 = w.joiner(&ticket, 2);
    w.connect(&mut j2, 11, 2);
    deliver(&mut w, 11, payload);
    assert_eq!(w.host.attempts_left(&ticket.invitation), Some(1));
}

#[test]
fn a_repeated_host_message_fails_the_joiners_attempt() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    let code = PairingCode::parse("000000").unwrap();
    let first = j
        .submit(&code, &mut ChaCha20Rng::from_seed([5; 32]))
        .unwrap();
    let [JoinerAction::Send(ControlMessage::CodeExchange { attempt, .. })] = &first[..] else {
        panic!()
    };
    // Some message the joiner did not expect at this step, twice.
    let junk = vec![0u8; 8];
    let actions = j.exchange_in(*attempt, &junk);
    assert!(
        actions.contains(&JoinerAction::Send(ControlMessage::CodeAbort {
            attempt: *attempt,
            code: ErrorCode::PairingFailed
        }))
    );
    assert_eq!(j.state(), JoinerState::AwaitingCode);
    assert_eq!(j.exchange_in(*attempt, &junk), vec![]);
    assert_eq!(j.attempts_left(), 2);
}

#[test]
fn an_in_person_ticket_is_believed_only_from_the_in_app_scanner() {
    let w = world();
    let ticket = w.invite_ticket_only(InvitationKind::InPerson);
    // A link covers URL opens, pastes, browsers and the system camera.
    let r = JoinerPairing::new(
        ticket.clone(),
        Arrival::Link,
        key(2),
        name("phone"),
        CpaceExchangeFactory,
        None,
        NOW,
    );
    assert_eq!(r.err(), Some(JoinerError::InPersonFromLink));
    assert_eq!(
        JoinerError::InPersonFromLink.code(),
        Some(ErrorCode::PairingFailed)
    );
    assert!(new_joiner(ticket, 2, None).is_ok());
    // A send link may arrive either way.
    let link = w.invite_ticket_only(InvitationKind::SendLink);
    for arrival in [Arrival::Link, Arrival::InAppScan] {
        assert!(JoinerPairing::new(
            link.clone(),
            arrival,
            key(2),
            name("phone"),
            CpaceExchangeFactory,
            None,
            NOW,
        )
        .is_ok());
    }
}

#[test]
fn a_device_never_pairs_with_itself() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::InPerson);
    // The joiner refuses its own host's ticket before dialing.
    assert_eq!(
        new_joiner(ticket.clone(), 1, None).err(),
        Some(JoinerError::OwnTicket)
    );
    // A host closes a proof made by its own identity.
    let exp = exporters(10);
    let mac = join_proof_mac(
        &ticket.secret,
        &ticket.invitation,
        &key(1),
        &key(1),
        &exp.join,
    );
    assert_eq!(
        w.host.on_join_proof(
            ConnectionId(10),
            &key(1),
            &exp,
            &ticket.invitation,
            &mac,
            "me",
            &w.grants,
            NOW
        ),
        vec![HostAction::Close {
            conn: ConnectionId(10),
            code: ErrorCode::NotAuthorized
        }]
    );
    assert_eq!(
        w.host.status(&ticket.invitation),
        Some(InvitationStatus::Open)
    );
}

#[test]
fn the_joiner_record_keeps_attempts_and_a_pending_outcome() {
    let w = world();
    let ticket = w.invite_ticket_only(InvitationKind::SendLink);
    let mut j = new_joiner(ticket.clone(), 2, None).unwrap();
    j.on_connected(exporters(1), NOW).unwrap();
    j.authorized(AuthorizedState::JoinOnly);
    let code = PairingCode::parse("111111").unwrap();
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    j.submit(&code, &mut rng).unwrap();
    let record = j.record();
    assert_eq!(record.attempts_left, 2);
    let bytes = record.to_bytes();
    assert_eq!(JoinerRecord::from_bytes(&bytes), Ok(record));

    // Reopening the link with the record keeps the count.
    let again = new_joiner(ticket.clone(), 2, Some(&record)).unwrap();
    assert_eq!(again.attempts_left(), 2);

    // No attempts left and nothing pending: refused at once.
    let spent = JoinerRecord {
        attempts_left: 0,
        ..record
    };
    assert_eq!(
        new_joiner(ticket.clone(), 2, Some(&spent)).err(),
        Some(JoinerError::AttemptsExhausted)
    );
    // A pending outcome is still learned, even after the ticket expired.
    let pending = JoinerRecord {
        outcome_pending: true,
        ..spent
    };
    let late = JoinerPairing::new(
        ticket.clone(),
        Arrival::Link,
        key(2),
        name("phone"),
        CpaceExchangeFactory,
        Some(&pending),
        ticket.expires_at.plus(60),
    )
    .unwrap();
    assert!(late.outcome_pending());

    // A record for another ticket, or bytes that are not a record.
    let other = JoinerRecord {
        ticket_hash: [9; 32],
        ..record
    };
    assert_eq!(
        new_joiner(ticket, 2, Some(&other)).err(),
        Some(JoinerError::BadRecord)
    );
    assert_eq!(
        JoinerRecord::from_bytes(&bytes[..bytes.len() - 1]),
        Err(JoinerError::BadRecord)
    );
    let mut too_many = record;
    too_many.attempts_left = 4;
    assert_eq!(
        JoinerRecord::from_bytes(&too_many.to_bytes()),
        Err(JoinerError::BadRecord)
    );
}

#[test]
fn a_granted_device_can_pair_again_by_link() {
    use crate::authz::{ConnectionGate, GateState, Traffic, Verdict};
    use crate::grants::NewGrant;
    use crate::time::Millis;

    let mut w = world();
    let (old, _) = w
        .grants
        .add(
            NewGrant {
                identity: key(2),
                name: "old phone".into(),
                role: Role::owner(),
                authorizing_owner: OwnerRef::from_bytes([0x51; 16]),
                expires_at: None,
                enrolled_by: None,
            },
            NOW,
        )
        .unwrap();
    // Another connection of the same device, live under the old grant.
    let other = ConnectionGate::open(ConnectionId(9), key(2), &mut w.grants, NOW, Millis(0));
    assert!(matches!(other.state(), GateState::Live { .. }));

    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    let mut gate = ConnectionGate::open(ConnectionId(10), key(2), &mut w.grants, NOW, Millis(0));
    assert_eq!(gate.state(), &GateState::Live { grant: old });
    // Step 2's notice reaches the joiner: it waits for the answer.
    let exp = exporters(10);
    let proof = j.on_connected(exp, NOW).unwrap();
    assert_eq!(j.authorized(AuthorizedState::Live), vec![]);
    // The host reads the proof on the live connection and answers it.
    assert_eq!(gate.check(Traffic::JoinProof), Verdict::Allow);
    let ControlMessage::JoinProof {
        invitation,
        mac,
        name,
    } = proof
    else {
        panic!()
    };
    let actions = w.host.on_join_proof(
        ConnectionId(10),
        &key(2),
        &exp,
        &invitation,
        &mac,
        &name,
        &w.grants,
        NOW,
    );
    assert!(actions.contains(&HostAction::Send {
        conn: ConnectionId(10),
        message: ControlMessage::Authorized {
            state: AuthorizedState::JoinOnly
        }
    }));
    assert!(!actions
        .iter()
        .any(|a| matches!(a, HostAction::AskApproval { .. })));
    gate.admit_join_only(invitation);
    assert!(matches!(gate.state(), GateState::JoinOnly { .. }));
    // A second proof on the connection is a protocol error.
    assert_eq!(
        gate.check(Traffic::JoinProof),
        Verdict::Close(ErrorCode::ProtocolError)
    );
    let mut gate = ConnectionGate::open(
        ConnectionId(10),
        key(2),
        &mut GrantTable::new(),
        NOW,
        Millis(0),
    );
    gate.admit_join_only(invitation);

    assert_eq!(j.authorized(AuthorizedState::JoinOnly), vec![]);
    assert_eq!(j.state(), JoinerState::AwaitingCode);
    let code = w.host.code(&ticket.invitation).unwrap().clone();
    let first = j
        .submit(&code, &mut ChaCha20Rng::from_seed([5; 32]))
        .unwrap();
    let (host_log, joiner_log) = w.exchange(&mut j, 10, first);
    assert!(matches!(&joiner_log[..], [JoinerAction::Paired(_)]));
    // The new grant replaced the old one: the other connection closes,
    // this one is bound to the new grant.
    let new = w.grants.live_grant(&key(2), NOW).unwrap();
    assert_ne!(new.id, old);
    assert_eq!(new.name, "phone 2");
    assert_eq!(w.grants.binding(ConnectionId(10)), Some(new.id));
    assert!(host_log.iter().any(|a| matches!(
        a,
        HostAction::Grant(GrantEvent::CloseChannels { channels, .. })
            if channels == &vec![ConnectionId(9)]
    )));
}

#[test]
fn a_proof_on_a_live_connection_that_opens_nothing_is_answered_live() {
    use crate::grants::NewGrant;
    let mut w = world();
    w.grants
        .add(
            NewGrant {
                identity: key(2),
                name: "phone".into(),
                role: Role::owner(),
                authorizing_owner: OwnerRef::from_bytes([0x51; 16]),
                expires_at: None,
                enrolled_by: None,
            },
            NOW,
        )
        .unwrap();
    let grant = w.grants.live_grant(&key(2), NOW).unwrap().id;
    w.grants.bind(ConnectionId(10), grant, NOW).unwrap();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut forged = ticket.clone();
    forged.secret = TicketSecret::from_bytes([0; 16]);
    let mut j = new_joiner(forged, 2, None).unwrap();
    let actions = w.connect(&mut j, 10, 2);
    assert_eq!(
        actions,
        vec![HostAction::Send {
            conn: ConnectionId(10),
            message: ControlMessage::Authorized {
                state: AuthorizedState::Live
            }
        }]
    );
    assert_eq!(w.grants.binding(ConnectionId(10)), Some(grant));
}

#[test]
fn a_send_link_never_asks_for_approval() {
    // The last attempt is running, so no code is shown; another joiner
    // arriving then is not asked about.
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let wrong = PairingCode::parse("000000").unwrap();
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    for _ in 0..2 {
        let first = j.submit(&wrong, &mut rng).unwrap();
        w.exchange(&mut j, 10, first);
    }
    let first = j.submit(&wrong, &mut rng).unwrap();
    let [JoinerAction::Send(ControlMessage::CodeExchange { attempt, payload })] = &first[..] else {
        panic!()
    };
    w.host.on_code_exchange(
        ConnectionId(10),
        *attempt,
        payload,
        &mut w.grants,
        NOW,
        &mut w.rng,
    );
    assert_eq!(w.host.code(&ticket.invitation), None);
    let mut late = w.joiner(&ticket, 3);
    let actions = w.connect(&mut late, 11, 3);
    assert!(actions.contains(&HostAction::AdmittedJoinOnly {
        conn: ConnectionId(11),
        invitation: ticket.invitation
    }));
    assert!(!actions.iter().any(|a| matches!(
        a,
        HostAction::AskApproval { .. } | HostAction::ShowCode { .. }
    )));
}

/// A factory whose exchanges fail on their first step, to show the debit
/// comes first.
#[derive(Clone)]
struct FailingFactory;
struct FailingExchange;
impl CodeExchange for FailingExchange {
    fn step(&mut self, _: Option<&[u8]>) -> Result<ExchangeStep, ExchangeError> {
        Err(ExchangeError::Malformed)
    }
}
impl CodeExchangeFactory for FailingFactory {
    type Exchange = FailingExchange;
    fn start<R: CryptoRng + ?Sized>(
        &self,
        _: ExchangeRole,
        _: &PairingCode,
        _: &BindingTranscript,
        _: &[u8; SID_LEN],
        _: &mut R,
    ) -> FailingExchange {
        FailingExchange
    }
}

#[test]
fn both_sides_debit_before_exchange_work_even_when_it_fails_at_once() {
    let mut w = World::new(FailingFactory);
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    let code = PairingCode::parse("123456").unwrap();
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    let actions = j.submit(&code, &mut rng).unwrap();
    assert_eq!(j.attempts_left(), 2);
    assert!(actions.contains(&JoinerAction::CodeRejected { attempts_left: 2 }));
    // Host side: the first message of a new attempt debits, then fails.
    w.host.on_code_exchange(
        ConnectionId(10),
        AttemptId([7; 16]),
        b"x",
        &mut w.grants,
        NOW,
        &mut w.rng,
    );
    assert_eq!(w.host.attempts_left(&ticket.invitation), Some(2));
}

#[test]
fn an_abandoned_attempt_keeps_its_debit() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    let code = w.host.code(&ticket.invitation).unwrap().clone();
    let first = j
        .submit(&code, &mut ChaCha20Rng::from_seed([5; 32]))
        .unwrap();
    let [JoinerAction::Send(ControlMessage::CodeExchange { attempt, payload })] = &first[..] else {
        panic!()
    };
    w.host.on_code_exchange(
        ConnectionId(10),
        *attempt,
        payload,
        &mut w.grants,
        NOW,
        &mut w.rng,
    );
    // The link drops mid-attempt.
    w.host.on_connection_closed(ConnectionId(10));
    j.closed(None);
    assert_eq!(w.host.attempts_left(&ticket.invitation), Some(2));
    assert_eq!(j.attempts_left(), 2);
    assert_eq!(j.state(), JoinerState::Connecting);
}

#[test]
fn a_fake_host_can_use_up_the_joiners_attempts_but_no_more() {
    // The joiner talks to a "host" that always rejects: its local cap holds.
    let ticket = world().invite(InvitationKind::SendLink);
    let mut j = new_joiner(ticket, 2, None).unwrap();
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    let code = PairingCode::parse("111111").unwrap();
    for round in 0..3u8 {
        j.on_connected(exporters(round), NOW).unwrap();
        j.authorized(AuthorizedState::JoinOnly);
        let first = j.submit(&code, &mut rng).unwrap();
        let [JoinerAction::Send(ControlMessage::CodeExchange { attempt, .. })] = &first[..] else {
            panic!()
        };
        j.abort(*attempt);
        if round < 2 {
            j.closed(None);
        }
    }
    assert_eq!(j.state(), JoinerState::Failed(ErrorCode::AttemptsExhausted));
    assert_eq!(
        j.on_connected(exporters(9), NOW),
        Err(JoinerError::WrongState)
    );
}

#[test]
fn send_link_joiner_refuses_paired_without_host_confirmation() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    assert_eq!(
        j.paired("Desk".into(), Role::owner()),
        vec![JoinerAction::Failed(ErrorCode::ProtocolError)]
    );
}

/// A swapped send link names the far end's key, so step 1 passes against
/// it. Its `AUTHORIZED {live}` must not end the flow "already paired" (and
/// get that key pinned) unless this device pinned the host before.
#[test]
fn send_link_already_paired_needs_an_earlier_pin() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);

    // Each joiner gets step 2's notice first, then the answer.
    let mut fresh = w.joiner(&ticket, 2);
    fresh.on_connected(exporters(10), NOW).unwrap();
    assert_eq!(fresh.authorized(AuthorizedState::Live), vec![]);
    assert_eq!(
        fresh.authorized(AuthorizedState::Live),
        vec![JoinerAction::Failed(ErrorCode::PairingFailed)]
    );
    assert_eq!(fresh.state(), JoinerState::Failed(ErrorCode::PairingFailed));

    let mut known = w.joiner(&ticket, 2);
    known.set_host_pinned(true);
    known.on_connected(exporters(11), NOW).unwrap();
    assert_eq!(known.authorized(AuthorizedState::Live), vec![]);
    assert_eq!(
        known.authorized(AuthorizedState::Live),
        vec![JoinerAction::AlreadyPaired]
    );

    // In person, the ticket came from the owner's own screen through the
    // app's scanner: unchanged.
    let in_person = w.invite(InvitationKind::InPerson);
    let mut j = w.joiner(&in_person, 2);
    j.on_connected(exporters(12), NOW).unwrap();
    assert_eq!(j.authorized(AuthorizedState::Live), vec![]);
    assert_eq!(
        j.authorized(AuthorizedState::Live),
        vec![JoinerAction::AlreadyPaired]
    );
}

#[test]
fn expired_invitations_close_their_joiners_and_refuse_new_ones() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::InPerson);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    assert!(w.host.tick(ticket.expires_at.minus(1)).is_empty());
    let actions = w.host.tick(ticket.expires_at);
    assert!(actions.contains(&HostAction::Close {
        conn: ConnectionId(10),
        code: ErrorCode::InvitationInvalid
    }));
    assert_eq!(
        w.host.status(&ticket.invitation),
        Some(InvitationStatus::Ended(ErrorCode::InvitationInvalid))
    );
    let mut late = w.joiner(&ticket, 3);
    assert_eq!(
        w.connect(&mut late, 11, 3),
        vec![HostAction::Close {
            conn: ConnectionId(11),
            code: ErrorCode::InvitationInvalid
        }]
    );
}

#[test]
fn denied_devices_cannot_join() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::InPerson);
    w.grants.deny(key(2), NOW);
    let mut j = w.joiner(&ticket, 2);
    assert_eq!(
        w.connect(&mut j, 10, 2),
        vec![HostAction::Close {
            conn: ConnectionId(10),
            code: ErrorCode::NotAuthorized
        }]
    );
}

#[test]
fn cancelling_grants_nothing() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::InPerson);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    let actions = w.host.cancel(&ticket.invitation);
    assert!(actions.contains(&HostAction::Close {
        conn: ConnectionId(10),
        code: ErrorCode::Cancelled
    }));
    assert_eq!(w.grants.grants().count(), 0);
    assert_eq!(
        w.host
            .approve(&ticket.invitation, ConnectionId(10), &mut w.grants, NOW),
        Err(HostPairingError::NotOpen)
    );
}

/// The debit is a durable write before the first share goes out: the flow
/// hands out `msg_a` only once the I/O layer says the write landed.
#[test]
fn the_debit_is_stored_before_the_first_share_goes_out() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    let code = w.host.code(&ticket.invitation).unwrap().clone();
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    let out = j.submit_code(&code, &mut rng).unwrap();
    let [JoinerAction::Persist { expected, record }] = &out[..] else {
        panic!("expected only the debit write, got {out:?}")
    };
    assert_eq!(*expected, None);
    assert_eq!(record.attempts_left, JOINER_ATTEMPTS_PER_FLOW - 1);
    assert!(!record.outcome_pending);
    let released = j.on_persisted();
    assert!(matches!(
        &released[..],
        [JoinerAction::Send(ControlMessage::CodeExchange { .. })]
    ));
    // Nothing is held twice.
    assert_eq!(j.on_persisted(), vec![]);
}

/// After the host's confirmation verifies, the outcome is marked pending
/// durably before the joiner's own confirmation goes out.
#[test]
fn the_pending_mark_is_stored_before_the_confirmation_goes_out() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    let code = w.host.code(&ticket.invitation).unwrap().clone();
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    let first = j.submit(&code, &mut rng).unwrap();
    let [JoinerAction::Send(ControlMessage::CodeExchange { attempt, payload })] = &first[..] else {
        panic!("no msg_a")
    };
    let reply = w.host.on_code_exchange(
        ConnectionId(10),
        *attempt,
        payload,
        &mut w.grants,
        NOW,
        &mut w.rng,
    );
    let msg_b = reply
        .iter()
        .find_map(|a| match a {
            HostAction::Send {
                message: ControlMessage::CodeExchange { payload, .. },
                ..
            } => Some(payload.clone()),
            _ => None,
        })
        .unwrap();
    let out = j.on_code_exchange(*attempt, &msg_b);
    let [JoinerAction::Persist { expected, record }] = &out[..] else {
        panic!("expected only the pending mark, got {out:?}")
    };
    assert_eq!(expected.map(|r| r.outcome_pending), Some(false));
    assert!(record.outcome_pending);
    assert!(j.outcome_pending());
    let released = j.on_persisted();
    assert!(matches!(
        &released[..],
        [JoinerAction::Send(ControlMessage::CodeExchange { .. })]
    ));
}

/// A write that does not land (another flow on the same ticket changed the
/// record, or storage failed) releases nothing and ends the flow.
#[test]
fn a_write_that_fails_sends_nothing() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    let code = w.host.code(&ticket.invitation).unwrap().clone();
    let out = j
        .submit_code(&code, &mut ChaCha20Rng::from_seed([5; 32]))
        .unwrap();
    assert!(matches!(&out[..], [JoinerAction::Persist { .. }]));
    assert_eq!(
        j.on_persist_failed(),
        vec![JoinerAction::Failed(ErrorCode::InternalError)]
    );
    assert_eq!(j.on_persisted(), vec![]);
    assert_eq!(j.state(), JoinerState::Failed(ErrorCode::InternalError));
}

/// A held message never goes out on a later connection.
#[test]
fn a_close_drops_what_a_write_was_holding() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    let code = w.host.code(&ticket.invitation).unwrap().clone();
    j.submit_code(&code, &mut ChaCha20Rng::from_seed([5; 32]))
        .unwrap();
    j.on_closed(None);
    assert_eq!(j.on_persisted(), vec![]);
    assert_eq!(j.record().attempts_left, JOINER_ATTEMPTS_PER_FLOW - 1);
}

/// The proof names the profile only for an in-person ticket.
#[test]
fn the_proof_name_carries_the_profile_only_in_person() {
    let w = world();
    let full = JoinerName {
        computer: "Phone".into(),
        profile: Some("Work".into()),
    };
    for (kind, expected) in [
        (InvitationKind::InPerson, "Phone (Work)"),
        (InvitationKind::SendLink, "Phone"),
    ] {
        let ticket = w.invite_ticket_only(kind);
        let mut j = JoinerPairing::new(
            ticket.clone(),
            arrival_for(&ticket),
            key(2),
            full.clone(),
            CpaceExchangeFactory,
            None,
            NOW,
        )
        .unwrap();
        let ControlMessage::JoinProof { name, .. } = j.on_connected(exporters(3), NOW).unwrap()
        else {
            panic!("not a proof")
        };
        assert_eq!(name, expected);
    }
    // The composed name must fit in 128 bytes.
    let ticket = w.invite_ticket_only(InvitationKind::InPerson);
    let long = JoinerName {
        computer: "c".repeat(120),
        profile: Some("profile".into()),
    };
    assert_eq!(
        JoinerPairing::new(
            ticket,
            Arrival::InAppScan,
            key(2),
            long,
            CpaceExchangeFactory,
            None,
            NOW,
        )
        .err(),
        Some(JoinerError::InvalidName)
    );
}

/// A proof timeout ends the flow but keeps a pending outcome stored, so a
/// later start asks again.
#[test]
fn a_proof_timeout_ends_the_flow_and_keeps_the_pending_mark() {
    let w = world();
    let ticket = w.invite_ticket_only(InvitationKind::SendLink);
    let stored = JoinerRecord {
        ticket_hash: ticket.hash(),
        attempts_left: 0,
        outcome_pending: true,
    };
    let mut j = new_joiner(ticket.clone(), 2, Some(&stored)).unwrap();
    j.on_connected(exporters(3), NOW).unwrap();
    assert_eq!(
        j.on_proof_timeout(),
        vec![JoinerAction::Failed(ErrorCode::NotAuthorized)]
    );
    assert_eq!(j.record(), stored);
    assert!(new_joiner(ticket, 2, Some(&j.record())).is_ok());
}
