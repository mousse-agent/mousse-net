//! Host and joiner pairing flows, driven message by message.

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
            key(seed),
            format!("phone {seed}"),
            self.factory.clone(),
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
            assert!(joiner.on_authorized(AuthorizedState::JoinOnly).is_empty());
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
                        joiner.on_code_exchange(attempt, &payload)
                    }
                    ControlMessage::CodeAbort { attempt, .. } => joiner.on_code_abort(attempt),
                    ControlMessage::Paired { host_name, role } => joiner.on_paired(host_name, role),
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

fn shown_codes(actions: &[HostAction]) -> Vec<PairingCode> {
    actions
        .iter()
        .filter_map(|a| match a {
            HostAction::ShowCode { code, .. } => Some(code.clone()),
            _ => None,
        })
        .collect()
}

fn sends(actions: &[HostAction]) -> Vec<&HostAction> {
    actions
        .iter()
        .filter(|a| matches!(a, HostAction::Send { .. }))
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

    let paired = j.on_paired("Desk".into(), Role::owner());
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
    let mut j = JoinerPairing::new(forged, key(2), "x".into(), CpaceExchangeFactory, NOW).unwrap();
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
        .submit_code(&code, &mut ChaCha20Rng::from_seed([5; 32]))
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
        let first = j.submit_code(&wrong, &mut rng).unwrap();
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
    let first = j.submit_code(&wrong, &mut rng).unwrap();
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
    assert_eq!(
        j.submit_code(&wrong, &mut rng),
        Err(JoinerError::WrongState)
    );
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
        let first = j.submit_code(code, rng).unwrap();
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
        let out = j.on_code_exchange(*attempt, &msg_b);
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
/// reconnects, even after its ticket ran out, and step 2 says live: paired.
#[test]
fn a_lost_paired_on_the_last_attempt_is_learned_on_reconnect() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    let wrong = PairingCode::parse("000000").unwrap();
    for _ in 0..2 {
        let first = j.submit_code(&wrong, &mut rng).unwrap();
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
    assert_eq!(j.on_closed(None), vec![]);
    assert_eq!(j.attempts_left(), 0);
    assert!(j.outcome_pending());
    assert_eq!(j.state(), JoinerState::Connecting);

    let later = NOW.plus(1_300);
    assert!(j.on_connected(exporters(11), later).is_ok());
    assert!(matches!(
        crate::authz::decide(&w.grants, &key(2), later),
        crate::authz::Step2::Live { .. }
    ));
    assert_eq!(
        j.on_authorized(AuthorizedState::Live),
        vec![JoinerAction::AlreadyPaired]
    );
    assert_eq!(j.state(), JoinerState::AlreadyPaired);
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
        j.on_authorized(AuthorizedState::JoinOnly);
        j.submit_code(&any, &mut rng).unwrap();
        j.on_closed(None);
    }
    w.connect(&mut j, 10, 2);
    let right = w.host.code(&ticket.invitation).unwrap().clone();
    w.attempt_until_confirmation(&mut j, 10, &right, &mut rng);
    w.host.on_connection_closed(ConnectionId(10));
    j.on_closed(None);
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
        j.on_authorized(AuthorizedState::JoinOnly),
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
    let first = j.submit_code(&wrong, &mut rng).unwrap();
    let (host_log, _) = w.exchange(&mut j, 10, first);
    let second_code = shown_codes(&host_log).remove(0);
    assert_ne!(second_code, first_code);
    assert_eq!(w.host.code(&ticket.invitation), Some(&second_code));

    // The code shown before is no longer accepted.
    let first = j.submit_code(&first_code, &mut rng).unwrap();
    let (host_log, joiner_log) = w.exchange(&mut j, 10, first);
    assert_eq!(
        joiner_log,
        vec![JoinerAction::CodeRejected { attempts_left: 1 }]
    );
    let third_code = shown_codes(&host_log).remove(0);

    // The last attempt shows no further code, and the current one works.
    let first = j.submit_code(&third_code, &mut rng).unwrap();
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
        let first = j.submit_code(&wrong, &mut rng).unwrap();
        w.exchange(&mut j, conn, first);
        assert_eq!(w.host.attempts_left(&ticket.invitation), Some(2 - i as u8));
    }
    assert_eq!(
        w.host.status(&ticket.invitation),
        Some(InvitationStatus::Ended(ErrorCode::AttemptsExhausted))
    );
}

#[test]
fn resends_are_answered_byte_for_byte_without_a_new_debit() {
    let mut w = world();
    let ticket = w.invite(InvitationKind::SendLink);
    let mut j = w.joiner(&ticket, 2);
    w.connect(&mut j, 10, 2);
    let code = w.host.code(&ticket.invitation).unwrap().clone();
    let first = j
        .submit_code(&code, &mut ChaCha20Rng::from_seed([5; 32]))
        .unwrap();
    let [JoinerAction::Send(ControlMessage::CodeExchange { attempt, payload })] = &first[..] else {
        panic!()
    };
    let reply1 = w.host.on_code_exchange(
        ConnectionId(10),
        *attempt,
        payload,
        &mut w.grants,
        NOW,
        &mut w.rng,
    );
    let reply2 = w.host.on_code_exchange(
        ConnectionId(10),
        *attempt,
        payload,
        &mut w.grants,
        NOW,
        &mut w.rng,
    );
    // The first reply also shows the next attempt's code; the resend only
    // repeats the message.
    assert_eq!(shown_codes(&reply1).len(), 1);
    assert_eq!(sends(&reply1), sends(&reply2));
    assert_eq!(sends(&reply2).len(), reply2.len());
    assert_eq!(w.host.attempts_left(&ticket.invitation), Some(2));
    assert_eq!(
        j.resend(),
        Some(ControlMessage::CodeExchange {
            attempt: *attempt,
            payload: payload.clone()
        })
    );

    // The same attempt id replayed on a different TLS session can never
    // succeed (its binding holds the old exporter): refused before any
    // debit or exchange work, with no new code.
    let mut j2 = w.joiner(&ticket, 2);
    w.connect(&mut j2, 11, 2);
    let replayed = w.host.on_code_exchange(
        ConnectionId(11),
        *attempt,
        payload,
        &mut w.grants,
        NOW,
        &mut w.rng,
    );
    assert_eq!(
        replayed,
        vec![HostAction::Send {
            conn: ConnectionId(11),
            message: ControlMessage::CodeAbort {
                attempt: *attempt,
                code: ErrorCode::PairingFailed
            }
        }]
    );
    assert_eq!(w.host.attempts_left(&ticket.invitation), Some(2));

    // A different message on a running attempt is fed to the exchange (and
    // fails it here); the debit is not repeated.
    let mut garbage = payload.clone();
    garbage[0] ^= 0xff;
    let actions = w.host.on_code_exchange(
        ConnectionId(10),
        *attempt,
        &garbage,
        &mut w.grants,
        NOW,
        &mut w.rng,
    );
    assert_eq!(w.host.attempts_left(&ticket.invitation), Some(2));
    assert!(actions.iter().any(|a| matches!(
        a,
        HostAction::Send {
            message: ControlMessage::CodeAbort { .. },
            ..
        }
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
    let actions = j.submit_code(&code, &mut rng).unwrap();
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
        .submit_code(&code, &mut ChaCha20Rng::from_seed([5; 32]))
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
    j.on_closed(None);
    assert_eq!(w.host.attempts_left(&ticket.invitation), Some(2));
    assert_eq!(j.attempts_left(), 2);
    assert_eq!(j.state(), JoinerState::Connecting);
}

#[test]
fn a_fake_host_can_use_up_the_joiners_attempts_but_no_more() {
    // The joiner talks to a "host" that always rejects: its local cap holds.
    let ticket = world().invite(InvitationKind::SendLink);
    let mut j =
        JoinerPairing::new(ticket, key(2), "phone".into(), CpaceExchangeFactory, NOW).unwrap();
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    let code = PairingCode::parse("111111").unwrap();
    for round in 0..3u8 {
        j.on_connected(exporters(round), NOW).unwrap();
        j.on_authorized(AuthorizedState::JoinOnly);
        let first = j.submit_code(&code, &mut rng).unwrap();
        let [JoinerAction::Send(ControlMessage::CodeExchange { attempt, .. })] = &first[..] else {
            panic!()
        };
        j.on_code_abort(*attempt);
        if round < 2 {
            j.on_closed(None);
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
        j.on_paired("Desk".into(), Role::owner()),
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

    let mut fresh = w.joiner(&ticket, 2);
    fresh.on_connected(exporters(10), NOW).unwrap();
    assert_eq!(
        fresh.on_authorized(AuthorizedState::Live),
        vec![JoinerAction::Failed(ErrorCode::PairingFailed)]
    );
    assert_eq!(
        fresh.state(),
        JoinerState::Failed(ErrorCode::PairingFailed)
    );

    let mut known = w.joiner(&ticket, 2);
    known.set_host_pinned(true);
    known.on_connected(exporters(11), NOW).unwrap();
    assert_eq!(
        known.on_authorized(AuthorizedState::Live),
        vec![JoinerAction::AlreadyPaired]
    );

    // In person, the ticket came from the owner's own screen: unchanged.
    let in_person = w.invite(InvitationKind::InPerson);
    let mut j = w.joiner(&in_person, 2);
    j.on_connected(exporters(12), NOW).unwrap();
    assert_eq!(
        j.on_authorized(AuthorizedState::Live),
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
