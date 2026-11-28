//! Rules of [`DirectJoinerPairing`] that `direct-joiner.json` does not
//! reach: what the person typed, the record formats, the ledger's life and
//! a failed write.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use super::*;
use crate::identity::SoftwareKey;
use crate::pairing::CpaceExchangeFactory;

const T: UnixTime = UnixTime(1_790_000_000);
const CODE: &str = "K7QM-2XPA-9RTE";

fn key(seed: u8) -> IdentityPublicKey {
    SoftwareKey::generate(&mut ChaCha20Rng::from_seed([seed; 32])).public_key()
}

fn lookup() -> DirectLookup {
    DirectLookup::from_canonical("K7QM").unwrap()
}

/// A Connect: the flow takes the lookup's hold and gets `ledger` and
/// `pending` loaded under it. Err: the refusal's name.
fn start(
    address: &str,
    code: &str,
    ledger: Option<&DirectLedger>,
    pending: Option<&DirectPending>,
    now: UnixTime,
) -> Result<DirectJoinerPairing<CpaceExchangeFactory>, &'static str> {
    let mut flow = DirectJoinerPairing::new(address, code, key(2), "Laptop", CpaceExchangeFactory)
        .map_err(|e| e.name())?;
    assert!(matches!(
        flow.start().as_slice(),
        [DirectJoinerAction::AcquireHold(_)]
    ));
    let pending: Vec<DirectPending> = pending.into_iter().cloned().collect();
    let actions = flow.on_records(ledger, &pending, now);
    match flow.state() {
        DirectJoinerState::Ended(end) => {
            // Refused before dialing: the hold goes back at once.
            assert!(matches!(
                actions.as_slice(),
                [
                    DirectJoinerAction::Ended(_),
                    DirectJoinerAction::ReleaseHold(_)
                ]
            ));
            Err(match end {
                DirectEnd::AttemptsExhausted => "attempts_exhausted",
                DirectEnd::BadRecord => "bad_record",
                _ => "ended",
            })
        }
        _ => Ok(flow),
    }
}

/// Inputs: the address forms the route grammar reads, and what it does not
/// (DNS names, no port, port 0, a leading zero, an unbracketed IPv6).
#[test]
fn typed_addresses() {
    for (text, canonical) in [
        ("192.168.1.20:47100", Some("192.168.1.20:47100")),
        (" 192.168.1.20:47100 ", Some("192.168.1.20:47100")),
        ("[fe80::1]:47100", Some("[fe80::1]:47100")),
        ("[FE80:0::1]:1", Some("[fe80::1]:1")),
        ("desk.local:47100", None),
        ("192.168.1.20", None),
        ("192.168.1.20:0", None),
        ("192.168.1.020:47100", None),
        ("192.168.1.20:047100", None),
        ("fe80::1:47100", None),
        ("[::ffff:192.168.1.20]:47100", None),
        ("", None),
    ] {
        assert_eq!(
            DirectAddress::parse(text).map(|a| a.to_text()).as_deref(),
            canonical,
            "{text:?}"
        );
    }
}

/// A bad address or code is refused before anything is dialled; the
/// address is read first.
#[test]
fn bad_input_is_refused_before_dialing() {
    let name = |r: Result<_, &'static str>| r.err();
    assert_eq!(
        name(start("desk:1", "nope", None, None, T)),
        Some("bad_address")
    );
    assert_eq!(
        name(start("10.0.0.2:47100", "K7QM-2XPA", None, None, T)),
        Some("bad_code")
    );
    assert_eq!(
        name(start("10.0.0.2:47100", "K7QM-2XPA-9RTU", None, None, T)),
        Some("bad_code")
    );
    assert!(start("10.0.0.2:47100", "k7qm 2xpa 9rte", None, None, T).is_ok());
}

#[test]
fn records_round_trip_and_refuse_what_they_cannot_hold() {
    let ledger = DirectLedger {
        lookup: lookup(),
        attempts_left: 3,
        first_debit: T,
    };
    assert_eq!(
        DirectLedger::from_bytes(&ledger.to_bytes()),
        Ok(ledger.clone())
    );
    let too_many = DirectLedger {
        attempts_left: DIRECT_JOINER_ATTEMPTS + 1,
        ..ledger.clone()
    };
    assert_eq!(
        DirectLedger::from_bytes(&too_many.to_bytes()),
        Err(DirectJoinError::BadRecord)
    );
    let pending = DirectPending {
        lookup: lookup(),
        host: key(1),
        invitation: InvitationId([7; 16]),
        address: DirectAddress::parse("[fe80::1]:47100").unwrap(),
        verified_at: T,
        attempt: AttemptId([5; 16]),
        cancelled: true,
    };
    assert_eq!(
        DirectPending::from_bytes(&pending.to_bytes()),
        Ok(pending.clone())
    );
    // A pending record's address must be in its canonical form.
    let mut odd = pending.to_bytes();
    let at = odd
        .windows(4)
        .position(|w| w == b"fe80")
        .expect("address text");
    odd[at..at + 4].copy_from_slice(b"FE80");
    assert_eq!(
        DirectPending::from_bytes(&odd),
        Err(DirectJoinError::BadRecord)
    );
    // Each record refuses the other's domain.
    assert_eq!(
        DirectLedger::from_bytes(&pending.to_bytes()),
        Err(DirectJoinError::BadRecord)
    );
}

/// The ledger counts for 24 h after its first debit, then a Connect starts
/// with every attempt again.
#[test]
fn the_ledger_counts_for_a_day_from_its_first_debit() {
    let empty = DirectLedger {
        lookup: lookup(),
        attempts_left: 0,
        first_debit: T,
    };
    let last_second = T.plus(DIRECT_LEDGER_LIFE_SECS - 1);
    assert_eq!(
        start("10.0.0.2:47100", CODE, Some(&empty), None, last_second).err(),
        Some("attempts_exhausted")
    );
    let next_day = start(
        "10.0.0.2:47100",
        CODE,
        Some(&empty),
        None,
        T.plus(DIRECT_LEDGER_LIFE_SECS),
    )
    .unwrap();
    assert_eq!(next_day.attempts_left(), DIRECT_JOINER_ATTEMPTS);
    // A ledger for another lookup is not this flow's.
    let other = DirectLedger {
        lookup: DirectLookup::from_canonical("ZZZZ").unwrap(),
        ..empty
    };
    assert_eq!(
        start("10.0.0.2:47100", CODE, Some(&other), None, T).err(),
        Some("bad_record")
    );
}

/// A pending record resumes only for the same lookup and address.
#[test]
fn a_pending_record_resumes_only_at_its_address() {
    let pending = DirectPending {
        lookup: lookup(),
        host: key(1),
        invitation: InvitationId([7; 16]),
        address: DirectAddress::parse("10.0.0.2:47100").unwrap(),
        verified_at: T,
        attempt: AttemptId([5; 16]),
        cancelled: false,
    };
    let same = start("10.0.0.2:47100", CODE, None, Some(&pending), T).unwrap();
    assert_eq!(same.pinned_host(), Some(key(1)));
    let elsewhere = start("10.0.0.3:47100", CODE, None, Some(&pending), T).unwrap();
    assert_eq!(elsewhere.pinned_host(), None);
}

/// A debit that cannot be stored sends nothing that waited for it.
#[test]
fn a_debit_that_fails_to_store_sends_no_share() {
    let mut flow = start("10.0.0.2:47100", CODE, None, None, T).unwrap();
    flow.on_connected(key(1), [3; 32]);
    assert!(matches!(
        flow.on_hello(4).as_slice(),
        [DirectJoinerAction::Send(ControlMessage::JoinDirect { .. })]
    ));
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    let actions = flow.on_authorized_direct(InvitationId([7; 16]), false, T, &mut rng);
    assert!(matches!(
        actions.as_slice(),
        [DirectJoinerAction::PersistLedger { expected: None, record }] if record.attempts_left == 4
    ));
    let after = flow.on_persist_failed();
    assert!(!after
        .iter()
        .any(|a| matches!(a, DirectJoinerAction::Send(_))));
    assert_eq!(
        flow.state(),
        DirectJoinerState::Ended(DirectEnd::Closed(Some(ErrorCode::InternalError)))
    );
}

/// After the code passed, only a settling answer clears the pending
/// record: a host's `CODE_ABORT` there closes the connection and the record
/// stays for a recovery.
#[test]
fn a_host_abort_after_the_code_passed_keeps_the_pending_record() {
    use crate::grants::{GrantTable, OwnerRef, Role};
    use crate::pairing::{DirectHostAction, DirectHostPairing, DirectInvitationParams};

    let host_key = key(1);
    let mut host = DirectHostPairing::new(host_key, "Desk".into(), CpaceExchangeFactory);
    let mut host_rng = ChaCha20Rng::from_seed([5; 32]);
    let created = host
        .create(
            DirectInvitationParams {
                role: Role::owner(),
                authorizing_owner: OwnerRef::from_bytes([0x51; 16]),
                grant_expires_at: None,
            },
            T,
            &mut host_rng,
        )
        .unwrap();
    let mut grants = GrantTable::new();
    let code = created.code.to_display();
    let mut flow = start("10.0.0.2:47100", &code, None, None, T).unwrap();
    let conn = crate::ConnectionId(1);
    let exporter = [9u8; 32];
    flow.on_connected(host_key, exporter);
    let Some(DirectJoinerAction::Send(ControlMessage::JoinDirect { lookup, name, .. })) =
        flow.on_hello(4).into_iter().next()
    else {
        panic!("JOIN_DIRECT")
    };
    host.on_join_direct(
        conn,
        &key(2),
        &exporter,
        &lookup,
        &name,
        None,
        &mut grants,
        T,
    );
    // Settle every write at once; return the messages for the host.
    fn settle(
        flow: &mut DirectJoinerPairing<CpaceExchangeFactory>,
        actions: Vec<DirectJoinerAction>,
    ) -> Vec<DirectJoinerAction> {
        let mut out = Vec::new();
        let mut queue: std::collections::VecDeque<_> = actions.into();
        while let Some(a) = queue.pop_front() {
            if matches!(
                a,
                DirectJoinerAction::PersistLedger { .. }
                    | DirectJoinerAction::PersistPending { .. }
            ) {
                out.push(a);
                for m in flow.on_persisted().into_iter().rev() {
                    queue.push_front(m);
                }
            } else {
                out.push(a);
            }
        }
        out
    }
    let sends = |actions: &[DirectJoinerAction]| -> Vec<ControlMessage> {
        actions
            .iter()
            .filter_map(|a| match a {
                DirectJoinerAction::Send(m) => Some(m.clone()),
                _ => None,
            })
            .collect()
    };
    let mut rng = ChaCha20Rng::from_seed([6; 32]);
    let first = flow_on_authorized(&mut flow, created.invitation, &mut rng);
    let a = settle(&mut flow, first);
    let msgs = sends(&a);
    let [ControlMessage::CodeExchange { attempt, payload }] = msgs.as_slice() else {
        panic!("msg_a")
    };
    let attempt = *attempt;
    let reply = host.on_code_exchange(conn, attempt, payload, T, &mut host_rng);
    let msg_b = reply
        .iter()
        .find_map(|a| match a {
            DirectHostAction::Send {
                message: ControlMessage::CodeExchange { payload, .. },
                ..
            } => Some(payload.clone()),
            _ => None,
        })
        .unwrap();
    let step = flow.on_code_exchange(attempt, &msg_b, T);
    let passed = settle(&mut flow, step);
    assert!(passed.iter().any(|a| matches!(
        a,
        DirectJoinerAction::PersistPending {
            record: Some(_),
            ..
        }
    )));
    assert_eq!(flow.state(), DirectJoinerState::AwaitingAllow);

    let after = flow.on_code_abort(attempt);
    assert!(after.contains(&DirectJoinerAction::Close(ErrorCode::PairingFailed)));
    assert!(after.contains(&DirectJoinerAction::Away));
    assert!(!after
        .iter()
        .any(|a| matches!(a, DirectJoinerAction::PersistPending { .. })));
    assert_eq!(flow.state(), DirectJoinerState::Away);
    assert!(flow.pending().is_some());
}

fn flow_on_authorized(
    flow: &mut DirectJoinerPairing<CpaceExchangeFactory>,
    invitation: InvitationId,
    rng: &mut ChaCha20Rng,
) -> Vec<DirectJoinerAction> {
    flow.on_authorized_direct(invitation, false, T, rng)
}

/// wire.md 10.9: a `PAIRED` that answers the recovery carrying this
/// device's cancel means the grant committed before the cancel arrived, so
/// it is taken. One that crosses the cancel on another connection pins
/// nothing.
#[test]
fn paired_in_answer_to_a_cancelling_recovery_is_taken() {
    let pending = DirectPending {
        lookup: lookup(),
        host: key(1),
        invitation: InvitationId([7; 16]),
        address: DirectAddress::parse("10.0.0.2:47100").unwrap(),
        verified_at: T,
        attempt: AttemptId([5; 16]),
        cancelled: true,
    };
    let mut flow = DirectJoinerPairing::resume(
        pending.address,
        lookup(),
        key(2),
        "Laptop",
        CpaceExchangeFactory,
        &Limits::DEFAULT,
    )
    .unwrap();
    flow.start();
    assert!(flow
        .on_records(None, std::slice::from_ref(&pending), T)
        .is_empty());
    flow.on_connected(key(1), [9; 32]);
    let sent = flow.on_hello(4);
    assert!(matches!(
        sent.as_slice(),
        [DirectJoinerAction::Send(ControlMessage::JoinDirect {
            recovery: Some(DirectRecovery { cancel: true, .. }),
            ..
        })]
    ));
    // Step 2's notice: the device holds the committed grant.
    assert!(flow.on_authorized(AuthorizedState::Live).is_empty());
    let paired = flow.on_paired("Desk".into(), Role::owner());
    assert!(
        matches!(paired.as_slice(), [DirectJoinerAction::Paired(p)] if p.invitation == pending.invitation)
    );
}

/// The hold (wire.md 10.9 "Joiner records"): nothing is loaded or dialled
/// without it, a refusal ends a new flow as busy, and the flow gives it
/// back when it goes away.
#[test]
fn the_lookup_hold_comes_before_the_records_and_goes_back_away() {
    let mut busy = DirectJoinerPairing::new(
        "10.0.0.2:47100",
        CODE,
        key(2),
        "Laptop",
        CpaceExchangeFactory,
    )
    .unwrap();
    assert!(busy.on_connected(key(1), [3; 32]).is_empty());
    assert_eq!(busy.state(), DirectJoinerState::Holding);
    busy.start();
    assert_eq!(
        busy.on_hold_refused(),
        vec![DirectJoinerAction::Ended(DirectEnd::Busy)]
    );

    let mut flow = start("10.0.0.2:47100", CODE, None, None, T).unwrap();
    flow.on_connected(key(1), [3; 32]);
    flow.on_hello(4);
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    flow.on_authorized_direct(InvitationId([7; 16]), false, T, &mut rng);
    flow.on_persisted();
    // The connection breaks before the code passed: the flow ends and the
    // hold goes back.
    let ended = flow.on_closed(None);
    assert_eq!(
        ended.last(),
        Some(&DirectJoinerAction::ReleaseHold(lookup()))
    );
}

/// A cancel whose write fails while connected closes that connection with
/// `INTERNAL_ERROR`; the close that waited for the write is never sent.
#[test]
fn a_failed_cancel_write_closes_the_live_connection() {
    let pending = DirectPending {
        lookup: lookup(),
        host: key(1),
        invitation: InvitationId([7; 16]),
        address: DirectAddress::parse("10.0.0.2:47100").unwrap(),
        verified_at: T,
        attempt: AttemptId([5; 16]),
        cancelled: false,
    };
    let mut flow = start("10.0.0.2:47100", CODE, None, Some(&pending), T).unwrap();
    flow.on_connected(key(1), [3; 32]);
    flow.on_hello(4);
    flow.on_authorized_direct(
        InvitationId([7; 16]),
        false,
        T,
        &mut ChaCha20Rng::from_seed([4; 32]),
    );
    assert_eq!(flow.state(), DirectJoinerState::AwaitingAllow);
    let asked = flow.cancel().unwrap();
    assert!(matches!(
        asked.as_slice(),
        [DirectJoinerAction::PersistPending { record: Some(r), .. }] if r.cancelled
    ));
    let failed = flow.on_persist_failed();
    assert_eq!(
        failed,
        vec![
            DirectJoinerAction::Close(ErrorCode::InternalError),
            DirectJoinerAction::Ended(DirectEnd::Closed(Some(ErrorCode::InternalError))),
            DirectJoinerAction::ReleaseHold(lookup()),
        ]
    );
}

/// wire.md 10.9 "Joiner": the hold stays while the pin is being stored. A
/// second `PAIRED` (a protocol error) closes the connection, but the flow
/// stays paired and keeps the hold until the pin is stored.
#[test]
fn the_hold_stays_while_the_pin_is_stored() {
    let pending = DirectPending {
        lookup: lookup(),
        host: key(1),
        invitation: InvitationId([7; 16]),
        address: DirectAddress::parse("10.0.0.2:47100").unwrap(),
        verified_at: T,
        cancelled: false,
        attempt: AttemptId([5; 16]),
    };
    let mut flow = start("10.0.0.2:47100", CODE, None, Some(&pending), T).unwrap();
    flow.on_connected(key(1), [9; 32]);
    flow.on_hello(4);
    flow.on_authorized(AuthorizedState::Live);
    let paired = flow.on_paired("Desk".into(), Role::owner());
    assert!(matches!(paired.as_slice(), [DirectJoinerAction::Paired(_)]));
    let again = flow.on_paired("Desk".into(), Role::owner());
    assert_eq!(
        again,
        vec![DirectJoinerAction::Close(ErrorCode::ProtocolError)]
    );
    assert!(flow.on_closed(None).is_empty());
    assert_eq!(flow.state(), DirectJoinerState::Paired);
    let stored = flow.on_pin_stored();
    assert!(matches!(
        stored.as_slice(),
        [DirectJoinerAction::PersistPending { record: None, .. }]
    ));
    assert_eq!(
        flow.on_persisted(),
        vec![
            DirectJoinerAction::Ended(DirectEnd::Paired),
            DirectJoinerAction::ReleaseHold(lookup()),
        ]
    );
}

/// A dial that fails before TLS is up: a first contact ends, a recovery
/// goes back away with its record; the hold goes back either way.
#[test]
fn a_failed_dial_gives_the_hold_back() {
    let mut first = start("10.0.0.2:47100", CODE, None, None, T).unwrap();
    assert_eq!(first.state(), DirectJoinerState::Connecting);
    assert_eq!(
        first.on_dial_failed(),
        vec![
            DirectJoinerAction::Ended(DirectEnd::Closed(None)),
            DirectJoinerAction::ReleaseHold(lookup()),
        ]
    );

    let pending = DirectPending {
        lookup: lookup(),
        host: key(1),
        invitation: InvitationId([7; 16]),
        address: DirectAddress::parse("10.0.0.2:47100").unwrap(),
        verified_at: T,
        cancelled: false,
        attempt: AttemptId([5; 16]),
    };
    let mut recovery = start("10.0.0.2:47100", CODE, None, Some(&pending), T).unwrap();
    assert_eq!(
        recovery.on_dial_failed(),
        vec![
            DirectJoinerAction::Away,
            DirectJoinerAction::ReleaseHold(lookup()),
        ]
    );
    assert_eq!(recovery.state(), DirectJoinerState::Away);
    assert_eq!(recovery.pending(), Some(&pending));
}

fn paired_recovery() -> (DirectJoinerPairing<CpaceExchangeFactory>, DirectPending) {
    let pending = DirectPending {
        lookup: lookup(),
        host: key(1),
        invitation: InvitationId([7; 16]),
        address: DirectAddress::parse("10.0.0.2:47100").unwrap(),
        verified_at: T,
        cancelled: false,
        attempt: AttemptId([5; 16]),
    };
    let flow = start("10.0.0.2:47100", CODE, None, Some(&pending), T).unwrap();
    (flow, pending)
}

/// A pin that cannot be stored: the receipt stays, the connection closes
/// with `INTERNAL_ERROR`, the hold goes back and the flow ends.
#[test]
fn a_failed_pin_write_keeps_the_receipt_and_gives_the_hold_back() {
    let (mut flow, pending) = paired_recovery();
    flow.on_connected(key(1), [9; 32]);
    flow.on_hello(4);
    flow.on_authorized(AuthorizedState::Live);
    let paired = flow.on_paired("Desk".into(), Role::owner());
    assert!(matches!(paired.as_slice(), [DirectJoinerAction::Paired(_)]));
    // An ordinary write acknowledgement does not stand for the pin.
    assert!(flow.on_persisted().is_empty());
    assert_eq!(
        flow.on_persist_failed(),
        vec![
            DirectJoinerAction::Close(ErrorCode::InternalError),
            DirectJoinerAction::Ended(DirectEnd::Closed(Some(ErrorCode::InternalError))),
            DirectJoinerAction::ReleaseHold(lookup()),
        ]
    );
    assert_eq!(flow.pending(), Some(&pending));
    assert!(flow.on_pin_stored().is_empty());
}

/// A recovery whose host now agrees minor 3 keeps its receipt and goes back
/// away for a later try; a first contact ends as needs update.
#[test]
fn a_minor_3_host_sends_a_recovery_away() {
    let (mut flow, pending) = paired_recovery();
    flow.on_connected(key(1), [9; 32]);
    assert_eq!(
        flow.on_hello(3),
        vec![
            DirectJoinerAction::Close(ErrorCode::UnsupportedVersion),
            DirectJoinerAction::Away,
            DirectJoinerAction::ReleaseHold(lookup()),
        ]
    );
    assert_eq!(flow.state(), DirectJoinerState::Away);
    assert_eq!(flow.pending(), Some(&pending));
    assert_eq!(
        flow.start(),
        vec![DirectJoinerAction::AcquireHold(lookup())]
    );

    let mut first = start("10.0.0.2:47100", CODE, None, None, T).unwrap();
    first.on_connected(key(1), [9; 32]);
    assert_eq!(
        first.on_hello(3),
        vec![
            DirectJoinerAction::Close(ErrorCode::UnsupportedVersion),
            DirectJoinerAction::Ended(DirectEnd::NeedsUpdate),
            DirectJoinerAction::ReleaseHold(lookup()),
        ]
    );
}
