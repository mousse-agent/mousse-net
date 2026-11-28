//! Rules of [`DirectHostPairing`] that `direct-host.json` does not reach:
//! creation, the stream that ends a fresh enrollment's cancel, a receipt
//! after a restart, denied identities and the timer.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

use std::collections::VecDeque;
use std::convert::Infallible;

use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, TryCryptoRng, TryRng};

use super::*;
use crate::identity::SoftwareKey;
use crate::pairing::CpaceExchangeFactory;

const T: UnixTime = UnixTime(1_790_000_000);

fn key(seed: u8) -> IdentityPublicKey {
    SoftwareKey::generate(&mut ChaCha20Rng::from_seed([seed; 32])).public_key()
}

fn params() -> DirectInvitationParams {
    DirectInvitationParams {
        role: Role::owner(),
        authorizing_owner: OwnerRef::from_bytes([0x51; 16]),
        grant_expires_at: None,
    }
}

fn host(limits: &Limits) -> DirectHostPairing<CpaceExchangeFactory> {
    DirectHostPairing::with_limits(key(1), "Desk".into(), CpaceExchangeFactory, limits)
}

fn create(h: &mut DirectHostPairing<CpaceExchangeFactory>) -> CreatedDirectInvitation {
    h.create(params(), T, &mut ChaCha20Rng::from_seed([9; 32]))
        .unwrap()
}

/// Hands out listed bytes, in order.
struct Script(VecDeque<u8>);

impl TryRng for Script {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        unreachable!("no u32 draws")
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        unreachable!("no u64 draws")
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for b in dst {
            *b = self.0.pop_front().expect("a listed byte");
        }
        Ok(())
    }
}

impl TryCryptoRng for Script {}

fn script(parts: &[&[u8]]) -> Script {
    Script(parts.iter().flat_map(|p| p.iter().copied()).collect())
}

/// The 12 drawn bytes that give `code`.
fn draw(code: &str) -> Vec<u8> {
    code.bytes()
        .map(|c| {
            crate::pairing::DIRECT_CODE_ALPHABET
                .iter()
                .position(|a| *a == c)
                .expect("an alphabet character") as u8
        })
        .collect()
}

#[test]
fn creation_keeps_open_lookups_apart_and_bounded() {
    let limits = Limits::DEFAULT
        .with_overrides(&[("DIRECT_MAX_OPEN", 2)])
        .unwrap();
    let mut h = host(&limits);
    let first = h
        .create(params(), T, &mut script(&[&[1; 16], &draw("K7QM2XPA9RTE")]))
        .unwrap();
    // The second invitation's first draw has the first one's lookup: the
    // whole code is drawn again.
    let second = h
        .create(
            params(),
            T,
            &mut script(&[&[2; 16], &draw("K7QMAAAAAAAA"), &draw("0000BBBBBBBB")]),
        )
        .unwrap();
    assert_eq!(second.code.as_str(), "0000BBBBBBBB");
    assert_ne!(first.code.lookup(), second.code.lookup());
    assert_eq!(
        h.create(params(), T, &mut script(&[&[3; 16], &draw("ZZZZZZZZZZZZ")]))
            .unwrap_err(),
        DirectHostError::TooManyOpen
    );
    // An ended invitation frees its place and its lookup.
    h.cancel(&first.invitation);
    let third = h
        .create(params(), T, &mut script(&[&[3; 16], &draw("K7QMCCCCCCCC")]))
        .unwrap();
    assert_eq!(third.code.lookup(), first.code.lookup());
}

/// Connect `joiner` on `conn` and run one attempt with the right code to
/// the end. Returns the host's answer to the joiner's confirmation.
fn pass(
    h: &mut DirectHostPairing<CpaceExchangeFactory>,
    created: &CreatedDirectInvitation,
    joiner: &IdentityPublicKey,
    conn: u64,
    grants: &mut GrantTable,
    now: UnixTime,
) -> Vec<DirectHostAction> {
    let mut rng = ChaCha20Rng::from_seed([conn as u8; 32]);
    let exporter = [conn as u8; 32];
    let lookup = created.code.lookup();
    let c = ConnectionId(conn);
    let admitted = h.on_join_direct(c, joiner, &exporter, &lookup, "j", None, grants, now);
    assert!(admitted
        .iter()
        .any(|a| matches!(a, DirectHostAction::AdmittedJoinOnly { .. })));
    let attempt = AttemptId([conn as u8; 16]);
    let binding =
        direct_binding_transcript(&lookup, &created.invitation, &key(1), joiner, &exporter);
    let sid = attempt_sid(&attempt, &exporter);
    let mut exchange = CpaceExchangeFactory.start(
        ExchangeRole::Initiator,
        created.code.secret().as_bytes(),
        &binding,
        &sid,
        &mut rng,
    );
    let msg_a = exchange.step(None).unwrap().send.unwrap();
    let reply = h.on_code_exchange(c, attempt, &msg_a, now, &mut rng);
    let msg_b = reply
        .iter()
        .find_map(|a| match a {
            DirectHostAction::Send {
                message: ControlMessage::CodeExchange { payload, .. },
                ..
            } => Some(payload.clone()),
            _ => None,
        })
        .expect("msg_b");
    let msg_c = exchange.step(Some(&msg_b)).unwrap().send.unwrap();
    h.on_code_exchange(c, attempt, &msg_c, now, &mut rng)
}

/// A `CANCELLED` close on a connection the host just enrolled undoes the
/// grant; once a stream has run on it, it is an ordinary close.
#[test]
fn a_cancelled_close_undoes_only_an_enrollment_that_carried_no_stream() {
    for (stream_first, kept) in [(false, false), (true, true)] {
        let mut h = host(&Limits::DEFAULT);
        let mut grants = GrantTable::new();
        let created = create(&mut h);
        let joiner = key(2);
        pass(&mut h, &created, &joiner, 7, &mut grants, T);
        let request = DirectRequestId {
            invitation: created.invitation,
            identity: joiner,
        };
        h.allow(&request, None, &mut grants, T).unwrap();
        assert!(grants.live_grant(&joiner, T).is_some());
        if stream_first {
            h.on_stream_opened(ConnectionId(7));
        }
        let actions =
            h.on_connection_closed(ConnectionId(7), Some(ErrorCode::Cancelled), &mut grants, T);
        assert_eq!(
            grants.live_grant(&joiner, T).is_some(),
            kept,
            "stream first: {stream_first}"
        );
        assert_eq!(
            actions
                .iter()
                .any(|a| matches!(a, DirectHostAction::EnrollmentUndone { .. })),
            !kept
        );
    }
}

/// Invitations live in memory only; the grant and its receipt are durable.
/// After a restart the receipt still answers, and a cancel still removes it.
#[test]
fn a_receipt_grant_answers_recovery_after_a_restart() {
    let mut grants = GrantTable::new();
    let joiner = key(2);
    let (lookup, invitation) = {
        let mut before = host(&Limits::DEFAULT);
        let created = create(&mut before);
        pass(&mut before, &created, &joiner, 7, &mut grants, T);
        let request = DirectRequestId {
            invitation: created.invitation,
            identity: joiner,
        };
        before.allow(&request, None, &mut grants, T).unwrap();
        (created.code.lookup(), created.invitation)
    };
    grants.unbind(ConnectionId(7));
    let mut after = host(&Limits::DEFAULT);
    for (cancel, conn) in [(false, 8u64), (true, 9)] {
        let grant = grants.live_grant(&joiner, T).map(|g| g.id).unwrap();
        grants.bind(ConnectionId(conn), grant, T).unwrap();
        let actions = after.on_join_direct(
            ConnectionId(conn),
            &joiner,
            &[conn as u8; 32],
            &lookup,
            "j",
            Some(DirectRecovery {
                receipt: invitation,
                cancel,
            }),
            &mut grants,
            T,
        );
        if cancel {
            assert!(grants.live_grant(&joiner, T).is_none());
            assert!(actions.contains(&DirectHostAction::Close {
                conn: ConnectionId(conn),
                code: ErrorCode::Cancelled
            }));
        } else {
            assert!(matches!(
                actions.as_slice(),
                [DirectHostAction::Send {
                    message: ControlMessage::Paired { .. },
                    ..
                }]
            ));
            grants.unbind(ConnectionId(conn));
        }
    }
}

#[test]
fn denied_identities_are_refused_before_any_lookup() {
    let mut h = host(&Limits::DEFAULT);
    let created = create(&mut h);
    let mut grants = GrantTable::new();
    let joiner = key(2);
    grants.deny(joiner, T);
    let actions = h.on_join_direct(
        ConnectionId(1),
        &joiner,
        &[1; 32],
        &created.code.lookup(),
        "j",
        None,
        &mut grants,
        T,
    );
    assert_eq!(
        actions,
        [DirectHostAction::Close {
            conn: ConnectionId(1),
            code: ErrorCode::NotAuthorized
        }]
    );
}

#[test]
fn the_next_deadline_is_the_expiry_or_an_earlier_window_end() {
    let mut grants = GrantTable::new();
    let mut h = host(&Limits::DEFAULT);
    let created = create(&mut h);
    assert_eq!(h.next_deadline(), Some(T.plus(600)));
    pass(&mut h, &created, &key(2), 3, &mut grants, T.plus(10));
    assert_eq!(h.next_deadline(), Some(T.plus(310)));
    // Past the expiry only the request's window remains.
    let mut h = host(&Limits::DEFAULT);
    let created = create(&mut h);
    pass(&mut h, &created, &key(2), 3, &mut grants, T.plus(599));
    h.tick(T.plus(600));
    assert_eq!(h.next_deadline(), Some(T.plus(899)));
}
