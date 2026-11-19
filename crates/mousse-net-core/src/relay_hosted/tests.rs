//! Hosted-mode tests. Each names the duty or rule it proves
//! (`docs/phase34-design.md` §A.9, §B.4, §B.10, §C.3). Tokens and blocks are
//! signed here with a throwaway issuer key.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use super::records::issuer_key_id;
use super::*;
use crate::identity::SoftwareKey;

const RELAY: RelayId = [0x11; 32];
const BOOT: BootId = [0x22; 16];
const H1: Handle = [0x31; 32];
const H2: Handle = [0x32; 32];
const GROUP: RateGroup = [0x41; 16];
/// Plus time when the boot is answered, Unix ms.
const P0: u64 = 1_700_000_000_000;
const P0_SECS: u64 = P0 / 1_000;
const MB: u64 = 1 << 20;

struct Issuer {
    key: SoftwareKey,
}

impl Issuer {
    fn new(seed: u8) -> Self {
        Self {
            key: SoftwareKey::generate(&mut ChaCha20Rng::from_seed([seed; 32])),
        }
    }

    fn keys(&self) -> IssuerKeys {
        IssuerKeys::new([self.key.public_key()])
    }

    fn token(&self, handle: Handle, not_before: u64, not_after: u64) -> Vec<u8> {
        let t = AdmissionToken {
            issuer_key_id: issuer_key_id(&self.key.public_key()),
            relay_id: RELAY,
            handle,
            not_before,
            not_after,
        };
        SignedEnvelope::sign(t.encode(), &self.key).encode()
    }

    fn block_with(&self, f: impl FnOnce(&mut LeaseBlock)) -> Vec<u8> {
        let mut b = LeaseBlock {
            issuer_key_id: issuer_key_id(&self.key.public_key()),
            lease_id: [1; 16],
            relay_id: RELAY,
            boot_id: BOOT,
            handle: H1,
            class: Class::Interactive,
            sequence: 1,
            rate_cap: 64 * MB,
            bytes: 4 * MB,
            not_before: P0_SECS - 10,
            expires_at: P0_SECS + 3_600,
            rate_group: GROUP,
        };
        f(&mut b);
        SignedEnvelope::sign(b.encode(), &self.key).encode()
    }

    fn block(&self, id: u8, seq: u64, class: Class, bytes: u64) -> Vec<u8> {
        self.block_with(|b| {
            b.lease_id = [id; 16];
            b.sequence = seq;
            b.class = class;
            b.bytes = bytes;
        })
    }
}

/// Monotonic `ms`, with the wall clock where Plus's clock is (unless a
/// test says otherwise).
fn at(ms: u64) -> Now {
    Now {
        mono: Millis(ms),
        wall: UnixTime((P0 + ms) / 1_000),
    }
}

/// A boot whose announcement Plus answered at monotonic 0 with P0, so the
/// Plus clock at monotonic `t` is `P0 + t`.
fn booted(issuer: &Issuer) -> Hosted {
    let mut h = Hosted::new(RELAY, BOOT, issuer.keys(), HostedLimits::DEFAULT);
    h.boot_answered(&BootAnswer { plus_time_ms: P0 }, Millis(0), at(0));
    h
}

fn registered(issuer: &Issuer) -> Hosted {
    let mut h = booted(issuer);
    h.register(
        H1,
        &issuer.token(H1, P0_SECS - 10, P0_SECS + 3_600),
        Some(50),
        at(0),
    )
    .unwrap();
    h
}

fn entry(h: &mut Hosted, id: u8, now: Now) -> Option<ReportEntry> {
    let entries = h.snapshot_entries();
    let _ = now;
    entries.into_iter().find(|e| e.lease_id == [id; 16])
}

fn statuses(events: &[Event]) -> Vec<LeaseStatus> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Status { entries, .. } => Some(entries.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

// --- Admission (§B.4, §A.9 duties 9 and 10) ---------------------------------

#[test]
fn a_valid_token_registers_and_a_bad_one_is_refused() {
    let issuer = Issuer::new(1);
    let mut h = booted(&issuer);
    let good = issuer.token(H1, P0_SECS - 10, P0_SECS + 3_600);
    assert_eq!(h.register(H1, &good, Some(50), at(0)), Ok(()));
    // A token for another handle.
    assert_eq!(
        h.register(H2, &good, Some(50), at(0)),
        Err(AdmissionRefusal::WrongHandle)
    );
    // Signed by a key the relay does not pin.
    let stranger = Issuer::new(2).token(H1, P0_SECS - 10, P0_SECS + 3_600);
    assert_eq!(
        h.register(H1, &stranger, Some(50), at(0)),
        Err(AdmissionRefusal::Token(RecordError::UnknownIssuer))
    );
    // For another relay.
    let other_relay = {
        let t = AdmissionToken {
            issuer_key_id: issuer_key_id(&issuer.key.public_key()),
            relay_id: [0x99; 32],
            handle: H1,
            not_before: 0,
            not_after: P0_SECS + 3_600,
        };
        SignedEnvelope::sign(t.encode(), &issuer.key).encode()
    };
    assert_eq!(
        h.register(H1, &other_relay, Some(50), at(0)),
        Err(AdmissionRefusal::WrongRelay)
    );
}

#[test]
fn a_hosted_register_needs_a_status_threshold() {
    let issuer = Issuer::new(1);
    let mut h = booted(&issuer);
    let good = issuer.token(H1, P0_SECS - 10, P0_SECS + 3_600);
    for bad in [None, Some(9), Some(91)] {
        assert_eq!(
            h.register(H1, &good, bad, at(0)),
            Err(AdmissionRefusal::Threshold)
        );
    }
    assert_eq!(h.register(H1, &good, Some(10), at(0)), Ok(()));
    assert_eq!(h.register(H1, &good, Some(90), at(0)), Ok(()));
}

#[test]
fn not_before_is_strict_on_the_plus_clock_and_the_same_token_works_later() {
    let issuer = Issuer::new(1);
    let mut h = booted(&issuer);
    // Valid from one second after P0. The wall clock is far ahead, but
    // once the Plus clock is set it is the one that counts.
    let token = issuer.token(H1, P0_SECS + 1, P0_SECS + 3_600);
    let mut now = at(999);
    now.wall = UnixTime(P0_SECS + 100_000);
    assert_eq!(
        h.register(H1, &token, Some(50), now),
        Err(AdmissionRefusal::NotBefore)
    );
    assert_eq!(h.register(H1, &token, Some(50), at(1_000)), Ok(()));
}

#[test]
fn before_the_first_plus_answer_a_token_is_judged_on_the_wall_clock() {
    let issuer = Issuer::new(1);
    let mut h = Hosted::new(RELAY, BOOT, issuer.keys(), HostedLimits::DEFAULT);
    let token = issuer.token(H1, P0_SECS + 5, P0_SECS + 3_600);
    assert_eq!(
        h.register(H1, &token, Some(50), at(0)),
        Err(AdmissionRefusal::NotBefore)
    );
    assert_eq!(h.register(H1, &token, Some(50), at(5_000)), Ok(()));
    // But no LEASE before the boot's first Plus answer (duty 12).
    let refused = h
        .lease(H1, &issuer.block(1, 1, Class::Interactive, MB), at(5_000))
        .unwrap_err();
    assert_eq!(refused.reason, LeaseRefusal::NoPlusClock);
    assert_eq!(refused.status.map(|s| s.state), Some(LeaseState::Refused));
    h.boot_answered(
        &BootAnswer {
            plus_time_ms: P0 + 5_000,
        },
        Millis(5_000),
        at(5_100),
    );
    assert_eq!(
        h.lease(H1, &issuer.block(1, 1, Class::Interactive, MB), at(5_100)),
        Ok(LeaseState::Current)
    );
}

#[test]
fn admit_renews_only_its_own_handle_with_a_valid_token() {
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    assert_eq!(
        h.admit(H1, &issuer.token(H2, P0_SECS, P0_SECS + 7_200), at(0)),
        Err(AdmissionRefusal::WrongHandle)
    );
    assert_eq!(
        h.admit(H1, &issuer.token(H1, P0_SECS - 100, P0_SECS - 1), at(0)),
        Err(AdmissionRefusal::Expired)
    );
    assert_eq!(
        h.admit(H2, &issuer.token(H2, P0_SECS, P0_SECS + 7_200), at(0)),
        Err(AdmissionRefusal::NotRegistered)
    );
    assert_eq!(
        h.admit(H1, &issuer.token(H1, P0_SECS, P0_SECS + 7_200), at(0)),
        Ok(())
    );
    // The renewal keeps the registration past the first token: no 4004 at
    // P0 + 3600 s although the handle holds no block.
    let ev = h.poll(at(3_601_000));
    assert!(!ev.iter().any(|e| matches!(e, Event::CloseHandle { .. })));
    let ev = h.poll(at(7_201_000));
    assert!(ev.contains(&Event::CloseHandle {
        handle: H1,
        code: CLOSE_ADMISSION_EXPIRED
    }));
}

#[test]
fn past_admission_expiry_an_unfunded_registration_closes_with_4004() {
    let issuer = Issuer::new(1);
    let mut h = booted(&issuer);
    h.register(
        H1,
        &issuer.token(H1, P0_SECS - 10, P0_SECS + 60),
        Some(50),
        at(0),
    )
    .unwrap();
    assert!(h.poll(at(60_000)).is_empty());
    assert_eq!(
        h.poll(at(60_001)),
        vec![Event::CloseHandle {
            handle: H1,
            code: CLOSE_ADMISSION_EXPIRED
        }]
    );
}

#[test]
fn past_admission_expiry_a_funded_registration_carries_on_but_takes_no_lease() {
    let issuer = Issuer::new(1);
    let mut h = booted(&issuer);
    h.register(
        H1,
        &issuer.token(H1, P0_SECS - 10, P0_SECS + 60),
        Some(90),
        at(0),
    )
    .unwrap();
    h.lease(
        H1,
        &issuer.block(1, 1, Class::Interactive, 2 * MESSAGE_MAX),
        at(0),
    )
    .unwrap();
    // Past not after: kept, and its circuits still forward.
    let later = at(120_000);
    assert!(!h
        .poll(later)
        .iter()
        .any(|e| matches!(e, Event::CloseHandle { .. })));
    assert_eq!(
        h.forward(
            H1,
            Class::Interactive,
            1,
            Direction::ToTarget,
            60_000,
            later
        ),
        Forward::Go
    );
    // No new LEASE past not after (duty 10).
    let refused = h
        .lease(H1, &issuer.block(2, 2, Class::Interactive, MB), later)
        .unwrap_err();
    assert_eq!(refused.reason, LeaseRefusal::AdmissionExpired);
    // Once the block is spent, the registration and its circuits close.
    assert_eq!(
        h.forward(
            H1,
            Class::Interactive,
            1,
            Direction::ToCaller,
            2 * MESSAGE_MAX - 60_000,
            later
        ),
        Forward::Go
    );
    assert!(h.poll(later).contains(&Event::CloseHandle {
        handle: H1,
        code: CLOSE_ADMISSION_EXPIRED
    }));
}

#[test]
fn a_dropped_registration_comes_back_with_its_expired_token_only_while_funded() {
    let issuer = Issuer::new(1);
    let mut h = booted(&issuer);
    let token = issuer.token(H1, P0_SECS - 10, P0_SECS + 60);
    h.register(H1, &token, Some(50), at(0)).unwrap();
    h.lease(H1, &issuer.block(1, 1, Class::Interactive, MB), at(0))
        .unwrap();
    // The connection drops during a Plus outage, after the token expired.
    h.unregister(&H1);
    assert_eq!(h.register(H1, &token, Some(50), at(120_000)), Ok(()));

    // The same on a handle that holds no usable block is refused.
    let token2 = issuer.token(H2, P0_SECS - 10, P0_SECS + 60);
    h.register(H2, &token2, Some(50), at(0)).unwrap();
    h.unregister(&H2);
    assert_eq!(
        h.register(H2, &token2, Some(50), at(120_000)),
        Err(AdmissionRefusal::Expired)
    );
}

// --- Leases (§B.10, §A.9 duties 6, 9 and 12) -------------------------------

#[test]
fn a_current_and_a_pending_per_class_and_handle_and_no_more() {
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    assert_eq!(
        h.lease(H1, &issuer.block(1, 1, Class::Interactive, MB), at(0)),
        Ok(LeaseState::Current)
    );
    assert_eq!(
        h.lease(H1, &issuer.block(2, 2, Class::Interactive, MB), at(0)),
        Ok(LeaseState::Pending)
    );
    let full = h
        .lease(H1, &issuer.block(3, 3, Class::Interactive, MB), at(0))
        .unwrap_err();
    assert_eq!(full.reason, LeaseRefusal::Full);
    assert_eq!(
        full.status,
        Some(LeaseStatus {
            lease_id: [3; 16],
            class: Class::Interactive,
            used: 0,
            bytes: MB,
            state: LeaseState::Refused
        })
    );
    // The other class has its own pair.
    assert_eq!(
        h.lease(H1, &issuer.block(4, 1, Class::Bulk, MB), at(0)),
        Ok(LeaseState::Current)
    );
}

#[test]
fn a_settled_block_presented_again_is_refused_by_its_sequence() {
    // Vector lease_sequence_replayed; control accept-replayed-lease.
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    let block = issuer.block(1, 1, Class::Interactive, MESSAGE_MAX);
    h.lease(H1, &block, at(0)).unwrap();
    assert_eq!(
        h.forward(
            H1,
            Class::Interactive,
            1,
            Direction::ToTarget,
            MESSAGE_MAX,
            at(0)
        ),
        Forward::Go
    );
    // Plus settles it; the relay forgets it.
    let part = h.next_report_part(at(0)).unwrap();
    h.report_answered(
        part.sequence,
        &ReportAnswer {
            highest_sequence: part.sequence,
            settled: vec![[1; 16]],
            stop: vec![],
            plus_time_ms: P0,
        },
        Millis(0),
        at(1),
    );
    assert_eq!(h.lease_count(), 0);
    let again = h.lease(H1, &block, at(2)).unwrap_err();
    assert_eq!(again.reason, LeaseRefusal::SequenceNotAbove);
}

#[test]
fn a_lower_sequence_never_presented_is_refused_and_a_refused_one_keeps_its_place() {
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    // Sequence 2 refused for not before does not use up its sequence.
    let early = issuer.block_with(|b| {
        b.lease_id = [2; 16];
        b.sequence = 2;
        b.not_before = P0_SECS + 1;
    });
    assert_eq!(
        h.lease(H1, &early, at(0)).unwrap_err().reason,
        LeaseRefusal::NotBefore
    );
    assert_eq!(h.lease(H1, &early, at(1_000)), Ok(LeaseState::Current));
    // Sequence 1, never presented, can never be now.
    assert_eq!(
        h.lease(H1, &issuer.block(1, 1, Class::Interactive, MB), at(1_000))
            .unwrap_err()
            .reason,
        LeaseRefusal::SequenceNotAbove
    );
}

#[test]
fn blocks_for_another_relay_boot_or_handle_are_refused() {
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    type Case = (fn(&mut LeaseBlock), LeaseRefusal);
    let cases: [Case; 6] = [
        (|b| b.relay_id = [0; 32], LeaseRefusal::WrongRelay),
        (|b| b.boot_id = [0; 16], LeaseRefusal::WrongBoot),
        (|b| b.handle = H2, LeaseRefusal::WrongHandle),
        (
            |b| b.rate_cap = RATE_CAP_FLOOR - 1,
            LeaseRefusal::RateCapTooLow,
        ),
        (
            |b| b.expires_at = b.not_before + BLOCK_MAX_LIFETIME_SECS + 1,
            LeaseRefusal::BadWindow,
        ),
        (|b| b.bytes = MESSAGE_MAX - 1, LeaseRefusal::TooSmall),
    ];
    for (edit, want) in cases {
        let env = issuer.block_with(edit);
        assert_eq!(h.lease(H1, &env, at(0)).unwrap_err().reason, want);
    }
    // At the floor exactly is fine.
    let ok = issuer.block_with(|b| b.rate_cap = RATE_CAP_FLOOR);
    assert_eq!(h.lease(H1, &ok, at(0)), Ok(LeaseState::Current));
}

#[test]
fn a_block_past_its_expiry_on_the_plus_clock_is_refused_whatever_the_wall_clock() {
    // Control expiry-on-relay-wall-clock.
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    let block = issuer.block_with(|b| b.expires_at = P0_SECS + 10);
    // Plus time is P0 + 10 s; the relay's wall clock is ten minutes behind.
    let mut now = at(10_000);
    now.wall = UnixTime(P0_SECS + 10 - 600);
    assert_eq!(
        h.lease(H1, &block, now).unwrap_err().reason,
        LeaseRefusal::Expired
    );
}

#[test]
fn a_lease_stops_at_its_expiry_on_the_plus_clock_while_the_wall_clock_lags() {
    // Control expiry-on-relay-wall-clock.
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    let block = issuer.block_with(|b| b.expires_at = P0_SECS + 10);
    h.lease(H1, &block, at(0)).unwrap();
    let mut now = at(10_000);
    now.wall = UnixTime(P0_SECS - 600);
    assert_eq!(
        h.forward(H1, Class::Interactive, 1, Direction::ToTarget, 100, now),
        Forward::Paused
    );
    let ev = h.poll(now);
    assert_eq!(
        statuses(&ev),
        vec![LeaseStatus {
            lease_id: [1; 16],
            class: Class::Interactive,
            used: 0,
            bytes: 4 * MB,
            state: LeaseState::Final
        }]
    );
}

#[test]
fn a_lease_past_admission_expiry_is_refused() {
    // Control ignore-admission-expiry.
    let issuer = Issuer::new(1);
    let mut h = booted(&issuer);
    h.register(
        H1,
        &issuer.token(H1, P0_SECS - 10, P0_SECS + 1),
        Some(50),
        at(0),
    )
    .unwrap();
    assert_eq!(
        h.lease(H1, &issuer.block(1, 1, Class::Interactive, MB), at(1_001))
            .unwrap_err()
            .reason,
        LeaseRefusal::AdmissionExpired
    );
}

#[test]
fn a_reload_changes_the_pinned_keys_without_ending_the_boot() {
    let old = Issuer::new(1);
    let new = Issuer::new(2);
    let mut h = registered(&old);
    h.lease(H1, &old.block(1, 1, Class::Interactive, MB), at(0))
        .unwrap();
    let from_new = new.block(2, 2, Class::Interactive, MB);
    assert_eq!(
        h.lease(H1, &from_new, at(0)).unwrap_err().reason,
        LeaseRefusal::Record(RecordError::UnknownIssuer)
    );
    h.set_issuer_keys(IssuerKeys::new([
        old.key.public_key(),
        new.key.public_key(),
    ]));
    assert_eq!(h.lease(H1, &from_new, at(0)), Ok(LeaseState::Pending));
    assert_eq!(h.boot_id(), BOOT);
}

// --- Counting and splitting (§A.9 duties 3, 5 and 7) -----------------------

#[test]
fn a_message_splits_byte_exactly_across_current_and_pending() {
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    h.lease(H1, &issuer.block(1, 1, Class::Bulk, 2 * MESSAGE_MAX), at(0))
        .unwrap();
    h.lease(H1, &issuer.block(2, 2, Class::Bulk, 2 * MESSAGE_MAX), at(0))
        .unwrap();
    let send = |h: &mut Hosted, d, n| h.forward(H1, Class::Bulk, 7, d, n, at(0));
    assert_eq!(send(&mut h, Direction::ToTarget, 60_000), Forward::Go);
    assert_eq!(send(&mut h, Direction::ToCaller, 60_000), Forward::Go);
    // 11 072 bytes are left on lease 1; this message takes them and
    // 48 928 from lease 2.
    assert_eq!(send(&mut h, Direction::ToTarget, 60_000), Forward::Go);
    let a = entry(&mut h, 1, at(0)).unwrap();
    let b = entry(&mut h, 2, at(0)).unwrap();
    assert_eq!(
        (a.to_target, a.to_caller, a.is_final),
        (71_072, 60_000, true)
    );
    assert_eq!((b.to_target, b.to_caller, b.is_final), (48_928, 0, false));
    let ev = h.poll(at(0));
    let st = statuses(&ev);
    // Threshold (50 %) on lease 1 once, then its final.
    assert_eq!(st.len(), 2, "{st:?}");
    assert_eq!(
        (st[0].lease_id, st[0].state, st[0].used),
        ([1; 16], LeaseState::Current, 120_000)
    );
    assert_eq!(
        (st[1].lease_id, st[1].state, st[1].used),
        ([1; 16], LeaseState::Final, 2 * MESSAGE_MAX)
    );
    assert_eq!(h.statuses(&H1)[0].lease_id, [2; 16]);
    assert_eq!(h.statuses(&H1)[0].state, LeaseState::Current);
}

#[test]
fn the_threshold_status_is_sent_once_per_lease() {
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    h.lease(H1, &issuer.block(1, 1, Class::Interactive, MB), at(0))
        .unwrap();
    for _ in 0..12 {
        h.forward(
            H1,
            Class::Interactive,
            1,
            Direction::ToTarget,
            60_000,
            at(0),
        );
    }
    assert_eq!(statuses(&h.poll(at(0))).len(), 1);
}

// --- Pause and refill (§B.10) ----------------------------------------------

#[test]
fn a_class_pauses_without_cover_and_a_lease_resumes_it() {
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    h.lease(H1, &issuer.block(1, 1, Class::Bulk, MESSAGE_MAX), at(0))
        .unwrap();
    h.forward(H1, Class::Bulk, 1, Direction::ToTarget, 60_000, at(0));
    // 5536 bytes left; the next 10 000-byte message waits.
    assert_eq!(
        h.forward(H1, Class::Bulk, 1, Direction::ToTarget, 10_000, at(0)),
        Forward::Paused
    );
    assert!(!h
        .poll(at(9_999))
        .iter()
        .any(|e| matches!(e, Event::CloseClass { .. })));
    h.lease(H1, &issuer.block(2, 2, Class::Bulk, MESSAGE_MAX), at(9_999))
        .unwrap();
    assert!(h.poll(at(9_999)).contains(&Event::Resumed {
        handle: H1,
        class: Class::Bulk
    }));
    assert_eq!(
        h.forward(H1, Class::Bulk, 1, Direction::ToTarget, 10_000, at(9_999)),
        Forward::Go
    );
    assert_eq!(entry(&mut h, 1, at(0)).unwrap().to_target, MESSAGE_MAX);
    assert_eq!(entry(&mut h, 2, at(0)).unwrap().to_target, 4_464);
    // The refill wait has been reset: nothing closes later.
    assert!(!h
        .poll(at(30_000))
        .iter()
        .any(|e| matches!(e, Event::CloseClass { .. })));
}

#[test]
fn without_a_refill_the_class_closes_with_4001_and_the_other_class_carries_on() {
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    h.lease(H1, &issuer.block(1, 1, Class::Bulk, MESSAGE_MAX), at(0))
        .unwrap();
    h.lease(H1, &issuer.block(2, 1, Class::Interactive, MB), at(0))
        .unwrap();
    h.forward(H1, Class::Bulk, 1, Direction::ToTarget, 60_000, at(0));
    assert_eq!(
        h.forward(H1, Class::Bulk, 1, Direction::ToTarget, 10_000, at(1_000)),
        Forward::Paused
    );
    assert_eq!(h.next_wakeup(at(1_000)), Some(Millis(11_000)));
    let ev = h.poll(at(11_000));
    assert!(ev.contains(&Event::CloseClass {
        handle: H1,
        class: Class::Bulk,
        code: CLOSE_LEASE_EXHAUSTED
    }));
    // The current lease is final with what it forwarded.
    let st: Vec<LeaseStatus> = statuses(&ev)
        .into_iter()
        .filter(|s| s.state == LeaseState::Final)
        .collect();
    assert_eq!(st.len(), 1);
    assert_eq!(
        (st[0].lease_id, st[0].used, st[0].state),
        ([1; 16], 60_000, LeaseState::Final)
    );
    let e = entry(&mut h, 1, at(0)).unwrap();
    assert_eq!((e.to_target, e.is_final), (60_000, true));
    // Interactive is untouched.
    assert_eq!(
        h.forward(
            H1,
            Class::Interactive,
            2,
            Direction::ToCaller,
            1_000,
            at(11_000)
        ),
        Forward::Go
    );
}

// --- Rate (§A.9 duty 8) ----------------------------------------------------

#[test]
fn parallel_sockets_share_their_group_rate() {
    // Control per-socket-rate.
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    let cap = RATE_CAP_FLOOR;
    let block = issuer.block_with(|b| {
        b.class = Class::Bulk;
        b.rate_cap = cap;
        b.bytes = 64 * MB;
    });
    h.lease(H1, &block, at(0)).unwrap();
    // Two sockets push as fast as they may for 10 s.
    let mut forwarded = 0u64;
    let mut ms = 0;
    while ms <= 10_000 {
        for circuit in [1, 2] {
            if h.forward(
                H1,
                Class::Bulk,
                circuit,
                Direction::ToTarget,
                16_384,
                at(ms),
            ) == Forward::Go
            {
                forwarded += 16_384;
            }
        }
        ms += 1;
    }
    // At most cap × (T + 1) over T = 10 s.
    assert!(forwarded <= cap * 11, "{forwarded} > {}", cap * 11);
    assert!(forwarded >= cap * 10, "{forwarded}");
}

#[test]
fn a_short_bucket_asks_the_leg_to_wait() {
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    let block = issuer.block_with(|b| b.rate_cap = RATE_CAP_FLOOR);
    h.lease(H1, &block, at(0)).unwrap();
    assert_eq!(
        h.forward(
            H1,
            Class::Interactive,
            1,
            Direction::ToTarget,
            MESSAGE_MAX,
            at(0)
        ),
        Forward::Go
    );
    // Empty now; a full message needs a whole second at 65 536 B/s.
    assert_eq!(
        h.forward(
            H1,
            Class::Interactive,
            2,
            Direction::ToTarget,
            MESSAGE_MAX,
            at(0)
        ),
        Forward::Wait {
            until: Millis(1_000)
        }
    );
    assert_eq!(
        h.forward(
            H1,
            Class::Interactive,
            2,
            Direction::ToTarget,
            MESSAGE_MAX,
            at(1_000)
        ),
        Forward::Go
    );
}

#[test]
fn the_cap_of_the_block_accepted_last_applies_to_its_group() {
    // Vector rate_group_cap_latest.
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    let fast = issuer.block_with(|b| {
        b.rate_cap = 4 * RATE_CAP_FLOOR;
        b.bytes = 64 * MB;
    });
    h.lease(H1, &fast, at(0)).unwrap();
    let slow = issuer.block_with(|b| {
        b.lease_id = [2; 16];
        b.sequence = 2;
        b.rate_cap = RATE_CAP_FLOOR;
        b.bytes = 64 * MB;
    });
    h.lease(H1, &slow, at(0)).unwrap();
    // The bucket now holds at most one second at the lower cap.
    assert_eq!(
        h.forward(
            H1,
            Class::Interactive,
            1,
            Direction::ToTarget,
            MESSAGE_MAX,
            at(0)
        ),
        Forward::Go
    );
    assert!(matches!(
        h.forward(H1, Class::Interactive, 1, Direction::ToTarget, 1, at(0)),
        Forward::Wait { .. }
    ));
}

// --- Release (§B.10) -------------------------------------------------------

#[test]
fn release_makes_leases_final_and_only_for_their_own_handle() {
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    h.register(
        H2,
        &issuer.token(H2, P0_SECS - 10, P0_SECS + 3_600),
        Some(50),
        at(0),
    )
    .unwrap();
    h.lease(H1, &issuer.block(1, 1, Class::Interactive, MB), at(0))
        .unwrap();
    h.lease(H1, &issuer.block(2, 2, Class::Interactive, MB), at(0))
        .unwrap();
    let other = issuer.block_with(|b| {
        b.lease_id = [9; 16];
        b.handle = H2;
    });
    h.lease(H2, &other, at(0)).unwrap();
    h.forward(H1, Class::Interactive, 1, Direction::ToTarget, 1_000, at(0));
    h.poll(at(0));
    // Naming another handle's lease changes nothing.
    assert_eq!(
        h.release(H1, &[[1; 16], [9; 16]], at(0)),
        Err(ReleaseRefusal::OtherHandle)
    );
    assert_eq!(
        h.release(H1, &[[1; 16]; 5], at(0)),
        Err(ReleaseRefusal::TooMany)
    );
    assert!(h.poll(at(0)).is_empty());
    // Releasing the current: final with its counters; the pending takes over.
    assert_eq!(h.release(H1, &[[1; 16], [0x77; 16]], at(0)), Ok(()));
    let st = statuses(&h.poll(at(0)));
    assert_eq!(st.len(), 1);
    assert_eq!(
        (st[0].lease_id, st[0].used, st[0].state),
        ([1; 16], 1_000, LeaseState::Final)
    );
    assert_eq!(h.statuses(&H1)[0].lease_id, [2; 16]);
    assert!(h.can_call(&H1, Class::Interactive, at(0)));
    assert_eq!(h.release(H1, &[[2; 16]], at(0)), Ok(()));
    assert!(!h.can_call(&H1, Class::Interactive, at(0)));
}

// --- Stopping (§A.9 duty 11) -----------------------------------------------

#[test]
fn a_stop_makes_every_lease_final_and_sends_a_stopping_snapshot() {
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    h.lease(H1, &issuer.block(1, 1, Class::Interactive, MB), at(0))
        .unwrap();
    h.forward(H1, Class::Interactive, 1, Direction::ToTarget, 500, at(0));
    // A heartbeat goes first.
    let first = h.next_report_part(at(0)).unwrap();
    h.stop(at(10));
    assert_eq!(
        h.forward(H1, Class::Interactive, 1, Direction::ToTarget, 1, at(10)),
        Forward::Stopped
    );
    assert_eq!(
        h.lease(H1, &issuer.block(2, 2, Class::Interactive, MB), at(10))
            .unwrap_err()
            .reason,
        LeaseRefusal::Stopping
    );
    // The part in flight is still sent first, then the stopping snapshot.
    assert_eq!(h.next_report_part(at(10)), Some(first.clone()));
    answer(&mut h, &first, &[]);
    let last = h.next_report_part(at(11)).unwrap();
    assert_eq!(last.boot_state, BootState::Stopping);
    assert_eq!(last.sequence, first.sequence + 1);
    assert_eq!(
        last.entries,
        vec![ReportEntry {
            lease_id: [1; 16],
            to_target: 500,
            to_caller: 0,
            is_final: true
        }]
    );
    assert!(!h.stop_reported());
    answer(&mut h, &last, &[]);
    assert!(h.stop_reported());
    assert_eq!(h.next_report_part(at(60_000)), None);
}

// --- Reports (§A.9 duty 4, §A.12) ------------------------------------------

fn answer(h: &mut Hosted, part: &ReportPart, settled: &[LeaseId]) {
    h.report_answered(
        part.sequence,
        &ReportAnswer {
            highest_sequence: part.sequence,
            settled: settled.to_vec(),
            stop: vec![],
            plus_time_ms: P0,
        },
        Millis(0),
        at(0),
    );
}

#[test]
fn no_report_before_plus_has_answered_the_boot() {
    let issuer = Issuer::new(1);
    let mut h = Hosted::new(RELAY, BOOT, issuer.keys(), HostedLimits::DEFAULT);
    assert_eq!(h.next_report_part(at(60_000)), None);
    assert_eq!(h.report_due(at(60_000)), None);
}

#[test]
fn an_empty_snapshot_is_one_heartbeat_part_every_report_interval() {
    let issuer = Issuer::new(1);
    let mut h = booted(&issuer);
    let p = h.next_report_part(at(0)).unwrap();
    assert_eq!((p.sequence, p.snapshot, p.part_count), (1, 1, 1));
    assert!(p.entries.is_empty());
    assert_eq!(p.sent_at, P0_SECS);
    // Sent again, the same, until stored.
    assert_eq!(h.next_report_part(at(500)), Some(p.clone()));
    answer(&mut h, &p, &[]);
    assert_eq!(h.next_report_part(at(9_999)), None);
    assert_eq!(h.report_due(at(5_000)), Some(Millis(10_000)));
    let p2 = h.next_report_part(at(10_000)).unwrap();
    assert_eq!((p2.sequence, p2.snapshot), (2, 2));
}

#[test]
fn a_large_snapshot_splits_into_parts_in_lease_id_order() {
    let issuer = Issuer::new(1);
    let mut h = booted(&issuer);
    // 2 500 leases, put straight into the book (signing 2 500 blocks is
    // slow in a debug build and proves nothing more here).
    for i in 0..2_500u32 {
        let mut handle = [0u8; 32];
        handle[..4].copy_from_slice(&i.to_be_bytes());
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&(2_500 - i).to_be_bytes());
        h.leases.insert(
            id,
            Lease {
                handle,
                class: Class::Bulk,
                rate_group: GROUP,
                bytes: MB,
                not_before_ms: 0,
                expires_ms: P0 + 3_600_000,
                to_target: u64::from(i),
                to_caller: 0,
                final_reason: None,
                threshold_sent: false,
            },
        );
    }
    let mut parts = Vec::new();
    while let Some(p) = h.next_report_part(at(0)) {
        answer(&mut h, &p, &[]);
        parts.push(p);
    }
    assert_eq!(parts.len(), 3);
    let counts: Vec<usize> = parts.iter().map(|p| p.entries.len()).collect();
    assert_eq!(counts, vec![1_024, 1_024, 452]);
    for (i, p) in parts.iter().enumerate() {
        assert_eq!(p.sequence, 1 + i as u64);
        assert_eq!((p.snapshot, p.part_count), (1, 3));
    }
    let ids: Vec<LeaseId> = parts
        .iter()
        .flat_map(|p| p.entries.iter().map(|e| e.lease_id))
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
    for p in &parts {
        let env = SignedEnvelope::sign(p.encode(), &issuer.key).encode();
        assert!(env.len() <= records::REPORT_MAX);
    }
}

#[test]
fn finals_close_together_share_one_snapshot_taken_soon_after() {
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    for (id, seq) in [(1u8, 1u64), (2, 2)] {
        h.lease(H1, &issuer.block(id, seq, Class::Interactive, MB), at(0))
            .unwrap();
    }
    let p = h.next_report_part(at(0)).unwrap();
    answer(&mut h, &p, &[]);
    // Two finals 300 ms apart, both within REPORT_MIN_MS of the last
    // snapshot: one snapshot at 1000 ms holds both.
    h.release(H1, &[[1; 16]], at(200)).unwrap();
    h.release(H1, &[[2; 16]], at(500)).unwrap();
    assert_eq!(h.report_due(at(500)), Some(Millis(1_000)));
    assert_eq!(h.next_report_part(at(999)), None);
    let p = h.next_report_part(at(1_000)).unwrap();
    assert!(p.entries.iter().all(|e| e.is_final));
    assert_eq!(p.entries.len(), 2);
    // Settled leases are listed no more.
    answer(&mut h, &p, &[[1; 16], [2; 16]]);
    assert_eq!(h.lease_count(), 0);
    let p = h.next_report_part(at(11_000)).unwrap();
    assert!(p.entries.is_empty());
}

#[test]
fn a_final_long_after_the_last_snapshot_is_reported_at_once() {
    let issuer = Issuer::new(1);
    let mut h = registered(&issuer);
    h.lease(H1, &issuer.block(1, 1, Class::Interactive, MB), at(0))
        .unwrap();
    let p = h.next_report_part(at(0)).unwrap();
    answer(&mut h, &p, &[]);
    h.release(H1, &[[1; 16]], at(5_000)).unwrap();
    assert_eq!(h.report_due(at(5_000)), Some(Millis(5_000)));
    assert!(h.next_report_part(at(5_000)).unwrap().entries[0].is_final);
}

#[test]
fn snapshots_taken_during_an_outage_replace_each_other_without_gaps() {
    let issuer = Issuer::new(1);
    let mut h = booted(&issuer);
    let first = h.next_report_part(at(0)).unwrap();
    // Plus does not answer; two more snapshots are taken meanwhile.
    for t in [10_000, 20_000] {
        h.report_tick(at(t));
        assert_eq!(h.next_report_part(at(t)), Some(first.clone()));
    }
    answer(&mut h, &first, &[]);
    let next = h.next_report_part(at(20_001)).unwrap();
    assert_eq!(next.sequence, 2);
    answer(&mut h, &next, &[]);
    assert_eq!(h.next_report_part(at(20_002)), None);
}

#[test]
fn a_report_answer_sets_the_plus_clock_only_from_a_quick_round_trip() {
    let issuer = Issuer::new(1);
    let mut h = Hosted::new(RELAY, BOOT, issuer.keys(), HostedLimits::DEFAULT);
    // A slow boot answer acknowledges the boot but sets no clock.
    h.boot_answered(&BootAnswer { plus_time_ms: P0 }, Millis(0), at(2_001));
    assert!(!h.clock().is_set());
    let p = h.next_report_part(at(2_001)).unwrap();
    // Before the clock is set, sent at is the wall clock.
    assert_eq!(p.sent_at, (P0 + 2_001) / 1_000);
    h.report_answered(
        p.sequence,
        &ReportAnswer {
            highest_sequence: 1,
            settled: vec![],
            stop: vec![],
            plus_time_ms: P0 + 2_100,
        },
        Millis(2_001),
        at(2_101),
    );
    assert_eq!(h.clock().now_ms(Millis(2_101)), Some(P0 + 2_200));
}

#[test]
fn limits_agree() {
    assert!(HostedLimits::DEFAULT
        .with_overrides(&[("RELAY_REPORT_MIN_MS", 5_000), ("RELAY_REPORT_MS", 5_000)])
        .is_err());
    assert!(HostedLimits::DEFAULT
        .with_overrides(&[("RELAY_REFILL_WAIT_MS", 10_001)])
        .is_err());
    assert!(HostedLimits::DEFAULT
        .with_overrides(&[
            ("RELAY_PLUS_RETRY_FIRST_MS", 2_000),
            ("RELAY_PLUS_RETRY_MAX_MS", 1_000)
        ])
        .is_err());
}
