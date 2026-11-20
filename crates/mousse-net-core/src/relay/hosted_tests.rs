//! The relay machine in hosted mode (`docs/phase34-design.md` §B.4, §B.6,
//! §B.10, §A.9): admission tokens on `REGISTER`, an unfunded class refused
//! like any other refusal, leases counted on every spliced message, pause
//! and refill, 4001, 4004 and `RELEASE`. Tokens and blocks are signed with
//! a throwaway issuer key.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use super::machine::{close, ConnId, IpKey, Now, Output, Relay, RelayConfig};
use super::msg::{Class, Mode, RefuseReason, RelayMessage};
use super::proof::{Binding, RelayClientKey, RelayId};
use super::RelayLimits;
use crate::identity::SoftwareKey;
use crate::relay_hosted::records::issuer_key_id;
use crate::relay_hosted::{
    AdmissionToken, BootAnswer, Hosted, HostedLimits, IssuerKeys, LeaseBlock, SignedEnvelope,
};
use crate::time::{Millis, UnixTime};

const BOOT: [u8; 16] = [0x22; 16];
/// Plus time when the boot is answered, Unix ms.
const P0: u64 = 1_700_000_000_000;
const P0_SECS: u64 = P0 / 1_000;

fn soft(seed: u8) -> SoftwareKey {
    SoftwareKey::generate(&mut ChaCha20Rng::from_seed([seed; 32]))
}

fn at(ms: u64) -> Now {
    Now {
        mono: Millis(ms),
        wall: UnixTime((P0 + ms) / 1_000),
    }
}

struct World {
    relay: Relay,
    id: RelayId,
    issuer: SoftwareKey,
    rng: ChaCha20Rng,
    bindings: std::collections::BTreeMap<u64, Binding>,
}

impl World {
    fn new() -> Self {
        let relay_key = soft(1);
        let id = RelayId::of(&relay_key.public_key());
        let issuer = soft(2);
        let mut hosted = Hosted::new(
            id.0,
            BOOT,
            IssuerKeys::new([issuer.public_key()]),
            HostedLimits::DEFAULT,
        );
        hosted.boot_answered(&BootAnswer { plus_time_ms: P0 }, Millis(0), at(0));
        let relay = Relay::new_hosted(
            RelayConfig {
                relay_key: relay_key.public_key(),
                boot_id: BOOT,
                limits: RelayLimits::DEFAULT,
            },
            hosted,
        );
        Self {
            relay,
            id,
            issuer,
            rng: ChaCha20Rng::from_seed([9; 32]),
            bindings: Default::default(),
        }
    }

    fn open(&mut self, t: u64, conn: u64) -> Vec<Output> {
        let exporter = [conn as u8; 32];
        let outs = self.relay.open(
            ConnId(conn),
            IpKey([conn as u8; 16]),
            exporter,
            at(t),
            &mut self.rng,
        );
        if let Some(RelayMessage::Hello { nonce, mode, .. }) = sent(&outs, conn) {
            assert_eq!(mode, Mode::Hosted);
            self.bindings.insert(conn, Binding { nonce, exporter });
        }
        outs
    }

    fn send(&mut self, t: u64, conn: u64, msg: &RelayMessage) -> Vec<Output> {
        self.relay
            .receive(ConnId(conn), &msg.encode(), at(t), &mut self.rng)
    }

    fn data(&mut self, t: u64, conn: u64, len: usize) -> Vec<Output> {
        self.relay.data(ConnId(conn), len, at(t), &mut self.rng)
    }

    fn tick(&mut self, t: u64) -> Vec<Output> {
        self.relay.tick(at(t), &mut self.rng)
    }

    fn token(&self, handle: [u8; 32], not_after: u64) -> Vec<u8> {
        let t = AdmissionToken {
            issuer_key_id: issuer_key_id(&self.issuer.public_key()),
            relay_id: self.id.0,
            handle,
            not_before: P0_SECS - 10,
            not_after,
        };
        SignedEnvelope::sign(t.encode(), &self.issuer).encode()
    }

    fn block(
        &self,
        handle: [u8; 32],
        id: u8,
        seq: u64,
        class: Class,
        bytes: u64,
        cap: u64,
    ) -> Vec<u8> {
        let b = LeaseBlock {
            issuer_key_id: issuer_key_id(&self.issuer.public_key()),
            lease_id: [id; 16],
            relay_id: self.id.0,
            boot_id: BOOT,
            handle,
            class,
            sequence: seq,
            rate_cap: cap,
            bytes,
            not_before: P0_SECS - 10,
            expires_at: P0_SECS + 3_600,
            rate_group: [7; 16],
        };
        SignedEnvelope::sign(b.encode(), &self.issuer).encode()
    }

    /// Register `k` on connection `conn` with a token valid until
    /// `not_after`.
    fn register(&mut self, t: u64, conn: u64, k: &RelayClientKey, not_after: u64) -> Vec<Output> {
        self.open(t, conn);
        let handle = k.handle(&self.id);
        let msg = RelayMessage::Register {
            key: k.public_key(),
            proof: k.register_proof(&self.id, &self.bindings[&conn]),
            hosted: Some((self.token(handle, not_after), 50)),
        };
        self.send(t, conn, &msg)
    }

    fn allow(&mut self, t: u64, reg: u64, caller: &RelayClientKey) {
        let msg = RelayMessage::AllowSet {
            sequence: t + 1,
            callers: vec![caller.fingerprint()],
            invitations: vec![],
        };
        self.send(t, reg, &msg);
    }

    fn call(
        &mut self,
        t: u64,
        conn: u64,
        caller: &RelayClientKey,
        handle: [u8; 32],
        class: Class,
    ) -> Vec<Output> {
        self.open(t, conn);
        let msg = RelayMessage::Call {
            handle,
            key: caller.public_key(),
            proof: caller.call_proof(&self.id, &handle, &self.bindings[&conn], class),
            class,
        };
        self.send(t, conn, &msg)
    }

    #[allow(clippy::too_many_arguments)]
    /// A spliced circuit of `class`: caller leg `leg`, accept leg `acc`.
    fn splice(
        &mut self,
        t: u64,
        reg: u64,
        target: &RelayClientKey,
        caller: &RelayClientKey,
        leg: u64,
        acc: u64,
        class: Class,
    ) {
        let handle = target.handle(&self.id);
        let outs = self.call(t, leg, caller, handle, class);
        let circuit = match sent(&outs, reg) {
            Some(RelayMessage::Incoming { circuit, .. }) => circuit,
            other => panic!("no INCOMING: {other:?}"),
        };
        self.open(t, acc);
        let msg = RelayMessage::Accept {
            handle,
            circuit,
            proof: target.accept_proof(&self.id, &circuit, &self.bindings[&acc]),
        };
        let outs = self.send(t, acc, &msg);
        assert!(
            outs.iter().any(|o| matches!(o, Output::Splice { .. })),
            "{outs:?}"
        );
    }
}

fn sent(outs: &[Output], conn: u64) -> Option<RelayMessage> {
    outs.iter().find_map(|o| match o {
        Output::Send { conn: c, message } if c.0 == conn => RelayMessage::decode(message).ok(),
        _ => None,
    })
}

fn closed(outs: &[Output], conn: u64) -> Option<u16> {
    outs.iter().find_map(|o| match o {
        Output::Close { conn: c, code } if c.0 == conn => Some(*code),
        _ => None,
    })
}

fn forwarded(outs: &[Output]) -> bool {
    outs.iter().any(|o| matches!(o, Output::Forward { .. }))
}

fn statuses(outs: &[Output], conn: u64) -> Vec<(u8, u64, u8)> {
    outs.iter()
        .filter_map(|o| match o {
            Output::Send { conn: c, message } if c.0 == conn => match RelayMessage::decode(message)
            {
                Ok(RelayMessage::LeaseStatus { entries }) => Some(entries),
                _ => None,
            },
            _ => None,
        })
        .flatten()
        .map(|e| (e.lease[0], e.used, e.state))
        .collect()
}

fn keys() -> (RelayClientKey, RelayClientKey) {
    (
        RelayClientKey::new(soft(0x61)),
        RelayClientKey::new(soft(0x71)),
    )
}

#[test]
fn a_hosted_register_needs_a_valid_token_for_its_handle() {
    let (target, other) = keys();
    let mut w = World::new();
    // Without the hosted keys it is a protocol error.
    w.open(0, 1);
    let plain = RelayMessage::Register {
        key: target.public_key(),
        proof: target.register_proof(&w.id, &w.bindings[&1]),
        hosted: None,
    };
    assert_eq!(closed(&w.send(0, 1, &plain), 1), Some(close::PROTOCOL));
    // A token for another handle is refused.
    w.open(0, 2);
    let msg = RelayMessage::Register {
        key: target.public_key(),
        proof: target.register_proof(&w.id, &w.bindings[&2]),
        hosted: Some((w.token(other.handle(&w.id), P0_SECS + 3_600), 50)),
    };
    let outs = w.send(0, 2, &msg);
    assert_eq!(
        sent(&outs, 2),
        Some(RelayMessage::Refused {
            reason: RefuseReason::Admission
        })
    );
    // Its own token registers.
    let outs = w.register(0, 3, &target, P0_SECS + 3_600);
    assert!(matches!(
        sent(&outs, 3),
        Some(RelayMessage::Registered { .. })
    ));
}

#[test]
fn an_unfunded_class_is_refused_like_any_refusal_and_a_lease_funds_it() {
    let (target, caller) = keys();
    let mut w = World::new();
    w.register(0, 1, &target, P0_SECS + 3_600);
    w.allow(0, 1, &caller);
    let h = target.handle(&w.id);
    // No lease: no INCOMING; UNREACHABLE at the refusal deadline only.
    let outs = w.call(0, 2, &caller, h, Class::Bulk);
    assert_eq!(sent(&outs, 1), None);
    assert_eq!(sent(&w.tick(499), 2), None);
    assert_eq!(sent(&w.tick(500), 2), Some(RelayMessage::Unreachable));
    // A bulk lease funds bulk only.
    w.send(
        600,
        1,
        &RelayMessage::Lease {
            block: w.block(h, 1, 1, Class::Bulk, 1 << 20, 1 << 24),
        },
    );
    let outs = w.call(600, 3, &caller, h, Class::Interactive);
    assert_eq!(sent(&outs, 1), None);
    let outs = w.call(600, 4, &caller, h, Class::Bulk);
    assert!(matches!(
        sent(&outs, 1),
        Some(RelayMessage::Incoming { .. })
    ));
}

#[test]
fn a_refused_lease_is_answered_with_state_3() {
    let (target, _) = keys();
    let mut w = World::new();
    w.register(0, 1, &target, P0_SECS + 3_600);
    let h = target.handle(&w.id);
    // Below the rate-cap floor.
    let outs = w.send(
        0,
        1,
        &RelayMessage::Lease {
            block: w.block(h, 1, 1, Class::Bulk, 1 << 20, 65_535),
        },
    );
    assert_eq!(statuses(&outs, 1), vec![(1, 0, 3)]);
    // Accepted leases get no answer.
    let outs = w.send(
        0,
        1,
        &RelayMessage::Lease {
            block: w.block(h, 2, 1, Class::Bulk, 1 << 20, 65_536),
        },
    );
    assert!(statuses(&outs, 1).is_empty());
}

#[test]
fn a_leg_pauses_without_cover_resumes_on_a_lease_and_closes_with_4001_without() {
    let (target, caller) = keys();
    let mut w = World::new();
    w.register(0, 1, &target, P0_SECS + 3_600);
    w.allow(0, 1, &caller);
    let h = target.handle(&w.id);
    w.send(
        0,
        1,
        &RelayMessage::Lease {
            block: w.block(h, 1, 1, Class::Bulk, 65_536, 1 << 24),
        },
    );
    w.splice(0, 1, &target, &caller, 2, 3, Class::Bulk);
    assert!(forwarded(&w.data(10, 2, 60_000)));
    // 5 536 bytes left: the next 10 000 bytes wait.
    let outs = w.data(20, 2, 10_000);
    assert!(!forwarded(&outs));
    assert!(outs.contains(&Output::Pause { conn: ConnId(2) }));
    // A refill resumes both legs, and the message splits across the leases.
    let outs = w.send(
        30,
        1,
        &RelayMessage::Lease {
            block: w.block(h, 2, 2, Class::Bulk, 65_536, 1 << 24),
        },
    );
    assert!(outs.contains(&Output::Resume { conn: ConnId(2) }));
    assert!(outs.contains(&Output::Resume { conn: ConnId(3) }));
    let outs = w.data(30, 2, 10_000);
    assert!(forwarded(&outs));
    assert_eq!(statuses(&outs, 1), vec![(1, 65_536, 2)]);
    // Lease 2 has 61 072 left; pause again and let the refill wait pass.
    assert!(forwarded(&w.data(40, 3, 61_000)));
    assert!(w
        .data(50, 3, 100)
        .contains(&Output::Pause { conn: ConnId(3) }));
    let outs = w.tick(50 + 9_999);
    assert_eq!(closed(&outs, 2), None);
    let outs = w.tick(50 + 10_000);
    assert_eq!(closed(&outs, 2), Some(close::LEASE_EXHAUSTED));
    assert_eq!(closed(&outs, 3), Some(close::LEASE_EXHAUSTED));
    // The current lease is final with what it forwarded; the registration
    // stays.
    assert_eq!(statuses(&outs, 1), vec![(2, 4_464 + 61_000, 2)]);
    assert_eq!(closed(&outs, 1), None);
}

#[test]
fn a_short_rate_bucket_holds_the_leg() {
    let (target, caller) = keys();
    let mut w = World::new();
    w.register(0, 1, &target, P0_SECS + 3_600);
    w.allow(0, 1, &caller);
    let h = target.handle(&w.id);
    w.send(
        0,
        1,
        &RelayMessage::Lease {
            block: w.block(h, 1, 1, Class::Interactive, 1 << 20, 65_536),
        },
    );
    w.splice(0, 1, &target, &caller, 2, 3, Class::Interactive);
    assert!(forwarded(&w.data(0, 2, 65_536)));
    assert_eq!(
        w.data(0, 3, 1_000),
        vec![Output::Hold {
            conn: ConnId(3),
            until: Millis(16)
        }]
    );
    assert!(forwarded(&w.data(16, 3, 1_000)));
}

#[test]
fn past_its_token_a_funded_registration_carries_on_and_closes_with_4004_when_unfunded() {
    let (target, caller) = keys();
    let mut w = World::new();
    w.register(0, 1, &target, P0_SECS + 60);
    w.allow(0, 1, &caller);
    let h = target.handle(&w.id);
    w.send(
        0,
        1,
        &RelayMessage::Lease {
            block: w.block(h, 1, 1, Class::Interactive, 1 << 20, 1 << 24),
        },
    );
    w.splice(0, 1, &target, &caller, 2, 3, Class::Interactive);
    // Keep the registration and circuit active, then go past not after
    // (P0 + 60 s): funded, they carry on.
    w.send(40_000, 1, &RelayMessage::Ping { data: [0; 8] });
    assert!(forwarded(&w.data(40_000, 2, 1_000)));
    let outs = w.tick(61_000);
    assert_eq!(closed(&outs, 1), None);
    assert!(forwarded(&w.data(61_000, 2, 1_000)));
    // RELEASE leaves it unfunded: registration and circuit close with 4004.
    let outs = w.send(
        61_001,
        1,
        &RelayMessage::Release {
            leases: vec![[1; 16]],
        },
    );
    assert_eq!(closed(&outs, 1), Some(close::ADMISSION_EXPIRED));
    assert_eq!(closed(&outs, 2), Some(close::ADMISSION_EXPIRED));
    assert_eq!(closed(&outs, 3), Some(close::ADMISSION_EXPIRED));
}

#[test]
fn hosted_messages_are_protocol_errors_in_self_mode() {
    let (target, _) = keys();
    let relay_key = soft(1);
    let id = RelayId::of(&relay_key.public_key());
    let mut relay = Relay::new(
        RelayConfig {
            relay_key: relay_key.public_key(),
            boot_id: BOOT,
            limits: RelayLimits::DEFAULT,
        },
        &[super::machine::AuthorizedKey::listed(target.fingerprint())],
        &[],
    );
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let outs = relay.open(ConnId(1), IpKey([1; 16]), [1; 32], at(0), &mut rng);
    let Some(RelayMessage::Hello { nonce, mode, .. }) = sent(&outs, 1) else {
        panic!("no hello")
    };
    assert_eq!(mode, Mode::SelfHosted);
    let binding = Binding {
        nonce,
        exporter: [1; 32],
    };
    let reg = RelayMessage::Register {
        key: target.public_key(),
        proof: target.register_proof(&id, &binding),
        hosted: None,
    };
    relay.receive(ConnId(1), &reg.encode(), at(0), &mut rng);
    let outs = relay.receive(
        ConnId(1),
        &RelayMessage::Lease { block: vec![1] }.encode(),
        at(0),
        &mut rng,
    );
    assert_eq!(closed(&outs, 1), Some(close::PROTOCOL));
}
