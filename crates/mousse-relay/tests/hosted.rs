//! `phase4.relay-leases` over real connections on loopback: a hosted relay
//! against the test issuer stand-in (`docs/phase34-design.md` §G.2, §B.10,
//! §A.9). Leases are counted byte-exactly across current and pending; a
//! paused class resumes on a refill with both peers still connected, or
//! closes with 4001 with its lease final; parallel sockets share their rate
//! group; refused blocks are answered; past admission expiry a funded
//! registration and its circuits carry on, a dropped one registers again
//! with its expired token, and an unfunded one closes with 4004; a stop
//! reports every lease final.

mod common;

#[path = "../../mousse-relay-plus/tests/support/test_issuer_standin.rs"]
mod test_issuer_standin;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{key, next, temp_dir, WAIT};
use mousse_net_core::relay::{Class, RefuseReason, RelayClientKey, RelayId, RelayMessage};
use mousse_net_core::relay_hosted::{BootState, HostedLimits};
use mousse_net_io::ManualClock;
use mousse_relay::client::{Received, RelayConn};
use mousse_relay::server::{self, HostedConfig, Running, ServerConfig, ISSUER_KEYS_FILE};
use mousse_relay::state::{hex, StateDir};
use mousse_relay_plus::settings::{HostedSettings, PlusUrl};
use test_issuer_standin::{BlockSpec, TestIssuerStandIn};

struct Hosted {
    plus: TestIssuerStandIn,
    clock: Arc<ManualClock>,
    path: PathBuf,
    relay: Option<Running>,
    id: RelayId,
}

impl Drop for Hosted {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl Hosted {
    async fn start(tag: &str, seed: u8, hosted: &[(&str, u64)]) -> Self {
        let path = temp_dir(tag);
        let dir = StateDir::init(&path, "127.0.0.1:443", &mut mousse_relay::os_rng()).unwrap();
        let plus = TestIssuerStandIn::start(seed).await;
        std::fs::write(
            path.join(ISSUER_KEYS_FILE),
            format!(
                "# test issuer\n{}\n",
                hex(plus.issuer_public_key().as_bytes())
            ),
        )
        .unwrap();
        let report = mousse_relay_plus::state::report_key(&path).unwrap();
        let id = dir.relay_id().unwrap();
        plus.add_relay(id.0, report.public_key());
        let mut overrides = vec![
            ("RELAY_REPORT_MS", 1_000),
            ("RELAY_REPORT_MIN_MS", 100),
            ("RELAY_PLUS_RETRY_FIRST_MS", 100),
            ("RELAY_PLUS_RETRY_MAX_MS", 1_000),
            ("RELAY_FINAL_REPORT_WAIT_MS", 2_000),
            ("RELAY_PLUS_TIMEOUT_MS", 2_000),
        ];
        overrides.extend_from_slice(hosted);
        let limits = HostedLimits::DEFAULT.with_overrides(&overrides).unwrap();
        let clock = Arc::new(ManualClock::new());
        let relay = server::start_with_clock(
            ServerConfig {
                state: dir,
                listen: "127.0.0.1:0".parse().unwrap(),
                limits: common::limits(&[]),
                hosted: Some(HostedConfig {
                    settings: HostedSettings {
                        plus_url: PlusUrl::parse(&plus.url()).unwrap(),
                        limits,
                    },
                    build_id: "mousse-relay test".into(),
                }),
            },
            clock.clone(),
        )
        .await
        .unwrap();
        let h = Self {
            plus,
            clock,
            path,
            relay: Some(relay),
            id,
        };
        // Boot acknowledged: the first heartbeat has arrived.
        let start = Instant::now();
        while h.plus.parts().is_empty() {
            assert!(start.elapsed() < WAIT, "no heartbeat");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        h
    }

    async fn dial(&self) -> RelayConn {
        let addr = self.relay.as_ref().unwrap().local_addr;
        RelayConn::dial(addr, "127.0.0.1", self.id).await.unwrap()
    }

    fn handle(&self, k: &RelayClientKey) -> [u8; 32] {
        k.handle(&self.id)
    }

    fn token(&self, k: &RelayClientKey, not_before: u64, not_after: u64) -> Vec<u8> {
        self.plus
            .token(self.id.0, self.handle(k), not_before, not_after)
    }

    /// Send a hosted `REGISTER` with `token`; the first answer.
    async fn try_register(&self, k: &RelayClientKey, token: Vec<u8>) -> (RelayConn, RelayMessage) {
        let mut c = self.dial().await;
        let msg = RelayMessage::Register {
            key: k.public_key(),
            proof: k.register_proof(&self.id, &c.binding),
            hosted: Some((token, 50)),
        };
        c.send(&msg).await.unwrap();
        let first = relay(&mut c).await;
        (c, first)
    }

    async fn register(&self, k: &RelayClientKey, caller: &RelayClientKey) -> RelayConn {
        let now = self.plus.plus_now();
        let (mut c, first) = self
            .try_register(k, self.token(k, now - 5, now + 3_600))
            .await;
        assert!(
            matches!(first, RelayMessage::Registered { .. }),
            "{first:?}"
        );
        c.send(&RelayMessage::AllowSet {
            sequence: 1,
            callers: vec![caller.fingerprint()],
            invitations: vec![],
        })
        .await
        .unwrap();
        assert_eq!(
            relay(&mut c).await,
            RelayMessage::AllowSetOk { sequence: 1 }
        );
        c
    }

    fn block(&self, boot_id: [u8; 16], k: &RelayClientKey, b: Block) -> Vec<u8> {
        let now = self.plus.plus_now();
        self.plus.block(&BlockSpec {
            lease_id: [b.id; 16],
            relay_id: self.id.0,
            boot_id,
            handle: self.handle(k),
            class: b.class,
            sequence: b.seq,
            rate_cap: b.cap,
            bytes: b.bytes,
            not_before: b.not_before.unwrap_or(now - 5),
            expires_at: now + 3_600,
            rate_group: [b.group; 16],
        })
    }

    async fn lease(&self, reg: &mut RelayConn, k: &RelayClientKey, b: Block) {
        let block = self.block(reg.boot_id, k, b);
        reg.send(&RelayMessage::Lease { block }).await.unwrap();
    }

    /// A spliced circuit from `caller` to `target`.
    async fn connect(
        &self,
        reg: &mut RelayConn,
        target: &RelayClientKey,
        caller: &RelayClientKey,
        class: Class,
    ) -> (RelayConn, RelayConn) {
        let handle = self.handle(target);
        let mut leg = self.dial().await;
        let msg = RelayMessage::Call {
            handle,
            key: caller.public_key(),
            proof: caller.call_proof(&self.id, &handle, &leg.binding, class),
            class,
        };
        leg.send(&msg).await.unwrap();
        let circuit = loop {
            match relay(reg).await {
                RelayMessage::Incoming { circuit, .. } => break circuit,
                RelayMessage::LeaseStatus { .. } => continue,
                other => panic!("expected INCOMING, got {other:?}"),
            }
        };
        let mut acc = self.dial().await;
        let msg = RelayMessage::Accept {
            handle,
            circuit,
            proof: target.accept_proof(&self.id, &circuit, &acc.binding),
        };
        acc.send(&msg).await.unwrap();
        assert_eq!(relay(&mut leg).await, RelayMessage::Spliced);
        assert_eq!(relay(&mut acc).await, RelayMessage::Spliced);
        (leg, acc)
    }

    async fn stop(&mut self) {
        if let Some(r) = self.relay.take() {
            r.stop().await.unwrap();
        }
    }

    /// Wait for the stand-in to hold a final for `lease`.
    async fn final_of(&self, lease: u8) -> (u64, u64) {
        let start = Instant::now();
        loop {
            if let Some(f) = self.plus.final_of([lease; 16]) {
                return f;
            }
            assert!(start.elapsed() < WAIT, "no final for lease {lease}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

#[derive(Clone, Copy)]
struct Block {
    id: u8,
    seq: u64,
    class: Class,
    bytes: u64,
    cap: u64,
    group: u8,
    not_before: Option<u64>,
}

fn block(id: u8, seq: u64, class: Class, bytes: u64) -> Block {
    Block {
        id,
        seq,
        class,
        bytes,
        cap: 1 << 26,
        group: 7,
        not_before: None,
    }
}

/// The next relay message on `c`; PINGs are skipped.
async fn relay(c: &mut RelayConn) -> RelayMessage {
    loop {
        match next(c).await {
            Received::Relay(RelayMessage::Ping { .. }) => continue,
            Received::Relay(m) => return m,
            other => panic!("expected a relay message, got {other:?}"),
        }
    }
}

/// The next `LEASE_STATUS` entries on `reg`: (lease id byte, used, state).
async fn status(reg: &mut RelayConn) -> Vec<(u8, u64, u8)> {
    loop {
        if let RelayMessage::LeaseStatus { entries } = relay(reg).await {
            return entries
                .into_iter()
                .map(|e| (e.lease[0], e.used, e.state))
                .collect();
        }
    }
}

/// The next `LEASE_STATUS` entries on `reg` that are not threshold
/// crossings (state 1).
async fn status_not_threshold(reg: &mut RelayConn) -> Vec<(u8, u64, u8)> {
    loop {
        let s: Vec<_> = status(reg).await.into_iter().filter(|e| e.2 != 1).collect();
        if !s.is_empty() {
            return s;
        }
    }
}

/// The close code of `c`, skipping anything before it.
async fn closed(c: &mut RelayConn) -> Option<u16> {
    loop {
        if let Received::Closed(code) = next(c).await {
            return code;
        }
    }
}

/// Peer bytes on `c`, or `None` if nothing arrives within `wait`.
async fn peer_within(c: &mut RelayConn, wait: Duration) -> Option<Vec<u8>> {
    match tokio::time::timeout(wait, c.recv()).await {
        Ok(Received::Peer(b)) => Some(b),
        Ok(other) => panic!("expected peer bytes, got {other:?}"),
        Err(_) => None,
    }
}

fn bytes(n: usize, fill: u8) -> Vec<u8> {
    vec![fill; n]
}

#[tokio::test(flavor = "multi_thread")]
async fn a_message_splits_byte_exactly_across_current_and_pending() {
    let (target, caller) = (key(0x61), key(0x71));
    let h = Hosted::start("hosted-split", 1, &[]).await;
    let mut reg = h.register(&target, &caller).await;
    h.lease(&mut reg, &target, block(1, 1, Class::Bulk, 65_536))
        .await;
    h.lease(&mut reg, &target, block(2, 2, Class::Bulk, 65_536))
        .await;
    let (mut leg, mut acc) = h.connect(&mut reg, &target, &caller, Class::Bulk).await;
    for fill in [1, 2] {
        leg.send_raw(bytes(60_000, fill)).await.unwrap();
        assert_eq!(next(&mut acc).await, Received::Peer(bytes(60_000, fill)));
    }
    // Lease 1 took 65 536 bytes and is final; lease 2 took 54 464.
    assert_eq!(status_not_threshold(&mut reg).await, vec![(1, 65_536, 2)]);
    reg.send(&RelayMessage::Release {
        leases: vec![[2; 16]],
    })
    .await
    .unwrap();
    assert_eq!(status_not_threshold(&mut reg).await, vec![(2, 54_464, 2)]);
    assert_eq!(h.final_of(1).await, (65_536, 0));
    assert_eq!(h.final_of(2).await, (54_464, 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_paused_leg_resumes_on_a_refill_with_both_peers_still_connected() {
    let (target, caller) = (key(0x62), key(0x72));
    let h = Hosted::start("hosted-pause", 2, &[]).await;
    let mut reg = h.register(&target, &caller).await;
    h.lease(&mut reg, &target, block(1, 1, Class::Bulk, 65_536))
        .await;
    let (mut leg, mut acc) = h.connect(&mut reg, &target, &caller, Class::Bulk).await;
    leg.send_raw(bytes(60_000, 1)).await.unwrap();
    assert_eq!(next(&mut acc).await, Received::Peer(bytes(60_000, 1)));
    // 5 536 bytes left: this message waits.
    leg.send_raw(bytes(10_000, 2)).await.unwrap();
    assert_eq!(
        peer_within(&mut acc, Duration::from_millis(500)).await,
        None
    );
    h.lease(&mut reg, &target, block(2, 2, Class::Bulk, 65_536))
        .await;
    assert_eq!(next(&mut acc).await, Received::Peer(bytes(10_000, 2)));
    // The circuit carries on both ways.
    acc.send_raw(b"back".to_vec()).await.unwrap();
    assert_eq!(next(&mut leg).await, Received::Peer(b"back".to_vec()));
    assert_eq!(h.final_of(1).await, (65_536, 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_refill_the_class_closes_with_4001_and_its_lease_is_final() {
    let (target, caller) = (key(0x63), key(0x73));
    let h = Hosted::start("hosted-4001", 3, &[("RELAY_REFILL_WAIT_MS", 1_000)]).await;
    let mut reg = h.register(&target, &caller).await;
    h.lease(&mut reg, &target, block(1, 1, Class::Bulk, 65_536))
        .await;
    let (mut leg, mut acc) = h.connect(&mut reg, &target, &caller, Class::Bulk).await;
    leg.send_raw(bytes(60_000, 1)).await.unwrap();
    assert_eq!(next(&mut acc).await, Received::Peer(bytes(60_000, 1)));
    let paused = Instant::now();
    leg.send_raw(bytes(10_000, 2)).await.unwrap();
    assert_eq!(closed(&mut acc).await, Some(4001));
    assert_eq!(closed(&mut leg).await, Some(4001));
    let took = paused.elapsed();
    assert!(took >= Duration::from_millis(900), "{took:?}");
    assert_eq!(status_not_threshold(&mut reg).await, vec![(1, 60_000, 2)]);
    assert_eq!(h.final_of(1).await, (60_000, 0));
    // The registration stays.
    reg.send(&RelayMessage::Ping { data: [5; 8] })
        .await
        .unwrap();
    assert_eq!(relay(&mut reg).await, RelayMessage::Pong { data: [5; 8] });
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unfunded_class_is_refused_at_the_deadline_and_a_lease_funds_it() {
    let (target, caller) = (key(0x64), key(0x74));
    let h = Hosted::start("hosted-unfunded", 4, &[]).await;
    let mut reg = h.register(&target, &caller).await;
    let handle = h.handle(&target);
    let mut leg = h.dial().await;
    let msg = RelayMessage::Call {
        handle,
        key: caller.public_key(),
        proof: caller.call_proof(&h.id, &handle, &leg.binding, Class::Interactive),
        class: Class::Interactive,
    };
    let sent = Instant::now();
    leg.send(&msg).await.unwrap();
    assert_eq!(relay(&mut leg).await, RelayMessage::Unreachable);
    assert!(sent.elapsed() >= Duration::from_millis(500));
    h.lease(&mut reg, &target, block(1, 1, Class::Interactive, 1 << 20))
        .await;
    let (mut leg, mut acc) = h
        .connect(&mut reg, &target, &caller, Class::Interactive)
        .await;
    leg.send_raw(b"hi".to_vec()).await.unwrap();
    assert_eq!(next(&mut acc).await, Received::Peer(b"hi".to_vec()));
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_blocks_are_answered_and_not_before_is_strict() {
    let (target, caller) = (key(0x65), key(0x75));
    let h = Hosted::start("hosted-refused", 5, &[]).await;
    let mut reg = h.register(&target, &caller).await;
    // A rate cap below 65 536 bytes per second.
    let mut low = block(1, 1, Class::Bulk, 1 << 20);
    low.cap = 65_535;
    h.lease(&mut reg, &target, low).await;
    assert_eq!(status(&mut reg).await, vec![(1, 0, 3)]);
    // Not valid for two more seconds on Plus's clock: refused, and the same
    // block accepted when presented again after it.
    let mut early = block(2, 1, Class::Bulk, 1 << 20);
    early.not_before = Some(h.plus.plus_now() + 2);
    let env = h.block(reg.boot_id, &target, early);
    reg.send(&RelayMessage::Lease { block: env.clone() })
        .await
        .unwrap();
    assert_eq!(status(&mut reg).await, vec![(2, 0, 3)]);
    tokio::time::sleep(Duration::from_millis(3_100)).await;
    reg.send(&RelayMessage::Lease { block: env }).await.unwrap();
    let (mut leg, mut acc) = h.connect(&mut reg, &target, &caller, Class::Bulk).await;
    leg.send_raw(b"ok".to_vec()).await.unwrap();
    assert_eq!(next(&mut acc).await, Received::Peer(b"ok".to_vec()));
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_sockets_share_their_rate_group() {
    // Control per-socket-rate.
    let (target, caller) = (key(0x66), key(0x76));
    let h = Hosted::start("hosted-rate", 6, &[]).await;
    let mut reg = h.register(&target, &caller).await;
    let mut b = block(1, 1, Class::Bulk, 1 << 24);
    b.cap = 65_536;
    h.lease(&mut reg, &target, b).await;
    let (mut leg1, mut acc1) = h.connect(&mut reg, &target, &caller, Class::Bulk).await;
    let (mut leg2, mut acc2) = h.connect(&mut reg, &target, &caller, Class::Bulk).await;
    let start = Instant::now();
    for _ in 0..2 {
        leg1.send_raw(bytes(65_536, 1)).await.unwrap();
        leg2.send_raw(bytes(65_536, 2)).await.unwrap();
    }
    for _ in 0..2 {
        assert_eq!(next(&mut acc1).await, Received::Peer(bytes(65_536, 1)));
        assert_eq!(next(&mut acc2).await, Received::Peer(bytes(65_536, 2)));
    }
    // 4 × 65 536 bytes at 65 536 B/s with a one-second bucket: at least
    // three seconds (cap × (T + 1)). Per-socket buckets would take one.
    let took = start.elapsed();
    assert!(took >= Duration::from_millis(2_900), "{took:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn past_admission_expiry_funded_carries_on_dropped_comes_back_unfunded_closes() {
    let (target, other, caller) = (key(0x67), key(0x68), key(0x77));
    let h = Hosted::start("hosted-admission", 7, &[]).await;
    let now = h.plus.plus_now();
    // Tokens valid for two more seconds.
    let token = h.token(&target, now - 5, now + 2);
    let (mut reg, first) = h.try_register(&target, token.clone()).await;
    assert!(matches!(first, RelayMessage::Registered { .. }));
    reg.send(&RelayMessage::AllowSet {
        sequence: 1,
        callers: vec![caller.fingerprint()],
        invitations: vec![],
    })
    .await
    .unwrap();
    assert_eq!(
        relay(&mut reg).await,
        RelayMessage::AllowSetOk { sequence: 1 }
    );
    h.lease(&mut reg, &target, block(1, 1, Class::Interactive, 1 << 20))
        .await;
    let (mut leg, mut acc) = h
        .connect(&mut reg, &target, &caller, Class::Interactive)
        .await;
    let other_token = h.token(&other, now - 5, now + 2);
    let (mut other_reg, first) = h.try_register(&other, other_token.clone()).await;
    assert!(matches!(first, RelayMessage::Registered { .. }));
    tokio::time::sleep(Duration::from_millis(3_200)).await;

    // Funded: the circuit carries on past the token.
    leg.send_raw(b"still".to_vec()).await.unwrap();
    assert_eq!(next(&mut acc).await, Received::Peer(b"still".to_vec()));
    // Unfunded: closed with 4004.
    assert_eq!(closed(&mut other_reg).await, Some(4004));
    // A dropped funded registration registers again with its expired token;
    // an unfunded one does not.
    reg.close().await;
    let (mut reg, first) = h.try_register(&target, token).await;
    assert!(
        matches!(first, RelayMessage::Registered { .. }),
        "{first:?}"
    );
    let (_, first) = h.try_register(&other, other_token).await;
    assert_eq!(
        first,
        RelayMessage::Refused {
            reason: RefuseReason::Admission
        }
    );
    // Without its block the registration and its circuit close with 4004.
    reg.send(&RelayMessage::Release {
        leases: vec![[1; 16]],
    })
    .await
    .unwrap();
    assert_eq!(closed(&mut reg).await, Some(4004));
    assert_eq!(closed(&mut leg).await, Some(4004));
    assert_eq!(closed(&mut acc).await, Some(4004));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stop_reports_every_lease_final() {
    let (target, caller) = (key(0x69), key(0x79));
    let mut h = Hosted::start("hosted-stop", 8, &[]).await;
    let mut reg = h.register(&target, &caller).await;
    h.lease(&mut reg, &target, block(1, 1, Class::Interactive, 1 << 20))
        .await;
    h.lease(&mut reg, &target, block(2, 1, Class::Bulk, 1 << 20))
        .await;
    let (mut leg, mut acc) = h
        .connect(&mut reg, &target, &caller, Class::Interactive)
        .await;
    leg.send_raw(bytes(1_234, 1)).await.unwrap();
    assert_eq!(next(&mut acc).await, Received::Peer(bytes(1_234, 1)));
    h.stop().await;
    assert_eq!(closed(&mut leg).await, Some(4003));
    let parts = h.plus.parts();
    let last = parts.last().unwrap();
    assert_eq!(last.boot_state, BootState::Stopping);
    assert!(last.entries.iter().all(|e| e.is_final));
    assert_eq!(h.plus.final_of([1; 16]), Some((1_234, 0)));
    assert_eq!(h.plus.final_of([2; 16]), Some((0, 0)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lease_ends_on_time_across_a_machine_sleep_with_plus_unreachable() {
    // Control relay-clock-pauses-in-sleep.
    let (target, caller) = (key(0x6a), key(0x7a));
    let h = Hosted::start("hosted-sleep", 9, &[("RELAY_REFILL_WAIT_MS", 1_000)]).await;
    let mut reg = h.register(&target, &caller).await;
    let now = h.plus.plus_now();
    let b = block(1, 1, Class::Interactive, 1 << 20);
    let env = h.plus.block(&BlockSpec {
        lease_id: [1; 16],
        relay_id: h.id.0,
        boot_id: reg.boot_id,
        handle: h.handle(&target),
        class: b.class,
        sequence: b.seq,
        rate_cap: b.cap,
        bytes: b.bytes,
        not_before: now - 5,
        // Twenty seconds left on Plus's clock.
        expires_at: now + 20,
        rate_group: [b.group; 16],
    });
    reg.send(&RelayMessage::Lease { block: env }).await.unwrap();
    let (mut leg, mut acc) = h
        .connect(&mut reg, &target, &caller, Class::Interactive)
        .await;
    leg.send_raw(b"before".to_vec()).await.unwrap();
    assert_eq!(next(&mut acc).await, Received::Peer(b"before".to_vec()));
    // Plus is cut off, and the machine sleeps for 25 seconds (less than any
    // idle limit): its monotonic clock that counts sleep and its wall clock
    // jump; tokio's clock does not.
    h.plus.set_down(true);
    h.clock.advance_mono(25_000);
    h.clock.advance(25);
    // The lease is past its expiry on the Plus clock: final, and nothing
    // more is forwarded on it.
    assert_eq!(status_not_threshold(&mut reg).await, vec![(1, 6, 2)]);
    leg.send_raw(b"after".to_vec()).await.unwrap();
    assert_eq!(
        peer_within(&mut acc, Duration::from_millis(500)).await,
        None
    );
}
