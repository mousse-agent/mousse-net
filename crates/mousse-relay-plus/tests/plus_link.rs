//! The hosted relay's link to Plus, against the test issuer stand-in on
//! loopback (`docs/phase34-design.md` §A.9 duties 1, 2, 4, 5, 11 and 12).

mod support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use mousse_net_core::identity::SoftwareKey;
use mousse_net_core::relay_hosted::records::{relay_id, MESSAGE_MAX};
use mousse_net_core::relay_hosted::{
    BootRecord, BootState, Class, Direction, Hosted, HostedLimits, LeaseRefusal, LeaseState,
    RelayId,
};
use mousse_net_io::rng::{os_rng, random_bytes};
use mousse_net_io::SystemClock;
use mousse_relay_plus::http::PlusHttp;
use mousse_relay_plus::link::{run, HostedRuntime, PlusLink};
use mousse_relay_plus::settings::PlusUrl;
use mousse_relay_plus::{issuers, state};

use support::test_issuer_standin::{BlockSpec, TestIssuerStandIn};

const H1: [u8; 32] = [0x31; 32];

fn limits() -> HostedLimits {
    HostedLimits::DEFAULT
        .with_overrides(&[
            ("RELAY_REPORT_MS", 1_000),
            ("RELAY_REPORT_MIN_MS", 100),
            ("RELAY_PLUS_RETRY_FIRST_MS", 100),
            ("RELAY_PLUS_RETRY_MAX_MS", 1_000),
            ("RELAY_FINAL_REPORT_WAIT_MS", 2_000),
            ("RELAY_PLUS_TIMEOUT_MS", 2_000),
        ])
        .unwrap()
}

struct Relay {
    id: RelayId,
    boot_id: [u8; 16],
    rt: Arc<HostedRuntime>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    log: Arc<Mutex<Vec<String>>>,
}

fn start(plus: &TestIssuerStandIn, limits: HostedLimits, generation: u64) -> Relay {
    let identity = SoftwareKey::generate(&mut os_rng());
    let id = relay_id(&identity.public_key());
    start_as(
        plus,
        limits,
        generation,
        id,
        SoftwareKey::generate(&mut os_rng()),
    )
}

fn start_as(
    plus: &TestIssuerStandIn,
    limits: HostedLimits,
    generation: u64,
    id: RelayId,
    report_key: SoftwareKey,
) -> Relay {
    plus.add_relay(id, report_key.public_key());
    let boot_id = random_bytes::<16>();
    let hosted = Hosted::new(id, boot_id, plus.keys(), limits);
    let rt = HostedRuntime::new(hosted, Arc::new(SystemClock::new()));
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    let link = PlusLink {
        http: PlusHttp::new(
            PlusUrl::parse(&plus.url()).unwrap(),
            Duration::from_millis(limits.plus_timeout_ms()),
            limits.plus_answer_max_bytes() as usize,
        )
        .unwrap(),
        report_key,
        boot: BootRecord {
            relay_id: id,
            boot_id,
            started_at: plus.plus_now(),
            build_id: "mousse-relay test".into(),
            generation,
        },
        log: Arc::new(move |l: &str| sink.lock().unwrap().push(l.to_owned())),
    };
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(run(rt.clone(), link, rx));
    Relay {
        id,
        boot_id,
        rt,
        stop,
        task,
        log,
    }
}

async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out: {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn block(plus: &TestIssuerStandIn, r: &Relay, id: u8, seq: u64, bytes: u64) -> Vec<u8> {
    let now = plus.plus_now();
    plus.block(&BlockSpec {
        lease_id: [id; 16],
        relay_id: r.id,
        boot_id: r.boot_id,
        handle: H1,
        class: Class::Interactive,
        sequence: seq,
        rate_cap: 1 << 24,
        bytes,
        not_before: now - 5,
        expires_at: now + 3_600,
        rate_group: [7; 16],
    })
}

fn register(plus: &TestIssuerStandIn, r: &Relay) {
    let now = plus.plus_now();
    let token = plus.token(r.id, H1, now - 5, now + 3_600);
    r.rt.with(|h, t| h.register(H1, &token, Some(50), t))
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_boot_answer_sets_the_plus_clock_whatever_the_relay_wall_clock() {
    let plus = TestIssuerStandIn::start(1).await;
    // Plus runs ten minutes ahead of this machine.
    plus.set_offset_ms(600_000);
    let r = start(&plus, limits(), 1);
    wait_for("boot", || r.rt.with(|h, _| h.clock().is_set())).await;
    let (est, real) = (
        r.rt.with(|h, t| h.clock().now_ms(t.mono)).unwrap(),
        plus.plus_now_ms(),
    );
    // Never behind Plus beyond drift; ahead by at most the round trip.
    assert!(est + 50 >= real && est <= real + 2_000, "{est} vs {real}");
    // A lease judged on that clock is accepted.
    register(&plus, &r);
    let b = block(&plus, &r, 1, 1, 1 << 20);
    assert_eq!(
        r.rt.with(|h, t| h.lease(H1, &b, t)),
        Ok(LeaseState::Current)
    );
    r.stop.send(true).unwrap();
    r.task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_same_boot_record_is_sent_again_through_an_outage() {
    let plus = TestIssuerStandIn::start(2).await;
    plus.fail_next(3);
    let r = start(&plus, limits(), 1);
    wait_for("boot", || r.rt.with(|h, _| h.clock().is_set())).await;
    let bodies = plus.boot_bodies();
    assert_eq!(bodies.len(), 4);
    assert!(bodies.iter().all(|b| *b == bodies[0]));
    // Reports start once the boot is known: a heartbeat arrives.
    wait_for("heartbeat", || !plus.parts().is_empty()).await;
    let p = &plus.parts()[0];
    assert_eq!((p.sequence, p.snapshot, p.part_count), (1, 1, 1));
    assert!(p.entries.is_empty());
    r.stop.send(true).unwrap();
    r.task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_boot_answer_is_retried_with_backoff() {
    let plus = TestIssuerStandIn::start(11).await;
    plus.set_bad_boot_answer(true);
    let r = start(&plus, limits(), 1);
    // Backoff from 100 ms, doubling: about four tries in a second; a tight
    // loop would make hundreds.
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    let tries = plus.boot_bodies().len();
    assert!((2..=8).contains(&tries), "{tries} tries");
    assert!(!r.rt.with(|h, _| h.clock().is_set()));
    plus.set_bad_boot_answer(false);
    wait_for("boot", || r.rt.with(|h, _| h.clock().is_set())).await;
    r.stop.send(true).unwrap();
    r.task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_generation_is_logged_and_retried_never_taken_as_booted() {
    let plus = TestIssuerStandIn::start(3).await;
    let identity = SoftwareKey::generate(&mut os_rng());
    let id = relay_id(&identity.public_key());
    // A state directory rolled back: Plus has seen generation 5 already.
    plus.seed_generation(id, 5);
    let r = start_as(&plus, limits(), 3, id, SoftwareKey::generate(&mut os_rng()));
    wait_for("three attempts", || plus.boot_bodies().len() >= 3).await;
    assert!(!r.rt.with(|h, _| h.clock().is_set()));
    assert!(plus.parts().is_empty());
    assert!(r
        .log
        .lock()
        .unwrap()
        .iter()
        .any(|l| l.contains("stale_generation")));
    // An operator resolves it at Plus; the same record is then acknowledged.
    plus.clear_generations(id);
    wait_for("boot", || r.rt.with(|h, _| h.clock().is_set())).await;
    r.stop.send(true).unwrap();
    r.task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn each_restart_announces_a_higher_generation_from_the_state_directory() {
    let plus = TestIssuerStandIn::start(4).await;
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "relay-plus-gen-{}",
        mousse_net_io::store::hex(&random_bytes::<6>())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let identity = SoftwareKey::generate(&mut os_rng());
    let id = relay_id(&identity.public_key());
    for want in 1..=2 {
        let generation = state::next_boot_generation(&dir).unwrap();
        assert_eq!(generation, want);
        let key = state::report_key(&dir).unwrap();
        let r = start_as(&plus, limits(), generation, id, key);
        wait_for("boot", || r.rt.with(|h, _| h.clock().is_set())).await;
        r.stop.send(true).unwrap();
        r.task.await.unwrap();
    }
    assert_eq!(plus.boot_bodies().len(), 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_final_reaches_plus_soon_and_a_settled_lease_is_forgotten() {
    let plus = TestIssuerStandIn::start(5).await;
    let r = start(&plus, limits(), 1);
    wait_for("boot", || r.rt.with(|h, _| h.clock().is_set())).await;
    register(&plus, &r);
    let b = block(&plus, &r, 1, 1, MESSAGE_MAX);
    r.rt.with(|h, t| h.lease(H1, &b, t)).unwrap();
    r.rt.with(|h, t| h.forward(H1, Class::Interactive, 1, Direction::ToTarget, 1_000, t));
    r.rt.with(|h, t| h.forward(H1, Class::Interactive, 1, Direction::ToCaller, 2_500, t));
    let released = Instant::now();
    r.rt.with(|h, t| h.release(H1, &[[1; 16]], t)).unwrap();
    wait_for("final", || plus.final_of([1; 16]).is_some()).await;
    // Within REPORT_MIN_MS (100 ms here) plus a round trip.
    assert!(
        released.elapsed() < Duration::from_millis(800),
        "{:?}",
        released.elapsed()
    );
    assert_eq!(plus.final_of([1; 16]), Some((1_000, 2_500)));
    wait_for("forgotten", || r.rt.with(|h, _| h.lease_count()) == 0).await;
    // Report sequences have no gaps.
    let seqs: Vec<u64> = plus.parts().iter().map(|p| p.sequence).collect();
    assert_eq!(seqs, (1..=seqs.len() as u64).collect::<Vec<_>>());
    r.stop.send(true).unwrap();
    r.task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stop_reports_every_lease_final_in_a_stopping_snapshot() {
    let plus = TestIssuerStandIn::start(6).await;
    let r = start(&plus, limits(), 1);
    wait_for("boot", || r.rt.with(|h, _| h.clock().is_set())).await;
    register(&plus, &r);
    for (id, seq) in [(1u8, 1u64), (2, 2)] {
        let b = block(&plus, &r, id, seq, 1 << 20);
        r.rt.with(|h, t| h.lease(H1, &b, t)).unwrap();
    }
    r.rt.with(|h, t| h.forward(H1, Class::Interactive, 1, Direction::ToTarget, 4_096, t));
    let late = block(&plus, &r, 3, 3, 1 << 20);
    r.stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), r.task)
        .await
        .unwrap()
        .unwrap();
    let parts = plus.parts();
    let last = parts.last().unwrap();
    assert_eq!(last.boot_state, BootState::Stopping);
    assert_eq!(last.entries.len(), 2);
    assert!(last.entries.iter().all(|e| e.is_final));
    assert_eq!(plus.final_of([1; 16]), Some((4_096, 0)));
    assert_eq!(plus.final_of([2; 16]), Some((0, 0)));
    // Nothing is forwarded or accepted after the stop.
    assert_eq!(
        r.rt.with(|h, t| h.lease(H1, &late, t)).unwrap_err().reason,
        LeaseRefusal::Stopping
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stop_waits_no_longer_than_the_final_report_wait_when_plus_is_down() {
    let plus = TestIssuerStandIn::start(7).await;
    let lim = limits()
        .with_overrides(&[("RELAY_FINAL_REPORT_WAIT_MS", 300)])
        .unwrap();
    let r = start(&plus, lim, 1);
    wait_for("boot", || r.rt.with(|h, _| h.clock().is_set())).await;
    plus.set_down(true);
    let asked = Instant::now();
    r.stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), r.task)
        .await
        .unwrap()
        .unwrap();
    let took = asked.elapsed();
    assert!(
        took >= Duration::from_millis(300) && took < Duration::from_millis(2_500),
        "{took:?}"
    );
    assert!(!r.rt.with(|h, _| h.stop_reported()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_answer_sets_no_clock_and_no_lease_is_taken_until_a_quick_one() {
    let plus = TestIssuerStandIn::start(8).await;
    let lim = limits()
        .with_overrides(&[("RELAY_CLOCK_RTT_MS", 100)])
        .unwrap();
    plus.set_delay_ms(300);
    let r = start(&plus, lim, 1);
    wait_for("boot acknowledged", || {
        r.log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("boot acknowledged"))
    })
    .await;
    assert!(!r.rt.with(|h, _| h.clock().is_set()));
    register(&plus, &r);
    let b = block(&plus, &r, 1, 1, 1 << 20);
    assert_eq!(
        r.rt.with(|h, t| h.lease(H1, &b, t)).unwrap_err().reason,
        LeaseRefusal::NoPlusClock
    );
    // A report answered quickly sets it; the same block is then accepted.
    plus.set_delay_ms(0);
    wait_for("clock", || r.rt.with(|h, _| h.clock().is_set())).await;
    assert_eq!(
        r.rt.with(|h, t| h.lease(H1, &b, t)),
        Ok(LeaseState::Current)
    );
    r.stop.send(true).unwrap();
    r.task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reload_pins_a_rotated_issuer_key_without_a_new_boot() {
    let plus = TestIssuerStandIn::start(9).await;
    let next = TestIssuerStandIn::start(10).await;
    let r = start(&plus, limits(), 1);
    wait_for("boot", || r.rt.with(|h, _| h.clock().is_set())).await;
    register(&plus, &r);
    let now = next.plus_now();
    let spec = BlockSpec {
        lease_id: [5; 16],
        relay_id: r.id,
        boot_id: r.boot_id,
        handle: H1,
        class: Class::Bulk,
        sequence: 1,
        rate_cap: 1 << 24,
        bytes: 1 << 20,
        not_before: now - 5,
        expires_at: now + 600,
        rate_group: [8; 16],
    };
    let b = next.block(&spec);
    assert!(r.rt.with(|h, t| h.lease(H1, &b, t)).is_err());
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "relay-plus-keys-{}",
        mousse_net_io::store::hex(&random_bytes::<6>())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("issuer-keys");
    // Both keys overlap during the rotation.
    let text = format!(
        "# issuer keys\n{}\n{}\n",
        mousse_net_io::store::hex(plus.issuer_public_key().as_bytes()),
        mousse_net_io::store::hex(next.issuer_public_key().as_bytes())
    );
    std::fs::write(&file, text).unwrap();
    r.rt.reload(issuers::load(&file).unwrap());
    assert_eq!(
        r.rt.with(|h, t| h.lease(H1, &b, t)),
        Ok(LeaseState::Current)
    );
    assert_eq!(r.rt.with(|h, _| h.boot_id()), r.boot_id);
    std::fs::remove_dir_all(&dir).unwrap();
    r.stop.send(true).unwrap();
    r.task.await.unwrap();
}
