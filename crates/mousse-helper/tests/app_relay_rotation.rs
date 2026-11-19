//! E-R4: manifests, stale-manifest dialling and manual key rotation
//! through the app channel, against the loopback test relay (Phase 3
//! §B.4 and §B.11). The check cell `phase3.relay-rotation` runs this file.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::*;
use mousse_net_io::relay::test_relay::{TestRelay, TestRelayConfig};
use serde_json::{json, Value};

struct Relay {
    rt: tokio::runtime::Runtime,
    relay: TestRelay,
}

impl Relay {
    fn start() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let relay = rt.block_on(TestRelay::start(TestRelayConfig::default()));
        Self { rt, relay }
    }

    fn link(&self) -> String {
        let _rt = self.rt.enter();
        self.relay.enrollment_link().to_text()
    }

    fn destination(&self) -> String {
        format!("relay://{}", self.relay.addr())
    }

    fn wait_handles(&self, n: usize) {
        let start = Instant::now();
        while self.relay.handles().len() != n {
            assert!(
                start.elapsed() < WAIT,
                "{} registrations, not {n}",
                self.relay.handles().len()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

const FAST: [(&str, &str); 4] = [
    ("VIA_RELAY_RETRY_FIRST_MS", "100"),
    ("VIA_RELAY_CHECK_MS", "100"),
    ("KEEP_RETRY_FIRST_MS", "100"),
    ("KEEP_RETRY_MAX_MS", "500"),
];

fn manual_clock() -> [(&'static str, &'static Path); 1] {
    [("MOUSSE_HELPER_MANUAL_CLOCK", Path::new("1"))]
}

fn enroll(app: &mut App, relay: &Relay) -> String {
    let reply = app.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(reply["relay"]["state"], "registered", "{reply}");
    reply["relay"]["id"].as_str().unwrap().to_owned()
}

fn wait_listed(host: &mut App, identity: &str) {
    let start = Instant::now();
    loop {
        let list = host.call("grants.list", json!({}));
        if list["grants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["identity"] == identity && g["relay"] == "listed")
        {
            return;
        }
        assert!(start.elapsed() < WAIT, "{identity} never listed");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_registered(app: &mut App) {
    let start = Instant::now();
    loop {
        let list = app.call("relay.list", json!({}));
        if list["relays"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["state"] == "registered")
        {
            return;
        }
        assert!(start.elapsed() < WAIT, "never registered again: {list}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn dial_up(from: &mut App, to: &str) -> Value {
    let start = Instant::now();
    loop {
        let reply = from.request("dial", json!({"identity": to}));
        if let Some(conn) = reply["conn"].as_u64() {
            return from.event("conn.up", |m| m["conn"] == conn);
        }
        assert!(start.elapsed() < WAIT, "dial never worked: {reply}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The manifest sequence `app` keeps for `host` (0: none).
fn sequence(app: &mut App, host: &str) -> u64 {
    peer_of(app, host)["relay"]["manifest"]["sequence"]
        .as_u64()
        .unwrap_or(0)
}

fn wait_sequence_above(app: &mut App, host: &str, above: u64) -> u64 {
    let start = Instant::now();
    loop {
        let now = sequence(app, host);
        if now > above {
            return now;
        }
        assert!(start.elapsed() < WAIT, "no manifest above {above}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Pair `peer` with `a`, enroll its caller key and allow `a`'s relay.
fn pair_and_allow(a: &mut App, peer: &mut App, relay: &Relay) -> u64 {
    pair_apps(a, peer);
    wait_listed(a, &peer.identity.clone());
    let host = a.identity.clone();
    let seq = wait_sequence_above(peer, &host, 0);
    peer.call(
        "peer.relay.allow",
        json!({"identity": host, "destination": relay.destination()}),
    );
    seq
}

#[test]
fn a_manual_rotation_asks_nothing_and_an_offline_caller_comes_back_through_the_old_route() {
    let relay = Relay::start();
    let a_end = Endpoint::init("rta");
    let b_end = Endpoint::init("rtb");
    let c_end = Endpoint::init("rtc");
    let mut a = a_end.app("hostA", &FAST);
    a.hello();
    let id = enroll(&mut a, &relay);
    let mut b = b_end.app("peerB", &FAST);
    b.hello();
    let mut c = c_end.app("peerC", &FAST);
    c.hello();
    let host = a.identity.clone();
    let seq_b = pair_and_allow(&mut a, &mut b, &relay);
    let seq_c = pair_and_allow(&mut a, &mut c, &relay);
    // C is offline through the rotation.
    c.kill();

    let offered = b.events("peer.relay.offered").len();
    let rotated = a.call("relay.rotate", json!({"relay": id}));
    assert!(rotated["relay"]["rotating_until"].is_u64(), "{rotated}");
    relay.wait_handles(2);
    // B, online, gets the new manifest at once and is asked nothing: the
    // destination is the same.
    wait_sequence_above(&mut b, &host, seq_b);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(b.events("peer.relay.offered").len(), offered);

    // A reachable only by relay; both keys register again.
    a.kill();
    let mut a = a_end.app("hostA", &FAST);
    a.hello();
    wait_registered(&mut a);
    relay.wait_handles(2);
    let up = dial_up(&mut b, &host);
    assert_eq!(up["route"]["kind"], "relay");

    // C comes back with only the old manifest: the old route still works
    // and brings the new manifest.
    let mut c = c_end.app("peerC", &FAST);
    c.hello();
    assert_eq!(sequence(&mut c, &host), seq_c);
    let c_up = dial_up(&mut c, &host);
    assert_eq!(c_up["route"]["kind"], "relay");
    wait_sequence_above(&mut c, &host, seq_c);

    // Removal holds across the rotation.
    let c_grant = a.call("grants.list", json!({}))["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["identity"] == c.identity.as_str())
        .unwrap()["grant"]
        .clone();
    a.call("grant.remove", json!({"grant": c_grant}));
    c.event("conn.down", |m| m["conn"] == c_up["conn"]);
    let again = c.request("dial", json!({"identity": host}));
    assert_eq!(again["error"], "unreachable", "{again}");
    let b_conn = up["conn"].clone();
    assert!(!b.events("conn.down").iter().any(|m| m["conn"] == b_conn));
}

#[test]
fn a_stale_manifest_s_routes_are_still_dialled() {
    let relay = Relay::start();
    let a_end = Endpoint::init("rsa");
    let b_end = Endpoint::init("rsb");
    let mut a = a_end.app_raw("hostA", &FAST, 0, &manual_clock());
    a.hello();
    enroll(&mut a, &relay);
    let mut b = b_end.app_raw("peerB", &FAST, 0, &manual_clock());
    b.hello();
    let host = a.identity.clone();
    pair_and_allow(&mut a, &mut b, &relay);
    a.kill();
    let mut a = a_end.app_raw("hostA", &FAST, 0, &manual_clock());
    a.hello();
    wait_registered(&mut a);
    // Past the manifest's lifetime on both clocks.
    let past = 2_592_000 + 86_400;
    a.call("test.clock", json!({"advance_secs": past}));
    b.call("test.clock", json!({"advance_secs": past}));
    assert_eq!(peer_of(&mut b, &host)["relay"]["manifest"]["stale"], true);
    let up = dial_up(&mut b, &host);
    assert_eq!(up["route"]["kind"], "relay");
}

#[test]
fn the_old_key_leaves_after_the_overlap() {
    let relay = Relay::start();
    let a_end = Endpoint::init("roa");
    let mut a = a_end.app_raw("hostA", &FAST, 0, &manual_clock());
    a.hello();
    let id = enroll(&mut a, &relay);
    relay.wait_handles(1);
    a.call("relay.rotate", json!({"relay": id}));
    relay.wait_handles(2);
    a.call("test.clock", json!({"advance_secs": 604_800 + 1}));
    relay.wait_handles(1);
    let list = a.call("relay.list", json!({}));
    assert!(list["relays"][0]["rotating_until"].is_null(), "{list}");
}
