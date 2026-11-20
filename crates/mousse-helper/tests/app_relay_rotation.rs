//! E-R4: manifests, stale-manifest dialling and manual key rotation
//! through the app channel, against a real `mousse-relay` on loopback (Phase 3
//! §B.4 and §B.11). The check cell `phase3.relay-rotation` runs this file.
//! The cases live in `common/relay_rotation.rs`; `app_relay_remote.rs` runs
//! the same ones against a relay on another machine.

mod common;
#[path = "common/relay.rs"]
mod relay_fixture;
#[path = "common/relay_rotation.rs"]
mod rotation;

#[test]
fn a_manual_rotation_asks_nothing_and_an_offline_caller_comes_back_through_the_old_route() {
    rotation::a_manual_rotation_asks_nothing_and_an_offline_caller_comes_back_through_the_old_route(
    );
}

#[test]
fn a_stale_manifest_s_routes_are_still_dialled() {
    rotation::a_stale_manifest_s_routes_are_still_dialled();
}

#[test]
fn the_old_key_leaves_after_the_overlap() {
    rotation::the_old_key_leaves_after_the_overlap();
}

/// A rotation whose `SUCCESSOR` never reached the relay before the host
/// stopped goes on after a restart: the old key stays current meanwhile,
/// and once the relay takes the new key both are registered.
#[test]
fn a_rotation_cut_off_before_the_relay_took_it_goes_on_after_a_restart() {
    use common::*;
    use serde_json::json;
    use std::time::{Duration, Instant};

    let relay = relay_fixture::TestRelay::start();
    let a_end = Endpoint::init("rka");
    let fast = [
        ("VIA_RELAY_RETRY_FIRST_MS", "100"),
        ("VIA_RELAY_ROTATION_RETRY_MS", "200"),
        ("VIA_RELAY_CHECK_MS", "100"),
    ];
    let mut a = a_end.app("hostA", &fast);
    a.hello();
    let enrolled = a.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");
    let id = enrolled["relay"]["id"].clone();
    relay.wait_live(1);

    // From here the relay hears nothing: whatever the rotation sends is lost.
    relay.cut();
    let rotated = a.call("relay.rotate", json!({"relay": id}));
    assert!(rotated.get("error").is_none(), "{rotated}");
    std::thread::sleep(Duration::from_millis(500));
    a.kill();
    relay.resume();

    let mut a = a_end.app("hostA", &fast);
    a.hello();
    let start = Instant::now();
    loop {
        let list = a.call("relay.list", json!({}));
        let r = &list["relays"][0];
        if r["state"] == "registered"
            && r["rotated_at"].is_u64()
            && r["rotating_until"].is_u64()
            && r["new_key_pending"] == false
        {
            break;
        }
        assert!(
            start.elapsed() < WAIT,
            "the rotation never finished: {list}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // The new key and the old one, through the overlap.
    relay.wait_live(2);
}

const ROTATE_FAST: [(&str, &str); 3] = [
    ("VIA_RELAY_RETRY_FIRST_MS", "100"),
    ("VIA_RELAY_ROTATION_RETRY_MS", "200"),
    ("VIA_RELAY_CHECK_MS", "100"),
];

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Poll `relay.list` until the first relay matches.
fn wait_relay(
    app: &mut common::App,
    what: &str,
    pred: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    let start = std::time::Instant::now();
    loop {
        let list = app.call("relay.list", serde_json::json!({}));
        let r = list["relays"][0].clone();
        if pred(&r) {
            return r;
        }
        assert!(start.elapsed() < common::WAIT, "{what}: {list}");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// A relay holding as many keys of one chain as it allows refuses the
/// next `SUCCESSOR` as `chain_full` and keeps the registration. The helper
/// ends that rotation (the current key stays), says so in `relay.state`,
/// sends no more `SUCCESSOR`s, and refuses the next rotation at once.
#[test]
fn a_full_key_chain_ends_the_rotation_and_keeps_the_registration() {
    use common::*;
    use serde_json::json;
    use std::time::Duration;

    let relay = relay_fixture::TestRelay::start_with(&[("RELAY_CHAIN_KEYS_MAX", 2)]);
    let a_end = Endpoint::init("rkc");
    let mut a = a_end.app("hostA", &ROTATE_FAST);
    a.hello();
    let enrolled = a.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");
    let id = enrolled["relay"]["id"].clone();

    // The first rotation fills the chain: the old key and the new one.
    let rotated = a.call("relay.rotate", json!({"relay": id}));
    assert!(rotated.get("error").is_none(), "{rotated}");
    let first = wait_relay(&mut a, "the first rotation never finished", |r| {
        r["new_key_pending"] == false && r["rotating_until"].is_u64()
    });
    relay.wait_live(2);

    let rotated = a.call("relay.rotate", json!({"relay": id}));
    assert!(rotated.get("error").is_none(), "{rotated}");
    let state = a.event("relay.state", |e| e["relay"]["chain_full"] == true);
    assert_eq!(state["relay"]["new_key_pending"], false, "{state}");
    assert!(state["relay"]["chain_full_until"].is_u64(), "{state}");
    let r = wait_relay(&mut a, "the rotation was not dropped", |r| {
        r["chain_full"] == true && r["new_key_pending"] == false
    });
    assert_eq!(r["rotated_at"], first["rotated_at"], "the key changed: {r}");
    assert_eq!(r["state"], "registered", "{r}");

    // Nothing flaps: no registration closes, nothing dials again.
    let made = relay.connections();
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(relay.connections(), made, "the registration was made again");
    relay.wait_live(2);
    let r = wait_relay(&mut a, "unreachable", |_| true);
    assert_eq!(r["state"], "registered", "{r}");

    // Known full: the next rotation is refused before anything is sent.
    let again = a.request("relay.rotate", json!({"relay": id}));
    assert_eq!(again["error"], "chain_full", "{again}");
    assert_eq!(relay.connections(), made);
}

/// A pending rotation can be cancelled: the current key stays, the relay
/// never hears of the new one, and a later rotation works.
#[test]
fn a_pending_rotation_can_be_cancelled() {
    use common::*;
    use serde_json::json;

    let relay = relay_fixture::TestRelay::start();
    let a_end = Endpoint::init("rkx");
    let mut a = a_end.app("hostA", &ROTATE_FAST);
    a.hello();
    let enrolled = a.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");
    let id = enrolled["relay"]["id"].clone();
    relay.wait_live(1);

    let none = a.request("relay.rotate", json!({"relay": id, "cancel": true}));
    assert_eq!(none["error"], "not_rotating", "{none}");

    // The relay hears nothing of this rotation.
    relay.cut();
    let rotated = a.call("relay.rotate", json!({"relay": id}));
    assert_eq!(rotated["relay"]["new_key_pending"], true, "{rotated}");
    let cancelled = a.call("relay.rotate", json!({"relay": id, "cancel": true}));
    assert!(cancelled.get("error").is_none(), "{cancelled}");
    assert_eq!(cancelled["relay"]["new_key_pending"], false, "{cancelled}");
    relay.resume();

    // Once the relay refuses the new key, it is dropped.
    let r = wait_relay(&mut a, "the cancel never finished", |r| {
        r["cancelling"] == false && r["new_key_pending"] == false && r["state"] == "registered"
    });
    assert!(r["rotated_at"].is_null(), "the key changed: {r}");
    assert!(r["rotating_until"].is_null(), "{r}");

    // A new rotation goes through.
    let rotated = a.call("relay.rotate", json!({"relay": id}));
    assert!(rotated.get("error").is_none(), "{rotated}");
    wait_relay(&mut a, "the next rotation never finished", |r| {
        r["new_key_pending"] == false && r["rotating_until"].is_u64()
    });
    relay.wait_live(2);
}

/// A relay that keeps superseded keys for less than `MANIFEST_OVERLAP_SECS`
/// says so in `REGISTERED`; the old key leaves before the relay drops it.
#[test]
fn the_overlap_is_never_longer_than_the_relay_s() {
    use common::*;
    use serde_json::json;

    let overlap = 86_400;
    let relay = relay_fixture::TestRelay::start_with(&[("RELAY_SUCCESSOR_OVERLAP_SECS", overlap)]);
    let a_end = Endpoint::init("rko");
    let mut a = a_end.app("hostA", &ROTATE_FAST);
    a.hello();
    let enrolled = a.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");
    let id = enrolled["relay"]["id"].clone();

    let before = unix_now();
    let rotated = a.call("relay.rotate", json!({"relay": id}));
    assert!(rotated.get("error").is_none(), "{rotated}");
    let r = wait_relay(&mut a, "the rotation never finished", |r| {
        r["new_key_pending"] == false && r["rotating_until"].is_u64()
    });
    let until = r["rotating_until"].as_u64().unwrap();
    // The rotation's start plus the relay's overlap, less the clock skew.
    assert!(until <= before + 2 + overlap - 600, "{until} {before}: {r}");
    assert!(until >= before + overlap - 600, "{until} {before}: {r}");
}
