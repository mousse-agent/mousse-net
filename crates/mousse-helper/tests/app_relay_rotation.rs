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
