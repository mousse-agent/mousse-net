//! A paired device that shares no protocol version with this computer
//! (`docs/pair-with-ip-design.md` §5): the dial says `unsupported_version
//! {peer_minor}`, the host it dialled raises `peer.incompatible` once, both
//! keep it as the device's last refusal, the keeper keeps trying at its
//! longest wait, and the first connection that agrees a version clears it.
//!
//! B is made older with `MOUSSE_NET_TEST_HELLO_MINOR`, so A (newer) is the
//! side that closes and B learns of it from A's close: both directions of
//! "the peer is newer / older" are seen once each.

mod common;

use std::path::Path;
use std::time::Instant;

use common::*;
use serde_json::{json, Value};

const OLD: &str = "1";

/// `app`'s grant for `identity`, as `grants.list` shows it.
fn grant_of(app: &mut App, identity: &str) -> Value {
    let list = app.call("grants.list", json!({}));
    list["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["identity"] == identity)
        .cloned()
        .unwrap_or(Value::Null)
}

/// Poll `get` until it is true, within `WAIT`.
fn until(what: &str, mut get: impl FnMut() -> bool) {
    let start = Instant::now();
    while !get() {
        assert!(start.elapsed() < WAIT, "never: {what}");
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[test]
fn a_device_refused_for_version_is_reported_kept_and_cleared_once_it_updates() {
    let (_ae, be, _ce) = (
        Endpoint::init("vra"),
        Endpoint::init("vrb"),
        Endpoint::init("vrc"),
    );
    let mut a = _ae.app("hostA", &[]);
    a.hello();
    let old = [("MOUSSE_NET_TEST_HELLO_MINOR", Path::new(OLD))];
    let mut b = be.app_raw("peerB", &[("KEEP_RETRY_MAX_MS", "30000")], 0, &old);
    b.hello();
    // A 1.2 app learns that the helper reports refusals for version.
    let hello = a.call("hello", json!({"proto": [1, 2]}));
    let features = hello["features"].as_array().cloned().unwrap_or_default();
    assert!(features.contains(&json!("version-refusals")), "{hello}");
    let route = hello["routes"][0].as_str().unwrap().to_owned();
    trust(&mut a, &mut b, &[&route]);

    // B's dial: A shares no version with it and says how new it is.
    let reply = b.request("dial", json!({"identity": a.identity}));
    assert_eq!(reply["error"], "unsupported_version", "{reply}");
    let newest = reply["peer_minor"].as_u64().expect("peer_minor");
    assert!(newest > 1, "{reply}");

    // A, the host, raises it for B, which holds a grant there.
    let raised = a.event("peer.incompatible", |m| {
        m["identity"] == b.identity.as_str()
    });
    assert_eq!(raised["peer_minor"], 1, "{raised}");

    // The keeper is not parked: it tries again at its longest wait.
    let failed = b.event("dial.failed", |m| m["why"] == "unsupported_version");
    assert_eq!(failed["retry_ms"], 30_000, "{failed}");
    assert_eq!(failed["peer_minor"], newest, "{failed}");

    // Both keep it as the device's last refusal.
    let on_b = peer_of(&mut b, &a.identity)["version_refusal"].clone();
    assert_eq!(on_b["peer_minor"], newest, "{on_b}");
    assert_eq!(on_b["local_minor"], 1, "{on_b}");
    let b_id = b.identity.clone();
    until("A keeps B's refusal", || {
        !grant_of(&mut a, &b_id)["version_refusal"].is_null()
    });
    let on_a = grant_of(&mut a, &b_id)["version_refusal"].clone();
    assert_eq!(on_a["peer_minor"], 1, "{on_a}");
    assert_eq!(on_a["local_minor"], newest, "{on_a}");

    // "Check again" refuses again; A raises nothing more within the hour.
    let again = b.request("dial", json!({"identity": a.identity}));
    assert_eq!(again["error"], "unsupported_version", "{again}");

    // An old device A knows nothing of raises nothing.
    let mut c = _ce.app_raw("peerC", &[], 0, &old);
    c.hello();
    c.call(
        "peer.add",
        json!({"identity": a.identity, "name": "hostA", "routes": [route]}),
    );
    let refused = c.request("dial", json!({"identity": a.identity}));
    assert!(refused.get("error").is_some(), "{refused}");
    a.call("grants.list", json!({}));
    let raised = a.events("peer.incompatible");
    assert_eq!(raised.len(), 1, "{raised:?}");

    // B updates: its first connection agrees a version and clears both.
    drop(b);
    let mut b = be.app("peerB", &[]);
    b.hello();
    wait_outbound(&b, &a.identity, 0);
    let a_id = a.identity.clone();
    until("B clears A's refusal", || {
        peer_of(&mut b, &a_id)["version_refusal"].is_null()
    });
    until("A clears B's refusal", || {
        grant_of(&mut a, &b_id)["version_refusal"].is_null()
    });
}
