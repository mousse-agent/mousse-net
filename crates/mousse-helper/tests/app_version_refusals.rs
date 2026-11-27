//! A paired host that shares no protocol version with this computer
//! (`docs/pair-with-ip-design.md` §5): the dial says `unsupported_version
//! {peer_minor}`, the host raises `peer.incompatible` once, both keep it
//! as the device's last refusal, the keeper keeps trying at its longest
//! wait, and once the host updates the same keeper connects and the
//! refusal is gone before `conn.up`.
//!
//! A, the host, is made older with `MOUSSE_NET_TEST_HELLO_MINOR`; B, which
//! dials it, is current. Each side sees the other's minor once.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

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

/// The keeper's `dial.failed` events for a refusal for version so far.
fn refused(b: &App) -> Vec<Value> {
    b.events("dial.failed")
        .into_iter()
        .filter(|m| m["why"] == "unsupported_version")
        .collect()
}

/// Wait for the keeper's refusal number `n` (from 0); returns it and when
/// it was seen.
fn nth_refused(b: &App, n: usize) -> (Value, Instant) {
    let seen = b.wait("a refused keeper dial", WAIT, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == "dial.failed" && m["why"] == "unsupported_version")
            .nth(n)
            .cloned()
    });
    (seen, Instant::now())
}

#[test]
fn a_host_refused_for_version_is_reported_kept_retried_and_cleared_once_it_updates() {
    let (ae, be, ce) = (
        Endpoint::init("vra"),
        Endpoint::init("vrb"),
        Endpoint::init("vrc"),
    );
    let old = [("MOUSSE_NET_TEST_HELLO_MINOR", Path::new(OLD))];
    let mut a = ae.app_raw("hostA", &[], 0, &old);
    let port = a.hello()["port"].as_u64().unwrap() as u16;
    // A 1.2 app learns that the helper reports refusals for version.
    let hello = a.call("hello", json!({"proto": [1, 2]}));
    let features = hello["features"].as_array().cloned().unwrap_or_default();
    assert!(features.contains(&json!("version-refusals")), "{hello}");
    let route = hello["routes"][0].as_str().unwrap().to_owned();
    let longest = 1_500;
    let mut b = be.app(
        "peerB",
        &[
            ("KEEP_RETRY_FIRST_MS", "100"),
            ("KEEP_RETRY_MAX_MS", &longest.to_string()),
        ],
    );
    b.hello();
    trust(&mut a, &mut b, &[&route]);
    let (a_id, b_id) = (a.identity.clone(), b.identity.clone());

    // B's keeper is refused, and waits its longest before the next try,
    // which it makes by itself.
    let (first, first_at) = nth_refused(&b, 0);
    assert_eq!(first["peer_minor"], 1, "{first}");
    assert_eq!(first["retry_ms"], longest, "{first}");
    let (_, second_at) = nth_refused(&b, 1);
    let gap = second_at - first_at;
    assert!(gap >= Duration::from_millis(1_000), "retried after {gap:?}");

    // A raised it once for B, which holds a grant there, with B's minor.
    let raised = a.event("peer.incompatible", |m| m["identity"] == b_id.as_str());
    let newest = raised["peer_minor"].as_u64().unwrap();
    assert!(newest > 1, "{raised}");

    // Both keep it as the device's last refusal.
    let on_b = peer_of(&mut b, &a_id)["version_refusal"].clone();
    assert_eq!(on_b["peer_minor"], 1, "{on_b}");
    assert_eq!(on_b["local_minor"], newest, "{on_b}");
    let on_a = grant_of(&mut a, &b_id)["version_refusal"].clone();
    assert_eq!(on_a["peer_minor"], newest, "{on_a}");
    assert_eq!(on_a["local_minor"], 1, "{on_a}");

    // "Check again" is a dial: refused at once, with A's minor.
    let again = b.request("dial", json!({"identity": a_id}));
    assert_eq!(again["error"], "unsupported_version", "{again}");
    assert_eq!(again["peer_minor"], 1, "{again}");

    // A current device A knows nothing of raises nothing.
    let mut c = ce.app("peerC", &[]);
    c.hello();
    c.call(
        "peer.add",
        json!({"identity": a_id, "name": "hostA", "routes": [route]}),
    );
    let no = c.request("dial", json!({"identity": a_id}));
    assert_eq!(no["error"], "unsupported_version", "{no}");
    a.call("grants.list", json!({}));
    let raised = a.events("peer.incompatible");
    assert_eq!(raised.len(), 1, "{raised:?}");

    // A restarts, still old: B's next refusal raises nothing within the
    // hour, across the restart.
    a.kill();
    let mut a = ae.app_raw("hostA", &[], port, &old);
    a.hello();
    let seen = refused(&b).len();
    nth_refused(&b, seen);
    a.call("grants.list", json!({}));
    assert!(a.events("peer.incompatible").is_empty());

    // A updates: the same keeper finds it, and both refusals are gone by
    // the time each side announces the connection.
    a.kill();
    let mut a = ae.app_with("hostA", &[], port, None);
    a.hello();
    wait_outbound(&b, &a_id, 0);
    let on_b = peer_of(&mut b, &a_id)["version_refusal"].clone();
    assert!(on_b.is_null(), "{on_b}");
    a.event("conn.up", |m| m["identity"] == b_id.as_str());
    let on_a = grant_of(&mut a, &b_id)["version_refusal"].clone();
    assert!(on_a.is_null(), "{on_a}");
}
