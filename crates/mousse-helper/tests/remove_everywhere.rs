//! E-L4: "Remove on all my hosts" over sessions (Phase 4, design Part D).
//! The host sends its grant list to owner-role callers on
//! `mousse-grants`; the admin device signs one removal per host and grant
//! id the user confirmed and sends it on `mousse-removal`; the host applies
//! it under its admission lock and answers with the journaled result.
//! The check cell `phase4.remove-everywhere` runs this file.

mod common;

use std::time::Duration;

use common::*;
use serde_json::{json, Value};

/// The grant id `host`'s last list (as `admin` stored it) names for
/// `device`, once it does.
fn planned_grant(admin: &mut App, host: &str, device: &str) -> u64 {
    let deadline = std::time::Instant::now() + WAIT;
    loop {
        let plan = admin.call("removal.plan", json!({"identity": device}));
        let grant = plan["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["host"] == host)
            .and_then(|h| h["grant"].as_u64());
        if let Some(g) = grant {
            return g;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no grant list from the host names the device: {plan}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The grant `identity` holds on `app`, if any.
fn grant_on(app: &mut App, identity: &str) -> Option<u64> {
    app.call("grants.list", json!({}))["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["identity"] == identity)
        .and_then(|g| g["grant"].as_u64())
}

/// The final `removal.state` of removal `id` on `admin`.
fn finished(admin: &App, id: &Value) -> Value {
    admin.event("removal.state", |m| m["id"] == *id && m["state"] == "done")
}

/// Open a stream from the caller so the host may open its own (wire.md §8
/// step 4), as the app's `mousse.hello` does.
fn caller_opens(app: &mut App, conn: u64) {
    app.open(conn, "mousse.hello", "interactive");
}

#[test]
fn removal_by_an_owner_ends_the_device_on_its_host() {
    // A is the host; B (the admin device) and C (the phone) paired with it
    // as owners.
    let mut p = pair_up("rmall", &[], &[]);
    let (_c_end, c, a_conn_c, _c_conn) = another_peer(&mut p.a, "rmallc", &[]);
    caller_opens(&mut p.b, p.b_conn);
    let host = p.a.identity.clone();
    let phone = c.identity.clone();
    let grant = planned_grant(&mut p.b, &host, &phone);
    assert_eq!(Some(grant), grant_on(&mut p.a, &phone));

    let confirmed = p.b.call(
        "removal.confirm",
        json!({"identity": phone, "name": "Phone", "hosts": [{"host": host, "grant": grant}]}),
    );
    let id = confirmed["removals"][0]["id"].clone();
    let done = finished(&p.b, &id);
    assert_eq!(done["result"], "applied");
    // On A: C's grant is gone and its connection closed as revoked.
    assert_eq!(grant_on(&mut p.a, &phone), None);
    let down = p.a.event("conn.down", |m| m["conn"] == a_conn_c);
    assert_eq!(down["reason"], "grant_revoked");
    // B's own grant stays.
    assert!(grant_on(&mut p.a, &p.b.identity.clone()).is_some());
    // A confirm repeated for the same host and grant is the same removal.
    let again = p.b.call(
        "removal.confirm",
        json!({"identity": phone, "name": "Phone", "hosts": [{"host": host, "grant": grant}]}),
    );
    assert_eq!(again["removals"][0]["id"], id);
    let listed = p.b.call("removal.list", json!({}));
    assert_eq!(listed["removals"].as_array().unwrap().len(), 1);
    drop(c);
}

#[test]
fn removal_with_a_stale_grant_id_leaves_the_newer_pairing() {
    let mut p = pair_up("rmstale", &[], &[]);
    let (_c_end, mut c, _a_conn_c, _) = another_peer(&mut p.a, "rmstalec", &[]);
    caller_opens(&mut p.b, p.b_conn);
    let host = p.a.identity.clone();
    let phone = c.identity.clone();
    let old = planned_grant(&mut p.b, &host, &phone);
    // C pairs with A again: a new grant id replaces the old one.
    pair_apps(&mut p.a, &mut c);
    let newer = grant_on(&mut p.a, &phone).unwrap();
    assert_ne!(old, newer);

    let confirmed = p.b.call(
        "removal.confirm",
        json!({"identity": phone, "name": "Phone", "hosts": [{"host": host, "grant": old}]}),
    );
    let done = finished(&p.b, &confirmed["removals"][0]["id"]);
    assert_eq!(done["result"], "stale");
    assert_eq!(grant_on(&mut p.a, &phone), Some(newer));
}

#[test]
fn removal_on_a_host_that_learns_the_device_later_needs_a_second_confirmation() {
    let mut p = pair_up("rmask", &[], &[]);
    caller_opens(&mut p.b, p.b_conn);
    let host = p.a.identity.clone();
    // D is not paired with A yet: A's list does not name it.
    let d_end = Endpoint::init("rmaskd");
    let mut d = d_end.app("rmaskd", &[]);
    d.hello();
    let device = d.identity.clone();
    let plan = p.b.call("removal.plan", json!({"identity": device}));
    assert_eq!(plan["hosts"][0]["host"], host.as_str());
    assert!(plan["hosts"][0]["grant"].is_null());
    let confirmed = p.b.call(
        "removal.confirm",
        json!({"identity": device, "name": "Tablet", "hosts": []}),
    );
    assert!(confirmed["removals"].as_array().unwrap().is_empty());
    assert_eq!(confirmed["unknown"][0], host.as_str());

    // D pairs with A; A's next list names it, and B asks instead of
    // removing it.
    pair_apps(&mut p.a, &mut d);
    let grant = grant_on(&mut p.a, &device).unwrap();
    let ask =
        p.b.event("removal.ask", |m| m["identity"] == device.as_str());
    assert_eq!(ask["host"], host.as_str());
    assert_eq!(ask["grant"], grant);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        grant_on(&mut p.a, &device),
        Some(grant),
        "removed without asking"
    );
    assert!(p.b.events("removal.state").is_empty());

    let yes = p.b.call(
        "removal.ask.answer",
        json!({"identity": device, "host": host, "grant": grant, "yes": true}),
    );
    let done = finished(&p.b, &yes["removals"][0]["id"]);
    assert_eq!(done["result"], "applied");
    assert_eq!(grant_on(&mut p.a, &device), None);
}

#[test]
fn removal_goes_only_to_hosts_where_this_device_is_an_owner() {
    let mut p = pair_up("rmnotowner", &[], &[]);
    caller_opens(&mut p.b, p.b_conn);
    let stranger = Endpoint::init("rmnotownerx");
    let mut x = stranger.app("rmnotownerx", &[]);
    x.hello();
    let reply = p.b.request(
        "removal.confirm",
        json!({"identity": p.b.identity.clone(), "name": "Self", "hosts": [{"host": x.identity, "grant": 1}]}),
    );
    assert_eq!(reply["error"], "failed");
}

#[test]
fn removal_streams_cannot_be_opened_by_the_app() {
    let mut p = pair_up("rmlabel", &[], &[]);
    let reply = p.b.request(
        "stream.open",
        json!({"conn": p.b_conn, "label": "mousse-removal", "class": "interactive"}),
    );
    assert_eq!(reply["error"], "bad_request");
}
