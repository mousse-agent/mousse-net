//! Grant roles on the app channel (`docs/pairing-flow-design.md` §8):
//! choosing the role at invitation, approval and `grant.add`, editing it in
//! place with `grant.set_role`, cutting what was served under the old role,
//! and serving a role other than `owner` only to an app that opted in.
//! The check cell `pairing-roles.grant-roles` runs this file.
//!
//! A is the host; B (and C) joined it.

mod common;
#[path = "common/relay.rs"]
mod relay_fixture;

use std::path::Path;
use std::time::Duration;

use common::*;
use serde_json::{json, Value};

/// `hello` as a 1.2 app that takes `grant-roles`.
fn hello_roles(app: &mut App) {
    let name = app.name.clone();
    let reply = app.call(
        "hello",
        json!({"proto": [1, 2], "name": name, "features": ["grant-roles"]}),
    );
    assert!(
        reply["features"]
            .as_array()
            .is_some_and(|f| f.contains(&json!("grant-roles"))),
        "{reply}"
    );
    app.identity = reply["identity"].as_str().unwrap().to_owned();
}

/// A started as a 1.2 app that takes `grant-roles`, and B as a plain app.
fn started(tag: &str) -> (Endpoint, App, Endpoint, App) {
    let a_end = Endpoint::init(&format!("{tag}a"));
    let b_end = Endpoint::init(&format!("{tag}b"));
    let mut a = a_end.app("hostA", &[]);
    hello_roles(&mut a);
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    (a_end, a, b_end, b)
}

/// What pairing in person with roles gave.
struct Paired {
    enrolled: Value,
    join: Value,
    a_conn: u64,
    b_conn: u64,
}

/// B joins A in person: A invites with `invite` (if any) and answers yes
/// with `answer` (if any).
fn pair_as(a: &mut App, b: &mut App, invite: Option<&str>, answer: Option<&str>) -> Paired {
    let fields = match invite {
        Some(role) => json!({"role": role}),
        None => json!({}),
    };
    let created = a.call("invite.create", fields);
    let invitation = created["invitation"].as_str().unwrap().to_owned();
    let join_id = b.start("join", json!({"ticket": created["uri"], "pinned": true}));
    let approval = a.event("approval", |m| m["invitation"] == invitation.as_str());
    let mut fields = json!({"request": approval["request"], "yes": true});
    if let Some(role) = answer {
        fields["role"] = json!(role);
    }
    a.call("approval.answer", fields);
    let join = b.reply(join_id);
    assert!(join.get("error").is_none(), "join: {join}");
    let enrolled = a.event("enrolled", |m| m["invitation"] == invitation.as_str());
    let identity = b.identity.clone();
    let a_conn = a.wait("the pairing connection on A", WAIT, |st| {
        st.messages
            .iter()
            .rev()
            .find(|m| {
                m["ev"] == "conn.up" && m["dir"] == "in" && m["identity"] == identity.as_str()
            })
            .map(|m| m["conn"].as_u64().unwrap())
    });
    Paired {
        b_conn: join["conn"].as_u64().unwrap(),
        enrolled,
        join,
        a_conn,
    }
}

/// `identity`'s grant on `app`, as `grants.list` shows it.
fn grant_of(app: &mut App, identity: &str) -> Value {
    app.call("grants.list", json!({}))["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["identity"] == identity)
        .cloned()
        .unwrap_or(Value::Null)
}

/// The `n`th (from 0) outbound connection `app` announced to `identity`.
fn outbound(app: &App, identity: &str, n: usize) -> u64 {
    app.wait("an outbound conn.up", WAIT, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == "conn.up" && m["dir"] == "out" && m["identity"] == identity)
            .nth(n)
            .map(|m| m["conn"].as_u64().unwrap())
    })
}

/// The `stream.incoming` on `app` for its `n`th stream on `conn`.
fn incoming(app: &App, conn: u64, n: usize) -> Value {
    app.wait("stream.incoming", WAIT, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == "stream.incoming" && m["conn"] == conn)
            .nth(n)
            .cloned()
    })
}

#[test]
fn the_role_chosen_with_the_answer_is_the_grants_role() {
    let (_ae, mut a, _be, mut b) = started("grra");
    let p = pair_as(&mut a, &mut b, Some("client"), Some("member"));
    assert_eq!(p.enrolled["role"], "member", "{}", p.enrolled);
    assert_eq!(p.join["role"], "member", "{}", p.join);
    let g = grant_of(&mut a, &b.identity);
    assert_eq!((&g["role"], &g["revision"]), (&json!("member"), &json!(1)));
}

/// A "Send link" invitation made with a role other than `owner` enrolls
/// with that role: the grant, `enrolled` and the joiner's reply carry it.
#[test]
fn a_link_invitation_keeps_its_role_on_enrollment() {
    let (_ae, mut a, _be, mut b) = started("grrl2");
    let invite = a.call("invite.create", json!({"kind": "link", "role": "viewer"}));
    let inv = invite["invitation"].as_str().unwrap().to_owned();
    let route = invite["routes"][0].as_str().unwrap().to_owned();
    let id = b.start(
        "join",
        json!({"ticket": invite["uri"], "arrival": "link", "approved": [route]}),
    );
    b.event("join.code_needed", |m| m["invitation"] == inv.as_str());
    b.call(
        "join.code",
        json!({"invitation": inv, "code": invite["code"]}),
    );
    let join = b.reply(id);
    assert_eq!(join["role"], "viewer", "{join}");
    let enrolled = a.event("enrolled", |m| m["invitation"] == inv.as_str());
    assert_eq!(enrolled["role"], "viewer", "{enrolled}");
    let g = grant_of(&mut a, &b.identity);
    assert_eq!((&g["role"], &g["revision"]), (&json!("viewer"), &json!(1)));
}

#[test]
fn without_a_chosen_role_the_grant_takes_the_invitations() {
    let (_ae, mut a, _be, mut b) = started("grrb");
    let p = pair_as(&mut a, &mut b, Some("client"), None);
    assert_eq!(p.enrolled["role"], "client", "{}", p.enrolled);
    assert_eq!(grant_of(&mut a, &b.identity)["role"], "client");
}

#[test]
fn a_bad_answer_is_refused_and_leaves_the_request_waiting() {
    let (_ae, mut a, _be, mut b) = started("grrc");
    let created = a.call("invite.create", json!({}));
    let invitation = created["invitation"].as_str().unwrap().to_owned();
    let join_id = b.start("join", json!({"ticket": created["uri"], "pinned": true}));
    let approval = a.event("approval", |m| m["invitation"] == invitation.as_str());
    let request = approval["request"].clone();
    for bad in [
        json!({"request": request, "yes": false, "role": "member"}),
        json!({"request": request, "yes": true, "role": "Not A Role"}),
        json!({"request": request, "yes": true, "role": 7}),
    ] {
        let reply = a.request("approval.answer", bad.clone());
        assert_eq!(reply["error"], "bad_request", "{bad}: {reply}");
    }
    a.call(
        "approval.answer",
        json!({"request": request, "yes": true, "role": "viewer"}),
    );
    assert!(b.reply(join_id).get("error").is_none());
    let enrolled = a.event("enrolled", |m| m["invitation"] == invitation.as_str());
    assert_eq!(enrolled["role"], "viewer");
}

#[test]
fn grant_add_takes_a_role_and_never_changes_an_existing_grant() {
    let (_ae, mut a, _be, b) = started("grrd");
    let made = a.call(
        "grant.add",
        json!({"identity": b.identity, "name": "peerB", "role": "viewer"}),
    );
    assert_eq!(
        (&made["role"], &made["already"]),
        (&json!("viewer"), &json!(false))
    );
    let again = a.call(
        "grant.add",
        json!({"identity": b.identity, "name": "peerB", "role": "owner"}),
    );
    assert_eq!(
        (&again["role"], &again["already"]),
        (&json!("viewer"), &json!(true))
    );
    assert_eq!(again["grant"], made["grant"]);
    let bad = a.request(
        "grant.add",
        json!({"identity": b.identity, "name": "peerB", "role": ""}),
    );
    assert_eq!(bad["error"], "bad_request", "{bad}");
}

/// An edit keeps the grant and closes its connection with `CANCELLED`;
/// a removal beside it still closes with `GRANT_REVOKED`.
#[test]
fn a_role_edit_cancels_where_a_removal_revokes() {
    let (_ae, mut a, _be, mut b) = started("grre");
    let pb = pair_as(&mut a, &mut b, None, None);
    let (_ce, mut c) = {
        let end = Endpoint::init("grrec");
        let mut app = end.app("peerC", &[]);
        app.hello();
        (end, app)
    };
    let pc = pair_as(&mut a, &mut c, None, None);
    let grant_b = grant_of(&mut a, &b.identity)["grant"].clone();
    let grant_c = grant_of(&mut a, &c.identity)["grant"].clone();

    let edited = a.call(
        "grant.set_role",
        json!({"grant": grant_b, "expected_revision": 1, "role": "member"}),
    );
    assert_eq!(
        edited,
        json!({"re": edited["re"], "grant": grant_b, "role": "member", "revision": 2, "changed": true})
    );
    let changed = a.event("grant.role_changed", |m| m["grant"] == grant_b);
    assert_eq!(
        (&changed["role"], &changed["revision"]),
        (&json!("member"), &json!(2))
    );
    let down = a.event("conn.down", |m| m["conn"] == pb.a_conn);
    assert_eq!(down["reason"], "cancelled", "{down}");
    assert_eq!(grant_of(&mut a, &b.identity)["grant"], grant_b);

    a.call("grant.remove", json!({"grant": grant_c}));
    let down = a.event("conn.down", |m| m["conn"] == pc.a_conn);
    assert_eq!(down["reason"], "grant_revoked", "{down}");
}

/// B's caller key on A, and the pair secret A answered it with, belong to
/// B's grant, which an edit keeps in place: after the edit and B's new
/// path, A holds the same key with the same salt (so the same pair
/// secret), and B the same sealed secret, without a new `peer.keys`.
#[test]
fn an_edit_keeps_the_caller_key_and_the_pair_secret() {
    let relay = relay_fixture::TestRelay::start();
    let (ae, mut a, be, mut b) = started("grrs");
    let enrolled = a.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");
    pair_as(&mut a, &mut b, None, None);
    b.event("peer.keys", |m| m["identity"] == a.identity.as_str());
    let a_identity = a.identity.clone();
    let keys = || -> Vec<Value> {
        let file: Value =
            serde_json::from_slice(&std::fs::read(ae.dir.join("relay-grants.json")).unwrap())
                .unwrap();
        file["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| json!([k["grant"], k["identity"], k["caller"], k["salt"]]))
            .collect()
    };
    let secret = || -> Value {
        let file: Value =
            serde_json::from_slice(&std::fs::read(be.dir.join("relay-peers.json")).unwrap())
                .unwrap();
        file["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["identity"] == a_identity.as_str())
            .map(|p| p["pair_secret"].clone())
            .unwrap_or(Value::Null)
    };
    let (keys_before, secret_before) = (keys(), secret());
    assert_eq!(keys_before.len(), 1, "{keys_before:?}");
    assert!(secret_before.is_string(), "{secret_before}");

    let grant = grant_of(&mut a, &b.identity)["grant"].clone();
    a.call(
        "grant.set_role",
        json!({"grant": grant, "expected_revision": 1, "role": "member"}),
    );
    // B's new path confirms its key again.
    outbound(&b, &a.identity, 1);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(keys(), keys_before);
    assert_eq!(secret(), secret_before);
    assert_eq!(b.events("peer.keys").len(), 1);
    let g = grant_of(&mut a, &b.identity);
    assert_eq!(
        (&g["grant"], &g["relay"]),
        (&grant, &json!("listed")),
        "{g}"
    );
}

/// While a removal that failed to save holds networking paused, a role
/// edit is refused as `paused` and changes nothing.
#[test]
fn a_role_edit_while_a_removal_is_not_saved_is_paused() {
    let (ae, mut a, _be, mut b) = started("grrp");
    pair_as(&mut a, &mut b, None, None);
    let (_ce, mut c) = {
        let end = Endpoint::init("grrpc");
        let mut app = end.app("peerC", &[]);
        app.hello();
        (end, app)
    };
    pair_as(&mut a, &mut c, None, None);
    let grant_b = grant_of(&mut a, &b.identity)["grant"].clone();
    let grant_c = grant_of(&mut a, &c.identity)["grant"].clone();
    // The grant table cannot be written: a directory is in its way.
    let table = ae.dir.join("grants.json");
    std::fs::remove_file(&table).unwrap();
    std::fs::create_dir_all(table.join("in-the-way")).unwrap();
    let removed = a.call("grant.remove", json!({"grant": grant_c}));
    assert_eq!(removed["paused"], true, "{removed}");
    let reply = a.request(
        "grant.set_role",
        json!({"grant": grant_b, "expected_revision": 1, "role": "member"}),
    );
    assert_eq!(reply["error"], "paused", "{reply}");
    let g = grant_of(&mut a, &b.identity);
    assert_eq!((&g["role"], &g["revision"]), (&json!("owner"), &json!(1)));
}

#[test]
fn a_stale_revision_is_refused_and_the_same_role_is_no_change() {
    let (_ae, mut a, _be, mut b) = started("grrf");
    pair_as(&mut a, &mut b, None, None);
    let grant = grant_of(&mut a, &b.identity)["grant"].clone();
    a.call(
        "grant.set_role",
        json!({"grant": grant, "expected_revision": 1, "role": "member"}),
    );
    let stale = a.request(
        "grant.set_role",
        json!({"grant": grant, "expected_revision": 1, "role": "owner"}),
    );
    assert_eq!(stale["error"], "revision_conflict", "{stale}");
    let g = grant_of(&mut a, &b.identity);
    assert_eq!((&g["role"], &g["revision"]), (&json!("member"), &json!(2)));
    let same = a.call(
        "grant.set_role",
        json!({"grant": grant, "expected_revision": 2, "role": "member"}),
    );
    assert_eq!(
        (&same["changed"], &same["revision"]),
        (&json!(false), &json!(2))
    );
    for (bad, code) in [
        (
            json!({"grant": 999, "expected_revision": 1, "role": "member"}),
            "no_grant",
        ),
        (json!({"grant": grant, "role": "member"}), "bad_request"),
        (
            json!({"grant": grant, "expected_revision": 2, "role": "Member"}),
            "bad_request",
        ),
        (
            json!({"grant": grant, "expected_revision": 2, "role": "member", "why": "x"}),
            "bad_request",
        ),
    ] {
        let reply = a.request("grant.set_role", bad.clone());
        assert_eq!(reply["error"], code, "{bad}: {reply}");
    }
}

/// B's grant on A is narrowed, B reconnects and calls A: an app that
/// did not opt in to `grant-roles` never gets the stream.
fn refused_to(a: &mut App, b: &mut App) {
    pair_as(a, b, None, None);
    let grant = grant_of(a, &b.identity)["grant"].clone();
    a.call(
        "grant.set_role",
        json!({"grant": grant, "expected_revision": 1, "role": "member"}),
    );
    // The keeper reconnects after CANCELLED.
    let conn = outbound(b, &a.identity, 1);
    let h = b.open(conn, "mousse.rpc", "interactive");
    b.send(h, b"for an owner only", true);
    let reset = b.event("stream.reset", |m| m["handle"] == h);
    assert_eq!(reset["code"], "refused_stream", "{reset}");
    assert!(a.events("stream.incoming").is_empty());
}

#[test]
fn a_1_1_app_never_gets_streams_of_a_restricted_grant() {
    let a_end = Endpoint::init("grrga");
    let b_end = Endpoint::init("grrgb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    refused_to(&mut a, &mut b);
}

#[test]
fn a_1_2_app_that_did_not_opt_in_never_gets_streams_of_a_restricted_grant() {
    let a_end = Endpoint::init("grrha");
    let b_end = Endpoint::init("grrhb");
    let mut a = a_end.app("hostA", &[]);
    let reply = a.call("hello", json!({"proto": [1, 2], "name": "hostA"}));
    a.identity = reply["identity"].as_str().unwrap().to_owned();
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    refused_to(&mut a, &mut b);
}

/// The other direction: B's app did not opt in to `grant-roles`, and B
/// grants A the role `member`. A call A opens on B's connection to it is
/// refused, and B's app never gets it.
#[test]
fn a_call_from_the_host_under_a_restricted_grant_is_refused_to_an_app_that_did_not_opt_in() {
    let (_ae, mut a, _be, mut b) = started("grrm");
    let p = pair_as(&mut a, &mut b, None, None);
    let added = b.call(
        "grant.add",
        json!({"identity": a.identity, "name": "hostA", "role": "member"}),
    );
    assert_eq!(added["role"], "member", "{added}");
    let h = b.open(p.b_conn, "mousse.rpc", "interactive");
    b.send(h, b"first", true);
    incoming(&a, p.a_conn, 0);
    let call = a.open(p.a_conn, "mousse.rpc", "interactive");
    a.send(call, b"for an owner only", false);
    let reset = a.event("stream.reset", |m| m["handle"] == call);
    assert_eq!(reset["code"], "refused_stream", "{reset}");
    assert!(
        b.events("stream.incoming").is_empty(),
        "{:?}",
        b.events("stream.incoming")
    );
}

/// Streams in both directions carry the grant they are served under: on
/// A, B's grant there; on B, its grant for A.
#[test]
fn every_stream_carries_its_grant_role_and_revision() {
    let (_ae, mut a, _be, mut b) = started("grri");
    let p = pair_as(&mut a, &mut b, None, Some("member"));
    let added = b.call(
        "grant.add",
        json!({"identity": a.identity, "name": "hostA", "role": "owner"}),
    );
    let h = b.open(p.b_conn, "mousse.rpc", "interactive");
    b.send(h, b"to A", true);
    let at_a = incoming(&a, p.a_conn, 0);
    let grant_b = grant_of(&mut a, &b.identity)["grant"].clone();
    assert_eq!(
        (&at_a["grant"], &at_a["role"], &at_a["revision"]),
        (&grant_b, &json!("member"), &json!(1)),
        "{at_a}"
    );
    let h = a.open(p.a_conn, "mousse.rpc", "interactive");
    a.send(h, b"to B", true);
    let at_b = incoming(&b, p.b_conn, 0);
    assert_eq!(
        (&at_b["grant"], &at_b["role"], &at_b["revision"]),
        (&added["grant"], &json!("owner"), &json!(1)),
        "{at_b}"
    );
}

/// A's app has stopped reading: B's bulk fills what A's helper writes to
/// it, and a second stream B opens is announced behind it. A narrows B's
/// grant meanwhile. Once A reads again, the cut stream's announcement
/// never arrives: the app hears of no stream under the old revision after
/// the edit, and of no reset for a stream it never saw.
#[test]
fn an_announcement_waiting_under_the_old_role_never_reaches_the_app() {
    let (_ae, mut a, _be, mut b) = started("grrq");
    let p = pair_as(&mut a, &mut b, None, None);
    let grant = grant_of(&mut a, &b.identity)["grant"].clone();
    let bulk = b.open(p.b_conn, "mousse.blob", "bulk");
    let first = a.incoming(p.a_conn, 0);
    a.accept(first);
    a.credit(first, 16 << 20);
    a.pause();
    let size = 6 << 20;
    b.send(bulk, &pattern(size, 7), false);
    b.wait("the bulk to go", WAIT, |st| {
        (st.tx[&bulk].sent == size as u64).then_some(())
    });
    std::thread::sleep(Duration::from_millis(500));
    let late = b.open(p.b_conn, "mousse.rpc", "interactive");
    b.send(late, b"late", false);
    std::thread::sleep(Duration::from_millis(500));
    let edit = a.start(
        "grant.set_role",
        json!({"grant": grant, "expected_revision": 1, "role": "member"}),
    );
    std::thread::sleep(Duration::from_millis(1000));
    a.resume();
    let reply = a.reply(edit);
    assert_eq!(reply["changed"], json!(true), "{reply}");
    a.event("conn.down", |m| m["conn"] == p.a_conn);
    let announced: Vec<Value> = a
        .events("stream.incoming")
        .into_iter()
        .filter(|m| m["conn"] == p.a_conn)
        .collect();
    assert_eq!(
        announced.len(),
        1,
        "a stream cut by the edit was announced: {announced:?}"
    );
    let resets: Vec<Value> = a
        .events("stream.reset")
        .into_iter()
        .filter(|m| m["handle"] != json!(first))
        .collect();
    assert!(resets.is_empty(), "{resets:?}");
}

/// A opens a call on B's connection to it just before B narrows its grant
/// for A; B's helper has accepted the call and not served it yet (a test
/// hold keeps it there, and keeps the closed connection's entry). The
/// edit cut that path: the call is never delivered on it, under either
/// revision.
#[test]
fn a_call_waiting_on_a_cut_path_is_never_delivered() {
    let a_end = Endpoint::init("grrka");
    let b_end = Endpoint::init("grrkb");
    let mut a = a_end.app("hostA", &[]);
    hello_roles(&mut a);
    let mut b = b_end.app_raw(
        "peerB",
        &[],
        0,
        &[
            ("MOUSSE_HELPER_TEST_STREAM_HOLD_MS", Path::new("1500")),
            ("MOUSSE_HELPER_TEST_DOWN_HOLD_MS", Path::new("5000")),
        ],
    );
    hello_roles(&mut b);
    let p = pair_as(&mut a, &mut b, None, None);
    let added = b.call(
        "grant.add",
        json!({"identity": a.identity, "name": "hostA"}),
    );
    let h = b.open(p.b_conn, "mousse.rpc", "interactive");
    b.send(h, b"first", true);
    incoming(&a, p.a_conn, 0);
    let call = a.open(p.a_conn, "mousse.rpc", "interactive");
    a.send(call, b"late call", false);
    std::thread::sleep(Duration::from_millis(300));
    let edited = b.call(
        "grant.set_role",
        json!({"grant": added["grant"], "expected_revision": 1, "role": "member"}),
    );
    assert_eq!(edited["changed"], json!(true), "{edited}");
    // Past the hold, while B still keeps the closed connection's entry.
    std::thread::sleep(Duration::from_millis(2500));
    let delivered: Vec<Value> = b
        .events("stream.incoming")
        .into_iter()
        .filter(|m| m["conn"] == p.b_conn)
        .collect();
    assert!(
        delivered.is_empty(),
        "a call was delivered on a path the edit cut: {delivered:?}"
    );
}

/// B narrows its grant for A while A has a call open on B's connection:
/// the call is reset with `CANCELLED` and B's connection to A, which
/// served it, closes with `CANCELLED`.
#[test]
fn a_role_edit_cuts_the_calls_served_on_the_reverse_path() {
    let a_end = Endpoint::init("grrja");
    let b_end = Endpoint::init("grrjb");
    let mut a = a_end.app("hostA", &[]);
    hello_roles(&mut a);
    let mut b = b_end.app("peerB", &[]);
    hello_roles(&mut b);
    let p = pair_as(&mut a, &mut b, None, None);
    let added = b.call(
        "grant.add",
        json!({"identity": a.identity, "name": "hostA"}),
    );
    let h = b.open(p.b_conn, "mousse.rpc", "interactive");
    b.send(h, b"first", true);
    incoming(&a, p.a_conn, 0);
    let call = a.open(p.a_conn, "mousse.rpc", "interactive");
    a.send(call, b"open call", false);
    let served = incoming(&b, p.b_conn, 0);
    let bh = served["handle"].clone();
    b.call(
        "grant.set_role",
        json!({"grant": added["grant"], "expected_revision": 1, "role": "member"}),
    );
    let reset = b.event("stream.reset", |m| m["handle"] == bh);
    assert_eq!(reset["code"], "cancelled", "{reset}");
    let down = b.event("conn.down", |m| m["conn"] == p.b_conn);
    assert_eq!(down["reason"], "cancelled", "{down}");
}

#[test]
fn a_role_edit_survives_a_restart() {
    let (a_end, mut a, _be, mut b) = started("grrk");
    pair_as(&mut a, &mut b, None, None);
    let grant = grant_of(&mut a, &b.identity)["grant"].clone();
    a.call(
        "grant.set_role",
        json!({"grant": grant, "expected_revision": 1, "role": "viewer"}),
    );
    a.kill();
    drop(a);
    let mut a = a_end.app("hostA", &[]);
    hello_roles(&mut a);
    let g = grant_of(&mut a, &b.identity);
    assert_eq!(
        (&g["grant"], &g["role"], &g["revision"]),
        (&grant, &json!("viewer"), &json!(2)),
        "{g}"
    );
}

/// Whether `admin`'s stored grant lists from `host` name `device`.
fn plan_names(admin: &mut App, host: &str, device: &str) -> bool {
    let plan = admin.call("removal.plan", json!({"identity": device}));
    plan["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h["host"] == host && h["grant"].is_u64())
}

/// B, an owner, gets A's grant list on `mousse-grants`. Once A narrows B's
/// grant, B gets no list again: a grant made after the edit never reaches
/// it.
#[test]
fn a_demoted_owner_gets_no_grant_list() {
    let (_ae, mut a, _be, mut b) = started("grrl");
    let p = pair_as(&mut a, &mut b, None, None);
    let (_ce, mut c) = {
        let end = Endpoint::init("grrlc");
        let mut app = end.app("peerC", &[]);
        app.hello();
        (end, app)
    };
    pair_as(&mut a, &mut c, None, None);
    // B opens a stream so A may open `mousse-grants` (wire.md 8, step 4).
    b.open(p.b_conn, "mousse.hello", "interactive");
    let (host, phone) = (a.identity.clone(), c.identity.clone());
    let deadline = std::time::Instant::now() + WAIT;
    while !plan_names(&mut b, &host, &phone) {
        assert!(std::time::Instant::now() < deadline, "no list from A");
        std::thread::sleep(Duration::from_millis(100));
    }

    let grant = grant_of(&mut a, &b.identity)["grant"].clone();
    a.call(
        "grant.set_role",
        json!({"grant": grant, "expected_revision": 1, "role": "member"}),
    );
    // The edit cut B's path; B comes back on a new one, live under the
    // member grant, and opens a stream on it as before.
    let old = p.b_conn;
    let again = b.wait("B's new path to A", WAIT, |st| {
        st.messages
            .iter()
            .find(|m| {
                m["ev"] == "conn.up"
                    && m["dir"] == "out"
                    && m["identity"] == host.as_str()
                    && m["conn"].as_u64() != Some(old)
            })
            .map(|m| m["conn"].as_u64().unwrap())
    });
    b.open(again, "mousse.hello", "interactive");
    let d_end = Endpoint::init("grrld");
    let mut d = d_end.app("peerD", &[]);
    d.hello();
    a.call(
        "grant.add",
        json!({"identity": d.identity, "name": "peerD"}),
    );
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        !plan_names(&mut b, &host, &d.identity),
        "a demoted owner got a grant list made after the edit"
    );
}
