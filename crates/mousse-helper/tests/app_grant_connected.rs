//! `grant.add_connected` on the app channel (`docs/pairing-flow-design.md`
//! §7): the owner allows the peer at the other end of a live connection to
//! use this computer, and the grant takes that connection's authenticated
//! identity. The check cell `pairing-roles.grant-connected` runs this file.
//!
//! A is the host; B joined it, so B holds an outbound connection to A on
//! which A asks for access to B's computer.

mod common;

use std::path::Path;

use common::*;
use mousse_net_core::grants::MAX_NAME_LEN;
use serde_json::{json, Value};

/// Debug builds: a closed connection's entry stays on the channel this
/// long before `conn.down`, so a request reaches the liveness check with
/// the closing entry still there, not the check for a missing one.
fn down_held() -> [(&'static str, &'static Path); 1] {
    [("MOUSSE_HELPER_TEST_DOWN_HOLD_MS", Path::new("5000"))]
}

/// B joined A in person, with an invitation of `role`.
struct Paired {
    a_end: Endpoint,
    a: App,
    b_end: Endpoint,
    b: App,
    /// B's outbound connection to A.
    b_conn: u64,
    /// A's inbound connection from B.
    a_conn: u64,
}

fn paired(tag: &str, role: &str) -> Paired {
    paired_with(tag, role, &[], &[])
}

/// [`paired`], with the debug-build hooks `a_raw` and `b_raw` set on A's
/// and B's helpers.
fn paired_with(tag: &str, role: &str, a_raw: &[(&str, &Path)], b_raw: &[(&str, &Path)]) -> Paired {
    let a_end = Endpoint::init(&format!("{tag}a"));
    let b_end = Endpoint::init(&format!("{tag}b"));
    let mut a = a_end.app_raw("hostA", &[], 0, a_raw);
    a.hello();
    let mut b = b_end.app_raw("peerB", &[], 0, b_raw);
    b.hello();
    let created = a.call("invite.create", json!({"role": role}));
    let invitation = created["invitation"].as_str().unwrap().to_owned();
    let join_id = b.start("join", json!({"ticket": created["uri"], "pinned": true}));
    let approval = a.event("approval", |m| m["invitation"] == invitation.as_str());
    a.call(
        "approval.answer",
        json!({"request": approval["request"], "yes": true}),
    );
    let join = b.reply(join_id);
    assert!(join.get("error").is_none(), "join: {join}");
    let identity = b.identity.clone();
    let a_conn = a.wait("the pairing connection on A", WAIT, |st| {
        st.messages
            .iter()
            .find(|m| {
                m["ev"] == "conn.up" && m["dir"] == "in" && m["identity"] == identity.as_str()
            })
            .map(|m| m["conn"].as_u64().unwrap())
    });
    Paired {
        b_conn: join["conn"].as_u64().unwrap(),
        a_conn,
        a_end,
        a,
        b_end,
        b,
    }
}

/// `identity`'s grants on `app`, as `grants.list` shows them.
fn grants_of(app: &mut App, identity: &str) -> Vec<Value> {
    app.call("grants.list", json!({}))["grants"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["identity"] == identity)
        .cloned()
        .collect()
}

fn add_connected(app: &mut App, conn: u64, role: &str) -> Value {
    app.request(
        "grant.add_connected",
        json!({"conn": conn, "name": "hostA", "role": role}),
    )
}

/// The grant is made for the identity the connection authenticated, with
/// the role asked for, and is on disk when the reply comes: a helper
/// killed right after it comes back with it.
#[test]
fn the_grant_is_the_connections_peer_and_is_saved_before_the_reply() {
    let mut p = paired("gcsv", "owner");
    let a_identity = p.a.identity.clone();
    let reply = add_connected(&mut p.b, p.b_conn, "viewer");
    assert_eq!(
        (&reply["role"], &reply["already"]),
        (&json!("viewer"), &json!(false)),
        "{reply}"
    );
    p.b.kill();
    let mut b = p.b_end.app("peerB", &[]);
    b.hello();
    let grants = grants_of(&mut b, &a_identity);
    assert_eq!(grants.len(), 1, "{grants:?}");
    assert_eq!(
        (&grants[0]["grant"], &grants[0]["role"]),
        (&reply["grant"], &json!("viewer")),
        "{grants:?}"
    );
}

/// The same request twice, back to back: one grant; the second reply
/// returns it.
#[test]
fn a_repeated_request_returns_the_one_grant() {
    let mut p = paired("gcdu", "owner");
    let a_identity = p.a.identity.clone();
    let fields = json!({"conn": p.b_conn, "name": "hostA", "role": "member"});
    let first = p.b.start("grant.add_connected", fields.clone());
    let second = p.b.start("grant.add_connected", fields);
    let (first, second) = (p.b.reply(first), p.b.reply(second));
    assert_eq!(first["grant"], second["grant"], "{first} {second}");
    assert_eq!(
        (&first["already"], &second["already"]),
        (&json!(false), &json!(true)),
        "{first} {second}"
    );
    assert_eq!(grants_of(&mut p.b, &a_identity).len(), 1);
}

/// `reply` is `no_conn` for a connection still on the channel but
/// closing, not for one already gone.
fn assert_closing(reply: &Value) {
    assert_eq!(reply["error"], json!("no_conn"), "{reply}");
    assert!(
        reply["reason"]
            .as_str()
            .is_some_and(|m| m.contains("is closing")),
        "{reply}"
    );
}

/// A connection that is closing when the request is handled grants
/// nothing: here `peer.forget` closes B's path to A just before. B keeps
/// the closing entry, so the request is refused by the liveness check.
#[test]
fn a_connection_closed_meanwhile_grants_nothing() {
    let mut p = paired_with("gccl", "owner", &[], &down_held());
    let a_identity = p.a.identity.clone();
    let forget = p.b.start("peer.forget", json!({"identity": a_identity}));
    let add = p.b.start(
        "grant.add_connected",
        json!({"conn": p.b_conn, "name": "hostA", "role": "owner"}),
    );
    assert_eq!(p.b.reply(forget)["forgotten"], json!(true));
    assert_closing(&p.b.reply(add));
    assert!(grants_of(&mut p.b, &a_identity).is_empty());
    // Nor does a connection number this channel never had.
    let reply = add_connected(&mut p.b, 9999, "owner");
    assert_eq!(reply["error"], json!("no_conn"), "{reply}");
}

/// A's inbound connection from B, closed by an edit of B's grant and then
/// by its removal, is refused while its entry is still there: no grant is
/// answered or made, and the edited grant keeps its role.
#[test]
fn an_inbound_connection_closed_by_an_edit_or_a_removal_grants_nothing() {
    let mut p = paired_with("gcin", "owner", &down_held(), &[]);
    let b_identity = p.b.identity.clone();
    let grant = grants_of(&mut p.a, &b_identity)[0]["grant"].clone();
    p.a.call(
        "grant.set_role",
        json!({"grant": grant, "expected_revision": 1, "role": "viewer"}),
    );
    assert_closing(&add_connected(&mut p.a, p.a_conn, "owner"));
    let grants = grants_of(&mut p.a, &b_identity);
    assert_eq!(grants.len(), 1, "{grants:?}");
    assert_eq!(
        (&grants[0]["role"], &grants[0]["revision"]),
        (&json!("viewer"), &json!(2)),
        "{grants:?}"
    );
    // B comes back on a new path, and A removes B's grant.
    let old = p.a_conn;
    let again = p.a.wait("B's new path to A", WAIT, |st| {
        st.messages
            .iter()
            .find(|m| {
                m["ev"] == "conn.up"
                    && m["dir"] == "in"
                    && m["identity"] == b_identity.as_str()
                    && m["conn"].as_u64() != Some(old)
            })
            .map(|m| m["conn"].as_u64().unwrap())
    });
    p.a.call("grant.remove", json!({"grant": grant}));
    assert_closing(&add_connected(&mut p.a, again, "owner"));
    assert!(grants_of(&mut p.a, &b_identity).is_empty());
}

/// B's outbound connection to A, closed by A (the peer's `GOAWAY`), not
/// by anything on B: B still reads it as closing and grants nothing.
#[test]
fn an_outbound_connection_the_peer_closed_grants_nothing() {
    let mut p = paired_with("gcga", "owner", &[], &down_held());
    let a_identity = p.a.identity.clone();
    let b_identity = p.b.identity.clone();
    let grant = grants_of(&mut p.a, &b_identity)[0]["grant"].clone();
    // A's edit closes its side of the path with GOAWAY.
    p.a.call(
        "grant.set_role",
        json!({"grant": grant, "expected_revision": 1, "role": "viewer"}),
    );
    let a_conn = p.a_conn;
    p.a.event("conn.down", |m| m["conn"].as_u64() == Some(a_conn));
    // A's side is done; the GOAWAY reached B before A's pipe closed.
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_closing(&add_connected(&mut p.b, p.b_conn, "owner"));
    assert!(grants_of(&mut p.b, &a_identity).is_empty());
}

/// While a removal that failed to save holds networking paused, no grant
/// is made.
#[test]
fn a_request_while_paused_is_refused() {
    let mut p = paired("gcps", "owner");
    let a_identity = p.a.identity.clone();
    let c_end = Endpoint::init("gcpsc");
    let mut c = c_end.app("peerC", &[]);
    c.hello();
    let added = p.b.call(
        "grant.add",
        json!({"identity": c.identity, "name": "C", "role": "viewer"}),
    );
    block_table(&p.b_end);
    let removed = p.b.call("grant.remove", json!({"grant": added["grant"]}));
    assert_eq!(removed["paused"], true, "{removed}");
    let reply = add_connected(&mut p.b, p.b_conn, "owner");
    assert_eq!(reply["error"], json!("paused"), "{reply}");
    assert!(grants_of(&mut p.b, &a_identity).is_empty());
}

/// The grant table cannot be written: a directory is in its way.
fn block_table(end: &Endpoint) {
    let table = end.dir.join("grants.json");
    let _ = std::fs::remove_file(&table);
    std::fs::create_dir_all(table.join("in-the-way")).unwrap();
}

fn unblock_table(end: &Endpoint) {
    std::fs::remove_dir_all(end.dir.join("grants.json")).unwrap();
}

/// A grant is answered only once the table is saved: a failed save is
/// `store_failed`, also for a grant that exists in memory only, on an
/// outbound connection (the grant this request made) and on an inbound
/// one (the grant it is live under, with another grant's save pending).
/// Once the table can be written, the repeated request saves it.
#[test]
fn a_grant_is_answered_only_once_saved() {
    let mut p = paired("gcsf", "owner");
    let a_identity = p.a.identity.clone();
    let b_identity = p.b.identity.clone();
    block_table(&p.b_end);
    for _ in 0..2 {
        let reply = add_connected(&mut p.b, p.b_conn, "viewer");
        assert_eq!(reply["error"], json!("store_failed"), "{reply}");
    }
    unblock_table(&p.b_end);
    let reply = add_connected(&mut p.b, p.b_conn, "viewer");
    assert_eq!(
        (&reply["role"], &reply["already"]),
        (&json!("viewer"), &json!(true)),
        "{reply}"
    );
    // A: another grant's save failed, so B's grant on A's inbound
    // connection is not answered until the table is saved.
    let c_end = Endpoint::init("gcsfc");
    let mut c = c_end.app("peerC", &[]);
    c.hello();
    let c_identity = c.identity.clone();
    block_table(&p.a_end);
    let added = p.a.request(
        "grant.add",
        json!({"identity": c_identity, "name": "C", "role": "viewer"}),
    );
    assert_eq!(added["error"], json!("store_failed"), "{added}");
    let reply = add_connected(&mut p.a, p.a_conn, "owner");
    assert_eq!(reply["error"], json!("store_failed"), "{reply}");
    unblock_table(&p.a_end);
    let reply = add_connected(&mut p.a, p.a_conn, "owner");
    assert_eq!(reply["already"], json!(true), "{reply}");
    // Both tables are on disk.
    p.a.kill();
    p.b.kill();
    let mut a = p.a_end.app("hostA", &[]);
    a.hello();
    assert_eq!(grants_of(&mut a, &c_identity).len(), 1);
    assert_eq!(grants_of(&mut a, &b_identity).len(), 1);
    let mut b = p.b_end.app("peerB", &[]);
    b.hello();
    assert_eq!(grants_of(&mut b, &a_identity).len(), 1);
}

/// A name the grant name rule refuses is `bad_request`, also when the
/// grant exists already.
#[test]
fn a_name_outside_the_rule_is_refused() {
    let mut p = paired("gcnm", "owner");
    let long = "n".repeat(MAX_NAME_LEN + 1);
    for name in ["", long.as_str()] {
        let reply = p.b.request(
            "grant.add_connected",
            json!({"conn": p.b_conn, "name": name, "role": "owner"}),
        );
        assert_eq!(reply["error"], json!("bad_request"), "{reply}");
    }
    let made = add_connected(&mut p.b, p.b_conn, "viewer");
    assert_eq!(made["already"], json!(false), "{made}");
    let reply = p.b.request(
        "grant.add_connected",
        json!({"conn": p.b_conn, "name": long, "role": "viewer"}),
    );
    assert_eq!(reply["error"], json!("bad_request"), "{reply}");
    let longest = "n".repeat(MAX_NAME_LEN);
    let reply = p.b.request(
        "grant.add_connected",
        json!({"conn": p.b_conn, "name": longest, "role": "viewer"}),
    );
    assert_eq!(reply["already"], json!(true), "{reply}");
}

/// A 1.2 app learns from `hello` that this helper takes
/// `grant.add_connected`.
#[test]
fn a_1_2_hello_lists_the_feature() {
    let end = Endpoint::init("gchl");
    let mut app = end.app("hostA", &[]);
    let hello = app.call("hello", json!({"proto": [1, 2]}));
    assert!(
        hello["features"]
            .as_array()
            .is_some_and(|f| f.contains(&json!("grant-add-connected"))),
        "{hello}"
    );
}

/// A grant that exists is returned with its own role, not widened to the
/// one asked for: on an outbound connection (a grant made earlier with
/// `grant.add`) and on an inbound one (the grant it is live under).
#[test]
fn an_existing_narrower_grant_is_returned_as_it_is() {
    let mut p = paired("gcnr", "viewer");
    let a_identity = p.a.identity.clone();
    let b_identity = p.b.identity.clone();
    let added = p.b.call(
        "grant.add",
        json!({"identity": a_identity, "name": "hostA", "role": "viewer"}),
    );
    let reply = add_connected(&mut p.b, p.b_conn, "owner");
    assert_eq!(
        (&reply["grant"], &reply["role"], &reply["already"]),
        (&added["grant"], &json!("viewer"), &json!(true)),
        "{reply}"
    );
    let grants = grants_of(&mut p.b, &a_identity);
    assert_eq!(
        (&grants[0]["role"], &grants[0]["revision"]),
        (&json!("viewer"), &json!(1)),
        "{grants:?}"
    );
    // A's inbound connection from B is live under A's viewer grant of B.
    let reply = add_connected(&mut p.a, p.a_conn, "owner");
    assert_eq!(
        (&reply["role"], &reply["already"]),
        (&json!("viewer"), &json!(true)),
        "{reply}"
    );
    let grants = grants_of(&mut p.a, &b_identity);
    assert_eq!(grants[0]["role"], json!("viewer"), "{grants:?}");
}

/// An identity this computer denied is refused, even on a live
/// connection.
#[test]
fn a_denied_identity_is_refused() {
    let mut p = paired("gcdn", "owner");
    let a_identity = p.a.identity.clone();
    let added = p.b.call(
        "grant.add",
        json!({"identity": a_identity, "name": "hostA", "role": "viewer"}),
    );
    p.b.kill();
    let grant = added["grant"].to_string();
    let mut remove = p.b_end.cli(&["remove", &grant, "--deny"], false);
    assert_eq!(
        remove.exit_within(WAIT),
        Some(0),
        "remove: {}",
        remove.err()
    );
    let mut b = p.b_end.app("peerB", &[]);
    b.hello();
    let conn = b.wait("B's path to A again", WAIT, |st| {
        st.messages
            .iter()
            .find(|m| {
                m["ev"] == "conn.up" && m["dir"] == "out" && m["identity"] == a_identity.as_str()
            })
            .map(|m| m["conn"].as_u64().unwrap())
    });
    let reply = add_connected(&mut b, conn, "owner");
    assert_eq!(reply["error"], json!("refused"), "{reply}");
    assert!(
        reply["reason"]
            .as_str()
            .is_some_and(|m| m.contains("denied")),
        "{reply}"
    );
    assert!(grants_of(&mut b, &a_identity).is_empty());
    drop(p.a);
    drop(p.a_end);
}

/// The identity is the connection's, never one the request names: a
/// request that names one is refused and grants nobody.
#[test]
fn the_identity_is_never_read_from_the_request() {
    let mut p = paired("gcid", "owner");
    let a_identity = p.a.identity.clone();
    let c_end = Endpoint::init("gcidc");
    let mut c = c_end.app("peerC", &[]);
    c.hello();
    let c_identity = c.identity.clone();
    let reply = p.b.request(
        "grant.add_connected",
        json!({"conn": p.b_conn, "name": "C", "role": "owner", "identity": c_identity}),
    );
    assert_eq!(reply["error"], json!("bad_request"), "{reply}");
    assert!(grants_of(&mut p.b, &c_identity).is_empty());
    assert!(grants_of(&mut p.b, &a_identity).is_empty());
}

/// Every field is required.
#[test]
fn a_request_missing_a_field_is_refused() {
    let mut p = paired("gcbr", "owner");
    let a_identity = p.a.identity.clone();
    for fields in [
        json!({"name": "hostA", "role": "owner"}),
        json!({"conn": p.b_conn, "role": "owner"}),
        json!({"conn": p.b_conn, "name": "hostA"}),
        json!({"conn": p.b_conn, "name": "hostA", "role": "Not A Role"}),
    ] {
        let reply = p.b.request("grant.add_connected", fields.clone());
        assert_eq!(reply["error"], json!("bad_request"), "{fields} {reply}");
    }
    assert!(grants_of(&mut p.b, &a_identity).is_empty());
}
