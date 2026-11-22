//! `grant.add_connected` on the app channel (`docs/pairing-flow-design.md`
//! §7): the owner allows the peer at the other end of a live connection to
//! use this computer, and the grant takes that connection's authenticated
//! identity. The check cell `pairing-roles.grant-connected` runs this file.
//!
//! A is the host; B joined it, so B holds an outbound connection to A on
//! which A asks for access to B's computer.

mod common;

use common::*;
use serde_json::{json, Value};

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
    let a_end = Endpoint::init(&format!("{tag}a"));
    let b_end = Endpoint::init(&format!("{tag}b"));
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut b = b_end.app("peerB", &[]);
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

/// A connection that is closing when the request is handled grants
/// nothing: here `peer.forget` closes B's path to A just before.
#[test]
fn a_connection_closed_meanwhile_grants_nothing() {
    let mut p = paired("gccl", "owner");
    let a_identity = p.a.identity.clone();
    let forget = p.b.start("peer.forget", json!({"identity": a_identity}));
    let add = p.b.start(
        "grant.add_connected",
        json!({"conn": p.b_conn, "name": "hostA", "role": "owner"}),
    );
    assert_eq!(p.b.reply(forget)["forgotten"], json!(true));
    let reply = p.b.reply(add);
    assert_eq!(reply["error"], json!("no_conn"), "{reply}");
    assert!(grants_of(&mut p.b, &a_identity).is_empty());
    // Nor does a connection number this channel never had.
    let reply = add_connected(&mut p.b, 9999, "owner");
    assert_eq!(reply["error"], json!("no_conn"), "{reply}");
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
