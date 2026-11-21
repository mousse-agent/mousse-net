//! One connection carries calls both ways (minor 3): the host opens app
//! streams on the caller's connection, and the caller serves them under its
//! own grant for the host (wire.md 8, step 5). `conn.up {both}` says so; a
//! removal of that grant resets them; with a minor 2 peer nothing changes.
//!
//! A is the host, B joined it: B's outbound connection is the only one.

mod common;

use std::path::Path;

use common::*;
use serde_json::{json, Value};

/// A and B paired (A hosts B), B holding a grant for A as the app's
/// pairing back does, and B's first stream to A sent. Returns the pairing
/// and B's grant for A.
fn paired(a: &mut App, b: &mut App) -> (Joined, u64) {
    let joined = pair_apps(a, b);
    let added = b.call(
        "grant.add",
        json!({"identity": a.identity, "name": "hostA"}),
    );
    let grant = added["grant"].as_u64().unwrap();
    // The caller opens streams first (wire.md 8, step 4).
    let h = b.open(joined.b_conn, "mousse.rpc", "interactive");
    b.send(h, b"hello A", true);
    let incoming = a.event("stream.incoming", |m| m["conn"] == joined.a_conn);
    let ah = incoming["handle"].as_u64().unwrap() as u32;
    a.accept(ah);
    a.credit(ah, 1 << 20);
    assert_eq!(a.until_fin(ah, WAIT), b"hello A");
    (joined, grant)
}

/// The `stream.incoming` on B for a stream A opened on B's connection.
fn incoming_on_b(b: &App, b_conn: u64, n: usize) -> Value {
    b.wait("a stream A opened on B's connection", WAIT, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == "stream.incoming" && m["conn"] == b_conn)
            .nth(n)
            .cloned()
    })
}

#[test]
fn the_dialled_side_calls_the_dialler_over_the_diallers_connection() {
    let (_ae, _be) = (Endpoint::init("bwa"), Endpoint::init("bwb"));
    let mut a = _ae.app("hostA", &[]);
    a.hello();
    let mut b = _be.app("peerB", &[]);
    b.hello();
    let (j, grant) = paired(&mut a, &mut b);
    let up_a = a.event("conn.up", |m| m["conn"] == j.a_conn);
    let up_b = b.event("conn.up", |m| m["conn"] == j.b_conn);
    assert_eq!(up_a["both"], true, "{up_a}");
    assert_eq!(up_b["both"], true, "{up_b}");

    // A calls B on B's connection: B serves it under its grant for A.
    let h = a.open(j.a_conn, "mousse.rpc", "interactive");
    a.send(h, b"hello B", true);
    let incoming = incoming_on_b(&b, j.b_conn, 0);
    assert_eq!(incoming["grant"], grant, "{incoming}");
    assert_eq!(incoming["label"], "mousse.rpc");
    let bh = incoming["handle"].as_u64().unwrap() as u32;
    b.accept(bh);
    b.credit(bh, 1 << 20);
    assert_eq!(b.until_fin(bh, WAIT), b"hello B");
    // Still one connection each way: B's.
    assert!(a.events("conn.up").iter().all(|m| m["dir"] == "in"));
}

#[test]
fn removing_the_grant_cuts_the_hosts_calls_and_keeps_the_connection() {
    let (_ae, _be) = (Endpoint::init("bxa"), Endpoint::init("bxb"));
    let mut a = _ae.app("hostA", &[]);
    a.hello();
    let mut b = _be.app("peerB", &[]);
    b.hello();
    let (j, grant) = paired(&mut a, &mut b);
    // An open call from A, then B removes its grant for A.
    let h = a.open(j.a_conn, "mousse.rpc", "interactive");
    a.send(h, b"open call", false);
    let incoming = incoming_on_b(&b, j.b_conn, 0);
    let bh = incoming["handle"].as_u64().unwrap();
    b.call("grant.remove", json!({"grant": grant}));
    let reset = b.event("stream.reset", |m| m["handle"] == bh);
    assert_eq!(reset["code"], "grant_revoked", "{reset}");
    let at_a = a.event("stream.reset", |m| m["handle"] == h);
    assert_eq!(at_a["code"], "grant_revoked", "{at_a}");
    // A new call from A is refused; B's own calls to A still work.
    let h2 = a.open(j.a_conn, "mousse.rpc", "interactive");
    let refused = a.event("stream.reset", |m| m["handle"] == h2);
    assert_eq!(refused["code"], "refused_stream", "{refused}");
    assert_eq!(b.events("stream.incoming").len(), 1);
    let mine = b.open(j.b_conn, "mousse.rpc", "interactive");
    b.send(mine, b"still mine", true);
    let at = a.wait("B's call after the removal", WAIT, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == "stream.incoming" && m["conn"] == j.a_conn)
            .nth(1)
            .cloned()
    });
    let ah = at["handle"].as_u64().unwrap() as u32;
    a.accept(ah);
    a.credit(ah, 1 << 20);
    assert_eq!(a.until_fin(ah, WAIT), b"still mine");
    assert!(
        b.events("conn.down").is_empty(),
        "{:?}",
        b.events("conn.down")
    );
}

#[test]
fn with_a_minor_2_peer_calls_stay_one_way() {
    let (_ae, _be) = (Endpoint::init("bya"), Endpoint::init("byb"));
    let mut a = _ae.app("hostA", &[]);
    a.hello();
    // B speaks minor 2, as a peer from before this change.
    let mut b = _be.app_raw(
        "peerB",
        &[],
        0,
        &[("MOUSSE_NET_TEST_HELLO_MINOR", Path::new("2"))],
    );
    b.hello();
    let (j, _) = paired(&mut a, &mut b);
    let up_a = a.event("conn.up", |m| m["conn"] == j.a_conn);
    assert_eq!(up_a["both"], false, "{up_a}");
    let refused = a.request(
        "stream.open",
        json!({"conn": j.a_conn, "label": "mousse.rpc", "class": "interactive"}),
    );
    assert_eq!(refused["error"], "one_way", "{refused}");
    assert!(b
        .events("stream.incoming")
        .iter()
        .all(|m| m["conn"] != j.b_conn));
}
