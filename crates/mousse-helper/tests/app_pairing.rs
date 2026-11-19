//! E3: pairing both ways through the app channel, idempotent `grant.add`
//! and `peer.add`, and removal journaled and fail-closed (Phase 1a §5).
//! The check cell `phase1a.helper-removal` runs this file: a crash between
//! a grant's removal and its save must never let the removed peer back in.

mod common;

use std::path::Path;
use std::time::Duration;

use common::*;
use serde_json::{json, Value};

/// Retry a failed save quickly.
const FAST_RETRY: [(&str, &str); 1] = [("REMOVAL_RETRY_MS", "50")];

/// The grant `identity` holds on `app`.
fn grant_of(app: &mut App, identity: &str) -> Option<Value> {
    let list = app.call("grants.list", json!({}));
    list["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["identity"] == identity)
        .cloned()
}

/// Make the grant table unsavable: a folder (with a file in it) where the
/// table is renamed to. Returns the table as it was.
fn block_grant_saves(dir: &Path) -> Vec<u8> {
    let table = dir.join("grants.json");
    let saved = std::fs::read(&table).unwrap();
    std::fs::remove_file(&table).unwrap();
    std::fs::create_dir_all(table.join("in-the-way")).unwrap();
    saved
}

fn unblock_grant_saves(dir: &Path) {
    std::fs::remove_dir_all(dir.join("grants.json")).unwrap();
}

/// `dial` from `from` to `to`: the reply.
fn dial(from: &mut App, to: &App) -> Value {
    from.request("dial", json!({"identity": to.identity}))
}

#[test]
fn two_apps_pair_both_ways_with_their_names_and_roles() {
    let a_end = Endpoint::init("bothwaysa");
    let b_end = Endpoint::init("bothwaysb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    a.call("config.set", json!({"name": "Desk"}));
    b.call("config.set", json!({"name": "Laptop (Work)"}));
    assert_eq!(
        a.request("config.set", json!({"name": ""}))["error"],
        "bad_name"
    );

    // A shows a ticket; B joins it; A is asked about B by its name.
    let joined = pair_apps(&mut a, &mut b);
    assert_eq!(joined.approval["name"], "Laptop (Work)");
    assert_eq!(joined.approval["identity"], b.identity.as_str());
    assert_eq!(joined.enrolled["identity"], b.identity.as_str());
    assert_eq!(joined.join["identity"], a.identity.as_str());
    assert_eq!(joined.join["name"], "Desk");
    assert_eq!(joined.join["role"], "owner");
    assert_eq!(joined.join["already"], false);
    let b_up = b.event("conn.up", |m| m["conn"] == joined.b_conn);
    assert_eq!(
        (b_up["dir"].clone(), b_up["role"].clone()),
        (json!("out"), json!("owner"))
    );
    let a_up = a.event("conn.up", |m| m["conn"] == joined.a_conn);
    assert_eq!(a_up["grant"], joined.enrolled["grant"]);
    assert_eq!(a_up["role"], "owner");

    // The other direction: B grants A, A adds B as a peer and dials it.
    let receipt = joined.invite["invitation"].clone();
    let added = b.call(
        "grant.add",
        json!({"identity": a.identity, "name": "Desk", "receipt": receipt}),
    );
    assert_eq!(added["already"], false);
    let b_hello = b.call("hello", json!({"proto": [1, 0]}));
    a.call(
        "peer.add",
        json!({"identity": b.identity, "name": "Laptop (Work)", "routes": b_hello["routes"]}),
    );
    let reply = a.call("dial", json!({"identity": b.identity}));
    let out = a.event("conn.up", |m| m["conn"] == reply["conn"]);
    assert_eq!(
        (out["dir"].clone(), out["role"].clone()),
        (json!("out"), json!("owner"))
    );
    let inbound = b.event("conn.up", |m| {
        m["dir"] == "in" && m["identity"] == a.identity.as_str()
    });
    assert_eq!(inbound["grant"], added["grant"]);

    let grant = grant_of(&mut b, &a.identity).unwrap();
    assert_eq!(grant["receipt"], receipt);
    assert_eq!(grant["role"], "owner");
    let peers = a.call("peers.list", json!({}));
    assert_eq!(peers["peers"][0]["identity"], b.identity.as_str());
    assert_eq!(peers["peers"][0]["role"], "owner");
    let peers = b.call("peers.list", json!({}));
    assert_eq!(peers["peers"][0]["name"], "Desk");
    a.assert_clean();
    b.assert_clean();
}

#[test]
fn grant_add_and_peer_add_repeat_without_changing_anything() {
    let mut p = pair_up("again", &[], &[]);
    let b_identity = p.b.identity.clone();
    let first = p.a.call(
        "grant.add",
        json!({"identity": b_identity, "name": "again", "receipt": null}),
    );
    // B already holds a grant from its pairing: that one is kept.
    assert_eq!(first["already"], true);
    let before = grant_of(&mut p.a, &b_identity).unwrap();
    assert_eq!(first["grant"], before["grant"]);
    let second = p.a.call(
        "grant.add",
        json!({"identity": b_identity, "name": "again"}),
    );
    assert_eq!(second["grant"], before["grant"]);
    assert_eq!(second["already"], true);
    // Its connection stayed up and nothing was closed.
    assert!(p.a.events("grant.closed").is_empty());
    let h = p.b.open(p.b_conn, "mousse.rpc", "interactive");
    assert!(h > 0);
    p.a.incoming(p.a_conn, 0);
    assert_eq!(
        p.a.call("grants.list", json!({}))["grants"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let routes = json!(["tcp://127.0.0.1:9"]);
    let add = json!({"identity": b_identity, "name": "B", "routes": routes});
    assert_eq!(p.a.call("peer.add", add.clone())["already"], false);
    assert_eq!(p.a.call("peer.add", add)["already"], true);
    assert_eq!(
        p.a.call("peers.list", json!({}))["peers"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        p.a.request(
            "peer.add",
            json!({"identity": b_identity, "name": "B", "routes": ["nowhere"]})
        )["error"],
        "bad_route"
    );

    // Forgetting a peer ends its dials and the connections this side made.
    let a_identity = p.a.identity.clone();
    assert_eq!(
        p.b.call("peer.forget", json!({"identity": a_identity}))["forgotten"],
        true
    );
    p.b.event("conn.down", |m| m["conn"] == p.b_conn);
    assert_eq!(dial(&mut p.b, &p.a)["error"], "no_peer");
}

#[test]
fn a_declined_or_cancelled_invitation_pairs_nothing() {
    let a_end = Endpoint::init("declinea");
    let b_end = Endpoint::init("declineb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut b = b_end.app("peerB", &[]);
    b.hello();

    let invite = a.call("invite.create", json!({}));
    assert!(invite["expires_at"].as_u64().unwrap() > 0);
    assert_eq!(invite["routes"], hello_routes(&mut a));
    let invitation = invite["invitation"].as_str().unwrap().to_owned();
    let join = b.start("join", json!({"ticket": invite["uri"], "pinned": true}));
    let approval = a.event("approval", |m| m["invitation"] == invitation.as_str());
    a.call(
        "approval.answer",
        json!({"request": approval["request"], "yes": false}),
    );
    assert_eq!(b.reply(join)["error"], "pairing_declined");
    let ended = a.event("invite.ended", |m| m["invitation"] == invitation.as_str());
    assert_eq!(ended["reason"], "pairing_declined");
    // An answer to a request that is gone changes nothing.
    assert_eq!(
        a.request(
            "approval.answer",
            json!({"request": approval["request"], "yes": true})
        )["error"],
        "no_request"
    );

    let invite = a.call("invite.create", json!({}));
    let invitation = invite["invitation"].as_str().unwrap().to_owned();
    a.call("invite.cancel", json!({"invitation": invitation}));
    let ended = a.event("invite.ended", |m| m["invitation"] == invitation.as_str());
    assert_eq!(ended["reason"], "cancelled");
    let reply = b.request("join", json!({"ticket": invite["uri"], "pinned": true}));
    assert_eq!(reply["error"], "invitation_invalid", "{reply}");

    assert!(grant_of(&mut a, &b.identity).is_none());
    assert!(b.call("peers.list", json!({}))["peers"]
        .as_array()
        .unwrap()
        .is_empty());
}

fn hello_routes(app: &mut App) -> Value {
    app.call("hello", json!({"proto": [1, 0]}))["routes"].clone()
}

/// `app` restarted on a new port: tell `peer` where it is now.
fn learn_routes(peer: &mut App, app: &mut App) {
    let routes = hello_routes(app);
    let name = app.name.clone();
    let identity = app.identity.clone();
    peer.call(
        "peer.add",
        json!({"identity": identity, "name": name, "routes": routes}),
    );
}

/// The joiner's recovery repeats `join` with its stored ticket (§5.1): the
/// host answers from the grant the invitation made, with no new question.
#[test]
fn a_repeated_pinned_join_learns_it_paired_without_asking_again() {
    let a_end = Endpoint::init("rejoina");
    let b_end = Endpoint::init("rejoinb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    let joined = pair_apps(&mut a, &mut b);
    let again = b.call(
        "join",
        json!({"ticket": joined.invite["uri"], "pinned": true}),
    );
    assert_eq!(again["identity"], a.identity.as_str());
    assert_eq!(again["role"], "owner");
    assert_eq!(again["already"], false);
    assert_ne!(again["conn"], joined.join["conn"]);
    assert_eq!(a.events("approval").len(), 1);
    assert_eq!(a.events("enrolled").len(), 1);
    // A join of an unknown ticket kind or text is refused before dialling.
    assert_eq!(
        b.request("join", json!({"ticket": "nonsense", "pinned": true}))["error"],
        "bad_ticket"
    );
}

/// The removal is decided, its save fails, and the helper is killed before
/// a retry works: the table on disk still holds the grant. The journal
/// makes the next start remove it again before anything is accepted.
#[test]
fn a_removed_peer_stays_out_after_a_crash_before_the_save() {
    let mut p = pair_up("crash", &[], &[]);
    let b_identity = p.b.identity.clone();
    let grant = grant_of(&mut p.a, &b_identity).unwrap()["grant"].clone();
    let table = block_grant_saves(&p.a_end.dir);

    let removed = p.a.call("grant.remove", json!({"grant": grant}));
    assert_eq!(removed["removed"], true);
    assert_eq!(removed["paused"], true);
    p.a.event("net.paused", |_| true);
    let down = p.b.event("conn.down", |m| m["conn"] == p.b_conn);
    assert_eq!(down["reason"], "grant_revoked");
    // Paused: A refuses to dial too.
    assert_eq!(dial(&mut p.a, &p.b)["error"], "paused");

    // Crash, with the old table back on disk.
    p.a.kill();
    unblock_grant_saves(&p.a_end.dir);
    std::fs::write(p.a_end.dir.join("grants.json"), table).unwrap();

    p.a = p.a_end.app("hostA", &[]);
    let hello = p.a.hello();
    assert_eq!(hello["paused"], Value::Null);
    assert!(grant_of(&mut p.a, &b_identity).is_none());
    learn_routes(&mut p.b, &mut p.a);
    let refused = dial(&mut p.b, &p.a);
    assert_eq!(refused["why"], "not_authorized", "{refused}");
    assert!(!p.a_end.dir.join("revoke.journal").exists());
}

#[test]
fn a_removal_that_cannot_be_saved_pauses_networking_until_it_is() {
    let mut p = pair_up("pause", &FAST_RETRY, &[]);
    let (_c_end, mut c, a_to_c, _c_conn) = another_peer(&mut p.a, "pausec", &[]);
    let b_identity = p.b.identity.clone();
    let grant = grant_of(&mut p.a, &b_identity).unwrap()["grant"].clone();
    let _table = block_grant_saves(&p.a_end.dir);

    let removed = p.a.call("grant.remove", json!({"grant": grant}));
    assert_eq!(removed["paused"], true);
    let paused = p.a.event("net.paused", |_| true);
    assert!(paused["reason"].as_str().unwrap().contains("saving"));
    p.a.event("store.failed", |_| true);
    // Every connection closed, C's too, and nobody gets in.
    let down = p.a.event("conn.down", |m| m["conn"] == a_to_c);
    assert_eq!(down["reason"], "internal_error");
    assert!(dial(&mut c, &p.a).get("error").is_some());
    let c_invite = c.call("invite.create", json!({}));
    assert_eq!(
        p.a.request("join", json!({"ticket": c_invite["uri"], "pinned": true}))["error"],
        "paused"
    );

    // The save works again: networking resumes, C is back, B stays out.
    unblock_grant_saves(&p.a_end.dir);
    p.a.event("net.resumed", |_| true);
    assert!(!p.a_end.dir.join("revoke.journal").exists());
    let back = dial(&mut c, &p.a);
    assert!(back.get("error").is_none(), "{back}");
    let refused = dial(&mut p.b, &p.a);
    assert_eq!(refused["why"], "not_authorized", "{refused}");

    // Saved: a restart keeps B out.
    p.a.kill();
    p.a = p.a_end.app("hostA", &[]);
    p.a.hello();
    assert!(grant_of(&mut p.a, &b_identity).is_none());
}

/// A path still opening when networking pauses never comes up: the dial
/// that opened it ends `paused`, and nothing is published after the pause
/// closed what was up.
#[test]
fn a_path_still_opening_when_networking_pauses_never_comes_up() {
    let mut p = pair_up("pauseop", &[], &[]);
    let h_end = Endpoint::init("pauseoph");
    let mut h = h_end.app("hostH", &[]);
    h.hello();
    let gate = gate_to(&route_of(&mut h));
    // A pairs with H as its caller, through the relay that holds the dial.
    trust(&mut h, &mut p.a, &[&gate.route]);
    gate.wait_accepted();

    let b_identity = p.b.identity.clone();
    let grant = grant_of(&mut p.a, &b_identity).unwrap()["grant"].clone();
    let _table = block_grant_saves(&p.a_end.dir);
    let removed = p.a.call("grant.remove", json!({"grant": grant}));
    assert_eq!(removed["paused"], true);
    p.a.event("net.paused", |_| true);

    // The dial passes step 1 after the pause.
    gate.open();
    h.event("conn.up", |m| m["identity"] == p.a.identity.as_str());
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        outbound_ups(&p.a, &h.identity),
        0,
        "{:?}",
        p.a.events("conn.up")
    );
    assert!(
        p.a_end.log().contains("networking is paused"),
        "{}",
        p.a_end.log()
    );
}

#[test]
fn a_removal_that_cannot_be_journaled_changes_nothing() {
    let mut p = pair_up("nojournal", &[], &[]);
    let b_identity = p.b.identity.clone();
    let grant = grant_of(&mut p.a, &b_identity).unwrap()["grant"].clone();
    std::fs::create_dir_all(p.a_end.dir.join("revoke.journal").join("in-the-way")).unwrap();

    let reply = p.a.request("grant.remove", json!({"grant": grant}));
    assert_eq!(reply["error"], "journal_failed", "{reply}");
    assert_eq!(reply["reason"], "Couldn't remove; try again");
    // B keeps its grant and its connection.
    assert!(grant_of(&mut p.a, &b_identity).is_some());
    let h = p.b.open(p.b_conn, "mousse.rpc", "interactive");
    assert!(h > 0);
    p.a.incoming(p.a_conn, 0);
    assert!(p.b.events("conn.down").is_empty());
    assert!(p.a.events("net.paused").is_empty());

    // Once it can be journaled, the removal goes through.
    std::fs::remove_dir_all(p.a_end.dir.join("revoke.journal")).unwrap();
    let removed = p.a.call("grant.remove", json!({"grant": grant}));
    assert_eq!(removed["removed"], true);
    assert_eq!(removed.get("paused"), None);
    p.b.event("conn.down", |m| m["conn"] == p.b_conn);
    // Removing it again finds it gone.
    assert_eq!(
        p.a.call("grant.remove", json!({"grant": grant}))["removed"],
        false
    );
}

/// The app channel replaces the Phase 0 control listener: an app-mode
/// helper writes no control file, so `invite` on the command line finds
/// no host.
#[test]
fn an_app_mode_helper_has_no_control_listener() {
    let end = Endpoint::init("noctl");
    let mut a = end.app("hostA", &[]);
    a.hello();
    assert!(!end.dir.join("control.json").exists());
    let mut invite = end.cli(&["invite", "--no-qr"], false);
    assert_ne!(invite.exit_within(WAIT), Some(0));
    assert!(
        invite.err().contains("no host is running"),
        "{}",
        invite.err()
    );
    // The app's own invitations work.
    a.call("invite.create", json!({}));
}
