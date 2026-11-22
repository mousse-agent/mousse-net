//! `grant.revoke_local` (`docs/pairing-flow-design.md` §6.1): ending this
//! computer's grant for a peer stops the peer's calls into this computer
//! and leaves this computer's own way to the peer as it was.
//!
//! A and B are paired both ways: A joined B with a "Send link" (A holds a
//! peer record for B, a `ticket` approval and the link's completion
//! record), and B joined A in person (A holds a grant for B). A revokes its
//! grant for B. `grant.remove` is run on the same pairing to pin what it
//! takes that `grant.revoke_local` keeps.
//!
//! Relay cleanup is checked on its own pairing: B joins A through A's relay
//! only, its caller key held back, so A keeps a recovery entry for it.
//!
//! The check `pairing-revoke.revoke-local` runs this file.

mod common;
#[path = "common/relay.rs"]
mod relay_fixture;

use std::path::Path;

use common::*;
use mousse_net_core::pairing::Ticket;
use mousse_net_core::relay_endpoint::RelayRoute;
use mousse_net_io::store::hex;
use relay_fixture::TestRelay as Relay;
use serde_json::{json, Value};

/// Retry a failed save quickly.
const FAST_RETRY: [(&str, &str); 1] = [("REMOVAL_RETRY_MS", "50")];

/// Fast relay re-registration and redials.
const RELAY_FAST: [(&str, &str); 3] = [
    ("VIA_RELAY_RETRY_FIRST_MS", "100"),
    ("KEEP_RETRY_FIRST_MS", "100"),
    ("KEEP_RETRY_MAX_MS", "500"),
];

/// A and B, paired both ways. The apps drop before their folders go.
struct Both {
    a: App,
    b: App,
    a_end: Endpoint,
    b_end: Endpoint,
    /// The ports A and B listen on, so a restart keeps the routes stored.
    a_port: u16,
    b_port: u16,
    /// A's grant for B.
    grant: u64,
    /// The link A joined B with.
    link: Ticket,
    /// A's connection to B from that join (outbound on A).
    a_to_b: u64,
    /// B's connection to A from its in-person join (outbound on B).
    b_to_a: u64,
}

fn hello(app: &mut App) -> Value {
    let name = app.name.clone();
    let reply = app.call("hello", json!({"proto": [1, 2], "name": name}));
    app.identity = reply["identity"].as_str().unwrap().to_owned();
    reply
}

fn start(end: &Endpoint, name: &str, env: &[(&str, &str)], port: u16) -> App {
    start_raw(end, name, env, port, &[])
}

/// [`start`], with the debug-build test hooks in `raw`.
fn start_raw(
    end: &Endpoint,
    name: &str,
    env: &[(&str, &str)],
    port: u16,
    raw: &[(&str, &Path)],
) -> App {
    let mut app = end.app_raw(name, env, port, raw);
    hello(&mut app);
    app
}

/// A debug-build test hook on A.
#[derive(Clone, Copy)]
enum Hook<'a> {
    None,
    /// Hold at this point while [`hold_file`] exists.
    Hold(&'a str),
    /// Stop at this point, as a crash would.
    Crash(&'a str),
}

/// The variable and value that set `hook` on the helper of `end`.
fn hook_var(end: &Endpoint, hook: Hook<'_>) -> Option<(&'static str, String)> {
    match hook {
        Hook::None => None,
        Hook::Hold(point) => Some((
            "MOUSSE_HELPER_TEST_HOLD",
            format!("{point}={}", hold_file(end).display()),
        )),
        Hook::Crash(point) => Some(("MOUSSE_HELPER_TEST_CRASH", point.to_owned())),
    }
}

/// Pair A and B both ways, with `env` on A.
fn both_ways(tag: &str, env: &[(&str, &str)]) -> Both {
    both_ways_hooked(tag, env, Hook::None)
}

/// [`both_ways`], with `hook` on A.
fn both_ways_hooked(tag: &str, env: &[(&str, &str)], hook: Hook<'_>) -> Both {
    let a_end = Endpoint::init(&format!("{tag}a"));
    let b_end = Endpoint::init(&format!("{tag}b"));
    let var = hook_var(&a_end, hook);
    let raw: Vec<(&str, &Path)> = var.iter().map(|(k, v)| (*k, Path::new(v))).collect();
    let mut a = start_raw(&a_end, "hostA", env, 0, &raw);
    let mut b = start(&b_end, "peerB", &[], 0);
    let a_port = a.call("hello", json!({"proto": [1, 2]}))["port"]
        .as_u64()
        .unwrap() as u16;
    let b_port = b.call("hello", json!({"proto": [1, 2]}))["port"]
        .as_u64()
        .unwrap() as u16;

    // A uses B: A joins B's link with B's route approved.
    let invite = b.call("invite.create", json!({"kind": "link"}));
    let uri = invite["uri"].as_str().unwrap().to_owned();
    let link = Ticket::from_fragment(&uri).unwrap();
    let inv = invite["invitation"].as_str().unwrap().to_owned();
    let id = a.start(
        "join",
        json!({"ticket": uri, "arrival": "link", "approved": [invite["routes"][0]]}),
    );
    a.event("join.code_needed", |m| m["invitation"] == inv.as_str());
    a.call(
        "join.code",
        json!({"invitation": inv, "code": invite["code"]}),
    );
    let joined = a.reply(id);
    assert!(joined.get("error").is_none(), "{joined}");
    let a_to_b = joined["conn"].as_u64().unwrap();

    // B uses A: B joins A in person.
    let pairing = pair_apps(&mut a, &mut b);
    let grant = pairing.enrolled["grant"].as_u64().unwrap();

    let mut both = Both {
        a,
        b,
        a_end,
        b_end,
        a_port,
        b_port,
        grant,
        link,
        a_to_b,
        b_to_a: pairing.b_conn,
    };
    // Each side's relay material arrives on its first connection: A as
    // B's caller holds B's pair secret, A as B's host B's caller key.
    let b_identity = both.b.identity.clone();
    until("A's relay material for both directions", || {
        peer_of(&mut both.a, &b_identity)["relay"]["keys"] == true
            && caller_key_listed(&both.a_end.dir, grant)
    });
    both
}

/// The file that holds A at its test hook while it exists.
fn hold_file(a_end: &Endpoint) -> std::path::PathBuf {
    a_end.dir.join("hold")
}

/// Wait until `ok` holds.
fn until(what: &str, mut ok: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !ok() {
        assert!(start.elapsed() < WAIT, "waited {WAIT:?} for {what}");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Whether the relay file of A's grants keeps a caller key for `grant`.
fn caller_key_listed(dir: &Path, grant: u64) -> bool {
    let Ok(bytes) = std::fs::read(dir.join("relay-grants.json")) else {
        return false;
    };
    let file: Value = serde_json::from_slice(&bytes).unwrap();
    file["keys"]
        .as_array()
        .is_some_and(|keys| keys.iter().any(|k| k["grant"] == grant))
}

/// Whether the relay file of A's grants keeps a recovery entry for `grant`.
fn recovery_listed(dir: &Path, grant: u64) -> bool {
    let Ok(bytes) = std::fs::read(dir.join("relay-grants.json")) else {
        return false;
    };
    let file: Value = serde_json::from_slice(&bytes).unwrap();
    file["recovery"]
        .as_array()
        .is_some_and(|entries| entries.iter().any(|r| r["grant"] == grant))
}

/// Host A on a relay, and B joined it through the relay only with its
/// caller key held back (`MOUSSE_HELPER_TEST_NO_KEYS`): A keeps a
/// recovery entry for B's grant. The apps drop before their folders and
/// the relay.
struct RelayOnly {
    a: App,
    _b: App,
    a_end: Endpoint,
    _b_end: Endpoint,
    _relay: Relay,
    grant: u64,
}

/// `uri`'s ticket with only its relay route.
fn relay_only(uri: &str) -> String {
    let fragment = uri.rsplit('#').next().unwrap();
    let mut ticket = Ticket::from_fragment(fragment).unwrap();
    ticket
        .routes
        .retain(|r| RelayRoute::parse_hint(r).is_some());
    assert_eq!(ticket.routes.len(), 1, "{:?}", ticket.routes);
    ticket.to_fragment()
}

/// [`RelayOnly`], with `hook` on A.
fn relay_only_without_keys(tag: &str, hook: Hook<'_>) -> RelayOnly {
    let relay = Relay::start();
    let a_end = Endpoint::init(&format!("{tag}a"));
    let b_end = Endpoint::init(&format!("{tag}b"));
    let var = hook_var(&a_end, hook);
    let raw: Vec<(&str, &Path)> = var.iter().map(|(k, v)| (*k, Path::new(v))).collect();
    let mut a = start_raw(&a_end, "hostA", &RELAY_FAST, 0, &raw);
    let reply = a.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(reply["relay"]["state"], "registered", "{reply}");
    let no_keys = [("MOUSSE_HELPER_TEST_NO_KEYS", Path::new("1"))];
    let mut b = start_raw(&b_end, "peerB", &RELAY_FAST, 0, &no_keys);
    let invite = a.call("invite.create", json!({}));
    let invitation = invite["invitation"].as_str().unwrap().to_owned();
    let ticket = relay_only(invite["uri"].as_str().unwrap());
    let id = b.start(
        "join",
        json!({"ticket": ticket, "pinned": true, "approved": [relay.destination()]}),
    );
    let approval = a.event("approval", |m| m["invitation"] == invitation.as_str());
    a.call(
        "approval.answer",
        json!({"request": approval["request"], "yes": true}),
    );
    let join = b.reply(id);
    assert!(join.get("error").is_none(), "{join}");
    let enrolled = a.event("enrolled", |m| m["invitation"] == invitation.as_str());
    let grant = enrolled["grant"].as_u64().unwrap();
    until("A's recovery entry for B", || {
        recovery_listed(&a_end.dir, grant)
    });
    assert!(!caller_key_listed(&a_end.dir, grant));
    RelayOnly {
        a,
        _b: b,
        a_end,
        _b_end: b_end,
        _relay: relay,
        grant,
    }
}

fn grant_of(app: &mut App, identity: &str) -> Option<Value> {
    let list = app.call("grants.list", json!({}));
    list["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["identity"] == identity)
        .cloned()
}

fn approvals_for(app: &mut App, identity: &str) -> Value {
    app.call("approvals.list", json!({"identity": identity}))["approvals"].clone()
}

fn link_status(app: &mut App, link: &Ticket) -> Value {
    app.call("join.status", json!({"ticket_hash": hex(&link.hash())}))
}

/// What A keeps for calling B: its row (less the route keep connected
/// notes and B's relay manifest, which B renews; the relay secret is
/// checked on its own), its approvals and whether the link's completion
/// record still answers.
fn outbound_state(both: &mut Both) -> (Value, Value, Value) {
    let identity = both.b.identity.clone();
    let mut row = peer_of(&mut both.a, &identity);
    if row.is_object() {
        row["last_route"] = Value::Null;
        row["relay"] = Value::Null;
    }
    let approvals = approvals_for(&mut both.a, &identity);
    let link = both.link.clone();
    let done = link_status(&mut both.a, &link)["done"].clone();
    (row, approvals, done)
}

/// A dials B and B serves a call from A on that connection.
fn a_calls_b(both: &mut Both, payload: &[u8]) {
    let identity = both.b.identity.clone();
    let reply = both.a.request("dial", json!({"identity": identity}));
    assert!(
        reply.get("error").is_none(),
        "A cannot reach B any more: {reply}"
    );
    let conn = reply["conn"].as_u64().unwrap();
    a_calls_b_on(both, conn, payload);
}

/// A opens a call to B on its connection `conn` and B reads it to its end.
fn a_calls_b_on(both: &mut Both, conn: u64, payload: &[u8]) -> u64 {
    let seen = both.b.events("stream.incoming").len();
    let h = both.a.open(conn, "mousse.rpc", "interactive");
    both.a.send(h, payload, true);
    let a_identity = both.a.identity.clone();
    let incoming = both.b.wait("A's call on B", WAIT, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == "stream.incoming")
            .nth(seen)
            .cloned()
    });
    let b_conn = incoming["conn"].as_u64().unwrap();
    let up = both.b.event("conn.up", |m| m["conn"] == b_conn);
    assert_eq!(up["identity"], a_identity.as_str(), "{up}");
    let bh = incoming["handle"].as_u64().unwrap() as u32;
    both.b.accept(bh);
    both.b.credit(bh, 1 << 20);
    assert_eq!(both.b.until_fin(bh, WAIT), payload);
    b_conn
}

/// B dials A: the reply.
fn b_dials_a(both: &mut Both) -> Value {
    let identity = both.a.identity.clone();
    both.b.request("dial", json!({"identity": identity}))
}

/// Make A's grant table unsavable; returns the table as it was.
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

/// Restart both helpers on their ports.
fn restart_both(both: &mut Both) {
    both.a.kill();
    both.b.kill();
    both.a = start(&both.a_end, "hostA", &[], both.a_port);
    both.b = start(&both.b_end, "peerB", &[], both.b_port);
}

#[test]
fn revoking_locally_ends_the_peers_use_of_this_computer_and_keeps_its_own() {
    let mut both = both_ways("rl-one", &[]);
    let features = both.a.call("hello", json!({"proto": [1, 2]}))["features"].clone();
    assert!(
        features
            .as_array()
            .unwrap()
            .contains(&json!("grant-revoke-local")),
        "{features}"
    );
    let b_identity = both.b.identity.clone();
    let kept = outbound_state(&mut both);
    assert!(kept.0.is_object() && kept.2.is_object(), "{kept:?}");
    assert_eq!(kept.1.as_array().unwrap().len(), 1, "{kept:?}");

    let reply = both
        .a
        .call("grant.revoke_local", json!({"grant": both.grant}));
    assert_eq!(reply["removed"], true, "{reply}");
    assert_eq!(reply.get("paused"), None, "{reply}");

    // B's use of A ends: the grant, its connection and its relay caller key.
    assert!(
        grant_of(&mut both.a, &b_identity).is_none(),
        "the grant survived a local revocation"
    );
    let closed = both.a.event("grant.closed", |m| m["grant"] == both.grant);
    assert!(closed["connections"].as_u64().unwrap() >= 1, "{closed}");
    let b_to_a = both.b_to_a;
    let down = both.b.event("conn.down", |m| m["conn"] == b_to_a);
    assert_eq!(down["reason"], "grant_revoked", "{down}");
    assert_eq!(b_dials_a(&mut both)["why"], "not_authorized");
    let grant = both.grant;
    let dir = both.a_end.dir.clone();
    until("the revoked grant's caller key to go", || {
        !caller_key_listed(&dir, grant)
    });

    // A's use of B stays: its row, approvals, completion record and relay
    // secrets, and A still calls B.
    assert_eq!(
        outbound_state(&mut both),
        kept,
        "a local revocation changed this computer's way to the peer"
    );
    assert_eq!(peer_of(&mut both.a, &b_identity)["relay"]["keys"], true);
    a_calls_b(&mut both, b"after the revocation");
    assert!(both.a.events("net.paused").is_empty());

    // Again: the grant is gone already.
    let again = both
        .a
        .call("grant.revoke_local", json!({"grant": both.grant}));
    assert_eq!(again["removed"], false, "{again}");

    // The same after both restart.
    restart_both(&mut both);
    assert!(grant_of(&mut both.a, &b_identity).is_none());
    assert_eq!(b_dials_a(&mut both)["why"], "not_authorized");
    assert_eq!(outbound_state(&mut both), kept);
    a_calls_b(&mut both, b"after a restart");
    both.a.assert_clean();
    both.b.assert_clean();
}

/// What `grant.remove` takes on the same pairing, and `grant.revoke_local`
/// keeps: this computer's approvals and completion record for the peer.
#[test]
fn grant_remove_also_drops_this_computers_approvals_and_completion_record() {
    let mut both = both_ways("rl-cmp", &[]);
    let b_identity = both.b.identity.clone();
    let (row, _, _) = outbound_state(&mut both);
    let reply = both.a.call("grant.remove", json!({"grant": both.grant}));
    assert_eq!(reply["removed"], true, "{reply}");
    assert!(grant_of(&mut both.a, &b_identity).is_none());
    let (row_after, approvals, done) = outbound_state(&mut both);
    assert_eq!(approvals, json!([]), "grant.remove kept the approvals");
    assert_eq!(done, Value::Null, "grant.remove kept the completion record");
    // The row itself stays with both: neither forgets the peer.
    assert_eq!(row_after, row);
}

/// On A's own connection to B (minor 3) B's calls into A are served under
/// A's grant: the revocation resets the open one and refuses new ones,
/// while A's calls to B go on over the same connection.
#[test]
fn on_a_shared_connection_the_peers_calls_stop_and_this_computers_go_on() {
    let mut both = both_ways("rl-shared", &[]);
    let a_to_b = both.a_to_b;
    let up = both.a.event("conn.up", |m| m["conn"] == a_to_b);
    assert_eq!(up["both"], true, "{up}");
    // A calls first on its connection; then B calls A on it.
    let b_from_a = a_calls_b_on(&mut both, a_to_b, b"first");
    let open = both.b.open(b_from_a, "mousse.rpc", "interactive");
    both.b.send(open, b"open call", false);
    let incoming = both.a.event("stream.incoming", |m| m["conn"] == a_to_b);
    assert_eq!(incoming["grant"], both.grant, "{incoming}");
    let served = incoming["handle"].as_u64().unwrap();

    both.a
        .call("grant.revoke_local", json!({"grant": both.grant}));
    let reset = both.a.event("stream.reset", |m| m["handle"] == served);
    assert_eq!(reset["code"], "grant_revoked", "{reset}");
    let at_b = both.b.event("stream.reset", |m| m["handle"] == open);
    assert_eq!(at_b["code"], "grant_revoked", "{at_b}");
    let refused = both.b.open(b_from_a, "mousse.rpc", "interactive");
    let refused = both.b.event("stream.reset", |m| m["handle"] == refused);
    assert_eq!(refused["code"], "refused_stream", "{refused}");

    // A's calls to B on that connection go on, and it stays up.
    a_calls_b_on(&mut both, a_to_b, b"still mine");
    assert!(
        both.a
            .events("conn.down")
            .iter()
            .all(|m| m["conn"] != a_to_b),
        "{:?}",
        both.a.events("conn.down")
    );
    assert_eq!(
        both.a
            .events("stream.incoming")
            .iter()
            .filter(|m| m["conn"] == a_to_b)
            .count(),
        1
    );
}

/// B has a call open on A's connection, which A's app accepted. A runs
/// `op` on its grant for B while the reset that follows a change to the
/// grant table is held (`served-reset`). B then sends on that call, and
/// answers a call of A's on the same connection after it. None of B's
/// bytes on its call reach A's app after the reply.
fn no_data_from_the_peers_call_after_the_reply(tag: &str, op: &str) {
    let mut both = both_ways_hooked(tag, &[], Hook::Hold("served-reset"));
    let a_to_b = both.a_to_b;
    let b_from_a = a_calls_b_on(&mut both, a_to_b, b"first");
    let open = both.b.open(b_from_a, "mousse.rpc", "interactive");
    both.b.send(open, b"before", false);
    let incoming = both.a.event("stream.incoming", |m| m["conn"] == a_to_b);
    let served = incoming["handle"].as_u64().unwrap() as u32;
    both.a.accept(served);
    both.a.credit(served, 1 << 20);
    until("B's first bytes at A", || both.a.received(served).0 == 6);

    // A's own call on the connection, which B answers last.
    let seen = both.b.events("stream.incoming").len();
    let mine = both.a.open(a_to_b, "mousse.rpc", "interactive");
    both.a.credit(mine, 1 << 20);
    both.a.send(mine, b"ping", false);
    let at_b = both.b.wait("A's call on B", WAIT, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == "stream.incoming")
            .nth(seen)
            .cloned()
    });
    let answer = at_b["handle"].as_u64().unwrap() as u32;
    both.b.accept(answer);

    let reply = both.a.call(op, json!({"grant": both.grant}));
    assert_eq!(reply["removed"], true, "{reply}");
    both.b.send(open, b"after the reply", false);
    both.b.send(answer, b"last", true);
    assert_eq!(both.a.until_fin(mine, WAIT), b"last");
    let _ = std::fs::remove_file(hold_file(&both.a_end));
    assert_eq!(
        both.a.received(served),
        (6, false),
        "B's bytes reached A's app after {op} replied"
    );
}

#[test]
fn after_a_local_revocation_replies_no_data_from_the_peers_call_arrives() {
    no_data_from_the_peers_call_after_the_reply("rl-after", "grant.revoke_local");
}

#[test]
fn after_a_grant_removal_replies_no_data_from_the_peers_call_arrives() {
    no_data_from_the_peers_call_after_the_reply("rl-rm-after", "grant.remove");
}

/// B has a stream open on its own connection to A, which A's app accepted
/// and has not credited, so B's bytes wait at A. A runs `op` on its grant
/// for B, and the end of that connection here is held (`inbound-down`),
/// as a slow close would be. A's app credits the stream after the reply:
/// none of B's bytes reach it.
fn no_data_from_the_peers_inbound_stream_after_the_reply(tag: &str, op: &str) {
    let mut both = both_ways_hooked(tag, &[], Hook::Hold("inbound-down"));
    let b_identity = both.b.identity.clone();
    let a_from_b = both.a.event("conn.up", |m| {
        m["dir"] == "in" && m["identity"] == b_identity.as_str()
    })["conn"]
        .as_u64()
        .unwrap();
    let open = both.b.open(both.b_to_a, "mousse.rpc", "bulk");
    both.b.send(open, &[b'x'; 4096], true);
    let incoming = both.a.event("stream.incoming", |m| m["conn"] == a_from_b);
    let handle = incoming["handle"].as_u64().unwrap() as u32;
    both.a.accept(handle);
    until("B's bytes waiting at A", || {
        both.a.stats()["queued_bytes"].as_u64().unwrap_or(0) > 0
    });
    let reply = both.a.call(op, json!({"grant": both.grant}));
    assert_eq!(reply["removed"], true, "{reply}");
    let hold = hold_file(&both.a_end);
    until("the end of B's connection held at A", || hold.exists());
    both.a.credit(handle, 1 << 20);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let _ = std::fs::remove_file(&hold);
    both.a.event("conn.down", |m| m["conn"] == a_from_b);
    assert_eq!(
        both.a.received(handle),
        (0, false),
        "B's bytes on its own connection reached A's app after {op} replied"
    );
}

#[test]
fn after_a_local_revocation_replies_no_data_from_the_peers_own_connection_arrives() {
    no_data_from_the_peers_inbound_stream_after_the_reply("rl-in-after", "grant.revoke_local");
}

#[test]
fn after_a_grant_removal_replies_no_data_from_the_peers_own_connection_arrives() {
    no_data_from_the_peers_inbound_stream_after_the_reply("rl-rm-in-after", "grant.remove");
}

/// The save fails: networking pauses until a retry saves it. B stays out
/// after the resume, and A's way to B is as it was.
#[test]
fn a_failed_save_pauses_and_after_the_resume_only_the_peers_access_is_gone() {
    let mut both = both_ways("rl-pause", &FAST_RETRY);
    let b_identity = both.b.identity.clone();
    let kept = outbound_state(&mut both);
    let _table = block_grant_saves(&both.a_end.dir);

    let reply = both
        .a
        .call("grant.revoke_local", json!({"grant": both.grant}));
    assert_eq!(reply["removed"], true, "{reply}");
    assert_eq!(reply["paused"], true, "{reply}");
    both.a.event("net.paused", |_| true);
    let b_to_a = both.b_to_a;
    let down = both.b.event("conn.down", |m| m["conn"] == b_to_a);
    assert_eq!(down["reason"], "grant_revoked", "{down}");
    let identity = both.b.identity.clone();
    assert_eq!(
        both.a.request("dial", json!({"identity": identity}))["error"],
        "paused"
    );

    unblock_grant_saves(&both.a_end.dir);
    both.a.event("net.resumed", |_| true);
    assert!(!both.a_end.dir.join("revoke.journal").exists());
    assert!(grant_of(&mut both.a, &b_identity).is_none());
    assert_eq!(b_dials_a(&mut both)["why"], "not_authorized");
    assert_eq!(outbound_state(&mut both), kept);
    a_calls_b(&mut both, b"after the resume");
}

/// The save fails and the helper is killed before a retry works, with the
/// old table on disk: the journal removes the grant again at the next
/// start, and A's way to B is as it was.
#[test]
fn a_crash_before_the_save_keeps_the_peer_out() {
    let mut both = both_ways("rl-crash", &[]);
    let b_identity = both.b.identity.clone();
    let kept = outbound_state(&mut both);
    let table = block_grant_saves(&both.a_end.dir);
    let reply = both
        .a
        .call("grant.revoke_local", json!({"grant": both.grant}));
    assert_eq!(reply["paused"], true, "{reply}");
    both.a.event("net.paused", |_| true);

    both.a.kill();
    unblock_grant_saves(&both.a_end.dir);
    std::fs::write(both.a_end.dir.join("grants.json"), table).unwrap();
    both.a = start(&both.a_end, "hostA", &[], both.a_port);
    assert_eq!(
        both.a.call("hello", json!({"proto": [1, 2]}))["paused"],
        Value::Null
    );
    assert!(
        grant_of(&mut both.a, &b_identity).is_none(),
        "the revoked grant came back after a crash"
    );
    assert_eq!(b_dials_a(&mut both)["why"], "not_authorized");
    assert_eq!(outbound_state(&mut both), kept);
    a_calls_b(&mut both, b"after the crash");
}

/// A stops right after it journaled the revocation, before the relay
/// cleanup ran. After a restart, B's caller key is gone from A's relay
/// file as well.
#[test]
fn a_crash_after_the_journal_leaves_no_caller_key() {
    let mut both = both_ways_hooked("rl-jkey", &[], Hook::Crash("removal-journaled"));
    let grant = both.grant;
    both.a.start("grant.revoke_local", json!({"grant": grant}));
    assert_eq!(both.a.exit_within(WAIT), Some(86), "{}", both.a.err());
    assert!(caller_key_listed(&both.a_end.dir, grant));
    both.a = start(&both.a_end, "hostA", &[], both.a_port);
    until("A to drop the revoked grant's caller key", || {
        !caller_key_listed(&both.a_end.dir, grant)
    });
}

/// The same crash, for a grant whose caller key never came: after a
/// restart its recovery entry is gone.
#[test]
fn a_crash_after_the_journal_leaves_no_recovery_entry() {
    let mut ro = relay_only_without_keys("rl-jrec", Hook::Crash("removal-journaled"));
    let grant = ro.grant;
    ro.a.start("grant.revoke_local", json!({"grant": grant}));
    assert_eq!(ro.a.exit_within(WAIT), Some(86), "{}", ro.a.err());
    assert!(recovery_listed(&ro.a_end.dir, grant));
    ro.a = start(&ro.a_end, "hostA", &RELAY_FAST, 0);
    until("A to drop the revoked grant's recovery entry", || {
        !recovery_listed(&ro.a_end.dir, grant)
    });
}

/// The recovery entry of a revoked grant whose caller key never came goes
/// with the grant.
#[test]
fn a_revoked_grants_recovery_entry_goes_though_its_caller_key_never_came() {
    let mut ro = relay_only_without_keys("rl-rec", Hook::None);
    let grant = ro.grant;
    let reply = ro.a.call("grant.revoke_local", json!({"grant": grant}));
    assert_eq!(reply["removed"], true, "{reply}");
    until("A to drop the revoked grant's recovery entry", || {
        !recovery_listed(&ro.a_end.dir, grant)
    });
}

/// B pairs with A again, and its new grant replaces the old one. Revoking
/// the old grant's id answers `removed: false` and leaves the new grant.
#[test]
fn revoking_a_replaced_grant_leaves_the_new_one() {
    let mut both = both_ways("rl-old", &[]);
    let old = both.grant;
    let again = pair_apps(&mut both.a, &mut both.b);
    let new = again.enrolled["grant"].as_u64().unwrap();
    assert_ne!(new, old);
    let b_identity = both.b.identity.clone();
    let reply = both.a.call("grant.revoke_local", json!({"grant": old}));
    assert_eq!(reply["removed"], false, "{reply}");
    let grant = grant_of(&mut both.a, &b_identity).map(|g| g["grant"].clone());
    assert_eq!(grant, Some(json!(new)), "the new grant went");
    let dial = b_dials_a(&mut both);
    assert!(dial.get("error").is_none(), "B cannot reach A: {dial}");
}

/// A reads B's caller-key request, and the grant it came on ends before
/// A stores the key (held at `keys-grant-read`): no key is kept for it.
#[test]
fn a_caller_key_for_a_grant_that_ended_while_it_was_read_is_not_kept() {
    let a_end = Endpoint::init("rl-keysa");
    let b_end = Endpoint::init("rl-keysb");
    let (k, v) = hook_var(&a_end, Hook::Hold("keys-grant-read")).unwrap();
    let mut a = start_raw(&a_end, "hostA", &[], 0, &[(k, Path::new(&v))]);
    let mut b = start(&b_end, "peerB", &[], 0);
    let grant = pair_apps(&mut a, &mut b).enrolled["grant"]
        .as_u64()
        .unwrap();
    until("A to read B's caller key request", || {
        hold_file(&a_end).exists()
    });
    let reply = a.call("grant.revoke_local", json!({"grant": grant}));
    assert_eq!(reply["removed"], true, "{reply}");
    std::fs::remove_file(hold_file(&a_end)).unwrap();
    until("A to answer B's caller key request", || {
        a_end.log().contains("caller key from") || caller_key_listed(&a_end.dir, grant)
    });
    assert!(
        !caller_key_listed(&a_end.dir, grant),
        "a caller key was kept for a grant that had ended"
    );
}

#[test]
fn a_revocation_that_cannot_be_journaled_changes_nothing() {
    let mut both = both_ways("rl-nojournal", &[]);
    let b_identity = both.b.identity.clone();
    let journal = both.a_end.dir.join("revoke.journal");
    std::fs::create_dir_all(journal.join("in-the-way")).unwrap();
    let reply = both
        .a
        .request("grant.revoke_local", json!({"grant": both.grant}));
    assert_eq!(reply["error"], "journal_failed", "{reply}");
    assert!(grant_of(&mut both.a, &b_identity).is_some());
    let b_to_a = both.b_to_a;
    let h = both.b.open(b_to_a, "mousse.rpc", "interactive");
    assert!(h > 0);
    assert!(both.b.events("conn.down").is_empty());
    assert!(both.a.events("net.paused").is_empty());
}

#[test]
fn malformed_requests_are_refused_and_change_nothing() {
    let mut both = both_ways("rl-bad", &[]);
    let b_identity = both.b.identity.clone();
    let grant = both.grant;
    for fields in [
        json!({}),
        json!({"grant": null}),
        json!({"grant": "1"}),
        json!({"grant": -1}),
        json!({"grant": 1.5}),
        json!({"grant": grant, "identity": b_identity}),
        json!({"grant": grant, "forget": false}),
    ] {
        let reply = both.a.request("grant.revoke_local", fields.clone());
        assert_eq!(reply["error"], "bad_request", "{fields}: {reply}");
    }
    assert!(grant_of(&mut both.a, &b_identity).is_some());
    assert!(both.a.events("grant.closed").is_empty());
    // A grant id that is not one: nothing to remove.
    let reply = both
        .a
        .call("grant.revoke_local", json!({"grant": grant + 1000}));
    assert_eq!(reply["removed"], false, "{reply}");
    assert!(grant_of(&mut both.a, &b_identity).is_some());
}
