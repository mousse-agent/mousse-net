//! What a "Send link" pairing through a relay keeps, over later pairings,
//! removals, disallows, crashes and failed writes (pairing-flow design §9,
//! `pairing-relay-completion`).
//!
//! Each pairing with a host takes a number that only grows, kept on the
//! host's relay entry: a completion record of an older pairing, or of one
//! that ended with a removal of the host's grant, restores no tag over a
//! newer one. A destination the owner disallowed is not approved again by
//! a replay. The way back through the relay is the caller key first, then
//! the ticket's tag, so a crash once the host answered `mousse-keys`, or a
//! pair secret from an earlier pairing, strands nothing.

mod common;
#[path = "common/relay.rs"]
mod relay_fixture;
#[path = "common/relay_link.rs"]
mod relay_link;

use std::path::Path;
use std::time::{Duration, Instant};

use common::*;
use relay_link::{Link, RelayHost};
use serde_json::{json, Value};

/// The test hook that holds A's caller key back from B.
fn no_keys() -> [(&'static str, &'static Path); 1] {
    [("MOUSSE_HELPER_TEST_NO_KEYS", Path::new("1"))]
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < WAIT, "never: {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The path of A's completion record for `link`.
fn record_path(a_end: &Endpoint, link: &Link) -> std::path::PathBuf {
    a_end
        .dir
        .join("joins")
        .join(format!("{}.done", link.hash()))
}

fn record(a_end: &Endpoint, link: &Link) -> Value {
    serde_json::from_slice(&std::fs::read(record_path(a_end, link)).unwrap()).unwrap()
}

/// Wait for `file`, which a held test hook creates.
fn held(file: &Path) {
    wait_until("the hook held", || file.exists());
}

/// A's join of `link` through the relay worked: its conn.
fn joined_via_relay(a: &mut App, host: &RelayHost, link: &Link) -> Value {
    let id = host.join(a, link);
    let reply = a.reply(id);
    assert!(reply.get("error").is_none(), "{reply}");
    let up = a.event("conn.up", |m| m["conn"] == reply["conn"]);
    assert_eq!(up["route"]["kind"], "relay", "{up}");
    reply["conn"].clone()
}

/// B removes its grant for A, and its caller key for A goes with it.
fn host_removes(host: &mut RelayHost, a_identity: &str) {
    let list = host.b.call("grants.list", json!({}));
    let grant = list["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["identity"] == a_identity)
        .map(|g| g["grant"].clone())
        .unwrap();
    let removed = host.b.call("grant.remove", json!({"grant": grant}));
    assert_eq!(removed["removed"], true, "{removed}");
}

fn approved_here(a: &App, host: &RelayHost) -> bool {
    let b_id = host.b.identity.as_str();
    relay_link::approvals(&a.dir)
        .iter()
        .any(|x| x["identity"] == b_id && x["destination"] == host.destination())
}

/// The ticket's relay hint.
fn hint(link: &Link) -> String {
    link.ticket
        .routes
        .iter()
        .find(|r| r.starts_with("relay://"))
        .unwrap()
        .clone()
}

// ---------------------------------------------------------------------------
// F: an older pairing's record restores no tag over a newer one

/// A paired with B through the relay by `l1`, B removed A, and A paired
/// again by `l2`; neither record acknowledged and B never got A's caller
/// key, so both tags are live. Returns the links and the tag the newer
/// pairing stored.
fn two_relay_pairings(host: &mut RelayHost, a: &mut App) -> (Link, Link, Value) {
    let b_id = host.b.identity.clone();
    let l1 = host.link();
    let conn = joined_via_relay(a, host, &l1);
    let first = relay_link::relay_peer(&a.dir, &b_id)["join_tag"].clone();
    assert!(first.is_string(), "the first pairing stored no tag");
    let a_id = a.identity.clone();
    host_removes(host, &a_id);
    a.event("conn.down", |m| m["conn"] == conn);
    let l2 = host.link();
    joined_via_relay(a, host, &l2);
    let newer = relay_link::relay_peer(&a.dir, &b_id)["join_tag"].clone();
    assert!(newer.is_string(), "the second pairing stored no tag");
    assert_ne!(newer, first, "the second pairing kept the first tag");
    (l1, l2, newer)
}

#[test]
fn an_older_pairings_record_leaves_the_newer_unacknowledged_pairings_tag() {
    let mut host = RelayHost::start("rc-older");
    let a_end = Endpoint::init("rc-older-a");
    let mut a = host.joiner(&a_end, &[], &no_keys());
    let (l1, _l2, newer) = two_relay_pairings(&mut host, &mut a);
    let b_id = host.b.identity.clone();
    let s = relay_link::status(&mut a, &l1);
    assert_eq!(s["done"]["identity"], b_id.as_str(), "{s}");
    let entry = relay_link::relay_peer(&a.dir, &b_id);
    assert_eq!(
        entry["join_tag"], newer,
        "an older record replaced the newer pairing's tag: {entry}"
    );
}

#[test]
fn an_older_pairings_record_leaves_the_newer_acknowledged_pairings_tag() {
    let mut host = RelayHost::start("rc-acked");
    let a_end = Endpoint::init("rc-acked-a");
    let mut a = host.joiner(&a_end, &[], &no_keys());
    let (l1, l2, newer) = two_relay_pairings(&mut host, &mut a);
    let ack = a.call("join.ack", json!({"ticket_hash": l2.hash()}));
    assert_eq!(ack["removed"], true, "{ack}");
    let b_id = host.b.identity.clone();
    let s = relay_link::status(&mut a, &l1);
    assert_eq!(s["done"]["identity"], b_id.as_str(), "{s}");
    let entry = relay_link::relay_peer(&a.dir, &b_id);
    assert_eq!(
        entry["join_tag"], newer,
        "an older record replaced the newer pairing's tag once it was acknowledged: {entry}"
    );
}

// ---------------------------------------------------------------------------
// G: a disallow outlasts a replay

#[test]
fn a_disallowed_relay_is_not_approved_again_by_a_replay() {
    let mut host = RelayHost::start("rc-disallow");
    let a_end = Endpoint::init("rc-disallow-a");
    let link = host.join_crashing(&a_end, "link-done-saved");
    let mut a = host.joiner(&a_end, &[], &[]);
    let b_id = host.b.identity.clone();
    relay_link::status(&mut a, &link);
    assert!(approved_here(&a, &host), "the replay approved nothing");
    a.call(
        "peer.relay.disallow",
        json!({"identity": b_id, "destination": host.destination()}),
    );
    assert!(!approved_here(&a, &host), "the disallow kept the approval");
    let s = relay_link::status(&mut a, &link);
    assert_eq!(s["done"]["identity"], b_id.as_str(), "{s}");
    assert!(
        !approved_here(&a, &host),
        "a replay approved a disallowed relay again"
    );
    // Restarted, the record still approves nothing.
    drop(a);
    let mut a = host.joiner(&a_end, &[], &[]);
    relay_link::status(&mut a, &link);
    assert!(
        !approved_here(&a, &host),
        "a replay after a restart approved a disallowed relay again"
    );
}

// ---------------------------------------------------------------------------
// H: a removal of the host's grant wins over a join and a failed delete

/// The owner removes the grant A holds for B while A's link join to B has
/// PAIRED and not yet stored its record: the join stores nothing.
#[test]
fn a_grant_removal_while_a_relay_link_join_has_paired_stores_nothing() {
    let mut host = RelayHost::start("rc-rm-paired");
    let a_end = Endpoint::init("rc-rm-paired-a");
    let file = a_end.dir.join("held");
    let hold = format!("link-paired={}", file.display());
    let mut a = host.joiner(
        &a_end,
        &[],
        &[("MOUSSE_HELPER_TEST_HOLD", Path::new(&hold))],
    );
    let b_id = host.b.identity.clone();
    let grant = a.call("grant.add", json!({"identity": b_id, "name": "hostB"}))["grant"].clone();
    let link = host.link();
    let id = host.join(&mut a, &link);
    held(&file);
    let removed = a.call("grant.remove", json!({"grant": grant}));
    assert_eq!(removed["removed"], true, "{removed}");
    std::fs::remove_file(&file).unwrap();
    let reply = a.reply(id);
    assert_eq!(
        reply["error"], "forgotten",
        "the join stored a host whose grant was removed: {reply}"
    );
    assert!(!record_path(&a_end, &link).exists(), "a record was kept");
    assert_eq!(peer_of(&mut a, &b_id), Value::Null);
    assert!(!approved_here(&a, &host), "the relay was approved");
    let entry = relay_link::relay_peer(&a.dir, &b_id);
    assert!(entry["join_tag"].is_null(), "a tag was kept: {entry}");
    let s = relay_link::status(&mut a, &link);
    assert_eq!(s["done"], Value::Null, "{s}");
}

/// The record of a host whose grant was removed could not be deleted: a
/// replay of it restores none of its relay writes. Unix: the delete is
/// made to fail with the folder's permissions.
#[cfg(unix)]
#[test]
fn a_record_a_grant_removal_failed_to_delete_restores_no_relay_writes() {
    let mut host = RelayHost::start("rc-rm-stuck");
    let a_end = Endpoint::init("rc-rm-stuck-a");
    let link = host.join_crashing(&a_end, "link-done-saved");
    let mut a = host.joiner(&a_end, &[], &[]);
    let b_id = host.b.identity.clone();
    let grant = a.call("grant.add", json!({"identity": b_id, "name": "hostB"}))["grant"].clone();
    let joins = a_end.dir.join("joins");
    let mode = |m: u32| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&joins, std::fs::Permissions::from_mode(m)).unwrap();
    };
    mode(0o555);
    let removed = a.request("grant.remove", json!({"grant": grant}));
    mode(0o755);
    assert_eq!(removed["removed"], true, "{removed}");
    assert!(
        record_path(&a_end, &link).exists(),
        "the record went, so this checks nothing"
    );
    relay_link::status(&mut a, &link);
    let entry = relay_link::relay_peer(&a.dir, &b_id);
    assert!(
        entry["join_tag"].is_null(),
        "a removed pairing's tag came back: {entry}"
    );
    let routes = entry["ticket_routes"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        routes.is_empty(),
        "a removed pairing's relay route came back: {entry}"
    );
    assert!(
        !approved_here(&a, &host),
        "a removed pairing's relay was approved again"
    );
}

// ---------------------------------------------------------------------------
// I and J: the caller key first, then the tag

/// A crash once B answered `mousse-keys` and before A stored the pair
/// secret: B lists A's key and holds the tag no more, and A still comes
/// back through the relay.
#[test]
fn a_crash_once_the_host_answered_the_keys_still_comes_back_over_the_relay() {
    let mut host = RelayHost::start("rc-keys-crash");
    let a_end = Endpoint::init("rc-keys-crash-a");
    let crash = [("MOUSSE_HELPER_TEST_CRASH", Path::new("keys-answered"))];
    let mut a = host.joiner(&a_end, &[], &crash);
    let a_id = a.identity.clone();
    let link = host.link();
    host.join(&mut a, &link);
    assert_eq!(
        a.exit_within(WAIT),
        Some(86),
        "never stopped at keys-answered: {}",
        a.err()
    );
    wait_until("B lists A's caller key", || {
        host.relay_status(&a_id) == "listed"
    });
    let b_id = host.b.identity.clone();
    let entry = relay_link::relay_peer(&a_end.dir, &b_id);
    assert!(entry["pair_secret"].is_null(), "{entry}");
    let mut a = host.joiner(&a_end, &[], &[]);
    let up = relay_link::dial_up(&mut a, &b_id);
    assert_eq!(up["route"]["kind"], "relay", "{up}");
}

/// A pair secret from an earlier pairing does not keep the newer
/// pairing's tag out: before B gets A's new caller key, A reaches B with
/// the tag.
#[test]
fn a_new_relay_pairing_after_an_earlier_pair_secret_is_reached_with_its_tag() {
    let mut host = RelayHost::start("rc-old-secret");
    let a_end = Endpoint::init("rc-old-secret-a");
    let mut a = host.joiner(&a_end, &[], &[]);
    let (a_id, b_id) = (a.identity.clone(), host.b.identity.clone());
    let l1 = host.link();
    let conn = joined_via_relay(&mut a, &host, &l1);
    a.event("peer.keys", |m| m["identity"] == b_id.as_str());
    host_removes(&mut host, &a_id);
    a.event("conn.down", |m| m["conn"] == conn);
    drop(a);
    let mut a = host.joiner(&a_end, &[], &no_keys());
    let l2 = host.link();
    joined_via_relay(&mut a, &host, &l2);
    let entry = relay_link::relay_peer(&a.dir, &b_id);
    assert!(entry["pair_secret"].is_string(), "{entry}");
    assert!(
        entry["join_tag"].is_string(),
        "the new pairing's tag was skipped for an earlier pair secret: {entry}"
    );
    drop(a);
    let mut a = host.joiner(&a_end, &[], &no_keys());
    let up = relay_link::dial_up(&mut a, &b_id);
    assert_eq!(up["route"]["kind"], "relay", "{up}");
}

// ---------------------------------------------------------------------------
// K: the tag's time runs from the PAIRED time

#[test]
fn a_relay_link_tags_time_runs_from_when_it_paired() {
    let rejoin = [
        ("VIA_RELAY_REJOIN_SECS", "600"),
        ("JOIN_DONE_KEEP_SECS", "86400"),
    ];
    let mut host = RelayHost::start("rc-paired-at");
    let a_end = Endpoint::init("rc-paired-at-a");
    let raw = [
        ("MOUSSE_HELPER_TEST_CRASH", Path::new("link-done-saved")),
        ("MOUSSE_HELPER_MANUAL_CLOCK", Path::new("1")),
    ];
    let mut a = host.joiner(&a_end, &rejoin, &raw);
    let link = host.link();
    a.start(
        "join",
        json!({"ticket": link.uri, "arrival": "link", "approved": [host.destination()]}),
    );
    a.event("join.code_needed", |m| m["invitation"] == link.inv.as_str());
    a.call("test.clock", json!({"advance_secs": 300}));
    a.call(
        "join.code",
        json!({"invitation": link.inv, "code": link.code}),
    );
    assert_eq!(
        a.exit_within(WAIT),
        Some(86),
        "never stopped at link-done-saved: {}",
        a.err()
    );
    let r = record(&a_end, &link);
    let at = r["at"].as_u64().unwrap();
    let expires = r["relay"]["tag_expires_at"].as_u64().unwrap();
    // The record is kept a day past the ticket, so the 600 s run out first.
    assert!(
        at + 600 <= r["expires_at"].as_u64().unwrap() + 86_400,
        "the record ends first, so this checks nothing: {r}"
    );
    assert_eq!(
        expires,
        at + 600,
        "the tag's time does not run from the PAIRED time: {r}"
    );
}

// ---------------------------------------------------------------------------
// L and N2: a relay route only with the tag sealed; a direct join keeps it

/// A's state, its relay seed unusable: no tag can be sealed.
fn without_seed(tag: &str) -> Endpoint {
    let a_end = Endpoint::init(tag);
    let seed = a_end.dir.join("relay-seed.key");
    let _ = std::fs::remove_file(&seed);
    std::fs::create_dir(&seed).unwrap();
    a_end
}

#[test]
fn a_relay_only_link_join_with_no_sealed_tag_is_refused() {
    let mut host = RelayHost::start("rc-no-seal");
    let a_end = without_seed("rc-no-seal-a");
    let mut a = host.joiner(&a_end, &[], &[]);
    let link = host.link();
    let id = a.start(
        "join",
        json!({"ticket": link.uri, "arrival": "link", "approved": [host.destination()]}),
    );
    // The reply, or the host asking for the code through the relay.
    let first = a.wait("the join's reply or its code request", WAIT, |st| {
        st.messages
            .iter()
            .find(|m| m.get("re") == Some(&json!(id)) || m["ev"] == "join.code_needed")
            .cloned()
    });
    assert_eq!(
        first["error"], "store",
        "a relay join ran with no way to store its tag: {first}"
    );
    let b_id = host.b.identity.clone();
    assert_eq!(peer_of(&mut a, &b_id), Value::Null);
}

/// A link join with the relay approved that reached B directly: its own
/// route (no class map).
fn joined_directly(host: &mut RelayHost, a_end: &Endpoint) -> (App, Link) {
    let mut a = a_end.app_raw("peerA", &relay_link::FAST, 0, &[]);
    relay_link::greet(&mut a);
    let link = host.link();
    let id = host.join(&mut a, &link);
    let reply = a.reply(id);
    assert!(reply.get("error").is_none(), "{reply}");
    let up = a.event("conn.up", |m| m["conn"] == reply["conn"]);
    assert_ne!(up["route"]["kind"], "relay", "{up}");
    (a, link)
}

#[test]
fn a_link_join_with_no_sealed_tag_still_goes_directly() {
    let mut host = RelayHost::start("rc-no-seal-direct");
    let a_end = without_seed("rc-no-seal-direct-a");
    let (mut a, _link) = joined_directly(&mut host, &a_end);
    let b_id = host.b.identity.clone();
    assert_eq!(peer_of(&mut a, &b_id)["name"], "hostB");
}

#[test]
fn a_direct_link_join_keeps_the_approved_relay_route_and_no_tag() {
    let mut host = RelayHost::start("rc-direct");
    let a_end = Endpoint::init("rc-direct-a");
    let (a, link) = joined_directly(&mut host, &a_end);
    let entry = relay_link::relay_peer(&a.dir, &host.b.identity);
    assert_eq!(entry["ticket_routes"], json!([hint(&link)]), "{entry}");
    assert!(approved_here(&a, &host), "the relay was not approved");
    assert!(
        entry["join_tag"].is_null(),
        "a direct join stored a tag: {entry}"
    );
    assert!(record(&a_end, &link)["relay"]["join_tag"].is_null());
}

// ---------------------------------------------------------------------------
// N1: a failed write keeps the record until it can be made

/// A relay-only link join whose write to `file` fails once it paired: the
/// join and `join.status` report the store failure, the record stays, and
/// once the file can be written `join.status` reports the pairing done.
fn a_blocked_write_keeps_the_record(tag: &str, file: &str) {
    let mut host = RelayHost::start(tag);
    let a_end = Endpoint::init(&format!("{tag}-a"));
    let mut a = host.joiner(&a_end, &[], &[]);
    let link = host.link();
    let id = a.start(
        "join",
        json!({"ticket": link.uri, "arrival": "link", "approved": [host.destination()]}),
    );
    a.event("join.code_needed", |m| m["invitation"] == link.inv.as_str());
    let path = a_end.dir.join(file);
    let aside = a_end.dir.join(format!("{file}.aside"));
    let had = path.exists();
    if had {
        std::fs::rename(&path, &aside).unwrap();
    }
    std::fs::create_dir(&path).unwrap();
    a.call(
        "join.code",
        json!({"invitation": link.inv, "code": link.code}),
    );
    let reply = a.reply(id);
    assert_eq!(reply["error"], "store", "{reply}");
    assert!(record_path(&a_end, &link).exists(), "the record went");
    let s = a.request("join.status", json!({"ticket_hash": link.hash()}));
    assert_eq!(s["error"], "store_failed", "{s}");
    assert!(record_path(&a_end, &link).exists(), "the record went");
    std::fs::remove_dir(&path).unwrap();
    if had {
        std::fs::rename(&aside, &path).unwrap();
    }
    let b_id = host.b.identity.clone();
    let s = relay_link::status(&mut a, &link);
    assert_eq!(s["done"]["identity"], b_id.as_str(), "{s}");
    assert!(approved_here(&a, &host), "the relay was not approved");
    let entry = relay_link::relay_peer(&a.dir, &b_id);
    assert_eq!(entry["ticket_routes"], json!([hint(&link)]), "{entry}");
    assert!(entry["join_tag"].is_string(), "no tag: {entry}");
}

#[test]
fn a_failed_relay_entry_write_keeps_the_record_until_it_works() {
    a_blocked_write_keeps_the_record("rc-block-peers", "relay-peers.json");
}

#[test]
fn a_failed_approval_write_keeps_the_record_until_it_works() {
    a_blocked_write_keeps_the_record("rc-block-approvals", "approvals.json");
}
