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

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use common::*;
use relay_fixture::TestRelay as Relay;
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

// ---------------------------------------------------------------------------
// A grant removal keeps the peer: its outbound dials and relay upgrades go on

/// A loopback TCP forwarder that can hold newly accepted connections until
/// released, so a test can run `grant.remove` while a dial or upgrade is in
/// flight.
struct HoldProxy {
    route: String,
    hold: Arc<(Mutex<bool>, Condvar)>,
    held_count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl HoldProxy {
    fn to(port: u16, hold_initially: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let route = format!("tcp://{}", listener.local_addr().unwrap());
        let hold = Arc::new((Mutex::new(hold_initially), Condvar::new()));
        let held_count = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (hold_t, count_t, stop_t) = (hold.clone(), held_count.clone(), stop.clone());
        std::thread::spawn(move || {
            for inbound in listener.incoming().flatten() {
                if stop_t.load(Ordering::SeqCst) {
                    break;
                }
                let (hold_c, count_c) = (hold_t.clone(), count_t.clone());
                std::thread::spawn(move || {
                    {
                        let (lock, cv) = &*hold_c;
                        let mut held = lock.lock().unwrap();
                        if *held {
                            count_c.fetch_add(1, Ordering::SeqCst);
                            while *held {
                                held = cv.wait(held).unwrap();
                            }
                        }
                    }
                    let Ok(outbound) = TcpStream::connect(("127.0.0.1", port)) else {
                        return;
                    };
                    let _ = inbound.set_nodelay(true);
                    let _ = outbound.set_nodelay(true);
                    let in_r = inbound.try_clone().unwrap();
                    let out_w = outbound.try_clone().unwrap();
                    std::thread::spawn(move || pump_stream(in_r, out_w));
                    pump_stream(outbound, inbound);
                });
            }
        });
        Self {
            route,
            hold,
            held_count,
            stop,
        }
    }

    fn set_hold(&self, on: bool) {
        let (lock, cv) = &*self.hold;
        *lock.lock().unwrap() = on;
        if !on {
            cv.notify_all();
        }
    }

    fn wait_held(&self) {
        wait_until("a dial held in the proxy", || {
            self.held_count.load(Ordering::SeqCst) > 0
        });
    }
}

impl Drop for HoldProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.set_hold(false);
    }
}

fn pump_stream(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

#[test]
fn a_grant_removal_lets_an_in_flight_outbound_dial_finish() {
    let a_end = Endpoint::init("rc-rm-dial-a");
    let b_end = Endpoint::init("rc-rm-dial-b");
    let mut a = a_end.app("peerA", &relay_link::FAST);
    let mut b = b_end.app("hostB", &relay_link::FAST);
    relay_link::greet(&mut a);
    relay_link::greet(&mut b);
    pair_apps(&mut b, &mut a);
    let b_id = b.identity.clone();
    let grant = a.call("grant.add", json!({"identity": b_id, "name": "hostB"}))["grant"].clone();

    // Restart B on a new port so A dials it only through HoldProxy.
    b.kill();
    b = b_end.app("hostB", &relay_link::FAST);
    let b_port = relay_link::greet(&mut b)["port"].as_u64().unwrap() as u16;
    let proxy = HoldProxy::to(b_port, false);
    a.call(
        "peer.addresses.set",
        json!({"identity": b_id, "routes": [proxy.route]}),
    );
    // Establish an initial outbound path through the proxy so keep-connected
    // is idle and `last_route` points at the proxy.
    let first = relay_link::dial_up(&mut a, &b_id);
    assert!(first["conn"].is_u64(), "{first}");

    // Hold the next dial, run `grant.remove` while it is in flight, then
    // release the proxy. The outbound dial must still finish.
    proxy.set_hold(true);
    let dial_id = a.start("dial", json!({"identity": b_id}));
    proxy.wait_held();
    let removed = a.call("grant.remove", json!({"grant": grant}));
    assert_eq!(removed["removed"], true, "{removed}");
    proxy.set_hold(false);

    let reply = a.reply(dial_id);
    assert!(
        reply.get("error").is_none(),
        "grant.remove killed an in-flight outbound dial: {reply}"
    );
    assert!(reply["conn"].is_u64(), "{reply}");
}

#[test]
fn a_grant_removal_lets_a_relayed_connection_upgrade_to_direct() {
    let relay = Relay::start();
    let a_end = Endpoint::init("rc-rm-upg-a");
    let b_end = Endpoint::init("rc-rm-upg-b");
    let mut b = b_end.app("hostB", &relay_link::FAST);
    relay_link::greet(&mut b);
    let enrolled = b.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");
    let mut a = a_end.app("peerA", &relay_link::FAST);
    relay_link::greet(&mut a);
    pair_apps(&mut b, &mut a);
    let (a_id, b_id) = (a.identity.clone(), b.identity.clone());
    wait_until("B lists A's caller key", || {
        let list = b.call("grants.list", json!({}));
        list["grants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["identity"] == a_id.as_str() && g["relay"] == "listed")
    });
    a.event("peer.manifest", |m| m["identity"] == b_id.as_str());
    a.call(
        "peer.relay.allow",
        json!({"identity": b_id, "destination": relay.destination()}),
    );
    let grant = a.call("grant.add", json!({"identity": b_id, "name": "hostB"}))["grant"].clone();

    // Restart B on a new port behind HoldProxy (initially holding).
    b.kill();
    b = b_end.app("hostB", &relay_link::FAST);
    let b_port = relay_link::greet(&mut b)["port"].as_u64().unwrap() as u16;
    wait_until("B registered again", || {
        let list = b.call("relay.list", json!({}));
        list["relays"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["state"] == "registered")
    });
    let proxy = HoldProxy::to(b_port, true);
    a.call(
        "peer.addresses.set",
        json!({"identity": b_id, "routes": [proxy.route]}),
    );
    a.kill();
    a = a_end.app("peerA", &relay_link::FAST);
    relay_link::greet(&mut a);

    // A dials B through the relay first, and its upgrade task starts
    // dialling the direct proxy.
    let relayed = a.wait("outbound relay conn.up", WAIT, |st| {
        st.messages
            .iter()
            .find(|m| m["ev"] == "conn.up" && m["dir"] == "out" && m["route"]["kind"] == "relay")
            .cloned()
    });
    let relayed_conn = relayed["conn"].as_u64().unwrap();
    proxy.wait_held();

    // Remove A's grant for B while the upgrade is in flight, then release
    // the direct proxy. The relayed connection must still upgrade.
    let removed = a.call("grant.remove", json!({"grant": grant}));
    assert_eq!(removed["removed"], true, "{removed}");
    proxy.set_hold(false);

    let reopen = a.event("path.reopen", |m| m["from"] == relayed_conn);
    let direct = reopen["conn"].as_u64().unwrap();
    let up = a.event("conn.up", |m| m["conn"] == direct);
    assert_eq!(up["route"]["kind"], "tcp", "{up}");
}

// ---------------------------------------------------------------------------
// Every link pairing takes a number, and an in-person join numbers above
// the records

#[test]
fn a_direct_link_pairing_blocks_an_earlier_unreplayed_relay_records_tag() {
    let mut host = RelayHost::start("rc-dir-num");
    let a_end = Endpoint::init("rc-dir-num-a");
    // Pairing 1: relay-only link join, crashes right after saving its
    // completion record (never replayed yet, so relay-peers.json has no
    // pairing number for B).
    let l1 = host.join_crashing(&a_end, "link-done-saved");
    let b_id = host.b.identity.clone();
    assert!(
        relay_link::relay_peer(&a_end.dir, &b_id).is_null(),
        "relay-peers.json already had B"
    );

    // Pairing 2: direct "Send link" join with NO approved relay route.
    // A uses no class map, so B's loopback TCP route is automatic.
    let mut a = a_end.app_raw("peerA", &relay_link::FAST, 0, &no_keys());
    relay_link::greet(&mut a);
    let a_id = a.identity.clone();
    host_removes(&mut host, &a_id);
    let l2 = host.link();
    let id = a.start("join", json!({"ticket": l2.uri, "arrival": "link"}));
    a.wait("join.code_needed for l2", WAIT, |st| {
        st.messages
            .iter()
            .find(|m| m["ev"] == "join.code_needed" && m["invitation"] == l2.inv.as_str())
            .cloned()
    });
    a.call("join.code", json!({"invitation": l2.inv, "code": l2.code}));
    let reply = a.reply(id);
    assert!(reply.get("error").is_none(), "{reply}");
    let up = a.event("conn.up", |m| m["conn"] == reply["conn"]);
    assert_ne!(up["route"]["kind"], "relay", "{up}");

    // Replaying the earlier relay record must NOT restore its superseded tag.
    let s = relay_link::status(&mut a, &l1);
    assert_eq!(s["done"]["identity"], b_id.as_str(), "{s}");
    let entry = relay_link::relay_peer(&a.dir, &b_id);
    assert!(
        entry["join_tag"].is_null(),
        "an older unreplayed relay record restored its tag after a direct link pairing: {entry}"
    );
}

#[test]
fn a_same_second_in_person_join_takes_a_number_above_an_unreplayed_link_record() {
    let mut host = RelayHost::start("rc-same-sec");
    let a_end = Endpoint::init("rc-same-sec-a");
    let clock = [
        ("MOUSSE_HELPER_MANUAL_CLOCK", Path::new("1")),
        ("MOUSSE_HELPER_TEST_NO_KEYS", Path::new("1")),
    ];
    let mut a = host.joiner(&a_end, &[], &clock);
    let b_id = host.b.identity.clone();

    // Pairing 1: relay-only link join whose relay-peers.json write fails,
    // leaving its completion record on disk with pairing = T while
    // relay-peers.json still has no entry for B.
    let l1 = host.link();
    let id = a.start(
        "join",
        json!({"ticket": l1.uri, "arrival": "link", "approved": [host.destination()]}),
    );
    a.event("join.code_needed", |m| m["invitation"] == l1.inv.as_str());
    let relay_peers = a_end.dir.join("relay-peers.json");
    std::fs::create_dir(&relay_peers).unwrap();
    a.call("join.code", json!({"invitation": l1.inv, "code": l1.code}));
    let reply = a.reply(id);
    assert_eq!(reply["error"], "store", "{reply}");
    std::fs::remove_dir(&relay_peers).unwrap();
    let mut rec1 = record(&a_end, &l1);
    assert!(rec1["relay"]["pairing"].as_u64().unwrap() > 0, "{rec1}");
    // Pairings in one second take numbers above the clock: this record's
    // is as if several came before it in that second.
    let p1 = rec1["relay"]["pairing"].as_u64().unwrap() + 1_000;
    rec1["relay"]["pairing"] = json!(p1);
    std::fs::write(
        record_path(&a_end, &l1),
        serde_json::to_vec_pretty(&rec1).unwrap(),
    )
    .unwrap();

    // Pairing 2: in-person join over the relay in the same second (manual
    // clock has not moved).
    let a_id = a.identity.clone();
    host_removes(&mut host, &a_id);
    let invite = host.b.call("invite.create", json!({"kind": "in_person"}));
    let inv = invite["invitation"].as_str().unwrap().to_owned();
    let id2 = a.start(
        "join",
        json!({
            "ticket": invite["uri"],
            "arrival": "scan",
            "approved": [host.destination()],
        }),
    );
    let approval = host
        .b
        .event("approval", |m| m["invitation"] == inv.as_str());
    host.b.call(
        "approval.answer",
        json!({"request": approval["request"], "yes": true}),
    );
    let reply2 = a.reply(id2);
    assert!(reply2.get("error").is_none(), "{reply2}");
    let entry_after = relay_link::relay_peer(&a.dir, &b_id);
    let p2 = entry_after["pairing"].as_u64().unwrap();
    let tag2 = entry_after["join_tag"].clone();
    assert!(
        p2 > p1,
        "same-second in-person join did not advance above the unreplayed record ({p2} <= {p1}): {entry_after}"
    );
    assert!(tag2.is_string(), "{entry_after}");

    // Replaying the older link record must NOT overwrite the in-person tag.
    let s = relay_link::status(&mut a, &l1);
    assert_eq!(s["done"]["identity"], b_id.as_str(), "{s}");
    let entry_final = relay_link::relay_peer(&a.dir, &b_id);
    assert_eq!(
        entry_final["join_tag"], tag2,
        "the older link record overwrote the same-second in-person tag: {entry_final}"
    );
}

// ---------------------------------------------------------------------------
// An older pairing's keys exchange never overwrites a newer pair secret

#[test]
fn a_stalled_older_keys_exchange_does_not_overwrite_a_newer_pair_secret() {
    let mut host = RelayHost::start("rc-stale-keys");
    let a_end = Endpoint::init("rc-stale-keys-a");
    let file = a_end.dir.join("held-keys");
    let hold = format!("keys-answered={}", file.display());
    let mut a = host.joiner(
        &a_end,
        &[],
        &[("MOUSSE_HELPER_TEST_HOLD", Path::new(&hold))],
    );
    let b_id = host.b.identity.clone();
    let l1 = host.link();
    joined_via_relay(&mut a, &host, &l1);
    // `ensure_keys` for pairing 1 has received B's answer and is held
    // before taking the relay lock.
    held(&file);

    // Simulate a newer pairing's pair secret and keys_pairing stored
    // meanwhile in relay-peers.json.
    let path = a_end.dir.join("relay-peers.json");
    let mut peers_file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let newer_secret = "aa".repeat(48);
    let entry = peers_file["peers"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p["identity"] == b_id.as_str())
        .unwrap();
    let p1 = entry["pairing"].as_u64().unwrap();
    entry["pairing"] = json!(p1 + 1);
    entry["keys_pairing"] = json!(p1 + 1);
    entry["pair_secret"] = json!(newer_secret);
    std::fs::write(&path, serde_json::to_vec_pretty(&peers_file).unwrap()).unwrap();

    // Release the stalled exchange and let it finish.
    // With the fix it writes nothing to wait for, so give it time.
    std::fs::remove_file(&file).unwrap();
    std::thread::sleep(Duration::from_millis(1_000));
    // Verify a normal op completes and the newer pair secret stayed intact.
    let _ = a.call("peers.list", json!({}));
    let after = relay_link::relay_peer(&a.dir, &b_id);
    assert_eq!(
        after["pair_secret"],
        json!(newer_secret),
        "a stalled older mousse-keys exchange overwrote a newer pair secret: {after}"
    );
    assert_eq!(after["keys_pairing"], json!(p1 + 1), "{after}");
}

// ---------------------------------------------------------------------------
// A refusal that outlasts the dial limit still falls back to the tag

#[test]
fn relay_recovery_falls_back_to_the_tag_when_call_times_out() {
    // Relay refusal delay exceeds the helper's relay dial timeout, so a
    // refused CALL ends as RelayError::Timeout instead of Unreachable.
    let mut host = RelayHost::start_with("rc-timeout-fb", &[("RELAY_REFUSE_MS", 1_500)]);
    let a_end = Endpoint::init("rc-timeout-fb-a");
    let fast_timeout = [("VIA_RELAY_DIAL_MS", "1000")];
    let mut a = host.joiner(&a_end, &fast_timeout, &[]);
    let (a_id, b_id) = (a.identity.clone(), host.b.identity.clone());
    // First pairing enrolls a caller key (so pair_secret is present).
    let l1 = host.link();
    let conn = joined_via_relay(&mut a, &host, &l1);
    a.event("peer.keys", |m| m["identity"] == b_id.as_str());
    host_removes(&mut host, &a_id);
    a.event("conn.down", |m| m["conn"] == conn);
    drop(a);

    // Second pairing has a new tag and holds back mousse-keys.
    let mut a = host.joiner(&a_end, &fast_timeout, &no_keys());
    let l2 = host.link();
    joined_via_relay(&mut a, &host, &l2);
    drop(a);

    // Recovery dial: CALL times out after 1000ms (before the 1500ms
    // refusal), and must still fall back to JOIN with the tag.
    let mut a = host.joiner(&a_end, &fast_timeout, &no_keys());
    let reply = a.request("dial", json!({"identity": b_id}));
    assert!(
        reply.get("error").is_none(),
        "recovery dial did not fall back to the tag on CALL timeout: {reply}"
    );
    let up = a.event("conn.up", |m| m["conn"] == reply["conn"]);
    assert_eq!(up["route"]["kind"], "relay", "{up}");
}

// ---------------------------------------------------------------------------
// A grant removal also ends a record from before pairing numbers

#[cfg(unix)]
#[test]
fn a_pre_pairing_number_record_that_failed_to_delete_restores_no_relay_writes() {
    let mut host = RelayHost::start("rc-rm-zero");
    let a_end = Endpoint::init("rc-rm-zero-a");
    let link = host.join_crashing(&a_end, "link-done-saved");
    // Strip the pairing number from the saved completion record so it
    // matches a record written before pairing numbers existed (pairing = 0).
    let rec_path = record_path(&a_end, &link);
    let mut rec: Value = serde_json::from_slice(&std::fs::read(&rec_path).unwrap()).unwrap();
    rec["relay"].as_object_mut().unwrap().remove("pairing");
    std::fs::write(&rec_path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();

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
    assert!(rec_path.exists(), "the record went, so this checks nothing");
    relay_link::status(&mut a, &link);
    let entry = relay_link::relay_peer(&a.dir, &b_id);
    assert!(
        entry["join_tag"].is_null(),
        "a removed pairing-0 record's tag came back: {entry}"
    );
    let routes = entry["ticket_routes"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        routes.is_empty(),
        "a removed pairing-0 record's relay route came back: {entry}"
    );
    assert!(
        !approved_here(&a, &host),
        "a removed pairing-0 record's relay was approved again"
    );
}
