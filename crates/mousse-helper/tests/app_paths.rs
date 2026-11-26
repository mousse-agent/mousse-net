//! E5a: reaching paired hosts (Phase 1a §5.3 and §6). The check cell
//! `phase1a.discovery` runs this file: the mDNS record carries no name, a
//! pin mismatch moves on to the next candidate, and the addresses a peer
//! supplies are private-range only (the owner's may be of any class but
//! `forbidden`, Phase 1b §1.3).
//!
//! Everything runs on loopback: helpers listen on 127.0.0.1 only, and the
//! browse source is a file (`MOUSSE_HELPER_BROWSE_FILE`), never multicast.
//! Debug builds take loopback addresses as private for this reason.

mod common;

use std::collections::HashSet;
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use mousse_net_core::pairing::Ticket;
use serde_json::{json, Value};

/// A fresh identity no helper here has.
fn some_identity() -> String {
    use mousse_net_core::identity::{IdentitySigner, SoftwareKey};
    let key = SoftwareKey::generate(&mut mousse_net_io::rng::os_rng());
    mousse_net_io::store::hex(IdentitySigner::public_key(&key).as_bytes())
}

/// A loopback address that accepts TCP and then says nothing: a candidate
/// that never passes step 1. Counts the connections it took.
struct Silent {
    route: String,
    accepted: Arc<AtomicUsize>,
}

fn silent() -> Silent {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let route = format!("tcp://{}", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    let held = Arc::new(Mutex::new(Vec::new()));
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            count.fetch_add(1, Ordering::SeqCst);
            held.lock().unwrap().push(stream);
        }
    });
    Silent { route, accepted }
}

impl Silent {
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// `peer.forget` while a path to that peer is still opening: once the
/// forget has answered, no path to it comes up.
#[test]
fn a_path_still_opening_when_its_peer_is_forgotten_never_comes_up() {
    let a_end = Endpoint::init("fga");
    let b_end = Endpoint::init("fgb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut b = b_end.app("peerB", &[("DIAL_TIMEOUT_MS", "30000")]);
    b.hello();
    let gate = gate_to(&route_of(&mut a));
    trust(&mut a, &mut b, &[&gate.route]);
    // B's keeper dials; the relay holds the connection.
    gate.wait_accepted();
    let forgot = b.call("peer.forget", json!({"identity": a.identity}));
    assert_eq!(forgot["forgotten"], true, "{forgot}");
    gate.open();
    // The dial passes step 1 now, after the forget.
    a.event("conn.up", |m| m["identity"] == b.identity.as_str());
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        outbound_ups(&b, &a.identity),
        0,
        "{:?}",
        b.events("conn.up")
    );
    assert!(
        b_end.log().contains("forgotten meanwhile"),
        "{}",
        b_end.log()
    );
    assert!(peer_of(&mut b, &a.identity).is_null());
}

/// The mDNS record says only "a Mousse host is here": random instance and
/// host names, `v=1`, and nothing of the device's name or identity.
#[test]
fn the_mdns_record_carries_no_name_or_identity() {
    use mousse_net_io::discovery::{random_instance_name, record, NAME_PREFIX, SERVICE_TYPE};
    let end = Endpoint::init("mdnsrec");
    let mut app = end.app("Alice Desk", &[]);
    let hello = app.hello();
    let port = hello["port"].as_u64().unwrap() as u16;
    let device = hello["device"].as_str().unwrap().to_owned();
    let computer = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default()
        .to_lowercase();
    let mut names = HashSet::new();
    for _ in 0..8 {
        let name = random_instance_name(&mut mousse_net_io::rng::os_rng());
        let info = record(&name, port).unwrap();
        let tail = &name[NAME_PREFIX.len()..];
        assert_eq!(tail.len(), 12, "{name}");
        assert!(tail
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)));
        assert_eq!(info.get_fullname(), format!("{name}.{SERVICE_TYPE}"));
        assert_eq!(info.get_hostname(), format!("{name}.local."));
        let props: Vec<(String, String)> = info
            .get_properties()
            .iter()
            .map(|p| (p.key().to_owned(), p.val_str().to_owned()))
            .collect();
        assert_eq!(props, vec![("v".to_owned(), "1".to_owned())]);
        let all =
            format!("{} {} {props:?}", info.get_fullname(), info.get_hostname()).to_lowercase();
        for secret in ["alice", &app.identity, &device] {
            assert!(!all.contains(secret), "{secret} in {all}");
        }
        if computer.len() > 2 {
            assert!(!all.contains(&computer), "the computer name in {all}");
        }
        names.insert(name);
    }
    assert_eq!(names.len(), 8, "every start gets a new name");
}

/// A candidate that answers with another identity (another profile, or a
/// device that took the address) is skipped, and the next one is tried.
/// One candidate at a time, so the mismatch comes first.
#[test]
fn a_pin_mismatch_moves_on_to_the_next_candidate() {
    let a_end = Endpoint::init("mma");
    let s_end = Endpoint::init("mms");
    let b_end = Endpoint::init("mmb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut s = s_end.app("other", &[]);
    s.hello();
    let mut b = b_end.app("peerB", &[("DIAL_PARALLEL", "1")]);
    b.hello();
    let (a_route, s_route) = (route_of(&mut a), route_of(&mut s));
    trust(&mut a, &mut b, &[&s_route, &a_route]);
    let reply = b.request("dial", json!({"identity": a.identity}));
    assert!(reply.get("error").is_none(), "dial: {reply}");
    let identity = b.identity.clone();
    a.event("conn.up", |m| {
        m["dir"] == "in" && m["identity"] == identity.as_str()
    });
    assert_eq!(peer_of(&mut b, &a.identity)["last_route"], a_route.as_str());
    assert!(
        s.events("conn.up").is_empty(),
        "the other endpoint admitted nothing"
    );
    assert!(
        b.events("dial.failed").is_empty(),
        "{:?}",
        b.events("dial.failed")
    );
}

/// Candidates are dialled several at once: three silent addresses ahead of
/// the host do not hold it up.
#[test]
fn candidates_are_dialled_several_at_once() {
    let a_end = Endpoint::init("para");
    let b_end = Endpoint::init("parb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    // One at a time, this would take three timeouts: 24 s.
    let mut b = b_end.app("peerB", &[("DIAL_TIMEOUT_MS", "8000")]);
    b.hello();
    let a_route = route_of(&mut a);
    let holes = [silent(), silent(), silent()];
    let start = Instant::now();
    trust(
        &mut a,
        &mut b,
        &[&holes[0].route, &holes[1].route, &holes[2].route, &a_route],
    );
    let reply = b.call("dial", json!({"identity": a.identity}));
    let took = start.elapsed();
    assert!(took < Duration::from_secs(6), "took {took:?}: {reply}");
    for hole in &holes {
        let deadline = Instant::now() + Duration::from_secs(5);
        while hole.accepted() == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(hole.accepted() > 0, "every candidate was tried");
    }
}

/// A candidate that never passes step 1 is given up after
/// `DIAL_TIMEOUT_MS`, well before the TCP and TLS timeouts.
#[test]
fn a_silent_candidate_is_given_up_after_the_dial_timeout() {
    let a_end = Endpoint::init("toa");
    let b_end = Endpoint::init("tob");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut b = b_end.app(
        "peerB",
        &[("DIAL_PARALLEL", "1"), ("DIAL_TIMEOUT_MS", "300")],
    );
    b.hello();
    let a_route = route_of(&mut a);
    let hole = silent();
    let start = Instant::now();
    trust(&mut a, &mut b, &[&hole.route, &a_route]);
    let reply = b.call("dial", json!({"identity": a.identity}));
    let took = start.elapsed();
    assert!(took < Duration::from_secs(4), "took {took:?}: {reply}");
    assert!(hole.accepted() > 0);
}

/// Once the pinned host itself refuses this device, no other candidate is
/// tried, and the keeper stops redialling it until something changes.
#[test]
fn the_hosts_own_refusal_stops_the_search() {
    let a_end = Endpoint::init("refa");
    let b_end = Endpoint::init("refb");
    let mut a = a_end.app("hostA", &[("JOIN_PROOF_WAIT_MS", "1000")]);
    a.hello();
    let mut b = b_end.app("peerB", &[("DIAL_PARALLEL", "1")]);
    b.hello();
    let a_route = route_of(&mut a);
    let hole = silent();
    // B knows A, but A holds no grant for B.
    let (identity, name) = (a.identity.clone(), a.name.clone());
    b.call(
        "peer.add",
        json!({"identity": identity, "name": name, "routes": [a_route, hole.route]}),
    );
    let reply = b.request("dial", json!({"identity": a.identity}));
    assert_eq!(reply["error"], "unreachable", "{reply}");
    assert_eq!(reply["why"], "not_authorized", "{reply}");
    let failed = b.event("dial.failed", |m| m["identity"] == identity.as_str());
    assert_eq!(failed["why"], "not_authorized", "{failed}");
    assert!(failed["retry_ms"].is_null(), "not retried: {failed}");
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(hole.accepted(), 0, "no candidate after the refusal");
    assert_eq!(b.events("dial.failed").len(), 1, "parked after the refusal");
}

/// A `dial` that waits its turn behind the keeper's dial to the same host
/// takes that dial's outcome: a host that refuses this device answers once
/// its proof window is over, and the app's dial does not wait out a second
/// window of its own.
#[test]
fn a_dial_waiting_behind_the_keeper_takes_its_refusal() {
    let a_end = Endpoint::init("behinda");
    let b_end = Endpoint::init("behindb");
    let mut a = a_end.app("hostA", &[("JOIN_PROOF_WAIT_MS", "3000")]);
    a.hello();
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    let a_route = route_of(&mut a);
    // B knows A, but A holds no grant for B: the keeper dials at once and A
    // holds that dial for its whole proof window.
    let (identity, name) = (a.identity.clone(), a.name.clone());
    b.call(
        "peer.add",
        json!({"identity": identity, "name": name, "routes": [a_route]}),
    );
    std::thread::sleep(Duration::from_millis(500));
    let start = Instant::now();
    let reply = b.request("dial", json!({"identity": a.identity}));
    let took = start.elapsed();
    assert_eq!(reply["why"], "not_authorized", "{reply}");
    assert!(
        took < Duration::from_millis(4_000),
        "one proof window, not two: took {took:?}"
    );
}

const PUBLIC: [&str; 7] = [
    "tcp://8.8.8.8:7443",
    "tcp://203.0.113.9:7443",
    "tcp://100.64.0.1:7443",
    "tcp://172.32.0.1:7443",
    "tcp://[2001:db8::1]:7443",
    "tcp://[fe80::1]:7443",
    "tcp://mac.local:7443",
];

const PRIVATE: [&str; 5] = [
    "tcp://10.1.2.3:7443",
    "tcp://172.20.0.5:7443",
    "tcp://192.168.1.9:7443",
    "tcp://169.254.9.9:7443",
    "tcp://[fd00::5]:7443",
];

/// `peer.addresses.set` takes the owner's addresses of every kind but none
/// that names a forbidden address (Phase 1b §1.3), and keeps them in
/// `peers.json` across a restart.
#[test]
fn peer_addresses_set_refuses_forbidden_addresses_and_they_persist() {
    let b_end = Endpoint::init("addrb");
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    let host = some_identity();
    b.call(
        "peer.add",
        json!({"identity": host, "name": "far", "routes": []}),
    );
    b.call(
        "peer.addresses.set",
        json!({"identity": host, "routes": PRIVATE}),
    );
    for bad in [
        "tcp://203.0.113.9:7443",
        "tcp://[2001:db8::1]:7443",
        "tcp://[fe80::1]:7443",
        "tcp://0.0.0.0:7443",
    ] {
        let reply = b.request(
            "peer.addresses.set",
            json!({"identity": host, "routes": ["tcp://10.0.0.1:1", bad]}),
        );
        assert_eq!(reply["error"], "forbidden_address", "{bad}: {reply}");
    }
    let unknown = b.request(
        "peer.addresses.set",
        json!({"identity": some_identity(), "routes": PRIVATE}),
    );
    assert_eq!(unknown["error"], "no_peer", "{unknown}");
    assert_eq!(peer_of(&mut b, &host)["addresses"], json!(PRIVATE));
    b.kill();
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    assert_eq!(peer_of(&mut b, &host)["addresses"], json!(PRIVATE));
}

/// The routes a host sends when it pairs back (`peer.add`) are private
/// range only: a list with any other address stores nothing.
#[test]
fn pairback_routes_are_private_range_only() {
    let b_end = Endpoint::init("pbb");
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    let host = some_identity();
    for bad in PUBLIC {
        let reply = b.request(
            "peer.add",
            json!({"identity": host, "name": "far", "routes": [PRIVATE[0], bad]}),
        );
        assert_eq!(reply["error"], "bad_route", "{bad}: {reply}");
    }
    assert!(peer_of(&mut b, &host).is_null(), "nothing stored");
    b.call(
        "peer.add",
        json!({"identity": host, "name": "far", "routes": PRIVATE}),
    );
    assert_eq!(peer_of(&mut b, &host)["routes"], json!(PRIVATE));
}

/// A ticket's hints outside private ranges are never dialled.
#[test]
fn ticket_hints_outside_private_ranges_are_not_dialled() {
    let a_end = Endpoint::init("tha");
    let b_end = Endpoint::init("thb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut b = b_end.app("peerB", &[("CONNECT_TIMEOUT_MS", "300")]);
    b.hello();
    let invite = a.call("invite.create", json!({}));
    let mut ticket = Ticket::from_fragment(invite["uri"].as_str().unwrap()).unwrap();
    ticket.routes = vec![
        "tcp://203.0.113.7:7443".into(),
        "tcp://198.51.100.7:7443".into(),
        "tcp://100.64.0.7:7443".into(),
    ];
    let reply = b.request(
        "join",
        json!({"ticket": ticket.to_fragment(), "pinned": true}),
    );
    assert_eq!(reply["error"], "no_route", "{reply}");
    assert!(
        b.events("join.progress").is_empty(),
        "{:?}",
        b.events("join.progress")
    );
}

/// The keeper holds a path to every paired host: it dials once the app
/// says hello, from the candidates stored in `peers.json`, also after a
/// restart, with no `dial` from the app.
#[test]
fn a_path_to_each_paired_host_is_kept_from_the_stored_candidates() {
    let a_end = Endpoint::init("kca");
    let b_end = Endpoint::init("kcb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    let a_route = route_of(&mut a);
    trust(&mut a, &mut b, &[]);
    b.call(
        "peer.addresses.set",
        json!({"identity": a.identity, "routes": [a_route]}),
    );
    wait_outbound(&b, &a.identity, 0);
    let stored = peer_of(&mut b, &a.identity);
    assert_eq!(stored["addresses"], json!([a_route]));
    assert_eq!(stored["last_route"], a_route.as_str());
    b.kill();
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    wait_outbound(&b, &a.identity, 0);
    assert_eq!(peer_of(&mut b, &a.identity)["addresses"], json!([a_route]));
}

/// The app's `hello` is already waiting on stdin when the helper starts,
/// so the channel can handle it before the keeper task first runs. The
/// start signal is queued for the keeper, never dropped: every start dials
/// the paired host (mousse-net#20).
#[test]
fn a_hello_waiting_at_start_always_starts_the_keeper() {
    const STARTS: usize = 10;
    let a_end = Endpoint::init("ksa");
    let b_end = Endpoint::init("ksb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    let a_route = route_of(&mut a);
    trust(&mut a, &mut b, &[]);
    b.call(
        "peer.addresses.set",
        json!({"identity": a.identity, "routes": [a_route]}),
    );
    wait_outbound(&b, &a.identity, 0);
    for _ in 0..STARTS {
        b.kill();
        // `hello` is written as soon as the process exists, before its
        // runtime has started any task.
        b = b_end.app("peerB", &[]);
        b.hello();
        wait_outbound(&b, &a.identity, 0);
    }
}

/// A host that went away is tried again after waits that double up to the
/// longest, and the path comes back on its own when the host does.
#[test]
fn a_host_that_is_down_is_retried_with_doubling_waits() {
    let a_end = Endpoint::init("bka");
    let b_end = Endpoint::init("bkb");
    let mut a = a_end.app("hostA", &[]);
    let port = a.hello()["port"].as_u64().unwrap() as u16;
    let mut b = b_end.app(
        "peerB",
        &[("KEEP_RETRY_FIRST_MS", "100"), ("KEEP_RETRY_MAX_MS", "400")],
    );
    b.hello();
    let a_route = route_of(&mut a);
    trust(&mut a, &mut b, &[&a_route]);
    wait_outbound(&b, &a.identity, 0);
    let seen = outbound_ups(&b, &a.identity);
    a.kill();
    let waits = b.wait("four failed redials", WAIT, |st| {
        let waits: Vec<Value> = st
            .messages
            .iter()
            .filter(|m| m["ev"] == "dial.failed")
            .map(|m| m["retry_ms"].clone())
            .collect();
        (waits.len() >= 4).then_some(waits)
    });
    assert_eq!(waits[..4], [json!(100), json!(200), json!(400), json!(400)]);
    let mut a = a_end.app_with("hostA", &[], port, None);
    a.hello();
    wait_outbound(&b, &a.identity, seen);
}

/// A host that moved (a new port here; a new address on a LAN) is found
/// through the browse source once its stored candidates fail. Another
/// endpoint the browse also finds is skipped, and the new address becomes
/// the last working route.
#[test]
fn a_host_that_moved_is_found_through_the_browse_source() {
    let a_end = Endpoint::init("mva");
    let s_end = Endpoint::init("mvs");
    let b_end = Endpoint::init("mvb");
    let browse = b_end.dir.join("browse-hosts.txt");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut s = s_end.app("other", &[]);
    s.hello();
    let mut b = b_end.app_with(
        "peerB",
        &[
            ("KEEP_RETRY_FIRST_MS", "100"),
            ("KEEP_RETRY_MAX_MS", "500"),
            ("BROWSE_CACHE_MS", "0"),
        ],
        0,
        Some(&browse),
    );
    b.hello();
    let a_route = route_of(&mut a);
    trust(&mut a, &mut b, &[&a_route]);
    wait_outbound(&b, &a.identity, 0);
    let seen = outbound_ups(&b, &a.identity);
    a.kill();
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let moved = route_of(&mut a);
    assert_ne!(moved, a_route);
    let s_route = route_of(&mut s);
    std::fs::write(
        &browse,
        format!(
            "{}\n{}\n",
            s_route.trim_start_matches("tcp://"),
            moved.trim_start_matches("tcp://")
        ),
    )
    .unwrap();
    wait_outbound(&b, &a.identity, seen);
    assert_eq!(peer_of(&mut b, &a.identity)["last_route"], moved.as_str());
    assert!(s.events("conn.up").is_empty());
}

// ---------------------------------------------------------------------
// Moving to the LAN (Phase 1b §1.4). A host is reached two ways through
// loopback forwarders: one whose port `MOUSSE_NET_TEST_CLASS_MAP` labels
// `tailnet`, one left `lan`. The LAN one appears through the browse file.
// ---------------------------------------------------------------------

/// A loopback forwarder to a helper that can cut every connection and
/// refuse new ones, then take them again; each connection may wait
/// `delay` first.
struct Fwd {
    route: String,
    port: u16,
    up: Arc<std::sync::atomic::AtomicBool>,
    held: Arc<Mutex<Vec<std::net::TcpStream>>>,
    accepted: Arc<AtomicUsize>,
}

fn forwarder(target: &str, delay: Duration) -> Fwd {
    use std::net::TcpStream;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let target = target.trim_start_matches("tcp://").to_owned();
    let up = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let held: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
    let accepted = Arc::new(AtomicUsize::new(0));
    let (is_up, keep, count) = (up.clone(), held.clone(), accepted.clone());
    std::thread::spawn(move || {
        for inbound in listener.incoming().flatten() {
            if !is_up.load(Ordering::SeqCst) {
                drop(inbound);
                continue;
            }
            count.fetch_add(1, Ordering::SeqCst);
            let (target, keep) = (target.clone(), keep.clone());
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                let Ok(outbound) = TcpStream::connect(&target) else {
                    return;
                };
                {
                    let mut keep = keep.lock().unwrap();
                    keep.push(inbound.try_clone().unwrap());
                    keep.push(outbound.try_clone().unwrap());
                }
                let (mut in_r, mut out_w) =
                    (inbound.try_clone().unwrap(), outbound.try_clone().unwrap());
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut in_r, &mut out_w);
                    let _ = out_w.shutdown(std::net::Shutdown::Both);
                });
                let (mut out_r, mut in_w) = (outbound, inbound);
                let _ = std::io::copy(&mut out_r, &mut in_w);
                let _ = in_w.shutdown(std::net::Shutdown::Both);
            });
        }
    });
    Fwd {
        route: format!("tcp://{addr}"),
        port: addr.port(),
        up,
        held,
        accepted,
    }
}

impl Fwd {
    /// Cut every connection through it and refuse new ones.
    fn cut(&self) {
        self.up.store(false, Ordering::SeqCst);
        for stream in self.held.lock().unwrap().drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    fn restore(&self) {
        self.up.store(true, Ordering::SeqCst);
    }

    /// Cut every connection through it but keep taking new ones: a LAN
    /// that answers and then drops.
    fn drop_all(&self) {
        for stream in self.held.lock().unwrap().drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// Host A and peer B, B reaching A through `tail` (labelled `tailnet`
/// for B) as the owner's address with an SSH address beside it, no LAN
/// address stored and an empty browse file: the reported case of a
/// one-way pairing made over Tailscale with SSH added later. Returns B's
/// browse file and its first path, on the tailnet.
struct OffLan {
    a: App,
    b: App,
    tail: Fwd,
    browse: std::path::PathBuf,
    first: u64,
    /// The file B holds at its test hook point, if one was given.
    hold: Option<std::path::PathBuf>,
    _ends: (Endpoint, Endpoint),
}

fn off_lan(tag: &str, b_env: &[(&str, &str)]) -> OffLan {
    off_lan_with(tag, b_env, None)
}

/// [`off_lan`], B holding at the test hook point `hold` (see
/// `MOUSSE_HELPER_TEST_HOLD`).
fn off_lan_with(tag: &str, b_env: &[(&str, &str)], hold: Option<&str>) -> OffLan {
    let a_end = Endpoint::init(&format!("{tag}a"));
    let b_end = Endpoint::init(&format!("{tag}b"));
    let browse = b_end.dir.join("browse-hosts.txt");
    std::fs::write(&browse, "").unwrap();
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let a_route = route_of(&mut a);
    let tail = forwarder(&a_route, Duration::ZERO);
    let map = format!("{}=tailnet", tail.port);
    let mut env: Vec<(&str, &str)> = vec![
        ("TEST_CLASS_MAP", &map),
        ("KEEP_RETRY_FIRST_MS", "100"),
        ("KEEP_RETRY_MAX_MS", "400"),
        ("BROWSE_CACHE_MS", "0"),
        ("LAN_PROBE_FIRST_MS", "200"),
        ("LAN_PROBE_MAX_MS", "400"),
    ];
    env.extend_from_slice(b_env);
    let hold_file = hold.map(|_| b_end.dir.join("held"));
    let hold_var = hold
        .zip(hold_file.as_ref())
        .map(|(point, file)| format!("{point}={}", file.display()));
    let mut raw: Vec<(&str, &Path)> = vec![("MOUSSE_HELPER_BROWSE_FILE", browse.as_path())];
    if let Some(var) = &hold_var {
        raw.push(("MOUSSE_HELPER_TEST_HOLD", Path::new(var)));
    }
    let mut b = b_end.app_raw("peerB", &env, 0, &raw);
    b.hello();
    trust(&mut a, &mut b, &[]);
    b.call(
        "peer.addresses.set",
        json!({"identity": a.identity, "routes": [tail.route, "ssh://me@box"]}),
    );
    let a_id = a.identity.clone();
    let up = b.event("conn.up", |m| {
        m["dir"] == "out" && m["identity"] == a_id.as_str()
    });
    assert_eq!(up["route"]["class"], "tailnet", "{up}");
    OffLan {
        first: up["conn"].as_u64().unwrap(),
        a,
        b,
        tail,
        browse,
        hold: hold_file,
        _ends: (a_end, b_end),
    }
}

fn list_browse(fx: &OffLan, routes: &[&str]) {
    let text: String = routes
        .iter()
        .map(|r| format!("{}\n", r.trim_start_matches("tcp://")))
        .collect();
    std::fs::write(&fx.browse, text).unwrap();
}

fn downs(app: &App, conn: u64) -> Vec<Value> {
    app.events("conn.down")
        .into_iter()
        .filter(|m| m["conn"] == conn)
        .collect()
}

/// The reported sequence. Reached over the tailnet with no LAN address
/// known, the host stays there; once the browse finds it on the LAN, the
/// LAN path is announced (`path.reopen` from the tailnet path) while the
/// tailnet path stays up, and takes over when the app has reopened. When
/// the LAN goes, the keeper dials the tailnet again; a LAN path that
/// lasted so short a time holds off the next probe for the cooldown.
#[test]
fn a_host_reached_over_the_tailnet_moves_to_the_lan_and_back() {
    let mut fx = off_lan("lnm", &[("LAN_FLAP_COOLDOWN_MS", "3000")]);
    let a_id = fx.a.identity.clone();
    // No LAN known: it stays on the tailnet, SSH beside it or not.
    std::thread::sleep(Duration::from_millis(1_000));
    assert!(fx.b.events("path.reopen").is_empty());
    let lan = forwarder(&route_of(&mut fx.a), Duration::ZERO);
    list_browse(&fx, &[&lan.route]);
    let first = fx.first;
    let reopen = fx.b.event("path.reopen", |m| m["from"] == first);
    let moved = reopen["conn"].as_u64().unwrap();
    let up = fx.b.event("conn.up", |m| m["conn"] == moved);
    assert_eq!(up["route"]["class"], "lan", "{up}");
    // The tailnet path stays until the app has moved.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        downs(&fx.b, first).is_empty(),
        "closed before path.reopened"
    );
    fx.b.call("path.reopened", json!({"conn": moved}));
    let down = fx.b.event("conn.down", |m| m["conn"] == first);
    assert_eq!(down["reason"], "path_replaced", "{down}");
    assert_eq!(peer_of(&mut fx.b, &a_id)["last_route"], lan.route.as_str());
    // The LAN goes: back on the tailnet.
    let seen = outbound_ups(&fx.b, &a_id);
    lan.cut();
    fx.b.event("conn.down", |m| m["conn"] == moved);
    let lost = Instant::now();
    wait_outbound(&fx.b, &a_id, seen);
    let back = fx.b.events("conn.up").last().cloned().unwrap();
    assert_eq!(back["route"]["class"], "tailnet", "{back}");
    // The LAN comes back at once, but the flap holds the probe off.
    lan.restore();
    let again = fx.b.event("path.reopen", |m| m["from"] == back["conn"]);
    assert!(
        lost.elapsed() >= Duration::from_millis(2_500),
        "probed again {:?} after a flap: {again}",
        lost.elapsed()
    );
}

/// A LAN that still answers but dropped a short-lived path is not
/// redialled first: while the flap cools down, the keeper's redial goes to
/// the tailnet ahead of the LAN, so it does not land on the same unstable
/// path again.
#[test]
fn a_lan_that_answers_but_keeps_dropping_is_redialled_after_the_tailnet() {
    let mut fx = off_lan("lnd", &[("LAN_FLAP_COOLDOWN_MS", "60000")]);
    let a_id = fx.a.identity.clone();
    let lan = forwarder(&route_of(&mut fx.a), Duration::ZERO);
    list_browse(&fx, &[&lan.route]);
    let first = fx.first;
    let reopen = fx.b.event("path.reopen", |m| m["from"] == first);
    let moved = reopen["conn"].as_u64().unwrap();
    fx.b.call("path.reopened", json!({"conn": moved}));
    fx.b.event("conn.down", |m| m["conn"] == first);
    // The LAN drops the path but still answers: the redial takes the
    // tailnet. Then the tailnet drops too: still cooling, the redial takes
    // the tailnet again rather than the LAN.
    let mut live = moved;
    for (round, path) in [&lan, &fx.tail].into_iter().enumerate() {
        let seen = outbound_ups(&fx.b, &a_id);
        path.drop_all();
        fx.b.event("conn.down", |m| m["conn"] == live);
        wait_outbound(&fx.b, &a_id, seen);
        let back = fx.b.events("conn.up").last().cloned().unwrap();
        assert_eq!(back["route"]["class"], "tailnet", "round {round}: {back}");
        live = back["conn"].as_u64().unwrap();
    }
}

/// What the browse finds that is not this host on the LAN never touches
/// the live path: another endpoint on a LAN address fails its pin, and a
/// host the browse lists at a tailnet address is never dialled (the
/// browse counts under the automatic rule only).
#[test]
fn a_wrong_pin_or_a_browse_result_off_the_lan_leaves_the_live_path() {
    let s_end = Endpoint::init("lnws");
    let mut s = s_end.app("other", &[]);
    s.hello();
    let s_route = route_of(&mut s);
    let fx = off_lan("lnw", &[]);
    // The tailnet forwarder's port is labelled `tailnet` for B.
    list_browse(&fx, &[&s_route, &fx.tail.route]);
    let taken = fx.tail.accepted();
    std::thread::sleep(Duration::from_millis(2_500));
    assert!(fx.b.events("path.reopen").is_empty());
    assert!(downs(&fx.b, fx.first).is_empty());
    assert!(s.events("conn.up").is_empty());
    assert_eq!(
        fx.tail.accepted(),
        taken,
        "a browse result off the LAN was dialled"
    );
}

/// Something that changes while a LAN probe is opening its path: the path
/// is closed, never announced, and the live one is kept (`peer.forget`
/// ends it as always).
#[test]
fn a_change_while_a_lan_probe_opens_leaves_no_lan_path() {
    for change in ["forget", "addresses"] {
        let mut fx = off_lan(&format!("lnc{}", &change[..1]), &[]);
        let gate = gate_to(&route_of(&mut fx.a));
        list_browse(&fx, &[&gate.route]);
        gate.wait_accepted();
        let a_id = fx.a.identity.clone();
        match change {
            "forget" => {
                fx.b.call("peer.forget", json!({"identity": a_id}));
            }
            _ => {
                let tail = fx.tail.route.clone();
                fx.b.call(
                    "peer.addresses.set",
                    json!({"identity": a_id, "routes": [tail]}),
                );
            }
        }
        // Nothing for a later probe to find: a LAN path now can only be
        // the one that was opening.
        list_browse(&fx, &[]);
        gate.open();
        std::thread::sleep(Duration::from_millis(800));
        let lan_ups: Vec<Value> =
            fx.b.events("conn.up")
                .into_iter()
                .filter(|m| m["route"]["class"] == "lan")
                .collect();
        assert!(lan_ups.is_empty(), "{change}: {lan_ups:?}");
        assert!(fx.b.events("path.reopen").is_empty(), "{change}");
    }
}

/// A route edit that lands after a LAN probe's last check, just before its
/// path would be announced: the edit bumps the route generation under the
/// lock the announcement checks it under, so the path is closed, never
/// announced, and the live one is kept.
#[test]
fn a_route_edit_just_before_a_lan_path_is_announced_leaves_no_lan_path() {
    let mut fx = off_lan_with("lnr", &[], Some("lan-publish"));
    let hold = fx.hold.clone().unwrap();
    let lan = forwarder(&route_of(&mut fx.a), Duration::ZERO);
    list_browse(&fx, &[&lan.route]);
    let start = std::time::Instant::now();
    while !hold.exists() {
        assert!(start.elapsed() < WAIT, "the probe never reached the hold");
        std::thread::sleep(Duration::from_millis(20));
    }
    let a_id = fx.a.identity.clone();
    let tail = fx.tail.route.clone();
    fx.b.call(
        "peer.addresses.set",
        json!({"identity": a_id, "routes": [tail]}),
    );
    list_browse(&fx, &[]);
    std::fs::remove_file(&hold).unwrap();
    std::thread::sleep(Duration::from_millis(800));
    let lan_ups: Vec<Value> =
        fx.b.events("conn.up")
            .into_iter()
            .filter(|m| m["route"]["class"] == "lan")
            .collect();
    assert!(lan_ups.is_empty(), "{lan_ups:?}");
    assert!(fx.b.events("path.reopen").is_empty());
    assert!(downs(&fx.b, fx.first).is_empty());
}
