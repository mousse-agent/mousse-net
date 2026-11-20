//! Phase 4 end to end: a real helper with `MOUSSE_NET_PLUS_URL` on real
//! hosted `mousse-relay`s, with the Plus test stand-ins (test fixtures, on
//! loopback; no real account). The helper reads the fleet, registers its
//! handle with an admission token, presents and prefetches lease blocks as
//! `LEASE_STATUS` says, rotates its handle with an overlap and releases the
//! old one, moves to another relay releasing the old relay's blocks before
//! the new relay is funded, and a caller that was offline through a
//! rotation finds the new route in its directory slot.
//!
//! The check cell `phase4.helper-plus` runs these with the rest of the
//! Plus client's tests (`cargo test -p mousse-helper plus`).

mod common;
#[path = "common/hosted.rs"]
mod hosted;
#[path = "../../mousse-relay-plus/tests/support/test_issuer_standin.rs"]
mod test_issuer_standin;

use std::path::Path;
use std::time::{Duration, Instant};

use common::*;
use hosted::Fleet;
use serde_json::{json, Value};

const FAST: [(&str, &str); 6] = [
    ("VIA_RELAY_RETRY_FIRST_MS", "100"),
    ("VIA_RELAY_CHECK_MS", "100"),
    ("KEEP_RETRY_FIRST_MS", "100"),
    ("KEEP_RETRY_MAX_MS", "500"),
    ("PLUS_RETRY_FIRST_MS", "100"),
    ("PLUS_SLOT_READ_SECS", "10"),
];

const INTERACTIVE: u64 = 0;

fn manual_clock() -> [(&'static str, &'static Path); 1] {
    [("MOUSSE_HELPER_MANUAL_CLOCK", Path::new("1"))]
}

/// A helper on `end` with Plus at `url` (and the manual clock if asked).
fn app(end: &Endpoint, name: &str, url: &str, clock: bool, extra: &[(&str, &str)]) -> App {
    let mut env: Vec<(&str, &str)> = FAST.to_vec();
    env.push(("PLUS_URL", url));
    env.extend_from_slice(extra);
    let raw: &[(&str, &Path)] = if clock { &manual_clock() } else { &[] };
    let mut a = end.app_raw(name, &env, 0, raw);
    a.hello();
    a
}

/// Sign `app` in to Plus: the code is typed on the website (the stand-in
/// approves it).
fn link(app: &mut App, fleet: &Fleet) {
    let started = app.call("plus.link.start", json!({}));
    let code = started["user_code"].as_str().unwrap().to_owned();
    assert!(fleet.plus.approve(&code).is_some());
    app.event("plus.link", |m| m["state"] == "approved");
}

fn wait_listed(host: &mut App, identity: &str) {
    let start = Instant::now();
    loop {
        let list = host.call("grants.list", json!({}));
        if list["grants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["identity"] == identity && g["relay"] == "listed")
        {
            return;
        }
        assert!(start.elapsed() < WAIT, "{identity} never listed");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn sequence(app: &mut App, host: &str) -> u64 {
    peer_of(app, host)["relay"]["manifest"]["sequence"]
        .as_u64()
        .unwrap_or(0)
}

fn wait_sequence_above(app: &mut App, host: &str, above: u64) -> u64 {
    let start = Instant::now();
    loop {
        let now = sequence(app, host);
        if now > above {
            return now;
        }
        assert!(start.elapsed() < WAIT, "no manifest above {above}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Pair `peer` with `host`, wait for its caller key and the host's
/// manifest, and approve the destinations given.
fn pair_and_allow(host: &mut App, peer: &mut App, destinations: &[String]) -> u64 {
    pair_apps(host, peer);
    wait_listed(host, &peer.identity.clone());
    let h = host.identity.clone();
    let seq = wait_sequence_above(peer, &h, 0);
    for d in destinations {
        peer.call("peer.relay.allow", json!({"identity": h, "destination": d}));
    }
    seq
}

fn dial_up(from: &mut App, to: &str) -> Value {
    let start = Instant::now();
    loop {
        let reply = from.request("dial", json!({"identity": to}));
        if let Some(conn) = reply["conn"].as_u64() {
            return from.event("conn.up", |m| m["conn"] == conn);
        }
        assert!(start.elapsed() < WAIT * 2, "dial never worked: {reply}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Send `bytes` on a new stream from `from` and read them on `to`.
fn carry(from: &mut App, conn: u64, to: &mut App, bytes: &[u8]) {
    let before = to.events("stream.incoming").len();
    let handle = from.open(conn, "mousse.rpc", "interactive");
    from.send(handle, bytes, true);
    let incoming = to.wait("the incoming stream", WAIT, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == "stream.incoming")
            .nth(before)
            .cloned()
    });
    let h = incoming["handle"].as_u64().unwrap() as u32;
    to.accept(h);
    to.credit(h, 1 << 20);
    assert_eq!(to.until_fin(h, WAIT), bytes);
}

/// A linked host funded on relay 0, and a caller paired with it that
/// approved `destinations`.
fn funded_pair(
    fleet: &Fleet,
    tag: &str,
    clock: bool,
    extra: &[(&str, &str)],
    destinations: &[String],
) -> (Endpoint, App, Endpoint, App, u64) {
    let a_end = Endpoint::init(&format!("{tag}a"));
    let b_end = Endpoint::init(&format!("{tag}b"));
    let url = fleet.plus.url();
    let mut a = app(&a_end, "hostA", &url, clock, extra);
    link(&mut a, fleet);
    // Registered with an admission token, and funded: a block of each
    // class asked for on the relay's boot.
    fleet.until("a handle admitted on relay 0", |f| {
        f.handles_on(0).len() == 1
    });
    fleet.until("blocks of both classes", |f| {
        let l = f.leases_on(0);
        l.iter().any(|x| x.2 == 0) && l.iter().any(|x| x.2 == 1)
    });
    let mut b = app(&b_end, "peerB", &url, false, &[]);
    let seq = pair_and_allow(&mut a, &mut b, destinations);
    (a_end, a, b_end, b, seq)
}

#[test]
fn plus_hosted_relay_calls_go_through_funded_and_prefetched_leases() {
    let fleet = Fleet::start(1);
    fleet.plus.set_block_bytes(65_536);
    let (a_end, mut a, _b_end, mut b, _) =
        funded_pair(&fleet, "hfa", false, &[], &[fleet.destination(0)]);
    let host = a.identity.clone();
    // A moves to a port B does not know: only the hosted relay reaches it.
    a.kill();
    let mut a = app(&a_end, "hostA", &fleet.plus.url(), false, &[]);
    let up = dial_up(&mut b, &host);
    assert_eq!(up["route"]["kind"], "relay", "{up}");
    // A relay forwards only on a presented, usable block (§B.10): the
    // call itself shows the blocks reached the relay. The relay still
    // holds A's block from before the restart, and A presented a second
    // one (current and pending); once the first is spent and the second
    // passes the threshold of its 64 KiB, LEASE_STATUS brings a third.
    let interactive_before = fleet
        .leases_on(0)
        .iter()
        .filter(|l| l.2 == INTERACTIVE)
        .count();
    carry(
        &mut b,
        up["conn"].as_u64().unwrap(),
        &mut a,
        &pattern(112 * 1024, 7),
    );
    fleet.until("the next interactive block, prefetched", |f| {
        f.leases_on(0).iter().filter(|l| l.2 == INTERACTIVE).count() > interactive_before
    });
}

#[test]
fn plus_hosted_handles_rotate_with_an_overlap_and_the_old_handle_releases_its_blocks() {
    let fleet = Fleet::start(1);
    let overlap = [
        ("HANDLE_ROTATE_SECS", "172800"),
        ("MANIFEST_OVERLAP_SECS", "86400"),
    ];
    let (_a_end, mut a, _b_end, mut b, seq) =
        funded_pair(&fleet, "hro", true, &overlap, &[fleet.destination(0)]);
    let host = a.identity.clone();
    let old = fleet.handles_on(0)[0];
    a.call("test.clock", json!({"advance_secs": 172_800}));
    // A new handle with its own token; new blocks go only to it.
    fleet.until("a second handle admitted", |f| f.handles_on(0).len() == 2);
    let new = *fleet.handles_on(0).iter().find(|h| **h != old).unwrap();
    fleet.until("blocks for the new handle", |f| {
        f.leases_on(0).iter().any(|l| l.1 == new)
    });
    // Both routes in a new manifest, sent at once to the online caller.
    let both = wait_sequence_above(&mut b, &host, seq);
    // The old handle kept its blocks through the overlap...
    assert!(fleet.leases_on(0).iter().any(|l| l.1 == old && !l.3));
    // ...and at its end releases them and leaves the manifest.
    a.call("test.clock", json!({"advance_secs": 86_400}));
    fleet.until("the old handle's blocks final", |f| {
        f.leases_on(0).iter().filter(|l| l.1 == old).all(|l| l.3)
    });
    wait_sequence_above(&mut b, &host, both);
    assert!(fleet.leases_on(0).iter().any(|l| l.1 == new && !l.3));
}

#[test]
fn plus_hosted_a_move_releases_the_old_relay_before_the_new_one_is_funded() {
    let fleet = Fleet::start(2);
    let stage = [("VIA_RELAY_MOVE_STAGE_SECS", "0")];
    let (a_end, mut a, _b_end, mut b, seq) = funded_pair(
        &fleet,
        "hmv",
        true,
        &stage,
        &[fleet.destination(0), fleet.destination(1)],
    );
    let host = a.identity.clone();
    // Plus lists only relay 1 now; A reads the fleet again within the hour.
    fleet.list(&[1]);
    a.call("test.clock", json!({"advance_secs": 3_600}));
    fleet.until("a handle admitted on relay 1", |f| {
        f.handles_on(1).len() == 1
    });
    // The cutover: relay 0's blocks are released (final at the relay, then
    // at Plus), and only then does relay 1 get blocks.
    fleet.until("relay 0's blocks final", |f| {
        f.leases_on(0).iter().all(|l| l.3)
    });
    fleet.until("blocks on relay 1", |f| !f.leases_on(1).is_empty());
    let first_new = fleet.leases_on(1).len();
    assert!(first_new >= 1);
    // The old route left the manifest; the caller reaches A through relay 1.
    wait_sequence_above(&mut b, &host, seq);
    a.kill();
    let mut _a = app(&a_end, "hostA", &fleet.plus.url(), true, &stage);
    let up = dial_up(&mut b, &host);
    assert_eq!(up["route"]["kind"], "relay", "{up}");
    assert_eq!(
        up["route"]["destination"].as_str().unwrap_or_default(),
        fleet.destination(1),
        "{up}"
    );
}

#[test]
fn mailbox_an_offline_caller_finds_the_rotated_route_in_its_directory_slot() {
    let fleet = Fleet::start(1);
    let overlap = [
        ("HANDLE_ROTATE_SECS", "172800"),
        ("MANIFEST_OVERLAP_SECS", "86400"),
    ];
    let (a_end, mut a, b_end, mut b, seq) =
        funded_pair(&fleet, "hsl", true, &overlap, &[fleet.destination(0)]);
    let host = a.identity.clone();
    // B is offline through the rotation and the whole overlap: its
    // manifest names only the old handle.
    b.kill();
    let first = fleet.handles_on(0)[0];
    a.call("test.clock", json!({"advance_secs": 172_800}));
    fleet.until("a second handle admitted", |f| f.handles_on(0).len() == 2);
    a.call("test.clock", json!({"advance_secs": 86_400}));
    fleet.until("the old handle released", |f| {
        f.leases_on(0).iter().filter(|l| l.1 == first).all(|l| l.3)
    });
    // A on a port B does not know: the old route answers UNREACHABLE, no
    // other route works, and B reads its slot.
    std::thread::sleep(Duration::from_millis(500));
    a.kill();
    let mut _a = app(&a_end, "hostA", &fleet.plus.url(), true, &overlap);
    let mut b = app(&b_end, "peerB", &fleet.plus.url(), false, &[]);
    assert_eq!(sequence(&mut b, &host), seq, "B kept the old manifest");
    let up = dial_up(&mut b, &host);
    assert_eq!(up["route"]["kind"], "relay", "{up}");
    assert!(
        sequence(&mut b, &host) > seq,
        "the slot's manifest was kept"
    );
}
