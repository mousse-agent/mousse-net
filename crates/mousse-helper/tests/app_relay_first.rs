//! Relay first, then direct if it is faster: a host with a relay route is
//! dialled through the relay first; its own routes are tried in the
//! background, and a direct path takes over (`path.reopen`) unless the
//! relayed one is quicker by more than `RELAY_SWITCH_MARGIN_MS`. If the
//! direct path drops, the relay carries the host again.
//!
//! Host A is reached directly only through a loopback proxy this file
//! runs, which can add delay or cut every connection. Loopback counts as
//! the LAN in test builds, and a LAN path always takes over; the proxy's
//! port is labelled tailnet (`MOUSSE_NET_TEST_CLASS_MAP`) where the round
//! trip has to decide.
//!
//! A "Send link" pairing that can only go through a relay is reached
//! through it again after a crash at each point after its completion
//! record was saved (pairing-flow design §9, `pairing-relay-completion`):
//! the record holds the relay route, its approval and the sealed tag, and
//! a replay brings back no tag that was retired or expired.

mod common;
#[path = "common/relay.rs"]
mod relay_fixture;
#[path = "common/relay_link.rs"]
mod relay_link;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use relay_fixture::TestRelay as Relay;
use serde_json::{json, Value};

/// Fast re-registration and redials.
const FAST: [(&str, &str); 3] = [
    ("VIA_RELAY_RETRY_FIRST_MS", "100"),
    ("KEEP_RETRY_FIRST_MS", "100"),
    ("KEEP_RETRY_MAX_MS", "500"),
];

/// A loopback proxy to `127.0.0.1:<port>` that delays each chunk by
/// `delay` in both directions, and can cut every connection.
struct Proxy {
    route: String,
    cut: Arc<AtomicBool>,
    socks: Arc<Mutex<Vec<TcpStream>>>,
}

impl Proxy {
    fn to(port: u64, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let route = format!("tcp://{}", listener.local_addr().unwrap());
        let cut = Arc::new(AtomicBool::new(false));
        let socks = Arc::new(Mutex::new(Vec::new()));
        let (gone, kept) = (cut.clone(), socks.clone());
        std::thread::spawn(move || {
            for inbound in listener.incoming().flatten() {
                if gone.load(Ordering::SeqCst) {
                    continue;
                }
                let Ok(outbound) = TcpStream::connect(("127.0.0.1", port as u16)) else {
                    continue;
                };
                let _ = inbound.set_nodelay(true);
                let _ = outbound.set_nodelay(true);
                let mut list = kept.lock().unwrap();
                list.push(inbound.try_clone().unwrap());
                list.push(outbound.try_clone().unwrap());
                drop(list);
                pump(
                    inbound.try_clone().unwrap(),
                    outbound.try_clone().unwrap(),
                    delay,
                );
                pump(outbound, inbound, delay);
            }
        });
        Self { route, cut, socks }
    }

    /// Close every connection, and every later one at once.
    fn cut(&self) {
        self.cut.store(true, Ordering::SeqCst);
        for s in self.socks.lock().unwrap().drain(..) {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

fn pump(mut from: TcpStream, mut to: TcpStream, delay: Duration) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = match from.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            if to.write_all(&buf[..n]).is_err() {
                break;
            }
        }
        let _ = to.shutdown(Shutdown::Write);
    });
}

/// Paired A (host, enrolled on a relay) and B (caller, the relay route
/// approved), with B's only working direct route to A through a proxy
/// with `delay`. B has just started again, so its first dial to A is the
/// one under test.
struct Fx {
    _relay: Relay,
    _a_end: Endpoint,
    _b_end: Endpoint,
    a: App,
    b: App,
    proxy: Proxy,
}

/// `class`: what B counts the proxy's route as, when not the LAN.
fn setup(tag: &str, delay: Duration, class: Option<&str>) -> Fx {
    let relay = Relay::start();
    let a_end = Endpoint::init(&format!("{tag}a"));
    let b_end = Endpoint::init(&format!("{tag}b"));
    let mut a = a_end.app("hostA", &FAST);
    a.hello();
    let enrolled = a.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");
    let mut b = b_end.app("peerB", &FAST);
    b.hello();
    pair_apps(&mut a, &mut b);
    let b_id = b.identity.clone();
    wait_until("A lists B's caller key", || {
        let list = a.call("grants.list", json!({}));
        list["grants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["identity"] == b_id.as_str() && g["relay"] == "listed")
    });
    b.event("peer.manifest", |m| m["identity"] == a.identity.as_str());
    b.call(
        "peer.relay.allow",
        json!({"identity": a.identity, "destination": relay.destination()}),
    );
    // A again, on a new port: the route in B's ticket stops answering, and
    // the proxy is B's only way to A directly.
    a.kill();
    a = a_end.app("hostA", &FAST);
    let port = a.hello()["port"].as_u64().unwrap();
    wait_until("A registered again", || {
        let list = a.call("relay.list", json!({}));
        list["relays"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["state"] == "registered")
    });
    let proxy = Proxy::to(port, delay);
    b.call(
        "peer.addresses.set",
        json!({"identity": a.identity, "routes": [proxy.route]}),
    );
    b.kill();
    let map = class.map(|class| {
        let port = proxy.route.rsplit(':').next().unwrap();
        format!("{port}={class}")
    });
    let mut env = FAST.to_vec();
    if let Some(map) = &map {
        env.push(("TEST_CLASS_MAP", map));
    }
    b = b_end.app("peerB", &env);
    b.hello();
    Fx {
        _relay: relay,
        _a_end: a_end,
        _b_end: b_end,
        a,
        b,
        proxy,
    }
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < WAIT, "never: {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The `n`th (from 0) outbound `conn.up` on `app`.
fn nth_up(app: &App, n: usize) -> Value {
    app.wait(&format!("outbound conn.up #{n}"), WAIT, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == "conn.up" && m["dir"] == "out")
            .nth(n)
            .cloned()
    })
}

/// Send `bytes` from `from` on a new stream on `conn` and read them on `to`.
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

#[test]
fn a_host_with_a_relay_route_is_reached_through_the_relay_first() {
    let fx = setup("rf1", Duration::ZERO, None);
    let first = nth_up(&fx.b, 0);
    assert_eq!(first["route"]["kind"], "relay", "{first}");
}

/// The relayed path keeps carrying streams until the app moves them; once
/// it said `path.reopened`, the relayed path closes with `PATH_REPLACED`
/// and the direct one carries them.
#[test]
fn a_faster_direct_path_takes_over_with_streams_intact() {
    let mut fx = setup("rf2", Duration::ZERO, None);
    let relayed = nth_up(&fx.b, 0);
    assert_eq!(relayed["route"]["kind"], "relay", "{relayed}");
    let relayed = relayed["conn"].as_u64().unwrap();
    let reopen = fx.b.event("path.reopen", |m| m["from"] == relayed);
    let direct = reopen["conn"].as_u64().unwrap();
    let up = fx.b.event("conn.up", |m| m["conn"] == direct);
    assert_eq!(up["route"]["kind"], "tcp", "{up}");
    // Not moved yet: the relayed path still carries a stream.
    carry(&mut fx.b, relayed, &mut fx.a, b"before the move");
    assert!(fx
        .b
        .events("conn.down")
        .iter()
        .all(|m| m["conn"] != relayed));
    fx.b.call("path.reopened", json!({"conn": direct}));
    let down = fx.b.event("conn.down", |m| m["conn"] == relayed);
    assert_eq!(down["reason"], "path_replaced", "{down}");
    carry(&mut fx.b, direct, &mut fx.a, b"after the move");
}

#[test]
fn a_slower_direct_path_does_not_take_over() {
    let mut fx = setup("rf3", Duration::from_millis(100), Some("tailnet"));
    let relayed = nth_up(&fx.b, 0);
    assert_eq!(relayed["route"]["kind"], "relay", "{relayed}");
    let relayed = relayed["conn"].as_u64().unwrap();
    // The direct path is tried and measured, and the relay kept.
    let log = fx.b.dir.join("helper.log");
    wait_until("B measured the direct path", || {
        std::fs::read_to_string(&log).is_ok_and(|t| t.contains("kept the relay"))
    });
    std::thread::sleep(Duration::from_millis(1_000));
    assert!(
        fx.b.events("path.reopen").is_empty(),
        "{:?}",
        fx.b.events("path.reopen")
    );
    let outs: Vec<Value> =
        fx.b.events("conn.up")
            .into_iter()
            .filter(|m| m["dir"] == "out")
            .collect();
    assert_eq!(outs.len(), 1, "{outs:?}");
    carry(&mut fx.b, relayed, &mut fx.a, b"still relayed");
}

/// The LAN wins over a relay whatever the round trips.
#[test]
fn a_slower_lan_path_still_takes_over() {
    let mut fx = setup("rf5", Duration::from_millis(100), None);
    let relayed = nth_up(&fx.b, 0);
    assert_eq!(relayed["route"]["kind"], "relay", "{relayed}");
    let relayed = relayed["conn"].as_u64().unwrap();
    let reopen = fx.b.event("path.reopen", |m| m["from"] == relayed);
    let direct = reopen["conn"].as_u64().unwrap();
    let up = fx.b.event("conn.up", |m| m["conn"] == direct);
    assert_eq!(up["route"]["class"], "lan", "{up}");
    fx.b.call("path.reopened", json!({"conn": direct}));
    let down = fx.b.event("conn.down", |m| m["conn"] == relayed);
    assert_eq!(down["reason"], "path_replaced", "{down}");
    carry(&mut fx.b, direct, &mut fx.a, b"on the LAN");
}

#[test]
fn the_relay_carries_the_host_again_when_the_direct_path_drops() {
    let mut fx = setup("rf4", Duration::ZERO, None);
    let relayed = nth_up(&fx.b, 0)["conn"].as_u64().unwrap();
    let reopen = fx.b.event("path.reopen", |m| m["from"] == relayed);
    let direct = reopen["conn"].as_u64().unwrap();
    fx.b.call("path.reopened", json!({"conn": direct}));
    fx.b.event("conn.down", |m| m["conn"] == relayed);
    fx.proxy.cut();
    fx.b.event("conn.down", |m| m["conn"] == direct);
    let again = nth_up(&fx.b, 2);
    assert_eq!(again["route"]["kind"], "relay", "{again}");
    carry(
        &mut fx.b,
        again["conn"].as_u64().unwrap(),
        &mut fx.a,
        b"relayed again",
    );
}

// ---------------------------------------------------------------------------
// Relay-only link completion recovery

/// The path of A's completion record for `link`.
fn record_path(a_end: &Endpoint, link: &relay_link::Link) -> std::path::PathBuf {
    a_end
        .dir
        .join("joins")
        .join(format!("{}.done", link.hash()))
}

/// A relay-only link join stopped at `point`, after its completion record
/// was saved: after a restart, `join.status` reports it done, A reaches B
/// again through the relay, and B lists A's caller key.
fn a_relay_link_join_stopped_at_comes_back_over_the_relay(tag: &str, point: &str) {
    let mut host = relay_link::RelayHost::start(tag);
    let a_end = Endpoint::init(&format!("{tag}-a"));
    let link = host.join_crashing(&a_end, point);
    let mut a = host.joiner(&a_end, &[], &[]);
    let b_id = host.b.identity.clone();
    let s = relay_link::status(&mut a, &link);
    assert_eq!(s["done"]["identity"], b_id.as_str(), "{s}");
    let up = relay_link::dial_up(&mut a, &b_id);
    assert_eq!(
        up["route"]["kind"], "relay",
        "A came back another way: {up}"
    );
    let a_id = a.identity.clone();
    wait_until("B lists A's caller key", || {
        host.relay_status(&a_id) == "listed"
    });
}

#[test]
fn a_crash_right_after_the_relay_link_record_still_comes_back_over_the_relay() {
    a_relay_link_join_stopped_at_comes_back_over_the_relay("rlc-saved", "link-done-saved");
}

#[test]
fn a_crash_after_the_relay_link_row_still_comes_back_over_the_relay() {
    a_relay_link_join_stopped_at_comes_back_over_the_relay("rlc-row", "link-row-saved");
}

#[test]
fn a_crash_after_the_relay_link_route_still_comes_back_over_the_relay() {
    a_relay_link_join_stopped_at_comes_back_over_the_relay("rlc-route", "link-relay-routes-saved");
}

/// The record keeps the tag sealed for this endpoint: neither the tag nor
/// the ticket's secret or link is in it in the clear, nor in A's log.
#[test]
fn a_relay_link_record_holds_the_tag_only_sealed() {
    let mut host = relay_link::RelayHost::start("rlc-sealed");
    let a_end = Endpoint::init("rlc-sealed-a");
    let link = host.join_crashing(&a_end, "link-done-saved");
    let text = std::fs::read_to_string(record_path(&a_end, &link)).unwrap();
    let record: Value = serde_json::from_str(&text).unwrap();
    assert!(
        record["relay"]["join_tag"].is_string(),
        "no tag kept: {record}"
    );
    let tag = mousse_net_io::store::hex(&link.tag());
    let secret = mousse_net_io::store::hex(link.ticket.secret.expose());
    let fragment = link.uri.rsplit('#').next().unwrap().to_owned();
    for (what, clear) in [
        ("tag", &tag),
        ("ticket secret", &secret),
        ("link", &fragment),
    ] {
        assert!(
            !text.to_lowercase().contains(&clear.to_lowercase()),
            "the record holds the {what} in the clear: {text}"
        );
    }
    let mut a = host.joiner(&a_end, &[], &[]);
    relay_link::status(&mut a, &link);
    assert!(!a_end.log().contains(&tag), "the tag is in A's log");
}

/// A record the app never acknowledged, replayed once the host answered
/// `mousse-keys`, does not bring the retired tag back.
#[test]
fn a_replay_after_the_hosts_keys_arrived_brings_back_no_tag() {
    let mut host = relay_link::RelayHost::start("rlc-keys");
    let a_end = Endpoint::init("rlc-keys-a");
    let mut a = host.joiner(&a_end, &[], &[]);
    let link = host.link();
    let id = host.join(&mut a, &link);
    let reply = a.reply(id);
    assert!(reply.get("error").is_none(), "{reply}");
    let up = a.event("conn.up", |m| m["conn"] == reply["conn"]);
    assert_eq!(up["route"]["kind"], "relay", "{up}");
    let b_id = host.b.identity.clone();
    a.event("peer.keys", |m| m["identity"] == b_id.as_str());
    let entry = relay_link::relay_peer(&a.dir, &b_id);
    assert!(entry["pair_secret"].is_string(), "{entry}");
    assert!(entry["join_tag"].is_null(), "{entry}");
    let s = relay_link::status(&mut a, &link);
    assert_eq!(s["done"]["identity"], b_id.as_str(), "{s}");
    let entry = relay_link::relay_peer(&a.dir, &b_id);
    assert!(
        entry["join_tag"].is_null(),
        "a replay brought back a retired tag: {entry}"
    );
}

/// Past the time the host keeps its recovery entry, a replay still stores
/// the route and its approval, but not the tag.
#[test]
fn a_replay_after_the_tag_expired_keeps_the_route_and_not_the_tag() {
    let rejoin = [("VIA_RELAY_REJOIN_SECS", "600")];
    let mut host = relay_link::RelayHost::start("rlc-expired");
    let a_end = Endpoint::init("rlc-expired-a");
    let link = host.join_crashing_with(&a_end, "link-done-saved", &rejoin);
    let clock = [("MOUSSE_HELPER_MANUAL_CLOCK", std::path::Path::new("1"))];
    let mut a = host.joiner(&a_end, &rejoin, &clock);
    a.call("test.clock", json!({"advance_secs": 601}));
    let b_id = host.b.identity.clone();
    let s = relay_link::status(&mut a, &link);
    assert_eq!(s["done"]["identity"], b_id.as_str(), "{s}");
    let entry = relay_link::relay_peer(&a.dir, &b_id);
    let hint = link
        .ticket
        .routes
        .iter()
        .find(|r| r.starts_with("relay://"))
        .unwrap()
        .clone();
    assert_eq!(entry["ticket_routes"], json!([hint]), "{entry}");
    assert!(
        relay_link::approvals(&a.dir)
            .iter()
            .any(|x| x["identity"] == b_id.as_str() && x["destination"] == host.destination()),
        "the relay was not approved again"
    );
    assert!(
        entry["join_tag"].is_null(),
        "an expired tag came back: {entry}"
    );
}

/// A record written by a helper from before the relay part still replays:
/// the host is stored and reported done, and no tag is made up.
#[test]
fn a_relay_link_record_from_before_still_replays() {
    let mut host = relay_link::RelayHost::start("rlc-old");
    let a_end = Endpoint::init("rlc-old-a");
    let link = host.join_crashing(&a_end, "link-done-saved");
    let path = record_path(&a_end, &link);
    let mut record: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(record["relay"].is_object(), "{record}");
    record.as_object_mut().unwrap().remove("relay");
    std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    let mut a = host.joiner(&a_end, &[], &[]);
    let b_id = host.b.identity.clone();
    let s = relay_link::status(&mut a, &link);
    assert_eq!(s["done"]["identity"], b_id.as_str(), "{s}");
    assert_eq!(peer_of(&mut a, &b_id)["name"], "hostB");
    assert!(relay_link::relay_peer(&a.dir, &b_id)["join_tag"].is_null());
}
