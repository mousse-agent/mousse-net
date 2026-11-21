//! Relay first, then direct if it is faster: a host with a relay route is
//! dialled through the relay first; its own routes are tried in the
//! background, and a direct path takes over (`path.reopen`) unless the
//! relayed one is quicker by more than `RELAY_SWITCH_MARGIN_MS`. If the
//! direct path drops, the relay carries the host again.
//!
//! Host A is reached directly only through a loopback proxy this file
//! runs, which can add delay or cut every connection.

mod common;
#[path = "common/relay.rs"]
mod relay_fixture;

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

fn setup(tag: &str, delay: Duration) -> Fx {
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
    b = b_end.app("peerB", &FAST);
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
    let fx = setup("rf1", Duration::ZERO);
    let first = nth_up(&fx.b, 0);
    assert_eq!(first["route"]["kind"], "relay", "{first}");
}

/// The relayed path keeps carrying streams until the app moves them; once
/// it said `path.reopened`, the relayed path closes with `PATH_REPLACED`
/// and the direct one carries them.
#[test]
fn a_faster_direct_path_takes_over_with_streams_intact() {
    let mut fx = setup("rf2", Duration::ZERO);
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
    let mut fx = setup("rf3", Duration::from_millis(100));
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

#[test]
fn the_relay_carries_the_host_again_when_the_direct_path_drops() {
    let mut fx = setup("rf4", Duration::ZERO);
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
