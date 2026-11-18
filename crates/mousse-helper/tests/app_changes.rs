//! E5b: renewals and network changes (Phase 1a §2, §6 and §8).
//!
//! - A path nearing its deadline is renewed: the new path is announced
//!   with `path.reopen`, and the old one closes with `PATH_REPLACED` only
//!   once the app said `path.reopened`.
//! - After a wake (a jump of the monotonic clock) a path that no longer
//!   answers is closed and the host redialled at once; after an interface
//!   change, a host that was down is redialled at once, not after its
//!   backoff.
//!
//! The helpers run on manual clocks (`MOUSSE_HELPER_MANUAL_CLOCK`, moved by
//! `test.clock`) and read their interface list from a file
//! (`MOUSSE_HELPER_INTERFACES_FILE`); both hooks exist in debug builds
//! only. Everything stays on loopback.

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use mousse_net_core::Limits as CoreLimits;
use serde_json::{json, Value};

const MANUAL_CLOCK: (&str, &str) = ("MOUSSE_HELPER_MANUAL_CLOCK", "1");

/// Pass bytes both ways.
const PASS: u8 = 0;
/// Connections already relayed pass; new ones are taken and never answered.
const HOLD_NEW: u8 = 1;
/// Nothing passes, and nothing closes: a path that died without a word,
/// as after a sleep or a lost network.
const FREEZE: u8 = 2;

/// A TCP relay on loopback to a helper.
struct Relay {
    route: String,
    mode: Arc<AtomicU8>,
}

impl Relay {
    fn to(target: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let route = format!("tcp://{}", listener.local_addr().unwrap());
        let target: SocketAddr = target.trim_start_matches("tcp://").parse().unwrap();
        let mode = Arc::new(AtomicU8::new(PASS));
        let accept_mode = mode.clone();
        let held = Arc::new(Mutex::new(Vec::new()));
        std::thread::spawn(move || {
            for inbound in listener.incoming().flatten() {
                if accept_mode.load(Ordering::SeqCst) != PASS {
                    held.lock().unwrap().push(inbound);
                    continue;
                }
                let Ok(outbound) = TcpStream::connect(target) else {
                    continue;
                };
                let pairs = [
                    (inbound.try_clone().unwrap(), outbound.try_clone().unwrap()),
                    (outbound, inbound),
                ];
                for (from, to) in pairs {
                    let mode = accept_mode.clone();
                    std::thread::spawn(move || pump(from, to, mode));
                }
            }
        });
        Self { route, mode }
    }

    fn set(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }
}

fn pump(mut from: TcpStream, mut to: TcpStream, mode: Arc<AtomicU8>) {
    from.set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let mut buf = [0u8; 16 * 1024];
    loop {
        if mode.load(Ordering::SeqCst) == FREEZE {
            std::thread::sleep(Duration::from_millis(20));
            continue;
        }
        match from.read(&mut buf) {
            Ok(0) => {
                let _ = to.shutdown(Shutdown::Write);
                return;
            }
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => return,
        }
    }
}

/// Start `serve --app` with test hooks set.
fn app(end: &Endpoint, name: &str, env: &[(&str, &str)], hooks: &[(&str, &str)]) -> App {
    let hooks: Vec<(&str, &Path)> = hooks.iter().map(|(k, v)| (*k, Path::new(v))).collect();
    end.app_raw(name, env, 0, &hooks)
}

/// The `n`th (from 0) `conn.up` `dir` for `identity`.
fn nth_up(app: &App, dir: &str, identity: &str, n: usize, limit: Duration) -> Value {
    app.wait(&format!("conn.up {n} ({dir})"), limit, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == "conn.up" && m["dir"] == dir && m["identity"] == identity)
            .nth(n)
            .cloned()
    })
}

/// Move both helpers' wall clocks to the moment `deadline`'s path is due
/// for renewal.
fn to_renewal(a: &mut App, b: &mut App, deadline: i64) {
    let now = b.call("test.clock", json!({}))["now"].as_i64().unwrap();
    let due = deadline
        - CoreLimits::DEFAULT.clock_skew_secs() as i64
        - CoreLimits::DEFAULT.renew_lead_secs() as i64;
    for app in [a, b] {
        app.call("test.clock", json!({"advance_secs": due - now}));
    }
}

/// A path due for renewal is renewed while the old one keeps working; the
/// old one closes with `PATH_REPLACED` only after `path.reopened`.
#[test]
fn a_renewed_path_replaces_the_old_one_once_reopened() {
    let a_end = Endpoint::init("rna");
    let b_end = Endpoint::init("rnb");
    let mut a = app(&a_end, "hostA", &[], &[MANUAL_CLOCK]);
    a.hello();
    let mut b = app(&b_end, "peerB", &[], &[MANUAL_CLOCK]);
    b.hello();
    let a_route = route_of(&mut a);
    trust(&mut a, &mut b, &[&a_route]);
    let up = nth_up(&b, "out", &a.identity, 0, WAIT);
    let old = up["conn"].as_u64().unwrap();
    let deadline = up["deadline"].as_i64().unwrap();
    let a_old = nth_up(&a, "in", &b.identity, 0, WAIT)["conn"]
        .as_u64()
        .unwrap();

    to_renewal(&mut a, &mut b, deadline);
    let reopen = b.event("path.reopen", |m| m["identity"] == a.identity.as_str());
    assert_eq!(reopen["from"], old, "{reopen}");
    let new = reopen["conn"].as_u64().unwrap();
    // Announced before path.reopen, with a later deadline.
    let up = nth_up(&b, "out", &a.identity, 1, WAIT);
    assert_eq!(up["conn"], new);
    assert!(up["deadline"].as_i64().unwrap() > deadline, "{up}");
    let a_new = nth_up(&a, "in", &b.identity, 1, WAIT)["conn"]
        .as_u64()
        .unwrap();

    // Not current yet: both paths carry streams.
    for (b_conn, a_conn, text) in [
        (old, a_old, &b"on the old path"[..]),
        (new, a_new, &b"on the new path"[..]),
    ] {
        let handle = b.open(b_conn, "mousse.rpc", "interactive");
        b.send(handle, text, true);
        let theirs = a.incoming(a_conn, 0);
        a.accept(theirs);
        a.credit(theirs, 1 << 20);
        assert_eq!(a.until_fin(theirs, WAIT), text);
    }
    assert!(
        b.events("conn.down").is_empty(),
        "{:?}",
        b.events("conn.down")
    );

    let unknown = b.request("path.reopened", json!({"conn": 999}));
    assert_eq!(unknown["error"], "no_conn", "{unknown}");
    b.call("path.reopened", json!({"conn": new}));
    let down = b.event("conn.down", |m| m["conn"] == old);
    assert_eq!(down["reason"], "path_replaced", "{down}");
    // Current now: nothing left to reopen.
    let again = b.request("path.reopened", json!({"conn": new}));
    assert_eq!(again["error"], "not_renewed", "{again}");
    assert!(b.events("conn.down").iter().all(|m| m["conn"] != new));
}

/// A renewal that cannot reach the host is reported, and the old path
/// stays.
#[test]
fn a_renewal_that_fails_is_reported_and_the_old_path_stays() {
    let a_end = Endpoint::init("rfa");
    let b_end = Endpoint::init("rfb");
    let mut a = app(&a_end, "hostA", &[], &[MANUAL_CLOCK]);
    a.hello();
    let mut b = app(
        &b_end,
        "peerB",
        &[("DIAL_TIMEOUT_MS", "300")],
        &[MANUAL_CLOCK],
    );
    b.hello();
    let relay = Relay::to(&route_of(&mut a));
    trust(&mut a, &mut b, &[&relay.route]);
    let up = nth_up(&b, "out", &a.identity, 0, WAIT);
    let old = up["conn"].as_u64().unwrap();

    relay.set(HOLD_NEW);
    to_renewal(&mut a, &mut b, up["deadline"].as_i64().unwrap());
    let failed = b.event("path.renew_failed", |m| {
        m["identity"] == a.identity.as_str()
    });
    assert!(
        failed["why"].as_str().is_some_and(|w| !w.is_empty()),
        "{failed}"
    );
    assert!(b.events("path.reopen").is_empty());
    assert!(b.events("conn.down").iter().all(|m| m["conn"] != old));
    let handle = b.open(old, "mousse.rpc", "interactive");
    assert!(handle > 0);
}

/// After a wake, a path that no longer answers is closed within the ping
/// wait and the host is dialled again at once, at an address that works.
#[test]
fn after_a_wake_a_dead_path_is_closed_and_the_host_redialled_at_once() {
    let a_end = Endpoint::init("wka");
    let b_end = Endpoint::init("wkb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut b = app(
        &b_end,
        "peerB",
        &[
            ("IFACE_POLL_MS", "100"),
            ("WAKE_PING_MS", "500"),
            ("DIAL_TIMEOUT_MS", "500"),
            // The redial is not the backoff's.
            ("KEEP_RETRY_FIRST_MS", "60000"),
        ],
        &[MANUAL_CLOCK],
    );
    b.hello();
    let a_route = route_of(&mut a);
    let relay = Relay::to(&a_route);
    trust(&mut a, &mut b, &[&relay.route]);
    let old = nth_up(&b, "out", &a.identity, 0, WAIT)["conn"]
        .as_u64()
        .unwrap();

    // The path dies without closing, and the host is at another address.
    relay.set(FREEZE);
    b.call(
        "peer.addresses.set",
        json!({"identity": a.identity, "routes": [a_route]}),
    );
    // Asleep for 20 s: within the idle timeout, so only the ping finds it.
    b.call("test.clock", json!({"advance_mono_ms": 20_000}));
    let soon = Duration::from_secs(6);
    let down = b.wait("the dead path to close", soon, |st| {
        st.messages
            .iter()
            .find(|m| m["ev"] == "conn.down" && m["conn"] == old)
            .cloned()
    });
    assert_eq!(down["reason"], "idle_timeout", "{down}");
    let up = nth_up(&b, "out", &a.identity, 1, soon);
    assert_ne!(up["conn"], old);
    assert!(
        b.events("dial.failed").is_empty(),
        "{:?}",
        b.events("dial.failed")
    );
}

/// After an interface change, a host that was down is dialled again at
/// once instead of after its backoff.
#[test]
fn after_an_interface_change_a_down_host_is_redialled_at_once() {
    let a_end = Endpoint::init("ifa");
    let b_end = Endpoint::init("ifb");
    let interfaces = b_end.dir.join("interfaces.txt");
    std::fs::write(&interfaces, "wlan0 192.168.1.20 up\n").unwrap();
    let mut a = a_end.app("hostA", &[]);
    let port = a.hello()["port"].as_u64().unwrap() as u16;
    let mut b = app(
        &b_end,
        "peerB",
        &[("IFACE_POLL_MS", "100"), ("KEEP_RETRY_FIRST_MS", "60000")],
        &[(
            "MOUSSE_HELPER_INTERFACES_FILE",
            interfaces.to_str().unwrap(),
        )],
    );
    b.hello();
    let a_route = route_of(&mut a);
    trust(&mut a, &mut b, &[&a_route]);
    let old = nth_up(&b, "out", &a.identity, 0, WAIT)["conn"]
        .as_u64()
        .unwrap();
    a.kill();
    b.event("conn.down", |m| m["conn"] == old);
    let mut a = a_end.app_with("hostA", &[], port, None);
    a.hello();
    // The backoff holds the redial back...
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(outbound_ups(&b, &a.identity), 1);
    // ...until the network changes.
    std::fs::write(&interfaces, "wlan0 10.0.0.7 up\n").unwrap();
    nth_up(&b, "out", &a.identity, 1, Duration::from_secs(5));
}
