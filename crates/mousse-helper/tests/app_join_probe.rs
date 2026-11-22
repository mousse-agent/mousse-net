//! Whether a link's host answers, before joining it
//! (`docs/pairing-flow-design.md` §5 and §12). The check
//! `pairing-flow.join-probe` runs this file.
//!
//! Everything listens on loopback. A stalled candidate is a listener that
//! takes the connection and never answers. The joiner that must not reach
//! the network runs under the egress fence (`MOUSSE_NET_TEST_EGRESS`
//! empty: loopback only, every other dial or lookup refused and logged),
//! and `MOUSSE_NET_TEST_CLASS_MAP` relabels loopback ports as tailnet or
//! public addresses.

mod common;
#[path = "common/relay.rs"]
mod relay_fixture;

use std::collections::BTreeMap;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use mousse_net_core::pairing::Ticket;
use mousse_net_io::store::hex;
use serde_json::{json, Value};

/// A loopback listener that takes connections, counts them and never
/// answers.
fn stalled() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in listener.incoming().flatten() {
            seen.fetch_add(1, Ordering::SeqCst);
            held.push(s);
        }
    });
    (addr, count)
}

/// A stalled listener that also counts the connections the dialler closed.
fn stalled_watching_close() -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let taken = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let (t, c) = (taken.clone(), closed.clone());
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            t.fetch_add(1, Ordering::SeqCst);
            let c = c.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
                c.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    (addr, taken, closed)
}

fn wait_until(what: &str, f: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !f() {
        assert!(Instant::now() < deadline, "waited for {what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// A helper on a new endpoint, greeted with protocol 1.2.
fn start(tag: &str, name: &str, env: &[(&str, &str)]) -> (Endpoint, App) {
    let end = Endpoint::init(tag);
    let mut app = end.app(name, env);
    app.hello();
    app.call("hello", json!({"proto": [1, 2]}));
    (end, app)
}

/// The ticket of `invite` with `routes` in place of its own.
fn with_routes(invite: &Value, routes: &[String]) -> String {
    let mut ticket = Ticket::from_fragment(invite["uri"].as_str().unwrap()).unwrap();
    ticket.routes = routes.to_vec();
    ticket.to_fragment()
}

fn hash_of(invite: &Value) -> String {
    let ticket = Ticket::from_fragment(invite["uri"].as_str().unwrap()).unwrap();
    hex(&ticket.hash())
}

/// Every file of a state directory but the log, with its bytes.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(at) = todo.pop() {
        for entry in std::fs::read_dir(&at).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                todo.push(path);
            } else if path.file_name().is_some_and(|n| n != "helper.log") {
                out.insert(path.clone(), std::fs::read(&path).unwrap_or_default());
            }
        }
    }
    out
}

/// A reply with its `re` dropped, to compare two answers to one question.
fn body(mut reply: Value) -> Value {
    reply.as_object_mut().unwrap().remove("re");
    reply
}

fn events_for(app: &App, ev: &str, invitation: &Value) -> usize {
    app.events(ev)
        .iter()
        .filter(|m| m["invitation"] == *invitation)
        .count()
}

/// How many messages answered request `id` so far.
fn answers(app: &App, id: u64) -> usize {
    app.st()
        .messages
        .iter()
        .filter(|m| m["re"] == json!(id))
        .count()
}

fn egress_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// B probes A's tickets and gets `reachable: true` with the route and the
/// time. A shows no approval, enrollment or new code, and its pre-auth
/// count returns to where it was. B stores, approves and announces
/// nothing, and the join that follows accepts the code A first showed,
/// with every attempt left.
#[test]
fn a_lan_probe_reaches_the_host_and_changes_nothing() {
    let (_ae, mut a) = start("jp-lan-a", "hostA", &[]);
    let (b_end, mut b) = start("jp-lan-b", "peerB", &[]);
    let route = route_of(&mut a);
    let preauth = a.stats()["preauth_open"].clone();

    // In person: a probe asks the host for no tap.
    let in_person = a.call("invite.create", json!({"way": "lan"}));
    let reply = b.call(
        "join.probe",
        json!({"ticket": in_person["uri"], "arrival": "scan"}),
    );
    assert_eq!(reply["reachable"], true, "{reply}");
    assert_eq!(reply["route"], route.as_str(), "{reply}");
    assert!(reply["ms"].is_u64(), "{reply}");
    // A tap would have been asked for by now: give a stray one a moment.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        a.events("approval").is_empty(),
        "the probe reached the invitation: {:?}",
        a.events("approval")
    );

    // A link: the first code still pairs, with every attempt left.
    let link = a.call("invite.create", json!({"kind": "link", "way": "lan"}));
    let inv = link["invitation"].clone();
    let codes = events_for(&a, "invite.code", &inv);
    let status = body(b.call("join.status", json!({"ticket_hash": hash_of(&link)})));
    let before = snapshot(&b_end.dir);
    let reply = b.call(
        "join.probe",
        json!({"ticket": link["uri"], "arrival": "link"}),
    );
    assert_eq!(reply["reachable"], true, "{reply}");
    assert_eq!(reply["route"], route.as_str(), "{reply}");
    assert_eq!(snapshot(&b_end.dir), before, "the probe stored something");
    assert_eq!(
        body(b.call("join.status", json!({"ticket_hash": hash_of(&link)}))),
        status,
        "the probe changed the join's status"
    );
    assert!(b.events("conn.up").is_empty(), "a probe announced a path");
    assert!(
        b.events("join.progress").is_empty(),
        "a probe sent progress"
    );
    assert_eq!(b.call("approvals.list", json!({}))["approvals"], json!([]));

    // The host: no tap, no enrollment, no new code, and its pre-auth slots
    // free again.
    let deadline = Instant::now() + WAIT;
    while a.stats()["preauth_open"] != preauth {
        assert!(Instant::now() < deadline, "A's pre-auth count stayed up");
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        a.events("approval").is_empty(),
        "{:?}",
        a.events("approval")
    );
    assert!(
        a.events("enrolled").is_empty(),
        "{:?}",
        a.events("enrolled")
    );
    assert_eq!(
        events_for(&a, "invite.code", &inv),
        codes,
        "the probe rotated the code"
    );
    assert!(a.call("grants.list", json!({}))["grants"]
        .as_array()
        .unwrap()
        .is_empty());

    let join = b.start("join", json!({"ticket": link["uri"], "arrival": "link"}));
    let needed = b.event("join.code_needed", |m| m["invitation"] == inv);
    assert_eq!(needed["attempts_left"], link["attempts_left"], "{needed}");
    b.call(
        "join.code",
        json!({"invitation": inv, "code": link["code"]}),
    );
    let joined = b.reply(join);
    assert!(joined.get("error").is_none(), "{joined}");
}

/// A ticket naming A but pointing at another helper is not reachable: the
/// helper that answers is not the ticket's host.
#[test]
fn a_ticket_pointing_at_another_helper_is_not_reachable() {
    let (_ae, mut a) = start("jp-other-a", "hostA", &[]);
    let (_ce, mut c) = start("jp-other-c", "other", &[]);
    let (_be, mut b) = start("jp-other-b", "peerB", &[]);
    let invite = a.call("invite.create", json!({"kind": "link"}));
    let ticket = with_routes(&invite, &[route_of(&mut c)]);
    let reply = b.call("join.probe", json!({"ticket": ticket, "arrival": "link"}));
    assert_eq!(reply["reachable"], false, "{reply}");
    let reason = reply["reason"].as_str().unwrap_or_default();
    assert!(
        ["pin_mismatch", "peer_certificate", "tls"].contains(&reason),
        "{reply}"
    );
}

/// A tailnet, public or tunnel hint causes no lookup and no connection
/// until its exact destination is in `approved`; then only that one is
/// dialled, and nothing passed to the probe is stored as an approval.
#[test]
fn only_approved_destinations_are_dialled() {
    let (_ae, mut a) = start("jp-appr-a", "hostA", &[]);
    let (tail, tail_n) = stalled();
    let (public, public_n) = stalled();
    let map = format!("{}=tailnet,{}=public", tail.port(), public.port());
    let b_end = Endpoint::init("jp-appr-b");
    let egress = b_end.dir.join("egress.jsonl");
    let mut b = b_end.app(
        "peerB",
        &[
            ("TEST_EGRESS", ""),
            ("TEST_EGRESS_LOG", egress.to_str().unwrap()),
            ("TEST_CLASS_MAP", &map),
            ("JOIN_PROBE_MS", "500"),
        ],
    );
    b.hello();
    b.call("hello", json!({"proto": [1, 2]}));
    let invite = a.call("invite.create", json!({"kind": "link"}));
    let ticket = with_routes(
        &invite,
        &[
            format!("tcp://{tail}"),
            format!("tcp://{public}"),
            "wss://t.example/mousse-net/1".into(),
        ],
    );
    let reply = b.call("join.probe", json!({"ticket": ticket, "arrival": "link"}));
    assert_eq!(reply["reachable"], Value::Null, "{reply}");
    assert_eq!(reply["reason"], "approval_required", "{reply}");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        tail_n.load(Ordering::SeqCst),
        0,
        "the tailnet hint was dialled"
    );
    assert_eq!(
        public_n.load(Ordering::SeqCst),
        0,
        "the public hint was dialled"
    );
    assert_eq!(egress_log(&egress), "", "the tunnel name was looked up");

    let reply = b.call(
        "join.probe",
        json!({
            "ticket": ticket,
            "arrival": "link",
            "approved": [format!("tcp://{public}")],
        }),
    );
    assert_eq!(reply["reason"], "approval_required", "{reply}");
    assert_eq!(
        public_n.load(Ordering::SeqCst),
        1,
        "the approved hint was not dialled"
    );
    assert_eq!(
        tail_n.load(Ordering::SeqCst),
        0,
        "an unapproved hint was dialled"
    );
    assert_eq!(egress_log(&egress), "", "an unapproved name was looked up");
    assert_eq!(
        b.call("approvals.list", json!({}))["approvals"],
        json!([]),
        "a probe stored an approval"
    );
}

/// A relay-only ticket answers `relay_unprobed`, also with its relay
/// approved, and the relay sees nothing from the probe. The join that
/// follows goes through the relay.
#[test]
fn a_relay_only_ticket_is_not_probed() {
    let relay = relay_fixture::TestRelay::start();
    let dest = relay.destination();
    let (_ae, mut a) = start("jp-relay-a", "hostA", &[]);
    let enrolled = a.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");
    let (_be, mut b) = start("jp-relay-b", "peerB", &[]);
    let invite = a.call("invite.create", json!({"way": "relay"}));
    let base = relay.connections();
    for approved in [json!([]), json!([dest])] {
        let reply = b.call(
            "join.probe",
            json!({"ticket": invite["uri"], "arrival": "scan", "approved": approved}),
        );
        assert_eq!(reply["reachable"], Value::Null, "{reply}");
        assert_eq!(reply["reason"], "relay_unprobed", "{reply}");
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(relay.connections(), base, "the probe reached the relay");

    let id = b.start(
        "join",
        json!({
            "ticket": invite["uri"],
            "arrival": "scan",
            "pinned": true,
            "approved": [dest],
        }),
    );
    let approval = a.event("approval", |m| m["invitation"] == invite["invitation"]);
    a.call(
        "approval.answer",
        json!({"request": approval["request"], "yes": true}),
    );
    let join = b.reply(id);
    assert!(join.get("error").is_none(), "{join}");
    assert!(relay.connections() > base, "the join did not use the relay");
}

/// With stalled candidates and `JOIN_PROBE_MS=500` the probe ends after one
/// deadline, and no candidate starts after it.
#[test]
fn one_deadline_bounds_the_whole_probe() {
    let (_ae, mut a) = start("jp-dl-a", "hostA", &[]);
    let (_be, mut b) = start("jp-dl-b", "peerB", &[("JOIN_PROBE_MS", "500")]);
    let stalls: Vec<(SocketAddr, Arc<AtomicUsize>)> = (0..3).map(|_| stalled()).collect();
    let invite = a.call("invite.create", json!({"kind": "link"}));
    let routes: Vec<String> = stalls.iter().map(|(a, _)| format!("tcp://{a}")).collect();
    let ticket = with_routes(&invite, &routes);
    let started = Instant::now();
    let reply = b.call("join.probe", json!({"ticket": ticket, "arrival": "link"}));
    let took = started.elapsed();
    assert_eq!(reply["reachable"], false, "{reply}");
    assert_eq!(reply["reason"], "timeout", "{reply}");
    std::thread::sleep(Duration::from_millis(300));
    let counts: Vec<usize> = stalls
        .iter()
        .map(|(_, n)| n.load(Ordering::SeqCst))
        .collect();
    assert_eq!(counts, [1, 0, 0], "a candidate started after the deadline");
    assert!(took < Duration::from_millis(1_400), "took {took:?}");
}

/// Two probes run at once by default; a third, or a second of the same
/// ticket, is `busy`. A cancelled probe ends once with `cancelled`, its
/// slot is free at once, and a second cancel says `cancelled: false`.
#[test]
fn probes_are_capped_and_cancel_frees_the_slot() {
    let (_ae, mut a) = start("jp-cap-a", "hostA", &[]);
    let (_be, mut b) = start("jp-cap-b", "peerB", &[]);
    let tickets: Vec<String> = (0..3)
        .map(|_| {
            let (addr, _) = stalled();
            let invite = a.call("invite.create", json!({"kind": "link"}));
            with_routes(&invite, &[format!("tcp://{addr}")])
        })
        .collect();
    let first = b.start(
        "join.probe",
        json!({"ticket": tickets[0], "arrival": "link"}),
    );
    let second = b.start(
        "join.probe",
        json!({"ticket": tickets[1], "arrival": "link"}),
    );
    let third = b.request(
        "join.probe",
        json!({"ticket": tickets[2], "arrival": "link"}),
    );
    assert_eq!(third["error"], "busy", "{third}");
    let again = b.request(
        "join.probe",
        json!({"ticket": tickets[0], "arrival": "link"}),
    );
    assert_eq!(again["error"], "busy", "{again}");

    let cancel = b.call("join.probe.cancel", json!({"probe": first}));
    assert_eq!(cancel["cancelled"], true, "{cancel}");
    let ended = b.reply(first);
    assert_eq!(ended["error"], "cancelled", "{ended}");
    // The freed slot takes a new probe, which runs.
    let third = b.start(
        "join.probe",
        json!({"ticket": tickets[2], "arrival": "link"}),
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        answers(&b, third),
        0,
        "the cancelled probe kept its slot: {:?}",
        b.st().messages.last()
    );
    let twice = b.call("join.probe.cancel", json!({"probe": first}));
    assert_eq!(twice["cancelled"], false, "{twice}");
    assert_eq!(
        answers(&b, first),
        1,
        "the cancelled probe was answered twice"
    );
    for id in [second, third] {
        let cancel = b.call("join.probe.cancel", json!({"probe": id}));
        assert_eq!(cancel["cancelled"], true, "{cancel}");
    }
}

/// A networking pause ends a running probe once, with `paused`.
#[test]
fn a_pause_ends_a_probe_once() {
    let mut p = pair_up("jp-pause", &[], &[("REMOVAL_RETRY_MS", "60000")]);
    p.b.call("hello", json!({"proto": [1, 2]}));
    // B, the prober, pauses: it removes a grant it cannot save.
    let c_end = Endpoint::init("jp-pause-c");
    let mut c = c_end.app("peerC", &[]);
    c.hello();
    pair_apps(&mut p.b, &mut c);
    let (addr, taken) = stalled();
    let invite = p.a.call("invite.create", json!({"kind": "link"}));
    let ticket = with_routes(&invite, &[format!("tcp://{addr}")]);
    let probe =
        p.b.start("join.probe", json!({"ticket": ticket, "arrival": "link"}));
    wait_until("the probe to dial", || taken.load(Ordering::SeqCst) == 1);
    let grant = p.b.call("grants.list", json!({}))["grants"][0]["grant"].clone();
    let table = p.b_end.dir.join("grants.json");
    std::fs::remove_file(&table).unwrap();
    std::fs::create_dir_all(table.join("in-the-way")).unwrap();
    let removed = p.b.call("grant.remove", json!({"grant": grant}));
    assert_eq!(removed["paused"], true);
    let reply = p.b.reply(probe);
    assert_eq!(reply["error"], "paused", "{reply}");
    p.b.event("net.paused", |_| true);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(answers(&p.b, probe), 1, "the probe was answered twice");
}

/// When the channel closes, the probe's dial is dropped.
#[test]
fn closing_the_channel_ends_a_probe() {
    let (_ae, mut a) = start("jp-close-a", "hostA", &[]);
    let (_be, mut b) = start("jp-close-b", "peerB", &[]);
    let (addr, taken, closed) = stalled_watching_close();
    let invite = a.call("invite.create", json!({"kind": "link"}));
    let ticket = with_routes(&invite, &[format!("tcp://{addr}")]);
    b.start("join.probe", json!({"ticket": ticket, "arrival": "link"}));
    wait_until("the probe to dial", || taken.load(Ordering::SeqCst) == 1);
    b.close_stdin();
    wait_until("the probe's connection to close", || {
        closed.load(Ordering::SeqCst) == 1
    });
}

/// Malformed probes and cancels are refused before anything is dialled,
/// and a 1.2 channel lists the feature.
#[test]
fn malformed_probes_are_refused() {
    let (_ae, mut a) = start("jp-bad-a", "hostA", &[]);
    let (_be, mut b) = start("jp-bad-b", "peerB", &[]);
    let (addr, taken) = stalled();
    let invite = a.call("invite.create", json!({"kind": "link"}));
    let t = with_routes(&invite, &[format!("tcp://{addr}")]);
    let nine: Vec<String> = (0..9).map(|n| format!("tcp://h{n}.example:7443")).collect();
    for bad in [
        json!({"ticket": t}),
        json!({"arrival": "link"}),
        json!({"ticket": t, "arrival": "post"}),
        json!({"ticket": t, "arrival": "link", "approved": "tcp://h.example:7443"}),
        json!({"ticket": t, "arrival": "link", "approved": nine}),
        json!({"ticket": t, "arrival": "link", "approved": [1]}),
        json!({"ticket": t, "arrival": "link", "pinned": true}),
    ] {
        let reply = b.request("join.probe", bad.clone());
        assert_eq!(reply["error"], "bad_request", "{bad}: {reply}");
    }
    let reply = b.request("join.probe", json!({"ticket": "AAAA", "arrival": "link"}));
    assert_eq!(reply["error"], "bad_ticket", "{reply}");
    for bad in [json!({}), json!({"probe": 1, "extra": true})] {
        let reply = b.request("join.probe.cancel", bad.clone());
        assert_eq!(reply["error"], "bad_request", "{bad}: {reply}");
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(taken.load(Ordering::SeqCst), 0, "a refused probe dialled");
    let hello = b.call("hello", json!({"proto": [1, 2]}));
    assert!(
        hello["features"]
            .as_array()
            .unwrap()
            .contains(&json!("join-probe")),
        "{hello}"
    );
}

/// Neither probe limit can be raised; lowered, the cap holds.
#[test]
fn probe_limits_can_only_be_lowered() {
    let dir = temp_dir("jp-limits");
    for (name, value, range) in [
        ("MOUSSE_NET_JOIN_PROBE_MS", "10001", "500 to 10000"),
        ("MOUSSE_NET_JOIN_PROBE_MS", "499", "500 to 10000"),
        ("MOUSSE_NET_JOIN_PROBES_MAX", "3", "1 to 2"),
        ("MOUSSE_NET_JOIN_PROBES_MAX", "0", "1 to 2"),
    ] {
        let out = std::process::Command::new(bin())
            .arg("--state")
            .arg(&dir)
            .arg("id")
            .env(name, value)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{name}={value}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "{name}={value} is out of range; allowed range is {range}"
            )),
            "{name}={value}: {stderr}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);

    let (_ae, mut a) = start("jp-one-a", "hostA", &[]);
    let (_be, mut b) = start("jp-one-b", "peerB", &[("JOIN_PROBES_MAX", "1")]);
    let tickets: Vec<String> = (0..2)
        .map(|_| {
            let (addr, _) = stalled();
            let invite = a.call("invite.create", json!({"kind": "link"}));
            with_routes(&invite, &[format!("tcp://{addr}")])
        })
        .collect();
    let first = b.start(
        "join.probe",
        json!({"ticket": tickets[0], "arrival": "link"}),
    );
    let second = b.request(
        "join.probe",
        json!({"ticket": tickets[1], "arrival": "link"}),
    );
    assert_eq!(second["error"], "busy", "{second}");
    b.call("join.probe.cancel", json!({"probe": first}));
}
