//! Inspecting a link with no network traffic (`docs/pairing-flow-design.md`
//! §4 and §12). The check `pairing.join-check` runs this file.
//!
//! The joiner runs under the egress fence (`MOUSSE_NET_TEST_EGRESS` empty:
//! loopback only, every other dial or lookup refused and logged), and its
//! loopback hints point at counting listeners, so any traffic shows.
//! `MOUSSE_NET_TEST_CLASS_MAP` relabels loopback ports as tailnet or
//! public addresses.

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use mousse_net_core::pairing::Ticket;
use mousse_net_core::relay::proof::RelayId;
use mousse_net_core::relay_endpoint::{RelayEndpoint, RelayRoute};
use mousse_net_core::UnixTime;
use serde_json::{json, Value};

/// A loopback listener that counts the connections it takes.
fn counting_listener() -> (SocketAddr, Arc<AtomicUsize>) {
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

/// A loopback port nothing listens on.
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
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

fn events_so_far(app: &App) -> usize {
    app.st()
        .messages
        .iter()
        .filter(|m| m.get("ev").is_some())
        .count()
}

/// What the fence refused and logged.
fn egress_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

struct Joiner {
    end: Endpoint,
    app: App,
    egress: PathBuf,
}

/// The joiner, under the egress fence, with `map` as its class map and
/// loopback as its only interface.
fn joiner(tag: &str, map: &str) -> Joiner {
    let end = Endpoint::init(tag);
    let egress = end.dir.join("egress.jsonl");
    let interfaces = end.dir.join("interfaces.txt");
    std::fs::write(&interfaces, "lo0 127.0.0.1\n").unwrap();
    let mut app = end.app_raw(
        "peerB",
        &[
            ("TEST_EGRESS", ""),
            ("TEST_EGRESS_LOG", egress.to_str().unwrap()),
            ("TEST_CLASS_MAP", map),
        ],
        0,
        &[("MOUSSE_HELPER_INTERFACES_FILE", &interfaces)],
    );
    app.hello();
    app.call("hello", json!({"proto": [1, 2]}));
    Joiner { end, app, egress }
}

fn relay_hint(port: u16) -> String {
    RelayRoute {
        endpoint: RelayEndpoint::parse(&format!("127.0.0.1:{port}")).unwrap(),
        relay: RelayId([1; 32]),
        handle: [2; 32],
    }
    .to_hint()
}

/// A ticket of `host` with `routes` in place of its own.
fn with_routes(invite: &Value, routes: &[String]) -> String {
    let mut ticket = Ticket::from_fragment(invite["uri"].as_str().unwrap()).unwrap();
    ticket.routes = routes.to_vec();
    ticket.to_fragment()
}

fn entry(route: &str, way: Value, eligibility: &str, destination: Value, reason: Value) -> Value {
    json!({
        "route": route,
        "way": way,
        "eligibility": eligibility,
        "destination": destination,
        "reason": reason,
    })
}

/// Drop `local` (advice, checked on its own) from each hint.
fn without_local(hints: &Value) -> Vec<Value> {
    hints
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            let mut h = h.clone();
            h.as_object_mut().unwrap().remove("local");
            h
        })
        .collect()
}

/// A ticket mixing every kind of hint keeps their order and gives the
/// exact approval destination for each. During the check nothing is
/// dialled, looked up or contacted, no event is sent and nothing is
/// written.
#[test]
fn a_mixed_ticket_is_inspected_in_order_with_no_traffic() {
    let a_end = Endpoint::init("jc-mix-a");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let invite = a.call("invite.create", json!({}));
    let (lan, lan_n) = counting_listener();
    let (tail, tail_n) = counting_listener();
    let (public, public_n) = counting_listener();
    let (relay, relay_n) = counting_listener();
    let map = format!("{}=tailnet,{}=public", tail.port(), public.port());
    let mut b = joiner("jc-mix-b", &map);

    let relay_text = relay_hint(relay.port());
    let first: Vec<String> = vec![
        format!("tcp://{lan}"),
        format!("tcp://{tail}"),
        format!("tcp://{public}"),
        "wss://t.example/mousse-net/1".into(),
        relay_text.clone(),
        "tcp://host.example:7443".into(),
        "mdns:Desk".into(),
        "ssh://a.example".into(),
    ];
    let second: Vec<String> = vec![
        "foo://x".into(),
        "tcp://nope".into(),
        "tcp://0.0.0.0:9".into(),
        "relay://broken".into(),
        "ws://127.0.0.1:9/mousse-net/1".into(),
    ];
    let before = snapshot(&b.end.dir);
    let seen = events_so_far(&b.app);

    let reply = b.app.call(
        "join.check",
        json!({"ticket": with_routes(&invite, &first), "arrival": "scan"}),
    );
    assert_eq!(reply["kind"], "in_person");
    assert_eq!(reply["invitation"], invite["invitation"]);
    let tcp = |a: SocketAddr| format!("tcp://{a}");
    assert_eq!(
        without_local(&reply["hints"]),
        vec![
            entry(
                &first[0],
                json!("lan"),
                "automatic",
                Value::Null,
                Value::Null
            ),
            entry(
                &first[1],
                json!("tailnet"),
                "approval_required",
                json!(tcp(tail)),
                Value::Null
            ),
            entry(
                &first[2],
                json!("public"),
                "approval_required",
                json!(tcp(public)),
                Value::Null
            ),
            entry(
                &first[3],
                json!("tunnel"),
                "approval_required",
                json!("wss://t.example:443/mousse-net/1"),
                Value::Null
            ),
            entry(
                &first[4],
                json!("relay"),
                "approval_required",
                json!(format!("relay://127.0.0.1:{}", relay.port())),
                Value::Null
            ),
            entry(
                &first[5],
                Value::Null,
                "approval_required",
                json!("tcp://host.example:7443"),
                Value::Null
            ),
            entry(
                &first[6],
                Value::Null,
                "skip",
                Value::Null,
                json!("unsupported_transport")
            ),
            entry(
                &first[7],
                Value::Null,
                "skip",
                Value::Null,
                json!("reserved")
            ),
        ],
        "{reply}"
    );
    let locals: Vec<&Value> = reply["hints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| &h["local"])
        .collect();
    assert_eq!(locals[0], "interface_present");
    assert_eq!(locals[5], "unknown");

    let reply = b.app.call(
        "join.check",
        json!({"ticket": with_routes(&invite, &second), "arrival": "scan"}),
    );
    let reasons: Vec<(Value, Value, Value)> = reply["hints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            (
                h["route"].clone(),
                h["eligibility"].clone(),
                h["reason"].clone(),
            )
        })
        .collect();
    assert_eq!(
        reasons,
        vec![
            (json!(second[0]), json!("skip"), json!("unknown_scheme")),
            (json!(second[1]), json!("skip"), json!("malformed")),
            (json!(second[2]), json!("skip"), json!("forbidden_address")),
            (json!(second[3]), json!("skip"), json!("malformed")),
            (json!(second[4]), json!("skip"), json!("reserved")),
        ],
        "{reply}"
    );

    // Nothing reached the network. A dial would have shown by now: give a
    // stray one a moment.
    std::thread::sleep(Duration::from_millis(300));
    for (what, n) in [
        ("lan", &lan_n),
        ("tailnet", &tail_n),
        ("public", &public_n),
        ("relay", &relay_n),
    ] {
        assert_eq!(n.load(Ordering::SeqCst), 0, "the {what} hint was dialled");
    }
    assert_eq!(egress_log(&b.egress), "", "a lookup or dial left loopback");
    assert_eq!(events_so_far(&b.app), seen, "join.check sent an event");
    assert_eq!(snapshot(&b.end.dir), before, "join.check wrote state");
}

/// The join that follows dials only the automatic hint and the one the
/// owner approved.
#[test]
fn the_join_after_a_check_dials_only_automatic_and_approved_hints() {
    let a_end = Endpoint::init("jc-join-a");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let invite = a.call("invite.create", json!({}));
    let lan = format!("tcp://127.0.0.1:{}", closed_port());
    let (tail, tail_n) = counting_listener();
    let (public, public_n) = counting_listener();
    let (relay, relay_n) = counting_listener();
    let map = format!("{}=tailnet,{}=public", tail.port(), public.port());
    let mut b = joiner("jc-join-b", &map);
    let routes = vec![
        lan.clone(),
        format!("tcp://{tail}"),
        format!("tcp://{public}"),
        "wss://t.example/mousse-net/1".into(),
        relay_hint(relay.port()),
    ];
    let ticket = with_routes(&invite, &routes);
    let check = b
        .app
        .call("join.check", json!({"ticket": ticket, "arrival": "scan"}));
    let approve = check["hints"][2]["destination"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(approve, format!("tcp://{public}"));

    let join = b.app.start(
        "join",
        json!({"ticket": ticket, "arrival": "scan", "approved": [approve]}),
    );
    let deadline = Instant::now() + WAIT;
    while public_n.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "the approved hint was not dialled"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    b.app.event("join.progress", |m| m["route"] == lan.as_str());
    b.app
        .call("join.cancel", json!({"invitation": invite["invitation"]}));
    let _ = b.app.reply(join);
    assert_eq!(
        tail_n.load(Ordering::SeqCst),
        0,
        "an unapproved hint was dialled"
    );
    assert_eq!(
        relay_n.load(Ordering::SeqCst),
        0,
        "an unapproved relay was dialled"
    );
    assert_eq!(
        egress_log(&b.egress),
        "",
        "an unapproved name was looked up"
    );
}

/// A pasted in-person ticket, this computer's own ticket, a damaged ticket
/// and an expired one fail before any traffic; malformed requests are
/// `bad_request`.
#[test]
fn refusals_come_before_any_traffic() {
    let a_end = Endpoint::init("jc-no-a");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let (lan, lan_n) = counting_listener();
    let mut b = joiner("jc-no-b", "");
    let routes = vec![
        format!("tcp://{lan}"),
        "wss://t.example/mousse-net/1".into(),
    ];

    let in_person = a.call("invite.create", json!({}));
    let ticket = with_routes(&in_person, &routes);
    let pasted = b
        .app
        .request("join.check", json!({"ticket": ticket, "arrival": "link"}));
    assert_eq!(pasted["error"], "pairing_failed", "{pasted}");

    let own = b.app.call("invite.create", json!({"kind": "link"}));
    let reply = b.app.request(
        "join.check",
        json!({"ticket": own["uri"], "arrival": "link"}),
    );
    assert_eq!(reply["error"], "pairing_failed", "{reply}");

    let reply = b
        .app
        .request("join.check", json!({"ticket": "AAAA", "arrival": "scan"}));
    assert_eq!(reply["error"], "bad_ticket", "{reply}");

    let link = a.call("invite.create", json!({"kind": "link"}));
    let mut expired = Ticket::from_fragment(link["uri"].as_str().unwrap()).unwrap();
    expired.routes = routes.clone();
    expired.expires_at = UnixTime(1_000);
    let reply = b.app.request(
        "join.check",
        json!({"ticket": expired.to_fragment(), "arrival": "link"}),
    );
    assert_eq!(reply["error"], "expired", "{reply}");

    let good = with_routes(&link, &routes);
    for bad in [
        json!({"ticket": good}),
        json!({"ticket": good, "arrival": "mail"}),
        json!({"ticket": good, "arrival": null}),
        json!({"ticket": good, "arrival": "link", "approved": []}),
        json!({"arrival": "link"}),
    ] {
        let reply = b.app.request("join.check", bad.clone());
        assert_eq!(reply["error"], "bad_request", "{bad}: {reply}");
    }
    // The well-formed link checks out.
    let fine = b
        .app
        .call("join.check", json!({"ticket": good, "arrival": "link"}));
    assert_eq!(fine["kind"], "link");

    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        lan_n.load(Ordering::SeqCst),
        0,
        "a refused ticket was dialled"
    );
    assert_eq!(egress_log(&b.egress), "");
}

/// While networking is paused `join.check` says so, as `join` does.
#[test]
fn a_pause_refuses_the_check_as_it_refuses_the_join() {
    let mut p = pair_up("jc-pause", &[], &[("REMOVAL_RETRY_MS", "60000")]);
    // B, the joiner here, pauses: it removes a grant it cannot save.
    let other_end = Endpoint::init("jc-pause-c");
    let mut c = other_end.app("peerC", &[]);
    c.hello();
    pair_apps(&mut p.b, &mut c);
    let grants = p.b.call("grants.list", json!({}));
    let grant = grants["grants"][0]["grant"].clone();
    let table = p.b_end.dir.join("grants.json");
    std::fs::remove_file(&table).unwrap();
    std::fs::create_dir_all(table.join("in-the-way")).unwrap();
    let removed = p.b.call("grant.remove", json!({"grant": grant}));
    assert_eq!(removed["paused"], true);
    p.b.event("net.paused", |_| true);
    let link = p.a.call("invite.create", json!({"kind": "link"}));
    let reply = p.b.request(
        "join.check",
        json!({"ticket": link["uri"], "arrival": "link"}),
    );
    assert_eq!(reply["error"], "paused", "{reply}");
    let join =
        p.b.request("join", json!({"ticket": link["uri"], "arrival": "link"}));
    assert_eq!(join["error"], "paused", "{join}");
}
