//! Choosing the way a ticket offers, and how each way stands
//! (`docs/pairing-flow-design.md` §1 to §3 and §12). The check
//! `pairing.invite-way` runs this file.
//!
//! Everything listens on loopback. A debug helper takes loopback as LAN;
//! `MOUSSE_NET_TEST_CLASS_MAP` relabels a loopback port as a tailnet
//! address, and `MOUSSE_HELPER_INTERFACES_FILE` gives the interface list,
//! so readiness does not depend on this computer's network.

mod common;
#[path = "common/relay.rs"]
mod relay_fixture;

use std::path::{Path, PathBuf};

use common::*;
use mousse_net_core::pairing::{Ticket, MAX_ROUTES, MAX_ROUTE_LEN};
use mousse_net_core::relay_endpoint::RelayRoute;
use serde_json::{json, Value};

const TUNNEL: &str = "wss://t.example:443/mousse-net/1";

/// Negotiate protocol 1.2 (after `hello`, which sets the identity).
fn hello12(app: &mut App) -> Value {
    app.hello();
    app.call("hello", json!({"proto": [1, 2]}))
}

fn routes_in(reply: &Value) -> Vec<String> {
    let ticket = Ticket::from_fragment(reply["uri"].as_str().unwrap()).unwrap();
    assert_eq!(
        json!(ticket.routes),
        reply["routes"],
        "the reply's routes are the ticket's"
    );
    ticket.routes
}

fn way_of<'a>(available: &'a Value, way: &str) -> &'a Value {
    available["ways"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["way"] == way)
        .unwrap_or_else(|| panic!("no {way} in {available}"))
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn interfaces_file(end: &Endpoint, lines: &str) -> PathBuf {
    let path = end.dir.join("interfaces.txt");
    std::fs::write(&path, lines).unwrap();
    path
}

fn app_with_interfaces(end: &Endpoint, env: &[(&str, &str)], port: u16, file: &Path) -> App {
    end.app_raw(
        "hostA",
        env,
        port,
        &[("MOUSSE_HELPER_INTERFACES_FILE", file)],
    )
}

/// A 1.2 channel lists `invite-way` and `route-readiness`.
#[test]
fn a_1_2_channel_lists_invite_way_and_route_readiness() {
    let end = Endpoint::init("iw-feat");
    let mut a = end.app("hostA", &[]);
    let hello = hello12(&mut a);
    let features = hello["features"].as_array().unwrap();
    assert!(features.contains(&json!("invite-way")), "{hello}");
    assert!(features.contains(&json!("route-readiness")), "{hello}");
}

/// `lan`, `tunnel` and `relay` tickets each carry only their own hints,
/// the reply's `ways` is exactly the way chosen, and an exact `route`
/// yields that one hint. Without a selector the ticket has the 1.1 routes
/// in the 1.1 order.
#[test]
fn each_way_carries_only_its_own_hints() {
    let relay = relay_fixture::TestRelay::start();
    let end = Endpoint::init("iw-each");
    let mut a = end.app_args("hostA", &[], &["--tunnel", "wss://t.example/mousse-net/1"]);
    let hello = hello12(&mut a);
    let enrolled = a.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");
    let lan = format!("tcp://127.0.0.1:{}", hello["port"]);

    let available = a.call("routes.available", json!({}));
    assert_eq!(
        available["ways"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w["way"].clone())
            .collect::<Vec<_>>(),
        ["lan", "tailnet", "public", "tunnel", "relay"]
    );
    assert_eq!(way_of(&available, "lan")["state"], "ready", "{available}");
    assert_eq!(way_of(&available, "lan")["routes"], json!([lan]));
    assert_eq!(way_of(&available, "tunnel")["routes"], json!([TUNNEL]));
    let relay_ready = way_of(&available, "relay");
    assert_eq!(relay_ready["state"], "ready", "{available}");
    let relay_hint = relay_ready["routes"][0].as_str().unwrap().to_owned();
    let parsed = RelayRoute::parse_hint(&relay_hint).expect("a relay hint");
    assert_eq!(parsed.endpoint.destination(), relay.destination());

    for (way, want) in [
        ("lan", lan.clone()),
        ("tunnel", TUNNEL.to_owned()),
        ("relay", relay_hint.clone()),
    ] {
        let reply = a.call("invite.create", json!({"way": way}));
        assert_eq!(routes_in(&reply), vec![want.clone()], "{way}: {reply}");
        assert_eq!(reply["ways"], json!([way]), "{reply}");
        // The same through the exact route, byte for byte.
        let exact = a.call("invite.create", json!({"way": way, "route": want}));
        assert_eq!(routes_in(&exact), [want], "{exact}");
    }
    // A link ticket follows the same rule and keeps its first code.
    let link = a.call("invite.create", json!({"kind": "link", "way": "lan"}));
    assert_eq!(routes_in(&link), vec![lan.clone()]);
    assert!(link["code"].is_string(), "{link}");

    // No selector: the 1.1 routes, in the 1.1 order, and the 1.1 reply,
    // field for field.
    let legacy = a.call("invite.create", json!({}));
    assert_eq!(routes_in(&legacy), [lan, TUNNEL.to_owned(), relay_hint]);
    let mut fields: Vec<&str> = legacy
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["expires_at", "invitation", "re", "routes", "uri"],
        "{legacy}"
    );
}

/// A `tailnet` ticket carries only the tailnet literal; with no LAN
/// interface, `lan` says so and cannot be chosen.
#[test]
fn a_tailnet_ticket_carries_only_the_tailnet_literal() {
    let end = Endpoint::init("iw-tail");
    let port = free_port();
    let file = interfaces_file(&end, "lo0 127.0.0.1\n");
    let map = format!("{port}=tailnet");
    let mut a = app_with_interfaces(&end, &[("TEST_CLASS_MAP", &map)], port, &file);
    hello12(&mut a);
    let tailnet = format!("tcp://127.0.0.1:{port}");
    let available = a.call("routes.available", json!({}));
    assert_eq!(
        way_of(&available, "tailnet")["state"],
        "ready",
        "{available}"
    );
    assert_eq!(way_of(&available, "tailnet")["routes"], json!([tailnet]));
    assert_eq!(
        way_of(&available, "lan")["reason"],
        "no_interface",
        "{available}"
    );
    let reply = a.call("invite.create", json!({"way": "tailnet"}));
    assert_eq!(routes_in(&reply), [tailnet]);
    assert_eq!(reply["ways"], json!(["tailnet"]));
    let refused = a.request("invite.create", json!({"way": "lan"}));
    assert_eq!(refused["error"], "way_unavailable", "{refused}");
    assert_eq!(refused["reason"], "no_interface", "{refused}");
}

/// With more port forwards than a ticket holds, the tunnel after them is
/// cut from the 1.1 ticket but still offered when chosen; a `public`
/// ticket holds the first `MAX_ROUTES`; an exact `route` yields that one,
/// also one beyond the cap; a route outside the inventory is never added
/// (`route_not_offered`).
#[test]
fn a_later_way_survives_a_full_ticket() {
    let end = Endpoint::init("iw-cap");
    let public: Vec<String> = (1..=MAX_ROUTES + 2)
        .map(|n| format!("tcp://p{n}.example:7443"))
        .collect();
    let first = public[..MAX_ROUTES].to_vec();
    std::fs::write(
        end.dir.join("routes.json"),
        serde_json::to_vec(&json!({
            "public": public,
            "forward_to": "127.0.0.1",
            "tunnels": ["wss://t.example/mousse-net/1"],
        }))
        .unwrap(),
    )
    .unwrap();
    let file = interfaces_file(&end, "lo0 127.0.0.1\n");
    let mut a = app_with_interfaces(&end, &[], 0, &file);
    hello12(&mut a);

    let legacy = a.call("invite.create", json!({}));
    assert_eq!(
        routes_in(&legacy),
        first,
        "the 1.1 ticket is the first eight"
    );

    let tunnel = a.call("invite.create", json!({"way": "tunnel"}));
    assert_eq!(routes_in(&tunnel), [TUNNEL], "{tunnel}");
    assert_eq!(tunnel["ways"], json!(["tunnel"]));

    let forwards = a.call("invite.create", json!({"way": "public"}));
    let carried = routes_in(&forwards);
    assert_eq!(carried.len(), MAX_ROUTES, "the cap holds");
    assert_eq!(carried, first);

    let one = a.call(
        "invite.create",
        json!({"way": "public", "route": public[2]}),
    );
    assert_eq!(routes_in(&one), [public[2].clone()]);
    // An entry past the cap can still be chosen exactly.
    let last = public.last().unwrap().clone();
    let beyond = a.call("invite.create", json!({"way": "public", "route": last}));
    assert_eq!(routes_in(&beyond), [last], "{beyond}");
    assert_eq!(beyond["ways"], json!(["public"]));

    // The way offers routes, but not this one: `route_not_offered`.
    let outside = a.request(
        "invite.create",
        json!({"way": "public", "route": "tcp://p99.example:7443"}),
    );
    assert_eq!(outside["error"], "way_unavailable", "{outside}");
    assert_eq!(outside["reason"], "route_not_offered", "{outside}");
    // A route of another way is not this way's.
    let other = a.request("invite.create", json!({"way": "public", "route": TUNNEL}));
    assert_eq!(other["error"], "way_unavailable", "{other}");
    assert_eq!(other["reason"], "route_not_offered", "{other}");
    // A way with nothing to offer keeps its own reason.
    let none = a.request(
        "invite.create",
        json!({"way": "relay", "route": "tcp://p1.example:7443"}),
    );
    assert_eq!(none["reason"], "not_configured", "{none}");

    let available = a.call("routes.available", json!({}));
    assert_eq!(way_of(&available, "tunnel")["routes"], json!([TUNNEL]));
    assert_eq!(way_of(&available, "public")["routes"], json!(first));
}

/// A helper with LAN on and one port forward and one tunnel saved, all
/// running. Tests bind loopback only, so LAN from `routes.json` offers
/// nothing here (`no_interface`); the port forward and the tunnel are
/// `ready`.
fn three_ways(end: &Endpoint) -> (App, PathBuf) {
    std::fs::write(
        end.dir.join("routes.json"),
        serde_json::to_vec(&json!({
            "lan": true,
            "public": ["tcp://p1.example:7443"],
            "forward_to": "127.0.0.1",
            "tunnels": ["wss://t.example/mousse-net/1"],
        }))
        .unwrap(),
    )
    .unwrap();
    let file = interfaces_file(end, "lo0 127.0.0.1\nen9 127.0.0.2\n");
    let mut a = app_with_interfaces(end, &[], 0, &file);
    hello12(&mut a);
    (a, file)
}

/// A saved change that waits for a restart hides the way it changes, and
/// that way alone: `restart_required` comes first, also while the running
/// listener still offers routes for it, and a selection of it is refused
/// with that reason. A way whose own setting is unchanged stays `ready`.
/// One case per kind of change, and a change that needs no restart.
#[test]
fn a_pending_restart_hides_only_the_way_it_changes() {
    let other_port = free_port();
    let cases: [(&str, Value, &[&str]); 5] = [
        ("lan-off", json!({"lan": false}), &["lan"]),
        ("fwd", json!({"forward_to": "127.0.0.2"}), &["public"]),
        ("pub-empty", json!({"public": []}), &["public"]),
        ("tun-none", json!({"tunnels": []}), &["tunnel"]),
        ("port", json!({"port": other_port}), &["lan", "public"]),
    ];
    for (tag, change, pending) in cases {
        let end = Endpoint::init(&format!("iw-rs-{tag}"));
        let (mut a, _file) = three_ways(&end);
        let before = a.call("routes.available", json!({}));
        assert_eq!(way_of(&before, "lan")["reason"], "no_interface", "{before}");
        for way in ["public", "tunnel"] {
            assert_eq!(way_of(&before, way)["state"], "ready", "{tag}: {before}");
        }
        let saved = a.call("routes.config", change.clone());
        assert_eq!(saved["restart_needed"], true, "{tag}: {saved}");
        let after = a.call("routes.available", json!({}));
        for way in ["lan", "public", "tunnel"] {
            let w = way_of(&after, way);
            if pending.contains(&way) {
                assert_eq!(w["state"], "unavailable", "{tag} {way}: {after}");
                assert_eq!(w["reason"], "restart_required", "{tag} {way}: {after}");
                assert_eq!(w["routes"], json!([]), "{tag} {way}");
                let refused = a.request("invite.create", json!({"way": way}));
                assert_eq!(refused["error"], "way_unavailable", "{tag}: {refused}");
                assert_eq!(refused["reason"], "restart_required", "{tag}: {refused}");
                // The exact route the listener still serves is refused too.
                if let Some(route) = way_of(&before, way)["routes"].get(0) {
                    let exact = a.request("invite.create", json!({"way": way, "route": route}));
                    assert_eq!(exact["reason"], "restart_required", "{tag}: {exact}");
                }
            } else if way == "lan" {
                assert_eq!(w["reason"], "no_interface", "{tag}: {after}");
            } else {
                assert_eq!(w["state"], "ready", "{tag} {way}: {after}");
                assert_eq!(w["routes"], way_of(&before, way)["routes"], "{tag} {way}");
                a.call("invite.create", json!({"way": way}));
            }
        }
    }

    // A new port forward list that needs no restart reaches the next
    // ticket at once: nothing is pending.
    let end = Endpoint::init("iw-rs-pub");
    let (mut a, _file) = three_ways(&end);
    let saved = a.call(
        "routes.config",
        json!({"public": ["tcp://p2.example:7443"]}),
    );
    assert_eq!(saved["restart_needed"], false, "{saved}");
    let after = a.call("routes.available", json!({}));
    let public = way_of(&after, "public");
    assert_eq!(public["state"], "ready", "{after}");
    assert_eq!(public["routes"], json!(["tcp://p2.example:7443"]));
}

/// A candidate longer than a ticket holds is left out before readiness and
/// before the cap: the way's other routes stay offered, and a way with
/// only such a route says `route_too_long`.
#[test]
fn a_route_too_long_for_a_ticket_is_left_out() {
    // A valid name of 251 characters: four labels of 60, then `example`.
    let host = format!("{}example", format!("{}.", "a".repeat(60)).repeat(4));
    let long = format!("wss://{host}/mousse-net/1");
    assert!(
        format!("wss://{host}:443/mousse-net/1").len() > MAX_ROUTE_LEN,
        "the canonical route is too long for a ticket"
    );
    let tunnels = |end: &Endpoint, list: Value| {
        std::fs::write(
            end.dir.join("routes.json"),
            serde_json::to_vec(&json!({"tunnels": list})).unwrap(),
        )
        .unwrap();
        let file = interfaces_file(end, "lo0 127.0.0.1\n");
        let mut a = app_with_interfaces(end, &[], 0, &file);
        hello12(&mut a);
        a
    };
    let end = Endpoint::init("iw-long");
    let mut a = tunnels(&end, json!([long, "wss://t.example/mousse-net/1"]));
    let available = a.call("routes.available", json!({}));
    let tunnel = way_of(&available, "tunnel");
    assert_eq!(tunnel["state"], "ready", "{available}");
    assert_eq!(tunnel["routes"], json!([TUNNEL]));
    let reply = a.call("invite.create", json!({"way": "tunnel"}));
    assert_eq!(routes_in(&reply), [TUNNEL]);

    let alone = Endpoint::init("iw-long1");
    let mut b = tunnels(&alone, json!([long]));
    let available = b.call("routes.available", json!({}));
    let tunnel = way_of(&available, "tunnel");
    assert_eq!(
        (&tunnel["state"], &tunnel["reason"]),
        (&json!("unavailable"), &json!("route_too_long")),
        "{available}"
    );
    let refused = b.request("invite.create", json!({"way": "tunnel"}));
    assert_eq!(refused["reason"], "route_too_long", "{refused}");
}

/// Every file of a state directory but the log, with its bytes.
fn snapshot(dir: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
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

/// A failed selection leaves nothing behind, as observed: no invitation
/// event or code, no file written, and no relay allow-set slot taken
/// (all eight are still free after it).
#[test]
fn a_failed_selection_leaves_no_invitation_code_or_slot() {
    let relay = relay_fixture::TestRelay::start();
    let end = Endpoint::init("iw-left");
    let file = interfaces_file(&end, "lo0 127.0.0.1\nutun4 100.100.9.9\n");
    let mut a = app_with_interfaces(&end, &[], 0, &file);
    hello12(&mut a);
    let enrolled = a.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");
    let relay_hint = way_of(&a.call("routes.available", json!({})), "relay")["routes"][0].clone();
    let before = snapshot(&end.dir);
    let messages = a.st().messages.len();
    for (selection, reason) in [
        (json!({"kind": "link", "way": "tailnet"}), "disabled"),
        (json!({"kind": "link", "way": "public"}), "not_configured"),
        (
            json!({"kind": "link", "way": "relay", "route": "tcp://127.0.0.1:9"}),
            "route_not_offered",
        ),
        (
            json!({"way": "relay", "route": format!("{}x", relay_hint.as_str().unwrap())}),
            "route_not_offered",
        ),
    ] {
        let refused = a.request("invite.create", selection.clone());
        assert_eq!(
            refused["error"], "way_unavailable",
            "{selection}: {refused}"
        );
        assert_eq!(refused["reason"], reason, "{selection}: {refused}");
        assert!(refused.get("code").is_none() && refused.get("invitation").is_none());
    }
    // Anything sent because of a refusal arrives before a later reply.
    a.call("routes.available", json!({}));
    let since: Vec<Value> = a.st().messages[messages..]
        .iter()
        .filter(|m| m.get("ev").is_some())
        .cloned()
        .collect();
    assert!(since.is_empty(), "events after refusals: {since:?}");
    assert_eq!(snapshot(&end.dir), before, "a refusal wrote state");
    for n in 0..8 {
        let made = a.request("invite.create", json!({"kind": "link", "way": "relay"}));
        assert!(made.get("error").is_none(), "relay ticket {n}: {made}");
    }
}

/// A recovery entry holds an allow-set slot: after a joiner enrolls through
/// a ticket that carried a relay hint, only seven new relay tickets fit,
/// and the eighth is `relay_capacity`.
#[test]
fn a_recovery_entry_holds_a_relay_slot() {
    let relay = relay_fixture::TestRelay::start();
    let end = Endpoint::init("iw-recov-a");
    let mut a = end.app("hostA", &[]);
    hello12(&mut a);
    let enrolled = a.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");
    let b_end = Endpoint::init("iw-recov-b");
    // B holds its caller key back, so the recovery entry stays listed.
    let mut b = b_end.app_raw(
        "peerB",
        &[],
        0,
        &[("MOUSSE_HELPER_TEST_NO_KEYS", Path::new("1"))],
    );
    b.hello();
    // The 1.1 ticket carries the LAN route and the relay hint; B joins
    // over LAN, which leaves the tag listed for recovery.
    let joined = pair_apps(&mut a, &mut b);
    assert!(
        joined.invite["routes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| RelayRoute::parse_hint(r.as_str().unwrap()).is_some()),
        "{}",
        joined.invite
    );
    let grants: Value =
        serde_json::from_slice(&std::fs::read(end.dir.join("relay-grants.json")).unwrap()).unwrap();
    assert_eq!(
        grants["recovery"].as_array().map(Vec::len),
        Some(1),
        "{grants}"
    );
    for n in 0..7 {
        let made = a.request("invite.create", json!({"way": "relay"}));
        assert!(made.get("error").is_none(), "relay ticket {n}: {made}");
    }
    let full = a.request("invite.create", json!({"way": "relay"}));
    assert_eq!(full["reason"], "relay_capacity", "{full}");
    let available = a.call("routes.available", json!({}));
    assert_eq!(way_of(&available, "relay")["reason"], "relay_capacity");
}

/// A relay that is set but not registered now (its relay is gone):
/// `relay_not_registered`.
#[test]
fn a_relay_set_but_not_registered_says_so() {
    let end = Endpoint::init("iw-unreg");
    {
        let relay = relay_fixture::TestRelay::start();
        let mut a = end.app("hostA", &[]);
        hello12(&mut a);
        let enrolled = a.call("relay.enroll", json!({"link": relay.link()}));
        assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");
        a.kill();
    }
    let mut a = end.app("hostA", &[]);
    hello12(&mut a);
    let available = a.call("routes.available", json!({}));
    let relay = way_of(&available, "relay");
    assert_eq!(
        (&relay["state"], &relay["reason"]),
        (&json!("unavailable"), &json!("relay_not_registered")),
        "{available}"
    );
    let refused = a.request("invite.create", json!({"way": "relay"}));
    assert_eq!(refused["reason"], "relay_not_registered", "{refused}");
}

/// A store that cannot be read is `store_failed`, never an empty list:
/// `routes.json`, `relays.json` and the relay grants file, each made
/// unreadable while the helper runs. A `lan` selection reads no relay
/// file.
#[test]
fn an_unreadable_store_is_store_failed() {
    let relay = relay_fixture::TestRelay::start();
    for (tag, file, ways) in [
        ("routes", "routes.json", &["lan", "relay"][..]),
        ("relays", "relays.json", &["relay"][..]),
        ("grants", "relay-grants.json", &["relay"][..]),
    ] {
        let end = Endpoint::init(&format!("iw-sf-{tag}"));
        let mut a = end.app("hostA", &[]);
        hello12(&mut a);
        let enrolled = a.call("relay.enroll", json!({"link": relay.link()}));
        assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");
        a.call("invite.create", json!({"way": "relay"}));
        let path = end.dir.join(file);
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir_all(path.join("in-the-way")).unwrap();
        let available = a.request("routes.available", json!({}));
        assert_eq!(available["error"], "store_failed", "{tag}: {available}");
        for way in ways {
            let refused = a.request("invite.create", json!({"way": way}));
            assert_eq!(refused["error"], "store_failed", "{tag} {way}: {refused}");
        }
        if tag != "routes" {
            a.call("invite.create", json!({"way": "lan"}));
        }
    }
}

/// The app's managed tunnel (`routes.managed_tunnel`) is a `tunnel`
/// candidate: once published the way is ready and a `tunnel` ticket
/// carries it, after a configured tunnel; once withdrawn the way has
/// nothing to offer again. Other ways never carry it, and the request
/// refuses a field it does not know.
#[test]
fn a_managed_tunnel_makes_the_tunnel_way_ready() {
    const MANAGED: &str = "wss://managed.example:443/mousse-net/1";
    let end = Endpoint::init("iw-managed");
    let mut a = end.app("hostA", &[]);
    let hello = hello12(&mut a);
    let features = hello["features"].as_array().unwrap();
    assert!(features.contains(&json!("managed-tunnel")), "{hello}");
    assert_eq!(hello["managed_tunnel"], true, "{hello}");
    let tunnel_state = |a: &mut App| {
        let available = a.call("routes.available", json!({}));
        let w = way_of(&available, "tunnel");
        (w["state"].clone(), w["reason"].clone(), w["routes"].clone())
    };
    let not_configured = (json!("unavailable"), json!("not_configured"), json!([]));
    assert_eq!(tunnel_state(&mut a), not_configured);
    let refused = a.request("invite.create", json!({"way": "tunnel"}));
    assert_eq!(refused["reason"], "not_configured", "{refused}");

    a.call("routes.managed_tunnel", json!({"route": MANAGED}));
    assert_eq!(
        tunnel_state(&mut a),
        (json!("ready"), Value::Null, json!([MANAGED]))
    );
    let reply = a.call("invite.create", json!({"way": "tunnel"}));
    assert_eq!(routes_in(&reply), [MANAGED], "{reply}");
    assert_eq!(reply["ways"], json!(["tunnel"]));
    let link = a.call(
        "invite.create",
        json!({"kind": "link", "way": "tunnel", "route": MANAGED}),
    );
    assert_eq!(routes_in(&link), [MANAGED], "{link}");
    let lan = a.call("invite.create", json!({"way": "lan"}));
    assert!(!routes_in(&lan).contains(&MANAGED.to_owned()), "{lan}");

    let unknown = a.request(
        "routes.managed_tunnel",
        json!({"route": MANAGED, "way": "tunnel"}),
    );
    assert_eq!(unknown["error"], "bad_request", "{unknown}");
    assert_eq!(
        tunnel_state(&mut a).0,
        "ready",
        "a refused request changes nothing"
    );

    a.call("routes.managed_tunnel", json!({"route": null}));
    assert_eq!(tunnel_state(&mut a), not_configured);
    let refused = a.request("invite.create", json!({"way": "tunnel", "route": MANAGED}));
    assert_eq!(refused["error"], "way_unavailable", "{refused}");
    drop(a);

    // With a configured tunnel, the managed one comes after it.
    let both = Endpoint::init("iw-managed-both");
    let mut b = both.app_args("hostA", &[], &["--tunnel", "wss://t.example/mousse-net/1"]);
    hello12(&mut b);
    b.call("routes.managed_tunnel", json!({"route": MANAGED}));
    assert_eq!(tunnel_state(&mut b).2, json!([TUNNEL, MANAGED]));
    let reply = b.call("invite.create", json!({"way": "tunnel"}));
    assert_eq!(routes_in(&reply), [TUNNEL, MANAGED], "{reply}");
}

/// A way that is off, waits for a restart, has no interface or is not
/// configured reports that reason; the healthy way stays selectable.
#[test]
fn readiness_says_why_a_way_is_not_ready() {
    let end = Endpoint::init("iw-why");
    let file = interfaces_file(&end, "lo0 127.0.0.1\nutun4 100.100.9.9\n");
    let mut a = app_with_interfaces(&end, &[], 0, &file);
    hello12(&mut a);
    let available = a.call("routes.available", json!({}));
    let reason = |way: &str| {
        let w = way_of(&available, way);
        (w["state"].clone(), w["reason"].clone(), w["routes"].clone())
    };
    assert_eq!(reason("lan").0, "ready", "{available}");
    assert_eq!(reason("lan").1, Value::Null);
    assert_eq!(
        reason("tailnet"),
        (json!("off"), json!("disabled"), json!([]))
    );
    for way in ["public", "tunnel", "relay"] {
        assert_eq!(
            reason(way),
            (json!("unavailable"), json!("not_configured"), json!([])),
            "{way}"
        );
    }
    let refused = a.request("invite.create", json!({"way": "tailnet"}));
    assert_eq!(refused["error"], "way_unavailable", "{refused}");
    assert_eq!(refused["reason"], "disabled");

    // Tailnet saved on while keeping LAN on: a restart is pending for
    // tailnet alone, and LAN stays ready and selectable.
    let saved = a.call("routes.config", json!({"lan": true, "tailnet": true}));
    assert_eq!(saved["restart_needed"], true, "{saved}");
    let available = a.call("routes.available", json!({}));
    assert_eq!(way_of(&available, "tailnet")["reason"], "restart_required");
    assert_eq!(way_of(&available, "lan")["state"], "ready");
    a.call("invite.create", json!({"way": "lan"}));

    // No tailnet address: `no_interface`.
    let bare = Endpoint::init("iw-none");
    let file = interfaces_file(&bare, "lo0 127.0.0.1\n");
    let mut b = app_with_interfaces(&bare, &[], 0, &file);
    hello12(&mut b);
    let available = b.call("routes.available", json!({}));
    assert_eq!(way_of(&available, "tailnet")["reason"], "no_interface");

    // The interfaces cannot be listed: `interface_unknown`, never "none".
    let blind = Endpoint::init("iw-blind");
    let missing = blind.dir.join("no-such-file");
    let mut c = app_with_interfaces(&blind, &[], 0, &missing);
    hello12(&mut c);
    let available = c.call("routes.available", json!({}));
    assert_eq!(way_of(&available, "tailnet")["reason"], "interface_unknown");
    assert_eq!(way_of(&available, "lan")["state"], "ready");
}

/// Tailnet on and an interface present, but its socket not bound:
/// `not_bound`.
#[test]
fn a_selected_way_whose_socket_is_not_bound_says_so() {
    let end = Endpoint::init("iw-unbound");
    let port = free_port();
    std::fs::write(
        end.dir.join("routes.json"),
        format!(r#"{{"tailnet": true, "port": {port}}}"#),
    )
    .unwrap();
    // An address this computer does not have, so it cannot be bound.
    let file = interfaces_file(&end, "lo0 127.0.0.1\nutun4 100.100.9.9\n");
    let mut a = app_with_interfaces(&end, &[], 0, &file);
    let hello = hello12(&mut a);
    assert_eq!(hello["unbound"], json!(["100.100.9.9"]), "{hello}");
    let available = a.call("routes.available", json!({}));
    assert_eq!(
        way_of(&available, "tailnet")["reason"],
        "not_bound",
        "{available}"
    );
}

/// Malformed selections are `bad_request`; a 1.1-shaped `invite.create`
/// with an extra field behaves as before; `routes.available` takes no
/// fields.
#[test]
fn malformed_selections_are_refused_and_1_1_requests_are_unchanged() {
    let end = Endpoint::init("iw-bad");
    let mut a = end.app("hostA", &[]);
    hello12(&mut a);
    for bad in [
        json!({"way": null}),
        json!({"way": "wifi"}),
        json!({"way": 5}),
        json!({"way": ["lan"]}),
        json!({"route": "tcp://127.0.0.1:9"}),
        json!({"way": "lan", "route": 5}),
        json!({"way": "lan", "route": null}),
        json!({"way": "lan", "kind": "bus"}),
        json!({"way": "lan", "kind": null}),
        json!({"way": "lan", "role": "Not A Role"}),
    ] {
        let reply = a.request("invite.create", bad.clone());
        assert_eq!(reply["error"], "bad_request", "{bad}: {reply}");
    }
    let old = a.call("invite.create", json!({"kind": "link", "extra": 1}));
    let hello = a.call("hello", json!({"proto": [1, 1]}));
    assert_eq!(routes_in(&old), [hello["routes"][0].as_str().unwrap()]);
    let reply = a.request("routes.available", json!({"way": "lan"}));
    assert_eq!(reply["error"], "bad_request", "{reply}");
}

/// The relay allow-set slots: a relay ticket never takes a slot held by an
/// open invitation, a refusal leaves no slot behind, the healthy way stays
/// selectable, and two requests for the last slot cannot both get it.
#[test]
fn relay_tickets_never_overbook_the_allow_set() {
    let relay = relay_fixture::TestRelay::start();
    let end = Endpoint::init("iw-slot");
    let mut a = end.app("hostA", &[]);
    hello12(&mut a);
    let enrolled = a.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");
    let mut open: Vec<String> = Vec::new();
    for _ in 0..8 {
        let reply = a.call("invite.create", json!({"way": "relay"}));
        open.push(reply["invitation"].as_str().unwrap().to_owned());
    }
    let full = a.request("invite.create", json!({"way": "relay"}));
    assert_eq!(full["error"], "way_unavailable", "{full}");
    assert_eq!(full["reason"], "relay_capacity", "{full}");
    let available = a.call("routes.available", json!({}));
    assert_eq!(way_of(&available, "relay")["reason"], "relay_capacity");
    assert_eq!(way_of(&available, "lan")["state"], "ready");
    a.call("invite.create", json!({"way": "lan"}));

    // One ends: one slot is free, and only one.
    let cancel = |a: &mut App, invitation: &str| {
        a.call("invite.cancel", json!({"invitation": invitation}));
        a.event("invite.ended", |m| m["invitation"] == invitation);
    };
    cancel(&mut a, &open.remove(0));
    a.call("invite.create", json!({"way": "relay"}));
    let again = a.request("invite.create", json!({"way": "relay"}));
    assert_eq!(again["reason"], "relay_capacity", "{again}");

    // Two at once for the last slot: one gets it.
    cancel(&mut a, &open.remove(0));
    let first = a.start("invite.create", json!({"way": "relay"}));
    let second = a.start("invite.create", json!({"way": "relay"}));
    let replies = [a.reply(first), a.reply(second)];
    let made = replies.iter().filter(|r| r.get("error").is_none()).count();
    assert_eq!(made, 1, "{replies:?}");
    assert!(
        replies.iter().any(|r| r["reason"] == "relay_capacity"),
        "{replies:?}"
    );
}

/// While networking is paused every way says so, and none can be chosen.
#[test]
fn a_pause_hides_every_way() {
    let mut p = pair_up("iw-pause", &[("REMOVAL_RETRY_MS", "60000")], &[]);
    let b_identity = p.b.identity.clone();
    let grants = p.a.call("grants.list", json!({}));
    let grant = grants["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["identity"] == b_identity.as_str())
        .unwrap()["grant"]
        .clone();
    let table = p.a_end.dir.join("grants.json");
    std::fs::remove_file(&table).unwrap();
    std::fs::create_dir_all(table.join("in-the-way")).unwrap();
    let removed = p.a.call("grant.remove", json!({"grant": grant}));
    assert_eq!(removed["paused"], true);
    p.a.event("net.paused", |_| true);
    let available = p.a.call("routes.available", json!({}));
    for w in available["ways"].as_array().unwrap() {
        assert_eq!(w["state"], "unavailable", "{available}");
        assert_eq!(w["reason"], "paused", "{available}");
        assert_eq!(w["routes"], json!([]));
    }
    let refused = p.a.request("invite.create", json!({"way": "lan"}));
    assert_eq!(refused["error"], "way_unavailable", "{refused}");
    assert_eq!(refused["reason"], "paused");
}

/// Without `routes.json`, a way the running listener actually serves
/// reports `restart_required` once a saved config turns it off or changes
/// its port.
#[test]
fn a_listener_without_routes_json_reports_restart_when_its_way_changes() {
    let end = Endpoint::init("iw-norj-lan");
    let file = interfaces_file(&end, "lo0 127.0.0.1\nutun4 100.100.9.9\n");
    let mut a = app_with_interfaces(&end, &[], 0, &file);
    hello12(&mut a);
    assert_eq!(
        way_of(&a.call("routes.available", json!({})), "lan")["state"],
        "ready"
    );
    // Saving `tailnet: true` writes `lan: false`, turning off the running LAN way.
    let saved = a.call("routes.config", json!({"tailnet": true}));
    assert_eq!(saved["restart_needed"], true, "{saved}");
    let available = a.call("routes.available", json!({}));
    assert_eq!(
        way_of(&available, "lan")["reason"],
        "restart_required",
        "{available}"
    );
    assert_eq!(
        way_of(&available, "tailnet")["reason"],
        "restart_required",
        "{available}"
    );
    let refused = a.request("invite.create", json!({"way": "lan"}));
    assert_eq!(refused["error"], "way_unavailable", "{refused}");
    assert_eq!(refused["reason"], "restart_required", "{refused}");
    // Keeping `lan: true` while setting a fixed port still needs a restart for LAN.
    a.call(
        "routes.config",
        json!({"lan": true, "tailnet": false, "port": 7443}),
    );
    let available = a.call("routes.available", json!({}));
    assert_eq!(
        way_of(&available, "lan")["reason"],
        "restart_required",
        "{available}"
    );

    // Same for a listener serving tailnet without `routes.json`.
    let tail_end = Endpoint::init("iw-norj-tail");
    let port = free_port();
    let tail_file = interfaces_file(&tail_end, "lo0 127.0.0.1\nutun4 100.100.9.9\n");
    let map = format!("{port}=tailnet");
    let mut b = app_with_interfaces(&tail_end, &[("TEST_CLASS_MAP", &map)], port, &tail_file);
    hello12(&mut b);
    assert_eq!(
        way_of(&b.call("routes.available", json!({})), "tailnet")["state"],
        "ready"
    );
    b.call("routes.config", json!({"lan": true}));
    let available = b.call("routes.available", json!({}));
    assert_eq!(
        way_of(&available, "tailnet")["reason"],
        "restart_required",
        "{available}"
    );
    let refused = b.request("invite.create", json!({"way": "tailnet"}));
    assert_eq!(refused["error"], "way_unavailable", "{refused}");
    assert_eq!(refused["reason"], "restart_required", "{refused}");
    // Keeping `tailnet: true` while changing the port still marks tailnet pending.
    b.call(
        "routes.config",
        json!({"lan": false, "tailnet": true, "port": 7443}),
    );
    let available = b.call("routes.available", json!({}));
    assert_eq!(
        way_of(&available, "tailnet")["reason"],
        "restart_required",
        "{available}"
    );
}

/// Selecting an unoffered exact `route` on `relay` reports `relay_capacity`
/// when all allow-set slots are full and `store_failed` when the grants
/// file cannot be read, rather than `route_not_offered`.
#[test]
fn a_relay_exact_route_checks_capacity_and_store_before_route_not_offered() {
    let relay = relay_fixture::TestRelay::start();
    let end = Endpoint::init("iw-rel-ex");
    let file = interfaces_file(&end, "lo0 127.0.0.1\n");
    let mut a = app_with_interfaces(&end, &[], 0, &file);
    hello12(&mut a);
    let enrolled = a.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(enrolled["relay"]["state"], "registered", "{enrolled}");

    let wrong = json!({"way": "relay", "route": "tcp://127.0.0.1:9"});
    let free = a.request("invite.create", wrong.clone());
    assert_eq!(free["error"], "way_unavailable", "{free}");
    assert_eq!(free["reason"], "route_not_offered", "{free}");

    for _ in 0..8 {
        a.call("invite.create", json!({"way": "relay"}));
    }
    let full = a.request("invite.create", wrong.clone());
    assert_eq!(full["error"], "way_unavailable", "{full}");
    assert_eq!(full["reason"], "relay_capacity", "{full}");

    let grants = end.dir.join("relay-grants.json");
    let _ = std::fs::remove_file(&grants);
    std::fs::create_dir_all(grants.join("in-the-way")).unwrap();
    let broken = a.request("invite.create", wrong);
    assert_eq!(broken["error"], "store_failed", "{broken}");
}

/// Duplicate `public` or `tunnels` entries in `routes.json` at start
/// (which `routes.config` deduplicates on save) do not mark those
/// untouched ways `restart_required` after an unrelated save.
#[test]
fn duplicate_routes_at_start_do_not_trigger_restart_required_after_unrelated_save() {
    let end = Endpoint::init("iw-dedup");
    std::fs::write(
        end.dir.join("routes.json"),
        serde_json::to_vec(&json!({
            "lan": true,
            "public": ["tcp://p1.example:7443", "tcp://P1.EXAMPLE:7443"],
            "forward_to": "127.0.0.1",
            "tunnels": [
                "wss://t.example/mousse-net/1",
                "wss://t.example:443/mousse-net/1"
            ],
        }))
        .unwrap(),
    )
    .unwrap();
    let file = interfaces_file(&end, "lo0 127.0.0.1\n");
    let mut a = app_with_interfaces(&end, &[], 0, &file);
    hello12(&mut a);

    let saved = a.call("routes.config", json!({"lan": false}));
    assert_eq!(saved["restart_needed"], true, "{saved}");
    let available = a.call("routes.available", json!({}));
    assert_eq!(
        way_of(&available, "lan")["reason"],
        "restart_required",
        "{available}"
    );
    assert_eq!(
        way_of(&available, "public")["state"],
        "ready",
        "{available}"
    );
    assert_eq!(
        way_of(&available, "public")["routes"],
        json!(["tcp://p1.example:7443"])
    );
    assert_eq!(
        way_of(&available, "tunnel")["state"],
        "ready",
        "{available}"
    );
    assert_eq!(way_of(&available, "tunnel")["routes"], json!([TUNNEL]));
    a.call("invite.create", json!({"way": "public"}));
    a.call("invite.create", json!({"way": "tunnel"}));
}
