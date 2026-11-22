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
use mousse_net_core::pairing::{Ticket, MAX_ROUTES};
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

    // No selector: the 1.1 routes, in the 1.1 order.
    let legacy = a.call("invite.create", json!({}));
    assert_eq!(routes_in(&legacy), [lan, TUNNEL.to_owned(), relay_hint]);
    assert_eq!(legacy["ways"], json!(["lan", "tunnel", "relay"]));
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

/// With eight port forwards filling a ticket, the tunnel after them is cut
/// from the 1.1 ticket but still offered when chosen; a `public` ticket
/// holds at most `MAX_ROUTES`; an exact `route` yields that one, and a
/// route outside the inventory is never added.
#[test]
fn a_later_way_survives_a_full_ticket() {
    let end = Endpoint::init("iw-cap");
    let public: Vec<String> = (1..=MAX_ROUTES)
        .map(|n| format!("tcp://p{n}.example:7443"))
        .collect();
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
        public,
        "the 1.1 ticket is the first eight"
    );

    let tunnel = a.call("invite.create", json!({"way": "tunnel"}));
    assert_eq!(routes_in(&tunnel), [TUNNEL], "{tunnel}");
    assert_eq!(tunnel["ways"], json!(["tunnel"]));

    let forwards = a.call("invite.create", json!({"way": "public"}));
    let carried = routes_in(&forwards);
    assert!(carried.len() <= MAX_ROUTES);
    assert_eq!(carried, public);

    let one = a.call(
        "invite.create",
        json!({"way": "public", "route": public[2]}),
    );
    assert_eq!(routes_in(&one), [public[2].clone()]);

    let outside = a.request(
        "invite.create",
        json!({"way": "public", "route": "tcp://p9.example:7443"}),
    );
    assert_eq!(outside["error"], "way_unavailable", "{outside}");
    // A route of another way is not this way's.
    let other = a.request("invite.create", json!({"way": "public", "route": TUNNEL}));
    assert_eq!(other["error"], "way_unavailable", "{other}");

    let available = a.call("routes.available", json!({}));
    assert_eq!(way_of(&available, "tunnel")["routes"], json!([TUNNEL]));
    assert_eq!(way_of(&available, "public")["routes"], json!(public));
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

    // Tailnet saved on, not running yet: a restart is pending for it alone.
    let saved = a.call("routes.config", json!({"tailnet": true}));
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
        json!({"way": "lan", "role": "owner"}),
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
