//! E-R3: the helper as a relay target and a relay caller, through the app
//! channel, against the loopback test relay (Phase 3 §B.4 to §B.12). The
//! check cell `phase3.relay-routes` runs this file.
//!
//! A host reached only through a relay is made by restarting it on a new
//! port: the caller's stored direct routes then fail, and it has no browse
//! source.

mod common;

use std::time::{Duration, Instant};

use common::*;
use mousse_net_core::pairing::Ticket;
use mousse_net_core::relay_wire::RelayRoute;
use mousse_net_io::relay::test_relay::{TestRelay, TestRelayConfig, TestRelayCounts};
use serde_json::{json, Value};

/// A test relay on loopback, in its own runtime.
struct Relay {
    rt: tokio::runtime::Runtime,
    relay: TestRelay,
}

impl Relay {
    fn start() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let relay = rt.block_on(TestRelay::start(TestRelayConfig::default()));
        Self { rt, relay }
    }

    fn link(&self) -> String {
        let _rt = self.rt.enter();
        self.relay.enrollment_link().to_text()
    }

    fn destination(&self) -> String {
        format!("relay://{}", self.relay.addr())
    }

    fn counts(&self) -> TestRelayCounts {
        self.relay.counts()
    }

    fn stop(&self) {
        let _rt = self.rt.enter();
        self.relay.stop();
    }
}

/// Fast re-registration and redials.
const FAST: [(&str, &str); 3] = [
    ("VIA_RELAY_RETRY_FIRST_MS", "100"),
    ("KEEP_RETRY_FIRST_MS", "100"),
    ("KEEP_RETRY_MAX_MS", "500"),
];

fn enroll(app: &mut App, relay: &Relay) -> Value {
    let reply = app.call("relay.enroll", json!({"link": relay.link()}));
    assert_eq!(reply["relay"]["state"], "registered", "{reply}");
    reply
}

/// The relay status `grants.list` shows for `identity` on `host`.
fn relay_status(host: &mut App, identity: &str) -> Value {
    let list = host.call("grants.list", json!({}));
    list["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["identity"] == identity)
        .map(|g| g["relay"].clone())
        .unwrap_or(Value::Null)
}

/// Wait until `host` lists `identity`'s caller key.
fn wait_listed(host: &mut App, identity: &str) {
    let start = Instant::now();
    while relay_status(host, identity) != "listed" {
        if start.elapsed() > WAIT {
            let logs: Vec<String> = std::fs::read_dir(host.dir.parent().unwrap())
                .unwrap()
                .flatten()
                .filter(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let host_name = host.dir.file_name().unwrap().to_string_lossy().into_owned();
                    name.get(..13) == host_name.get(..13)
                })
                .filter_map(|e| std::fs::read_to_string(e.path().join("helper.log")).ok())
                .collect();
            panic!(
                "{identity} never listed
host log: {}
all logs: {logs:#?}",
                std::fs::read_to_string(host.dir.join("helper.log")).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Restart `app` on a new port: its old direct route stops answering.
fn restart(app: &mut App, end: &Endpoint, name: &str, env: &[(&str, &str)]) {
    app.kill();
    *app = end.app(name, env);
    app.hello();
}

/// Wait for the relay to show `app`'s registration again.
fn wait_registered(app: &mut App) {
    let start = Instant::now();
    loop {
        let list = app.call("relay.list", json!({}));
        if list["relays"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["state"] == "registered")
        {
            return;
        }
        assert!(start.elapsed() < WAIT, "never registered again: {list}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `dial` until it works (the keeper may be dialling too): the outbound
/// connection's `conn.up`.
fn dial_up(from: &mut App, to: &str) -> Value {
    let start = Instant::now();
    loop {
        let reply = from.request("dial", json!({"identity": to}));
        if let Some(conn) = reply["conn"].as_u64() {
            return from.event("conn.up", |m| m["conn"] == conn);
        }
        assert!(start.elapsed() < WAIT, "dial never worked: {reply}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Send `bytes` from `from` on a new stream of `class` and read them on
/// `to`: the inbound connection on `to` that carried it.
fn carry(from: &mut App, conn: u64, to: &mut App, class: &str, bytes: &[u8]) -> u64 {
    let before = to.events("stream.incoming").len();
    let handle = from.open(conn, "mousse.rpc", class);
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
    assert_eq!(incoming["class"], class);
    incoming["conn"].as_u64().unwrap()
}

#[test]
fn app_cases_run_over_a_relay_route_with_bulk_on_its_own_connection_and_removal_closes_only_that_caller(
) {
    let relay = Relay::start();
    let a_end = Endpoint::init("rra");
    let b_end = Endpoint::init("rrb");
    let c_end = Endpoint::init("rrc");
    let mut a = a_end.app("hostA", &FAST);
    a.hello();
    enroll(&mut a, &relay);
    let mut b = b_end.app("peerB", &FAST);
    b.hello();
    let mut c = c_end.app("peerC", &FAST);
    c.hello();
    pair_apps(&mut a, &mut b);
    pair_apps(&mut a, &mut c);
    // Each caller enrolled its own caller key; each got the manifest and
    // was asked about the relay route.
    wait_listed(&mut a, &b.identity.clone());
    wait_listed(&mut a, &c.identity.clone());
    let dest = relay.destination();
    for peer in [&mut b, &mut c] {
        let offered = peer.event("peer.relay.offered", |m| {
            m["identity"] == a.identity.as_str()
        });
        assert_eq!(offered["destination"], dest.as_str());
        peer.call(
            "peer.relay.allow",
            json!({"identity": a.identity, "destination": dest}),
        );
    }

    restart(&mut a, &a_end, "hostA", &FAST);
    wait_registered(&mut a);
    let b_up = dial_up(&mut b, &a.identity.clone());
    let c_up = dial_up(&mut c, &a.identity.clone());
    for up in [&b_up, &c_up] {
        assert_eq!(up["route"]["kind"], "relay", "{up}");
        assert_eq!(up["route"]["destination"], dest.as_str());
    }
    let (b_conn, c_conn) = (
        b_up["conn"].as_u64().unwrap(),
        c_up["conn"].as_u64().unwrap(),
    );

    // Interactive on the relay connection itself.
    let calls = relay.counts().calls;
    let a_in = carry(&mut b, b_conn, &mut a, "interactive", &pattern(10_000, 1));
    let a_up = a.event("conn.up", |m| m["conn"] == a_in);
    assert_eq!(a_up["route"]["kind"], "relay");
    assert_eq!(relay.counts().calls, calls);
    // Bulk goes over a second call of class bulk: another outer
    // connection and peer session, seen on A as its own connection.
    let a_bulk = carry(&mut b, b_conn, &mut a, "bulk", &pattern(300_000, 2));
    assert_ne!(a_bulk, a_in);
    let bulk_up = a.event("conn.up", |m| m["conn"] == a_bulk);
    assert_eq!(bulk_up["route"]["class"], "relay_bulk");
    assert_eq!(relay.counts().calls, calls + 1);

    // Remove C: its relay circuit closes at once, B's stays.
    let c_grant = a.call("grants.list", json!({}))["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["identity"] == c.identity.as_str())
        .unwrap()["grant"]
        .clone();
    a.call("grant.remove", json!({"grant": c_grant}));
    c.event("conn.down", |m| m["conn"] == c_conn);
    carry(&mut b, b_conn, &mut a, "interactive", &pattern(5_000, 3));
    assert!(
        !b.events("conn.down").iter().any(|m| m["conn"] == b_conn),
        "B's relay connection closed with C's removal"
    );
    // C is not let through again.
    let again = c.request("dial", json!({"identity": a.identity}));
    assert_eq!(again["error"], "unreachable", "{again}");
    b.assert_clean();
    a.assert_clean();
}

#[test]
fn caller_keys_are_per_pairing() {
    let a_end = Endpoint::init("cka");
    let d_end = Endpoint::init("ckd");
    let b_end = Endpoint::init("ckb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut d = d_end.app("hostD", &[]);
    d.hello();
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    pair_apps(&mut a, &mut b);
    pair_apps(&mut d, &mut b);
    let on_a = peer_of(&mut b, &a.identity.clone())["relay"]["caller"].clone();
    let on_d = peer_of(&mut b, &d.identity.clone())["relay"]["caller"].clone();
    assert!(on_a.is_string() && on_d.is_string());
    assert_ne!(
        on_a, on_d,
        "one caller key for two hosts links them at a relay"
    );
}

#[test]
fn a_relay_route_is_dialled_only_once_its_destination_is_approved() {
    let one = Relay::start();
    let two = Relay::start();
    let a_end = Endpoint::init("raa");
    let b_end = Endpoint::init("rab");
    let mut a = a_end.app("hostA", &FAST);
    a.hello();
    enroll(&mut a, &one);
    enroll(&mut a, &two);
    let mut b = b_end.app("peerB", &FAST);
    b.hello();
    pair_apps(&mut a, &mut b);
    wait_listed(&mut a, &b.identity.clone());
    b.event("peer.manifest", |m| m["identity"] == a.identity.as_str());
    let routes = peer_of(&mut b, &a.identity.clone())["relay"]["routes"].clone();
    assert_eq!(routes.as_array().unwrap().len(), 2, "{routes}");
    assert!(routes
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["approved"] == false && r["from"] == "manifest"));

    restart(&mut a, &a_end, "hostA", &FAST);
    wait_registered(&mut a);
    // Nothing approved: no relay is dialled.
    let reply = b.request("dial", json!({"identity": a.identity}));
    assert_eq!(reply["error"], "unreachable", "{reply}");
    assert_eq!((one.counts().calls, two.counts().calls), (0, 0));

    // One approved, and down: the other destination is not tried.
    b.call(
        "peer.relay.allow",
        json!({"identity": a.identity, "destination": one.destination()}),
    );
    one.stop();
    let reply = b.request("dial", json!({"identity": a.identity}));
    assert_eq!(reply["error"], "unreachable", "{reply}");
    assert_eq!(
        two.counts().calls,
        0,
        "an unapproved destination was dialled"
    );

    // Approving the second lets it through.
    b.call(
        "peer.relay.allow",
        json!({"identity": a.identity, "destination": two.destination()}),
    );
    let up = dial_up(&mut b, &a.identity.clone());
    assert_eq!(up["route"]["destination"], two.destination().as_str());
    let approvals = b.call("approvals.list", json!({"identity": a.identity}));
    assert_eq!(approvals["approvals"].as_array().unwrap().len(), 2);
    assert!(approvals["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .all(|x| x["source"] == "manifest"));
    // Removing the approval stops relay dials to it.
    b.call(
        "peer.relay.disallow",
        json!({"identity": a.identity, "destination": two.destination()}),
    );
    let before = two.counts().calls;
    let conn = up["conn"].as_u64().unwrap();
    a.kill();
    b.event("conn.down", |m| m["conn"] == conn);
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(two.counts().calls, before);
}

/// A ticket with only its relay hints: the joiner can reach the host only
/// through the relay.
fn relay_only(uri: &str) -> String {
    let fragment = uri.rsplit('#').next().unwrap();
    let mut ticket = Ticket::from_fragment(fragment).unwrap();
    ticket
        .routes
        .retain(|r| RelayRoute::parse_hint(r).is_some());
    assert_eq!(ticket.routes.len(), 1, "{:?}", ticket.routes);
    ticket.to_fragment()
}

/// Join `joiner` with `ticket` through the relay `dest`, A approving.
fn join_through(
    a: &mut App,
    joiner: &mut App,
    ticket: &str,
    invitation: &str,
    dest: &str,
) -> Value {
    let id = joiner.start(
        "join",
        json!({"ticket": ticket, "pinned": true, "approved": [dest]}),
    );
    let approval = a.event("approval", |m| {
        m["invitation"] == invitation && m["identity"] == joiner.identity.as_str()
    });
    a.call(
        "approval.answer",
        json!({"request": approval["request"], "yes": true}),
    );
    joiner.reply(id)
}

#[test]
fn relay_only_pairing_recovers_with_one_grant_and_only_for_that_grant() {
    let relay = Relay::start();
    let dest = relay.destination();
    let a_end = Endpoint::init("rpa");
    let b_end = Endpoint::init("rpb");
    let d_end = Endpoint::init("rpd");
    let mut a = a_end.app("hostA", &FAST);
    a.hello();
    enroll(&mut a, &relay);
    // D is paired the usual way and so holds a grant of its own.
    let mut d = d_end.app("peerD", &FAST);
    d.hello();
    pair_apps(&mut a, &mut d);

    // B joins through the relay only, and its circuit drops after PAIRED,
    // before its caller key went over (held back by the test hook).
    let no_keys = [("MOUSSE_HELPER_TEST_NO_KEYS", std::path::Path::new("1"))];
    let mut b = b_end.app_raw("peerB", &FAST, 0, &no_keys);
    b.hello();
    let invite = a.call("invite.create", json!({}));
    let invitation = invite["invitation"].as_str().unwrap().to_owned();
    let ticket = relay_only(invite["uri"].as_str().unwrap());
    let join = join_through(&mut a, &mut b, &ticket, &invitation, &dest);
    assert!(
        join.get("error").is_none(),
        "{join}
A: {}
B: {}",
        a_end.log(),
        b_end.log()
    );
    let up = b.event("conn.up", |m| m["conn"] == join["conn"]);
    assert_eq!(up["route"]["kind"], "relay");
    assert_eq!(relay_status(&mut a, &b.identity.clone()), "no_key");
    b.kill();

    // Back without the hook: B can't CALL (its key is not listed), so it
    // comes back by JOIN with the ticket's tag on its grant, sends its key,
    // and the circuit is promoted.
    let mut b = b_end.app("peerB", &FAST);
    b.hello();
    let up = dial_up(&mut b, &a.identity.clone());
    assert_eq!(up["route"]["kind"], "relay");
    let start = Instant::now();
    while relay_status(&mut a, &b.identity.clone()) != "listed" {
        assert!(
            start.elapsed() < WAIT,
            "B never listed
A: {}
B: {}",
            a_end.log(),
            b_end.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    b.event("peer.keys", |m| m["identity"] == a.identity.as_str());
    assert!(peer_of(&mut b, &a.identity.clone())["relay"]["keys"] == true);
    let grants = a.call("grants.list", json!({}))["grants"].clone();
    let for_b = grants
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["identity"] == b.identity.as_str())
        .count();
    assert_eq!(for_b, 1, "recovery made a second grant: {grants}");

    // The recovery entry is gone: the stolen ticket gets nobody through,
    // not even a device that holds a grant of its own.
    let reply = d.request(
        "join",
        json!({"ticket": ticket, "pinned": true, "approved": [dest]}),
    );
    assert!(reply.get("error").is_some(), "{reply}");
    let grants_after = a.call("grants.list", json!({}))["grants"].clone();
    assert_eq!(grants_after.as_array().unwrap().len(), 2);
}

#[test]
fn a_grant_rides_a_recovery_circuit_only_for_its_own_invitation() {
    let relay = Relay::start();
    let dest = relay.destination();
    let a_end = Endpoint::init("rqa");
    let b_end = Endpoint::init("rqb");
    let d_end = Endpoint::init("rqd");
    let mut a = a_end.app("hostA", &FAST);
    a.hello();
    enroll(&mut a, &relay);
    let mut d = d_end.app("peerD", &FAST);
    d.hello();
    pair_apps(&mut a, &mut d);
    let no_keys = [("MOUSSE_HELPER_TEST_NO_KEYS", std::path::Path::new("1"))];
    let mut b = b_end.app_raw("peerB", &FAST, 0, &no_keys);
    b.hello();
    let invite = a.call("invite.create", json!({}));
    let invitation = invite["invitation"].as_str().unwrap().to_owned();
    let ticket = relay_only(invite["uri"].as_str().unwrap());
    let join = join_through(&mut a, &mut b, &ticket, &invitation, &dest);
    assert!(join.get("error").is_none(), "{join}");

    // While B's recovery entry is listed, D (granted, holding the leaked
    // ticket) rides a join circuit: A closes it.
    let reply = d.request(
        "join",
        json!({"ticket": ticket, "pinned": true, "approved": [dest]}),
    );
    if let Some(conn) = reply["conn"].as_u64() {
        let down = d.event("conn.down", |m| m["conn"] == conn);
        assert!(
            down["reason"]
                .as_str()
                .is_some_and(|r| r.eq_ignore_ascii_case("invitation_invalid")),
            "{down}"
        );
    } else {
        assert!(reply.get("error").is_some(), "{reply}");
    }
    let grants = a.call("grants.list", json!({}))["grants"].clone();
    assert_eq!(grants.as_array().unwrap().len(), 2, "{grants}");
}

#[test]
fn removals_reach_the_relay_after_a_restart_too() {
    let relay = Relay::start();
    let a_end = Endpoint::init("rja");
    let b_end = Endpoint::init("rjb");
    let mut a = a_end.app("hostA", &FAST);
    a.hello();
    enroll(&mut a, &relay);
    let mut b = b_end.app("peerB", &FAST);
    b.hello();
    pair_apps(&mut a, &mut b);
    wait_listed(&mut a, &b.identity.clone());
    let grant = a.call("grants.list", json!({}))["grants"][0]["grant"].clone();
    // A crash right after the removal was journaled: the replay at start
    // runs before any registration, so the relay never lists B again.
    std::fs::write(
        a_end.dir.join("revoke.journal"),
        serde_json::to_vec(&json!({"version": 1, "revoke": [grant]})).unwrap(),
    )
    .unwrap();
    a.kill();
    let mut a = a_end.app("hostA", &FAST);
    a.hello();
    wait_registered(&mut a);
    let handles = relay.relay.handles();
    assert_eq!(handles.len(), 1);
    let set = relay.relay.allow_set(&handles[0]).unwrap();
    assert!(set.callers.is_empty(), "{set:?}");
}
