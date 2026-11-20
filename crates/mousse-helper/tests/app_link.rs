//! "Send link" in app mode (Phase 1b §5): the host's code and attempts, the
//! joiner's code entry, every tampered field of §5.5, swapped links that
//! must never end "already paired", completion records and their replay,
//! and crashes at each point of a link join.
//!
//! Helpers run `serve --app` on loopback. Crashes use the debug-build hook
//! `MOUSSE_HELPER_TEST_CRASH`, which stops the helper at a named point.

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use mousse_net_core::grants::OwnerRef;
use mousse_net_core::identity::SoftwareKey;
use mousse_net_core::pairing::{
    BindingTranscript, CodeExchange, CodeExchangeFactory, ExchangeError, ExchangeRole,
    ExchangeStep, InvitationId, InvitationKind, PairingCode, Ticket, TicketSecret, SID_LEN,
};
use mousse_net_core::UnixTime;
use mousse_net_io::pipe::accept_tcp;
use mousse_net_io::store::{hex, identity_from_hex};
use mousse_net_io::{Host, HostConfig, SystemClock};
use serde_json::{json, Value};

/// A helper on a new endpoint, greeted with protocol 1.1. Bind the result
/// as `(end, app)` so the app stops before its folder goes.
fn start(tag: &str, name: &str) -> (Endpoint, App) {
    let end = Endpoint::init(tag);
    let mut app = end.app(name, &[]);
    hello(&mut app);
    (end, app)
}

fn hello(app: &mut App) -> Value {
    let name = app.name.clone();
    let reply = app.call("hello", json!({"proto": [1, 1], "name": name}));
    app.identity = reply["identity"].as_str().unwrap().to_owned();
    reply
}

/// The helper on `end` again, as after a restart.
fn again(end: &Endpoint, name: &str) -> App {
    let mut app = end.app(name, &[]);
    hello(&mut app);
    app
}

/// The helper on `end`, set to stop at `point`.
fn crashing(end: &Endpoint, name: &str, point: &str) -> App {
    let mut app = end.app_raw(
        name,
        &[],
        0,
        &[("MOUSSE_HELPER_TEST_CRASH", Path::new(point))],
    );
    hello(&mut app);
    app
}

/// A link invitation on `host`: the reply, its ticket and invitation id.
struct Link {
    invite: Value,
    ticket: Ticket,
    inv: String,
}

impl Link {
    fn uri(&self) -> String {
        self.invite["uri"].as_str().unwrap().to_owned()
    }

    fn route(&self) -> String {
        self.invite["routes"][0].as_str().unwrap().to_owned()
    }

    fn code(&self) -> String {
        self.invite["code"].as_str().unwrap().to_owned()
    }
}

fn link(host: &mut App) -> Link {
    let invite = host.call("invite.create", json!({"kind": "link"}));
    let ticket = Ticket::from_fragment(invite["uri"].as_str().unwrap()).unwrap();
    let inv = invite["invitation"].as_str().unwrap().to_owned();
    Link {
        invite,
        ticket,
        inv,
    }
}

fn hash_of(ticket: &Ticket) -> String {
    hex(&ticket.hash())
}

fn status(app: &mut App, ticket: &Ticket) -> Value {
    app.call("join.status", json!({"ticket_hash": hash_of(ticket)}))
}

/// Start a link join of `uri` with `fields` added: the request id.
fn join(app: &mut App, uri: &str, fields: Value) -> u64 {
    let mut request = json!({"ticket": uri, "arrival": "link"});
    for (k, v) in fields.as_object().unwrap() {
        request[k] = v.clone();
    }
    app.start("join", request)
}

/// The `n`th (from 0) event `ev` for invitation `inv`.
fn nth(app: &App, ev: &str, inv: &str, n: usize) -> Value {
    app.wait(&format!("{ev} #{n} for {inv}"), WAIT, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == ev && m["invitation"] == inv)
            .nth(n)
            .cloned()
    })
}

fn count(app: &App, ev: &str, inv: &str) -> usize {
    app.events(ev)
        .iter()
        .filter(|m| m["invitation"] == inv)
        .count()
}

/// The code the host shows once `left` attempts are left.
fn code_with(host: &App, inv: &str, left: u64) -> String {
    host.wait(&format!("the code with {left} tries left"), WAIT, |st| {
        st.messages
            .iter()
            .find(|m| {
                m["ev"] == "invite.code" && m["invitation"] == inv && m["attempts_left"] == left
            })
            .map(|m| m["code"].as_str().unwrap().to_owned())
    })
}

/// A six-digit code that differs from `code` in every digit.
fn wrong(code: &str) -> String {
    code.bytes()
        .map(|d| char::from(b'0' + (d - b'0' + 1) % 10))
        .collect()
}

fn type_code(app: &mut App, inv: &str, code: &str) {
    app.call("join.code", json!({"invitation": inv, "code": code}));
}

fn grants(app: &mut App) -> Vec<Value> {
    app.call("grants.list", json!({}))["grants"]
        .as_array()
        .unwrap()
        .clone()
}

fn grants_for(app: &mut App, identity: &str) -> Vec<Value> {
    grants(app)
        .into_iter()
        .filter(|g| g["identity"] == identity)
        .collect()
}

fn approvals(dir: &Path) -> Vec<Value> {
    match std::fs::read(dir.join("approvals.json")) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes).unwrap()["approvals"]
            .as_array()
            .unwrap()
            .clone(),
        Err(_) => Vec::new(),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A loopback address that takes connections and drops each at once: a
/// dial there shows up in `accepted`.
fn dead_end() -> Gate {
    let gate = gate_to("tcp://127.0.0.1:1");
    gate.open();
    gate
}

/// A moment for a dial that should not happen to show up.
fn settle_a_moment() {
    std::thread::sleep(Duration::from_millis(500));
}

/// Pair `a` with `b` by link; returns the link.
fn pair_by_link(a: &mut App, b: &mut App, approved: &[&str]) -> Link {
    let l = link(b);
    let id = join(a, &l.uri(), json!({"approved": approved}));
    nth(a, "join.code_needed", &l.inv, 0);
    type_code(a, &l.inv, &l.code());
    let reply = a.reply(id);
    assert!(reply.get("error").is_none(), "{reply}");
    l
}

#[test]
fn a_link_pairs_with_the_code_the_host_shows_and_no_tap() {
    let (_be, mut b) = start("lk-pair-b", "hostB");
    let (_ae, mut a) = start("lk-pair-a", "peerA");
    let l = link(&mut b);
    let code = l.code();
    assert!(
        code.len() == 6 && code.bytes().all(|c| c.is_ascii_digit()),
        "{}",
        l.invite
    );
    assert_eq!(l.invite["attempts_left"], 3);
    assert!(l.invite["expires_at"].as_u64().unwrap() > now_secs());
    assert_eq!(l.ticket.kind, InvitationKind::SendLink);

    let route = l.route();
    let id = join(&mut a, &l.uri(), json!({"approved": [route]}));
    let needed = nth(&a, "join.code_needed", &l.inv, 0);
    assert_eq!(needed["attempts_left"], 3);
    // Typed as shown, with the space.
    type_code(&mut a, &l.inv, &format!("{} {}", &code[..3], &code[3..]));
    let reply = a.reply(id);
    assert!(reply.get("error").is_none(), "{reply}");
    assert_eq!(reply["identity"], b.identity.as_str());
    assert_eq!(reply["name"], "hostB");
    assert_eq!(reply["role"], "owner");
    assert_eq!(reply["already"], false);
    assert_eq!(reply["ticket_hash"], hash_of(&l.ticket));

    b.event("enrolled", |m| m["invitation"] == l.inv.as_str());
    assert!(
        b.events("approval").is_empty(),
        "a link never asks for a tap"
    );
    let granted = grants_for(&mut b, &a.identity.clone());
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0]["name"], "peerA");
    assert_eq!(granted[0]["receipt"], l.inv.as_str());

    let s = status(&mut a, &l.ticket);
    assert_eq!(s["done"]["identity"], b.identity.as_str(), "{s}");
    assert_eq!(s["done"]["name"], "hostB");
    assert_eq!(s["done"]["role"], "owner");
    assert_eq!(s["pending"], false);
    let peer = peer_of(&mut a, &b.identity.clone());
    assert_eq!(peer["routes"], json!(l.ticket.routes));
    let kept = approvals(&a.dir);
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(kept[0]["identity"], b.identity.as_str());
    assert_eq!(kept[0]["destination"], route.as_str());
    assert_eq!(kept[0]["source"], "ticket");

    let ack = a.call("join.ack", json!({"ticket_hash": hash_of(&l.ticket)}));
    assert_eq!(ack["removed"], true);
    assert_eq!(status(&mut a, &l.ticket)["done"], Value::Null);
    // The pairing itself stays.
    assert_eq!(peer_of(&mut a, &b.identity.clone())["name"], "hostB");
}

#[test]
fn each_attempt_gets_a_new_code() {
    let (_be, mut b) = start("lk-new-b", "hostB");
    let (_ae, mut a) = start("lk-new-a", "peerA");
    let l = link(&mut b);
    let first = l.code();
    let id = join(&mut a, &l.uri(), json!({}));
    nth(&a, "join.code_needed", &l.inv, 0);
    assert_eq!(code_with(&b, &l.inv, 3), first);
    type_code(&mut a, &l.inv, &wrong(&first));
    let failed = nth(&a, "join.attempt_failed", &l.inv, 0);
    assert_eq!(failed["attempts_left"], 2);
    let second = code_with(&b, &l.inv, 2);
    assert_ne!(second, first, "the failed attempt's code is shown again");
    type_code(&mut a, &l.inv, &second);
    let reply = a.reply(id);
    assert!(reply.get("error").is_none(), "{reply}");
}

/// Three wrong codes on a link join of `l`; returns the join's reply.
fn three_wrong(a: &mut App, b: &App, l: &Link) -> Value {
    let id = join(a, &l.uri(), json!({}));
    nth(a, "join.code_needed", &l.inv, 0);
    type_code(a, &l.inv, &wrong(&l.code()));
    assert_eq!(nth(a, "join.attempt_failed", &l.inv, 0)["attempts_left"], 2);
    type_code(a, &l.inv, &wrong(&code_with(b, &l.inv, 2)));
    assert_eq!(nth(a, "join.attempt_failed", &l.inv, 1)["attempts_left"], 1);
    type_code(a, &l.inv, &wrong(&code_with(b, &l.inv, 1)));
    a.reply(id)
}

#[test]
fn three_wrong_codes_end_the_invitation_and_the_flow() {
    let (_be, mut b) = start("lk-three-b", "hostB");
    let (_ae, mut a) = start("lk-three-a", "peerA");
    let l = link(&mut b);
    let reply = three_wrong(&mut a, &b, &l);
    assert_eq!(reply["error"], "attempts_exhausted", "{reply}");
    let ended = b.event("invite.ended", |m| m["invitation"] == l.inv.as_str());
    assert_eq!(ended["reason"], "attempts_exhausted");
    assert!(grants(&mut b).is_empty());
    assert_eq!(status(&mut a, &l.ticket)["attempts_left"], 0);
}

#[test]
fn an_exhausted_link_fails_again_on_both_sides() {
    let (_be, mut b) = start("lk-again-b", "hostB");
    let (_ae, mut a) = start("lk-again-a", "peerA");
    let (_de, mut d) = start("lk-again-d", "peerD");
    let l = link(&mut b);
    assert_eq!(three_wrong(&mut a, &b, &l)["error"], "attempts_exhausted");
    // This side: from the flow record, before dialling.
    let gone = a.request("join", json!({"ticket": l.uri(), "arrival": "link"}));
    assert_eq!(gone["error"], "attempts_exhausted", "{gone}");
    // The host: the invitation is gone, for any device.
    let other = d.request("join", json!({"ticket": l.uri(), "arrival": "link"}));
    assert_eq!(other["error"], "invitation_invalid", "{other}");
    assert!(grants(&mut b).is_empty());
}

#[test]
fn a_restart_mid_code_keeps_the_joiners_count() {
    let (_be, mut b) = start("lk-restart-b", "hostB");
    let (ae, mut a) = start("lk-restart-a", "peerA");
    let l = link(&mut b);
    join(&mut a, &l.uri(), json!({}));
    nth(&a, "join.code_needed", &l.inv, 0);
    type_code(&mut a, &l.inv, &wrong(&l.code()));
    assert_eq!(
        nth(&a, "join.attempt_failed", &l.inv, 0)["attempts_left"],
        2
    );
    a.kill();
    let mut a = again(&ae, "peerA");
    assert_eq!(status(&mut a, &l.ticket)["attempts_left"], 2);
    let id = join(&mut a, &l.uri(), json!({}));
    assert_eq!(nth(&a, "join.code_needed", &l.inv, 0)["attempts_left"], 2);
    type_code(&mut a, &l.inv, &code_with(&b, &l.inv, 2));
    let reply = a.reply(id);
    assert!(reply.get("error").is_none(), "{reply}");
}

#[test]
fn a_reconnect_keeps_the_hosts_count() {
    let (_be, mut b) = start("lk-recon-b", "hostB");
    let (_ae, mut a) = start("lk-recon-a", "peerA");
    let l = link(&mut b);
    join(&mut a, &l.uri(), json!({}));
    nth(&a, "join.code_needed", &l.inv, 0);
    type_code(&mut a, &l.inv, &wrong(&l.code()));
    nth(&a, "join.attempt_failed", &l.inv, 0);
    // Shown when the attempt started: the next code, 2 left.
    assert_eq!(nth(&b, "invite.code", &l.inv, 1)["attempts_left"], 2);
    a.call("join.cancel", json!({"invitation": l.inv}));
    let id = join(&mut a, &l.uri(), json!({}));
    assert_eq!(nth(&a, "join.code_needed", &l.inv, 1)["attempts_left"], 2);
    // Shown again for the new connection: still 2 left.
    let shown = nth(&b, "invite.code", &l.inv, 2);
    assert_eq!(
        shown["attempts_left"], 2,
        "a reconnect gave the host its tries back"
    );
    type_code(&mut a, &l.inv, shown["code"].as_str().unwrap());
    let reply = a.reply(id);
    assert!(reply.get("error").is_none(), "{reply}");
}

#[test]
fn a_code_that_is_not_six_digits_spends_no_attempt() {
    let (_be, mut b) = start("lk-bad-b", "hostB");
    let (_ae, mut a) = start("lk-bad-a", "peerA");
    let l = link(&mut b);
    assert_eq!(
        a.request("join.code", json!({"invitation": l.inv, "code": "123456"}))["error"],
        "no_join"
    );
    let id = join(&mut a, &l.uri(), json!({}));
    nth(&a, "join.code_needed", &l.inv, 0);
    for bad in ["12a456", "12345", "1234567", ""] {
        let reply = a.request("join.code", json!({"invitation": l.inv, "code": bad}));
        assert_eq!(reply["error"], "bad_code", "{bad:?}: {reply}");
    }
    assert!(a.events("join.attempt_failed").is_empty());
    // No attempt started on the host either: no new code after the one
    // shown again when A was let in.
    nth(&b, "invite.code", &l.inv, 0);
    settle_a_moment();
    assert_eq!(count(&b, "invite.code", &l.inv), 1);
    type_code(&mut a, &l.inv, &l.code());
    let reply = a.reply(id);
    assert!(reply.get("error").is_none(), "{reply}");
}

#[test]
fn a_link_changed_to_in_person_is_refused_before_dialling() {
    let (_be, mut b) = start("lk-kind-b", "hostB");
    let (_ae, mut a) = start("lk-kind-a", "peerA");
    let gate = dead_end();
    let mut t = link(&mut b).ticket;
    t.kind = InvitationKind::InPerson;
    t.routes = vec![gate.route.clone()];
    let reply = a.request(
        "join",
        json!({"ticket": t.to_fragment(), "arrival": "link"}),
    );
    assert_eq!(reply["error"], "pairing_failed", "{reply}");
    // An in-person ticket as made also needs a scan.
    let invite = b.call("invite.create", json!({"kind": "in_person"}));
    let mut t = Ticket::from_fragment(invite["uri"].as_str().unwrap()).unwrap();
    t.routes = vec![gate.route.clone()];
    let reply = a.request(
        "join",
        json!({"ticket": t.to_fragment(), "arrival": "link"}),
    );
    assert_eq!(reply["error"], "pairing_failed", "{reply}");
    settle_a_moment();
    assert_eq!(gate.accepted.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn a_damaged_link_is_refused() {
    let (_be, mut b) = start("lk-damaged-b", "hostB");
    let (_ae, mut a) = start("lk-damaged-a", "peerA");
    let uri = link(&mut b).uri();
    for bad in [
        "not a link!".to_owned(),
        uri[..uri.len() / 2].to_owned(),
        format!("{uri}AA"),
    ] {
        let reply = a.request("join", json!({"ticket": bad, "arrival": "link"}));
        assert_eq!(reply["error"], "bad_ticket", "{bad}: {reply}");
    }
    assert!(b.events("invite.code").is_empty());
}

#[test]
fn a_link_past_its_expiry_is_refused_before_dialling() {
    let (_be, mut b) = start("lk-past-b", "hostB");
    let (_ae, mut a) = start("lk-past-a", "peerA");
    let gate = dead_end();
    let mut t = link(&mut b).ticket;
    t.expires_at = UnixTime(now_secs() - 3_600);
    t.routes = vec![gate.route.clone()];
    let reply = a.request(
        "join",
        json!({"ticket": t.to_fragment(), "arrival": "link"}),
    );
    assert_eq!(reply["error"], "expired", "{reply}");
    settle_a_moment();
    assert_eq!(gate.accepted.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(status(&mut a, &t)["pending"], false);
}

#[test]
fn a_changed_secret_or_invitation_spends_no_attempt() {
    let (_be, mut b) = start("lk-secret-b", "hostB");
    let (_ae, mut a) = start("lk-secret-a", "peerA");
    let l = link(&mut b);
    let mut secret = l.ticket.clone();
    secret.secret = TicketSecret::from_bytes([9; 16]);
    let mut invitation = l.ticket.clone();
    invitation.invitation = InvitationId([7; 16]);
    for t in [&secret, &invitation] {
        let reply = a.request(
            "join",
            json!({"ticket": t.to_fragment(), "arrival": "link"}),
        );
        assert_eq!(reply["error"], "invitation_invalid", "{reply}");
        let s = status(&mut a, t);
        assert_eq!(s["attempts_left"], 3, "{s}");
        assert_eq!(s["pending"], false);
    }
    // The host spent nothing either: the real link still has 3.
    assert!(b.events("invite.code").is_empty());
    let id = join(&mut a, &l.uri(), json!({}));
    assert_eq!(nth(&a, "join.code_needed", &l.inv, 0)["attempts_left"], 3);
    assert_eq!(nth(&b, "invite.code", &l.inv, 0)["attempts_left"], 3);
    type_code(&mut a, &l.inv, &l.code());
    let reply = a.reply(id);
    assert!(reply.get("error").is_none(), "{reply}");
}

/// A changed field the join proof does not cover: the ticket hash differs,
/// so the code exchange fails and one attempt goes on each side.
fn one_attempt_each(tag: &str, change: impl FnOnce(&mut Ticket)) {
    let (_be, mut b) = start(&format!("{tag}-b"), "hostB");
    let (_ae, mut a) = start(&format!("{tag}-a"), "peerA");
    let l = link(&mut b);
    let mut t = l.ticket.clone();
    change(&mut t);
    assert_ne!(t.hash(), l.ticket.hash());
    let id = join(&mut a, &t.to_fragment(), json!({}));
    assert_eq!(nth(&a, "join.code_needed", &l.inv, 0)["attempts_left"], 3);
    // The code the host shows, typed exactly.
    type_code(&mut a, &l.inv, &l.code());
    assert_eq!(
        nth(&a, "join.attempt_failed", &l.inv, 0)["attempts_left"],
        2
    );
    assert_eq!(nth(&b, "invite.code", &l.inv, 1)["attempts_left"], 2);
    a.call("join.cancel", json!({"invitation": l.inv}));
    assert_eq!(a.reply(id)["error"], "cancelled");
    assert!(grants(&mut b).is_empty());
    assert_eq!(peer_of(&mut a, &b.identity.clone()), Value::Null);
}

#[test]
fn a_changed_route_hint_spends_one_attempt_on_each_side() {
    one_attempt_each("lk-hint", |t| t.routes.push("tcp://127.0.0.1:9".into()));
}

#[test]
fn a_changed_expiry_spends_one_attempt_on_each_side() {
    one_attempt_each("lk-exp", |t| t.expires_at = t.expires_at.plus(60));
}

/// B's link with C's key and address in it, as a swap in transit would
/// leave it. C already grants A, so it answers A's proof
/// `AUTHORIZED {live}`.
fn swapped(a: &mut App, b: &mut App, c: &mut App) -> Ticket {
    let (identity, name) = (a.identity.clone(), a.name.clone());
    c.call("grant.add", json!({"identity": identity, "name": name}));
    let route = hello(c)["routes"][0].as_str().unwrap().to_owned();
    let mut t = link(b).ticket;
    t.host_identity = identity_from_hex(&c.identity).unwrap();
    t.routes = vec![route];
    t
}

#[test]
fn a_swapped_link_never_ends_already_paired() {
    let (_be, mut b) = start("lk-swap-b", "hostB");
    let (_ce, mut c) = start("lk-swap-c", "fakeC");
    let (_ae, mut a) = start("lk-swap-a", "peerA");
    let t = swapped(&mut a, &mut b, &mut c);
    // `pinned`, as the app sends it for its consented row: ignored here.
    let reply = a.request(
        "join",
        json!({"ticket": t.to_fragment(), "arrival": "link", "pinned": true}),
    );
    assert_eq!(reply["error"], "pairing_failed", "{reply}");
    assert_eq!(peer_of(&mut a, &c.identity.clone()), Value::Null);
    let s = status(&mut a, &t);
    assert_eq!(s["done"], Value::Null);
    assert_eq!(s["pending"], false);
}

#[test]
fn an_expired_swapped_link_ends_expired_with_no_pending_outcome() {
    let (_be, mut b) = start("lk-swapx-b", "hostB");
    let (_ce, mut c) = start("lk-swapx-c", "fakeC");
    let (_ae, mut a) = start("lk-swapx-a", "peerA");
    let mut t = swapped(&mut a, &mut b, &mut c);
    t.expires_at = UnixTime(now_secs() - 3_600);
    let reply = a.request(
        "join",
        json!({"ticket": t.to_fragment(), "arrival": "link", "pinned": true}),
    );
    assert_eq!(reply["error"], "expired", "{reply}");
    assert_eq!(peer_of(&mut a, &c.identity.clone()), Value::Null);
    let s = status(&mut a, &t);
    assert_eq!(s["done"], Value::Null);
    assert_eq!(s["pending"], false);
}

#[test]
fn a_swapped_links_code_fails_and_the_real_invitation_is_untouched() {
    let (_be, mut b) = start("lk-swapc-b", "hostB");
    let (_ce, mut c) = start("lk-swapc-c", "fakeC");
    let (_ae, mut a) = start("lk-swapc-a", "peerA");
    let real = link(&mut b);
    // C's own link reached A in place of B's; A types B's code.
    let fake = link(&mut c);
    let id = join(&mut a, &fake.uri(), json!({"pinned": true}));
    nth(&a, "join.code_needed", &fake.inv, 0);
    type_code(&mut a, &fake.inv, &real.code());
    assert_eq!(
        nth(&a, "join.attempt_failed", &fake.inv, 0)["attempts_left"],
        2
    );
    a.call("join.cancel", json!({"invitation": fake.inv}));
    assert_eq!(a.reply(id)["error"], "cancelled");
    assert!(grants(&mut c).is_empty());
    assert_eq!(peer_of(&mut a, &c.identity.clone()), Value::Null);
    // B never saw A: its link still pairs with its first code.
    assert!(b.events("invite.code").is_empty());
    let id = join(&mut a, &real.uri(), json!({}));
    assert_eq!(
        nth(&a, "join.code_needed", &real.inv, 0)["attempts_left"],
        3
    );
    assert_eq!(nth(&b, "invite.code", &real.inv, 0)["attempts_left"], 3);
    type_code(&mut a, &real.inv, &real.code());
    let reply = a.reply(id);
    assert!(reply.get("error").is_none(), "{reply}");
}

/// A code exchange that claims the peer confirmed at once and sends
/// nothing: a host that enrolls without the joiner's key confirmation.
#[derive(Clone, Copy)]
struct NoConfirm;

struct NoConfirmExchange;

impl CodeExchange for NoConfirmExchange {
    fn step(&mut self, _incoming: Option<&[u8]>) -> Result<ExchangeStep, ExchangeError> {
        Ok(ExchangeStep {
            send: None,
            peer_confirmed: true,
        })
    }
}

impl CodeExchangeFactory for NoConfirm {
    type Exchange = NoConfirmExchange;

    fn start<R: rand_core::CryptoRng + ?Sized>(
        &self,
        _role: ExchangeRole,
        _code: &PairingCode,
        _binding: &BindingTranscript,
        _sid: &[u8; SID_LEN],
        _rng: &mut R,
    ) -> NoConfirmExchange {
        NoConfirmExchange
    }
}

#[test]
fn a_host_that_skips_the_code_confirmation_pairs_nothing() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (uri, _host, _events) = rt.block_on(async {
        let signer: mousse_net_io::SharedSigner =
            Arc::new(SoftwareKey::generate(&mut mousse_net_io::rng::os_rng()));
        let config = HostConfig {
            name: "fake host".into(),
            state_dir: None,
            owner: OwnerRef::from_bytes([0x5a; 16]),
            limits: mousse_net_io::Limits::DEFAULT,
            clock: Arc::new(SystemClock::new()),
            ticket_identity: None,
            streams: None,
        };
        let (host, events) = Host::new(signer, config, NoConfirm).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let route = format!("tcp://{}", listener.local_addr().unwrap());
        let serving = host.clone();
        tokio::spawn(async move {
            while let Ok((pipe, _)) = accept_tcp(&listener).await {
                let host = serving.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = host.accept(pipe).await {
                        while conn.accept_stream().await.is_some() {}
                    }
                });
            }
        });
        let created = host.invite(InvitationKind::SendLink, vec![route]).unwrap();
        (created.fragment, host, events)
    });
    let ticket = Ticket::from_fragment(&uri).unwrap();
    let inv = hex(&ticket.invitation.0);
    let (_ae, mut a) = start("lk-noconf-a", "peerA");
    let id = join(&mut a, &uri, json!({}));
    nth(&a, "join.code_needed", &inv, 0);
    type_code(&mut a, &inv, "123456");
    let reply = a.reply(id);
    assert!(
        reply.get("error").is_some(),
        "paired without the code: {reply}"
    );
    let fake = hex(ticket.host_identity.as_bytes());
    assert_eq!(peer_of(&mut a, &fake), Value::Null);
    assert_eq!(status(&mut a, &ticket)["done"], Value::Null);
}

#[test]
fn a_crash_after_the_confirmation_recovers_from_the_pending_record() {
    let (_be, mut b) = start("lk-lost-b", "hostB");
    let ae = Endpoint::init("lk-lost-a");
    let mut a = crashing(&ae, "peerA", "link-paired");
    let l = link(&mut b);
    join(&mut a, &l.uri(), json!({}));
    nth(&a, "join.code_needed", &l.inv, 0);
    type_code(&mut a, &l.inv, &l.code());
    assert_eq!(a.exit_within(WAIT), Some(86), "{}", a.err());
    b.event("enrolled", |m| m["invitation"] == l.inv.as_str());

    let mut a = again(&ae, "peerA");
    let s = status(&mut a, &l.ticket);
    assert_eq!(s["done"], Value::Null, "{s}");
    assert_eq!(s["pending"], true, "{s}");
    // Repeating the join learns the outcome from the host's receipt.
    let reply = a.request("join", json!({"ticket": l.uri(), "arrival": "link"}));
    assert!(reply.get("error").is_none(), "{reply}");
    assert_eq!(reply["already"], false);
    assert_eq!(reply["identity"], b.identity.as_str());
    let s = status(&mut a, &l.ticket);
    assert_eq!(s["done"]["identity"], b.identity.as_str(), "{s}");
    assert_eq!(s["pending"], false);
    assert_eq!(grants_for(&mut b, &a.identity.clone()).len(), 1);
}

/// A link join that stops right after its completion record is written:
/// the host has enrolled A, A's `peers.json` does not hold B yet. Returns
/// A's endpoint and the link.
fn stopped_after_record(tag: &str, b: &mut App) -> (Endpoint, Link) {
    let ae = Endpoint::init(tag);
    let mut a = crashing(&ae, "peerA", "link-done-saved");
    let l = link(b);
    join(&mut a, &l.uri(), json!({"approved": [l.route()]}));
    nth(&a, "join.code_needed", &l.inv, 0);
    type_code(&mut a, &l.inv, &l.code());
    assert_eq!(a.exit_within(WAIT), Some(86), "{}", a.err());
    b.event("enrolled", |m| m["invitation"] == l.inv.as_str());
    drop(a);
    (ae, l)
}

#[test]
fn a_crash_after_the_completion_record_is_replayed_with_routes_and_approvals() {
    let (_be, mut b) = start("lk-replay-b", "hostB");
    let (ae, l) = stopped_after_record("lk-replay-a", &mut b);
    let mut a = again(&ae, "peerA");
    assert_eq!(peer_of(&mut a, &b.identity.clone()), Value::Null);
    let s = status(&mut a, &l.ticket);
    assert_eq!(s["done"]["identity"], b.identity.as_str(), "{s}");
    assert_eq!(s["done"]["name"], "hostB");
    assert_eq!(s["done"]["role"], "owner");
    let peer = peer_of(&mut a, &b.identity.clone());
    assert_eq!(peer["routes"], json!(l.ticket.routes), "{peer}");
    assert_eq!(peer["last_route"], l.route().as_str());
    let kept = approvals(&a.dir);
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(kept[0]["identity"], b.identity.as_str());
    assert_eq!(kept[0]["destination"], l.route().as_str());
    // Replaying again changes nothing.
    status(&mut a, &l.ticket);
    assert_eq!(peer_of(&mut a, &b.identity.clone()), peer);
    assert_eq!(approvals(&a.dir), kept);
    // And the replayed peer can be dialled.
    let identity = b.identity.clone();
    a.call("dial", json!({"identity": identity}));
}

#[test]
fn a_replay_after_a_restart_clears_the_durable_pending_mark() {
    let (_be, mut b) = start("lk-mark-b", "hostB");
    let (ae, l) = stopped_after_record("lk-mark-a", &mut b);
    let mut a = again(&ae, "peerA");
    let s = status(&mut a, &l.ticket);
    assert!(s["done"].is_object(), "{s}");
    assert_eq!(s["pending"], false, "the durable pending mark stayed: {s}");
    // Also as stored, for the next start.
    a.kill();
    let mut a = again(&ae, "peerA");
    assert_eq!(status(&mut a, &l.ticket)["pending"], false);
}

#[test]
fn a_replay_after_the_host_was_removed_restores_nothing() {
    let (_be, mut b) = start("lk-forget-b", "hostB");
    let (ae, l) = stopped_after_record("lk-forget-a", &mut b);
    let mut a = again(&ae, "peerA");
    let identity = b.identity.clone();
    a.call("peer.forget", json!({"identity": identity}));
    let s = status(&mut a, &l.ticket);
    assert_eq!(s["done"], Value::Null, "a removed host came back: {s}");
    assert_eq!(s["pending"], false);
    assert_eq!(peer_of(&mut a, &identity), Value::Null);
    assert!(approvals(&a.dir).is_empty());
}

/// A link join that A's owner removes the host from while A holds at
/// `point`: the host is not stored and no path to it stays open, whether
/// the removal comes before the join stores the host or after.
fn removed_during_the_join(tag: &str, point: &str) {
    let (_be, mut b) = start(&format!("{tag}-b"), "hostB");
    let ae = Endpoint::init(&format!("{tag}-a"));
    let held = ae.dir.join("held");
    let hold = format!("{point}={}", held.display());
    let mut a = ae.app_raw(
        "peerA",
        &[],
        0,
        &[("MOUSSE_HELPER_TEST_HOLD", Path::new(&hold))],
    );
    hello(&mut a);
    let l = link(&mut b);
    let id = join(&mut a, &l.uri(), json!({"approved": [l.route()]}));
    nth(&a, "join.code_needed", &l.inv, 0);
    type_code(&mut a, &l.inv, &l.code());
    let until = std::time::Instant::now() + WAIT;
    while !held.exists() {
        assert!(std::time::Instant::now() < until, "the join never held");
        std::thread::sleep(Duration::from_millis(20));
    }
    let identity = b.identity.clone();
    let forget = a.start("peer.forget", json!({"identity": identity}));
    // The removal runs now, or waits for the join's store to finish.
    settle_a_moment();
    std::fs::remove_file(&held).unwrap();
    let reply = a.reply(id);
    if reply.get("error").is_some() {
        assert_eq!(reply["error"], "forgotten", "{reply}");
    } else {
        let conn = reply["conn"].clone();
        a.event("conn.down", |m| m["conn"] == conn);
    }
    let gone = a.reply(forget);
    assert!(gone.get("error").is_none(), "{gone}");
    assert_eq!(
        peer_of(&mut a, &identity),
        Value::Null,
        "a removed host came back"
    );
    assert_eq!(status(&mut a, &l.ticket)["done"], Value::Null);
    assert!(approvals(&a.dir).is_empty());
}

#[test]
fn a_host_removed_before_the_join_stores_it_stays_removed() {
    removed_during_the_join("lk-rm-early", "link-paired");
}

#[test]
fn a_host_removed_while_the_join_stores_it_keeps_no_path() {
    removed_during_the_join("lk-rm-late", "link-done-saved");
}

#[test]
fn a_grant_removal_also_drops_the_completion_record() {
    let (_be, mut b) = start("lk-ungrant-b", "hostB");
    let (ae, l) = stopped_after_record("lk-ungrant-a", &mut b);
    let mut a = again(&ae, "peerA");
    let identity = b.identity.clone();
    let grant =
        a.call("grant.add", json!({"identity": identity, "name": "hostB"}))["grant"].clone();
    let removed = a.call("grant.remove", json!({"grant": grant}));
    assert_eq!(removed["removed"], true);
    let s = status(&mut a, &l.ticket);
    assert_eq!(s["done"], Value::Null, "{s}");
    assert_eq!(peer_of(&mut a, &identity), Value::Null);
}

/// The result of A adding B one way (as over SSH): B grants A, A holds
/// B's pin under a name of its own and is connected to it (as keep
/// connected leaves it). Returns B's grant id for A and A's stored row
/// for B.
fn one_way(a: &mut App, b: &mut App) -> (Value, Value) {
    let (identity, name) = (a.identity.clone(), a.name.clone());
    let grant = b.call("grant.add", json!({"identity": identity, "name": name}))["grant"].clone();
    let route = hello(b)["routes"][0].as_str().unwrap().to_owned();
    let identity = b.identity.clone();
    a.call(
        "peer.add",
        json!({"identity": identity, "name": "B over SSH", "routes": [route]}),
    );
    wait_outbound(a, &identity, 0);
    (grant, row_of(a, &identity))
}

/// A's stored row for `identity`, less `last_route` (keep connected
/// notes the route it dials).
fn row_of(app: &mut App, identity: &str) -> Value {
    let mut row = peer_of(app, identity);
    row["last_route"] = Value::Null;
    row
}

#[test]
fn a_crash_after_connect_with_a_held_pin_grants_nothing() {
    let (_be, mut b) = start("lk-held-b", "hostB");
    let (ae, mut a) = start("lk-held-a", "peerA");
    let (grant, row) = one_way(&mut a, &mut b);
    let l = link(&mut b);
    join(&mut a, &l.uri(), json!({"pinned": true}));
    nth(&a, "join.code_needed", &l.inv, 0);
    a.kill();
    let mut a = again(&ae, "peerA");
    let s = status(&mut a, &l.ticket);
    assert_eq!(s["done"], Value::Null, "{s}");
    assert_eq!(s["pending"], false);
    assert!(grants(&mut a).is_empty());
    let on_b = grants_for(&mut b, &a.identity.clone());
    assert_eq!(on_b.len(), 1);
    assert_eq!(on_b[0]["grant"], grant);
    assert_eq!(row_of(&mut a, &b.identity.clone()), row);
}

#[test]
fn a_damaged_link_after_a_one_way_add_changes_no_grant() {
    let (_be, mut b) = start("lk-oneway-b", "hostB");
    let (_ae, mut a) = start("lk-oneway-a", "peerA");
    let (grant, row) = one_way(&mut a, &mut b);
    let mut t = link(&mut b).ticket;
    t.secret = TicketSecret::from_bytes([3; 16]);
    let reply = a.request(
        "join",
        json!({"ticket": t.to_fragment(), "arrival": "link", "pinned": true}),
    );
    // Existing access, not this link's: "already", and nothing to grant
    // back.
    assert!(reply.get("error").is_none(), "{reply}");
    assert_eq!(reply["already"], true);
    let s = status(&mut a, &t);
    assert_eq!(s["done"], Value::Null, "{s}");
    assert_eq!(s["pending"], false);
    let on_b = grants_for(&mut b, &a.identity.clone());
    assert_eq!(on_b.len(), 1);
    assert_eq!(on_b[0]["grant"], grant);
    assert!(grants(&mut a).is_empty());
    assert_eq!(row_of(&mut a, &b.identity.clone()), row);
}

#[test]
fn an_unacknowledged_completion_record_goes_after_its_time() {
    let (_be, mut b) = start("lk-keep-b", "hostB");
    let ae = Endpoint::init("lk-keep-a");
    let mut a = ae.app_raw(
        "peerA",
        &[("JOIN_DONE_KEEP_SECS", "0")],
        0,
        &[("MOUSSE_HELPER_MANUAL_CLOCK", Path::new("1"))],
    );
    hello(&mut a);
    let l = pair_by_link(&mut a, &mut b, &[]);
    assert!(status(&mut a, &l.ticket)["done"].is_object());
    let now = a.call("test.clock", json!({}))["now"].as_u64().unwrap();
    let past = l.ticket.expires_at.secs() + 2 - now;
    a.call("test.clock", json!({"advance_secs": past}));
    assert_eq!(status(&mut a, &l.ticket)["done"], Value::Null);
    // The pairing itself stays.
    assert_eq!(peer_of(&mut a, &b.identity.clone())["name"], "hostB");
}

#[test]
fn the_helper_speaks_1_1_and_still_serves_1_0() {
    let end = Endpoint::init("lk-proto");
    let mut app = end.app("hostA", &[]);
    assert_eq!(
        app.call("hello", json!({"proto": [1, 0]}))["proto"],
        json!([1, 0])
    );
    assert_eq!(
        app.call("hello", json!({"proto": [1, 1]}))["proto"],
        json!([1, 1])
    );
}

#[test]
fn malformed_link_requests_are_refused() {
    let (_be, mut b) = start("lk-malformed-b", "hostB");
    let (_ae, mut a) = start("lk-malformed-a", "peerA");
    assert_eq!(
        b.request("invite.create", json!({"kind": "qr"}))["error"],
        "bad_request"
    );
    let uri = link(&mut b).uri();
    for fields in [
        json!({"ticket": uri, "arrival": "mail"}),
        json!({"ticket": uri, "arrival": "link", "approved": "tcp://127.0.0.1:1"}),
        json!({"ticket": uri, "arrival": "link", "approved": [1]}),
    ] {
        assert_eq!(a.request("join", fields)["error"], "bad_request");
    }
    for op in ["join.status", "join.ack"] {
        assert_eq!(
            a.request(op, json!({"ticket_hash": "abc"}))["error"],
            "bad_request"
        );
    }
    assert!(b.events("invite.code").is_empty());
}
