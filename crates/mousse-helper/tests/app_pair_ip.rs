//! Pair with IP through the app channel (`docs/pair-with-ip-design.md` §4,
//! §1.4 steps 8 and 9, §1.6). The check `pair-with-ip.helper` runs this
//! file.
//!
//! Two helpers on loopback. Pair with IP needs wire minor 4, which a debug
//! helper speaks with `MOUSSE_NET_TEST_HELLO_MINOR=4`; without it every
//! Pair with IP operation answers `unsupported`. A debug helper takes
//! loopback as a local network address, so the `lan` way offers
//! `127.0.0.1:<port>` and the joiner may type it.

mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::{json, Value};

const MINOR4: &[(&str, &str)] = &[("TEST_HELLO_MINOR", "4")];

/// A host A and a joiner B at minor 4. Apps drop before their directories.
struct Rig {
    a: App,
    b: App,
    a_end: Endpoint,
    b_end: Endpoint,
}

fn rig(tag: &str, a_env: &[(&str, &str)]) -> Rig {
    let a_end = Endpoint::init(&format!("{tag}a"));
    let b_end = Endpoint::init(&format!("{tag}b"));
    let mut a = a_end.app("hostA", a_env);
    a.hello();
    let mut b = b_end.app("peerB", MINOR4);
    b.hello();
    Rig { a, b, a_end, b_end }
}

/// B again, after it stopped: the same state directory.
fn restart_b(r: &mut Rig) {
    r.b.kill();
    let mut b = r.b_end.app("peerB", MINOR4);
    b.hello();
    r.b = b;
}

/// A Pair with IP invitation on the local network way.
fn invite(a: &mut App) -> Value {
    a.call("invite.create", json!({"kind": "direct", "way": "lan"}))
}

/// `code` with its last character changed: the same lookup, another
/// secret, so the host finds the invitation and debits an attempt.
fn wrong(code: &str) -> String {
    let mut chars: Vec<char> = code.chars().collect();
    let last = chars.last_mut().unwrap();
    *last = if *last == 'Z' { 'Y' } else { 'Z' };
    chars.into_iter().collect()
}

fn join(b: &mut App, invite: &Value, code: &str) -> u64 {
    b.start(
        "join.direct",
        json!({"address": invite["address"], "code": code}),
    )
}

/// The flow id of the `join.direct` request just made on `b`, from its
/// first progress event at or after `seen`.
fn progress(b: &App, step: &str, seen: usize) -> Value {
    b.wait(&format!("join.progress {step}"), WAIT, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == "join.progress")
            .skip(seen)
            .find(|m| m["step"] == step)
            .cloned()
    })
}

fn progress_count(b: &App) -> usize {
    b.events("join.progress").len()
}

fn approval_for(a: &App, invitation: &str, pred: impl Fn(&Value) -> bool) -> Value {
    a.event("approval", |m| m["invitation"] == invitation && pred(m))
}

fn has_grant(a: &mut App, identity: &str) -> bool {
    a.call("grants.list", json!({}))["grants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["identity"] == identity)
}

/// Nothing arrives for `what` within `quiet`.
fn none_within(app: &App, quiet: Duration, what: &str, f: impl Fn(&Value) -> bool) {
    let end = Instant::now() + quiet;
    while Instant::now() < end {
        if let Some(m) = app.st().messages.iter().find(|m| f(m)) {
            panic!("{what}: {m}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// End to end: a wrong code costs one attempt on both sides, the right
/// code waits for Allow with the joiner's short id on both screens, Allow
/// pairs it over the same connection, the first stream commits the grant,
/// and Remove ends it.
#[test]
fn pairs_from_the_ops_end_to_end() {
    let mut r = rig("pip-e2e", MINOR4);
    let inv = invite(&mut r.a);
    assert_eq!(inv["kind"], "direct", "{inv}");
    assert_eq!(inv["ways"], json!(["lan"]), "{inv}");
    assert!(inv.get("uri").is_none(), "no ticket: {inv}");
    let invitation = inv["invitation"].as_str().unwrap().to_owned();
    let code = inv["code"].as_str().unwrap().to_owned();
    let first_left = inv["attempts_left"].as_u64().unwrap();

    // A wrong code: one attempt fewer, the same code shown again.
    let id = join(&mut r.b, &inv, &wrong(&code));
    let failed = r.b.reply(id);
    assert_eq!(failed["error"], "pairing_failed", "{failed}");
    assert!(
        failed["attempts_left"].as_u64().unwrap() < first_left,
        "{failed}"
    );
    let shown =
        r.a.event("invite.code", |m| m["invitation"] == invitation.as_str());
    assert_eq!(shown["attempts_left"], first_left - 1, "{shown}");
    assert_eq!(shown["code"], code.as_str(), "the same code");

    // The right code: waiting for Allow, nothing paired yet.
    let seen = progress_count(&r.b);
    let id = join(&mut r.b, &inv, &code);
    let waiting = progress(&r.b, "awaiting_approval", seen);
    let ask = approval_for(&r.a, &invitation, |_| true);
    assert_eq!(ask["kind"], "direct", "{ask}");
    assert_eq!(ask["state"], "connected", "{ask}");
    assert_eq!(ask["decision"], "pending", "{ask}");
    assert_eq!(ask["identity"], r.b.identity.as_str(), "{ask}");
    assert_eq!(ask["device"], waiting["short_id"], "both show B's short id");
    assert_eq!(waiting["request"], json!(id), "progress names its request");
    none_within(
        &r.b,
        Duration::from_millis(500),
        "a reply before Allow",
        |m| m.get("re") == Some(&json!(id)),
    );
    assert!(!has_grant(&mut r.a, &r.b.identity), "no grant before Allow");

    r.a.call(
        "approval.answer",
        json!({"request": ask["request"], "yes": true}),
    );
    let joined = r.b.reply(id);
    assert!(joined.get("error").is_none(), "{joined}");
    assert_eq!(joined["identity"], r.a.identity.as_str(), "{joined}");
    assert_eq!(joined["invitation"], invitation.as_str(), "{joined}");
    let enrolled =
        r.a.event("enrolled", |m| m["invitation"] == invitation.as_str());
    assert_eq!(enrolled["kind"], "direct", "{enrolled}");
    assert_eq!(enrolled["provisional"], true, "{enrolled}");
    r.a.event("approval.ended", |m| {
        m["request"] == ask["request"] && m["reason"] == "enrolled"
    });
    let peer = peer_of(&mut r.b, &r.a.identity);
    let route = format!("tcp://{}", inv["address"].as_str().unwrap());
    assert!(
        peer["addresses"]
            .as_array()
            .unwrap()
            .contains(&json!(route)),
        "the typed address is an owner address: {peer}"
    );

    // The first stream commits the grant.
    let conn = joined["conn"].as_u64().expect("the pairing connection");
    r.b.open(conn, "mousse.rpc", "interactive");
    r.a.event("grant.committed", |m| {
        m["identity"] == r.b.identity.as_str()
    });

    // Remove.
    let grant = enrolled["grant"].clone();
    r.a.call("grant.remove", json!({"grant": grant}));
    assert!(!has_grant(&mut r.a, &r.b.identity));
    r.b.event("conn.down", |m| m["conn"] == conn);

    // The code is in no log and no error output, in any form.
    let bare = code.replace('-', "");
    for text in [r.a_end.log(), r.b_end.log(), r.a.err(), r.b.err()] {
        assert!(!text.contains(&code) && !text.contains(&bare), "{text}");
        assert!(!text.contains(&wrong(&code)), "{text}");
    }
}

/// Allow while the joiner is away marks the same request allowed, and the
/// grant is made only when the joiner is back: here a restarted helper
/// whose startup recovery, with no request from the app, claims it.
#[test]
fn allow_while_away_is_claimed_by_the_startup_recovery() {
    let mut r = rig("pip-away", MINOR4);
    let inv = invite(&mut r.a);
    let invitation = inv["invitation"].as_str().unwrap().to_owned();
    let code = inv["code"].as_str().unwrap().to_owned();
    join(&mut r.b, &inv, &code);
    progress(&r.b, "awaiting_approval", 0);
    let ask = approval_for(&r.a, &invitation, |m| m["state"] == "connected");

    // B goes away; the same request says so.
    r.b.kill();
    let away = approval_for(&r.a, &invitation, |m| m["state"] == "away");
    assert_eq!(away["request"], ask["request"], "the same request id");

    // Allow while away: allowed, no grant yet.
    r.a.call(
        "approval.answer",
        json!({"request": ask["request"], "yes": true}),
    );
    let allowed = approval_for(&r.a, &invitation, |m| m["decision"] == "allowed");
    assert_eq!(allowed["request"], ask["request"], "{allowed}");
    assert_eq!(allowed["state"], "away", "{allowed}");
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        r.a.events("enrolled").is_empty(),
        "no enrollment while away"
    );
    assert!(!has_grant(&mut r.a, &r.b.identity), "no grant while away");

    // B is back: its startup recovery alone claims the enrollment.
    restart_b(&mut r);
    let ended = r.b.event("join.direct.ended", |_| true);
    assert!(ended.get("error").is_none(), "{ended}");
    assert_eq!(ended["identity"], r.a.identity.as_str(), "{ended}");
    let enrolled =
        r.a.event("enrolled", |m| m["invitation"] == invitation.as_str());
    assert_eq!(enrolled["identity"], r.b.identity.as_str(), "{enrolled}");
}

/// After a restart the startup recovery runs before any request (the host
/// sees the device back), and a `join.direct` with the same address and
/// code takes that very flow: the same flow id, its progress now naming
/// the request, and no new code attempt.
#[test]
fn a_join_takes_the_recovery_started_at_startup() {
    let mut r = rig("pip-take", MINOR4);
    let inv = invite(&mut r.a);
    let invitation = inv["invitation"].as_str().unwrap().to_owned();
    let code = inv["code"].as_str().unwrap().to_owned();
    join(&mut r.b, &inv, &code);
    progress(&r.b, "awaiting_approval", 0);
    let ask = approval_for(&r.a, &invitation, |m| m["state"] == "connected");
    r.b.kill();
    approval_for(&r.a, &invitation, |m| m["state"] == "away");
    let attempts = r.a.events("invite.code").len();
    let asked = r.a.events("approval").len();

    restart_b(&mut r);
    // Back with no request from the app: the startup recovery.
    r.a.wait("B back by its recovery", WAIT, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == "approval")
            .skip(asked)
            .find(|m| m["state"] == "connected")
            .cloned()
    });
    let recovered = progress(&r.b, "awaiting_approval", 0);
    assert!(recovered.get("request").is_none(), "{recovered}");

    let seen = progress_count(&r.b);
    let id = join(&mut r.b, &inv, &code);
    let taken = progress(&r.b, "awaiting_approval", seen);
    assert_eq!(taken["flow"], recovered["flow"], "the same flow");
    assert_eq!(taken["request"], json!(id), "{taken}");
    r.a.call(
        "approval.answer",
        json!({"request": ask["request"], "yes": true}),
    );
    let joined = r.b.reply(id);
    assert!(joined.get("error").is_none(), "{joined}");
    assert_eq!(joined["flow"], recovered["flow"], "{joined}");
    assert_eq!(
        r.a.events("invite.code").len(),
        attempts,
        "no new code attempt"
    );
}

/// A joiner's cancel that crosses the host's Allow wins: whichever arrives
/// first, no grant is left and the joiner stores nothing.
#[test]
fn a_joiner_cancel_wins_over_a_crossing_allow() {
    let mut r = rig("pip-cross", MINOR4);
    let inv = invite(&mut r.a);
    let invitation = inv["invitation"].as_str().unwrap().to_owned();
    let code = inv["code"].as_str().unwrap().to_owned();
    let id = join(&mut r.b, &inv, &code);
    let waiting = progress(&r.b, "awaiting_approval", 0);
    let ask = approval_for(&r.a, &invitation, |_| true);

    let cancel =
        r.b.start("join.direct.cancel", json!({"flow": waiting["flow"]}));
    let allow = r.a.start(
        "approval.answer",
        json!({"request": ask["request"], "yes": true}),
    );
    let cancelled = r.b.reply(id);
    assert_eq!(cancelled["error"], "cancelled", "{cancelled}");
    let done = r.b.reply(cancel);
    assert!(done.get("error").is_none(), "{done}");
    r.a.reply(allow);

    // The host ends the request or undoes the enrollment; either way no
    // grant stays.
    r.a.wait("the cancel on A", WAIT, |st| {
        st.messages
            .iter()
            .find(|m| {
                (m["ev"] == "approval.ended" && m["reason"] == "cancelled")
                    || m["ev"] == "enrollment.undone"
            })
            .cloned()
    });
    assert!(
        !has_grant(&mut r.a, &r.b.identity),
        "no grant after the cancel"
    );
    assert_eq!(
        peer_of(&mut r.b, &r.a.identity),
        Value::Null,
        "B stores no host"
    );
    let status = r.b.call("join.status", json!({}));
    assert_eq!(status["direct"], json!([]), "{status}");
}

/// Decline ends the joiner's flow with `declined` and takes the prompt
/// away.
#[test]
fn decline_ends_the_join() {
    let mut r = rig("pip-decl", MINOR4);
    let inv = invite(&mut r.a);
    let invitation = inv["invitation"].as_str().unwrap().to_owned();
    let id = join(&mut r.b, &inv, inv["code"].as_str().unwrap());
    let ask = approval_for(&r.a, &invitation, |_| true);
    r.a.call(
        "approval.answer",
        json!({"request": ask["request"], "yes": false}),
    );
    let declined = r.b.reply(id);
    assert_eq!(declined["error"], "declined", "{declined}");
    r.a.event("approval.ended", |m| {
        m["request"] == ask["request"] && m["reason"] == "declined"
    });
    assert!(!has_grant(&mut r.a, &r.b.identity));
}

/// An invitation that expires ends with `invite.ended`, and a join to it
/// afterwards finds none. Takes a minute: the lifetime cannot be shorter.
#[test]
fn an_expired_invitation_ends_and_finds_no_join() {
    let mut env = MINOR4.to_vec();
    env.push(("DIRECT_INVITE_LIFETIME_SECS", "60"));
    let mut r = rig("pip-exp", &env);
    let inv = invite(&mut r.a);
    let invitation = inv["invitation"].as_str().unwrap().to_owned();
    let ended = r.a.wait("invite.ended", Duration::from_secs(90), |st| {
        st.messages
            .iter()
            .find(|m| m["ev"] == "invite.ended" && m["invitation"] == invitation.as_str())
            .cloned()
    });
    // The reason kind 1 and 2 invitations give for their end too.
    assert_eq!(ended["reason"], "invitation_invalid", "{ended}");
    let id = join(&mut r.b, &inv, inv["code"].as_str().unwrap());
    let refused = r.b.reply(id);
    assert_eq!(refused["error"], "invitation_invalid", "{refused}");
}

/// The joiner's completion is listed by `join.status {}` by invitation
/// until `join.ack {invitation}` drops it.
#[test]
fn join_status_lists_the_completion_until_acknowledged() {
    let mut r = rig("pip-ack", MINOR4);
    let inv = invite(&mut r.a);
    let invitation = inv["invitation"].as_str().unwrap().to_owned();
    let id = join(&mut r.b, &inv, inv["code"].as_str().unwrap());
    let ask = approval_for(&r.a, &invitation, |_| true);
    r.a.call(
        "approval.answer",
        json!({"request": ask["request"], "yes": true}),
    );
    let joined = r.b.reply(id);
    assert!(joined.get("error").is_none(), "{joined}");

    // Listed across a restart.
    restart_b(&mut r);
    let status = r.b.call("join.status", json!({}));
    let list = status["direct"].as_array().unwrap();
    assert_eq!(list.len(), 1, "{status}");
    assert_eq!(list[0]["invitation"], invitation.as_str(), "{status}");
    assert_eq!(list[0]["identity"], r.a.identity.as_str(), "{status}");
    assert_eq!(status["direct_unreadable"], 0, "{status}");

    let acked = r.b.call("join.ack", json!({"invitation": invitation}));
    assert_eq!(acked["removed"], true, "{acked}");
    let status = r.b.call("join.status", json!({}));
    assert_eq!(status["direct"], json!([]), "{status}");
}

/// Without wire minor 4 every Pair with IP operation answers
/// `unsupported`: the new ops, and the new forms of `invite.create`,
/// `join.status` (no `ticket_hash`) and `join.ack` (by invitation).
#[test]
fn without_minor_4_every_pair_with_ip_op_is_unsupported() {
    let end = Endpoint::init("pip-off");
    let mut a = end.app("hostA", &[]);
    a.hello();
    for (op, fields) in [
        ("invite.create", json!({"kind": "direct", "way": "lan"})),
        (
            "join.direct",
            json!({"address": "127.0.0.1:9", "code": "0123-4567-89AB"}),
        ),
        ("join.direct.cancel", json!({"flow": "f1"})),
        ("join.status", json!({})),
        ("join.ack", json!({"invitation": "00".repeat(16)})),
    ] {
        let reply = a.request(op, fields);
        assert_eq!(reply["error"], "unsupported", "{op}: {reply}");
    }
}

/// At minor 4 a ticket invitation's approval is the 1.1 one: no `kind`,
/// `state` or `decision`, and one answer ends it.
#[test]
fn ticket_approvals_are_unchanged_at_minor_4() {
    let mut r = rig("pip-tkt", MINOR4);
    let joined = pair_apps(&mut r.a, &mut r.b);
    for field in ["kind", "state", "decision", "answer_by"] {
        assert!(
            joined.approval.get(field).is_none(),
            "{field}: {}",
            joined.approval
        );
    }
    std::thread::sleep(Duration::from_millis(300));
    let again: Vec<Value> =
        r.a.events("approval")
            .into_iter()
            .filter(|m| m["request"] == joined.approval["request"])
            .collect();
    assert_eq!(again.len(), 1, "sent once: {again:?}");
    assert!(r.a.events("approval.ended").is_empty());
}

/// The command line: `invite --direct` shows the address and the code,
/// `join-direct <address>` asks for the code at a prompt, the host's
/// question names the device's short id, and both ends report the pairing.
#[test]
fn the_cli_pairs_with_the_code_typed_at_a_prompt() {
    const HELLO: &[(&str, &str)] = &[("MOUSSE_NET_TEST_HELLO_MINOR", "4")];
    let a_end = Endpoint::init("pip-clia");
    let b_end = Endpoint::init("pip-clib");
    let serve = a_end.cli_env(
        &["serve", "--name", "hostA", "--no-mdns", "--port", "0"],
        HELLO,
    );
    serve.wait_for("ready ");
    let mut invite = a_end.cli_env(&["invite", "--direct"], HELLO);
    let address = invite.wait_for("ADDRESS ")["ADDRESS ".len()..].to_owned();
    let code = invite.wait_for("CODE ")["CODE ".len()..]
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();

    let mut join = b_end.cli_env(&["join-direct", &address], HELLO);
    join.wait_for("Type the code");
    join.type_line(&format!("{code}\n"));
    let waiting = join.wait_for("waiting for Allow on the host");
    let device = waiting.rsplit(' ').next().unwrap().to_owned();
    let question = invite.wait_for("Allow it?");
    assert!(question.contains(&device), "{question} names {device}");
    invite.type_line("y\n");
    invite.wait_for("paired: grant ");
    join.wait_for("paired with hostA");
    assert_eq!(join.exit_within(WAIT), Some(0), "{}", join.err());
    assert_eq!(invite.exit_within(WAIT), Some(0), "{}", invite.err());
    drop(serve);
}

/// A host A and a joiner B at minor 4, B with `b_env` besides.
fn rig_with(tag: &str, b_env: &[(&str, &str)]) -> Rig {
    let a_end = Endpoint::init(&format!("{tag}a"));
    let b_end = Endpoint::init(&format!("{tag}b"));
    let mut a = a_end.app("hostA", MINOR4);
    a.hello();
    let mut env = MINOR4.to_vec();
    env.extend_from_slice(b_env);
    let mut b = b_end.app("peerB", &env);
    b.hello();
    Rig { a, b, a_end, b_end }
}

/// `peer.forget` of the host while a re-pair by code waits for Allow wins:
/// the Allow that follows stores nothing on the joiner, which answers
/// `removed`, lists no completion and keeps the host forgotten.
#[test]
fn a_forget_while_a_repair_waits_stores_nothing() {
    let mut r = rig("pip-fgt", MINOR4);
    pair_apps(&mut r.a, &mut r.b);
    let inv = invite(&mut r.a);
    let invitation = inv["invitation"].as_str().unwrap().to_owned();
    let id = join(&mut r.b, &inv, inv["code"].as_str().unwrap());
    let ask = approval_for(&r.a, &invitation, |m| m["state"] == "connected");
    let a_identity = r.a.identity.clone();
    r.b.call("peer.forget", json!({"identity": a_identity}));
    let ups = outbound_ups(&r.b, &a_identity);

    r.a.call(
        "approval.answer",
        json!({"request": ask["request"], "yes": true}),
    );
    let refused = r.b.reply(id);
    assert_eq!(refused["error"], "removed", "{refused}");
    assert_eq!(peer_of(&mut r.b, &a_identity), Value::Null);
    let status = r.b.call("join.status", json!({}));
    assert_eq!(status["direct"], json!([]), "{status}");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(outbound_ups(&r.b, &a_identity), ups, "no path to A");
}

/// A removal of the host also drops the kept record of a join to it: after
/// the next restart no recovery reaches the host or pairs with it.
#[test]
fn a_forget_drops_the_kept_record_of_a_join_to_that_host() {
    let fast = [("DIRECT_RETRY_FIRST_MS", "100")];
    let mut r = rig_with("pip-fgtrec", &fast);
    let inv = invite(&mut r.a);
    let invitation = inv["invitation"].as_str().unwrap().to_owned();
    join(&mut r.b, &inv, inv["code"].as_str().unwrap());
    let ask = approval_for(&r.a, &invitation, |m| m["state"] == "connected");
    let a_identity = r.a.identity.clone();
    r.b.call("peer.forget", json!({"identity": a_identity}));
    r.b.kill();
    approval_for(&r.a, &invitation, |m| m["state"] == "away");
    r.a.call(
        "approval.answer",
        json!({"request": ask["request"], "yes": true}),
    );
    approval_for(&r.a, &invitation, |m| m["decision"] == "allowed");
    let asked = r.a.events("approval").len();

    let mut env = MINOR4.to_vec();
    env.extend_from_slice(&fast);
    let mut b = r.b_end.app("peerB", &env);
    b.hello();
    r.b = b;
    std::thread::sleep(Duration::from_millis(1500));
    let back: Vec<Value> = r.a.events("approval").into_iter().skip(asked).collect();
    assert!(back.is_empty(), "a recovery reached A: {back:?}");
    assert!(r.a.events("enrolled").is_empty());
    assert_eq!(peer_of(&mut r.b, &a_identity), Value::Null);
}

/// Networking paused at startup (a removal journal that does not read):
/// no kept record is recovered, so nothing dials, until the pause ends;
/// then the recovery runs.
#[test]
fn a_helper_paused_at_startup_recovers_nothing_until_it_resumes() {
    let b_env = [("DIRECT_RETRY_FIRST_MS", "100"), ("REMOVAL_RETRY_MS", "50")];
    let mut r = rig_with("pip-pause", &b_env);
    let inv = invite(&mut r.a);
    let invitation = inv["invitation"].as_str().unwrap().to_owned();
    join(&mut r.b, &inv, inv["code"].as_str().unwrap());
    approval_for(&r.a, &invitation, |m| m["state"] == "connected");
    r.b.kill();
    approval_for(&r.a, &invitation, |m| m["state"] == "away");
    let asked = r.a.events("approval").len();

    let journal = r.b_end.dir.join("revoke.journal");
    std::fs::write(&journal, b"not a journal").unwrap();
    let mut env = MINOR4.to_vec();
    env.extend_from_slice(&b_env);
    let mut b = r.b_end.app("peerB", &env);
    let hello = b.hello();
    assert!(hello["paused"].is_string(), "{hello}");
    r.b = b;
    std::thread::sleep(Duration::from_millis(1500));
    let back: Vec<Value> = r.a.events("approval").into_iter().skip(asked).collect();
    assert!(back.is_empty(), "a recovery dialled while paused: {back:?}");

    // The pause ends: the recovery runs.
    std::fs::remove_file(&journal).unwrap();
    r.b.event("net.resumed", |_| true);
    r.a.wait("B back after the pause", WAIT, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == "approval")
            .skip(asked)
            .find(|m| m["state"] == "connected")
            .cloned()
    });
}

/// A kept pending record whose contents do not read is counted by
/// `join.status` (with those whose names do not read) and left in place.
#[test]
fn join_status_counts_a_kept_record_that_does_not_read() {
    let mut r = rig("pip-unread", MINOR4);
    let inv = invite(&mut r.a);
    let invitation = inv["invitation"].as_str().unwrap().to_owned();
    join(&mut r.b, &inv, inv["code"].as_str().unwrap());
    approval_for(&r.a, &invitation, |m| m["state"] == "connected");
    r.b.kill();
    let pending: Vec<_> = std::fs::read_dir(r.b_end.dir.join("direct"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pending"))
        .collect();
    assert_eq!(pending.len(), 1, "{pending:?}");
    std::fs::write(&pending[0], b"damaged").unwrap();

    restart_b(&mut r);
    let status = r.b.call("join.status", json!({}));
    assert_eq!(status["direct_unreadable"], 1, "{status}");
    assert_eq!(std::fs::read(&pending[0]).unwrap(), b"damaged", "kept");
}

/// Two devices pass the code of one invitation: two requests with ids of
/// their own. Allowing one with its own role enrolls that device with that
/// role on both sides and takes the other request away.
#[test]
fn two_devices_get_their_own_requests_and_the_allowed_one_its_role() {
    let mut r = rig("pip-two", MINOR4);
    let c_end = Endpoint::init("pip-twoc");
    let mut c = c_end.app("peerC", MINOR4);
    c.hello();
    let inv = invite(&mut r.a);
    let invitation = inv["invitation"].as_str().unwrap().to_owned();
    let code = inv["code"].as_str().unwrap().to_owned();
    let b_id = join(&mut r.b, &inv, &code);
    let c_id = join(&mut c, &inv, &code);
    let b_ask = approval_for(&r.a, &invitation, |m| {
        m["identity"] == r.b.identity.as_str()
    });
    let c_ask = approval_for(&r.a, &invitation, |m| m["identity"] == c.identity.as_str());
    assert_ne!(b_ask["request"], c_ask["request"], "a request each");

    r.a.call(
        "approval.answer",
        json!({"request": c_ask["request"], "yes": true, "role": "viewer"}),
    );
    let joined = c.reply(c_id);
    assert!(joined.get("error").is_none(), "{joined}");
    assert_eq!(joined["role"], "viewer", "{joined}");
    let enrolled =
        r.a.event("enrolled", |m| m["invitation"] == invitation.as_str());
    assert_eq!(enrolled["identity"], c.identity.as_str(), "{enrolled}");
    assert_eq!(enrolled["role"], "viewer", "{enrolled}");
    r.a.event("approval.ended", |m| {
        m["request"] == b_ask["request"] && m["reason"] == "dismissed"
    });
    let other = r.b.reply(b_id);
    assert!(other.get("error").is_some(), "{other}");
    assert!(!has_grant(&mut r.a, &r.b.identity));
    drop(c);
}

const CLI_HELLO: &[(&str, &str)] = &[("MOUSSE_NET_TEST_HELLO_MINOR", "4")];

/// Without wire minor 4 the CLI refuses before anything happens:
/// `join-direct` asks for no code, and `invite --direct` asks the running
/// host (which speaks minor 4) for nothing.
#[test]
fn the_cli_refuses_pair_with_ip_without_minor_4() {
    let a_end = Endpoint::init("pip-cliofa");
    let b_end = Endpoint::init("pip-cliofb");
    let serve = a_end.cli_env(
        &["serve", "--name", "hostA", "--no-mdns", "--port", "0"],
        CLI_HELLO,
    );
    serve.wait_for("ready ");
    let mut invite = a_end.cli_env(&["invite", "--direct"], &[]);
    assert_ne!(invite.exit_within(WAIT), Some(0));
    assert!(invite.err().contains("wire minor 4"), "{}", invite.err());
    assert!(!invite.out().contains("CODE "), "{}", invite.out());

    let mut join = b_end.cli_env(&["join-direct", "127.0.0.1:9"], &[]);
    assert_ne!(join.exit_within(WAIT), Some(0));
    assert!(join.err().contains("wire minor 4"), "{}", join.err());
    assert!(!join.out().contains("Type the code"), "{}", join.out());
    drop(serve);
}

/// `join-direct` with a grant list it cannot read stops before it asks for
/// the code or dials: a denied host must never see this device's
/// certificate.
#[test]
fn the_cli_join_stops_when_the_deny_list_does_not_read() {
    let b_end = Endpoint::init("pip-clideny");
    std::fs::write(b_end.dir.join("grants.json"), b"not a grant list").unwrap();
    let mut join = b_end.cli_env(&["join-direct", "127.0.0.1:9"], CLI_HELLO);
    join.end_stdin();
    assert_ne!(join.exit_within(WAIT), Some(0));
    assert!(join.err().contains("grant list"), "{}", join.err());
    assert!(!join.out().contains("Type the code"), "{}", join.out());
}

/// A code typed after the address is never echoed: the error is in fixed
/// words.
#[test]
fn the_cli_never_echoes_a_code_given_as_an_argument() {
    let b_end = Endpoint::init("pip-cliarg");
    let mut join = b_end.cli_env(&["join-direct", "127.0.0.1:9", "QQQQ-RRRR-SSSS"], CLI_HELLO);
    assert_eq!(join.exit_within(WAIT), Some(2));
    for text in [join.out(), join.err()] {
        assert!(!text.contains("QQQQ"), "{text}");
    }
    assert!(join.err().contains("type the code"), "{}", join.err());
}

/// `invite --direct` shows a local network address only: a listener whose
/// address is not one (here relabelled public) has none to show.
#[test]
fn the_cli_invite_shows_no_address_that_is_not_local() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let a_end = Endpoint::init("pip-clipub");
    let map = format!("{port}=public");
    let env = [
        ("MOUSSE_NET_TEST_HELLO_MINOR", "4"),
        ("MOUSSE_NET_TEST_CLASS_MAP", map.as_str()),
    ];
    let port = port.to_string();
    let serve = a_end.cli_env(
        &["serve", "--name", "hostA", "--no-mdns", "--port", &port],
        &env,
    );
    serve.wait_for("ready ");
    let mut invite = a_end.cli_env(&["invite", "--direct"], &env);
    assert_ne!(invite.exit_within(WAIT), Some(0));
    assert!(!invite.out().contains("ADDRESS"), "{}", invite.out());
    assert!(invite.err().contains("local network"), "{}", invite.err());
    drop(serve);
}

/// The CLI host retires a question whose request ended: its late answer is
/// not sent, and the same device passing the code again gets a new
/// question.
#[test]
fn the_cli_invite_asks_again_after_a_request_ends() {
    let a_end = Endpoint::init("pip-cliaska");
    let b_end = Endpoint::init("pip-cliaskb");
    let serve = a_end.cli_env(
        &["serve", "--name", "hostA", "--no-mdns", "--port", "0"],
        CLI_HELLO,
    );
    serve.wait_for("ready ");
    let mut invite = a_end.cli_env(&["invite", "--direct"], CLI_HELLO);
    let address = invite.wait_for("ADDRESS ")["ADDRESS ".len()..].to_owned();
    let code = invite.wait_for("CODE ")["CODE ".len()..]
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let mut b = b_end.app("peerB", MINOR4);
    b.hello();
    let first = b.start("join.direct", json!({"address": address, "code": code}));
    let waiting = progress(&b, "awaiting_approval", 0);
    invite.wait_for("Allow it?");

    // B cancels: the question on screen no longer counts.
    b.call("join.direct.cancel", json!({"flow": waiting["flow"]}));
    assert_eq!(b.reply(first)["error"], "cancelled");
    invite.wait_for("no longer counts");
    // The cancelled flow ends once the host has it; then B joins again.
    b.event("join.direct.ended", |m| m["flow"] == waiting["flow"]);
    let seen = progress_count(&b);
    let again = b.start("join.direct", json!({"address": address, "code": code}));
    progress(&b, "awaiting_approval", seen);
    // The stale answer is dropped; the new question gets its own.
    invite.type_line("y\n");
    invite.wait_for("nothing was sent");
    let start = Instant::now();
    while invite.out().matches("Allow it?").count() < 2 {
        assert!(start.elapsed() < WAIT, "no new question: {}", invite.out());
        std::thread::sleep(Duration::from_millis(25));
    }
    none_within(
        &b,
        Duration::from_millis(300),
        "a pairing before the answer",
        |m| m.get("re") == Some(&json!(again)) && m.get("error").is_none(),
    );
    invite.type_line("y\n");
    let joined = b.reply(again);
    assert!(joined.get("error").is_none(), "{joined}");
    invite.wait_for("paired: grant ");
    drop(b);
    drop(serve);
}
