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
/// recovering its pending record, and a `join.direct` with the same address
/// and code taking that recovery.
#[test]
fn allow_while_away_enrolls_on_reconnect_after_a_restart() {
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

    // B is back: it recovers, and the same join takes the recovery.
    restart_b(&mut r);
    let id = join(&mut r.b, &inv, &code);
    let joined = r.b.reply(id);
    assert!(joined.get("error").is_none(), "{joined}");
    assert_eq!(joined["identity"], r.a.identity.as_str(), "{joined}");
    let enrolled =
        r.a.event("enrolled", |m| m["invitation"] == invitation.as_str());
    assert_eq!(enrolled["identity"], r.b.identity.as_str(), "{enrolled}");
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
