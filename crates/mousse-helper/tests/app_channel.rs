//! E1: `serve --app` on stdin and stdout. Framing, stream handles under
//! equal wire stream ids, FIN in order after a stalled final write, hello,
//! the helper's own log, and exit on EOF.

mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::json;

#[test]
fn hello_comes_first_and_the_helpers_own_lines_go_to_its_log() {
    let end = Endpoint::init("hello");
    let mut a = end.app("hostA", &[]);
    assert_eq!(a.request("stats", json!({}))["error"], "no_hello");
    assert_eq!(
        a.request("hello", json!({"proto": [2, 0]}))["error"],
        "unsupported_proto"
    );
    assert_eq!(
        a.request("hello", json!({"proto": [1, 0], "profile": "another"}))["error"],
        "wrong_profile"
    );
    // The lower minor wins.
    let hello = a.call("hello", json!({"proto": [1, 7], "name": "x"}));
    assert_eq!(hello["proto"], json!([1, 0]));
    let identity = hello["identity"].as_str().unwrap();
    assert!(
        !identity.is_empty() && identity.chars().all(|c| c.is_ascii_hexdigit()),
        "{hello}"
    );
    let port = hello["port"].as_u64().unwrap();
    assert!(port > 0);
    let route = format!("tcp://127.0.0.1:{port}");
    assert_eq!(hello["routes"], json!([route]), "{hello}");
    assert!(!hello["build"].as_str().unwrap().is_empty());
    assert_eq!(a.request("nope", json!({}))["error"], "unknown_op");

    // stdout carried frames only (the reader checks every one); the
    // helper's own lines are in its log.
    let log = end.log();
    assert!(
        log.contains("ready ") && log.contains(&format!("port {port}")),
        "{log}"
    );

    a.call("shutdown", json!({}));
    assert_eq!(a.exit_within(WAIT), Some(0), "{}", a.err());
    assert!(a.st().closed);
    assert!(end.log().contains("stopped"));
    a.assert_clean();
}

#[test]
fn stdin_closing_ends_every_connection_cleanly_and_the_helper_exits() {
    let mut p = pair_up("eof", &[], &[]);
    let h = p.b.open(p.b_conn, "mousse.rpc", "interactive");
    p.a.incoming(p.a_conn, 0);
    assert!(h > 0);

    let started = Instant::now();
    p.b.close_stdin();
    assert_eq!(p.b.exit_within(WAIT), Some(0), "{}", p.b.err());
    let down = p.a.event("conn.down", |m| m["conn"] == p.a_conn);
    assert_eq!(down["reason"], "no_error", "{down}");
    assert_eq!(down["identity"], p.b.identity.as_str());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert!(p.b_end.log().contains("app channel ended: Eof"));
    p.a.assert_clean();
}

#[test]
fn equal_wire_stream_ids_on_two_connections_get_their_own_handles() {
    let mut p = pair_up("ids", &[], &[]);
    let (_c_end, mut c, a_to_c, c_conn) = another_peer(&mut p.a, "idsc", &[]);
    assert_ne!(a_to_c, p.a_conn);

    // The first stream each caller opens: wire stream ids restart on every
    // connection, so both carry the same one.
    let hb = p.b.open(p.b_conn, "mousse.rpc", "interactive");
    let hc = c.open(c_conn, "mousse.rpc", "interactive");
    let from_b = p.a.incoming(p.a_conn, 0);
    let from_c = p.a.incoming(a_to_c, 0);
    assert_ne!(from_b, from_c);

    for h in [from_b, from_c] {
        p.a.accept(h);
        p.a.credit(h, 1 << 20);
    }
    p.b.credit(hb, 1 << 20);
    c.credit(hc, 1 << 20);
    p.b.send(hb, b"from b", true);
    c.send(hc, b"from c, longer", true);
    assert_eq!(p.a.until_fin(from_b, WAIT), b"from b");
    assert_eq!(p.a.until_fin(from_c, WAIT), b"from c, longer");

    p.a.send(from_b, b"to b", true);
    p.a.send(from_c, b"to c", true);
    assert_eq!(p.b.until_fin(hb, WAIT), b"to b");
    assert_eq!(c.until_fin(hc, WAIT), b"to c");

    // Done both ways: the handles are gone and are never reused.
    let next = p.b.open(p.b_conn, "mousse.rpc", "interactive");
    assert!(next > hb);
    let again = p.a.incoming(p.a_conn, 1);
    assert!(again > from_b.max(from_c), "{again}");
    let start = Instant::now();
    loop {
        let stats = p.a.stats();
        if stats["handles"] == 1 {
            break;
        }
        assert!(start.elapsed() < WAIT, "finished handles stayed: {stats}");
        std::thread::sleep(Duration::from_millis(50));
    }
    for app in [&p.a, &p.b, &c] {
        app.assert_clean();
    }
}

#[test]
fn fin_follows_every_byte_of_a_stalled_final_write() {
    let mut p = pair_up("fin", &[], &[]);
    let body = pattern(2 << 20, 7);
    let hb = p.b.open(p.b_conn, "mousse.blob", "bulk");
    let ha = p.a.incoming(p.a_conn, 0);
    p.a.accept(ha);

    // B's final write: all of it with FIN. A grants no credit, so it
    // stalls with FIN queued behind its bytes.
    p.b.send(hb, &body, true);
    let sent = p.b.settle(Duration::from_millis(500), |b| b.sent(hb));
    assert!(sent < body.len() as u64, "B's write never stalled: {sent}");
    assert!(!p.b.st().tx[&hb].fin_sent);
    assert_eq!(p.a.received(ha), (0, false));

    // A stops reading and then grants it all: its helper queues every byte
    // and the FIN while its writer is stalled.
    p.a.pause();
    p.a.credit(ha, 4 << 20);
    p.b.wait("B's FIN to go", WAIT, |st| {
        st.tx[&hb].fin_sent.then_some(())
    });
    std::thread::sleep(Duration::from_millis(500));
    p.a.resume();

    let got = p.a.until_fin(ha, WAIT);
    assert_eq!(got.len(), body.len());
    assert!(got == body, "the bytes differ");
    p.a.assert_clean();
    p.b.assert_clean();
}

#[test]
fn a_malformed_frame_ends_the_channel_and_the_helper_exits() {
    let end = Endpoint::init("bad");
    let cases: [(Vec<u8>, &str); 3] = [
        (frame(0x09, b""), "unknown frame type"),
        (vec![0, 0, 0, 0], "frame length 0"),
        (
            data_frame(1, false, b"x")
                .into_iter()
                .enumerate()
                .map(|(i, b)| if i == 9 { 0x02 } else { b })
                .collect(),
            "malformed DATA",
        ),
    ];
    for (bytes, why) in cases {
        let mut a = end.app("hostA", &[]);
        a.hello();
        a.raw(&bytes);
        assert_eq!(a.exit_within(WAIT), Some(2), "{why}: {}", a.err());
        assert!(
            a.err().contains("app channel") && a.err().contains(why),
            "{}",
            a.err()
        );
    }
}

#[test]
fn frames_for_unknown_handles_are_dropped_and_data_beyond_credit_ends_the_channel() {
    let mut p = pair_up("drop", &[], &[]);
    p.b.raw(&data_frame(999, false, b"lost"));
    p.b.raw(&credit_frame(999, 10));
    assert_eq!(
        p.b.request("stream.reset", json!({"handle": 999, "code": "cancelled"}))["error"],
        "no_stream"
    );
    let stats = p.b.stats();
    assert_eq!(stats["dropped_frames"], 3, "{stats}");

    // Credit returns as the engine takes bytes, but the engine takes at
    // most its wire window and write queue (512 KiB) beyond the 256 KiB
    // granted: 2 MiB is beyond credit whatever came back meanwhile.
    let h = p.b.open(p.b_conn, "mousse.blob", "bulk");
    p.b.wait("credit on the new stream", WAIT, |st| {
        st.tx.get(&h).filter(|t| t.credit > 0).map(|_| ())
    });
    let mut over = 0;
    while over < 2 << 20 {
        p.b.raw(&data_frame(h, false, &[0; MAX_DATA]));
        over += MAX_DATA as u64;
    }
    assert_eq!(p.b.exit_within(WAIT), Some(2));
    assert!(p.b.err().contains("credit"), "{}", p.b.err());
    p.a.event("conn.down", |m| m["conn"] == p.a_conn);
}

#[test]
fn inbound_passes_only_app_labels_and_outbound_refuses_host_opened_streams() {
    let mut p = pair_up("labels", &[], &[]);
    let term = p.b.open(p.b_conn, "terminal", "interactive");
    let reset = p.b.event("stream.reset", |m| m["handle"] == term);
    assert_eq!(reset["code"], "refused_stream");

    // The host's app opens a stream on its inbound connection: not in
    // 1.0, so the caller's helper refuses it.
    let from_host = p.a.open(p.a_conn, "mousse.rpc", "interactive");
    let reset = p.a.event("stream.reset", |m| m["handle"] == from_host);
    assert_eq!(reset["code"], "refused_stream");

    // An app reset reaches the peer's app with its code.
    let h = p.b.open(p.b_conn, "mousse.sub", "interactive");
    let ha = p.a.incoming(p.a_conn, 0);
    p.a.call("stream.reset", json!({"handle": ha, "code": "cancelled"}));
    let reset = p.b.event("stream.reset", |m| m["handle"] == h);
    assert_eq!(reset["code"], "cancelled");

    // One editor tunnel (Phase 1b §9.2) reaches the app with its label.
    p.b.open(p.b_conn, "mousse.tunnel", "interactive");
    let tunnel = p.a.incoming(p.a_conn, 1);
    let incoming = p.a.event("stream.incoming", |m| m["handle"] == tunnel);
    assert_eq!(incoming["label"], "mousse.tunnel");

    assert_eq!(p.a.events("stream.incoming").len(), 2);
    assert!(p.b.events("stream.incoming").is_empty());
    p.a.assert_clean();
    p.b.assert_clean();
}

/// An app that stops reading stdout: replies pile up past
/// APP_CONTROL_QUEUE_BYTES, the channel ends, and the helper still exits,
/// although its writer is blocked on the full pipe.
#[test]
fn an_app_that_stops_reading_does_not_keep_the_helper_alive() {
    use std::io::Write as _;
    use std::process::Stdio;

    let end = Endpoint::init("unread");
    let mut cmd = end.command(&["serve", "--app", "--no-mdns", "--port", "0"]);
    cmd.stdin(Stdio::piped())
        .env("MOUSSE_NET_APP_CONTROL_QUEUE_BYTES", "65536");
    let mut child = cmd.spawn().unwrap();
    // stdout is held, never read.
    let _stdout = child.stdout.take().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        // Each request gets a `no_hello` reply of about 60 bytes: far more
        // than the queue limit and any pipe buffer.
        for id in 0..20_000u64 {
            let body = serde_json::to_vec(&json!({"op": "stats", "id": id})).unwrap();
            if stdin.write_all(&frame(0x01, &body)).is_err() {
                return;
            }
        }
        // stdin stays open: only the stuck channel can end the helper.
        std::thread::sleep(WAIT * 2);
    });

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if started.elapsed() > WAIT {
            break None;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    if status.is_none() {
        let _ = child.kill();
    }
    let log = end.log();
    assert!(status.is_some(), "the helper did not exit:\n{log}");
    assert!(log.contains("app channel ended: Stuck"), "{log}");
    drop(writer);
}

/// `init --app` (the app's first start) ends with its stdin, as `serve
/// --app` does: an app killed during it leaves no `init` behind. The hold
/// stands for an init still busy, a keystore that is slow to answer.
#[test]
fn init_for_the_app_exits_when_its_stdin_closes() {
    let end = Endpoint {
        dir: temp_dir("initeof"),
    };
    let mut init = end.cli_env(&["init", "--app"], &[("MOUSSE_NET_INIT_HOLD_MS", "30000")]);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(init.exit_within(Duration::ZERO), None, "{}", init.err());
    let closed = Instant::now();
    init.end_stdin();
    assert_eq!(init.exit_within(WAIT), Some(3), "{}", init.err());
    assert!(
        closed.elapsed() < Duration::from_secs(1),
        "{:?}",
        closed.elapsed()
    );
    assert!(!end.dir.join("endpoint.json").exists());

    // With its stdin open it makes the endpoint and exits.
    let mut init = end.cli_env(&["init", "--app"], &[]);
    assert_eq!(init.exit_within(WAIT), Some(0), "{}", init.err());
    assert!(init.out().contains("created endpoint"), "{}", init.out());
}

/// A device with no grant dials in and waits for a proof it never sends:
/// the host's app hears nothing of it, before or after the proof wait
/// closes it (Phase 1b §6.1, the helper's `inbound`).
#[test]
fn a_connection_that_never_becomes_live_is_never_announced() {
    let a_end = Endpoint::init("unlive-a");
    let b_end = Endpoint::init("unlive-b");
    let mut a = a_end.app("hostA", &[("JOIN_PROOF_WAIT_MS", "1000")]);
    let mut b = b_end.app("peerB", &[]);
    a.hello();
    b.hello();
    let route = route_of(&mut a);
    // B pins A, but A never grants B.
    let (identity, name) = (a.identity.clone(), a.name.clone());
    b.call(
        "peer.add",
        json!({"identity": identity, "name": name, "routes": [route]}),
    );
    // Long enough for B's dial, A's proof wait and its close.
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(a.events("conn.up").is_empty(), "{:?}", a.events("conn.up"));
    a.assert_clean();
}
