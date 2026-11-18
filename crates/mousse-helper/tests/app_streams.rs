//! E2: pumps, app credit, engine receive admission (stream caps),
//! read-ahead and priority, both directions.

mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::{json, Value};

const KIB: u64 = 1024;
/// The engine's initial credit on every wire stream.
const INITIAL_CREDIT: u64 = 256 * KIB;

/// A caller with room for more than the host's caps.
const ROOMY: [(&str, &str); 3] = [
    ("STREAMS_PER_CONNECTION", "64"),
    ("STREAMS_PER_ENDPOINT", "256"),
    ("APP_CREDIT_BUDGET_BYTES", "67108864"),
];

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| panic!("not a number: {v}"))
}

/// Open `n` bulk streams from B.
fn open_bulk(app: &mut App, conn: u64, n: usize) -> Vec<u32> {
    (0..n)
        .map(|_| app.open(conn, "mousse.blob", "bulk"))
        .collect()
}

/// The handles B's app learned were reset, with their codes.
fn resets(app: &App) -> Vec<(u32, String)> {
    app.events("stream.reset")
        .iter()
        .map(|m| {
            (
                u(&m["handle"]) as u32,
                m["code"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect()
}

#[test]
fn a_peer_opening_past_the_connection_cap_is_refused() {
    let mut p = pair_up("cap", &[], &ROOMY);
    let opened = open_bulk(&mut p.b, p.b_conn, 40);
    p.a.incoming(p.a_conn, 31);
    let refused = p.b.wait("8 refusals", WAIT, |st| {
        let r: Vec<_> = st
            .messages
            .iter()
            .filter(|m| m["ev"] == "stream.reset")
            .cloned()
            .collect();
        (r.len() >= 8).then_some(r)
    });
    assert!(refused.iter().all(|m| m["code"] == "refused_stream"));
    // The last eight: places go in open order.
    let mut handles: Vec<u32> = refused.iter().map(|m| u(&m["handle"]) as u32).collect();
    handles.sort_unstable();
    assert_eq!(handles, opened[32..]);
    let stats = p.a.stats();
    assert_eq!(stats["open_streams"], 32, "{stats}");
    assert_eq!(stats["refused_streams"], 8, "{stats}");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(p.a.events("stream.incoming").len(), 32);
    p.a.assert_clean();
    p.b.assert_clean();
}

#[test]
fn with_app_reads_stalled_the_engine_queue_stays_within_the_caps() {
    let mut p = pair_up("queue", &[], &ROOMY);
    let opened = open_bulk(&mut p.b, p.b_conn, 40);
    for &h in &opened {
        p.b.send(h, &pattern(512 * KIB as usize, h as u8), false);
    }
    // A's app reads nothing: everything waits in A's engine.
    let total = p.b.settle(Duration::from_millis(700), |b| {
        opened.iter().map(|&h| b.sent(h)).sum::<u64>()
    });
    let stats = p.a.stats();
    let peak = u(&stats["peak_queued_bytes"]);
    let bound = 32 * INITIAL_CREDIT;
    assert!(peak <= bound, "{peak} queued, bound {bound}: {stats}");
    // And the bound was reached: the test filled every admitted stream.
    assert!(peak >= bound - 2 * INITIAL_CREDIT, "{peak}: {stats}");
    assert!(total > peak);
    assert_eq!(u(&stats["app_buffered_bytes"]), 0);
    p.a.assert_clean();
}

#[test]
fn the_endpoint_cap_counts_every_connection_and_own_opens_wait_for_a_place() {
    let caps = [
        ("STREAMS_PER_CONNECTION", "4"),
        ("STREAMS_PER_ENDPOINT", "6"),
    ];
    let mut p = pair_up("endp", &caps, &[]);
    let (_c_end, mut c, a_to_c, c_conn) = another_peer(&p.a_end, &mut p.a, "endpc", &[]);
    let from_b = open_bulk(&mut p.b, p.b_conn, 5);
    // Four per connection.
    p.a.incoming(p.a_conn, 3);
    let r = p.b.event("stream.reset", |_| true);
    assert_eq!(
        (u(&r["handle"]) as u32, r["code"].as_str().unwrap()),
        (from_b[4], "refused_stream")
    );
    // Six in all: C gets two.
    let from_c = open_bulk(&mut c, c_conn, 4);
    p.a.incoming(a_to_c, 1);
    c.wait("two refusals", WAIT, |st| {
        (st.messages
            .iter()
            .filter(|m| m["ev"] == "stream.reset")
            .count()
            >= 2)
            .then_some(())
    });
    let mut refused: Vec<u32> = resets(&c).iter().map(|(h, _)| *h).collect();
    refused.sort_unstable();
    assert_eq!(refused, from_c[2..]);
    assert_eq!(u(&p.a.stats()["refused_streams"]), 3);

    // A's own open finds no place.
    assert_eq!(
        p.a.request(
            "stream.open",
            json!({"conn": p.a_conn, "label": "mousse.rpc", "class": "interactive"})
        )["error"],
        "stream_limit"
    );
    // One ends: its place frees once both sides are done with it.
    p.b.call(
        "stream.reset",
        json!({"handle": from_b[0], "code": "cancelled"}),
    );
    let start = Instant::now();
    loop {
        let reply = p.a.request(
            "stream.open",
            json!({"conn": p.a_conn, "label": "mousse.rpc", "class": "interactive"}),
        );
        if reply.get("handle").is_some() {
            break;
        }
        assert_eq!(reply["error"], "stream_limit");
        assert!(start.elapsed() < WAIT, "the place never freed");
        std::thread::sleep(Duration::from_millis(50));
    }
    p.a.assert_clean();
}

#[test]
fn an_app_opening_past_its_own_cap_gets_stream_limit() {
    let mut p = pair_up("own", &[], &[("STREAMS_PER_CONNECTION", "3")]);
    let opened = open_bulk(&mut p.b, p.b_conn, 3);
    let reply = p.b.request(
        "stream.open",
        json!({"conn": p.b_conn, "label": "mousse.blob", "class": "bulk"}),
    );
    assert_eq!(reply["error"], "stream_limit", "{reply}");
    // The peer never saw a fourth.
    p.a.incoming(p.a_conn, 2);
    p.b.call(
        "stream.reset",
        json!({"handle": opened[1], "code": "cancelled"}),
    );
    let start = Instant::now();
    loop {
        let reply = p.b.request(
            "stream.open",
            json!({"conn": p.b_conn, "label": "mousse.blob", "class": "bulk"}),
        );
        if reply.get("handle").is_some() {
            break;
        }
        assert!(start.elapsed() < WAIT, "the place never freed");
        std::thread::sleep(Duration::from_millis(50));
    }
    p.a.incoming(p.a_conn, 3);
}

#[test]
fn the_helper_reads_ahead_only_within_app_credit_and_the_remote_writer_stalls() {
    let mut p = pair_up("ahead", &[], &[]);
    let body = pattern(4 << 20, 3);
    let hb = p.b.open(p.b_conn, "mousse.blob", "bulk");
    let ha = p.a.incoming(p.a_conn, 0);
    p.a.accept(ha);
    p.a.credit(ha, 64 * KIB as u32);
    p.b.send(hb, &body, true);

    // One read fits: credit covers the read-ahead once. Then nothing
    // more is read, and B's writes stall on wire credit.
    let sent = p.b.settle(Duration::from_millis(700), |b| b.sent(hb));
    let (got, fin) = p.a.received(ha);
    assert!(got as u64 <= 64 * KIB && !fin, "{got}");
    assert!(sent < 2 << 20, "B never stalled: {sent}");
    let stats = p.a.stats();
    assert!(u(&stats["peak_app_buffered_bytes"]) <= 64 * KIB, "{stats}");
    assert!(u(&stats["queued_bytes"]) <= INITIAL_CREDIT, "{stats}");
    p.a.assert_clean();

    // Credit in small steps: never a byte beyond it.
    for _ in 0..20 {
        p.a.credit(ha, 20 * KIB as u32);
        std::thread::sleep(Duration::from_millis(20));
    }
    p.a.assert_clean();
    p.a.credit(ha, 8 << 20);
    let all = p.a.until_fin(ha, WAIT);
    assert!(all == body, "the bytes differ");
    p.a.assert_clean();
    p.b.assert_clean();
}

#[test]
fn credit_comes_from_one_budget_with_a_reserve_for_interactive() {
    // 512 KiB in all, 256 KiB of it for interactive only, 128 KiB a stream.
    let budget = [
        ("APP_CREDIT_BUDGET_BYTES", "524288"),
        ("APP_CREDIT_INTERACTIVE_RESERVE_BYTES", "262144"),
        ("APP_STREAM_CREDIT_BYTES", "131072"),
    ];
    let mut p = pair_up("budget", &[], &budget);
    let bulk = open_bulk(&mut p.b, p.b_conn, 3);
    let total = |app: &App, h: u32| app.st().tx.get(&h).map(|t| t.credit_total).unwrap_or(0);
    p.b.wait("credit on two bulk streams", WAIT, |st| {
        let n = bulk
            .iter()
            .filter(|h| st.tx.get(h).is_some_and(|t| t.credit_total == 128 * KIB))
            .count();
        (n == 2).then_some(())
    });
    assert_eq!(total(&p.b, bulk[2]), 0, "bulk got into the reserve");
    let i1 = p.b.open(p.b_conn, "mousse.rpc", "interactive");
    let i2 = p.b.open(p.b_conn, "mousse.rpc", "interactive");
    p.b.wait("interactive credit from the reserve", WAIT, |st| {
        [i1, i2]
            .iter()
            .all(|h| st.tx.get(h).is_some_and(|t| t.credit_total == 128 * KIB))
            .then_some(())
    });
    assert_eq!(u(&p.b.stats()["app_credit_out_bytes"]), 512 * KIB);

    // The engine takes a bulk stream's bytes: the credit returns, and the
    // stream that had none gets its turn first. Interactive streams with
    // full credit take nothing.
    let first = *bulk.iter().find(|&&h| total(&p.b, h) > 0).unwrap();
    p.b.send(first, &pattern(128 * KIB as usize, 1), false);
    p.b.wait("the waiting bulk stream's turn", WAIT, |st| {
        st.tx
            .get(&bulk[2])
            .is_some_and(|t| t.credit_total > 0)
            .then_some(())
    });
    let start = Instant::now();
    loop {
        let after = total(&p.b, first) + total(&p.b, bulk[2]);
        if after == 256 * KIB {
            break;
        }
        assert!(start.elapsed() < WAIT, "{after}");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(total(&p.b, i1) + total(&p.b, i2), 256 * KIB);
    assert_eq!(u(&p.b.stats()["app_credit_out_bytes"]), 512 * KIB);
    p.b.assert_clean();
}

#[test]
fn interactive_data_overtakes_bulk_queued_for_a_stalled_app() {
    let mut p = pair_up("prio", &[], &[]);
    let hi = p.b.open(p.b_conn, "mousse.rpc", "interactive");
    let hk = p.b.open(p.b_conn, "mousse.blob", "bulk");
    let ai = p.a.incoming(p.a_conn, 0);
    let ak = p.a.incoming(p.a_conn, 1);
    for (h, credit) in [(ai, 1 << 20), (ak, 16 << 20)] {
        p.a.accept(h);
        p.a.credit(h, credit);
    }
    // A's app stops reading; 6 MiB of bulk queues up in its helper.
    p.a.pause();
    let bulk = 6 << 20;
    p.b.send(hk, &pattern(bulk, 9), false);
    p.b.wait("the bulk to go", WAIT, |st| {
        (st.tx[&hk].sent == bulk as u64).then_some(())
    });
    std::thread::sleep(Duration::from_millis(500));
    p.b.send(hi, b"ping", false);
    std::thread::sleep(Duration::from_millis(300));
    let resumed = Instant::now();
    p.a.resume();
    let at = p.a.wait("the ping", WAIT, |st| {
        st.rx
            .get(&ai)
            .and_then(|r| r.arrivals.first().map(|(t, _)| *t))
    });
    let before: usize =
        p.a.st()
            .rx
            .get(&ak)
            .map(|r| {
                r.arrivals
                    .iter()
                    .filter(|(t, _)| *t <= at)
                    .map(|(_, n)| n)
                    .sum()
            })
            .unwrap_or(0);
    eprintln!(
        "interactive DATA arrived {:?} after the app resumed, behind {before} bulk bytes",
        at.saturating_duration_since(resumed)
    );
    // Behind at most the frame being written and the pipe's buffer.
    assert!(before <= 1 << 20, "{before} bulk bytes went first");
    p.a.wait("all the bulk", WAIT, |st| {
        st.rx.get(&ak).filter(|r| r.bytes.len() == bulk).map(|_| ())
    });
    p.a.assert_clean();
}

#[test]
fn interactive_keeps_moving_while_bulk_is_stalled_both_ways() {
    // Small budgets so stalled bulk uses up all but the reserve.
    let budget = [
        ("APP_CREDIT_BUDGET_BYTES", "1048576"),
        ("APP_CREDIT_INTERACTIVE_RESERVE_BYTES", "262144"),
        ("APP_STREAM_CREDIT_BYTES", "262144"),
    ];
    let mut p = pair_up("both", &budget, &budget);
    let bulk_b = open_bulk(&mut p.b, p.b_conn, 4);
    let bulk_a: Vec<u32> = (0..4).map(|n| p.a.incoming(p.a_conn, n)).collect();
    for &h in &bulk_a {
        p.a.accept(h);
    }
    // Neither app grants bulk credit; both send more than fits.
    for (&hb, &ha) in bulk_b.iter().zip(&bulk_a) {
        p.b.send(hb, &pattern(1 << 20, 1), false);
        p.a.send(ha, &pattern(1 << 20, 2), false);
    }
    p.b.settle(Duration::from_millis(500), |b| {
        bulk_b.iter().map(|&h| b.sent(h)).sum::<u64>()
    });
    p.a.settle(Duration::from_millis(500), |a| {
        bulk_a.iter().map(|&h| a.sent(h)).sum::<u64>()
    });
    // The budget is used up for bulk on both sides.
    for app in [&mut p.a, &mut p.b] {
        let stats = app.stats();
        assert!(u(&stats["app_credit_out_bytes"]) >= 768 * KIB, "{stats}");
    }

    let hi = p.b.open(p.b_conn, "mousse.rpc", "interactive");
    let ai = p.a.incoming(p.a_conn, 4);
    p.a.accept(ai);
    p.a.credit(ai, 1 << 20);
    p.b.credit(hi, 1 << 20);
    let start = Instant::now();
    for round in 0..20u8 {
        p.b.send(hi, &[round; 100], false);
        p.a.wait("B's message", WAIT, |st| {
            (st.rx.get(&ai).map_or(0, |r| r.bytes.len()) == 100 * (round as usize + 1))
                .then_some(())
        });
        p.a.send(ai, &[round; 50], false);
        p.b.wait("A's answer", WAIT, |st| {
            (st.rx.get(&hi).map_or(0, |r| r.bytes.len()) == 50 * (round as usize + 1)).then_some(())
        });
    }
    let took = start.elapsed();
    eprintln!("20 interactive round trips with bulk stalled both ways: {took:?}");
    assert!(took < Duration::from_secs(5), "{took:?}");
    p.a.assert_clean();
    p.b.assert_clean();
}
