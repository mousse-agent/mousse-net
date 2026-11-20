//! `phase3.relay-limits`: connections per address, accept legs per handle,
//! circuits per caller, the per-circuit queue, the first-message wait, the
//! egress ceiling and the pre-accept budget, each tightened through its
//! limit. (Tighten-only parsing is a unit test in `src/limits.rs`; the
//! circuit and registration idle waits are in the core vectors.)

mod common;

use std::time::{Duration, Instant};

use common::*;
use mousse_net_core::pairing::{InvitationId, TicketSecret};
use mousse_net_core::relay::msg::InvitationEntry;
use mousse_net_core::relay::{proof, Class, RefuseReason, RelayMessage};
use mousse_relay::client::{DialError, Received};

#[tokio::test(flavor = "multi_thread")]
async fn connections_per_address_do_not_count_accepted_legs() {
    let (target, caller) = (key(0x61), key(0x71));
    let f = Fixture::new("per-ip", &[("RELAY_CONNECTIONS_PER_IP", 3)], &[&target]).await;
    let h = f.handle(&target);
    let mut reg = f.register(&target).await; // 1
    allow(&mut reg, 1, &[&caller]).await;
    let mut a = f.call(&caller, h, Class::Interactive).await; // 2
    let c1 = incoming(&mut reg).await;
    let mut acc = f.accept(&target, c1).await; // 3, then not counted
    assert_eq!(relay(&mut a).await, RelayMessage::Spliced);
    assert_eq!(relay(&mut acc).await, RelayMessage::Spliced);
    let _third = f.dial().await; // 3
    match f.try_dial().await {
        Err(DialError::ClosedBeforeHello(Some(4006)))
        | Err(DialError::Tls(_))
        | Err(DialError::Upgrade(_)) => {}
        other => panic!("a fourth connection from one address was let in: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn accept_legs_per_handle_and_circuits_per_caller() {
    let (target, caller) = (key(0x61), key(0x71));
    let f = Fixture::new(
        "legs",
        &[
            ("RELAY_ACCEPT_LEGS_PER_HANDLE", 1),
            ("RELAY_CIRCUITS_PER_CALLER", 2),
        ],
        &[&target],
    )
    .await;
    let h = f.handle(&target);
    let mut reg = f.register(&target).await;
    allow(&mut reg, 1, &[&caller]).await;
    let mut a = f.call(&caller, h, Class::Interactive).await;
    let c1 = incoming(&mut reg).await;
    let _b = f.call(&caller, h, Class::Bulk).await;
    let c2 = incoming(&mut reg).await;
    // Two circuits open for the caller: a third call is refused.
    let mut c = f.call(&caller, h, Class::Interactive).await;
    assert_eq!(
        next(&mut c).await,
        Received::Relay(RelayMessage::Unreachable)
    );
    let mut acc = f.accept(&target, c1).await;
    assert_eq!(relay(&mut a).await, RelayMessage::Spliced);
    assert_eq!(relay(&mut acc).await, RelayMessage::Spliced);
    // A second accept leg for the handle: REFUSED(limit).
    let mut acc2 = f.accept(&target, c2).await;
    assert_eq!(
        relay(&mut acc2).await,
        RelayMessage::Refused {
            reason: RefuseReason::Limit
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_connection_closes_at_the_first_message_wait() {
    let f = Fixture::new("hello", &[("RELAY_HELLO_WAIT_MS", 500)], &[]).await;
    let mut c = f.dial().await;
    let start = Instant::now();
    assert_eq!(closed(&mut c).await, Some(4002));
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(450) && took < Duration::from_millis(2_000),
        "{took:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_egress_ceiling_holds() {
    let (target, caller) = (key(0x61), key(0x71));
    let f = Fixture::new("egress", &[("RELAY_EGRESS_BPS", 125_000)], &[&target]).await;
    let mut reg = f.register(&target).await;
    allow(&mut reg, 1, &[&caller]).await;
    let (mut leg, mut acc) = f.connect(&mut reg, &target, &caller, Class::Bulk).await;
    let start = Instant::now();
    let total = 5 * 60_000;
    let sender = tokio::spawn(async move {
        for _ in 0..5 {
            leg.send_raw(vec![7; 60_000]).await.unwrap();
        }
        leg
    });
    let mut got = 0;
    while got < total {
        match next(&mut acc).await {
            Received::Peer(b) => got += b.len(),
            other => panic!("{other:?}"),
        }
    }
    let took = start.elapsed();
    // A full bucket (125 000 bytes), one message of overdraft, then 125 000
    // bytes a second: (300 000 - 125 000 - 60 000) / 125 000 = 0.92 s.
    // Unthrottled, loopback takes a few milliseconds.
    assert!(
        took >= Duration::from_millis(850),
        "{total} bytes in {took:?}"
    );
    let _ = sender.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_full_queue_stops_reading_the_sender() {
    let (target, caller) = (key(0x61), key(0x71));
    let f = Fixture::new("queue", &[("RELAY_QUEUE_BYTES", 16_384)], &[&target]).await;
    let mut reg = f.register(&target).await;
    allow(&mut reg, 1, &[&caller]).await;
    // The accept leg never reads.
    let (mut leg, _acc) = f.connect(&mut reg, &target, &caller, Class::Bulk).await;
    let limit = 64 * 1024 * 1024;
    let mut sent = 0usize;
    let blocked = loop {
        match tokio::time::timeout(Duration::from_secs(2), leg.send_raw(vec![1; 60_000])).await {
            Ok(Ok(())) => sent += 60_000,
            Ok(Err(e)) => panic!("send failed: {e}"),
            Err(_) => break true,
        }
        if sent > limit {
            break false;
        }
    };
    assert!(
        blocked,
        "the relay kept reading {sent} bytes for a leg that never reads"
    );
}

/// A leg that stops reading is closed once a write to it makes no progress
/// for `RELAY_SEND_WAIT_MS`, and its circuit with it; the circuit idle wait
/// (60 s) never comes into it.
#[tokio::test(flavor = "multi_thread")]
async fn a_leg_that_stops_reading_closes_at_the_send_wait() {
    let (target, caller) = (key(0x61), key(0x71));
    let f = Fixture::new(
        "send-wait",
        &[("RELAY_SEND_WAIT_MS", 1_000), ("RELAY_QUEUE_BYTES", 16_384)],
        &[&target],
    )
    .await;
    let mut reg = f.register(&target).await;
    allow(&mut reg, 1, &[&caller]).await;
    // The accept leg never reads.
    let (mut leg, _acc) = f.connect(&mut reg, &target, &caller, Class::Bulk).await;
    let start = Instant::now();
    let mut sent = 0usize;
    loop {
        match tokio::time::timeout(Duration::from_millis(500), leg.send_raw(vec![1; 60_000])).await
        {
            Ok(Ok(())) => sent += 60_000,
            Ok(Err(_)) | Err(_) => break,
        }
        assert!(sent < 256 * 1024 * 1024, "the leg never filled");
    }
    // The relay gives up on the accept leg; the caller's leg closes too.
    closed(&mut leg).await;
    let took = start.elapsed();
    assert!(took < Duration::from_secs(8), "{took:?}");
}

/// A close does not queue behind a blocked write: when the operator
/// revokes the target, the relay gives the accept leg that stopped reading
/// the close linger, then drops it, instead of holding it until it reads
/// again.
#[tokio::test(flavor = "multi_thread")]
async fn a_close_does_not_wait_behind_a_blocked_write() {
    let (target, caller) = (key(0x61), key(0x71));
    let f = Fixture::new(
        "close-linger",
        &[
            ("RELAY_CLOSE_LINGER_MS", 300),
            ("RELAY_QUEUE_BYTES", 16_384),
        ],
        &[&target],
    )
    .await;
    let mut reg = f.register(&target).await;
    allow(&mut reg, 1, &[&caller]).await;
    let (mut leg, mut acc) = f.connect(&mut reg, &target, &caller, Class::Bulk).await;
    let mut sent = 0usize;
    loop {
        match tokio::time::timeout(Duration::from_millis(500), leg.send_raw(vec![1; 60_000])).await
        {
            Ok(Ok(())) => sent += 60_000,
            Ok(Err(_)) | Err(_) => break,
        }
        assert!(sent < 256 * 1024 * 1024, "the leg never filled");
    }
    assert_eq!(f.dir.revoke(now(), &target.fingerprint()).unwrap(), 1);
    // Past the next state read (RELAY_STATE_POLL_MS, 1 s) and the linger
    // (twice: the blocked write, then the close frame).
    tokio::time::sleep(Duration::from_millis(2_000)).await;
    // Reading now would unblock a writer still waiting; one that let go
    // never sends its close frame.
    let end = loop {
        if let Received::Closed(code) = next(&mut acc).await {
            break code;
        }
    };
    assert_eq!(end, None, "the relay held the blocked leg until it read");
}

/// PINGs from a client that never reads its PONGs: the relay queues at
/// most `RELAY_CONTROL_QUEUE_MESSAGES` toward it, then closes it, well
/// before the send wait (20 s) would.
#[tokio::test(flavor = "multi_thread")]
async fn pings_without_reading_close_at_the_control_queue_bound() {
    let target = key(0x61);
    let f = Fixture::new("control-queue", &[], &[&target]).await;
    let mut reg = f.register(&target).await;
    let ping = RelayMessage::Ping { data: [9; 8] }.encode();
    let start = Instant::now();
    let deadline = start + Duration::from_secs(12);
    let mut sent = 0u64;
    let ended = loop {
        // A send that never waits never times out: check the clock too.
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break false;
        }
        match tokio::time::timeout(left, reg.send_raw(ping.clone())).await {
            Ok(Ok(())) => sent += 1,
            Ok(Err(_)) => break true,
            Err(_) => break false,
        }
    };
    assert!(
        ended,
        "the relay still took PINGs after {sent} without a PONG read"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_join_circuit_closes_over_its_preaccept_budget() {
    let target = key(0x61);
    let f = Fixture::new("budget", &[("RELAY_PREACCEPT_BYTES", 16_384)], &[&target]).await;
    let h = f.handle(&target);
    let tag = proof::invitation_tag(&InvitationId([1; 16]), &TicketSecret::from_bytes([2; 16]));
    let mut reg = f.register(&target).await;
    reg.send(&RelayMessage::AllowSet {
        sequence: 1,
        callers: vec![],
        invitations: vec![InvitationEntry {
            tag_hash: proof::tag_hash(&tag),
            expires_at: now().0 + 600,
        }],
    })
    .await
    .unwrap();
    assert_eq!(
        relay(&mut reg).await,
        RelayMessage::AllowSetOk { sequence: 1 }
    );
    let mut joiner = f.dial().await;
    joiner
        .send(&RelayMessage::Join { handle: h, tag })
        .await
        .unwrap();
    let circuit = incoming(&mut reg).await;
    let mut acc = f.accept(&target, circuit).await;
    assert_eq!(relay(&mut joiner).await, RelayMessage::Spliced);
    assert_eq!(relay(&mut acc).await, RelayMessage::Spliced);
    joiner.send_raw(vec![5; 16_384]).await.unwrap();
    assert_eq!(next(&mut acc).await, Received::Peer(vec![5; 16_384]));
    joiner.send_raw(vec![5; 1]).await.unwrap();
    assert_eq!(closed(&mut joiner).await, Some(4006));
    assert_eq!(closed(&mut acc).await, Some(4006));
}
