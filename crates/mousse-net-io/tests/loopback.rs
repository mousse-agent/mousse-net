//! One host and its callers over real TLS on loopback TCP.

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use mousse_net_core::control::ControlMessage;
use mousse_net_core::mux::{Mux, MuxEvent, MuxRole, PriorityClass};
use mousse_net_core::pairing::Ticket;
use mousse_net_core::{ErrorCode, Millis, PROTOCOL_MINOR_VERSION};
use mousse_net_io::certs::CertManager;
use mousse_net_io::keystore::KeyStorage;
use mousse_net_io::pipe::connect_tcp;
use mousse_net_io::{
    tls, Caller, Endpoint, JoinOutcome, ManualClock, NetError, PortChoice, TlsPolicy,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn wait_until(what: &str, cond: impl Fn() -> bool) {
    within(what, async {
        while !cond() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
}

async fn join_with(
    caller: &Caller,
    host: &TestHost,
    ticket: &Ticket,
) -> Result<(mousse_net_io::Connection, JoinOutcome), NetError> {
    let pipe = connect_tcp(&host.route()).await?;
    within("join", caller.join(pipe, ticket, "laptop")).await
}

/// Connect with `pin` and let the host's join-proof wait run out. The
/// result is what an ungranted identity gets.
async fn dial_refused(caller: &Caller, host: &TestHost) -> NetError {
    let before = host.accepted.load(Ordering::SeqCst);
    let pipe = connect_tcp(&host.route()).await.unwrap();
    let conn = caller.connect(pipe, host.identity()).await.unwrap();
    wait_until("host accepted", || {
        host.accepted.load(Ordering::SeqCst) > before
    })
    .await;
    host.skip_join_wait();
    match within("refusal", conn.settled(false)).await {
        mousse_net_io::ConnStatus::Closed(reason) => NetError::Closed(reason),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pair_in_person_open_a_terminal_then_removal_closes_it_at_once() {
    let mut host = TestHost::start(new_signer()).await;
    let caller = new_caller(new_signer());
    let conn = pair(&caller, &mut host, "laptop").await;
    assert_eq!(conn.kx_group(), "X25519MLKEM768");
    let mut stream = open_echo(&conn).await;
    assert_eq!(stream.class(), PriorityClass::Interactive);
    assert_echo(&mut stream, b"uname -a\n").await;

    let grant = host.grant_of(&caller.identity()).unwrap();
    assert_eq!(host.host.connections_for(grant), 1);
    let started = Instant::now();
    assert!(host.host.remove_grant(grant));
    assert_eq!(close_code(&conn).await, Some(ErrorCode::GrantRevoked));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert!(stream.reader.read().await.is_err());
    assert!(stream.writer.write(b"more").await.is_err());
    assert_eq!(host.host.connections_for(grant), 0);

    // The device is no longer known: a new connection is refused.
    let refused = dial_refused(&caller, &host).await;
    assert!(
        closed_with(&refused, ErrorCode::NotAuthorized),
        "{refused:?}"
    );
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_host_identity_on_reconnect_fails_before_any_data() {
    let mut real = TestHost::start(new_signer()).await;
    let caller = new_caller(new_signer());
    drop(pair(&caller, &mut real, "laptop").await);

    // Another host answers at the address the caller dials.
    let impostor = TestHost::start(new_signer()).await;
    let err = dial(&caller, &impostor.route(), real.identity())
        .await
        .unwrap_err();
    assert!(is_pin_mismatch(&err), "{err:?}");
    wait_until("impostor saw the abort", || {
        !impostor.rejected.lock().unwrap().is_empty()
    })
    .await;
    assert_eq!(impostor.accepted.load(Ordering::SeqCst), 0);
    assert_eq!(impostor.streams.load(Ordering::SeqCst), 0);

    // The real host still works with the same pin.
    let conn = dial(&caller, &real.route(), real.identity()).await.unwrap();
    open_echo(&conn).await;
    impostor.stop().await;
    real.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ungranted_identity_cannot_open_streams() {
    let host = TestHost::start(new_signer()).await;
    // A peer that skips the client-side checks and writes mux frames itself.
    let clock = Arc::new(ManualClock::new());
    let certs = CertManager::new(new_signer(), clock.clone());
    let own = certs.current().unwrap();
    let pipe = connect_tcp(&host.route()).await.unwrap();
    let (mut tls, _) = tls::connect(pipe, &own, host.identity(), clock, TlsPolicy::default())
        .await
        .unwrap();
    let mut mux = Mux::new(MuxRole::Caller, Millis(0));
    mux.send_control(
        ControlMessage::Hello {
            minor_version: PROTOCOL_MINOR_VERSION,
        }
        .encode(),
    )
    .unwrap();
    let stream = mux
        .open_stream(PriorityClass::Interactive, "terminal")
        .unwrap();
    mux.send(stream, b"id\n").unwrap();
    while let Some(bytes) = mux.poll_transmit(Millis(0)) {
        tls.write_all(&bytes).await.unwrap();
    }
    tls.flush().await.unwrap();

    let mut events = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match within("host reply", tls.read(&mut buf)).await {
            Ok(0) | Err(_) => break,
            Ok(n) => events.extend(mux.receive(&buf[..n], Millis(1)).unwrap_or_default()),
        }
    }
    assert!(
        events.iter().any(|e| matches!(
            e,
            MuxEvent::GoAway {
                code: ErrorCode::NotAuthorized
            }
        )),
        "{events:?}"
    );
    // Nothing but the host's HELLO came back: no AUTHORIZED, no stream.
    for event in &events {
        match event {
            MuxEvent::Control(bytes) => assert!(
                matches!(
                    ControlMessage::decode(bytes),
                    Ok(ControlMessage::Hello { .. })
                ),
                "{event:?}"
            ),
            MuxEvent::GoAway { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(host.streams.load(Ordering::SeqCst), 0);
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ticket_replayed_after_use_is_refused() {
    let mut host = TestHost::start(new_signer()).await;
    let ticket = host.invite();
    let first = new_caller(new_signer());
    let pipe = connect_tcp(&host.route()).await.unwrap();
    let (joined, ()) = tokio::join!(
        within("join", first.join(pipe, &ticket, "laptop")),
        host.approve_next_request()
    );
    assert!(matches!(joined.unwrap().1, JoinOutcome::Paired(_)));

    let second = new_caller(new_signer());
    let err = join_with(&second, &host, &ticket).await.unwrap_err();
    assert!(closed_with(&err, ErrorCode::InvitationInvalid), "{err:?}");
    assert!(host.grant_of(&second.identity()).is_none());
    assert_eq!(host.host.grants().len(), 1);
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_ticket_is_refused_by_the_host_and_by_the_joiner() {
    let host = TestHost::start(new_signer()).await;
    // Made five minutes "ago" on the host clock, so the host can pass its
    // expiry without its own certificate looking far ahead of the joiner.
    host.clock.advance(-300);
    let ticket = host.invite();

    // The joiner's clock is past the ticket's expiry plus the allowed skew:
    // it refuses the ticket without dialling.
    let late_clock = Arc::new(ManualClock::new());
    late_clock.advance(901);
    let late = new_caller_with_clock(new_signer(), late_clock);
    let pipe = connect_tcp(&host.route()).await.unwrap();
    let err = late.join(pipe, &ticket, "laptop").await.unwrap_err();
    assert!(matches!(err, NetError::Ticket(_)), "{err:?}");

    // The host's clock is past the expiry: it refuses the join proof.
    host.clock.advance(601);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let caller = new_caller(new_signer());
    let err = join_with(&caller, &host, &ticket).await.unwrap_err();
    assert!(closed_with(&err, ErrorCode::InvitationInvalid), "{err:?}");
    assert!(host.host.grants().is_empty());
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paired_caller_reconnects_after_a_host_restart_on_the_kept_port() {
    let dir = temp_dir("restart");
    let (mut endpoint, key) = Endpoint::create(&dir, None, KeyStorage::InsecureFile).unwrap();
    let mut host = TestHost::start_endpoint(&mut endpoint, Arc::new(key), "desk").await;
    let caller = new_caller(new_signer());
    let conn = pair(&caller, &mut host, "laptop").await;
    let (pin, route) = (host.identity(), host.route());
    host.stop().await;
    within("closed on quit", conn.closed()).await;
    drop(endpoint);

    let mut endpoint = Endpoint::open(&dir).unwrap();
    let signer = endpoint_signer(&endpoint);
    let host = TestHost::start_endpoint(&mut endpoint, signer, "desk").await;
    assert_eq!(host.route(), route);
    let conn = dial(&caller, &route, pin).await.unwrap();
    open_echo(&conn).await;
    drop(conn);
    host.stop().await;
    drop(endpoint);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paired_caller_finds_the_host_after_a_port_change() {
    let dir = temp_dir("portchange");
    let (mut endpoint, key) = Endpoint::create(&dir, None, KeyStorage::InsecureFile).unwrap();
    let mut host = TestHost::start_endpoint(&mut endpoint, Arc::new(key), "desk").await;
    let caller = new_caller(new_signer());
    drop(pair(&caller, &mut host, "laptop").await);
    let (pin, old) = (host.identity(), host.route());
    host.stop().await;
    drop(endpoint);

    let mut endpoint = Endpoint::open(&dir).unwrap();
    let signer = endpoint_signer(&endpoint);
    let host = TestHost::start_endpoint_on(&mut endpoint, signer, "desk", PortChoice::Auto).await;
    let new = host.route();
    assert_ne!(new, old);
    // The old address no longer answers; the manually entered new one does.
    let (conn, used) = within("dial", caller.dial_candidates(&[old, new.clone()], pin))
        .await
        .unwrap();
    assert_eq!(used, new);
    open_echo(&conn).await;
    drop(conn);
    host.stop().await;
    drop(endpoint);
    std::fs::remove_dir_all(&dir).unwrap();
}
