//! One host and its callers over real TLS on loopback TCP.

mod common;

use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use mousse_net_core::control::ControlMessage;
use mousse_net_core::mux::{Mux, MuxEvent, MuxRole, PriorityClass};
use mousse_net_core::pairing::{
    BindingTranscript, CodeExchange, CodeExchangeFactory, CpaceExchangeFactory, ExchangeError,
    ExchangeRole, ExchangeStep, InvitationKind, InvitationStatus, PairingCode, Ticket, SID_LEN,
};
use mousse_net_core::session::RENEW_LEAD_SECS;
use mousse_net_core::{
    ErrorCode, Millis, UnixTime, CLOCK_SKEW_SECS, PROTOCOL_MINOR_VERSION, PROTOCOL_VERSION,
};
use mousse_net_io::certs::CertManager;
use mousse_net_io::keystore::KeyStorage;
use mousse_net_io::pipe::connect_tcp;
use mousse_net_io::store::GrantStore;
use mousse_net_io::{
    tls, Caller, Clock, Endpoint, JoinOutcome, ManualClock, NetError, NoCode, PathEvent,
    PortChoice, TlsPolicy,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

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
    assert!(matches!(host.host.remove_grant(grant), Ok(true)));
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
            major_version: PROTOCOL_VERSION,
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
async fn traffic_runs_through_the_deadline_second_and_stops_right_after_it() {
    let mut host = TestHost::start(new_signer()).await;
    let clock = Arc::new(ManualClock::new());
    let caller = new_caller_with_clock(new_signer(), clock.clone());
    let conn = pair(&caller, &mut host, "laptop").await;
    let deadline = conn.deadline();
    let mut stream = open_echo(&conn).await;

    // At the deadline second itself, everything still works.
    host.clock.freeze_at(deadline);
    clock.freeze_at(deadline);
    assert_echo(&mut stream, b"last second").await;
    let opened = host.streams.load(Ordering::SeqCst);

    // One second later the caller refuses to open or send, before its
    // timer fires, and nothing reaches the host.
    clock.freeze_at(UnixTime(deadline.0 + 1));
    let refused = conn
        .open_stream(PriorityClass::Interactive, "terminal")
        .await;
    assert!(
        matches!(&refused, Err(e) if closed_with(e, ErrorCode::CertExpired)),
        "{:?}",
        refused.err()
    );
    assert!(stream.writer.write(b"too late").await.is_err());
    assert_eq!(close_code(&conn).await, Some(ErrorCode::CertExpired));
    assert_eq!(host.streams.load(Ordering::SeqCst), opened);

    // The receiving side checks too: a host one second past the deadline
    // drops what a caller still at the deadline sends.
    clock.thaw();
    host.clock.thaw();
    let conn = dial(&caller, &host.route(), host.identity()).await.unwrap();
    assert_eq!(conn.deadline(), deadline);
    clock.freeze_at(deadline);
    host.clock.freeze_at(deadline);
    let mut stream = open_echo(&conn).await;
    host.clock.freeze_at(UnixTime(deadline.0 + 1));
    let _ = stream.writer.write(b"after the deadline").await;
    let echoed = within("the stream to end", stream.reader.read()).await;
    assert!(
        !matches!(echoed, Ok(Some(_))),
        "the host accepted data after the deadline"
    );
    assert_eq!(close_code(&conn).await, Some(ErrorCode::CertExpired));
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_is_renewed_before_its_deadline_and_replaced_only_after_reopening() {
    let mut host = TestHost::start(new_signer()).await;
    let clock = Arc::new(ManualClock::new());
    let caller = Arc::new(new_caller_with_clock(new_signer(), clock.clone()));
    let mut path_events = caller.start_renewals();
    let old = pair(&caller, &mut host, "laptop").await;
    caller.remember_routes(host.identity(), vec![host.route()]);
    let mut old_stream = open_echo(&old).await;

    // Both devices reach the renewal time: the earlier not_after minus the
    // renewal lead (the deadline adds the clock skew to not_after).
    let renew_at = old.deadline().0 - CLOCK_SKEW_SECS - RENEW_LEAD_SECS;
    let skip = renew_at as i64 - clock.now().0 as i64;
    clock.advance(skip);
    host.clock.advance(skip);
    let (from, new) = match within("the renewal", path_events.recv()).await {
        Some(PathEvent::Reopen { pin, from, conn }) => {
            assert_eq!(pin, host.identity());
            (from, conn)
        }
        other => panic!("expected a renewed path, got {other:?}"),
    };
    assert_eq!(from, old.id());
    assert_ne!(new.id(), old.id());
    assert!(
        new.deadline() > old.deadline(),
        "the new path did not renew"
    );

    // Not current yet: the old path keeps working while channels reopen.
    assert_echo(&mut old_stream, b"still current").await;
    let mut new_stream = open_echo(&new).await;
    assert!(old.status().is_live());
    caller.reopened(&new).unwrap();
    assert_eq!(close_code(&old).await, Some(ErrorCode::PathReplaced));
    assert_echo(&mut new_stream, b"on the new path").await;
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_that_cannot_be_saved_reports_it_and_still_ends_access_at_once() {
    let dir = temp_dir("unsaved");
    let (mut endpoint, key) = Endpoint::create(&dir, None, KeyStorage::InsecureFile).unwrap();
    let store = GrantStore::in_dir(&endpoint.grants_dir());
    let mut host = TestHost::start_endpoint(&mut endpoint, Arc::new(key), "desk").await;
    let caller = new_caller(new_signer());
    let conn = pair(&caller, &mut host, "laptop").await;
    let mut stream = open_echo(&conn).await;
    let grant = host.grant_of(&caller.identity()).unwrap();
    assert_eq!(store.load().unwrap().grants().count(), 1);

    // A folder where grants.json goes: the save cannot replace it.
    std::fs::remove_file(store.path()).unwrap();
    std::fs::create_dir(store.path()).unwrap();
    let removed = host.host.remove_grant(grant);
    assert!(
        matches!(removed, Err(NetError::Store(_))),
        "the failed save was not reported: {removed:?}"
    );
    // Access still ends at once.
    assert_eq!(close_code(&conn).await, Some(ErrorCode::GrantRevoked));
    assert!(stream.reader.read().await.is_err());
    assert!(host.grant_of(&caller.identity()).is_none());
    assert!(host.host.has_unsaved_changes());

    // Once the file can be written again, the host saves on its own.
    std::fs::remove_dir(store.path()).unwrap();
    within("the retried save", async {
        while host.host.has_unsaved_changes() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert_eq!(store.load().unwrap().grants().count(), 0);
    host.stop().await;
    drop(endpoint);
    std::fs::remove_dir_all(&dir).unwrap();
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

/// Start a send-link join in the background. Returns the code channel, the
/// asks the joiner makes, and the join result.
type JoinTask = tokio::task::JoinHandle<Result<(mousse_net_io::Connection, JoinOutcome), NetError>>;

fn start_link_join(
    caller: Arc<Caller>,
    host: &TestHost,
    ticket: Ticket,
) -> (
    mpsc::UnboundedSender<String>,
    mpsc::UnboundedReceiver<Option<u8>>,
    JoinTask,
) {
    let (type_tx, typed) = mpsc::unbounded_channel();
    let (asks, asks_rx) = mpsc::unbounded_channel();
    let route = host.route();
    let join = tokio::spawn(async move {
        let pipe = connect_tcp(&route).await?;
        let mut codes = TypedCodes { asks, typed };
        caller
            .join_with_code(pipe, &ticket, "phone", &mut codes)
            .await
    });
    (type_tx, asks_rx, join)
}

/// The real code exchange, flagging when this side sent its final
/// confirmation (the joiner's `msg_c`).
#[derive(Clone)]
struct FlagConfirm(Arc<AtomicU8>);

struct FlaggedExchange {
    inner: <CpaceExchangeFactory as CodeExchangeFactory>::Exchange,
    flag: Arc<AtomicU8>,
}

impl CodeExchange for FlaggedExchange {
    fn step(&mut self, incoming: Option<&[u8]>) -> Result<ExchangeStep, ExchangeError> {
        let step = self.inner.step(incoming)?;
        if step.peer_confirmed && step.send.is_some() {
            self.flag.store(CONFIRMED, Ordering::SeqCst);
        }
        Ok(step)
    }
}

impl CodeExchangeFactory for FlagConfirm {
    type Exchange = FlaggedExchange;

    fn start<R: rand_core::CryptoRng + ?Sized>(
        &self,
        role: ExchangeRole,
        code: &PairingCode,
        binding: &BindingTranscript,
        sid: &[u8; SID_LEN],
        rng: &mut R,
    ) -> FlaggedExchange {
        FlaggedExchange {
            inner: CpaceExchangeFactory.start(role, code, binding, sid, rng),
            flag: self.0.clone(),
        }
    }
}

const CONFIRMED: u8 = 1;
const CUT: u8 = 2;

/// A TCP pipe that, once armed and the confirmation is out, lets that one
/// write through and then reads nothing more: the host gets `msg_c`, the
/// joiner never sees `PAIRED`.
struct LosePaired {
    tcp: tokio::net::TcpStream,
    flag: Option<Arc<AtomicU8>>,
}

impl tokio::io::AsyncRead for LosePaired {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self
            .flag
            .as_ref()
            .is_some_and(|f| f.load(Ordering::SeqCst) == CUT)
        {
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.tcp).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for LosePaired {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let written = std::pin::Pin::new(&mut self.tcp).poll_write(cx, data);
        if let (Some(flag), std::task::Poll::Ready(Ok(n))) = (&self.flag, &written) {
            if *n > 0 && flag.load(Ordering::SeqCst) == CONFIRMED {
                flag.store(CUT, Ordering::SeqCst);
            }
        }
        written
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.tcp).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_paired_is_settled_by_reconnecting_with_the_same_join() {
    let mut host = TestHost::start(new_signer()).await;
    let flag = Arc::new(AtomicU8::new(0));
    let caller = Arc::new(Caller::with_factory(
        new_signer(),
        Arc::new(ManualClock::new()),
        TlsPolicy::default(),
        FlagConfirm(flag.clone()),
    ));
    let ticket = host.invite_kind(InvitationKind::SendLink);
    let (type_tx, typed) = mpsc::unbounded_channel();
    let (asks, mut asks_rx) = mpsc::unbounded_channel();
    let route = host.route();
    let redials = Arc::new(AtomicUsize::new(0));
    let join = {
        let (caller, ticket, route, redials) = (
            caller.clone(),
            ticket.clone(),
            route.clone(),
            redials.clone(),
        );
        tokio::spawn(async move {
            let first = LosePaired {
                tcp: connect_tcp(&route).await?,
                flag: Some(flag),
            };
            let mut codes = TypedCodes { asks, typed };
            let redial = || {
                redials.fetch_add(1, Ordering::SeqCst);
                let route = route.clone();
                async move {
                    Ok(LosePaired {
                        tcp: connect_tcp(&route).await?,
                        flag: None,
                    })
                }
            };
            caller
                .join_with_redial(first, &ticket, "phone", &mut codes, false, redial)
                .await
        })
    };
    let code = host.next_code().await;
    assert_eq!(within("ask", asks_rx.recv()).await, Some(None));
    type_tx.send(code).unwrap();
    let (conn, outcome) = within("join", join).await.unwrap().unwrap();
    // The first connection lost PAIRED; the same join reconnected once and
    // learned from AUTHORIZED {live} that the host enrolled it.
    assert_eq!(outcome, JoinOutcome::AlreadyPaired);
    assert_eq!(redials.load(Ordering::SeqCst), 1);
    assert!(host.grant_of(&caller.identity()).is_some());
    assert_echo(&mut open_echo(&conn).await, b"after the lost PAIRED").await;
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_link_ends_already_paired_only_for_a_host_pinned_before() {
    let mut host = TestHost::start(new_signer()).await;
    let caller = new_caller(new_signer());
    drop(pair(&caller, &mut host, "laptop").await);

    // The device has a grant, but does not claim to know this host: a send
    // link must not skip the code exchange on the host's word alone.
    let ticket = host.invite_kind(InvitationKind::SendLink);
    let pipe = connect_tcp(&host.route()).await.unwrap();
    let err = within(
        "join",
        caller.join_with_code(pipe, &ticket, "laptop", &mut NoCode),
    )
    .await
    .unwrap_err();
    assert!(closed_with(&err, ErrorCode::PairingFailed), "{err}");

    // With its earlier pin, it is already paired.
    let pipe = connect_tcp(&host.route()).await.unwrap();
    let no_redial = || async { Err::<tokio::net::TcpStream, _>(NetError::Refused("none".into())) };
    let (conn, outcome) = within(
        "join",
        caller.join_with_redial(pipe, &ticket, "laptop", &mut NoCode, true, no_redial),
    )
    .await
    .unwrap();
    assert_eq!(outcome, JoinOutcome::AlreadyPaired);
    open_echo(&conn).await;
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_link_pairs_with_the_right_code_and_three_wrong_codes_end_it() {
    let mut host = TestHost::start(new_signer()).await;

    // The right code pairs, and the connection is live at once.
    let caller = Arc::new(new_caller(new_signer()));
    let ticket = host.invite_kind(InvitationKind::SendLink);
    let (type_code, mut asks, join) = start_link_join(caller.clone(), &host, ticket.clone());
    let code = host.next_code().await;
    assert_eq!(within("ask", asks.recv()).await, Some(None));
    type_code.send(code).unwrap();
    let (conn, outcome) = within("join", join).await.unwrap().unwrap();
    assert!(matches!(outcome, JoinOutcome::Paired(_)), "{outcome:?}");
    assert!(host.grant_of(&caller.identity()).is_some());
    assert_echo(&mut open_echo(&conn).await, b"after the code").await;
    assert_eq!(
        host.host.invitation_status(&ticket.invitation),
        Some(InvitationStatus::Consumed {
            grant: host.grant_of(&caller.identity()).unwrap()
        })
    );

    // Three wrong codes: the joiner is asked again after each of the first
    // two, then the host ends the invitation and enrolls no one.
    let stranger = Arc::new(new_caller(new_signer()));
    let ticket = host.invite_kind(InvitationKind::SendLink);
    let (type_code, mut asks, join) = start_link_join(stranger.clone(), &host, ticket.clone());
    let mut retries = Vec::new();
    for _ in 0..3 {
        let shown = host.next_code().await;
        retries.push(within("ask", asks.recv()).await.unwrap());
        type_code.send(wrong_code(&shown)).unwrap();
    }
    assert_eq!(retries, vec![None, Some(2), Some(1)]);
    let err = within("join", join).await.unwrap().unwrap_err();
    assert!(closed_with(&err, ErrorCode::AttemptsExhausted), "{err}");
    assert_eq!(host.invitation_ended().await, ErrorCode::AttemptsExhausted);
    assert_eq!(
        host.host.invitation_status(&ticket.invitation),
        Some(InvitationStatus::Ended(ErrorCode::AttemptsExhausted))
    );
    assert_eq!(host.grant_of(&stranger.identity()), None);

    // The ended invitation does not admit the device again.
    let (_type_code, _asks, join) = start_link_join(stranger.clone(), &host, ticket);
    let err = within("join", join).await.unwrap().unwrap_err();
    assert!(closed_with(&err, ErrorCode::InvitationInvalid), "{err}");
    host.stop().await;
}
