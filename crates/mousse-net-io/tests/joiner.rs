//! The joiner's side of pairing over loopback TCP: how the ticket arrived,
//! the stored flow record, the wait for the proof's answer, and step 1
//! failures on candidate addresses.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use mousse_net_core::pairing::{Arrival, InvitationKind, JoinerError, JoinerRecord, Ticket};
use mousse_net_core::session_cert::CertError;
use mousse_net_core::ErrorCode;
use mousse_net_io::certs::CertManager;
use mousse_net_io::pipe::{connect_tcp, parse_route};
use mousse_net_io::store::{FlowHold, FlowRecordStore, FlowRecords};
use mousse_net_io::{tls, Caller, JoinOutcome, Limits, ManualClock, NetError, NoCode, TlsPolicy};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

/// A caller whose flow records live in `dir`.
fn caller_with_records(signer: mousse_net_io::SharedSigner, dir: &std::path::Path) -> Caller {
    let mut caller = new_caller(signer);
    caller.use_flow_records(Arc::new(FlowRecordStore::in_dir(dir)));
    caller
}

/// Join with a send link, typing the codes `type_code` decides from the code
/// the host shows (`None` gives up). Returns the asks the joiner made and
/// the result. `shown` is the host's current code, kept across joins: a new
/// one is shown only after a failed attempt.
async fn link_join(
    caller: &Caller,
    host: &mut TestHost,
    ticket: &Ticket,
    shown: &mut Option<String>,
    mut type_code: impl FnMut(&str) -> Option<String>,
) -> (
    Vec<Option<u8>>,
    Result<(mousse_net_io::Connection, JoinOutcome), NetError>,
) {
    let (type_tx, typed) = mpsc::unbounded_channel();
    let mut type_tx = Some(type_tx);
    let (asks_tx, mut asks) = mpsc::unbounded_channel();
    let mut codes = TypedCodes {
        asks: asks_tx,
        typed,
    };
    let pipe = connect_tcp(&host.route()).await.unwrap();
    let join = caller.join_with_code(pipe, ticket, Arrival::Link, "laptop", &mut codes);
    tokio::pin!(join);
    let mut seen = Vec::new();
    loop {
        tokio::select! {
            result = &mut join => return (seen, result),
            ask = asks.recv() => {
                let Some(ask) = ask else { continue };
                seen.push(ask);
                if ask.is_some() || shown.is_none() {
                    *shown = Some(host.next_code().await);
                }
                let current = shown.clone().unwrap_or_default();
                match (type_code(&current), &type_tx) {
                    (Some(code), Some(tx)) => tx.send(code).unwrap(),
                    _ => type_tx = None,
                }
            }
            () = tokio::time::sleep(WAIT) => panic!("join stalled after asks {seen:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_in_person_ticket_that_came_as_a_link_is_refused_before_dialling() {
    let host = TestHost::start(new_signer()).await;
    let ticket = host.invite();
    let caller = new_caller(new_signer());
    let pipe = connect_tcp(&host.route()).await.unwrap();
    let err = within("join", caller.join(pipe, &ticket, Arrival::Link, "laptop"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, NetError::Join(JoinerError::InPersonFromLink)),
        "{err:?}"
    );
    assert_eq!(
        JoinerError::InPersonFromLink.code(),
        Some(ErrorCode::PairingFailed)
    );
    assert!(host.host.grants().is_empty());
    host.stop().await;
}

/// The count of code attempts survives the app being closed and the link
/// opened again: a new caller on the same endpoint state goes on from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_joiners_attempt_count_survives_a_restart() {
    let dir = temp_dir("flow-records");
    let signer = new_signer();
    let mut host = TestHost::start(new_signer()).await;
    let ticket = host.invite_kind(InvitationKind::SendLink);
    let store = FlowRecordStore::in_dir(&dir);
    let mut shown = None;

    // One wrong code, then the owner gives up.
    let first = caller_with_records(signer.clone(), &dir);
    let mut typed = 0;
    let (asks, result) = link_join(&first, &mut host, &ticket, &mut shown, |shown| {
        typed += 1;
        (typed == 1).then(|| wrong_code(shown))
    })
    .await;
    assert_eq!(asks, vec![None, Some(2)]);
    assert!(result.is_err());
    assert_eq!(
        store.load(&ticket.hash()).unwrap(),
        Some(JoinerRecord {
            ticket_hash: ticket.hash(),
            attempts_left: 2,
            outcome_pending: false,
        })
    );
    drop(first);

    // The app starts again and the link is opened again: two attempts left,
    // not three.
    let second = caller_with_records(signer, &dir);
    let (asks, result) = link_join(&second, &mut host, &ticket, &mut shown, |shown| {
        Some(wrong_code(shown))
    })
    .await;
    assert_eq!(asks, vec![None, Some(1)]);
    assert!(result.is_err());
    assert_eq!(
        store.load(&ticket.hash()).unwrap().unwrap().attempts_left,
        0
    );
    host.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A flow record store that never saves.
struct BrokenRecords;

impl FlowRecords for BrokenRecords {
    fn load(&self, _: &[u8; 32]) -> Result<Option<JoinerRecord>, NetError> {
        Ok(None)
    }

    fn swap(&self, _: Option<&JoinerRecord>, _: &JoinerRecord) -> Result<(), NetError> {
        Err(NetError::Store("disk full".into()))
    }

    fn hold(&self, _: &[u8; 32]) -> Result<FlowHold, NetError> {
        Ok(FlowHold::new(()))
    }
}

/// Flow records on disk, in an app that is killed the moment the
/// outcome-pending mark lands: that write is durable, and nothing after it
/// happens.
struct KilledAfterPendingMark(FlowRecordStore);

impl FlowRecords for KilledAfterPendingMark {
    fn load(&self, ticket_hash: &[u8; 32]) -> Result<Option<JoinerRecord>, NetError> {
        self.0.load(ticket_hash)
    }

    fn swap(&self, expected: Option<&JoinerRecord>, record: &JoinerRecord) -> Result<(), NetError> {
        self.0.swap(expected, record)?;
        if record.outcome_pending && !expected.is_some_and(|e| e.outcome_pending) {
            return Err(NetError::Store("the app was killed".into()));
        }
        Ok(())
    }

    fn hold(&self, ticket_hash: &[u8; 32]) -> Result<FlowHold, NetError> {
        self.0.hold(ticket_hash)
    }
}

/// While one join of a link waits for its code, a second join of the same
/// link on the same endpoint state is refused before it reads the flow
/// record: it could otherwise clear a pending mark the first still needs.
/// Once the first join ends, the link can be opened again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_join_of_a_link_in_progress_is_refused() {
    let dir = temp_dir("one-join");
    let signer = new_signer();
    let mut host = TestHost::start(new_signer()).await;
    let ticket = host.invite_kind(InvitationKind::SendLink);
    let first = caller_with_records(signer.clone(), &dir);
    let second = caller_with_records(signer, &dir);

    let (type_tx, typed) = mpsc::unbounded_channel::<String>();
    let (asks_tx, mut asks) = mpsc::unbounded_channel();
    let mut codes = TypedCodes {
        asks: asks_tx,
        typed,
    };
    let pipe = connect_tcp(&host.route()).await.unwrap();
    let join = first.join_with_code(pipe, &ticket, Arrival::Link, "laptop", &mut codes);
    tokio::pin!(join);
    tokio::select! {
        ask = asks.recv() => assert_eq!(ask, Some(None)),
        result = &mut join => panic!("the first join ended early: {result:?}"),
    }

    let pipe = connect_tcp(&host.route()).await.unwrap();
    let mut no_code = NoCode;
    let err = within(
        "second join",
        second.join_with_code(pipe, &ticket, Arrival::Link, "laptop", &mut no_code),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("another pairing with this link"),
        "{err}"
    );

    // The owner gives up on the first; then the link opens again.
    drop(type_tx);
    assert!(within("first join", join).await.is_err());
    let mut shown = None;
    let (asks, result) = link_join(&second, &mut host, &ticket, &mut shown, |shown| {
        Some(shown.into())
    })
    .await;
    assert_eq!(asks, vec![None]);
    assert!(matches!(result.unwrap().1, JoinOutcome::Paired(_)));
    second.pin_stored(&ticket).unwrap();
    host.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The outcome-pending mark is stored before this side's confirmation goes
/// out. If the app dies right after it lands, the confirmation never
/// leaves and the host enrolls nothing; opening the link again with the
/// stored record reconnects, learns that it is not enrolled, and pairs with
/// the current code. The mark is cleared only once the pin is stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_between_the_pending_mark_and_the_confirmation_still_recovers() {
    let dir = temp_dir("pending-crash");
    let signer = new_signer();
    let mut host = TestHost::start(new_signer()).await;
    let ticket = host.invite_kind(InvitationKind::SendLink);
    let store = FlowRecordStore::in_dir(&dir);
    let mut shown = None;

    let mut first = new_caller(signer.clone());
    first.use_flow_records(Arc::new(KilledAfterPendingMark(FlowRecordStore::in_dir(
        &dir,
    ))));
    let (asks, result) = link_join(&first, &mut host, &ticket, &mut shown, |shown| {
        Some(shown.into())
    })
    .await;
    assert_eq!(asks, vec![None]);
    let err = result.map(|(_, outcome)| outcome).unwrap_err();
    assert!(matches!(err, NetError::Store(_)), "{err:?}");
    assert_eq!(
        store.load(&ticket.hash()).unwrap(),
        Some(JoinerRecord {
            ticket_hash: ticket.hash(),
            attempts_left: 2,
            outcome_pending: true,
        })
    );
    // The confirmation never went out.
    assert!(host.host.grants().is_empty());
    drop(first);
    // The attempt drew the next code when it started.
    shown = Some(host.next_code().await);

    let second = caller_with_records(signer, &dir);
    let (asks, result) = link_join(&second, &mut host, &ticket, &mut shown, |shown| {
        Some(shown.into())
    })
    .await;
    assert_eq!(asks, vec![None]);
    let (_conn, outcome) = result.unwrap();
    assert!(matches!(outcome, JoinOutcome::Paired(_)), "{outcome:?}");
    assert!(!host.host.grants().is_empty());
    assert!(store.load(&ticket.hash()).unwrap().unwrap().outcome_pending);
    second.pin_stored(&ticket).unwrap();
    assert_eq!(
        store.load(&ticket.hash()).unwrap(),
        Some(JoinerRecord {
            ticket_hash: ticket.hash(),
            attempts_left: 1,
            outcome_pending: false,
        })
    );
    host.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The debit is saved before the attempt's first message goes out: when
/// the save fails, nothing is sent, even with the right code.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attempt_whose_debit_cannot_be_saved_sends_nothing() {
    let mut host = TestHost::start(new_signer()).await;
    let ticket = host.invite_kind(InvitationKind::SendLink);
    let mut caller = new_caller(new_signer());
    caller.use_flow_records(Arc::new(BrokenRecords));
    let mut shown = None;
    let (_, result) = link_join(&caller, &mut host, &ticket, &mut shown, |shown| {
        Some(shown.into())
    })
    .await;
    let err = result.map(|(_, outcome)| outcome).unwrap_err();
    assert!(matches!(err, NetError::Store(_)), "{err:?}");
    assert!(host.host.grants().is_empty());

    // The host saw no attempt: another device still has all three.
    let other = new_caller(new_signer());
    let (asks, result) = link_join(&other, &mut host, &ticket, &mut shown, |shown| {
        Some(wrong_code(shown))
    })
    .await;
    assert_eq!(asks, vec![None, Some(2), Some(1)]);
    assert!(result.is_err());
    host.stop().await;
}

/// A host that completes TLS and then never answers the join proof: the
/// joiner closes with `NOT_AUTHORIZED` once 10 s have passed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proof_with_no_answer_closes_after_ten_seconds() {
    let host_clock = Arc::new(ManualClock::new());
    let host_cert = CertManager::new(new_signer(), host_clock.clone())
        .current()
        .unwrap();
    let host_identity = *host_cert.identity();
    let listener = tokio::net::TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let route = parse_route(&format!("tcp://{}", listener.local_addr().unwrap())).unwrap();
    let silent = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let (mut tls, _) = tls::accept(tcp, &host_cert, host_clock, TlsPolicy::default())
            .await
            .unwrap();
        let mut buf = [0u8; 4096];
        while matches!(tls.read(&mut buf).await, Ok(n) if n > 0) {}
    });

    // A ticket naming the silent host.
    let real = TestHost::start(new_signer()).await;
    let mut ticket = real.invite();
    ticket.host_identity = host_identity;
    real.stop().await;

    let clock = Arc::new(ManualClock::new());
    let caller = new_caller_with_clock(new_signer(), clock.clone());
    let pipe = connect_tcp(&route).await.unwrap();
    let mut no_code = NoCode;
    let join = caller.join_with_code(pipe, &ticket, Arrival::InAppScan, "laptop", &mut no_code);
    tokio::pin!(join);
    // Not before the wait is over.
    assert!(
        tokio::time::timeout(Duration::from_millis(1_500), &mut join)
            .await
            .is_err(),
        "gave up before the wait was over"
    );
    clock.advance_mono(Limits::DEFAULT.io().proof_answer_wait_ms());
    let err = within("give up", join).await.unwrap_err();
    assert!(closed_with(&err, ErrorCode::NotAuthorized), "{err:?}");
    silent.abort();
}

/// Any step 1 failure on a candidate address means "try the next one". A
/// certificate failure is reported only when no candidate passed, the
/// window one (the clock message) over an address that did not answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_step_one_failure_on_a_candidate_tries_the_next_and_the_clock_message_waits() {
    let signer = new_signer();
    let mut good = TestHost::start(signer.clone()).await;
    let caller = new_caller(new_signer());
    drop(pair(&caller, &mut good, "laptop").await);

    // The same identity on another address, with a clock two days behind:
    // its certificate is outside the caller's window.
    let skewed = TestHost::start(signer).await;
    skewed.clock.advance(-2 * 86_400);
    let stranger = TestHost::start(new_signer()).await;
    let nobody = {
        let listener = tokio::net::TcpListener::bind((LOOPBACK, 0)).await.unwrap();
        let route = parse_route(&format!("tcp://{}", listener.local_addr().unwrap())).unwrap();
        drop(listener);
        route
    };
    let pin = good.identity();

    let (conn, used) = within(
        "dial",
        caller.dial_candidates(&[stranger.route(), skewed.route(), good.route()], pin),
    )
    .await
    .unwrap();
    assert_eq!(used, good.route());
    drop(conn);

    let err = within(
        "dial",
        caller.dial_candidates(&[skewed.route(), nobody.clone(), stranger.route()], pin),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, NetError::PeerCertificate(CertError::OutsideWindow)),
        "{err:?}"
    );

    // Another endpoint alone is not reported as a certificate problem.
    let err = within("dial", caller.dial_candidates(&[stranger.route()], pin))
        .await
        .unwrap_err();
    assert!(!matches!(err, NetError::PeerCertificate(_)), "{err:?}");
    for host in [good, skewed, stranger] {
        host.stop().await;
    }
}
