//! The join-proof deadlines on both sides, at their boundary: an answer or
//! a proof one millisecond before the deadline counts, one at the deadline
//! does not, even when it arrives before the timer runs.
//!
//! The read path alone decides: the endpoints' clocks are frozen and moved
//! by hand, the tests run on paused tokio time over in-memory pipes, so no
//! real timer or ticker can fire between moving a clock and the read that
//! follows it (paused time moves only when every task waits).

mod common;

use std::sync::Arc;

use common::*;
use mousse_net_core::control::{AuthorizedState, ControlMessage, VersionSupport};
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::{Mux, MuxEvent, MuxRole};
use mousse_net_core::pairing::Arrival;
use mousse_net_core::ErrorCode;
use mousse_net_io::certs::CertManager;
use mousse_net_io::{tls, Clock, CloseReason, Limits, ManualClock, NetError, NoCode, TlsPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};

const WAIT_MS: u64 = Limits::DEFAULT.io().proof_answer_wait_ms();
const PROOF_WAIT_MS: u64 = Limits::DEFAULT.core().join_proof_wait_ms();

fn hello() -> ControlMessage {
    ControlMessage::Hello {
        major_version: VersionSupport::LOCAL.major,
        minor_version: VersionSupport::LOCAL.minor,
    }
}

/// What the test tells the fake host to send.
enum Say {
    Control(ControlMessage),
    GoAway(ErrorCode),
}

/// A host that completes TLS, says HELLO, reports the joiner's JOIN_PROOF
/// and then sends only what the test tells it to. After each control
/// message it pings, and reports the pong: the joiner has handled the
/// message by then.
struct FakeHost {
    proof: oneshot::Receiver<()>,
    handled: mpsc::UnboundedReceiver<()>,
    say: mpsc::UnboundedSender<Say>,
    task: tokio::task::JoinHandle<()>,
}

/// Start a fake host on an in-memory pipe; returns it, the joiner's end of
/// the pipe and the host's identity.
fn fake_host() -> (FakeHost, DuplexStream, IdentityPublicKey) {
    let clock = Arc::new(ManualClock::new());
    let cert = CertManager::new(new_signer(), clock.clone())
        .current()
        .unwrap();
    let identity = *cert.identity();
    let (hosts, joiners) = tokio::io::duplex(1 << 16);
    let (proof_tx, proof) = oneshot::channel();
    let (say, mut said) = mpsc::unbounded_channel::<Say>();
    let (handled_tx, handled) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let (stream, _) = tls::accept(hosts, &cert, clock.clone(), TlsPolicy::default())
            .await
            .unwrap();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let mut mux = Mux::new(MuxRole::Host, clock.mono());
        mux.send_control(hello().encode()).unwrap();
        let mut proof_tx = Some(proof_tx);
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            while let Some(frame) = mux.poll_transmit(clock.mono()) {
                if wr.write_all(&frame).await.is_err() {
                    return;
                }
            }
            let _ = wr.flush().await;
            tokio::select! {
                read = rd.read(&mut buf) => {
                    let n = match read {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };
                    let Ok(events) = mux.receive(&buf[..n], clock.mono()) else {
                        return;
                    };
                    for event in events {
                        match event {
                            MuxEvent::Control(bytes)
                                if matches!(
                                    ControlMessage::decode(&bytes),
                                    Ok(ControlMessage::JoinProof { .. })
                                ) =>
                            {
                                if let Some(tx) = proof_tx.take() {
                                    let _ = tx.send(());
                                }
                            }
                            MuxEvent::Pong { .. } => {
                                let _ = handled_tx.send(());
                            }
                            _ => {}
                        }
                    }
                }
                say = said.recv() => match say {
                    Some(Say::Control(message)) => {
                        mux.send_control(message.encode()).unwrap();
                        while let Some(frame) = mux.poll_transmit(clock.mono()) {
                            if wr.write_all(&frame).await.is_err() {
                                return;
                            }
                        }
                        // Quiet for a keepalive period: the mux pings.
                        clock.advance_mono(Limits::DEFAULT.core().keepalive_ms());
                        if mux.on_timeout(clock.mono()).is_err() {
                            return;
                        }
                    }
                    Some(Say::GoAway(code)) => mux.close(code),
                    None => return,
                },
            }
        }
    });
    (
        FakeHost {
            proof,
            handled,
            say,
            task,
        },
        joiners,
        identity,
    )
}

/// The joiner's side: join the fake host in person with the clock at
/// `elapsed` ms after the proof went out when the answer arrives. Returns
/// how the join ended.
async fn answer_at(elapsed: u64) -> NetError {
    let (host, pipe, identity) = fake_host();
    let real = TestHost::start(new_signer()).await;
    let mut ticket = real.invite();
    ticket.host_identity = identity;
    real.stop().await;

    let clock = Arc::new(ManualClock::new());
    clock.freeze_mono();
    let caller = new_caller_with_clock(new_signer(), clock.clone());
    let mut no_code = NoCode;
    let join = caller.join_with_code(pipe, &ticket, Arrival::InAppScan, "laptop", &mut no_code);
    tokio::pin!(join);
    let FakeHost {
        proof,
        mut handled,
        say,
        task,
    } = host;
    tokio::select! {
        _ = &mut join => panic!("the join ended before its proof was sent"),
        seen = proof => seen.unwrap(),
    }
    // The joiner's driver now sleeps on the recheck. Paused time does not
    // move while the answer is on its way, so it reaches the read first.
    clock.advance_mono(elapsed);
    say.send(Say::Control(ControlMessage::Authorized {
        state: AuthorizedState::JoinOnly,
    }))
    .unwrap();
    let err = tokio::select! {
        result = &mut join => result.unwrap_err(),
        seen = handled.recv() => match seen {
            // The joiner hung up, and the fake host saw it first.
            None => within("join end", join).await.unwrap_err(),
            // The answer counted, so the wait is over for good: past it,
            // the join ends only when the host says no.
            Some(()) => {
                clock.advance_mono(WAIT_MS);
                say.send(Say::GoAway(ErrorCode::PairingDeclined)).unwrap();
                within("join end", join).await.unwrap_err()
            }
        }
    };
    task.abort();
    err
}

/// An answer one millisecond before the wait is over counts: the joiner
/// waits for the owner and ends only when the host says no.
#[tokio::test(start_paused = true)]
async fn an_answer_just_in_time_counts() {
    let err = answer_at(WAIT_MS - 1).await;
    assert!(
        matches!(
            err,
            NetError::Closed(CloseReason::Peer(ErrorCode::PairingDeclined))
        ),
        "{err:?}"
    );
}

/// An answer at the end of the wait does not, even if it is read before
/// the joiner's timer runs.
#[tokio::test(start_paused = true)]
async fn an_answer_at_the_end_of_the_wait_is_refused() {
    let err = answer_at(WAIT_MS).await;
    assert!(
        matches!(
            err,
            NetError::Closed(CloseReason::Local(ErrorCode::NotAuthorized))
        ),
        "{err:?}"
    );
}

/// The host's side: a caller with no grant sends a JOIN_PROOF (with a
/// wrong MAC) `elapsed` ms after it connected. Returns the host's close.
async fn proof_at(host: &TestHost, elapsed: u64) -> ErrorCode {
    let caller_clock = Arc::new(ManualClock::new());
    let cert = CertManager::new(new_signer(), caller_clock.clone())
        .current()
        .unwrap();
    let (hosts, callers) = tokio::io::duplex(1 << 16);
    let accepting = host.host.clone();
    let accept = tokio::spawn(async move { accepting.accept(hosts).await });
    let (stream, _) = tls::connect(
        callers,
        &cert,
        host.identity(),
        caller_clock.clone(),
        TlsPolicy::default(),
    )
    .await
    .unwrap();
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut mux = Mux::new(MuxRole::Caller, caller_clock.mono());
    mux.send_control(hello().encode()).unwrap();
    let mut buf = vec![0u8; 16 * 1024];
    let mut proof_sent = false;
    let invitation = host.invite().invitation;
    loop {
        while let Some(frame) = mux.poll_transmit(caller_clock.mono()) {
            wr.write_all(&frame).await.unwrap();
        }
        wr.flush().await.unwrap();
        let n = within("host frames", rd.read(&mut buf)).await.unwrap();
        assert!(n > 0, "the host hung up without a GOAWAY");
        for event in mux.receive(&buf[..n], caller_clock.mono()).unwrap() {
            match event {
                // The host's HELLO: its gate is open, and its driver sleeps
                // on the recheck. Move its clock, then send the proof.
                MuxEvent::Control(_) if !proof_sent => {
                    proof_sent = true;
                    host.clock.advance_mono(elapsed);
                    let proof = ControlMessage::JoinProof {
                        invitation,
                        mac: [7; 32],
                        name: "laptop".into(),
                    };
                    mux.send_control(proof.encode()).unwrap();
                }
                MuxEvent::GoAway { code } => {
                    accept.abort();
                    return code;
                }
                _ => {}
            }
        }
    }
}

/// A proof one millisecond before the host's wait is over is checked (and
/// this one is wrong); one at the end of the wait is refused unread, even
/// before the host's timer or ticker runs.
#[tokio::test(start_paused = true)]
async fn the_host_checks_a_proof_just_in_time_and_refuses_one_at_the_deadline() {
    let host = TestHost::start(new_signer()).await;
    host.clock.freeze_mono();
    assert_eq!(
        proof_at(&host, PROOF_WAIT_MS - 1).await,
        ErrorCode::InvitationInvalid
    );
    assert_eq!(
        proof_at(&host, PROOF_WAIT_MS).await,
        ErrorCode::NotAuthorized
    );
    host.stop().await;
}
