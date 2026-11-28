//! The host side of Pair with IP (wire.md 10.9) in `mousse-net-io`, over
//! real TCP and TLS on loopback, against a scripted joiner that speaks the
//! wire messages itself with the real code exchange.
//!
//! Both sides speak minor 4 through the debug-only test hook
//! (`MOUSSE_NET_TEST_HELLO_MINOR`); the variable is process wide, so every
//! test in this binary sets it before anything starts.
//!
//! What each test pins, and the must-fail control that breaks it:
//!
//! | Test | Control |
//! |---|---|
//! | success: Allow, then the first stream commits | `direct-skip-allow`, `direct-attempt-not-debited` |
//! | a wrong lookup is held for the full hold, place and all | `direct-miss-closes-at-once` |
//! | relay circuits and ws tunnels are refused | `direct-on-any-transport` |
//! | a granted device's lookup takes a place counted against its source | `direct-live-place-without-source` |
//! | Allow while away, then recovery | `direct-enroll-without-connection` |
//! | a cancel crossing Allow removes the provisional grant | `direct-allow-beats-cancel` |
//! | a provisional grant survives a restart; its commit is saved | `direct-commit-unsaved` |
#![cfg(debug_assertions)]

mod common;

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};

use common::*;
use mousse_net_core::control::{
    AuthorizedState, ControlMessage, DirectRecovery, VersionSupport, DIRECT_MINOR_VERSION,
};
use mousse_net_core::grants::{OwnerRef, Role};
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::{Mux, MuxEvent, MuxRole, PriorityClass};
use mousse_net_core::pairing::{
    attempt_sid, direct_binding_transcript, AttemptId, CodeExchange, CodeExchangeFactory,
    CpaceExchangeFactory, DirectCode, DirectLookup, DirectRequestId, ExchangeRole, InvitationId,
    RequestDecision, RequestPresence, EXPORTER_LEN,
};
use mousse_net_core::ErrorCode;
use mousse_net_io::certs::CertManager;
use mousse_net_io::conn::TEST_HELLO_MINOR_VAR;
use mousse_net_io::pipe::{accept_tcp, connect_tcp, route_from_addr};
use mousse_net_io::rng::os_rng;
use mousse_net_io::{
    tls, Clock, DirectEvent, DirectInvite, Host, HostConfig, HostEvent, Limits, ListenerKind,
    ManualClock, SharedSigner, TlsPolicy,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const HOLD_MS: u64 = Limits::DEFAULT.core().direct_miss_hold_ms();

/// Speak minor 4 on both sides. Set once, before any connection reads it.
fn minor_4() {
    static SET: Once = Once::new();
    const _: () = assert!(VersionSupport::LOCAL.minor < DIRECT_MINOR_VERSION);
    SET.call_once(|| std::env::set_var(TEST_HELLO_MINOR_VAR, DIRECT_MINOR_VERSION.to_string()));
}

// ---------------------------------------------------------------------------
// The host: a TCP listener that admits each connection as serve.rs does
// (a TCP place counted against the source address), and echoes streams.

struct DirectHost {
    host: Host,
    events: mpsc::UnboundedReceiver<HostEvent>,
    addr: SocketAddr,
    accept: JoinHandle<()>,
}

impl DirectHost {
    async fn start(signer: SharedSigner, state_dir: Option<PathBuf>) -> Self {
        let clock = Arc::new(ManualClock::new());
        let config = HostConfig {
            name: "desk".into(),
            state_dir,
            owner: OwnerRef::from_bytes([0x5a; 16]),
            limits: Limits::DEFAULT,
            clock,
            ticket_identity: None,
            streams: None,
        };
        let (host, events) =
            Host::new(signer, config, CpaceExchangeFactory).expect("the host starts");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepting = host.clone();
        let accept = tokio::spawn(async move {
            let streams = Arc::new(AtomicUsize::new(0));
            while let Ok((pipe, from)) = accept_tcp(&listener).await {
                let Ok(slot) = accepting.admit(ListenerKind::Tcp, Some(from.ip())) else {
                    continue;
                };
                let host = accepting.clone();
                let streams = streams.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = host.accept_admitted(pipe, slot).await {
                        serve_echo(conn, streams).await;
                    }
                });
            }
        });
        Self {
            host,
            events,
            addr,
            accept,
        }
    }

    fn invite(&self) -> DirectInvite {
        self.host
            .invite_direct(self.addr, Role::owner())
            .expect("a direct invitation")
    }

    /// The next Pair with IP event.
    async fn next(&mut self) -> DirectEvent {
        loop {
            match within("a Pair with IP event", self.events.recv()).await {
                Some(HostEvent::Direct(event)) => return event,
                Some(_) => continue,
                None => panic!("host events ended"),
            }
        }
    }

    /// Skip events until one matches.
    async fn until(&mut self, what: &str, f: impl Fn(&DirectEvent) -> bool) -> DirectEvent {
        loop {
            let event = self.next().await;
            if f(&event) {
                return event;
            }
            let _ = what;
        }
    }

    fn provisional_of(&self, identity: &IdentityPublicKey) -> bool {
        self.host
            .provisional_grants()
            .iter()
            .any(|g| g.identity == *identity)
    }

    fn granted(&self, identity: &IdentityPublicKey) -> bool {
        self.host.grants().iter().any(|g| g.identity == *identity)
    }

    async fn stop(self) {
        self.accept.abort();
        let _ = self.accept.await;
        self.host.close_all(ErrorCode::NoError);
    }
}

// ---------------------------------------------------------------------------
// The scripted joiner: TLS (pinned to the host, as a test may), the mux, and
// the code exchange by hand.

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// What arrived from the host.
#[derive(Debug, PartialEq, Eq)]
enum Got {
    Control(ControlMessage),
    Data(Vec<u8>),
    GoAway(ErrorCode),
    /// The pipe ended with no GOAWAY.
    Closed,
}

struct Joiner {
    signer: SharedSigner,
    identity: IdentityPublicKey,
    clock: Arc<ManualClock>,
}

impl Joiner {
    fn new() -> Self {
        let signer = new_signer();
        let identity = signer.public_key();
        Self {
            signer,
            identity,
            clock: Arc::new(ManualClock::new()),
        }
    }

    /// Dial the host's listener over TCP.
    async fn dial(&self, host: &DirectHost) -> Peer {
        let pipe = connect_tcp(&route_from_addr(host.addr)).await.unwrap();
        self.connect(pipe, host.host.identity()).await
    }

    /// TLS on `pipe`, `HELLO` both ways (the joiner waits for the host's).
    async fn connect(&self, pipe: impl mousse_net_io::pipe::Pipe, host: IdentityPublicKey) -> Peer {
        let cert = CertManager::new(self.signer.clone(), self.clock.clone())
            .current()
            .unwrap();
        let (stream, handshake) = within(
            "the TLS handshake",
            tls::connect(pipe, &cert, host, self.clock.clone(), TlsPolicy::default()),
        )
        .await
        .expect("TLS to the host");
        let mut mux = Mux::new(MuxRole::Caller, self.clock.mono());
        let hello = ControlMessage::Hello {
            major_version: VersionSupport::LOCAL.major,
            minor_version: DIRECT_MINOR_VERSION,
        };
        mux.send_control(hello.encode()).unwrap();
        let mut peer = Peer {
            io: Box::new(stream),
            mux,
            clock: self.clock.clone(),
            pending: VecDeque::new(),
            pair: handshake.exporters.pair,
            host,
            joiner: self.identity,
            attempt: None,
        };
        match peer.next().await {
            Got::Control(ControlMessage::Hello { minor_version, .. }) => {
                assert_eq!(
                    minor_version, DIRECT_MINOR_VERSION,
                    "the host speaks minor 4"
                );
            }
            other => panic!("expected the host's HELLO, got {other:?}"),
        }
        peer
    }
}

struct Peer {
    io: Box<dyn Io>,
    mux: Mux,
    clock: Arc<ManualClock>,
    pending: VecDeque<MuxEvent>,
    pair: [u8; EXPORTER_LEN],
    host: IdentityPublicKey,
    joiner: IdentityPublicKey,
    attempt: Option<AttemptId>,
}

impl Peer {
    async fn flush(&mut self) {
        while let Some(frame) = self.mux.poll_transmit(self.clock.mono()) {
            if self.io.write_all(&frame).await.is_err() {
                return;
            }
        }
        let _ = self.io.flush().await;
    }

    fn send(&mut self, message: ControlMessage) {
        self.mux.send_control(message.encode()).unwrap();
    }

    /// Send and push it out.
    async fn say(&mut self, message: ControlMessage) {
        self.send(message);
        self.flush().await;
    }

    /// The next thing the host sent that matters here (pongs, stream opens
    /// and ends are skipped).
    async fn next(&mut self) -> Got {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            while let Some(event) = self.pending.pop_front() {
                match event {
                    MuxEvent::Control(bytes) => {
                        return Got::Control(ControlMessage::decode(&bytes).expect("a message"))
                    }
                    MuxEvent::Data { stream, bytes } => {
                        self.mux.release(stream, bytes.len() as u64);
                        return Got::Data(bytes);
                    }
                    MuxEvent::GoAway { code } => return Got::GoAway(code),
                    _ => {}
                }
            }
            self.flush().await;
            let n = match within("the host", self.io.read(&mut buf)).await {
                Ok(n) if n > 0 => n,
                _ => return Got::Closed,
            };
            match self.mux.receive(&buf[..n], self.clock.mono()) {
                Ok(events) => self.pending.extend(events),
                Err(_) => return Got::Closed,
            }
        }
    }

    async fn control(&mut self) -> ControlMessage {
        match self.next().await {
            Got::Control(message) => message,
            other => panic!("expected a control message, got {other:?}"),
        }
    }

    /// Read until the host closes; return its GOAWAY code.
    async fn closed_with(&mut self) -> ErrorCode {
        loop {
            match self.next().await {
                Got::GoAway(code) => return code,
                Got::Closed => panic!("the host hung up without a GOAWAY"),
                _ => {}
            }
        }
    }

    async fn join_direct(&mut self, lookup: DirectLookup, recovery: Option<DirectRecovery>) {
        self.say(ControlMessage::JoinDirect {
            lookup,
            name: "laptop".into(),
            recovery,
        })
        .await;
    }

    /// Look the code up; the host answers `AUTHORIZED {join_only, I}`.
    async fn admitted(&mut self, code: &DirectCode) -> InvitationId {
        self.join_direct(code.lookup(), None).await;
        match self.control().await {
            ControlMessage::AuthorizedDirect {
                invitation,
                not_received: false,
            } => invitation,
            other => panic!("expected AUTHORIZED {{join_only, I}}, got {other:?}"),
        }
    }

    /// Run one attempt with `typed` against invitation `invitation`. True
    /// when the host's confirmation verified (then `msg_c` went out).
    async fn attempt(&mut self, typed: &DirectCode, invitation: InvitationId) -> bool {
        let attempt = AttemptId(mousse_net_io::rng::random_bytes::<16>());
        self.attempt = Some(attempt);
        let binding = direct_binding_transcript(
            &typed.lookup(),
            &invitation,
            &self.host,
            &self.joiner,
            &self.pair,
        );
        let sid = attempt_sid(&attempt, &self.pair);
        let secret = typed.secret();
        let mut exchange = CpaceExchangeFactory.start(
            ExchangeRole::Initiator,
            secret.as_bytes(),
            &binding,
            &sid,
            &mut os_rng(),
        );
        let msg_a = exchange.step(None).unwrap().send.expect("msg_a");
        self.say(ControlMessage::CodeExchange {
            attempt,
            payload: msg_a,
        })
        .await;
        let msg_b = match self.control().await {
            ControlMessage::CodeExchange { payload, .. } => payload,
            other => panic!("expected msg_b, got {other:?}"),
        };
        match exchange.step(Some(&msg_b)) {
            Ok(step) => {
                assert!(step.peer_confirmed, "the host's confirmation verified");
                let msg_c = step.send.expect("msg_c");
                self.say(ControlMessage::CodeExchange {
                    attempt,
                    payload: msg_c,
                })
                .await;
                true
            }
            Err(_) => {
                self.say(ControlMessage::CodeAbort {
                    attempt,
                    code: ErrorCode::PairingFailed,
                })
                .await;
                false
            }
        }
    }

    /// Open a stream and see one round trip through the host's echo.
    async fn echo(&mut self) {
        let stream = self
            .mux
            .open_stream(PriorityClass::Interactive, "terminal")
            .unwrap();
        self.mux.send(stream, b"ping").unwrap();
        loop {
            match self.next().await {
                Got::Data(bytes) => {
                    assert_eq!(bytes, b"ping");
                    return;
                }
                Got::Control(_) => continue,
                other => panic!("the stream did not run: {other:?}"),
            }
        }
    }

    /// Close with `GOAWAY(code)`.
    async fn goaway(mut self, code: ErrorCode) {
        self.mux.close(code);
        self.flush().await;
        let _ = self.io.shutdown().await;
    }
}

/// A code with the same lookup and another secret.
fn other_secret(code: &DirectCode) -> DirectCode {
    let text = code.as_str();
    let flipped: String = text[4..]
        .chars()
        .map(|c| if c == '0' { '1' } else { '0' })
        .collect();
    DirectCode::parse(&format!("{}{flipped}", &text[..4])).unwrap()
}

/// A lookup no open invitation has.
fn other_lookup(code: &DirectCode) -> DirectLookup {
    let first = code.as_str().as_bytes()[0];
    let swapped = if first == b'Z' { "Y" } else { "Z" };
    DirectLookup::from_canonical(&format!("{swapped}{}", &code.as_str()[1..4])).unwrap()
}

/// Pass the code on a fresh connection and wait for the host's prompt.
async fn passed(host: &mut DirectHost, joiner: &Joiner, invite: &DirectInvite) -> Peer {
    let mut peer = joiner.dial(host).await;
    let invitation = peer.admitted(&invite.code).await;
    assert_eq!(invitation, invite.invitation);
    assert!(peer.attempt(&invite.code, invitation).await);
    peer
}

// ---------------------------------------------------------------------------

/// The code passes, the owner allows, the device is told it is paired under
/// a provisional grant, and its first stream commits that grant before
/// anything on it runs. Each attempt is debited, and nothing pairs before
/// the owner allows.
#[tokio::test]
async fn the_code_then_allow_pairs_and_the_first_stream_commits() {
    minor_4();
    let mut host = DirectHost::start(new_signer(), None).await;
    let joiner = Joiner::new();
    let invite = host.invite();
    assert_eq!(invite.attempts_left, 5);

    let mut peer = passed(&mut host, &joiner, &invite).await;
    assert_eq!(
        host.next().await,
        DirectEvent::Code {
            invitation: invite.invitation,
            attempts_left: 4
        },
        "the attempt was debited"
    );
    let request = match host.next().await {
        DirectEvent::Approval(a) => {
            assert_eq!(a.request.identity, joiner.identity);
            assert_eq!(a.presence, RequestPresence::Connected);
            assert_eq!(a.decision, RequestDecision::Pending);
            a.request
        }
        other => panic!("the owner is asked first, got {other:?}"),
    };
    assert!(
        !host.provisional_of(&joiner.identity) && !host.granted(&joiner.identity),
        "nothing is granted before Allow"
    );

    host.host.allow_direct(&request, None).unwrap();
    match peer.control().await {
        ControlMessage::Paired { host_name, role } => {
            assert_eq!(host_name, "desk");
            assert_eq!(role, Role::owner());
        }
        other => panic!("expected PAIRED, got {other:?}"),
    }
    assert!(host.provisional_of(&joiner.identity));
    assert!(
        !host.granted(&joiner.identity),
        "provisional until a stream"
    );

    peer.echo().await;
    host.until("the commit", |e| matches!(e, DirectEvent::Committed { .. }))
        .await;
    assert!(host.granted(&joiner.identity));
    assert!(!host.provisional_of(&joiner.identity));
    host.stop().await;
}

/// A lookup that finds nothing holds the connection, and its pre-auth
/// place, for the whole miss hold, then closes it with
/// `INVITATION_INVALID`. No attempt is debited.
#[tokio::test]
async fn a_wrong_lookup_is_held_for_the_full_hold() {
    minor_4();
    let host = DirectHost::start(new_signer(), None).await;
    let invite = host.invite();
    let joiner = Joiner::new();
    let mut peer = joiner.dial(&host).await;
    let places = host.host.preauth_stats().open(ListenerKind::Tcp);
    assert_eq!(places, 1, "the joiner's connection holds a TCP place");

    let started = Instant::now();
    peer.join_direct(other_lookup(&invite.code), None).await;
    // Halfway through the hold the place is still held.
    tokio::time::sleep(Duration::from_millis(HOLD_MS / 2)).await;
    assert_eq!(host.host.preauth_stats().open(ListenerKind::Tcp), 1);
    assert_eq!(peer.closed_with().await, ErrorCode::InvitationInvalid);
    assert!(
        started.elapsed() >= Duration::from_millis(HOLD_MS),
        "closed after {:?}, before the {HOLD_MS} ms hold",
        started.elapsed()
    );
    assert_eq!(
        host.host.direct_code(&invite.invitation).map(|(_, n)| n),
        Some(5),
        "a miss debits nothing"
    );
    host.stop().await;
}

/// Pair with IP is answered only on connections the TCP listener accepted:
/// a relay circuit and a ws tunnel are refused with `INVITATION_INVALID`
/// at once, even for the right lookup.
#[tokio::test]
async fn a_relay_circuit_or_ws_tunnel_is_never_answered() {
    minor_4();
    let host = DirectHost::start(new_signer(), None).await;
    let invite = host.invite();
    let joiner = Joiner::new();

    for kind in [ListenerKind::Relay, ListenerKind::Ws] {
        let (hosts, joiners) = tokio::io::duplex(1 << 16);
        let accepting = host.host.clone();
        tokio::spawn(async move {
            let conn = match kind {
                ListenerKind::Relay => accepting.accept_relay(hosts).await,
                _ => {
                    let slot = accepting.admit(kind, None).unwrap();
                    accepting.accept_admitted(hosts, slot).await
                }
            };
            if let Ok(conn) = conn {
                conn.closed().await;
            }
        });
        let mut peer = joiner.connect(joiners, host.host.identity()).await;
        peer.join_direct(invite.code.lookup(), None).await;
        let started = Instant::now();
        assert_eq!(
            peer.closed_with().await,
            ErrorCode::InvitationInvalid,
            "{kind:?}"
        );
        assert!(
            started.elapsed() < Duration::from_millis(HOLD_MS),
            "{kind:?} is refused, not looked up"
        );
    }
    assert_eq!(
        host.host.direct_code(&invite.invitation).map(|(_, n)| n),
        Some(5)
    );
    host.stop().await;
}

/// A device that holds a grant here looks a code up from its live
/// connection: that first takes a new TCP place counted against its source
/// address. With its address's share full it is closed with
/// `INTERNAL_ERROR`; with one free, the place is held through the miss.
#[tokio::test]
async fn a_granted_devices_lookup_takes_a_place_counted_against_its_source() {
    minor_4();
    let host = DirectHost::start(new_signer(), None).await;
    let invite = host.invite();
    let joiner = Joiner::new();
    host.host
        .add_grant(joiner.identity, "laptop".into(), None)
        .unwrap();
    let per_source = Limits::DEFAULT.io().preauth_per_source();
    let loopback = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));

    // Full: every place of 127.0.0.1 is taken.
    let mut peer = joiner.dial(&host).await;
    assert!(matches!(
        peer.control().await,
        ControlMessage::Authorized {
            state: AuthorizedState::Live
        }
    ));
    let held: Vec<_> = (0..per_source)
        .map(|_| host.host.admit(ListenerKind::Tcp, loopback).unwrap())
        .collect();
    peer.join_direct(invite.code.lookup(), None).await;
    assert_eq!(peer.closed_with().await, ErrorCode::InternalError);
    drop(held);

    // One free: the lookup takes it, and the miss holds it.
    let mut peer = joiner.dial(&host).await;
    let _ = peer.control().await;
    let held: Vec<_> = (1..per_source)
        .map(|_| host.host.admit(ListenerKind::Tcp, loopback).unwrap())
        .collect();
    let before = host.host.preauth_stats().open(ListenerKind::Tcp);
    peer.join_direct(other_lookup(&invite.code), None).await;
    tokio::time::sleep(Duration::from_millis(HOLD_MS / 2)).await;
    assert_eq!(
        host.host.preauth_stats().open(ListenerKind::Tcp),
        before + 1
    );
    assert_eq!(peer.closed_with().await, ErrorCode::InvitationInvalid);
    drop(held);
    assert!(host.granted(&joiner.identity), "the miss leaves the grant");
    host.stop().await;
}

/// The owner allows a device whose connection dropped: no grant is made
/// then. Its recovery connection, pinned and with the receipt, is enrolled
/// at once and told it is paired.
#[tokio::test]
async fn allow_while_away_enrolls_on_the_recovery_connection() {
    minor_4();
    let mut host = DirectHost::start(new_signer(), None).await;
    let joiner = Joiner::new();
    let invite = host.invite();
    let peer = passed(&mut host, &joiner, &invite).await;
    let request = DirectRequestId {
        invitation: invite.invitation,
        identity: joiner.identity,
    };
    host.until("the prompt", |e| matches!(e, DirectEvent::Approval(_)))
        .await;
    // Dropped, not cancelled: the request stays, away.
    drop(peer);
    host.until(
        "the device away",
        |e| matches!(e, DirectEvent::Approval(a) if a.presence == RequestPresence::Away),
    )
    .await;

    host.host.allow_direct(&request, None).unwrap();
    match host.next().await {
        DirectEvent::Approval(a) => {
            assert_eq!(a.decision, RequestDecision::Allowed);
            assert_eq!(a.presence, RequestPresence::Away);
        }
        other => panic!("expected the allowed prompt, got {other:?}"),
    }
    assert!(
        !host.granted(&joiner.identity) && !host.provisional_of(&joiner.identity),
        "nothing is granted with no connection of the device"
    );

    let mut peer = joiner.dial(&host).await;
    peer.join_direct(
        invite.code.lookup(),
        Some(DirectRecovery {
            receipt: invite.invitation,
            cancel: false,
        }),
    )
    .await;
    assert!(matches!(
        peer.control().await,
        ControlMessage::AuthorizedDirect {
            invitation,
            not_received: false
        } if invitation == invite.invitation
    ));
    assert!(matches!(
        peer.control().await,
        ControlMessage::Paired { .. }
    ));
    assert!(host.provisional_of(&joiner.identity));
    peer.echo().await;
    host.until("the commit", |e| matches!(e, DirectEvent::Committed { .. }))
        .await;
    assert!(host.granted(&joiner.identity));
    host.stop().await;
}

/// The joiner cancels while the owner's Allow crosses it: its `CODE_ABORT`
/// for the attempt that passed reaches the host through the live gate and
/// removes the provisional grant, and nothing else.
#[tokio::test]
async fn a_cancel_crossing_allow_removes_the_provisional_grant() {
    minor_4();
    let mut host = DirectHost::start(new_signer(), None).await;
    let joiner = Joiner::new();
    let invite = host.invite();
    let mut peer = passed(&mut host, &joiner, &invite).await;
    let request = match host
        .until("the prompt", |e| matches!(e, DirectEvent::Approval(_)))
        .await
    {
        DirectEvent::Approval(a) => a.request,
        _ => unreachable!(),
    };

    // The cancel leaves before the joiner has read PAIRED.
    host.host.allow_direct(&request, None).unwrap();
    let attempt = peer.attempt.expect("the attempt that passed");
    peer.say(ControlMessage::CodeAbort {
        attempt,
        code: ErrorCode::Cancelled,
    })
    .await;
    assert_eq!(peer.closed_with().await, ErrorCode::Cancelled);
    host.until("the undo", |e| {
        matches!(e, DirectEvent::EnrollmentUndone { identity, .. } if *identity == joiner.identity)
    })
    .await;
    assert!(!host.provisional_of(&joiner.identity));
    assert!(!host.granted(&joiner.identity));
    host.stop().await;
}

/// A provisional grant is stored with the table: after a restart the
/// device's next ordinary connection is bound to it, and its first stream
/// commits it. The commit is saved before that stream runs, so the next
/// restart finds the grant committed.
#[tokio::test]
async fn a_provisional_grant_survives_a_restart_and_its_commit_is_saved() {
    minor_4();
    let dir = temp_dir("direct-restart");
    let signer = new_signer();
    let joiner = Joiner::new();
    let mut host = DirectHost::start(signer.clone(), Some(dir.clone())).await;
    let invite = host.invite();
    let mut peer = passed(&mut host, &joiner, &invite).await;
    let request = match host
        .until("the prompt", |e| matches!(e, DirectEvent::Approval(_)))
        .await
    {
        DirectEvent::Approval(a) => a.request,
        _ => unreachable!(),
    };
    host.host.allow_direct(&request, None).unwrap();
    assert!(matches!(
        peer.control().await,
        ControlMessage::Paired { .. }
    ));
    peer.goaway(ErrorCode::NoError).await;
    host.stop().await;

    let mut host = DirectHost::start(signer.clone(), Some(dir.clone())).await;
    assert!(
        host.provisional_of(&joiner.identity),
        "kept across the restart"
    );
    assert!(!host.granted(&joiner.identity));
    let mut peer = joiner.dial(&host).await;
    assert!(matches!(
        peer.control().await,
        ControlMessage::Authorized {
            state: AuthorizedState::Live
        }
    ));
    peer.echo().await;
    host.until("the commit", |e| matches!(e, DirectEvent::Committed { .. }))
        .await;
    peer.goaway(ErrorCode::NoError).await;
    host.stop().await;

    let host = DirectHost::start(signer, Some(dir.clone())).await;
    assert!(
        host.granted(&joiner.identity) && !host.provisional_of(&joiner.identity),
        "the commit was saved before the stream ran"
    );
    host.stop().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// A wrong secret is debited, the host keeps the same code and the
/// invitation stays open; the next connection with the right code passes.
#[tokio::test]
async fn a_wrong_secret_is_debited_and_the_code_stays() {
    minor_4();
    let mut host = DirectHost::start(new_signer(), None).await;
    let joiner = Joiner::new();
    let invite = host.invite();
    let mut peer = joiner.dial(&host).await;
    let invitation = peer.admitted(&invite.code).await;
    assert!(!peer.attempt(&other_secret(&invite.code), invitation).await);
    peer.goaway(ErrorCode::PairingFailed).await;
    assert_eq!(
        host.next().await,
        DirectEvent::Code {
            invitation,
            attempts_left: 4
        }
    );
    let (code, left) = host.host.direct_code(&invitation).unwrap();
    assert_eq!((code.as_str(), left), (invite.code.as_str(), 4));
    let _peer = passed(&mut host, &joiner, &invite).await;
    host.until("the prompt", |e| matches!(e, DirectEvent::Approval(_)))
        .await;
    host.stop().await;
}
