//! Pair with IP, the joiner's I/O (wire.md 10.9 "Joiner"), over loopback
//! TCP and TLS against the core's host machine, `DirectHostPairing`, run
//! here behind its gate (8.1) by a small host. Both sides speak minor 4.
//!
//! `MOUSSE_NET_TEST_HELLO_MINOR` is process wide: every test in this binary
//! sets it to 4 for the joiner. The test host sends its own `HELLO`, so it
//! can speak minor 3 where a test needs an older host.
#![cfg(debug_assertions)]

mod common;

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{new_signer, temp_dir, within};
use mousse_net_core::authz::{ConnectionGate, Traffic, Verdict};
use mousse_net_core::control::{
    AuthorizedState, ControlMessage, VersionSupport, DIRECT_MINOR_VERSION,
};
use mousse_net_core::grants::{GrantEvent, GrantTable, OwnerRef, Role};
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::{Mux, MuxEvent, MuxRole, PriorityClass};
use mousse_net_core::pairing::{
    AttemptId, CpaceExchangeFactory, DirectAddress, DirectEnd, DirectHostAction, DirectHostPairing,
    DirectInvitationParams, DirectLookup, DirectPaired, DirectPending, DirectRequestId,
    InvitationId, DIRECT_CODE_ALPHABET,
};
use mousse_net_core::{ConnectionId, ErrorCode, UnixTime};
use mousse_net_io::certs::CertManager;
use mousse_net_io::conn::TEST_HELLO_MINOR_VAR;
use mousse_net_io::tls::DeniedCheck;
use mousse_net_io::{
    tls, Caller, Clock, DirectJoin, DirectJoinEvent, DirectPins, DirectRecordStore, DirectRecords,
    DirectSetup, Limits, MemoryDirectRecords, NetError, SharedSigner, SystemClock, TlsPolicy,
};
use rand_core::{TryCryptoRng, TryRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const HOST_NAME: &str = "Desk";

fn minor_4() {
    std::env::set_var(TEST_HELLO_MINOR_VAR, DIRECT_MINOR_VERSION.to_string());
}

/// Draws for `create`: the invitation id, then the code `forced` (12
/// characters of the code alphabet), when one is given.
struct Draws {
    forced: Option<Vec<u8>>,
}

impl TryRng for Draws {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(rand_core::Rng::next_u32(&mut mousse_net_io::rng::os_rng()))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(rand_core::Rng::next_u64(&mut mousse_net_io::rng::os_rng()))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        match (&self.forced, dst.len()) {
            (Some(code), 12) => dst.copy_from_slice(code),
            _ => rand_core::Rng::fill_bytes(&mut mousse_net_io::rng::os_rng(), dst),
        }
        Ok(())
    }
}

impl TryCryptoRng for Draws {}

fn draw_for(code: &str) -> Vec<u8> {
    code.bytes()
        .filter(|c| *c != b'-')
        .map(|c| DIRECT_CODE_ALPHABET.iter().position(|a| *a == c).unwrap() as u8)
        .collect()
}

enum HostCmd {
    Send(ControlMessage),
    Close(ErrorCode),
    /// The connection breaks: no GOAWAY.
    Break,
}

struct HostConn {
    gate: ConnectionGate,
    tx: mpsc::UnboundedSender<HostCmd>,
}

struct HostState {
    machine: DirectHostPairing<CpaceExchangeFactory>,
    grants: GrantTable,
    conns: HashMap<u64, HostConn>,
    next_conn: u64,
    /// The newest minor this host speaks.
    minor: u64,
    /// The next `PAIRED` is lost: its connection breaks instead.
    lose_paired: bool,
    /// `JOIN_DIRECT` is never answered.
    silent: bool,
    /// What the host did, in order, for the tests to read.
    log: Vec<String>,
    /// TLS handshakes the host completed (it saw a client certificate).
    handshakes: usize,
    /// TLS handshakes that failed at the host.
    refused_handshakes: usize,
}

/// A host running the core's Pair with IP machine behind its gate.
struct TestHost {
    addr: SocketAddr,
    identity: IdentityPublicKey,
    state: Arc<Mutex<HostState>>,
    invitation: InvitationId,
    code: String,
    clock: Arc<dyn Clock>,
    accept: tokio::task::JoinHandle<()>,
}

fn now(clock: &Arc<dyn Clock>) -> UnixTime {
    clock.now()
}

impl TestHost {
    async fn start(signer: SharedSigner, code: Option<&str>, minor: u64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        Self::start_on(listener, signer, code, minor).await
    }

    /// A host listening at `addr`, the address of a host that stopped
    /// (its listener may take a moment to go).
    async fn start_at(addr: SocketAddr, signer: SharedSigner) -> Self {
        let listener = within("the old address", async {
            loop {
                match TcpListener::bind(addr).await {
                    Ok(listener) => return listener,
                    Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
                }
            }
        })
        .await;
        Self::start_on(listener, signer, None, DIRECT_MINOR_VERSION).await
    }

    async fn start_on(
        listener: TcpListener,
        signer: SharedSigner,
        code: Option<&str>,
        minor: u64,
    ) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let certs = Arc::new(CertManager::new(signer, clock.clone()));
        let identity = *certs.current().unwrap().identity();
        let mut machine = DirectHostPairing::new(identity, HOST_NAME.into(), CpaceExchangeFactory);
        let created = machine
            .create(
                DirectInvitationParams {
                    role: Role::owner(),
                    authorizing_owner: OwnerRef::from_bytes([0x51; 16]),
                    grant_expires_at: None,
                },
                now(&clock),
                &mut Draws {
                    forced: code.map(draw_for),
                },
            )
            .unwrap();
        let state = Arc::new(Mutex::new(HostState {
            machine,
            grants: GrantTable::new(),
            conns: HashMap::new(),
            next_conn: 1,
            minor,
            lose_paired: false,
            silent: false,
            log: Vec::new(),
            handshakes: 0,
            refused_handshakes: 0,
        }));
        let addr = listener.local_addr().unwrap();
        let (st, ck) = (state.clone(), clock.clone());
        let accept = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(tcp, certs.clone(), st.clone(), ck.clone()));
            }
        });
        Self {
            addr,
            identity,
            state,
            invitation: created.invitation,
            code: created.code.to_display().to_string(),
            clock,
            accept,
        }
    }

    fn address(&self) -> String {
        self.addr.to_string()
    }

    fn log(&self) -> Vec<String> {
        self.state.lock().unwrap().log.clone()
    }

    fn logged(&self, what: &str) -> bool {
        self.log().iter().any(|l| l.starts_with(what))
    }

    /// The owner allows `joiner`'s request, once the host has it (its
    /// confirmation may still be on its way when the joiner reports that
    /// the code passed).
    async fn allow(&self, joiner: IdentityPublicKey) {
        wait_for("the request", || self.logged("approval:")).await;
        let mut st = self.state.lock().unwrap();
        let request = DirectRequestId {
            invitation: self.invitation,
            identity: joiner,
        };
        let st = &mut *st;
        let actions = st
            .machine
            .allow(&request, None, &mut st.grants, now(&self.clock))
            .expect("allow");
        apply(st, actions);
    }

    /// Break every connection the host has (no GOAWAY).
    fn break_all(&self) {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        for c in st.conns.values() {
            let _ = c.tx.send(HostCmd::Break);
        }
    }

    fn grants(&self) -> (usize, usize) {
        let st = self.state.lock().unwrap();
        (
            st.grants.grants().count(),
            st.grants.provisional_grants().count(),
        )
    }
}

impl Drop for TestHost {
    fn drop(&mut self) {
        self.accept.abort();
        self.break_all();
    }
}

/// Apply the host machine's actions to the gates and connections.
fn apply(st: &mut HostState, actions: Vec<DirectHostAction>) {
    for a in actions {
        match a {
            DirectHostAction::Send { conn, message } => {
                if let Some(c) = st.conns.get(&conn.0) {
                    if st.lose_paired && matches!(message, ControlMessage::Paired { .. }) {
                        st.lose_paired = false;
                        st.log.push("paired_lost".into());
                        let _ = c.tx.send(HostCmd::Break);
                    } else {
                        if matches!(message, ControlMessage::Paired { .. }) {
                            st.log.push("paired".into());
                        }
                        let _ = c.tx.send(HostCmd::Send(message));
                    }
                }
            }
            DirectHostAction::Close { conn, code } => {
                st.log.push(format!("close:{}", code.name()));
                if let Some(c) = st.conns.get_mut(&conn.0) {
                    c.gate.close(code);
                    let _ = c.tx.send(HostCmd::Close(code));
                }
            }
            DirectHostAction::MissHold { conn, hold_ms } => {
                st.log.push("miss_hold".into());
                if let Some(c) = st.conns.get_mut(&conn.0) {
                    c.gate.hold();
                    let tx = c.tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(hold_ms)).await;
                        let _ = tx.send(HostCmd::Close(ErrorCode::InvitationInvalid));
                    });
                }
            }
            DirectHostAction::AdmittedJoinOnly { conn, invitation } => {
                st.log.push("admitted".into());
                if let Some(c) = st.conns.get_mut(&conn.0) {
                    c.gate.admit_join_only(invitation);
                }
            }
            DirectHostAction::Enrolled {
                conn,
                grant,
                attempt,
                ..
            } => {
                st.log.push("enrolled".into());
                if let Some(c) = st.conns.get_mut(&conn.0) {
                    c.gate.bind_direct(grant, true, attempt);
                }
            }
            DirectHostAction::Bound {
                conn,
                grant,
                provisional,
            } => {
                st.log.push("bound".into());
                if let Some(c) = st.conns.get_mut(&conn.0) {
                    c.gate.bind_direct(grant, provisional, None);
                }
            }
            DirectHostAction::Committed { bound, .. } => {
                st.log.push("committed".into());
                for b in bound {
                    if let Some(c) = st.conns.get_mut(&b.0) {
                        c.gate.committed();
                    }
                }
            }
            DirectHostAction::Grant(GrantEvent::CloseChannels { channels, code, .. }) => {
                for ch in channels {
                    if let Some(c) = st.conns.get_mut(&ch.0) {
                        c.gate.close(code);
                        let _ = c.tx.send(HostCmd::Close(code));
                    }
                }
            }
            DirectHostAction::Approval(a) => {
                st.log.push(format!("approval:{:?}", a.presence));
            }
            DirectHostAction::ApprovalEnded { reason, .. } => {
                st.log.push(format!("approval_ended:{reason:?}"));
            }
            DirectHostAction::EnrollmentUndone { .. } => st.log.push("undone".into()),
            DirectHostAction::InvitationEnded { reason, .. } => {
                st.log.push(format!("ended:{}", reason.name()));
            }
            DirectHostAction::AttemptsLeft { attempts_left, .. } => {
                st.log.push(format!("attempts_left:{attempts_left}"));
            }
        }
    }
}

/// One connection of the test host: TLS, the host's `HELLO`, step 2 with
/// its gate, then every message through the gate to the machine.
async fn serve(
    tcp: tokio::net::TcpStream,
    certs: Arc<CertManager>,
    state: Arc<Mutex<HostState>>,
    clock: Arc<dyn Clock>,
) {
    let own = certs.current().unwrap();
    let Ok((stream, handshake)) = tls::accept(tcp, &own, clock.clone(), TlsPolicy::default()).await
    else {
        state.lock().unwrap().refused_handshakes += 1;
        return;
    };
    let peer = handshake.peer.identity;
    let exporter = handshake.exporters.pair;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut mux = Mux::new(MuxRole::Host, clock.mono());
    let (conn, minor) = {
        let mut st = state.lock().unwrap();
        st.handshakes += 1;
        let conn = st.next_conn;
        st.next_conn += 1;
        let t = now(&clock);
        let gate = ConnectionGate::open(ConnectionId(conn), peer, &mut st.grants, t, clock.mono());
        let live = matches!(gate.state(), mousse_net_core::authz::GateState::Live { .. });
        st.conns.insert(
            conn,
            HostConn {
                gate,
                tx: tx.clone(),
            },
        );
        if live {
            let _ = tx.send(HostCmd::Send(ControlMessage::Authorized {
                state: AuthorizedState::Live,
            }));
        }
        (conn, st.minor)
    };
    let hello = ControlMessage::Hello {
        major_version: VersionSupport::LOCAL.major,
        minor_version: minor,
    };
    mux.send_control(hello.encode()).unwrap();
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut buf = vec![0u8; 32 * 1024];
    let mut peer_closed: Option<Option<ErrorCode>> = None;
    'run: loop {
        while let Some(frame) = mux.poll_transmit(clock.mono()) {
            if wr.write_all(&frame).await.is_err() {
                peer_closed = Some(None);
                break 'run;
            }
        }
        let _ = wr.flush().await;
        if mux.is_closed() {
            break;
        }
        tokio::select! {
            cmd = rx.recv() => match cmd {
                Some(HostCmd::Send(m)) => { let _ = mux.send_control(m.encode()); }
                Some(HostCmd::Close(code)) => mux.close(code),
                Some(HostCmd::Break) | None => break 'run,
            },
            n = rd.read(&mut buf) => {
                let n = match n { Ok(0) | Err(_) => { peer_closed = Some(None); break 'run; } Ok(n) => n };
                let Ok(events) = mux.receive(&buf[..n], clock.mono()) else {
                    peer_closed = Some(None);
                    break 'run;
                };
                for event in events {
                    match event {
                        MuxEvent::Control(bytes) => {
                            let Ok(m) = ControlMessage::decode(&bytes) else { continue };
                            if matches!(m, ControlMessage::Hello { .. }) {
                                continue;
                            }
                            if let ControlMessage::CodeAbort { code, .. } = &m {
                                state.lock().unwrap().log.push(format!("abort:{conn}:{}", code.name()));
                            }
                            on_message(&state, &clock, conn, peer, &exporter, m);
                        }
                        MuxEvent::StreamOpened { .. } => on_stream(&state, &clock, conn),
                        MuxEvent::GoAway { code } => {
                            state.lock().unwrap().log.push(format!("goaway:{conn}:{}", code.name()));
                            peer_closed = Some(Some(code));
                            break 'run;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    let mut st = state.lock().unwrap();
    st.conns.remove(&conn);
    let st = &mut *st;
    st.grants.unbind(ConnectionId(conn));
    let code = peer_closed.flatten();
    let actions =
        st.machine
            .on_connection_closed(ConnectionId(conn), code, &mut st.grants, now(&clock));
    apply(st, actions);
}

fn on_message(
    state: &Arc<Mutex<HostState>>,
    clock: &Arc<dyn Clock>,
    conn: u64,
    peer: IdentityPublicKey,
    exporter: &[u8; 32],
    m: ControlMessage,
) {
    let mut st = state.lock().unwrap();
    let st = &mut *st;
    let Some(c) = st.conns.get_mut(&conn) else {
        return;
    };
    match c.gate.check_message(&m) {
        Verdict::Allow => {}
        Verdict::Close(code) => {
            let _ = c.tx.send(HostCmd::Close(code));
            return;
        }
        _ => return,
    }
    let t = now(clock);
    let id = ConnectionId(conn);
    if st.silent && matches!(m, ControlMessage::JoinDirect { .. }) {
        st.log.push("unanswered".into());
        return;
    }
    let actions = match m {
        ControlMessage::JoinDirect {
            lookup,
            name,
            recovery,
        } => st.machine.on_join_direct(
            id,
            &peer,
            exporter,
            &lookup,
            &name,
            recovery,
            &mut st.grants,
            t,
        ),
        ControlMessage::CodeExchange { attempt, payload } => {
            st.machine
                .on_code_exchange(id, attempt, &payload, t, &mut mousse_net_io::rng::os_rng())
        }
        ControlMessage::CodeAbort { attempt, code } => {
            st.machine
                .on_code_abort(id, attempt, code, &mut st.grants, t)
        }
        _ => vec![DirectHostAction::Close {
            conn: id,
            code: ErrorCode::ProtocolError,
        }],
    };
    apply(st, actions);
}

fn on_stream(state: &Arc<Mutex<HostState>>, clock: &Arc<dyn Clock>, conn: u64) {
    let mut st = state.lock().unwrap();
    let st = &mut *st;
    let Some(c) = st.conns.get_mut(&conn) else {
        return;
    };
    match c.gate.check(Traffic::Stream) {
        Verdict::Commit(grant) => {
            let actions =
                st.machine
                    .on_first_stream(ConnectionId(conn), grant, &mut st.grants, now(clock));
            apply(st, actions);
            st.log.push("stream".into());
        }
        Verdict::Allow => st.log.push("stream".into()),
        _ => st.log.push("stream_refused".into()),
    }
}

/// The joiner's pins: stored in memory, or refused while `fail` is set.
#[derive(Default)]
struct Pins {
    stored: Mutex<Vec<DirectPaired>>,
    fail: AtomicBool,
}

impl DirectPins for Pins {
    fn store(&self, paired: &DirectPaired) -> Result<(), NetError> {
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(NetError::Store("the pin could not be stored".into()));
        }
        self.stored.lock().unwrap().push(paired.clone());
        Ok(())
    }
}

struct Joiner {
    signer: SharedSigner,
    caller: Arc<Caller>,
    setup: DirectSetup,
    pins: Arc<Pins>,
}

fn limits() -> Limits {
    Limits::DEFAULT
        .with_overrides(&[
            ("DIRECT_RETRY_FIRST_MS", 100),
            ("DIRECT_RETRY_MAX_MS", 1_000),
            ("PROOF_ANSWER_WAIT_MS", 3_000),
        ])
        .unwrap()
}

impl Joiner {
    fn new(records: Arc<dyn DirectRecords>) -> Self {
        Self::with_signer(new_signer(), records)
    }

    fn with_signer(signer: SharedSigner, records: Arc<dyn DirectRecords>) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let caller = Arc::new(Caller::new(signer.clone(), clock, limits()));
        let pins = Arc::new(Pins::default());
        let nobody: DeniedCheck = Arc::new(|_| false);
        Self {
            signer,
            caller,
            setup: DirectSetup {
                records,
                pins: pins.clone(),
                denied: nobody,
            },
            pins,
        }
    }

    /// The same device after a restart: a new caller over the same store.
    fn restarted(&self) -> Self {
        let mut again = Self::with_signer(self.signer.clone(), self.setup.records.clone());
        again.pins = self.pins.clone();
        again.setup.pins = self.pins.clone();
        again
    }

    fn identity(&self) -> IdentityPublicKey {
        self.caller.identity()
    }

    fn join(&self, host: &TestHost, code: &str) -> DirectJoin {
        self.caller
            .join_direct(&self.setup, &host.address(), code, "laptop")
            .unwrap()
    }
}

async fn next(join: &mut DirectJoin) -> DirectJoinEvent {
    within("joiner event", join.event())
        .await
        .expect("the flow ended without this event")
}

/// Wait for an event matching `want`, skipping others.
async fn until(join: &mut DirectJoin, want: impl Fn(&DirectJoinEvent) -> bool) -> DirectJoinEvent {
    loop {
        let e = next(join).await;
        if want(&e) {
            return e;
        }
    }
}

/// Every event until the stream ends.
async fn drain(join: &mut DirectJoin) -> Vec<DirectJoinEvent> {
    within("the end of the events", async {
        let mut out = Vec::new();
        while let Some(e) = join.event().await {
            out.push(e);
        }
        out
    })
    .await
}

async fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    within(what, async {
        while !f() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

fn wrong_secret(code: &str) -> String {
    let lookup = &code[..4];
    let wrong = if &code[5..] == "0000-0000" {
        "0000-0001"
    } else {
        "0000-0000"
    };
    format!("{lookup}-{wrong}")
}

fn ledger(records: &dyn DirectRecords, code: &str) -> Option<u8> {
    let lookup = DirectLookup::from_canonical(&code[..4]).unwrap();
    let anywhere = DirectAddress::parse("127.0.0.1:1").unwrap();
    records
        .load(&lookup, &anywhere)
        .unwrap()
        .0
        .map(|l| l.attempts_left)
}

fn pending_count(records: &dyn DirectRecords, code: &str) -> usize {
    let lookup = DirectLookup::from_canonical(&code[..4]).unwrap();
    let found = records.pending_slots().unwrap();
    assert!(found.unreadable.is_empty(), "{:?}", found.unreadable);
    found.slots.iter().filter(|s| s.lookup == lookup).count()
}

/// The pending record kept at `host`'s address.
fn pending_at(records: &dyn DirectRecords, host: &TestHost) -> Option<DirectPending> {
    let lookup = DirectLookup::from_canonical(&host.code[..4]).unwrap();
    let address = DirectAddress::parse(&host.address()).unwrap();
    records.load(&lookup, &address).unwrap().1
}

fn disk(tag: &str) -> (Arc<dyn DirectRecords>, PathBuf) {
    let dir = temp_dir(tag);
    (Arc::new(DirectRecordStore::in_dir(&dir)), dir)
}

/// The whole pairing: the code passes, the owner allows, the pin is stored
/// only then, the connection is live, and its first stream commits the
/// host's provisional grant.
#[tokio::test]
async fn a_connect_pairs_and_its_first_stream_commits() {
    minor_4();
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION).await;
    let (records, dir) = disk("direct-ok");
    let joiner = Joiner::new(records.clone());
    let mut join = joiner.join(&host, &host.code);
    assert_eq!(next(&mut join).await, DirectJoinEvent::CodePassed);
    // Nothing is pinned before PAIRED.
    assert!(joiner.pins.stored.lock().unwrap().is_empty());
    assert_eq!(pending_count(&*records, &host.code), 1);
    host.allow(joiner.identity()).await;
    let paired = until(&mut join, |e| matches!(e, DirectJoinEvent::Paired(_))).await;
    let DirectJoinEvent::Paired(p) = paired else {
        unreachable!()
    };
    assert_eq!(p.identity, host.identity);
    assert_eq!(p.name, HOST_NAME);
    assert_eq!(p.invitation, host.invitation);
    assert_eq!(
        next(&mut join).await,
        DirectJoinEvent::Ended(DirectEnd::Paired)
    );
    let joined = within("join end", join.finish()).await.unwrap();
    assert_eq!(joined.end, DirectEnd::Paired);
    let conn = joined.connection.expect("a live connection");
    assert!(conn.status().is_live());
    assert_eq!(joiner.pins.stored.lock().unwrap().len(), 1);
    // The pending record went after the pin; the ledger kept the debit.
    assert_eq!(pending_count(&*records, &host.code), 0);
    assert_eq!(ledger(&*records, &host.code), Some(4));
    assert_eq!(host.grants(), (0, 1));
    let _stream = within(
        "first stream",
        conn.open_stream(PriorityClass::Interactive, "app"),
    )
    .await
    .unwrap();
    wait_for("the commit", || host.logged("committed")).await;
    assert_eq!(host.grants(), (1, 0));
    std::fs::remove_dir_all(dir).ok();
}

/// A wrong secret spends one attempt and ends the Connect; the next try is
/// a new Connect. A wrong lookup finds nothing and spends nothing.
#[tokio::test]
async fn a_wrong_secret_spends_an_attempt_and_a_wrong_lookup_none() {
    minor_4();
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION).await;
    let records: Arc<dyn DirectRecords> = Arc::new(MemoryDirectRecords::default());
    let joiner = Joiner::new(records.clone());
    let mut join = joiner.join(&host, &wrong_secret(&host.code));
    // The events end once the flow has.
    assert_eq!(
        drain(&mut join).await.last(),
        Some(&DirectJoinEvent::Ended(DirectEnd::CodeFailed {
            attempts_left: 4
        }))
    );
    let joined = within("wrong secret", join.finish()).await.unwrap();
    assert_eq!(joined.end, DirectEnd::CodeFailed { attempts_left: 4 });
    assert_eq!(ledger(&*records, &host.code), Some(4));
    assert!(host.logged("attempts_left:4"));

    let other = if host.code.starts_with("0000") {
        "0001"
    } else {
        "0000"
    };
    let code = format!("{other}{}", &host.code[4..]);
    let join = joiner.join(&host, &code);
    let joined = within("wrong lookup", join.finish()).await.unwrap();
    assert_eq!(
        joined.end,
        DirectEnd::Closed(Some(ErrorCode::InvitationInvalid))
    );
    assert!(host.logged("miss_hold"));
    assert_eq!(ledger(&*records, &code), None);
    assert!(joiner.pins.stored.lock().unwrap().is_empty());
}

/// Two far ends with the typed lookup and new keys each time draw from the
/// same ledger: the count is per typed lookup, not per key.
#[tokio::test]
async fn far_ends_that_change_keys_share_one_ledger() {
    minor_4();
    let code = "K7QM-2XPA-9RTE";
    let a = TestHost::start(new_signer(), Some(code), DIRECT_MINOR_VERSION).await;
    let b = TestHost::start(new_signer(), Some(code), DIRECT_MINOR_VERSION).await;
    assert_ne!(a.identity, b.identity);
    let records: Arc<dyn DirectRecords> = Arc::new(MemoryDirectRecords::default());
    let joiner = Joiner::new(records.clone());
    let wrong = wrong_secret(code);
    let first = within("try a", joiner.join(&a, &wrong).finish())
        .await
        .unwrap();
    assert_eq!(first.end, DirectEnd::CodeFailed { attempts_left: 4 });
    let second = within("try b", joiner.join(&b, &wrong).finish())
        .await
        .unwrap();
    assert_eq!(second.end, DirectEnd::CodeFailed { attempts_left: 3 });
    assert_eq!(ledger(&*records, code), Some(3));
}

/// A far end showing this device's own key ends the flow before this
/// device's certificate goes out.
#[tokio::test]
async fn its_own_device_is_refused_before_its_certificate_goes_out() {
    minor_4();
    let signer = new_signer();
    let host = TestHost::start(signer.clone(), None, DIRECT_MINOR_VERSION).await;
    let joiner = Joiner::with_signer(signer, Arc::new(MemoryDirectRecords::default()));
    let joined = within("own device", joiner.join(&host, &host.code).finish())
        .await
        .unwrap();
    assert_eq!(joined.end, DirectEnd::OwnDevice);
}

/// A host that agrees minor 3 cannot pair this way: the joiner needs the
/// host updated, and nothing is debited.
#[tokio::test]
async fn a_minor_3_host_needs_an_update() {
    minor_4();
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION - 1).await;
    let records: Arc<dyn DirectRecords> = Arc::new(MemoryDirectRecords::default());
    let joiner = Joiner::new(records.clone());
    let joined = within("minor 3", joiner.join(&host, &host.code).finish())
        .await
        .unwrap();
    assert_eq!(joined.end, DirectEnd::NeedsUpdate);
    assert_eq!(ledger(&*records, &host.code), None);
}

/// `PAIRED` is lost and the app quits; after a restart the kept pending
/// record is recovered with no code, and the host's answer pairs it.
#[tokio::test]
async fn a_lost_paired_is_learned_by_recovery_after_a_restart() {
    minor_4();
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION).await;
    let (records, dir) = disk("direct-lost");
    let joiner = Joiner::new(records.clone());
    let mut join = joiner.join(&host, &host.code);
    assert_eq!(next(&mut join).await, DirectJoinEvent::CodePassed);
    host.state.lock().unwrap().lose_paired = true;
    host.allow(joiner.identity()).await;
    assert_eq!(next(&mut join).await, DirectJoinEvent::Away);
    // The app quits while away: what it stored stays.
    join.stop();
    assert_eq!(pending_count(&*records, &host.code), 1);
    assert!(joiner.pins.stored.lock().unwrap().is_empty());

    let again = joiner.restarted();
    let mut joins = again
        .caller
        .resume_direct(&again.setup, "laptop")
        .unwrap()
        .joins;
    assert_eq!(joins.len(), 1);
    let mut join = joins.remove(0);
    let paired = until(&mut join, |e| matches!(e, DirectJoinEvent::Paired(_))).await;
    assert!(matches!(paired, DirectJoinEvent::Paired(p) if p.identity == host.identity));
    let joined = within("recovery", join.finish()).await.unwrap();
    assert_eq!(joined.end, DirectEnd::Paired);
    assert_eq!(pending_count(&*records, &host.code), 0);
    let conn = joined.connection.unwrap();
    let _stream = within(
        "first stream",
        conn.open_stream(PriorityClass::Interactive, "app"),
    )
    .await
    .unwrap();
    wait_for("the commit", || host.logged("committed")).await;
    std::fs::remove_dir_all(dir).ok();
}

/// The connection breaks while the request waits; the owner allows while
/// the device is away, and its recovery is enrolled.
#[tokio::test]
async fn an_allow_while_away_is_claimed_by_the_recovery() {
    minor_4();
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION).await;
    let records: Arc<dyn DirectRecords> = Arc::new(MemoryDirectRecords::default());
    let joiner = Joiner::new(records.clone());
    let mut join = joiner.join(&host, &host.code);
    assert_eq!(next(&mut join).await, DirectJoinEvent::CodePassed);
    wait_for("the request", || host.logged("approval:")).await;
    host.break_all();
    assert_eq!(next(&mut join).await, DirectJoinEvent::Away);
    wait_for("the request away", || host.logged("approval:Away")).await;
    host.allow(joiner.identity()).await;
    let joined = within("claim", join.finish()).await.unwrap();
    assert_eq!(joined.end, DirectEnd::Paired);
    assert_eq!(joiner.pins.stored.lock().unwrap().len(), 1);
    assert!(host.logged("enrolled"));
}

/// A cancel while connected: the abort and the close reach the host, which
/// ends the request; the record stays until a recovery hears the answer.
#[tokio::test]
async fn a_cancel_while_connected_ends_the_request() {
    minor_4();
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION).await;
    let records: Arc<dyn DirectRecords> = Arc::new(MemoryDirectRecords::default());
    let joiner = Joiner::new(records.clone());
    let mut join = joiner.join(&host, &host.code);
    assert_eq!(next(&mut join).await, DirectJoinEvent::CodePassed);
    join.cancel().unwrap();
    assert_eq!(next(&mut join).await, DirectJoinEvent::Away);
    // The abort, then the close, on the connection the code passed on.
    let cancelled = ErrorCode::Cancelled.name();
    let goaway_end = format!(":{cancelled}");
    wait_for("the cancel's GOAWAY", || {
        host.log()
            .iter()
            .any(|l| l.starts_with("goaway:") && l.ends_with(&goaway_end))
    })
    .await;
    let log = host.log();
    let goaway = log
        .iter()
        .position(|l| l.starts_with("goaway:") && l.ends_with(&goaway_end))
        .unwrap();
    let conn = log[goaway]
        .strip_prefix("goaway:")
        .and_then(|l| l.strip_suffix(&goaway_end))
        .unwrap();
    let abort = log
        .iter()
        .position(|l| *l == format!("abort:{conn}:{cancelled}"));
    assert!(abort.is_some_and(|a| a < goaway), "{log:?}");
    assert!(host.logged("approval_ended:Cancelled"), "{log:?}");
    let joined = within("cancel", join.finish()).await.unwrap();
    assert_eq!(joined.end, DirectEnd::Closed(Some(ErrorCode::Cancelled)));
    assert_eq!(pending_count(&*records, &host.code), 0);
    assert!(joiner.pins.stored.lock().unwrap().is_empty());
}

/// A cancel while away is stored first, then delivered by the recovery.
#[tokio::test]
async fn a_cancel_while_away_reaches_the_host_with_the_recovery() {
    minor_4();
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION).await;
    let records: Arc<dyn DirectRecords> = Arc::new(MemoryDirectRecords::default());
    let joiner = Joiner::new(records.clone());
    let mut join = joiner.join(&host, &host.code);
    assert_eq!(next(&mut join).await, DirectJoinEvent::CodePassed);
    wait_for("the request", || host.logged("approval:")).await;
    host.break_all();
    assert_eq!(next(&mut join).await, DirectJoinEvent::Away);
    join.cancel().unwrap();
    assert!(pending_at(&*records, &host).unwrap().cancelled);
    let joined = within("cancel away", join.finish()).await.unwrap();
    assert_eq!(joined.end, DirectEnd::Closed(Some(ErrorCode::Cancelled)));
    assert!(host.logged("approval_ended:Cancelled"));
    assert_eq!(pending_count(&*records, &host.code), 0);
}

/// One flow per typed lookup: a second Connect while the first holds it is
/// busy, and dials nothing.
#[tokio::test]
async fn the_hold_refuses_a_second_flow() {
    minor_4();
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION).await;
    let records: Arc<dyn DirectRecords> = Arc::new(MemoryDirectRecords::default());
    let joiner = Joiner::new(records.clone());
    let mut first = joiner.join(&host, &host.code);
    assert_eq!(next(&mut first).await, DirectJoinEvent::CodePassed);
    let handshakes = host.state.lock().unwrap().handshakes;
    let second = within("second", joiner.join(&host, &host.code).finish())
        .await
        .unwrap();
    assert_eq!(second.end, DirectEnd::Busy);
    assert_eq!(host.state.lock().unwrap().handshakes, handshakes);
    first.stop();
}

/// Where a crash can stop the joiner: a record store whose `n`th write
/// lands and then reports a failure, as a process that stopped right after
/// the write would leave it; nothing that waited for it goes out.
struct CrashAfter {
    inner: Arc<dyn DirectRecords>,
    writes_left: Mutex<usize>,
}

impl CrashAfter {
    fn landed(&self) -> Result<(), NetError> {
        let mut left = self.writes_left.lock().unwrap();
        if *left == 0 {
            return Ok(());
        }
        *left -= 1;
        if *left == 0 {
            return Err(NetError::Store("stopped after the write".into()));
        }
        Ok(())
    }
}

impl DirectRecords for CrashAfter {
    fn hold(
        &self,
        lookup: &DirectLookup,
    ) -> Result<Option<mousse_net_io::store::FlowHold>, NetError> {
        self.inner.hold(lookup)
    }

    fn load(
        &self,
        lookup: &DirectLookup,
        address: &DirectAddress,
    ) -> Result<
        (
            Option<mousse_net_core::pairing::DirectLedger>,
            Option<DirectPending>,
        ),
        NetError,
    > {
        self.inner.load(lookup, address)
    }

    fn swap_ledger(
        &self,
        expected: Option<&mousse_net_core::pairing::DirectLedger>,
        record: &mousse_net_core::pairing::DirectLedger,
    ) -> Result<(), NetError> {
        self.inner.swap_ledger(expected, record)?;
        self.landed()
    }

    fn swap_pending(
        &self,
        lookup: &DirectLookup,
        address: &mousse_net_core::pairing::DirectAddress,
        expected: Option<&mousse_net_core::pairing::DirectPending>,
        record: Option<&mousse_net_core::pairing::DirectPending>,
    ) -> Result<(), NetError> {
        self.inner.swap_pending(lookup, address, expected, record)?;
        self.landed()
    }

    fn pending_slots(&self) -> Result<mousse_net_io::PendingSlots, NetError> {
        self.inner.pending_slots()
    }
}

/// Crash points, each followed by a restart over the same store:
/// - after the debit, before `msg_a`: the debit stays, nothing is pending;
/// - after the pending record, before `msg_c`: the recovery learns that the
///   host never had the confirmation (`not_received`);
/// - after `PAIRED`, when the pin cannot be stored: the record stays, and
///   the recovery pairs again from the host's grant.
#[tokio::test]
async fn crash_points_leave_what_a_restart_needs() {
    minor_4();
    // After the debit.
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION).await;
    let (store, dir) = disk("direct-crash-1");
    let crash: Arc<dyn DirectRecords> = Arc::new(CrashAfter {
        inner: store.clone(),
        writes_left: Mutex::new(1),
    });
    let joiner = Joiner::new(crash);
    let joined = within("crash 1", joiner.join(&host, &host.code).finish())
        .await
        .unwrap();
    assert_eq!(
        joined.end,
        DirectEnd::Closed(Some(ErrorCode::InternalError))
    );
    assert_eq!(ledger(&*store, &host.code), Some(4));
    assert_eq!(pending_count(&*store, &host.code), 0);
    assert!(
        !host.logged("attempts_left"),
        "msg_a went out: {:?}",
        host.log()
    );
    std::fs::remove_dir_all(dir).ok();

    // After the pending record.
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION).await;
    let (store, dir) = disk("direct-crash-2");
    let crash: Arc<dyn DirectRecords> = Arc::new(CrashAfter {
        inner: store.clone(),
        writes_left: Mutex::new(2),
    });
    let joiner = Joiner::new(crash);
    let joined = within("crash 2", joiner.join(&host, &host.code).finish())
        .await
        .unwrap();
    assert_eq!(
        joined.end,
        DirectEnd::Closed(Some(ErrorCode::InternalError))
    );
    assert_eq!(pending_count(&*store, &host.code), 1);
    assert!(!host.logged("approval"), "msg_c went out: {:?}", host.log());
    let again = Joiner::with_signer(joiner.signer.clone(), store.clone());
    let mut joins = again
        .caller
        .resume_direct(&again.setup, "laptop")
        .unwrap()
        .joins;
    let joined = within("recovery 2", joins.remove(0).finish())
        .await
        .unwrap();
    assert_eq!(joined.end, DirectEnd::NotReceived { attempts_left: 4 });
    assert_eq!(pending_count(&*store, &host.code), 0);
    std::fs::remove_dir_all(dir).ok();

    // The pin cannot be stored.
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION).await;
    let (store, dir) = disk("direct-crash-3");
    let joiner = Joiner::new(store.clone());
    joiner.pins.fail.store(true, Ordering::SeqCst);
    let mut join = joiner.join(&host, &host.code);
    assert_eq!(next(&mut join).await, DirectJoinEvent::CodePassed);
    host.allow(joiner.identity()).await;
    let joined = within("pin fails", join.finish()).await.unwrap();
    assert_eq!(
        joined.end,
        DirectEnd::Closed(Some(ErrorCode::InternalError))
    );
    assert_eq!(pending_count(&*store, &host.code), 1);
    assert!(joiner.pins.stored.lock().unwrap().is_empty());
    let again = joiner.restarted();
    let mut joins = again
        .caller
        .resume_direct(&again.setup, "laptop")
        .unwrap()
        .joins;
    let joined = within("recovery 3", joins.remove(0).finish())
        .await
        .unwrap();
    assert_eq!(joined.end, DirectEnd::Paired);
    assert_eq!(joiner.pins.stored.lock().unwrap().len(), 1);
    assert_eq!(pending_count(&*store, &host.code), 0);
    std::fs::remove_dir_all(dir).ok();
}

/// A host that never answers `JOIN_DIRECT`: after the answer wait (8.2,
/// 3 s here) the joiner closes with `NOT_AUTHORIZED`, and nothing is
/// debited.
#[tokio::test]
async fn an_unanswered_join_direct_times_out() {
    minor_4();
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION).await;
    host.state.lock().unwrap().silent = true;
    let records: Arc<dyn DirectRecords> = Arc::new(MemoryDirectRecords::default());
    let joiner = Joiner::new(records.clone());
    let joined = within("answer wait", joiner.join(&host, &host.code).finish())
        .await
        .unwrap();
    assert_eq!(
        joined.end,
        DirectEnd::Closed(Some(ErrorCode::NotAuthorized))
    );
    assert!(host.logged("unanswered"));
    assert_eq!(ledger(&*records, &host.code), None);
}

/// Two kept pending records under one typed lookup (two addresses): at
/// startup both are recovered. One flow holds the lookup at a time; the
/// other tries again with backoff, and both pair.
#[tokio::test]
async fn startup_recovers_every_kept_record_one_flow_at_a_time() {
    minor_4();
    let code = "K7QM-2XPA-9RTE";
    let a = TestHost::start(new_signer(), Some(code), DIRECT_MINOR_VERSION).await;
    let b = TestHost::start(new_signer(), Some(code), DIRECT_MINOR_VERSION).await;
    let (records, dir) = disk("direct-two");
    let joiner = Joiner::new(records.clone());
    for host in [&a, &b] {
        let mut join = joiner.join(host, code);
        assert_eq!(next(&mut join).await, DirectJoinEvent::CodePassed);
        wait_for("the request", || host.logged("approval:")).await;
        host.break_all();
        assert_eq!(next(&mut join).await, DirectJoinEvent::Away);
        join.stop();
        wait_for("the request away", || host.logged("approval:Away")).await;
        host.allow(joiner.identity()).await;
    }
    assert_eq!(pending_count(&*records, code), 2);
    let again = joiner.restarted();
    let joins = again
        .caller
        .resume_direct(&again.setup, "laptop")
        .unwrap()
        .joins;
    assert_eq!(joins.len(), 2);
    for join in joins {
        let joined = within("recovery", join.finish()).await.unwrap();
        assert_eq!(joined.end, DirectEnd::Paired);
    }
    assert_eq!(pending_count(&*records, code), 0);
    assert_eq!(joiner.pins.stored.lock().unwrap().len(), 2);
    std::fs::remove_dir_all(dir).ok();
}

/// At startup a damaged record stops only its own flow: that flow fails and
/// its events end, and a healthy record under the same lookup is still
/// recovered and pairs. A file kept as a pending record whose name does
/// not read is reported.
#[tokio::test]
async fn a_damaged_record_stops_only_its_own_recovery() {
    minor_4();
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION).await;
    let (records, dir) = disk("direct-damaged");
    let joiner = Joiner::new(records.clone());
    let mut join = joiner.join(&host, &host.code);
    assert_eq!(next(&mut join).await, DirectJoinEvent::CodePassed);
    wait_for("the request", || host.logged("approval:")).await;
    host.break_all();
    assert_eq!(next(&mut join).await, DirectJoinEvent::Away);
    join.stop();
    wait_for("the request away", || host.logged("approval:Away")).await;
    host.allow(joiner.identity()).await;
    // A record under the same lookup, at another address, that does not
    // read; and a file whose name does not read.
    let lookup = DirectLookup::from_canonical(&host.code[..4]).unwrap();
    let store = DirectRecordStore::in_dir(&dir);
    let damaged = store.pending_path(
        &lookup,
        &DirectAddress::parse("192.168.1.20:47100").unwrap(),
    );
    std::fs::write(&damaged, b"junk").unwrap();
    let misnamed = damaged.with_file_name(format!("{}-zz.pending", lookup.as_str()));
    std::fs::write(&misnamed, b"junk").unwrap();

    let again = joiner.restarted();
    let resumed = again.caller.resume_direct(&again.setup, "laptop").unwrap();
    assert_eq!(resumed.unreadable.len(), 1);
    let joins = resumed.joins;
    assert_eq!(joins.len(), 2);
    let (mut failed, mut paired) = (0, 0);
    for mut join in joins {
        let events = drain(&mut join).await;
        match within("recovery", join.finish()).await {
            Err(_) => {
                assert_eq!(events, Vec::new());
                failed += 1;
            }
            Ok(joined) => {
                assert_eq!(joined.end, DirectEnd::Paired);
                assert_eq!(
                    events.last(),
                    Some(&DirectJoinEvent::Ended(DirectEnd::Paired))
                );
                paired += 1;
            }
        }
    }
    assert_eq!((failed, paired), (1, 1));
    assert_eq!(pending_at(&*records, &host), None);
    // The damaged record and the misnamed file are left as they are.
    assert!(damaged.exists() && misnamed.exists());
    std::fs::remove_dir_all(dir).ok();
}

/// A recovery is pinned to the stored host key: when another device now
/// answers at the stored address, this device's certificate never reaches
/// it, and the pending record stays.
#[tokio::test]
async fn a_recovery_never_shows_its_certificate_to_another_key_at_the_address() {
    minor_4();
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION).await;
    let (records, dir) = disk("direct-moved");
    let joiner = Joiner::new(records.clone());
    let mut join = joiner.join(&host, &host.code);
    assert_eq!(next(&mut join).await, DirectJoinEvent::CodePassed);
    wait_for("the request", || host.logged("approval:")).await;
    join.stop();
    let (addr, code) = (host.addr, host.code.clone());
    drop(host);
    let other = TestHost::start_at(addr, new_signer()).await;

    let again = joiner.restarted();
    let mut joins = again
        .caller
        .resume_direct(&again.setup, "laptop")
        .unwrap()
        .joins;
    assert_eq!(joins.len(), 1);
    let mut join = joins.remove(0);
    assert_eq!(next(&mut join).await, DirectJoinEvent::Away);
    wait_for("the refused handshake", || {
        other.state.lock().unwrap().refused_handshakes > 0
    })
    .await;
    assert_eq!(other.state.lock().unwrap().handshakes, 0);
    assert_eq!(pending_count(&*records, &code), 1);
    join.stop();
    std::fs::remove_dir_all(dir).ok();
}

/// A first contact joins the host's session only once it pairs: a Connect
/// that fails leaves a path this device already has to that host alone.
#[tokio::test]
async fn a_first_contact_displaces_no_path_unless_it_pairs() {
    minor_4();
    let host = TestHost::start(new_signer(), None, DIRECT_MINOR_VERSION).await;
    let joiner = Joiner::new(Arc::new(MemoryDirectRecords::default()));
    let pipe = tokio::net::TcpStream::connect(host.addr).await.unwrap();
    let path = within(
        "the existing path",
        joiner.caller.connect(pipe, host.identity),
    )
    .await
    .unwrap();
    let joined = within(
        "wrong secret",
        joiner.join(&host, &wrong_secret(&host.code)).finish(),
    )
    .await
    .unwrap();
    assert_eq!(joined.end, DirectEnd::CodeFailed { attempts_left: 4 });
    // The existing path's own close is the next thing the host hears from
    // it; a path the Connect displaced would have closed with
    // PATH_REPLACED before.
    path.close(ErrorCode::NoError);
    let no_error = format!(":{}", ErrorCode::NoError.name());
    wait_for("the path's own close", || {
        host.log()
            .iter()
            .any(|l| l.starts_with("goaway:") && l.ends_with(&no_error))
    })
    .await;
    let replaced = format!(":{}", ErrorCode::PathReplaced.name());
    assert!(
        !host.log().iter().any(|l| l.ends_with(&replaced)),
        "{:?}",
        host.log()
    );
}

/// A cancel made right after startup, before the recovery has loaded
/// anything, is taken: once the records are loaded the recovery marks its
/// record cancelled.
#[tokio::test(flavor = "current_thread")]
async fn a_cancel_right_after_startup_is_taken() {
    minor_4();
    let records: Arc<dyn DirectRecords> = Arc::new(MemoryDirectRecords::default());
    let lookup = DirectLookup::from_canonical("K7QM").unwrap();
    // Nobody listens here: the recovery's dial fails, and it stays away.
    let free = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = DirectAddress::parse(&free.local_addr().unwrap().to_string()).unwrap();
    drop(free);
    let kept = DirectPending {
        lookup: lookup.clone(),
        host: *CertManager::new(new_signer(), Arc::new(SystemClock::new()))
            .current()
            .unwrap()
            .identity(),
        invitation: InvitationId([7; 16]),
        address,
        verified_at: UnixTime(1_790_000_000),
        cancelled: false,
        attempt: AttemptId([5; 16]),
    };
    records
        .swap_pending(&lookup, &address, None, Some(&kept))
        .unwrap();
    let joiner = Joiner::new(records.clone());
    let mut resumed = joiner
        .caller
        .resume_direct(&joiner.setup, "laptop")
        .unwrap();
    let join = resumed.joins.remove(0);
    // Before the task has run at all.
    join.cancel().unwrap();
    wait_for("the cancel marked", || {
        records
            .load(&lookup, &address)
            .unwrap()
            .1
            .is_some_and(|p| p.cancelled)
    })
    .await;
    join.stop();
}

/// A record store that panics when it loads.
#[derive(Default)]
struct PanicsOnLoad(MemoryDirectRecords);

impl DirectRecords for PanicsOnLoad {
    fn hold(
        &self,
        lookup: &DirectLookup,
    ) -> Result<Option<mousse_net_io::store::FlowHold>, NetError> {
        self.0.hold(lookup)
    }

    fn load(
        &self,
        _lookup: &DirectLookup,
        _address: &DirectAddress,
    ) -> Result<
        (
            Option<mousse_net_core::pairing::DirectLedger>,
            Option<DirectPending>,
        ),
        NetError,
    > {
        panic!("the store failed to load");
    }

    fn swap_ledger(
        &self,
        expected: Option<&mousse_net_core::pairing::DirectLedger>,
        record: &mousse_net_core::pairing::DirectLedger,
    ) -> Result<(), NetError> {
        self.0.swap_ledger(expected, record)
    }

    fn swap_pending(
        &self,
        lookup: &DirectLookup,
        address: &DirectAddress,
        expected: Option<&DirectPending>,
        record: Option<&DirectPending>,
    ) -> Result<(), NetError> {
        self.0.swap_pending(lookup, address, expected, record)
    }

    fn pending_slots(&self) -> Result<mousse_net_io::PendingSlots, NetError> {
        self.0.pending_slots()
    }
}

/// The event stream ends even when the flow's task panics.
#[tokio::test]
async fn the_events_end_when_the_flow_panics() {
    minor_4();
    let joiner = Joiner::new(Arc::new(PanicsOnLoad::default()));
    let mut join = joiner
        .caller
        .join_direct(&joiner.setup, "127.0.0.1:1", "K7QM-2XPA-9RTE", "laptop")
        .unwrap();
    assert_eq!(drain(&mut join).await, Vec::new());
    assert!(within("the panic", join.finish()).await.is_err());
}
