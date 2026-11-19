//! A minimal self-mode relay on loopback, for tests of the endpoint side
//! until `mousse-relay` (E-R2) replaces it in the checks.
//!
//! It follows §B.3 to §B.9 for self mode: registration by an authorized
//! key or an enrollment code, allow-sets that replace each other and close
//! removed callers' circuits at once, `CALL` and `JOIN` refused at one
//! constant deadline, accept legs signed by the registration key, the
//! pre-accept budget, `PROMOTE` and `SUCCESSOR`. It has no limits beyond
//! those, and logs nothing.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use mousse_net_core::identity::SoftwareKey;
use mousse_net_core::relay_wire::{
    accept_record, call_record, handle, register_record, relay_certificate, relay_id,
    successor_record, tag_hash, AllowedInvitation, Binding, CircuitId, Class, CloseCode,
    EnrollmentLink, Fingerprint, Handle, IncomingKind, Mode, RelayEndpoint, RelayId, RelayMessage,
    RELAY_ALPN, RELAY_EXPORTER_LABEL, RELAY_PATH, RELAY_SUBPROTOCOL, RELAY_VERSION,
};
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode as WsCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use super::outer::{ws_config, RelayLink, RelaySigningKey};
use super::AllowSet;
use crate::rng::{os_rng, random_bytes};
use crate::tls::provider;

type ServerTls = tokio_rustls::server::TlsStream<TcpStream>;
type Ws = WebSocketStream<ServerTls>;

/// Test relay settings (§H.1 names, test-sized defaults).
#[derive(Clone, Copy, Debug)]
pub struct TestRelayConfig {
    /// `MOUSSE_NET_RELAY_REFUSE_MS`.
    pub refuse: Duration,
    /// `MOUSSE_NET_RELAY_ACCEPT_WAIT_MS`.
    pub accept_wait: Duration,
    /// `MOUSSE_NET_RELAY_PREACCEPT_BYTES`.
    pub preaccept_bytes: u64,
    /// `MOUSSE_NET_RELAY_PREACCEPT_PER_TARGET`.
    pub preaccept_per_target: usize,
    /// `MOUSSE_NET_RELAY_CIRCUITS_PER_CALLER`.
    pub circuits_per_caller: usize,
}

impl Default for TestRelayConfig {
    fn default() -> Self {
        Self {
            refuse: Duration::from_millis(500),
            accept_wait: Duration::from_secs(10),
            preaccept_bytes: 65_536,
            preaccept_per_target: 4,
            circuits_per_caller: 8,
        }
    }
}

enum ToReg {
    Send(Box<RelayMessage>),
    Close(u16),
}

struct Reg {
    key: mousse_net_core::identity::PublicKey,
    conn: u64,
    tx: mpsc::UnboundedSender<ToReg>,
    allow: AllowSet,
    sequence: u64,
}

struct Circuit {
    handle: Handle,
    caller: Option<Fingerprint>,
    join: bool,
    kill: watch::Sender<Option<u16>>,
    promoted: watch::Sender<bool>,
}

struct Pending {
    handle: Handle,
    leg: oneshot::Sender<Ws>,
}

#[derive(Default)]
struct State {
    authorized: HashSet<Fingerprint>,
    codes: HashSet<[u8; 16]>,
    regs: HashMap<Handle, Reg>,
    pending: HashMap<CircuitId, Pending>,
    circuits: HashMap<CircuitId, Circuit>,
    next_conn: u64,
    calls: u64,
    joins: u64,
    connections: u64,
}

/// What a test can count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TestRelayCounts {
    /// Outer connections accepted.
    pub connections: u64,
    /// `CALL`s received.
    pub calls: u64,
    /// `JOIN`s received.
    pub joins: u64,
}

struct Inner {
    key: Arc<SoftwareKey>,
    config: TestRelayConfig,
    state: Mutex<State>,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn relay(&self) -> RelayId {
        relay_id(&self.key.public_key())
    }
}

/// A running test relay.
pub struct TestRelay {
    addr: SocketAddr,
    inner: Arc<Inner>,
    task: JoinHandle<()>,
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Debug)]
struct Resolver(Arc<CertifiedKey>);

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

impl TestRelay {
    /// Start a relay with a fresh identity on `127.0.0.1`, any port.
    pub async fn start(config: TestRelayConfig) -> Self {
        Self::start_with(Arc::new(SoftwareKey::generate(&mut os_rng())), 0, config).await
    }

    /// Start a relay with `key` on `127.0.0.1:port` (0: any), as after a
    /// restart: same identity, nothing else kept but the authorized keys
    /// a test adds back.
    pub async fn start_with(key: Arc<SoftwareKey>, port: u16, config: TestRelayConfig) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("bind the test relay");
        let addr = listener.local_addr().expect("test relay address");
        let certified = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(relay_certificate(&key))],
            Arc::new(RelaySigningKey::new(key.clone())),
        ));
        let mut tls = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver(certified)));
        tls.alpn_protocols = vec![RELAY_ALPN.to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let inner = Arc::new(Inner {
            key,
            config,
            state: Mutex::new(State::default()),
        });
        let task = tokio::spawn({
            let inner = inner.clone();
            async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        continue;
                    };
                    let _ = tcp.set_nodelay(true);
                    tokio::spawn(connection(inner.clone(), acceptor.clone(), tcp));
                }
            }
        });
        Self { addr, inner, task }
    }

    /// Where it listens.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Its identity key.
    pub fn key(&self) -> Arc<SoftwareKey> {
        self.inner.key.clone()
    }

    /// Its relay id.
    pub fn relay_id(&self) -> RelayId {
        self.inner.relay()
    }

    /// Its endpoint, as a manifest names it.
    pub fn endpoint(&self) -> RelayEndpoint {
        RelayEndpoint::parse(&self.addr.to_string()).expect("loopback endpoint")
    }

    /// A fresh enrollment link (`mousse-relay enroll`).
    pub fn enrollment_link(&self) -> EnrollmentLink {
        let code = random_bytes::<16>();
        self.inner.lock().codes.insert(code);
        EnrollmentLink {
            endpoint: self.endpoint(),
            relay: self.relay_id(),
            code,
        }
    }

    /// Authorize a registration key by fingerprint.
    pub fn authorize(&self, key: Fingerprint) {
        self.inner.lock().authorized.insert(key);
    }

    /// The authorized registration keys.
    pub fn authorized(&self) -> Vec<Fingerprint> {
        self.inner.lock().authorized.iter().copied().collect()
    }

    /// `mousse-relay revoke`: drop a key and close its registration and
    /// circuits.
    pub fn revoke(&self, key: Fingerprint) {
        let mut st = self.inner.lock();
        st.authorized.remove(&key);
        let gone: Vec<Handle> = st
            .regs
            .iter()
            .filter(|(_, r)| r.key.fingerprint() == key)
            .map(|(h, _)| *h)
            .collect();
        for h in gone {
            if let Some(reg) = st.regs.remove(&h) {
                let _ = reg.tx.send(ToReg::Close(CloseCode::Removed.code()));
            }
            for c in st.circuits.values().filter(|c| c.handle == h) {
                let _ = c.kill.send(Some(CloseCode::Removed.code()));
            }
        }
    }

    /// The live allow-set of `handle`.
    pub fn allow_set(&self, handle: &Handle) -> Option<AllowSet> {
        self.inner.lock().regs.get(handle).map(|r| r.allow.clone())
    }

    /// Live registrations.
    pub fn handles(&self) -> Vec<Handle> {
        self.inner.lock().regs.keys().copied().collect()
    }

    /// Spliced circuits of `handle`, with their caller fingerprint.
    pub fn circuits(&self, handle: &Handle) -> Vec<Option<Fingerprint>> {
        self.inner
            .lock()
            .circuits
            .values()
            .filter(|c| c.handle == *handle)
            .map(|c| c.caller)
            .collect()
    }

    /// What it has seen.
    pub fn counts(&self) -> TestRelayCounts {
        let st = self.inner.lock();
        TestRelayCounts {
            connections: st.connections,
            calls: st.calls,
            joins: st.joins,
        }
    }

    /// Stop: close every connection with 4003 and stop listening.
    pub fn stop(&self) {
        self.task.abort();
        let mut st = self.inner.lock();
        for reg in st.regs.values() {
            let _ = reg.tx.send(ToReg::Close(CloseCode::RelayStopping.code()));
        }
        for c in st.circuits.values() {
            let _ = c.kill.send(Some(CloseCode::RelayStopping.code()));
        }
        st.regs.clear();
        st.pending.clear();
    }
}

// The upgrade callback's error type is tungstenite's.
#[allow(clippy::result_large_err)]
async fn connection(inner: Arc<Inner>, acceptor: tokio_rustls::TlsAcceptor, tcp: TcpStream) {
    inner.lock().connections += 1;
    let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(tcp)).await
    else {
        return;
    };
    let mut exporter = [0u8; 32];
    if tls
        .get_ref()
        .1
        .export_keying_material(&mut exporter, RELAY_EXPORTER_LABEL.as_bytes(), None)
        .is_err()
    {
        return;
    }
    let check = |req: &Request, mut resp: Response| -> Result<Response, ErrorResponse> {
        let offered = req
            .headers()
            .get_all("Sec-WebSocket-Protocol")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|p| p.trim() == RELAY_SUBPROTOCOL);
        if req.uri().path() != RELAY_PATH || !offered {
            let mut refuse = ErrorResponse::new(None);
            *refuse.status_mut() = StatusCode::NOT_FOUND;
            return Err(refuse);
        }
        resp.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static(RELAY_SUBPROTOCOL),
        );
        Ok(resp)
    };
    let Ok(Ok(ws)) = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::accept_hdr_async_with_config(tls, check, Some(ws_config())),
    )
    .await
    else {
        return;
    };
    let binding = Binding {
        relay: inner.relay(),
        nonce: random_bytes::<32>(),
        exporter,
    };
    let mut link = RelayLink::from_parts(ws, binding, Mode::SelfHosted);
    let hello = RelayMessage::Hello {
        version: RELAY_VERSION,
        nonce: binding.nonce,
        boot_id: [0; 16],
        mode: Mode::SelfHosted,
    };
    if link.send(&hello).await.is_err() {
        return;
    }
    let first = match tokio::time::timeout(Duration::from_secs(5), link.recv()).await {
        Ok(Ok(m)) => m,
        _ => return,
    };
    match first {
        RelayMessage::Register { key, proof, .. } => {
            let h = handle(&binding.relay, &key);
            let ok = inner.lock().authorized.contains(&key.fingerprint())
                && key.verify(&register_record(&binding, &h), &proof).is_ok();
            if !ok {
                refuse(link, "not_authorized").await;
                return;
            }
            registration(inner, link, key, h).await;
        }
        RelayMessage::Enroll { key, proof, code } => {
            let h = handle(&binding.relay, &key);
            let ok = key.verify(&register_record(&binding, &h), &proof).is_ok() && {
                let mut st = inner.lock();
                let fresh = st.codes.remove(&code);
                if fresh {
                    st.authorized.insert(key.fingerprint());
                }
                fresh
            };
            if !ok {
                refuse(link, "not_authorized").await;
                return;
            }
            registration(inner, link, key, h).await;
        }
        RelayMessage::Call {
            handle: h,
            key,
            proof,
            class,
        } => {
            let deadline = Instant::now() + inner.config.refuse;
            let fp = key.fingerprint();
            let admitted = {
                let mut st = inner.lock();
                st.calls += 1;
                let open = st
                    .circuits
                    .values()
                    .filter(|c| c.handle == h && c.caller == Some(fp))
                    .count();
                st.regs
                    .get(&h)
                    .is_some_and(|r| r.allow.callers.contains(&fp))
                    && key
                        .verify(&call_record(&binding, &h, class), &proof)
                        .is_ok()
                    && open < inner.config.circuits_per_caller
            };
            if !admitted {
                unreachable_at(link, deadline).await;
                return;
            }
            circuit(
                inner,
                link,
                h,
                IncomingKind::Call,
                class,
                Some(fp),
                deadline,
            )
            .await;
        }
        RelayMessage::Join { handle: h, tag } => {
            let deadline = Instant::now() + inner.config.refuse;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let admitted = {
                let mut st = inner.lock();
                st.joins += 1;
                let joins = st
                    .circuits
                    .values()
                    .filter(|c| c.handle == h && c.join && c.caller.is_none())
                    .count();
                let hash = tag_hash(&tag);
                st.regs.get(&h).is_some_and(|r| {
                    r.allow
                        .invitations
                        .iter()
                        .any(|i: &AllowedInvitation| i.tag_hash == hash && i.expires_at > now)
                }) && joins < inner.config.preaccept_per_target
            };
            if !admitted {
                unreachable_at(link, deadline).await;
                return;
            }
            circuit(
                inner,
                link,
                h,
                IncomingKind::Join,
                Class::Interactive,
                None,
                deadline,
            )
            .await;
        }
        RelayMessage::Accept {
            handle: h,
            circuit,
            proof,
        } => {
            let leg = {
                let mut st = inner.lock();
                let key = st.regs.get(&h).map(|r| r.key);
                let ok = key.is_some_and(|k| {
                    k.verify(&accept_record(&binding, &h, &circuit), &proof)
                        .is_ok()
                }) && st.pending.get(&circuit).is_some_and(|p| p.handle == h);
                if ok {
                    st.pending.remove(&circuit)
                } else {
                    None
                }
            };
            match leg {
                Some(p) => {
                    let _ = p.leg.send(link.into_ws());
                }
                None => link.close(1008).await,
            }
        }
        _ => link.close(1002).await,
    }
}

async fn refuse(mut link: RelayLink<ServerTls>, reason: &str) {
    let _ = link
        .send(&RelayMessage::Refused {
            reason: reason.into(),
        })
        .await;
    link.close(1008).await;
}

async fn unreachable_at(mut link: RelayLink<ServerTls>, deadline: Instant) {
    tokio::time::sleep_until(deadline).await;
    let _ = link.send(&RelayMessage::Unreachable).await;
    link.close(1000).await;
}

async fn registration(
    inner: Arc<Inner>,
    mut link: RelayLink<ServerTls>,
    key: mousse_net_core::identity::PublicKey,
    h: Handle,
) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let conn = {
        let mut st = inner.lock();
        st.next_conn += 1;
        let conn = st.next_conn;
        if let Some(old) = st.regs.insert(
            h,
            Reg {
                key,
                conn,
                tx,
                allow: AllowSet::default(),
                sequence: 0,
            },
        ) {
            let _ = old.tx.send(ToReg::Close(CloseCode::Replaced.code()));
        }
        conn
    };
    let binding = link.binding();
    if link
        .send(&RelayMessage::Registered { handle: h })
        .await
        .is_err()
    {
        drop_reg(&inner, &h, conn);
        return;
    }
    loop {
        tokio::select! {
            got = link.recv() => {
                let Ok(msg) = got else { break };
                match msg {
                    RelayMessage::AllowSet { sequence, callers, invitations } => {
                        let mut st = inner.lock();
                        let Some(reg) = st.regs.get_mut(&h).filter(|r| r.conn == conn) else { break };
                        if sequence <= reg.sequence {
                            continue;
                        }
                        reg.sequence = sequence;
                        reg.allow = AllowSet { callers: callers.clone(), invitations };
                        let _ = reg.tx.send(ToReg::Send(Box::new(RelayMessage::AllowSetOk { sequence })));
                        // Exactly the circuits whose caller left the set.
                        for c in st.circuits.values() {
                            if c.handle == h && c.caller.is_some_and(|fp| !callers.contains(&fp)) {
                                let _ = c.kill.send(Some(CloseCode::Removed.code()));
                            }
                        }
                    }
                    RelayMessage::Ping(b) => {
                        if link.send(&RelayMessage::Pong(b)).await.is_err() { break }
                    }
                    RelayMessage::Pong(_) => {}
                    RelayMessage::Promote { circuit, caller } => {
                        let mut st = inner.lock();
                        let listed = st.regs.get(&h).is_some_and(|r| r.allow.callers.contains(&caller));
                        match st.circuits.get_mut(&circuit) {
                            Some(c) if listed && c.handle == h && c.join => {
                                c.caller = Some(caller);
                                let _ = c.promoted.send(true);
                            }
                            _ => {}
                        }
                    }
                    RelayMessage::Successor { key: new, proof_new, proof_current } => {
                        let record = successor_record(&binding, &handle(&binding.relay, &new));
                        if new.verify(&record, &proof_new).is_ok()
                            && key.verify(&record, &proof_current).is_ok()
                            && inner.lock().authorized.contains(&key.fingerprint())
                        {
                            inner.lock().authorized.insert(new.fingerprint());
                        } else {
                            link.close(1008).await;
                            break;
                        }
                    }
                    _ => {
                        link.close(1002).await;
                        break;
                    }
                }
            }
            out = rx.recv() => match out {
                Some(ToReg::Send(m)) => {
                    if link.send(&m).await.is_err() { break }
                }
                Some(ToReg::Close(code)) => {
                    link.close(code).await;
                    break;
                }
                None => break,
            },
        }
    }
    drop_reg(&inner, &h, conn);
}

fn drop_reg(inner: &Inner, h: &Handle, conn: u64) {
    let mut st = inner.lock();
    if st.regs.get(h).is_some_and(|r| r.conn == conn) {
        st.regs.remove(h);
    }
}

async fn circuit(
    inner: Arc<Inner>,
    link: RelayLink<ServerTls>,
    h: Handle,
    kind: IncomingKind,
    class: Class,
    caller: Option<Fingerprint>,
    deadline: Instant,
) {
    let id = random_bytes::<16>();
    let (leg_tx, leg_rx) = oneshot::channel();
    let told = {
        let mut st = inner.lock();
        st.pending.insert(
            id,
            Pending {
                handle: h,
                leg: leg_tx,
            },
        );
        st.regs.get(&h).map(|r| {
            r.tx.send(ToReg::Send(Box::new(RelayMessage::Incoming {
                circuit: id,
                kind,
                class,
                caller,
            })))
            .is_ok()
        })
    };
    if told != Some(true) {
        inner.lock().pending.remove(&id);
        unreachable_at(link, deadline).await;
        return;
    }
    let other = match tokio::time::timeout(inner.config.accept_wait, leg_rx).await {
        Ok(Ok(ws)) => ws,
        _ => {
            inner.lock().pending.remove(&id);
            unreachable_at(link, deadline).await;
            return;
        }
    };
    let (kill_tx, kill_rx) = watch::channel(None);
    let (promoted_tx, promoted_rx) = watch::channel(false);
    inner.lock().circuits.insert(
        id,
        Circuit {
            handle: h,
            caller,
            join: kind == IncomingKind::Join,
            kill: kill_tx,
            promoted: promoted_tx,
        },
    );
    let mut target = other;
    let spliced = Message::binary(RelayMessage::Spliced.encode());
    let mut caller_ws = link.into_ws();
    if caller_ws.send(spliced.clone()).await.is_err() || target.send(spliced).await.is_err() {
        inner.lock().circuits.remove(&id);
        return;
    }
    let budget = (kind == IncomingKind::Join).then_some(inner.config.preaccept_bytes);
    splice(caller_ws, target, kill_rx, promoted_rx, budget).await;
    inner.lock().circuits.remove(&id);
}

async fn splice(
    mut a: Ws,
    mut b: Ws,
    mut kill: watch::Receiver<Option<u16>>,
    promoted: watch::Receiver<bool>,
    budget: Option<u64>,
) {
    let mut sent = [0u64; 2];
    let code = loop {
        tokio::select! {
            m = a.next() => match m {
                Some(Ok(Message::Binary(bytes))) => {
                    sent[0] += bytes.len() as u64;
                    if over(budget, &promoted, sent[0]) { break 4006 }
                    if b.send(Message::Binary(bytes)).await.is_err() { break 1000 }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break 1000,
                Some(Ok(_)) => {}
            },
            m = b.next() => match m {
                Some(Ok(Message::Binary(bytes))) => {
                    sent[1] += bytes.len() as u64;
                    if over(budget, &promoted, sent[1]) { break 4006 }
                    if a.send(Message::Binary(bytes)).await.is_err() { break 1000 }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break 1000,
                Some(Ok(_)) => {}
            },
            changed = kill.changed() => {
                if changed.is_err() { break 1000 }
                if let Some(code) = *kill.borrow() { break code }
            }
        }
    };
    let frame = CloseFrame {
        code: WsCode::from(code),
        reason: "".into(),
    };
    let _ = a.close(Some(frame.clone())).await;
    let _ = b.close(Some(frame)).await;
}

fn over(budget: Option<u64>, promoted: &watch::Receiver<bool>, sent: u64) -> bool {
    budget.is_some_and(|max| !*promoted.borrow() && sent > max)
}
