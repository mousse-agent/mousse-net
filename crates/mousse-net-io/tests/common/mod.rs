//! Loopback hosts and callers for the integration tests.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mousse_net_core::grants::{GrantId, OwnerRef};
use mousse_net_core::identity::{IdentityPublicKey, SoftwareKey};
use mousse_net_core::mux::PriorityClass;
use mousse_net_core::pairing::{Arrival, CpaceExchangeFactory, InvitationKind, Ticket};
use mousse_net_core::ErrorCode;
use mousse_net_io::pipe::{accept_tcp, connect_tcp, route_from_addr, route_uri, Route};
use mousse_net_io::rng::os_rng;
use mousse_net_io::store::hex;
use mousse_net_io::{
    Caller, CloseReason, CodeEntry, Connection, Endpoint, Host, HostConfig, HostEvent, Limits,
    ManualClock, MuxStream, NetError, PortChoice, SharedSigner,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
pub const WAIT: Duration = Duration::from_secs(5);

pub fn temp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "mousse-net-it-{tag}-{}",
        hex(&mousse_net_io::rng::random_bytes::<6>())
    ))
}

pub fn new_signer() -> SharedSigner {
    Arc::new(SoftwareKey::generate(&mut os_rng()))
}

pub async fn within<T>(what: &str, fut: impl std::future::Future<Output = T>) -> T {
    match tokio::time::timeout(WAIT, fut).await {
        Ok(v) => v,
        Err(_) => panic!("timed out: {what}"),
    }
}

/// A host listening on loopback, echoing every stream it is given.
pub struct TestHost {
    pub host: Host,
    pub clock: Arc<ManualClock>,
    pub addr: SocketAddr,
    pub accepted: Arc<AtomicUsize>,
    pub rejected: Arc<Mutex<Vec<String>>>,
    pub streams: Arc<AtomicUsize>,
    events: mpsc::UnboundedReceiver<HostEvent>,
    accept: JoinHandle<()>,
}

impl TestHost {
    /// A host with grants in memory only.
    pub async fn start(signer: SharedSigner) -> Self {
        let clock = Arc::new(ManualClock::new());
        let config = HostConfig {
            name: "test host".into(),
            state_dir: None,
            owner: OwnerRef::from_bytes([0x5a; 16]),
            limits: Limits::DEFAULT,
            clock: clock.clone(),
            ticket_identity: None,
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        Self::run(signer, config, clock, listener)
    }

    /// The host of an endpoint, on its kept port.
    pub async fn start_endpoint(endpoint: &mut Endpoint, signer: SharedSigner, name: &str) -> Self {
        Self::start_endpoint_on(endpoint, signer, name, PortChoice::Kept).await
    }

    pub async fn start_endpoint_on(
        endpoint: &mut Endpoint,
        signer: SharedSigner,
        name: &str,
        port: PortChoice,
    ) -> Self {
        let clock = Arc::new(ManualClock::new());
        let config = HostConfig::for_endpoint(endpoint, name.into(), clock.clone()).unwrap();
        let listener = endpoint.bind(LOOPBACK, port).await.unwrap();
        Self::run(signer, config, clock, listener)
    }

    /// A host with explicit settings (for broken setups in controls).
    pub fn run(
        signer: SharedSigner,
        config: HostConfig,
        clock: Arc<ManualClock>,
        listener: TcpListener,
    ) -> Self {
        let (host, events) = Host::new(signer, config, CpaceExchangeFactory).unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let rejected = Arc::new(Mutex::new(Vec::new()));
        let streams = Arc::new(AtomicUsize::new(0));
        let accept = tokio::spawn(accept_loop(
            host.clone(),
            listener,
            accepted.clone(),
            rejected.clone(),
            streams.clone(),
        ));
        Self {
            host,
            clock,
            addr,
            accepted,
            rejected,
            streams,
            events,
            accept,
        }
    }

    pub fn identity(&self) -> IdentityPublicKey {
        self.host.identity()
    }

    pub fn route(&self) -> Route {
        route_from_addr(self.addr)
    }

    /// An in-person ticket, read back from its fragment like a joiner would.
    pub fn invite(&self) -> Ticket {
        self.invite_kind(InvitationKind::InPerson)
    }

    /// A ticket of `kind`.
    pub fn invite_kind(&self, kind: InvitationKind) -> Ticket {
        let created = self
            .host
            .invite(kind, vec![route_uri(&self.route())])
            .unwrap();
        Ticket::from_fragment(&created.fragment).unwrap()
    }

    /// Wait for "Is the device next to you?" and say yes.
    pub async fn approve_next_request(&mut self) {
        loop {
            match within("approval request", self.events.recv()).await {
                Some(HostEvent::ApprovalRequested(req)) => {
                    self.host.approve(&req).unwrap();
                    return;
                }
                Some(_) => continue,
                None => panic!("host events ended"),
            }
        }
    }

    /// Wait for the next code the host shows for a send link.
    pub async fn next_code(&mut self) -> String {
        loop {
            match within("code shown", self.events.recv()).await {
                Some(HostEvent::ShowCode { code, .. }) => return code.as_str().to_owned(),
                Some(_) => continue,
                None => panic!("host events ended"),
            }
        }
    }

    /// Wait for an invitation to end without pairing, and return why.
    pub async fn invitation_ended(&mut self) -> ErrorCode {
        loop {
            match within("invitation end", self.events.recv()).await {
                Some(HostEvent::InvitationEnded { reason, .. }) => return reason,
                Some(_) => continue,
                None => panic!("host events ended"),
            }
        }
    }

    pub fn grant_of(&self, identity: &IdentityPublicKey) -> Option<GrantId> {
        self.host
            .grants()
            .into_iter()
            .find(|g| g.identity == *identity)
            .map(|g| g.id)
    }

    /// Skip the join-proof wait, so an ungranted connection is refused now.
    pub fn skip_join_wait(&self) {
        self.clock
            .advance_mono(Limits::DEFAULT.core().join_proof_wait_ms() + 1_000);
    }

    /// Stop listening and close every connection, as a quit would.
    pub async fn stop(self) {
        self.accept.abort();
        let _ = self.accept.await;
        self.host.close_all(ErrorCode::NoError);
    }
}

async fn accept_loop(
    host: Host,
    listener: TcpListener,
    accepted: Arc<AtomicUsize>,
    rejected: Arc<Mutex<Vec<String>>>,
    streams: Arc<AtomicUsize>,
) {
    loop {
        let Ok((pipe, _)) = accept_tcp(&listener).await else {
            return;
        };
        let host = host.clone();
        let accepted = accepted.clone();
        let rejected = rejected.clone();
        let streams = streams.clone();
        tokio::spawn(async move {
            match host.accept(pipe).await {
                Ok(conn) => {
                    accepted.fetch_add(1, Ordering::SeqCst);
                    serve_echo(conn, streams).await;
                }
                Err(e) => rejected.lock().unwrap().push(e.to_string()),
            }
        });
    }
}

/// Echo every stream on `conn` until it closes.
async fn serve_echo(conn: Connection, streams: Arc<AtomicUsize>) {
    while let Some(stream) = conn.accept_stream().await {
        streams.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let (mut rd, wr) = stream.split();
            while let Ok(Some(bytes)) = rd.read().await {
                if wr.write(&bytes).await.is_err() {
                    return;
                }
            }
            wr.finish();
        });
    }
}

pub fn new_caller(signer: SharedSigner) -> Caller {
    Caller::new(signer, Arc::new(ManualClock::new()), Limits::DEFAULT)
}

pub fn new_caller_with_clock(signer: SharedSigner, clock: Arc<ManualClock>) -> Caller {
    Caller::new(signer, clock, Limits::DEFAULT)
}

/// Pair `caller` with `host` in person, approving on the host.
pub async fn pair(caller: &Caller, host: &mut TestHost, name: &str) -> Connection {
    let ticket = host.invite();
    let pipe = connect_tcp(&host.route()).await.unwrap();
    let join = caller.join(pipe, &ticket, Arrival::InAppScan, name);
    let approve = host.approve_next_request();
    let (result, ()) = tokio::join!(within("join", join), approve);
    let (conn, outcome) = result.unwrap();
    assert!(
        matches!(outcome, mousse_net_io::JoinOutcome::Paired(_)),
        "{outcome:?}"
    );
    conn
}

pub async fn dial(
    caller: &Caller,
    route: &Route,
    pin: IdentityPublicKey,
) -> Result<Connection, NetError> {
    let pipe = connect_tcp(route).await?;
    caller.dial(pipe, pin).await
}

/// Open a terminal-like interactive stream and check one round trip.
pub async fn open_echo(conn: &Connection) -> MuxStream {
    let mut stream = within(
        "open",
        conn.open_stream(PriorityClass::Interactive, "terminal"),
    )
    .await
    .unwrap();
    assert_echo(&mut stream, b"hello").await;
    stream
}

pub async fn assert_echo(stream: &mut MuxStream, bytes: &[u8]) {
    stream.writer.write(bytes).await.unwrap();
    let mut got = Vec::new();
    while got.len() < bytes.len() {
        match within("echo", stream.reader.read()).await {
            Ok(Some(chunk)) => got.extend(chunk),
            other => panic!("stream ended early: {other:?}"),
        }
    }
    assert_eq!(got, bytes);
}

/// How a connection closed, from the caller's side.
pub async fn close_code(conn: &Connection) -> Option<ErrorCode> {
    match within("close", conn.closed()).await {
        CloseReason::Peer(code) | CloseReason::Local(code) => Some(code),
        _ => None,
    }
}

pub fn is_pin_mismatch(e: &NetError) -> bool {
    matches!(
        e,
        NetError::PeerCertificate(mousse_net_core::session_cert::CertError::PinMismatch)
    )
}

pub fn closed_with(e: &NetError, code: ErrorCode) -> bool {
    matches!(e, NetError::Closed(CloseReason::Peer(c)) | NetError::Closed(CloseReason::Local(c)) if *c == code)
}

pub fn endpoint_signer(endpoint: &Endpoint) -> SharedSigner {
    Arc::new(endpoint.load_identity(true).unwrap())
}

/// Codes typed by the test: each ask is reported on `asks` (with the
/// attempts left after a wrong code) and answered from `typed`.
pub struct TypedCodes {
    pub asks: mpsc::UnboundedSender<Option<u8>>,
    pub typed: mpsc::UnboundedReceiver<String>,
}

impl CodeEntry for TypedCodes {
    async fn code(&mut self, retry: Option<u8>) -> Option<String> {
        let _ = self.asks.send(retry);
        self.typed.recv().await
    }
}

/// A six-digit code that differs from `code` in every digit.
pub fn wrong_code(code: &str) -> String {
    code.bytes()
        .map(|d| char::from(b'0' + (d - b'0' + 1) % 10))
        .collect()
}
