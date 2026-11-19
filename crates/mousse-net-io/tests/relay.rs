//! Calls through a relay (§B.3 to §B.8) against a real `mousse-relay` on
//! loopback: the peer TLS runs end to end inside the splice, the relay's
//! key is pinned before any relay message, and the allow-set decides who
//! reaches the host.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use mousse_net_core::identity::SoftwareKey;
use mousse_net_core::relay::machine::AuthorizedKey;
use mousse_net_core::relay::{Class, EnrollmentLink, RelayClientKey, RelayId, RelayLimits};
use mousse_net_core::time::UnixTime;
use mousse_net_io::relay::{
    dial_call, AllowSet, Proof, RelayAddr, RelayError, TargetCommand, TargetEvent, TargetLink,
};
use mousse_net_io::rng::os_rng;
use mousse_net_io::{Caller, Connection, Host};
use mousse_relay::server::{self, Running, ServerConfig};
use mousse_relay::state::{hex, StateDir};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// The relay's refusal deadline in these tests (its least).
const REFUSE: Duration = Duration::from_millis(500);

fn key() -> Arc<RelayClientKey> {
    Arc::new(RelayClientKey::new(SoftwareKey::generate(&mut os_rng())))
}

fn now() -> UnixTime {
    UnixTime(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
}

/// A `mousse-relay` on 127.0.0.1 with its own state directory.
struct TestRelay {
    dir: StateDir,
    path: PathBuf,
    running: Option<Running>,
}

impl TestRelay {
    async fn start() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mousse-net-io-relay-{}",
            hex(&mousse_net_io::rng::random_bytes::<8>())
        ));
        let dir = StateDir::init(&path, "127.0.0.1:443", &mut mousse_relay::os_rng()).unwrap();
        let limits = RelayLimits::DEFAULT
            .with_overrides(&[
                ("RELAY_STATE_POLL_MS", 100),
                ("RELAY_REFUSE_MS", REFUSE.as_millis() as u64),
            ])
            .unwrap();
        let running = server::start(ServerConfig {
            state: dir.clone(),
            listen: "127.0.0.1:0".parse().unwrap(),
            limits,
            hosted: None,
        })
        .await
        .unwrap();
        Self {
            dir,
            path,
            running: Some(running),
        }
    }

    fn running(&self) -> &Running {
        self.running.as_ref().unwrap()
    }

    fn relay_id(&self) -> RelayId {
        self.running().relay_id
    }

    /// Authorize a registration key, as `mousse-relay authorize` does.
    async fn authorize(&self, key: &RelayClientKey) {
        self.dir
            .update(now(), |l| {
                l.authorized.push(AuthorizedKey {
                    fingerprint: key.fingerprint(),
                    drop_at: None,
                })
            })
            .unwrap();
        // The relay reads its lists every RELAY_STATE_POLL_MS.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    /// A fresh enrollment link for this relay's port.
    async fn enrollment_link(&self) -> EnrollmentLink {
        let mut link = self
            .dir
            .enroll(now(), 600, &mut mousse_relay::os_rng())
            .unwrap();
        link.port = self.running().local_addr.port();
        tokio::time::sleep(Duration::from_millis(300)).await;
        link
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        drop(self.running.take());
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn addr(relay: &TestRelay) -> RelayAddr {
    RelayAddr {
        addr: relay.running().local_addr,
        name: None,
    }
}

/// A host registered on a relay; every spliced circuit runs the host side
/// of a peer session and echoes its streams.
struct Target {
    handle: [u8; 32],
    allow: watch::Sender<AllowSet>,
    accepted: Arc<AtomicUsize>,
    _commands: mpsc::UnboundedSender<TargetCommand>,
    task: JoinHandle<RelayError>,
    _serve: JoinHandle<()>,
}

impl Target {
    async fn start(relay: &TestRelay, host: Host, proof: Proof, set: AllowSet) -> Self {
        let reg = key();
        if matches!(proof, Proof::Register) {
            relay.authorize(&reg).await;
        }
        let link = within(
            "register",
            TargetLink::register(&addr(relay), relay.relay_id(), reg, proof, WAIT),
        )
        .await
        .expect("registered");
        let handle = link.handle();
        let (allow, allow_rx) = watch::channel(set);
        let (commands, commands_rx) = mpsc::unbounded_channel();
        let (events_tx, mut events) = mpsc::unbounded_channel();
        let task = tokio::spawn(link.run(
            allow_rx,
            commands_rx,
            events_tx,
            Duration::from_secs(10),
            Duration::from_secs(60),
        ));
        let accepted = Arc::new(AtomicUsize::new(0));
        let acks = Arc::new(AtomicUsize::new(0));
        let serve = tokio::spawn({
            let accepted = accepted.clone();
            let acks = acks.clone();
            async move {
                while let Some(event) = events.recv().await {
                    match event {
                        TargetEvent::AllowSetOk { .. } => {
                            acks.fetch_add(1, Ordering::SeqCst);
                        }
                        TargetEvent::Incoming { pipe, .. } => {
                            let host = host.clone();
                            let accepted = accepted.clone();
                            tokio::spawn(async move {
                                if let Ok(conn) = host.accept(pipe).await {
                                    accepted.fetch_add(1, Ordering::SeqCst);
                                    serve_echo(conn, Arc::new(AtomicUsize::new(0))).await;
                                }
                            });
                        }
                        TargetEvent::AcceptFailed { .. } => {}
                    }
                }
            }
        });
        // The first allow-set is in before anyone calls.
        wait_for("first allow-set", || acks.load(Ordering::SeqCst) > 0).await;
        Self {
            handle,
            allow,
            accepted,
            _commands: commands,
            task,
            _serve: serve,
        }
    }
}

async fn wait_for(what: &str, cond: impl Fn() -> bool) {
    within(what, async {
        while !cond() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
}

fn listing(callers: &[&RelayClientKey]) -> AllowSet {
    AllowSet {
        callers: callers.iter().map(|k| k.fingerprint()).collect(),
        invitations: Vec::new(),
    }
}

async fn call(
    relay: &TestRelay,
    pin: RelayId,
    handle: [u8; 32],
    caller_key: &RelayClientKey,
    caller: &Caller,
    host: &TestHost,
) -> Result<Connection, String> {
    let pipe = dial_call(
        &addr(relay),
        pin,
        handle,
        caller_key,
        Class::Interactive,
        WAIT,
    )
    .await
    .map_err(|e| e.word().to_owned())?;
    within(
        "peer TLS through the relay",
        caller.dial(pipe, host.identity()),
    )
    .await
    .map_err(|e| e.to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listed_caller_reaches_the_host_with_peer_tls_end_to_end() {
    let relay = TestRelay::start().await;
    let mut host = TestHost::start(new_signer()).await;
    let caller = new_caller(new_signer());
    drop(pair(&caller, &mut host, "laptop").await);
    let caller_key = key();
    let target = Target::start(
        &relay,
        host.host.clone(),
        Proof::Register,
        listing(&[&caller_key]),
    )
    .await;

    let conn = call(
        &relay,
        relay.relay_id(),
        target.handle,
        &caller_key,
        &caller,
        &host,
    )
    .await
    .unwrap();
    // The hybrid group is the peer session's own, not the relay's.
    assert_eq!(conn.kx_group(), "X25519MLKEM768");
    assert_eq!(conn.peer(), &host.identity());
    let _stream = open_echo(&conn).await;
    assert_eq!(target.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_wrong_relay_key_fails_before_any_relay_message() {
    let relay = TestRelay::start().await;
    let host = TestHost::start(new_signer()).await;
    let caller_key = key();
    let target = Target::start(
        &relay,
        host.host.clone(),
        Proof::Register,
        listing(&[&caller_key]),
    )
    .await;
    let other = RelayId::of(&key().public_key());
    let caller = new_caller(new_signer());

    let got = call(&relay, other, target.handle, &caller_key, &caller, &host).await;

    // `relay_key` comes from the outer TLS handshake, before any relay
    // message. Without the pin the relay itself refuses the CALL, whose
    // proof names another relay.
    assert_eq!(got.err().as_deref(), Some("relay_key"));
    assert_eq!(target.accepted.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unlisted_caller_is_unreachable_at_the_constant_deadline() {
    let relay = TestRelay::start().await;
    let host = TestHost::start(new_signer()).await;
    let listed = key();
    let target = Target::start(
        &relay,
        host.host.clone(),
        Proof::Register,
        listing(&[&listed]),
    )
    .await;
    let caller = new_caller(new_signer());

    for (what, handle) in [("unlisted key", target.handle), ("unknown handle", [7; 32])] {
        let started = Instant::now();
        let got = call(&relay, relay.relay_id(), handle, &key(), &caller, &host).await;
        assert_eq!(got.err().as_deref(), Some("relay_refused"), "{what}");
        assert!(started.elapsed() >= REFUSE, "{what} answered early");
    }
    assert_eq!(target.accepted.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_a_caller_from_the_allow_set_closes_only_its_circuits() {
    let relay = TestRelay::start().await;
    let mut host = TestHost::start(new_signer()).await;
    let (a, b) = (new_caller(new_signer()), new_caller(new_signer()));
    drop(pair(&a, &mut host, "a").await);
    drop(pair(&b, &mut host, "b").await);
    let (ka, kb) = (key(), key());
    let target = Target::start(
        &relay,
        host.host.clone(),
        Proof::Register,
        listing(&[&ka, &kb]),
    )
    .await;
    let id = relay.relay_id();
    let conn_a = call(&relay, id, target.handle, &ka, &a, &host)
        .await
        .unwrap();
    let conn_b = call(&relay, id, target.handle, &kb, &b, &host)
        .await
        .unwrap();
    let _sa = open_echo(&conn_a).await;
    let mut sb = open_echo(&conn_b).await;

    target.allow.send_replace(listing(&[&kb]));

    within("a's circuit closed", conn_a.closed()).await;
    assert_echo(&mut sb, b"still here").await;
    let again = call(&relay, id, target.handle, &ka, &a, &host).await;
    assert_eq!(again.err().as_deref(), Some("relay_refused"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_enrollment_code_registers_once() {
    let relay = TestRelay::start().await;
    let host = TestHost::start(new_signer()).await;
    let link = EnrollmentLink::parse(&relay.enrollment_link().await.to_text()).unwrap();
    assert_eq!(link.relay, relay.relay_id());

    let target = Target::start(
        &relay,
        host.host.clone(),
        Proof::Enroll(link.code),
        AllowSet::default(),
    )
    .await;
    // The enrolled key is the one authorized key now.
    assert_eq!(relay.dir.read().unwrap().authorized.len(), 1);

    let id = relay.relay_id();
    let again =
        TargetLink::register(&addr(&relay), id, key(), Proof::Enroll(link.code), WAIT).await;
    assert_eq!(again.err().map(|e| e.word()), Some("relay_not_authorized"));
    let unknown = TargetLink::register(&addr(&relay), id, key(), Proof::Register, WAIT).await;
    assert_eq!(
        unknown.err().map(|e| e.word()),
        Some("relay_not_authorized")
    );
    assert!(!target.task.is_finished());
}
