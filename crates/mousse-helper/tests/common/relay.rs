//! A real `mousse-relay` on loopback for the helper's relay tests, in its
//! own runtime, behind a forwarder that counts the connections made to it.
//! Enrollment links name the forwarder, so every connection a helper makes
//! to this relay is counted. Test files include it with `#[path]`.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mousse_net_core::pairing::RouteHost;
use mousse_net_core::relay::{Class, RelayClientKey, RelayId, RelayLimits};
use mousse_net_core::relay_endpoint::{derive_key, CALLER_KEY_INFO, REGISTRATION_KEY_INFO};
use mousse_net_core::time::UnixTime;
use mousse_net_io::keystore::{relay_seed, KeyStorage};
use mousse_net_io::relay::{dial_call, RelayAddr};
use mousse_net_io::store::unhex;
use mousse_relay::server::{self, Running, ServerConfig};
use mousse_relay::state::{hex, StateDir};
use serde_json::Value;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const WAIT: Duration = Duration::from_secs(20);

pub struct TestRelay {
    rt: tokio::runtime::Runtime,
    pub dir: StateDir,
    path: PathBuf,
    running: Option<Running>,
    relay_id: RelayId,
    front: SocketAddr,
    connections: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
    forwarder: JoinHandle<()>,
}

fn now() -> UnixTime {
    UnixTime(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
}

/// Counts a forwarded connection as live until both directions end.
struct Live(Arc<AtomicUsize>);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl TestRelay {
    pub fn start() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let tag = mousse_net_io::rng::random_bytes::<6>();
        let path = std::env::temp_dir().join(format!("mousse-helper-relay-{}", hex(&tag)));
        let dir = StateDir::init(&path, "127.0.0.1:443", &mut mousse_relay::os_rng()).unwrap();
        let limits = RelayLimits::DEFAULT
            .with_overrides(&[("RELAY_STATE_POLL_MS", 100)])
            .unwrap();
        let running = rt
            .block_on(server::start(ServerConfig {
                state: dir.clone(),
                listen: "127.0.0.1:0".parse().unwrap(),
                limits,
                hosted: None,
            }))
            .unwrap();
        let target = running.local_addr;
        let relay_id = running.relay_id;
        let connections = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(AtomicUsize::new(0));
        let listener = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        let front = listener.local_addr().unwrap();
        let forwarder = rt.spawn({
            let connections = connections.clone();
            let live = live.clone();
            async move {
                while let Ok((mut inbound, _)) = listener.accept().await {
                    connections.fetch_add(1, Ordering::SeqCst);
                    live.fetch_add(1, Ordering::SeqCst);
                    let held = Live(live.clone());
                    tokio::spawn(async move {
                        let _held = held;
                        if let Ok(mut out) = TcpStream::connect(target).await {
                            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut out).await;
                        }
                    });
                }
            }
        });
        Self {
            rt,
            dir,
            path,
            running: Some(running),
            relay_id,
            front,
            connections,
            live,
            forwarder,
        }
    }

    /// A fresh enrollment link naming the forwarder.
    pub fn link(&self) -> String {
        let mut link = self
            .dir
            .enroll(now(), 600, &mut mousse_relay::os_rng())
            .unwrap();
        link.host = RouteHost::Ipv4(std::net::Ipv4Addr::LOCALHOST);
        link.port = self.front.port();
        // The running relay reads new codes every RELAY_STATE_POLL_MS.
        std::thread::sleep(Duration::from_millis(300));
        link.to_text()
    }

    /// The destination helpers approve: `relay://127.0.0.1:<forwarder>`.
    pub fn destination(&self) -> String {
        format!("relay://{}", self.front)
    }

    /// Connections made to this relay so far.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Wait until exactly `n` connections to this relay are open. With no
    /// circuits up, that is the number of live registrations.
    pub fn wait_live(&self, n: usize) {
        let start = Instant::now();
        while self.live.load(Ordering::SeqCst) != n {
            assert!(
                start.elapsed() < WAIT,
                "{} connections open, not {n}",
                self.live.load(Ordering::SeqCst)
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// `CALL` `handle` with `key` and wait for the answer: `Ok` once
    /// spliced, else the error's word (`relay_refused` when the relay
    /// does not list the key for the handle).
    pub fn call(&self, handle: [u8; 32], key: &RelayClientKey) -> Result<(), &'static str> {
        let addr = RelayAddr {
            addr: self.front,
            name: None,
        };
        self.rt
            .block_on(dial_call(
                &addr,
                self.relay_id,
                handle,
                key,
                Class::Interactive,
                WAIT,
            ))
            .map(drop)
            .map_err(|e| e.word())
    }

    /// Stop the relay and its forwarder: dials to it are refused.
    pub fn stop(&mut self) {
        self.forwarder.abort();
        if let Some(r) = self.running.take() {
            let _ = self.rt.block_on(r.stop());
        }
    }

    /// The handle of `host_dir`'s current registration key on this relay,
    /// from its relay seed and stored salt.
    pub fn handle_of(&self, host_dir: &Path) -> [u8; 32] {
        handle_in(host_dir, &self.relay_id)
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The handle of `host_dir`'s current registration key on the relay
/// `relay_id`, from its relay seed and stored salt.
pub fn handle_in(host_dir: &Path, relay_id: &RelayId) -> [u8; 32] {
    let relays = read_json(&host_dir.join("relays.json"));
    let salt = relays["relays"][0]["salt"].as_str().unwrap();
    key_from(host_dir, REGISTRATION_KEY_INFO, salt).handle(relay_id)
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn key_from(dir: &Path, info: &str, salt: &str) -> RelayClientKey {
    let seed = relay_seed(dir, "", KeyStorage::InsecureFile).unwrap();
    RelayClientKey::new(derive_key(&seed, info, &unhex(salt).unwrap()).unwrap())
}

/// The caller key `caller_dir` uses for the host `host_identity` (hex),
/// from its relay seed and stored salt.
pub fn caller_key_of(caller_dir: &Path, host_identity: &str) -> RelayClientKey {
    let peers = read_json(&caller_dir.join("relay-peers.json"));
    let salt = peers["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["identity"] == host_identity)
        .unwrap()["salt"]
        .as_str()
        .unwrap()
        .to_owned();
    key_from(caller_dir, CALLER_KEY_INFO, &salt)
}
