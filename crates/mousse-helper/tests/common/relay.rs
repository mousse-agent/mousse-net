//! A real `mousse-relay` on loopback for the helper's relay tests, in its
//! own runtime, behind a forwarder that counts the connections made to it.
//! Enrollment links name the forwarder, so every dial a helper makes to
//! this relay is counted.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mousse_net_core::pairing::RouteHost;
use mousse_net_core::relay::RelayLimits;
use mousse_net_core::time::UnixTime;
use mousse_relay::server::{self, Running, ServerConfig};
use mousse_relay::state::{hex, StateDir};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

pub struct TestRelay {
    rt: tokio::runtime::Runtime,
    pub dir: StateDir,
    path: PathBuf,
    running: Option<Running>,
    front: SocketAddr,
    connections: Arc<AtomicUsize>,
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

impl TestRelay {
    pub fn start() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let mut tag = [0u8; 6];
        getrandom_fill(&mut tag);
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
        let connections = Arc::new(AtomicUsize::new(0));
        let listener = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        let front = listener.local_addr().unwrap();
        let counted = connections.clone();
        let forwarder = rt.spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    if let Ok(mut out) = TcpStream::connect(target).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut out).await;
                    }
                });
            }
        });
        Self {
            rt,
            dir,
            path,
            running: Some(running),
            front,
            connections,
            forwarder,
        }
    }

    /// A fresh enrollment link naming the forwarder.
    pub fn link(&self) -> String {
        let mut link = self
            .dir
            .enroll(now(), 3_600, &mut mousse_relay::os_rng())
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

    /// Stop the relay and its forwarder: dials to it are refused.
    pub fn stop(&mut self) {
        self.forwarder.abort();
        if let Some(r) = self.running.take() {
            let _ = self.rt.block_on(r.stop());
        }
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn getrandom_fill(buf: &mut [u8]) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (n >> (i * 8)) as u8 ^ (std::process::id() as u8).wrapping_mul(i as u8 + 1);
    }
}
