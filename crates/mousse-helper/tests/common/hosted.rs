//! Hosted relays for the helper's end-to-end tests (Phase 4): real
//! `mousse-relay` processes in hosted mode (in this test process, in their
//! own runtime) and the two Plus test stand-ins, both test fixtures:
//!
//! - the relay side's issuer stand-in (`mousse-relay-plus`'s
//!   `test_issuer_standin.rs`): boot records, heartbeats and usage reports;
//! - the endpoint side's stand-in (`plus_standin.rs`): link, tokens, the
//!   fleet, admission, leases, directory and inbox.
//!
//! Each relay pins the endpoint stand-in's throwaway issuer key, so the
//! admission tokens and blocks the helper gets are the ones the relay
//! checks. A thread carries the finals the relays report over to the
//! endpoint stand-in, as Plus would. Test files include it with `#[path]`
//! and declare `test_issuer_standin` at their root.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mousse_net_core::relay::{RelayId, RelayLimits};
use mousse_net_core::relay_hosted::HostedLimits;
use mousse_net_io::relay::{RelayAddr, RelayLink};
use mousse_relay::server::{self, HostedConfig, Running, ServerConfig, ISSUER_KEYS_FILE};
use mousse_relay::state::{hex, StateDir};
use mousse_relay_plus::settings::{HostedSettings, PlusUrl};

use crate::common::plus_standin::PlusStandIn;
use crate::test_issuer_standin::TestIssuerStandIn;

const WAIT: Duration = Duration::from_secs(20);

/// One hosted relay.
pub struct HostedRelay {
    pub id: RelayId,
    pub key: [u8; 65],
    pub addr: SocketAddr,
    path: PathBuf,
    running: Option<Running>,
}

/// Plus (both stand-ins) and its relay fleet.
pub struct Fleet {
    pub rt: tokio::runtime::Runtime,
    pub plus: Arc<PlusStandIn>,
    pub issuer: Arc<TestIssuerStandIn>,
    pub relays: Vec<HostedRelay>,
    stop: Arc<AtomicBool>,
    bridge: Option<std::thread::JoinHandle<()>>,
}

impl Fleet {
    /// Plus and `n` hosted relays; the fleet Plus lists is the first one.
    pub fn start(n: usize) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let plus = Arc::new(PlusStandIn::start());
        let issuer = Arc::new(rt.block_on(TestIssuerStandIn::start(77)));
        let mut relays = Vec::new();
        for i in 0..n {
            relays.push(start_relay(&rt, &plus, &issuer, i));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let bridge = std::thread::spawn({
            let plus = plus.clone();
            let issuer = issuer.clone();
            let stop = stop.clone();
            move || {
                while !stop.load(Ordering::SeqCst) {
                    for (lease, _, _, _, done) in plus.leases() {
                        if !done && issuer.final_of(lease).is_some() {
                            plus.finalize_lease(lease);
                        }
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        });
        let fleet = Self {
            rt,
            plus,
            issuer,
            relays,
            stop,
            bridge: Some(bridge),
        };
        fleet.list(&[0]);
        fleet
    }

    /// The fleet Plus lists: these relays, in this order.
    pub fn list(&self, which: &[usize]) {
        self.plus.set_relays(
            which
                .iter()
                .map(|&i| {
                    let r = &self.relays[i];
                    (r.key, "test".to_owned(), vec![r.addr.to_string()])
                })
                .collect(),
        );
    }

    /// The destination a caller approves for relay `i`.
    pub fn destination(&self, i: usize) -> String {
        format!("relay://{}", self.relays[i].addr)
    }

    /// Stop relay `i`: it reports every lease final and closes.
    pub fn stop_relay(&mut self, i: usize) {
        if let Some(r) = self.relays[i].running.take() {
            let _ = self.rt.block_on(r.stop());
        }
    }

    /// Blocks issued for relay `i`: `(lease, handle, class, done)`.
    pub fn leases_on(&self, i: usize) -> Vec<([u8; 16], [u8; 32], u64, bool)> {
        let id = self.relays[i].id.0;
        self.plus
            .leases()
            .into_iter()
            .filter(|(_, relay, ..)| *relay == id)
            .map(|(l, _, h, c, d)| (l, h, c, d))
            .collect()
    }

    /// Handles given an admission token on relay `i`.
    pub fn handles_on(&self, i: usize) -> Vec<[u8; 32]> {
        let id = self.relays[i].id.0;
        self.plus
            .admitted()
            .into_iter()
            .filter(|(_, relay)| *relay == id)
            .map(|(h, _)| h)
            .collect()
    }

    /// Wait until `what` holds.
    pub fn until(&self, what: &str, mut ok: impl FnMut(&Self) -> bool) {
        let start = Instant::now();
        while !ok(self) {
            assert!(start.elapsed() < WAIT * 2, "never: {what}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Fleet {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(b) = self.bridge.take() {
            let _ = b.join();
        }
        for i in 0..self.relays.len() {
            self.stop_relay(i);
            let _ = std::fs::remove_dir_all(&self.relays[i].path);
        }
    }
}

fn start_relay(
    rt: &tokio::runtime::Runtime,
    plus: &PlusStandIn,
    issuer: &TestIssuerStandIn,
    i: usize,
) -> HostedRelay {
    let tag = mousse_net_io::rng::random_bytes::<6>();
    let path = std::env::temp_dir().join(format!("mousse-helper-hosted-{i}-{}", hex(&tag)));
    let dir = StateDir::init(&path, "127.0.0.1:443", &mut mousse_relay::os_rng()).unwrap();
    std::fs::write(
        path.join(ISSUER_KEYS_FILE),
        format!(
            "# the endpoint stand-in's throwaway issuer key\n{}\n",
            hex(&plus.issuer_public_key())
        ),
    )
    .unwrap();
    let report = mousse_relay_plus::state::report_key(&path).unwrap();
    let id = dir.relay_id().unwrap();
    issuer.add_relay(id.0, report.public_key());
    let key: [u8; 65] = *dir.identity().unwrap().public_key().as_bytes();
    let limits = HostedLimits::DEFAULT
        .with_overrides(&[
            ("RELAY_REPORT_MS", 1_000),
            ("RELAY_REPORT_MIN_MS", 100),
            ("RELAY_PLUS_RETRY_FIRST_MS", 100),
            ("RELAY_PLUS_RETRY_MAX_MS", 1_000),
            ("RELAY_FINAL_REPORT_WAIT_MS", 2_000),
            ("RELAY_PLUS_TIMEOUT_MS", 2_000),
        ])
        .unwrap();
    let running = rt
        .block_on(server::start(ServerConfig {
            state: dir,
            listen: "127.0.0.1:0".parse().unwrap(),
            limits: RelayLimits::DEFAULT
                .with_overrides(&[("RELAY_STATE_POLL_MS", 100)])
                .unwrap(),
            hosted: Some(HostedConfig {
                settings: HostedSettings {
                    plus_url: PlusUrl::parse(&issuer.url()).unwrap(),
                    limits,
                },
                build_id: "mousse-relay test".into(),
            }),
        }))
        .unwrap();
    let addr = running.local_addr;
    // The relay's boot is known at Plus (its boot record): blocks name it.
    let boot = rt
        .block_on(RelayLink::connect(
            &RelayAddr { addr, name: None },
            id,
            WAIT,
        ))
        .unwrap()
        .boot_id();
    plus.register_boot(id.0, boot);
    // Boot acknowledged: its boot record has arrived.
    let start = Instant::now();
    while issuer.boot_bodies().len() <= i {
        assert!(start.elapsed() < WAIT, "no boot record");
        std::thread::sleep(Duration::from_millis(10));
    }
    HostedRelay {
        id,
        key,
        addr,
        path,
        running: Some(running),
    }
}
