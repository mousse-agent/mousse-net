//! Shared helpers: a relay on loopback with its own state directory, and
//! clients that speak the relay protocol.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use mousse_net_core::identity::SoftwareKey;
use mousse_net_core::relay::machine::AuthorizedKey;
use mousse_net_core::relay::{Class, RelayClientKey, RelayId, RelayLimits, RelayMessage};
use mousse_net_core::time::UnixTime;
use mousse_relay::client::{DialError, Received, RelayConn};
use mousse_relay::server::{self, Running, ServerConfig};
use mousse_relay::state::{hex, StateDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

pub const WAIT: Duration = Duration::from_secs(10);

pub fn temp_dir(tag: &str) -> PathBuf {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).unwrap();
    std::env::temp_dir().join(format!("mousse-relay-{tag}-{}", hex(&b)))
}

pub fn now() -> UnixTime {
    UnixTime(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
}

pub fn key(seed: u8) -> RelayClientKey {
    RelayClientKey::new(SoftwareKey::from_secret_bytes(&[seed; 32]).unwrap())
}

pub fn limits(overrides: &[(&str, u64)]) -> RelayLimits {
    RelayLimits::DEFAULT.with_overrides(overrides).unwrap()
}

/// A relay on 127.0.0.1 with its own state directory.
pub struct Fixture {
    pub dir: StateDir,
    pub path: PathBuf,
    pub limits: RelayLimits,
    pub relay: Option<Running>,
    pub addr: SocketAddr,
    pub id: RelayId,
}

impl Fixture {
    pub async fn new(tag: &str, overrides: &[(&str, u64)], authorized: &[&RelayClientKey]) -> Self {
        let path = temp_dir(tag);
        let dir = StateDir::init(&path, "127.0.0.1:443", &mut mousse_relay::os_rng()).unwrap();
        dir.update(now(), |l| {
            for k in authorized {
                l.authorized.push(AuthorizedKey {
                    fingerprint: k.fingerprint(),
                    drop_at: None,
                });
            }
        })
        .unwrap();
        let mut f = Self {
            dir,
            path,
            limits: limits(overrides),
            relay: None,
            addr: "127.0.0.1:0".parse().unwrap(),
            id: RelayId([0; 32]),
        };
        f.start().await;
        f
    }

    pub async fn start(&mut self) {
        let running = server::start(ServerConfig {
            state: self.dir.clone(),
            listen: "127.0.0.1:0".parse().unwrap(),
            limits: self.limits,
        })
        .await
        .unwrap();
        self.addr = running.local_addr;
        self.id = running.relay_id;
        self.relay = Some(running);
    }

    pub async fn stop(&mut self) {
        if let Some(r) = self.relay.take() {
            r.stop().await.unwrap();
        }
    }

    pub async fn dial(&self) -> RelayConn {
        self.try_dial().await.unwrap()
    }

    pub async fn try_dial(&self) -> Result<RelayConn, DialError> {
        RelayConn::dial(self.addr, "127.0.0.1", self.id).await
    }

    pub fn handle(&self, k: &RelayClientKey) -> [u8; 32] {
        k.handle(&self.id)
    }

    /// A registration connection for `k`.
    pub async fn register(&self, k: &RelayClientKey) -> RelayConn {
        let mut c = self.dial().await;
        let msg = RelayMessage::Register {
            key: k.public_key(),
            proof: k.register_proof(&self.id, &c.binding),
            hosted: None,
        };
        c.send(&msg).await.unwrap();
        assert_eq!(
            relay(&mut c).await,
            RelayMessage::Registered {
                handle: self.handle(k)
            }
        );
        c
    }

    /// A call leg that has sent its `CALL`.
    pub async fn call(&self, caller: &RelayClientKey, handle: [u8; 32], class: Class) -> RelayConn {
        let mut c = self.dial().await;
        let msg = RelayMessage::Call {
            handle,
            key: caller.public_key(),
            proof: caller.call_proof(&self.id, &handle, &c.binding, class),
            class,
        };
        c.send(&msg).await.unwrap();
        c
    }

    /// An accept leg that has sent its `ACCEPT`.
    pub async fn accept(&self, target: &RelayClientKey, circuit: [u8; 16]) -> RelayConn {
        let mut c = self.dial().await;
        let msg = RelayMessage::Accept {
            handle: self.handle(target),
            circuit,
            proof: target.accept_proof(&self.id, &circuit, &c.binding),
        };
        c.send(&msg).await.unwrap();
        c
    }

    /// A spliced call from `caller` to `target` (registered on `reg`).
    pub async fn connect(
        &self,
        reg: &mut RelayConn,
        target: &RelayClientKey,
        caller: &RelayClientKey,
        class: Class,
    ) -> (RelayConn, RelayConn) {
        let mut leg = self.call(caller, self.handle(target), class).await;
        let circuit = incoming(reg).await;
        let mut acc = self.accept(target, circuit).await;
        assert_eq!(relay(&mut leg).await, RelayMessage::Spliced);
        assert_eq!(relay(&mut acc).await, RelayMessage::Spliced);
        (leg, acc)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The next thing on `c`, within [`WAIT`].
pub async fn next(c: &mut RelayConn) -> Received {
    tokio::time::timeout(WAIT, c.recv())
        .await
        .expect("nothing arrived in time")
}

/// The next relay message on `c`; PINGs are skipped.
pub async fn relay(c: &mut RelayConn) -> RelayMessage {
    loop {
        match next(c).await {
            Received::Relay(RelayMessage::Ping { .. }) => continue,
            Received::Relay(m) => return m,
            other => panic!("expected a relay message, got {other:?}"),
        }
    }
}

/// The circuit of the next `INCOMING` on `reg`.
pub async fn incoming(reg: &mut RelayConn) -> [u8; 16] {
    match relay(reg).await {
        RelayMessage::Incoming { circuit, .. } => circuit,
        other => panic!("expected INCOMING, got {other:?}"),
    }
}

pub async fn allow(reg: &mut RelayConn, sequence: u64, callers: &[&RelayClientKey]) {
    reg.send(&RelayMessage::AllowSet {
        sequence,
        callers: callers.iter().map(|c| c.fingerprint()).collect(),
        invitations: vec![],
    })
    .await
    .unwrap();
    assert_eq!(relay(reg).await, RelayMessage::AllowSetOk { sequence });
}

/// The close code `c` ends with (after an optional relay message).
pub async fn closed(c: &mut RelayConn) -> Option<u16> {
    loop {
        if let Received::Closed(code) = next(c).await {
            return code;
        }
    }
}

/// Turn a spliced relay leg into a byte stream. `inject` sends raw peer
/// messages beside the stream (the packet control).
pub fn bridge(mut conn: RelayConn) -> (DuplexStream, mpsc::UnboundedSender<Vec<u8>>) {
    let (mine, theirs) = tokio::io::duplex(256 * 1024);
    let (tx, mut inject) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        let (mut rd, mut wr) = tokio::io::split(theirs);
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            tokio::select! {
                n = rd.read(&mut buf) => match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => if conn.send_raw(buf[..n].to_vec()).await.is_err() { break },
                },
                got = conn.recv() => match got {
                    Received::Peer(b) => if wr.write_all(&b).await.is_err() { break },
                    _ => break,
                },
                raw = inject.recv() => if let Some(raw) = raw {
                    let _ = conn.send_raw(raw).await;
                },
            }
        }
    });
    (mine, tx)
}
