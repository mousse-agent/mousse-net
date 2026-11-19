//! The running relay: TLS and WebSocket on each connection, the core
//! admission machine behind one lock, a timer that fires its waits on time,
//! splicing with per-circuit queues and the shared egress ceiling, and the
//! state directory for the authorized list and enrollment codes.
//!
//! Logs carry counts only: no address, key, handle or fingerprint.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use mousse_net_core::relay::machine::{ConnId, IpKey, Now, Output, Relay, RelayConfig};
use mousse_net_core::relay::{Class, RelayId, RelayLimits};
use mousse_net_core::time::{Millis, UnixTime};
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role};
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::WebSocketStream;

use crate::egress::Egress;
use crate::state::{Lists, StateDir, StateError};
use crate::{os_rng, tls, upgrade, OsRng};

type Ws = WebSocketStream<BufReader<TlsStream<TcpStream>>>;

/// What a connection's writer does next.
enum Cmd {
    /// Send a binary message. `permits` go back to this connection's queue
    /// once written (forwarded peer bytes).
    Send {
        bytes: Vec<u8>,
        class: Class,
        permits: usize,
    },
    /// Send a close frame and stop.
    Close(u16),
}

struct ConnHandle {
    tx: mpsc::UnboundedSender<Cmd>,
    /// Bytes queued toward this connection may not exceed
    /// `RELAY_QUEUE_BYTES`: a forwarding reader takes permits first.
    queue: Arc<Semaphore>,
    /// The other leg and the circuit class, once spliced.
    peer: Option<(ConnId, Class)>,
    /// Told when the relay closed this connection, so its reader stops.
    stop: Arc<Notify>,
}

struct Core {
    relay: Relay,
    conns: HashMap<ConnId, ConnHandle>,
    next_conn: u64,
    rng: OsRng,
    /// Addresses with a connection still in its TLS and WebSocket upgrade.
    upgrading: HashMap<IpKey, u64>,
    upgrading_total: u64,
    #[cfg(mousse_control = "relay-persist-allow-set")]
    control: crate::control::PersistAllowSet,
}

struct Shared {
    core: Mutex<Core>,
    limits: RelayLimits,
    epoch: Instant,
    wall_offset: Option<u64>,
    wake: Notify,
    egress: Egress,
    state: StateDir,
}

/// How to run a relay.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// The state directory (`mousse-relay init`).
    pub state: StateDir,
    /// Where to listen.
    pub listen: SocketAddr,
    /// Limits.
    pub limits: RelayLimits,
}

/// A started relay.
#[derive(Debug)]
pub struct Running {
    /// The address it listens on.
    pub local_addr: SocketAddr,
    /// Its relay id.
    pub relay_id: RelayId,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), String>>,
}

impl Running {
    /// Stop: every connection closes with 4003, then the process lock is
    /// released.
    pub async fn stop(mut self) -> Result<(), String> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.task.await.map_err(|e| e.to_string())?
    }

    /// Wait until the relay ends (it only ends when stopped).
    pub async fn wait(self) -> Result<(), String> {
        self.task.await.map_err(|e| e.to_string())?
    }
}

/// The address key a connection counts against: an IPv4 address (an
/// IPv4-mapped IPv6 one counts as IPv4), or the /64 of an IPv6 address.
pub fn ip_key(addr: IpAddr) -> IpKey {
    let mut k = [0u8; 16];
    match addr {
        IpAddr::V4(v4) => {
            k[..4].copy_from_slice(&v4.octets());
            k[15] = 4;
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => return ip_key(IpAddr::V4(v4)),
            None => {
                k[..8].copy_from_slice(&v6.octets()[..8]);
                k[15] = 6;
            }
        },
    }
    IpKey(k)
}

impl Shared {
    fn now(&self) -> Now {
        let mono = Millis(self.epoch.elapsed().as_millis() as u64);
        let wall = match self.wall_offset {
            Some(base) => base + mono.0 / 1000,
            None => SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        Now {
            mono,
            wall: UnixTime(wall),
        }
    }

    /// Carry out `outs` in order, under the core lock. `payload` is the
    /// peer message of a `Forward`, with the queue permits it took.
    fn execute(&self, core: &mut Core, outs: Vec<Output>, mut payload: Option<(Vec<u8>, usize)>) {
        for out in outs {
            match out {
                Output::Send { conn, message } => {
                    if let Some(h) = core.conns.get(&conn) {
                        let _ = h.tx.send(Cmd::Send {
                            bytes: message,
                            class: Class::Interactive,
                            permits: 0,
                        });
                    }
                }
                Output::Close { conn, code } => {
                    if let Some(h) = core.conns.remove(&conn) {
                        let _ = h.tx.send(Cmd::Close(code));
                        h.queue.close();
                        h.stop.notify_one();
                    }
                }
                Output::Splice {
                    caller,
                    target,
                    class,
                    ..
                } => {
                    if let Some(h) = core.conns.get_mut(&caller) {
                        h.peer = Some((target, class));
                    }
                    if let Some(h) = core.conns.get_mut(&target) {
                        h.peer = Some((caller, class));
                    }
                }
                Output::Forward { to, .. } => {
                    if let (Some((bytes, permits)), Some(h)) = (payload.take(), core.conns.get(&to))
                    {
                        let class = h.peer.map(|(_, c)| c).unwrap_or(Class::Interactive);
                        let _ = h.tx.send(Cmd::Send {
                            bytes,
                            class,
                            permits,
                        });
                    }
                }
                Output::Authorize { fingerprint } => self.persist(|l| {
                    if !l.authorized.iter().any(|k| k.fingerprint == fingerprint) {
                        l.authorized.push(mousse_net_core::relay::AuthorizedKey {
                            fingerprint,
                            drop_at: None,
                        });
                    }
                }),
                Output::Supersede {
                    fingerprint,
                    drop_at,
                } => self.persist(|l| {
                    for k in l
                        .authorized
                        .iter_mut()
                        .filter(|k| k.fingerprint == fingerprint)
                    {
                        k.drop_at = Some(drop_at);
                    }
                }),
                Output::Drop { fingerprint } => {
                    self.persist(|l| l.authorized.retain(|k| k.fingerprint != fingerprint))
                }
                Output::ConsumeCode { hash } => {
                    self.persist(|l| l.codes.retain(|c| c.hash != hash))
                }
            }
        }
        self.wake.notify_one();
    }

    /// A durable change to the lists. A relay that cannot write its state
    /// directory stops: it must not answer as if the change were stored.
    fn persist(&self, change: impl FnOnce(&mut Lists)) {
        if let Err(e) = self.state.update(self.now().wall, change) {
            // Nothing after this output may go out.
            eprintln!("mousse-relay: cannot write the state directory: {e}; stopping");
            std::process::abort();
        }
    }

    /// Apply the authorized list and codes from the state directory, so
    /// `revoke` and `enroll` take effect.
    fn reload(&self) {
        // Read under the core lock: the relay's own durable changes are made
        // under it too, so a read can never be older than the machine.
        let mut guard = self.core.lock().expect("core");
        let core = &mut *guard;
        let Ok(lists) = self.state.read() else {
            return;
        };
        let now = self.now();
        let mut authorized = lists.authorized.clone();
        authorized.sort_by_key(|k| k.fingerprint);
        let mut codes = lists.codes.clone();
        codes.sort_by_key(|c| c.hash);
        if authorized == core.relay.authorized() && codes == core.relay.codes() {
            return;
        }
        let outs = core
            .relay
            .replace_state(&lists.authorized, &lists.codes, now, &mut core.rng);
        self.execute(core, outs, None);
    }
}

/// Start a relay. It holds the state directory's process lock until it
/// stops.
pub async fn start(config: ServerConfig) -> Result<Running, String> {
    start_inner(config, None).await
}

/// Start a relay whose wall clock is `wall_base` plus whole seconds since
/// it started (tests only).
#[doc(hidden)]
pub async fn start_with_wall(config: ServerConfig, wall_base: u64) -> Result<Running, String> {
    start_inner(config, Some(wall_base)).await
}

async fn start_inner(config: ServerConfig, wall_offset: Option<u64>) -> Result<Running, String> {
    let lock = config.state.lock_process().map_err(|e| e.to_string())?;
    let identity = config.state.identity().map_err(|e| e.to_string())?;
    let lists = config.state.read().map_err(|e: StateError| e.to_string())?;
    let relay_key = identity.public_key();
    let relay_id = RelayId::of(&relay_key);
    let mut boot_id = [0u8; 16];
    rand_core::Rng::fill_bytes(&mut os_rng(), &mut boot_id);
    let acceptor = TlsAcceptor::from(tls::server_config(identity));
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", config.listen))?;
    let local_addr = listener.local_addr().map_err(|e| e.to_string())?;
    let shared = Arc::new(Shared {
        core: Mutex::new(Core {
            relay: Relay::new(
                RelayConfig {
                    relay_key,
                    boot_id,
                    limits: config.limits,
                },
                &lists.authorized,
                &lists.codes,
            ),
            conns: HashMap::new(),
            next_conn: 1,
            rng: os_rng(),
            upgrading: HashMap::new(),
            upgrading_total: 0,
            #[cfg(mousse_control = "relay-persist-allow-set")]
            control: crate::control::PersistAllowSet::load(&config.state),
        }),
        limits: config.limits,
        epoch: Instant::now(),
        wall_offset,
        wake: Notify::new(),
        egress: Egress::new(config.limits.egress_bps()),
        state: config.state.clone(),
    });
    let (stop_tx, stop_rx) = oneshot::channel();
    let task = tokio::spawn(serve(shared, listener, acceptor, stop_rx, lock));
    Ok(Running {
        local_addr,
        relay_id,
        stop: Some(stop_tx),
        task,
    })
}

async fn serve(
    shared: Arc<Shared>,
    listener: TcpListener,
    acceptor: TlsAcceptor,
    mut stop: oneshot::Receiver<()>,
    lock: crate::state::ProcessLock,
) -> Result<(), String> {
    let timer = tokio::spawn(timer(shared.clone()));
    let poll = tokio::spawn(poll_state(shared.clone()));
    loop {
        tokio::select! {
            _ = &mut stop => break,
            accepted = listener.accept() => {
                let Ok((tcp, addr)) = accepted else { continue };
                let _ = tcp.set_nodelay(true);
                let ip = ip_key(addr.ip());
                if !admit_upgrade(&shared, ip) {
                    drop(tcp);
                    continue;
                }
                tokio::spawn(connection(shared.clone(), acceptor.clone(), tcp, ip));
            }
        }
    }
    timer.abort();
    poll.abort();
    drop(listener);
    {
        let mut core = shared.core.lock().expect("core");
        let outs = core.relay.stop();
        shared.execute(&mut core, outs, None);
    }
    // Give the writers a moment to send their close frames.
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(lock);
    Ok(())
}

/// A connection in its upgrade counts against the same limits as an open
/// one, so handshakes cannot be used to get around them.
fn admit_upgrade(shared: &Shared, ip: IpKey) -> bool {
    let mut core = shared.core.lock().expect("core");
    let l = &shared.limits;
    let open = core.relay.counts().connections as u64;
    let at_ip = core.upgrading.get(&ip).copied().unwrap_or(0) + core.relay.connections_at(ip);
    if open + core.upgrading_total >= l.max_connections() || at_ip >= l.connections_per_ip() {
        return false;
    }
    *core.upgrading.entry(ip).or_insert(0) += 1;
    core.upgrading_total += 1;
    true
}

fn upgrade_done(shared: &Shared, ip: IpKey) {
    let mut core = shared.core.lock().expect("core");
    if let Some(n) = core.upgrading.get_mut(&ip) {
        *n -= 1;
        if *n == 0 {
            core.upgrading.remove(&ip);
        }
    }
    core.upgrading_total -= 1;
}

async fn handshake(
    shared: &Shared,
    acceptor: TlsAcceptor,
    tcp: TcpStream,
) -> Result<(Ws, [u8; 32]), String> {
    let tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
    tls::check(tls.get_ref().1, false)?;
    let exporter = tls::exporter(tls.get_ref().1).map_err(|e| e.to_string())?;
    let mut stream = BufReader::new(tls);
    if let Err(e) = upgrade::accept(&mut stream, shared.limits.header_max_bytes() as usize).await {
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
        return Err(format!("{e:?}"));
    }
    let ws =
        WebSocketStream::from_raw_socket(stream, Role::Server, Some(upgrade::ws_config())).await;
    Ok((ws, exporter))
}

async fn connection(shared: Arc<Shared>, acceptor: TlsAcceptor, tcp: TcpStream, ip: IpKey) {
    let wait = Duration::from_millis(shared.limits.upgrade_wait_ms());
    let upgraded = tokio::time::timeout(wait, handshake(&shared, acceptor, tcp)).await;
    upgrade_done(&shared, ip);
    let Ok(Ok((ws, exporter))) = upgraded else {
        return;
    };
    let (sink, stream) = ws.split();
    let (tx, rx) = mpsc::unbounded_channel();
    let queue = Arc::new(Semaphore::new(shared.limits.queue_bytes() as usize));
    let stop = Arc::new(Notify::new());
    let conn = {
        let mut guard = shared.core.lock().expect("core");
        let core = &mut *guard;
        let conn = ConnId(core.next_conn);
        core.next_conn += 1;
        core.conns.insert(
            conn,
            ConnHandle {
                tx,
                queue: queue.clone(),
                peer: None,
                stop: stop.clone(),
            },
        );
        let now = shared.now();
        let outs = core.relay.open(conn, ip, exporter, now, &mut core.rng);
        shared.execute(core, outs, None);
        conn
    };
    let writer = tokio::spawn(writer(shared.clone(), sink, rx, queue));
    reader(&shared, conn, stream, stop).await;
    {
        let mut guard = shared.core.lock().expect("core");
        let core = &mut *guard;
        if core.conns.contains_key(&conn) {
            let now = shared.now();
            let outs = core.relay.closed(conn, now, &mut core.rng);
            core.conns.remove(&conn);
            shared.execute(core, outs, None);
        }
    }
    let _ = writer.await;
}

async fn reader(shared: &Shared, conn: ConnId, mut stream: SplitStream<Ws>, stop: Arc<Notify>) {
    loop {
        let next = tokio::select! {
            _ = stop.notified() => return,
            next = stream.next() => next,
        };
        let close_with = match next {
            Some(Ok(Message::Binary(bytes))) => {
                on_message(shared, conn, bytes.to_vec()).await;
                continue;
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
            Some(Ok(Message::Text(_))) => Some(1003),
            Some(Err(tungstenite::Error::Capacity(_))) => Some(1009),
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => None,
        };
        // A text or oversized message: the relay closes it itself, then
        // treats it as closed by the client (relay.md 2, 4.3).
        let mut guard = shared.core.lock().expect("core");
        let core = &mut *guard;
        if let Some(code) = close_with {
            if let Some(h) = core.conns.get(&conn) {
                let _ = h.tx.send(Cmd::Close(code));
            }
        }
        if core.conns.remove(&conn).is_some() {
            let now = shared.now();
            let outs = core.relay.closed(conn, now, &mut core.rng);
            shared.execute(core, outs, None);
        }
        return;
    }
}

async fn on_message(shared: &Shared, conn: ConnId, bytes: Vec<u8>) {
    // A spliced leg forwards; take queue room on the other leg first, so a
    // slow reader stops this one (TCP pushes back on the sender).
    let peer_queue = {
        let core = shared.core.lock().expect("core");
        core.conns
            .get(&conn)
            .and_then(|h| h.peer)
            .and_then(|(peer, _)| core.conns.get(&peer).map(|p| p.queue.clone()))
    };
    let Some(queue) = peer_queue else {
        let mut guard = shared.core.lock().expect("core");
        let core = &mut *guard;
        if !core.conns.contains_key(&conn) {
            return;
        }
        let now = shared.now();
        let outs = core.relay.receive(conn, &bytes, now, &mut core.rng);
        #[cfg(mousse_control = "relay-persist-allow-set")]
        let outs = core.control.after_receive(
            &shared.state,
            conn,
            &bytes,
            outs,
            now,
            &mut core.relay,
            &mut core.rng,
        );
        shared.execute(core, outs, None);
        return;
    };
    let want = bytes.len().min(shared.limits.queue_bytes() as usize).max(1);
    let permits = match queue.acquire_many(want as u32).await {
        Ok(p) => {
            p.forget();
            want
        }
        Err(_) => 0,
    };
    let mut guard = shared.core.lock().expect("core");
    let core = &mut *guard;
    if !core.conns.contains_key(&conn) {
        queue.add_permits(permits);
        return;
    }
    marker_tap(&bytes);
    let now = shared.now();
    let len = bytes.len();
    let outs = core.relay.data(conn, len, now, &mut core.rng);
    let forwarded = outs.iter().any(|o| matches!(o, Output::Forward { .. }));
    if !forwarded {
        queue.add_permits(permits);
    }
    shared.execute(core, outs, Some((bytes, permits)));
}

/// The relay's view of spliced bytes. Release builds do nothing here; the
/// memory positive control of `phase3.marker` copies them into the heap.
#[inline]
fn marker_tap(_bytes: &[u8]) {
    #[cfg(mousse_control = "marker-in-relay-memory")]
    crate::control::keep_in_memory(_bytes);
}

async fn writer(
    shared: Arc<Shared>,
    mut sink: SplitSink<Ws, Message>,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    queue: Arc<Semaphore>,
) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            Cmd::Send {
                bytes,
                class,
                permits,
            } => {
                shared.egress.take(bytes.len(), class).await;
                let sent = sink.send(Message::Binary(bytes.into())).await;
                queue.add_permits(permits);
                if sent.is_err() {
                    break;
                }
            }
            Cmd::Close(code) => {
                let frame = CloseFrame {
                    code: CloseCode::from(code),
                    reason: "".into(),
                };
                let _ = tokio::time::timeout(
                    Duration::from_secs(2),
                    sink.send(Message::Close(Some(frame))),
                )
                .await;
                let _ = tokio::time::timeout(Duration::from_secs(2), sink.close()).await;
                break;
            }
        }
    }
}

/// Fire the machine's waits when they are due.
async fn timer(shared: Arc<Shared>) {
    loop {
        let next = {
            let core = shared.core.lock().expect("core");
            core.relay.next_wake()
        };
        // Wall-clock times (join expiries, key drops) need a tick at least
        // once a second.
        let cap = shared.epoch.elapsed() + Duration::from_secs(1);
        let at = next
            .map(|m| Duration::from_millis(m.0))
            .unwrap_or(cap)
            .min(cap);
        tokio::select! {
            _ = tokio::time::sleep_until(shared.epoch + at) => {
                let mut guard = shared.core.lock().expect("core");
                let core = &mut *guard;
                let now = shared.now();
                let outs = core.relay.tick(now, &mut core.rng);
                shared.execute(core, outs, None);
            }
            _ = shared.wake.notified() => {}
        }
    }
}

/// Pick up `revoke` and `enroll` from the state directory.
async fn poll_state(shared: Arc<Shared>) {
    let every = Duration::from_millis(shared.limits.state_poll_ms());
    loop {
        tokio::time::sleep(every).await;
        shared.reload();
    }
}
