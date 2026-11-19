//! The running relay: TLS and WebSocket on each connection, the core
//! admission machine behind one lock, a timer that fires its waits on time,
//! splicing with per-circuit queues and the shared egress ceiling, and the
//! state directory for the authorized list and enrollment codes.
//!
//! In hosted mode (`docs/phase34-design.md` §B.10) the machine also holds
//! the boot's leases: the boot generation is written before the relay
//! serves, the Plus link announces the boot and sends reports in the
//! background, a spliced leg waits while its class is paused or its rate
//! bucket is short, the pinned issuer keys are read again with the state
//! directory (and at once on `SIGHUP`), and a stop waits for the stopping
//! snapshot before the connections close.
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
use mousse_net_core::relay_hosted::{BootRecord, Hosted};
use mousse_net_core::time::{Millis, UnixTime};
use mousse_relay_plus::http::PlusHttp;
use mousse_relay_plus::link::{self as plus_link, HostedCell, PlusLink};
use mousse_relay_plus::settings::HostedSettings;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch, Notify, Semaphore};
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

type Ws = WebSocketStream<BufReader<Box<dyn crate::Io>>>;

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
    /// Hosted: told when this paused leg may try its message again.
    resume: Arc<Notify>,
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
    /// Hosted: the Plus link's wake, when a lease became final.
    report_wake: Notify,
    /// Hosted: the issuer keys file as last read.
    issuer_keys: Mutex<Option<String>>,
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
    /// Hosted mode, or `None` for a self-hosted relay. One mode per process.
    pub hosted: Option<HostedConfig>,
}

/// Hosted mode's settings.
#[derive(Clone, Debug)]
pub struct HostedConfig {
    /// `MOUSSE_NET_RELAY_PLUS_URL` and the hosted limits.
    pub settings: HostedSettings,
    /// The build id in the boot record.
    pub build_id: String,
}

/// The pinned issuer keys file in the state directory.
pub const ISSUER_KEYS_FILE: &str = "issuer-keys";

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
                Output::Resume { conn } => {
                    if let Some(h) = core.conns.get(&conn) {
                        h.resume.notify_one();
                    }
                }
                // The leg's reader acts on these itself (`on_message`).
                Output::Hold { .. } | Output::Pause { .. } => {}
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
        if core
            .relay
            .hosted_mut()
            .is_some_and(|h| h.take_report_wake())
        {
            self.report_wake.notify_one();
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
        self.reload_issuer_keys(core);
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

impl Shared {
    /// Hosted: read the issuer keys file again; a change takes effect
    /// without ending the boot. A file that does not parse leaves the keys
    /// in force.
    fn reload_issuer_keys(&self, core: &mut Core) {
        let Some(h) = core.relay.hosted_mut() else {
            return;
        };
        let path = self.state.path().join(ISSUER_KEYS_FILE);
        let Ok(text) = std::fs::read_to_string(&path) else {
            return;
        };
        let mut last = self.issuer_keys.lock().expect("issuer keys");
        if last.as_deref() == Some(text.as_str()) {
            return;
        }
        match mousse_relay_plus::issuers::parse(&text) {
            Ok(keys) => {
                h.set_issuer_keys(keys);
                eprintln!("mousse-relay: issuer keys reloaded");
            }
            Err(e) => eprintln!("mousse-relay: issuer keys not reloaded: {e}"),
        }
        *last = Some(text);
    }
}

impl HostedCell for Shared {
    fn with_hosted<R>(&self, f: impl FnOnce(&mut Hosted, Now) -> R) -> R {
        let now = self.now();
        let r = {
            let mut core = self.core.lock().expect("core");
            f(core.relay.hosted_mut().expect("hosted mode"), now)
        };
        // Events the call queued (statuses of settled leases) go out on the
        // next timer turn.
        self.wake.notify_one();
        r
    }

    fn report_wake(&self) -> &Notify {
        &self.report_wake
    }

    fn now(&self) -> Now {
        Shared::now(self)
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
    #[cfg(mousse_control = "marker-in-relay-memory")]
    crate::control::keep_marker_in_memory();
    let lock = config.state.lock_process().map_err(|e| e.to_string())?;
    let identity = config.state.identity().map_err(|e| e.to_string())?;
    let lists = config.state.read().map_err(|e: StateError| e.to_string())?;
    let relay_key = identity.public_key();
    let relay_id = RelayId::of(&relay_key);
    let mut boot_id = [0u8; 16];
    rand_core::Rng::fill_bytes(&mut os_rng(), &mut boot_id);
    let relay_config = RelayConfig {
        relay_key,
        boot_id,
        limits: config.limits,
    };
    // Hosted: the boot generation is durable before the relay serves
    // (§A.9 duty 1), under the process lock taken above.
    let (relay, plus, issuer_text) = match &config.hosted {
        None => (
            Relay::new(relay_config, &lists.authorized, &lists.codes),
            None,
            None,
        ),
        Some(h) => {
            let dir = config.state.path();
            let generation = mousse_relay_plus::state::next_boot_generation(dir)
                .map_err(|e| format!("boot generation: {e}"))?;
            let report_key = mousse_relay_plus::state::report_key(dir)
                .map_err(|e| format!("report key: {e}"))?;
            let keys_path = dir.join(ISSUER_KEYS_FILE);
            let issuer_text = std::fs::read_to_string(&keys_path)
                .map_err(|e| format!("{}: {e}", keys_path.display()))?;
            let keys = mousse_relay_plus::issuers::parse(&issuer_text)
                .map_err(|e| format!("{}: {e}", keys_path.display()))?;
            let limits = h.settings.limits;
            let http = PlusHttp::new(
                h.settings.plus_url.clone(),
                Duration::from_millis(limits.plus_timeout_ms()),
                limits.plus_answer_max_bytes() as usize,
            )?;
            let started_at = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let link = PlusLink {
                http,
                report_key,
                boot: BootRecord {
                    relay_id: relay_id.0,
                    boot_id,
                    started_at,
                    build_id: h.build_id.clone(),
                    generation,
                },
                log: Arc::new(|l: &str| eprintln!("mousse-relay: {l}")),
            };
            let hosted = Hosted::new(relay_id.0, boot_id, keys, limits);
            (
                Relay::new_hosted(relay_config, hosted),
                Some(link),
                Some(issuer_text),
            )
        }
    };
    let acceptor = TlsAcceptor::from(tls::server_config(identity));
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", config.listen))?;
    let local_addr = listener.local_addr().map_err(|e| e.to_string())?;
    let shared = Arc::new(Shared {
        core: Mutex::new(Core {
            relay,
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
        report_wake: Notify::new(),
        issuer_keys: Mutex::new(issuer_text),
    });
    let (stop_tx, stop_rx) = oneshot::channel();
    let final_wait = config.hosted.as_ref().map(|h| {
        let l = h.settings.limits;
        Duration::from_millis(l.final_report_wait_ms() + l.plus_timeout_ms())
    });
    let task = tokio::spawn(serve(
        shared, listener, acceptor, stop_rx, lock, plus, final_wait,
    ));
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
    plus: Option<PlusLink>,
    final_wait: Option<Duration>,
) -> Result<(), String> {
    let timer = tokio::spawn(timer(shared.clone()));
    let poll = tokio::spawn(poll_state(shared.clone()));
    let hangup = tokio::spawn(reload_on_hangup(shared.clone()));
    // Hosted: the boot announcement and reports run in the background.
    let (plus_stop, plus_stop_rx) = watch::channel(false);
    let mut plus_task =
        plus.map(|link| tokio::spawn(plus_link::run(shared.clone(), link, plus_stop_rx)));
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
    drop(listener);
    // Hosted: forward nothing more, make every lease final, and wait for the
    // stopping snapshot (§A.9 duty 11).
    if let Some(task) = plus_task.take() {
        {
            let mut guard = shared.core.lock().expect("core");
            let core = &mut *guard;
            let now = shared.now();
            let outs = core.relay.begin_stop(now);
            shared.execute(core, outs, None);
        }
        let _ = plus_stop.send(true);
        let wait = final_wait.unwrap_or_default() + Duration::from_millis(500);
        let _ = tokio::time::timeout(wait, task).await;
    }
    timer.abort();
    poll.abort();
    hangup.abort();
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
    let (io, exporter) = outer_tls(acceptor, tcp).await?;
    let mut stream = BufReader::new(io);
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
    let resume = Arc::new(Notify::new());
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
                resume: resume.clone(),
            },
        );
        let now = shared.now();
        let outs = core.relay.open(conn, ip, exporter, now, &mut core.rng);
        shared.execute(core, outs, None);
        conn
    };
    let writer = tokio::spawn(writer(shared.clone(), sink, rx, queue));
    reader(&shared, conn, stream, stop, resume).await;
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

async fn reader(
    shared: &Shared,
    conn: ConnId,
    mut stream: SplitStream<Ws>,
    stop: Arc<Notify>,
    resume: Arc<Notify>,
) {
    loop {
        let next = tokio::select! {
            _ = stop.notified() => return,
            next = stream.next() => next,
        };
        let close_with = match next {
            Some(Ok(Message::Binary(bytes))) => {
                if !on_message(shared, conn, bytes.to_vec(), &stop, &resume).await {
                    return;
                }
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

/// Handle one message from `conn`. Returns false once the relay closed
/// the connection while the message waited.
async fn on_message(
    shared: &Shared,
    conn: ConnId,
    bytes: Vec<u8>,
    stop: &Notify,
    resume: &Notify,
) -> bool {
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
            return true;
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
        return true;
    };
    let want = bytes.len().min(shared.limits.queue_bytes() as usize).max(1);
    let permits = match queue.acquire_many(want as u32).await {
        Ok(p) => {
            p.forget();
            want
        }
        Err(_) => 0,
    };
    marker_tap(&bytes);
    let mut bytes = Some(bytes);
    loop {
        // Hosted: the message may have to wait for its rate bucket or a
        // lease; nothing more is read from this leg meanwhile, so TCP
        // pushes back on the sender.
        let wait = {
            let mut guard = shared.core.lock().expect("core");
            let core = &mut *guard;
            if !core.conns.contains_key(&conn) {
                queue.add_permits(permits);
                return false;
            }
            let now = shared.now();
            let len = bytes.as_ref().map_or(0, Vec::len);
            let outs = core.relay.data(conn, len, now, &mut core.rng);
            let forwarded = outs.iter().any(|o| matches!(o, Output::Forward { .. }));
            let wait = outs.iter().find_map(|o| match o {
                Output::Hold { conn: c, until } if *c == conn => Some(Some(*until)),
                Output::Pause { conn: c } if *c == conn => Some(None),
                _ => None,
            });
            let payload = if forwarded {
                bytes.take().map(|b| (b, permits))
            } else {
                None
            };
            if !forwarded && wait.is_none() {
                queue.add_permits(permits);
            }
            shared.execute(core, outs, payload);
            match wait {
                Some(w) => w,
                None => return true,
            }
        };
        let sleep = async {
            match wait {
                Some(until) => {
                    let now = shared.now().mono;
                    tokio::time::sleep(Duration::from_millis(until.since(now))).await
                }
                None => resume.notified().await,
            }
        };
        tokio::select! {
            _ = sleep => {}
            _ = stop.notified() => {
                queue.add_permits(permits);
                return false;
            }
        }
    }
}

/// The outer TLS of a new connection, and its exporter.
#[cfg(not(mousse_control = "marker-in-splice"))]
async fn outer_tls(
    acceptor: TlsAcceptor,
    tcp: TcpStream,
) -> Result<(Box<dyn crate::Io>, [u8; 32]), String> {
    let tls: TlsStream<TcpStream> = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
    tls::check(tls.get_ref().1, false)?;
    let exporter = tls::exporter(tls.get_ref().1).map_err(|e| e.to_string())?;
    Ok((Box::new(tls), exporter))
}

/// `marker-in-splice` (`phase3.marker`, packet positive control): the
/// relay runs without outer TLS, so a packet capture sees what it forwards.
#[cfg(mousse_control = "marker-in-splice")]
async fn outer_tls(
    _acceptor: TlsAcceptor,
    tcp: TcpStream,
) -> Result<(Box<dyn crate::Io>, [u8; 32]), String> {
    Ok((Box::new(tcp), [0; 32]))
}

/// The relay's view of spliced bytes. Release builds do nothing here. A
/// debug build writes them to the file named by `MOUSSE_RELAY_TAP`, the
/// "debug relay tap" of `phase3.marker`.
#[inline]
fn marker_tap(_bytes: &[u8]) {
    #[cfg(debug_assertions)]
    crate::control::tap(_bytes);
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
            let hosted = core.relay.next_hosted_wake(shared.now());
            match (core.relay.next_wake(), hosted) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            }
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

/// Read the state directory again at once on `SIGHUP` (`reload`).
async fn reload_on_hangup(shared: Arc<Shared>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let Ok(mut hup) = signal(SignalKind::hangup()) else {
            return;
        };
        while hup.recv().await.is_some() {
            shared.reload();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = shared;
        std::future::pending::<()>().await;
    }
}

/// Pick up `revoke` and `enroll` (and, hosted, the issuer keys) from the
/// state directory.
async fn poll_state(shared: Arc<Shared>) {
    let every = Duration::from_millis(shared.limits.state_poll_ms());
    loop {
        tokio::time::sleep(every).await;
        shared.reload();
    }
}
