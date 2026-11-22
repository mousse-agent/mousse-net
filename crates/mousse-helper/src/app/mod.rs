//! `serve --app`: the channel to the Mousse app on stdin and stdout
//! (Phase 1a §1 and §2).
//!
//! - **Framing** ([`frame`]): JSON, DATA and CREDIT frames. A malformed
//!   frame closes the channel and the helper exits.
//! - **Handles.** Every stream gets a handle that is unique for the life of
//!   this process and never reused, bound to one connection and one wire
//!   stream. Wire stream ids restart on every connection, so two
//!   connections can use the same one at once; handles never collide.
//!   Connection numbers are never reused either, so a reconnect is a new
//!   number (its generation). DATA, CREDIT and `stream.reset` name only
//!   handles; a frame for an unknown or ended handle is dropped and counted.
//! - **Pumps.** Reading stdin never waits on writing stdout or on the
//!   engine: each stream has its own pump each way.
//! - **Writer order** ([`out`]): control (JSON, then CREDIT), then
//!   interactive DATA, then bulk DATA, streams taking turns in a class. FIN
//!   is a flag on a DATA frame in the stream's own queue.
//! - **Credit, app to engine** ([`budget`]): the helper grants the app
//!   credit from one budget, at most `APP_STREAM_CREDIT_BYTES` a stream,
//!   with `APP_CREDIT_INTERACTIVE_RESERVE_BYTES` kept for interactive
//!   streams. It returns once the engine has taken the bytes. Data beyond
//!   credit is malformed.
//! - **Credit, engine to app (read-ahead).** Reading an engine stream
//!   returns wire credit to the peer at once, so the helper reads a stream
//!   only while the app's credit covers what it has buffered plus
//!   `APP_READ_AHEAD_BYTES`. When the app stalls, the remote writer stalls.
//! - **Exit.** On stdin EOF the helper sends `GOAWAY NO_ERROR` on every
//!   connection and exits.
//!
//! Requests are `{"id", "op", ...}`; replies `{"re", ...}` or
//! `{"re", "error", "reason"}`; events `{"ev", ...}`.

mod budget;
mod changes;
mod engine_ops;
mod frame;
mod out;
mod pairing;
mod paths;
mod relay;
mod relay_store;
mod routes;

pub use changes::{clock, interface_ips, interface_source};
pub use paths::{browse_source, StoreCandidates};
pub(crate) use relay::dial_join_route;

/// Whether a stored role (a peer record's) is `owner`.
pub fn role_is_owner(stored: &str) -> bool {
    engine_ops::is_owner(stored)
}

pub(crate) use paths::{stored_search, ticket_candidates};

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::PriorityClass;
use mousse_net_core::{ErrorCode, BOTH_WAYS_MIN_MINOR};
use mousse_net_io::pipe::RouteKind;
use mousse_net_io::store::{hex, short_id};
use mousse_net_io::{
    Caller, CloseReason, Connection, Host, HostEvent, ListenerKind, MuxStream, NetError,
    RouteClass, StreamAdmission, StreamReader, StreamWriter,
};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch, Notify};

use self::budget::Budget;
use self::frame::Frame;
use self::out::{Meta, Out};
use crate::applog;
use crate::engine::{Engine, ENGINE_PREFIX};
use crate::limits::HelperLimits;
use crate::revoke::Removal;

/// The protocol this helper speaks: 1.2 (`docs/pairing-flow-design.md` §1),
/// which serves 1.1 and 1.0 apps too.
const PROTO: (u64, u64) = (1, 2);

/// What this helper implements beyond 1.1, listed in the `hello` reply of a
/// 1.2 channel. An older helper ignores a field it does not know, so an app
/// reads this list before it sends one.
pub const FEATURES: &[&str] = &["grant-revoke-local"];

/// The stream labels an inbound connection passes on to the app (§3.2).
pub const LABELS: [&str; 6] = [
    "mousse.hello",
    "mousse.rpc",
    "mousse.sub",
    "mousse.blob",
    "mousse.put",
    // One editor tunnel (Phase 1b §9.2).
    "mousse.tunnel",
];

/// What the app learns in the `hello` reply.
pub struct AppInfo {
    pub identity: IdentityPublicKey,
    /// The device name `PAIRED` and joins send until `config.set` (or
    /// `hello`) names another.
    pub name: String,
    pub profile: String,
    pub port: u16,
    /// The loopback ws listener's port, while it runs (Phase 1b §4.1).
    pub ws_port: Option<u16>,
    /// What the listener serves now (Phase 1b §1.5): the routes tickets
    /// carry, the unbound addresses and the routes config in effect.
    pub listen: crate::serve::SharedListen,
    pub state_dir: PathBuf,
    /// Where to look for paired hosts that moved (Phase 1a §6).
    pub browse: Option<Arc<mousse_net_io::discovery::CachedBrowse>>,
    /// The identity key, to sign this host's manifest.
    pub signer: mousse_net_io::SharedSigner,
    /// The endpoint id and where its identity is kept: the relay seed is
    /// kept the same way.
    pub endpoint_id: String,
    pub key_storage: mousse_net_io::keystore::KeyStorage,
    /// Debug builds with `MOUSSE_HELPER_MANUAL_CLOCK=1`: the clock
    /// `test.clock` moves.
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub manual_clock: Option<Arc<mousse_net_io::ManualClock>>,
    /// SSH routes (Phase 1b §3), shared with the caller's `ssh` tier.
    pub ssh: Arc<crate::ssh::Ssh>,
}

/// Why the channel ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum End {
    /// stdin closed: the app exited or crashed.
    Eof,
    /// The app asked for `shutdown`.
    Shutdown,
    /// A malformed frame, or data beyond credit.
    Malformed(String),
    /// The app stopped reading: its control queue passed its limit.
    Stuck,
}

impl End {
    /// The error `serve` exits with, if any.
    pub fn error(&self) -> Option<String> {
        match self {
            End::Eof | End::Shutdown => None,
            End::Malformed(why) => Some(format!("app channel: {why}")),
            End::Stuck => Some(
                "app channel: the app stopped reading (APP_CONTROL_QUEUE_BYTES reached)".into(),
            ),
        }
    }
}

/// One app channel.
#[derive(Clone)]
pub struct App {
    shared: Arc<Shared>,
}

struct Shared {
    core: Mutex<Core>,
    wake_writer: Notify,
    ended: watch::Sender<Option<End>>,
    caller: Arc<Caller>,
    host: Host,
    removal: Arc<Removal>,
    admission: Arc<StreamAdmission>,
    pairing: Mutex<pairing::State>,
    keep: paths::Keep,
    relay: relay::State,
    /// SSH routes: `ssh.*` and the connection window (Phase 1b §3).
    ssh: Arc<crate::ssh::Ssh>,
    info: AppInfo,
    limits: HelperLimits,
    engine: Arc<Engine>,
}

/// One chunk from the app for the engine.
struct Chunk {
    bytes: Vec<u8>,
    fin: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rx {
    Open,
    /// FIN is queued for the app.
    FinQueued,
    /// FIN was written.
    Done,
}

struct ConnEntry {
    conn: Arc<Connection>,
    identity: IdentityPublicKey,
    inbound: bool,
    /// An outbound path the caller holds as its host's candidate, not yet
    /// reopened: announced by `path.reopen` (a renewal) or by `conn.up`
    /// while another path to the host was up (a dial). The only handles
    /// `path.reopened` accepts.
    reopen: bool,
    /// Inbound: the caller has opened a stream, so the host may open one.
    caller_opened: bool,
    /// Outbound through a relay: the route, for its bulk companion.
    via: Option<mousse_net_core::relay_endpoint::RelayRoute>,
}

struct StreamEntry {
    conn: u64,
    class: PriorityClass,
    writer: StreamWriter,
    /// The app accepted it (always, for a stream it opened).
    accepted: bool,
    // Engine to app.
    rx: Rx,
    /// Credit the app granted and the helper has not used.
    rx_credit: u64,
    /// Read from the engine, queued for the app.
    rx_buffered: u64,
    wake: Arc<Notify>,
    // App to engine.
    tx: Option<mpsc::UnboundedSender<Chunk>>,
    /// Credit granted to the app that it has not used.
    tx_credit: u64,
    /// Credit granted and not yet taken by the engine (held from the
    /// budget).
    tx_window: u64,
    tx_done: bool,
    /// A stream the host opened on this computer's own connection to it
    /// (minor 3): the grant of this computer's it is served under. It is
    /// reset when that grant stops being live.
    served: Option<u64>,
}

struct Core {
    hello: bool,
    out: Out,
    budget: Budget,
    conns: HashMap<u64, ConnEntry>,
    streams: BTreeMap<u32, StreamEntry>,
    next_conn: u64,
    next_handle: u32,
    /// The last stream granted credit, per class (streams take turns).
    turn: [u32; 2],
    dropped: u64,
    buffered: u64,
    peak_buffered: u64,
    /// Shutdown: end once everything queued is written.
    ending: Option<End>,
    /// Per peer, how often `peer.forget` removed it. A dial or a renewal
    /// reads it before it starts and publishes its path only if it has not
    /// changed, so no path to a forgotten peer comes up after the forget.
    peer_gen: HashMap<IdentityPublicKey, u64>,
}

/// Why a connection that finished opening was closed instead of published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stale {
    /// Networking paused meanwhile.
    Paused,
    /// Its peer was forgotten meanwhile.
    Forgotten,
}

fn lock(core: &Mutex<Core>) -> MutexGuard<'_, Core> {
    core.lock().unwrap_or_else(|e| e.into_inner())
}

fn class_name(class: PriorityClass) -> &'static str {
    match class {
        PriorityClass::Interactive => "interactive",
        PriorityClass::Bulk => "bulk",
    }
}

fn close_word(reason: &CloseReason) -> String {
    match reason {
        CloseReason::Local(code) | CloseReason::Peer(code) => code.name().into(),
        CloseReason::PipeClosed => "connection_dropped".into(),
        CloseReason::Io(_) => "io_error".into(),
    }
}

fn error_code(name: &str) -> ErrorCode {
    ErrorCode::ALL
        .iter()
        .copied()
        .find(|c| c.name() == name)
        .unwrap_or(ErrorCode::Cancelled)
}

fn error(id: &Value, error: &str, reason: impl Into<String>) -> Value {
    json!({"re": id, "error": error, "reason": reason.into()})
}

impl App {
    /// Start the channel on stdin and stdout.
    pub fn start(
        host: Host,
        caller: Arc<Caller>,
        removal: Arc<Removal>,
        info: AppInfo,
        engine: Arc<Engine>,
        mut engine_events: mpsc::UnboundedReceiver<Value>,
    ) -> Self {
        let limits = *crate::limits::helper();
        let (ended, _) = watch::channel(None);
        let shared = Arc::new(Shared {
            core: Mutex::new(Core {
                hello: false,
                out: Out::default(),
                budget: Budget::new(
                    limits.app_credit_budget_bytes(),
                    limits.app_credit_interactive_reserve_bytes(),
                ),
                conns: HashMap::new(),
                streams: BTreeMap::new(),
                next_conn: 1,
                next_handle: 1,
                turn: [0, 0],
                dropped: 0,
                buffered: 0,
                peak_buffered: 0,
                ending: None,
                peer_gen: HashMap::new(),
            }),
            wake_writer: Notify::new(),
            ended,
            admission: host.stream_admission(),
            caller,
            host,
            removal,
            pairing: Mutex::new(pairing::State::new(info.name.clone())),
            keep: paths::Keep::default(),
            relay: relay::State::new(&info),
            ssh: info.ssh.clone(),
            info,
            limits,
            engine,
        });
        tokio::spawn(read_stdin(shared.clone()));
        tokio::spawn(write_stdout(shared.clone()));
        tokio::spawn(pairing::watch_pause(shared.clone()));
        tokio::spawn(pairing::prune_completions(shared.clone()));
        tokio::spawn(paths::keep_connected(shared.clone()));
        tokio::spawn(changes::forward_renewals(shared.clone()));
        tokio::spawn(watch_served(shared.clone()));
        // Phase 4's mailbox reads pair secrets and the manifest from here.
        shared
            .engine
            .set_pairs(Arc::new(relay::Pairs(Arc::downgrade(&shared))));
        tokio::spawn(relay::run(shared.clone()));
        tokio::spawn(relay::hosted::run(shared.clone()));
        let events_to = shared.clone();
        tokio::spawn(async move {
            while let Some(event) = engine_events.recv().await {
                events_to.event(event);
            }
        });
        Self { shared }
    }

    /// Wait until the channel ends.
    pub async fn ended(&self) -> End {
        let mut rx = self.shared.ended.subscribe();
        let end = match rx.wait_for(Option::is_some).await {
            Ok(end) => end.clone(),
            Err(_) => None,
        };
        end.unwrap_or(End::Eof)
    }

    /// An inbound connection that came over a `kind` listener from
    /// `from` to the listener's address `local`: announced once it is live,
    /// with its route. Returns its number.
    pub async fn inbound(
        &self,
        conn: Connection,
        kind: RouteKind,
        from: Option<std::net::SocketAddr>,
        local: Option<std::net::SocketAddr>,
    ) -> Option<u64> {
        let class = match (kind, from) {
            (RouteKind::Tcp, Some(from)) => RouteClass::of_tcp(
                self.shared
                    .caller
                    .addr_policy()
                    .class_of_inbound(from, local),
            ),
            (RouteKind::Ssh, _) => RouteClass::Ssh,
            _ => RouteClass::Tunnel,
        };
        let route = json!({"kind": kind.name(), "class": class.name()});
        self.inbound_on(conn, route).await
    }

    /// An inbound connection on `route` (as `conn.up` shows it): announced
    /// once it is live. Returns its number.
    pub async fn inbound_on(&self, conn: Connection, route: Value) -> Option<u64> {
        let peer = short_id(conn.peer());
        // Must-fail control: announce the connection before step 2 settles.
        let wait_for_live = !cfg!(mousse_control = "inbound-before-live");
        if wait_for_live && !conn.settled(true).await.is_live() {
            applog::line(format!("refused {peer}: not live"));
            return None;
        }
        let grant = self.shared.host.grant_of(conn.id());
        let mut fields = json!({"dir": "in", "route": route});
        if let Some(g) = &grant {
            fields["grant"] = json!(g.id.0);
            fields["role"] = json!(g.role.as_str());
        }
        let no = self.shared.add_conn(conn, true, fields).ok()?;
        applog::line(format!("connected {peer} (in)"));
        Some(no)
    }

    /// Close inbound connection `no` when the socket that accepted it
    /// closes (`closing` turns true or its sender goes).
    pub fn close_with_socket(&self, no: u64, mut closing: tokio::sync::watch::Receiver<bool>) {
        let Some(conn) = lock(&self.shared.core)
            .conns
            .get(&no)
            .map(|e| e.conn.clone())
        else {
            return;
        };
        tokio::spawn(async move {
            tokio::select! {
                _ = closing.wait_for(|closed| *closed) => conn.close(ErrorCode::Cancelled),
                _ = conn.closed() => {}
            }
        });
    }

    /// The network changed (an interface, or a wake): check every
    /// connection and redial what is down.
    pub fn net_change(&self, change: mousse_net_io::watch::NetChange) {
        tokio::spawn(changes::on_change(self.shared.clone(), change));
    }

    /// An event from the host: pairing, grants, the grant store.
    pub fn host_event(&self, event: HostEvent) {
        pairing::host_event(&self.shared, event);
    }

    /// Close every connection the channel opened (the host closes its own).
    pub fn close_all(&self) {
        let core = lock(&self.shared.core);
        for entry in core.conns.values() {
            entry.conn.close(ErrorCode::NoError);
        }
    }
}

impl Shared {
    fn end(&self, end: End) {
        self.ended.send_if_modified(|v| {
            if v.is_none() {
                *v = Some(end);
                true
            } else {
                false
            }
        });
    }

    /// Wake the writer, and end the channel if the app stopped reading.
    fn queued(&self, core: &Core) {
        self.wake_writer.notify_one();
        if core.out.control_bytes() as u64 > self.limits.app_control_queue_bytes() {
            self.end(End::Stuck);
        }
    }

    fn reply(&self, core: &mut Core, value: Value) {
        core.out.json(&value);
        self.queued(core);
    }

    /// Queue an event for the app.
    fn event(&self, value: Value) {
        let mut core = lock(&self.core);
        core.out.json(&value);
        self.queued(&core);
    }

    /// Publish a connection: `conn.up`. While networking is paused it is
    /// closed instead.
    fn add_conn(
        self: &Arc<Self>,
        conn: Connection,
        inbound: bool,
        fields: Value,
    ) -> Result<u64, Stale> {
        self.publish(conn, inbound, None, fields)
    }

    /// The generation of `pin` (see `Core::peer_gen`).
    fn peer_gen(&self, pin: &IdentityPublicKey) -> u64 {
        lock(&self.core).peer_gen.get(pin).copied().unwrap_or(0)
    }

    /// Publish an outbound path to a peer whose generation was `gen` when
    /// the work that opened it started. If the peer was forgotten since,
    /// the path is closed instead and `None` is returned.
    fn add_outbound(
        self: &Arc<Self>,
        conn: Connection,
        gen: u64,
        fields: Value,
    ) -> Result<u64, Stale> {
        self.publish(conn, false, Some(gen), fields)
    }

    /// Note that outbound connection `no` runs through a relay route.
    fn set_via(&self, no: u64, route: mousse_net_core::relay_endpoint::RelayRoute) {
        if let Some(entry) = lock(&self.core).conns.get_mut(&no) {
            entry.via = Some(route);
        }
    }

    fn publish(
        self: &Arc<Self>,
        conn: Connection,
        inbound: bool,
        gen: Option<u64>,
        mut fields: Value,
    ) -> Result<u64, Stale> {
        let identity = *conn.peer();
        let no = {
            let mut core = lock(&self.core);
            // Checked under the lock `watch_pause` closes connections
            // under: a pause either sees this connection or is seen here.
            if self.removal.is_paused() {
                drop(core);
                conn.close(ErrorCode::InternalError);
                applog::line(format!(
                    "closed a new path with {}: networking is paused",
                    short_id(&identity)
                ));
                return Err(Stale::Paused);
            }
            if let Some(gen) = gen {
                if core.peer_gen.get(&identity).copied().unwrap_or(0) != gen {
                    drop(core);
                    conn.close(ErrorCode::Cancelled);
                    applog::line(format!(
                        "closed a new path to {}: forgotten meanwhile",
                        short_id(&identity)
                    ));
                    return Err(Stale::Forgotten);
                }
            }
            // Under the core lock `path.reopened` takes, so the app can
            // reopen this path as soon as it sees `conn.up`.
            let reopen = !inbound && self.caller.is_reopening(&conn);
            let conn = Arc::new(conn);
            let no = core.next_conn;
            core.next_conn += 1;
            core.conns.insert(
                no,
                ConnEntry {
                    conn: conn.clone(),
                    identity,
                    inbound,
                    reopen,
                    caller_opened: false,
                    via: None,
                },
            );
            fields["ev"] = json!("conn.up");
            fields["conn"] = json!(no);
            fields["identity"] = json!(hex(identity.as_bytes()));
            fields["deadline"] = json!(conn.deadline().secs());
            // Minor 3: calls go both ways on this connection.
            fields["both"] = json!(both_ways(&conn));
            core.out.conn_event(no, &fields);
            self.queued(&core);
            tokio::spawn(conn_task(self.clone(), no, conn.clone(), inbound));
            if !inbound {
                let shared = self.clone();
                tokio::spawn(async move { relay::ensure_keys(&shared, &conn).await });
            }
            no
        };
        Ok(no)
    }

    /// The connection ended: its streams end with it (`conn.down` says so).
    fn conn_down(self: &Arc<Self>, no: u64, reason: &CloseReason) {
        let mut core = lock(&self.core);
        let Some(entry) = core.conns.remove(&no) else {
            return;
        };
        let handles: Vec<u32> = core
            .streams
            .iter()
            .filter(|(_, s)| s.conn == no)
            .map(|(h, _)| *h)
            .collect();
        for h in handles {
            drop_stream(&mut core, h);
        }
        core.regrant(&self.limits);
        let event = json!({
            "ev": "conn.down",
            "conn": no,
            "identity": hex(entry.identity.as_bytes()),
            "reason": close_word(reason),
        });
        core.out.conn_event(no, &event);
        self.queued(&core);
        drop(core);
        relay::conn_gone(self, no);
        if !entry.inbound {
            self.keep.kick(paths::Kick::Look);
            if entry.via.is_some() {
                let shared = self.clone();
                tokio::spawn(async move { relay::drop_companion(&shared, no).await });
            }
        }
        applog::line(format!("closed {}: {reason}", short_id(&entry.identity)));
    }

    /// A new stream on connection `no`. Returns its handle, or `None` if
    /// the connection is gone (the stream is reset).
    fn add_stream(
        self: &Arc<Self>,
        core: &mut Core,
        no: u64,
        stream: MuxStream,
        accepted: bool,
    ) -> Option<u32> {
        if !core.conns.contains_key(&no) || core.next_handle == u32::MAX {
            stream.writer.reset(ErrorCode::RefusedStream);
            return None;
        }
        let handle = core.next_handle;
        core.next_handle += 1;
        let class = stream.class();
        let (reader, writer) = stream.split();
        let (tx, rx) = mpsc::unbounded_channel();
        let wake = Arc::new(Notify::new());
        core.streams.insert(
            handle,
            StreamEntry {
                conn: no,
                class,
                writer: writer.clone(),
                accepted,
                rx: Rx::Open,
                rx_credit: 0,
                rx_buffered: 0,
                wake: wake.clone(),
                tx: Some(tx),
                tx_credit: 0,
                tx_window: 0,
                tx_done: false,
                served: None,
            },
        );
        tokio::spawn(rx_pump(self.clone(), handle, reader, wake));
        tokio::spawn(tx_pump(self.clone(), handle, writer, rx));
        Some(handle)
    }

    fn on_frame(self: &Arc<Self>, frame: Frame) -> Result<(), End> {
        match frame {
            Frame::Json(map) => {
                self.on_request(map);
                Ok(())
            }
            Frame::Data { handle, fin, bytes } => self.app_data(handle, fin, bytes),
            Frame::Credit { handle, bytes } => {
                let mut core = lock(&self.core);
                match core.streams.get_mut(&handle) {
                    Some(s) if s.rx != Rx::Done => {
                        s.rx_credit = s.rx_credit.saturating_add(u64::from(bytes));
                        s.wake.notify_one();
                    }
                    _ => core.dropped += 1,
                }
                Ok(())
            }
        }
    }

    /// Bytes (and maybe FIN) from the app for the engine.
    fn app_data(&self, handle: u32, fin: bool, bytes: Vec<u8>) -> Result<(), End> {
        let mut core = lock(&self.core);
        let core = &mut *core;
        let Some(s) = core.streams.get_mut(&handle) else {
            core.dropped += 1;
            return Ok(());
        };
        let Some(tx) = s.tx.as_ref() else {
            core.dropped += 1;
            return Ok(());
        };
        let n = bytes.len() as u64;
        if n > s.tx_credit {
            return Err(End::Malformed(format!(
                "{n} bytes on handle {handle} with {} bytes of credit",
                s.tx_credit
            )));
        }
        s.tx_credit -= n;
        if !fin {
            if n > 0 {
                let _ = tx.send(Chunk { bytes, fin: false });
            }
            return Ok(());
        }
        #[cfg(mousse_control = "fin-overtakes")]
        {
            s.writer.finish();
            let _ = tx.send(Chunk { bytes, fin: false });
        }
        #[cfg(not(mousse_control = "fin-overtakes"))]
        let _ = tx.send(Chunk { bytes, fin: true });
        // Nothing more comes this way: unused credit goes back.
        s.tx = None;
        let unused = s.tx_credit;
        s.tx_credit = 0;
        s.tx_window -= unused;
        let class = s.class;
        core.out.take_credit(handle);
        core.budget.give_back(class, unused);
        core.regrant(&self.limits);
        self.wake_writer.notify_one();
        Ok(())
    }

    fn on_request(self: &Arc<Self>, map: Map<String, Value>) {
        let id = map.get("id").cloned().unwrap_or(Value::Null);
        let op = map.get("op").and_then(Value::as_str).unwrap_or("");
        let mut core = lock(&self.core);
        if op != "hello" && !core.hello {
            self.reply(&mut core, error(&id, "no_hello", "send hello first"));
            return;
        }
        match op {
            "hello" => {
                let reply = self.hello(&id, &map);
                if reply.get("error").is_none() && !core.hello {
                    core.hello = true;
                    // Keep paired hosts connected from now on.
                    self.keep.kick(paths::Kick::Reset(None));
                }
                self.reply(&mut core, reply);
            }
            "shutdown" => {
                self.reply(&mut core, json!({"re": id}));
                core.ending = Some(End::Shutdown);
                self.wake_writer.notify_one();
            }
            "stats" => {
                let a = &self.admission;
                let pre = self.host.preauth_stats();
                let per_kind = |n: fn(&mousse_net_io::PreAuthStats, ListenerKind) -> u64| {
                    ListenerKind::ALL
                        .iter()
                        .map(|k| (k.name().to_owned(), Value::from(n(&pre, *k))))
                        .collect::<Map<String, Value>>()
                };
                let reply = json!({
                    "preauth_open": per_kind(mousse_net_io::PreAuthStats::open),
                    "preauth_refused": per_kind(mousse_net_io::PreAuthStats::refused),
                    "re": id,
                    "open_streams": a.open_streams(),
                    "queued_bytes": a.queued_bytes(),
                    "peak_queued_bytes": a.peak_queued_bytes(),
                    "held_bytes": a.held_bytes(),
                    "peak_held_bytes": a.peak_held_bytes(),
                    "refused_streams": a.refused_streams(),
                    "handles": core.streams.len(),
                    "conns": core.conns.len(),
                    "app_buffered_bytes": core.buffered,
                    "peak_app_buffered_bytes": core.peak_buffered,
                    "app_credit_out_bytes": core.budget.used(),
                    "dropped_frames": core.dropped,
                });
                self.reply(&mut core, reply);
            }
            "stream.accept" => {
                let handle = map.get("handle").and_then(Value::as_u64);
                let found = handle
                    .and_then(|h| u32::try_from(h).ok())
                    .and_then(|h| core.streams.get_mut(&h));
                match found {
                    Some(s) => {
                        s.accepted = true;
                        s.wake.notify_one();
                        core.regrant(&self.limits);
                        self.reply(&mut core, json!({"re": id}));
                    }
                    None => {
                        core.dropped += 1;
                        self.reply(&mut core, error(&id, "no_stream", "no such stream"));
                    }
                }
            }
            "stream.reset" => {
                let handle = map
                    .get("handle")
                    .and_then(Value::as_u64)
                    .and_then(|h| u32::try_from(h).ok());
                let code = error_code(map.get("code").and_then(Value::as_str).unwrap_or(""));
                match handle.and_then(|h| core.streams.get(&h).map(|s| (h, s.writer.clone()))) {
                    Some((h, writer)) => {
                        writer.reset(code);
                        drop_stream(&mut core, h);
                        core.regrant(&self.limits);
                        self.reply(&mut core, json!({"re": id}));
                    }
                    None => {
                        core.dropped += 1;
                        self.reply(&mut core, error(&id, "no_stream", "no such stream"));
                    }
                }
            }
            "stream.open" => {
                let conn = map.get("conn").and_then(Value::as_u64);
                let label = map.get("label").and_then(Value::as_str).map(str::to_owned);
                let class = match map.get("class").and_then(Value::as_str) {
                    Some("interactive") => Some(PriorityClass::Interactive),
                    Some("bulk") => Some(PriorityClass::Bulk),
                    _ => None,
                };
                let entry = conn.and_then(|c| {
                    core.conns
                        .get(&c)
                        .map(|e| (c, e.conn.clone(), e.identity, e.via.clone(), e.inbound))
                });
                // Engine stream labels belong to the helper.
                let label = label.filter(|l| !l.starts_with(ENGINE_PREFIX));
                match (entry, label, class) {
                    // Calls toward the caller ride its connection only from
                    // minor 3 (`conn.up {both}`).
                    (Some((_, conn, _, _, true)), Some(_), Some(_)) if !both_ways(&conn) => self
                        .reply(
                            &mut core,
                            error(
                                &id,
                                "one_way",
                                "the caller on this connection does not take calls on it",
                            ),
                        ),
                    (Some((no, conn, pin, via, _)), Some(label), Some(class)) => {
                        drop(core);
                        let shared = self.clone();
                        tokio::spawn(async move {
                            // Bulk through a relay has its own outer
                            // connection and peer session (Phase 3 B.6).
                            let conn = match via {
                                Some(route) if class == PriorityClass::Bulk => {
                                    match relay::bulk_companion(&shared, no, pin, route).await {
                                        Ok(bulk) => bulk,
                                        Err(e) => {
                                            shared.event(error(&id, "no_conn", e.to_string()));
                                            return;
                                        }
                                    }
                                }
                                _ => conn,
                            };
                            open_stream(shared, id, no, conn, label, class).await;
                        });
                    }
                    (None, _, _) => {
                        self.reply(&mut core, error(&id, "no_conn", "no such connection"))
                    }
                    _ => self.reply(
                        &mut core,
                        error(
                            &id,
                            "bad_request",
                            "stream.open needs conn, label and class",
                        ),
                    ),
                }
            }
            "path.reopened" => {
                let reply = changes::reopened(self, &mut core, &id, &map);
                self.reply(&mut core, reply);
            }
            "routes.config" => {
                drop(core);
                let reply = routes::config(self, &id, &map);
                self.event(reply);
            }
            "routes.test" => {
                drop(core);
                let route = map.get("route").and_then(Value::as_str).map(str::to_owned);
                tokio::spawn(routes::test(self.clone(), id, route));
            }
            #[cfg(debug_assertions)]
            "test.clock" => {
                let reply = changes::test_clock(self, &id, &map);
                self.reply(&mut core, reply);
            }
            #[cfg(debug_assertions)]
            "test.ssh_dial" => {
                drop(core);
                tokio::spawn(ssh_dial_op(self.clone(), id, map));
            }
            op if crate::ssh::OPS.contains(&op) => {
                drop(core);
                tokio::spawn(ssh_op(self.clone(), id, op.to_owned(), map));
            }
            op if pairing::OPS.contains(&op) => {
                drop(core);
                pairing::on_request(self, id, op, &map);
            }
            op if relay::OPS.contains(&op) => {
                drop(core);
                relay::on_request(self, id, op, &map);
            }
            op if engine_ops::OPS.contains(&op) => {
                drop(core);
                engine_ops::on_request(self, id, op, &map);
            }
            other => {
                let reason = format!("unknown op {other:?}");
                self.reply(&mut core, error(&id, "unknown_op", reason));
            }
        }
    }

    fn hello(&self, id: &Value, map: &Map<String, Value>) -> Value {
        let proto: Vec<u64> = map
            .get("proto")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect())
            .unwrap_or_default();
        let (Some(&major), Some(&minor)) = (proto.first(), proto.get(1)) else {
            return error(id, "bad_request", "hello needs proto [major, minor]");
        };
        if major != PROTO.0 {
            return error(
                id,
                "unsupported_proto",
                format!("this helper speaks {}.{}", PROTO.0, PROTO.1),
            );
        }
        if let Some(profile) = map.get("profile").and_then(Value::as_str) {
            if profile != self.info.profile {
                return error(
                    id,
                    "wrong_profile",
                    "this endpoint belongs to another profile",
                );
            }
        }
        if let Some(name) = map.get("name").and_then(Value::as_str) {
            if let Err(e) = pairing::set_name(self, name) {
                return error(id, "bad_name", e);
            }
        }
        let listen = self
            .info
            .listen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let agreed = minor.min(PROTO.1);
        let mut reply = json!({
            "re": id,
            "proto": [PROTO.0, agreed],
            "build": crate::BUILD,
            "identity": hex(self.info.identity.as_bytes()),
            "device": short_id(&self.info.identity),
            "port": self.info.port,
            "ws_port": self.info.ws_port,
            "routes": listen.routes,
            "routes_config": listen.config,
            "unbound": listen.unbound,
            "paused": self.removal.paused_reason(),
        });
        // Only a 1.2 app reads the list; 1.1 and 1.0 replies stay as they were.
        if agreed >= 2 {
            reply["features"] = json!(FEATURES);
        }
        reply
    }

    fn has(&self, handle: u32) -> bool {
        lock(&self.core).streams.contains_key(&handle)
    }

    /// Whether the engine side of `handle` may be read now.
    fn may_read(&self, handle: u32) -> Option<bool> {
        let core = lock(&self.core);
        let s = core.streams.get(&handle)?;
        if s.rx != Rx::Open {
            return None;
        }
        if cfg!(mousse_control = "read-without-credit") {
            return Some(s.accepted);
        }
        Some(s.accepted && s.rx_credit >= s.rx_buffered + self.limits.app_read_ahead_bytes())
    }

    fn rx_data(&self, handle: u32, bytes: &[u8]) {
        let mut core = lock(&self.core);
        let core = &mut *core;
        let Some(s) = core.streams.get_mut(&handle) else {
            return;
        };
        if s.rx != Rx::Open {
            return;
        }
        let n = bytes.len() as u64;
        s.rx_buffered += n;
        let class = s.class;
        core.buffered += n;
        core.peak_buffered = core.peak_buffered.max(core.buffered);
        for chunk in bytes.chunks(frame::MAX_DATA) {
            core.out.data(handle, class, false, chunk);
        }
        self.wake_writer.notify_one();
    }

    fn rx_fin(&self, handle: u32) {
        let mut core = lock(&self.core);
        let core = &mut *core;
        let Some(s) = core.streams.get_mut(&handle) else {
            return;
        };
        s.rx = Rx::FinQueued;
        let class = s.class;
        #[cfg(mousse_control = "fin-overtakes")]
        {
            let _ = class;
            core.out.fin_as_control(handle);
        }
        #[cfg(not(mousse_control = "fin-overtakes"))]
        core.out.data(handle, class, true, &[]);
        self.queued(core);
    }

    /// The peer reset the stream: tell the app, drop what is queued.
    fn rx_reset(&self, handle: u32, code: ErrorCode) {
        let mut core = lock(&self.core);
        if !core.streams.contains_key(&handle) {
            return;
        }
        drop_stream(&mut core, handle);
        core.regrant(&self.limits);
        let event = json!({"ev": "stream.reset", "handle": handle, "code": code.name()});
        core.out.json(&event);
        self.queued(&core);
    }

    /// The engine took `n` bytes from the app: the credit goes back.
    fn tx_took(&self, handle: u32, n: u64) {
        let mut core = lock(&self.core);
        let core = &mut *core;
        let Some(s) = core.streams.get_mut(&handle) else {
            return;
        };
        let n = n.min(s.tx_window);
        s.tx_window -= n;
        let class = s.class;
        core.budget.give_back(class, n);
        core.regrant(&self.limits);
        self.wake_writer.notify_one();
    }

    /// The app-to-engine pump ended (after FIN, or because the stream or
    /// connection ended).
    fn tx_ended(&self, handle: u32) {
        let mut core = lock(&self.core);
        let core = &mut *core;
        let Some(s) = core.streams.get_mut(&handle) else {
            return;
        };
        s.tx_done = true;
        s.tx = None;
        s.wake.notify_one();
        let left = s.tx_window;
        s.tx_window = 0;
        s.tx_credit = 0;
        let class = s.class;
        core.out.take_credit(handle);
        core.budget.give_back(class, left);
        core.maybe_remove(handle);
        core.regrant(&self.limits);
        self.wake_writer.notify_one();
    }

    fn after_write(&self, meta: Meta) {
        let Meta::Data { handle, len, fin } = meta else {
            return;
        };
        let mut core = lock(&self.core);
        let core = &mut *core;
        core.buffered = core.buffered.saturating_sub(len);
        let Some(s) = core.streams.get_mut(&handle) else {
            return;
        };
        s.rx_credit = s.rx_credit.saturating_sub(len);
        s.rx_buffered = s.rx_buffered.saturating_sub(len);
        s.wake.notify_one();
        if fin {
            s.rx = Rx::Done;
            s.wake.notify_one();
            core.maybe_remove(handle);
        }
    }
}

/// End a stream here: queued frames go, held credit returns, its pumps
/// stop.
fn drop_stream(core: &mut Core, handle: u32) {
    let Some(s) = core.streams.remove(&handle) else {
        return;
    };
    core.out.discard(handle);
    core.buffered = core.buffered.saturating_sub(s.rx_buffered);
    core.budget.give_back(s.class, s.tx_window);
    s.wake.notify_one();
}

impl Core {
    fn maybe_remove(&mut self, handle: u32) {
        if let Some(s) = self.streams.get(&handle) {
            if s.rx == Rx::Done && s.tx_done {
                self.streams.remove(&handle);
            }
        }
    }

    /// Grant credit to streams that can take more, interactive first,
    /// streams taking turns within a class.
    fn regrant(&mut self, limits: &HelperLimits) {
        let max = limits.app_stream_credit_bytes();
        for (slot, class) in [PriorityClass::Interactive, PriorityClass::Bulk]
            .into_iter()
            .enumerate()
        {
            let wanting: Vec<u32> = self
                .streams
                .iter()
                .filter(|(_, s)| {
                    s.class == class && s.accepted && s.tx.is_some() && s.tx_window < max
                })
                .map(|(h, _)| *h)
                .collect();
            let start = wanting
                .iter()
                .position(|h| *h > self.turn[slot])
                .unwrap_or(0);
            for &handle in wanting[start..].iter().chain(&wanting[..start]) {
                let Some(s) = self.streams.get_mut(&handle) else {
                    continue;
                };
                let got = self.budget.take(class, max - s.tx_window);
                if got == 0 {
                    break;
                }
                s.tx_window += got;
                s.tx_credit += got;
                self.out.credit(handle, got);
                self.turn[slot] = handle;
            }
        }
    }
}

async fn read_stdin(shared: Arc<Shared>) {
    let mut stdin = tokio::io::stdin();
    let size = usize::try_from(crate::limits::get().net.io().read_buffer_bytes()).unwrap_or(32_768);
    let mut buf = vec![0u8; size];
    let mut inbuf: Vec<u8> = Vec::new();
    loop {
        let n = match stdin.read(&mut buf).await {
            Ok(0) | Err(_) => {
                shared.end(End::Eof);
                return;
            }
            Ok(n) => n,
        };
        inbuf.extend_from_slice(&buf[..n]);
        let mut at = 0;
        loop {
            match frame::decode(&inbuf[at..]) {
                Ok(Some((frame, used))) => {
                    at += used;
                    if let Err(end) = shared.on_frame(frame) {
                        shared.end(end);
                        return;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    shared.end(End::Malformed(e.to_string()));
                    return;
                }
            }
        }
        inbuf.drain(..at);
    }
}

async fn write_stdout(shared: Arc<Shared>) {
    let mut stdout = tokio::io::stdout();
    loop {
        let next = {
            let mut core = lock(&shared.core);
            match core.out.next() {
                Some(next) => Some(next),
                None => {
                    if let Some(end) = core.ending.take() {
                        drop(core);
                        shared.end(end);
                        return;
                    }
                    None
                }
            }
        };
        let Some((bytes, meta)) = next else {
            shared.wake_writer.notified().await;
            continue;
        };
        // One frame at a time, flushed: an interactive frame waits behind
        // at most the frame being written and the pipe's buffer.
        if stdout.write_all(&bytes).await.is_err() || stdout.flush().await.is_err() {
            shared.end(End::Eof);
            return;
        }
        shared.after_write(meta);
    }
}

/// Whether `conn` carries calls both ways: its agreed minor is 3 or more.
fn both_ways(conn: &Connection) -> bool {
    conn.minor().unwrap_or(0) >= BOTH_WAYS_MIN_MINOR
}

/// A stream the host opened on this computer's connection to it: passed
/// to the app as `stream.incoming` with the grant it is served under, if
/// the connection's minor allows it, its label is an app label, networking
/// is not paused and the host holds a live grant here. Otherwise it is
/// refused. The grant is read under the core lock [`watch_served`] resets
/// under, so a removal either sees the stream or is seen here.
fn serve_host_stream(shared: &Arc<Shared>, no: u64, conn: &Connection, stream: MuxStream) {
    let both = both_ways(conn) && LABELS.contains(&stream.label());
    let mut core = lock(&shared.core);
    let grant = if both && !shared.removal.is_paused() {
        shared.host.live_grant(conn.peer())
    } else {
        None
    };
    let Some(grant) = grant else {
        drop(core);
        stream.writer.reset(ErrorCode::RefusedStream);
        return;
    };
    let label = stream.label().to_owned();
    let class = stream.class();
    let Some(handle) = shared.add_stream(&mut core, no, stream, false) else {
        return;
    };
    if let Some(entry) = core.streams.get_mut(&handle) {
        entry.served = Some(grant.id.0);
    }
    let event = json!({
        "ev": "stream.incoming",
        "conn": no,
        "handle": handle,
        "label": label,
        "class": class_name(class),
        "grant": grant.id.0,
        "role": grant.role.as_str(),
    });
    core.out.json(&event);
    shared.queued(&core);
}

/// Reset every host-opened stream whose grant here is no longer live (a
/// removal, an expiry, a pause), on every change to the grant table and
/// when networking pauses.
async fn watch_served(shared: Arc<Shared>) {
    let mut grants = shared.host.grants_changed();
    let mut pause = shared.removal.watch();
    loop {
        tokio::select! {
            changed = grants.changed() => if changed.is_err() { return },
            changed = pause.changed() => if changed.is_err() { return },
        }
        let mut core = lock(&shared.core);
        let paused = shared.removal.is_paused();
        let gone: Vec<(u32, StreamWriter)> = core
            .streams
            .iter()
            .filter_map(|(h, s)| {
                let grant = s.served?;
                let identity = core.conns.get(&s.conn)?.identity;
                let live = !paused
                    && shared
                        .host
                        .live_grant(&identity)
                        .is_some_and(|g| g.id.0 == grant);
                (!live).then(|| (*h, s.writer.clone()))
            })
            .collect();
        for (handle, writer) in gone {
            writer.reset(ErrorCode::GrantRevoked);
            drop_stream(&mut core, handle);
            let event = json!({"ev": "stream.reset", "handle": handle, "code": ErrorCode::GrantRevoked.name()});
            core.out.json(&event);
        }
        core.regrant(&shared.limits);
        shared.queued(&core);
    }
}

/// Watch one connection: hand its peer's streams to the app (or refuse
/// them), and report its end.
async fn conn_task(shared: Arc<Shared>, no: u64, conn: Arc<Connection>, inbound: bool) {
    // Inbound: the host opens engine streams only once the caller has
    // opened one.
    let (opened, opened_rx) = watch::channel(false);
    if inbound {
        shared.engine.on_inbound(conn.clone(), opened_rx);
    } else {
        shared.engine.on_outbound(conn.clone());
    }
    let accept = async {
        while let Some(stream) = conn.accept_stream().await {
            opened.send_replace(true);
            if inbound {
                // The engine lets a host open streams only once its caller
                // has opened one.
                let first = {
                    let mut core = lock(&shared.core);
                    core.conns
                        .get_mut(&no)
                        .is_some_and(|e| !std::mem::replace(&mut e.caller_opened, true))
                };
                if first {
                    relay::send_manifest(&shared, no, conn.clone());
                }
            }
            if stream.label().starts_with(ENGINE_PREFIX) {
                // The relay's engine streams (minor 1), then Phase 4's.
                let keys = conn.minor().unwrap_or(0) >= relay::KEYS_MINOR;
                match stream.label() {
                    relay::MANIFEST_LABEL if keys && !inbound => {
                        tokio::spawn(relay::read_manifest(shared.clone(), *conn.peer(), stream));
                    }
                    relay::KEYS_LABEL if keys && inbound => {
                        tokio::spawn(relay::serve_keys(shared.clone(), conn.clone(), stream));
                    }
                    _ => shared.engine.on_stream(conn.clone(), inbound, stream),
                }
            } else if !inbound {
                // From minor 3 the host may call this computer over this
                // computer's own connection, under this computer's grant
                // for it (wire.md 8, step 5). Before, it opens none.
                serve_host_stream(&shared, no, &conn, stream);
            } else if LABELS.contains(&stream.label()) {
                let label = stream.label().to_owned();
                let class = stream.class();
                let mut core = lock(&shared.core);
                if let Some(handle) = shared.add_stream(&mut core, no, stream, false) {
                    let event = json!({
                        "ev": "stream.incoming",
                        "conn": no,
                        "handle": handle,
                        "label": label,
                        "class": class_name(class),
                    });
                    core.out.json(&event);
                    shared.queued(&core);
                }
            } else if stream.label() == crate::serve::INFO_LABEL {
                tokio::spawn(crate::serve::send_info(stream));
            } else {
                stream.writer.reset(ErrorCode::RefusedStream);
            }
        }
        std::future::pending::<()>().await;
    };
    let reason = tokio::select! {
        () = accept => CloseReason::PipeClosed,
        reason = conn.closed() => reason,
    };
    shared.conn_down(no, &reason);
}

async fn open_stream(
    shared: Arc<Shared>,
    id: Value,
    no: u64,
    conn: Arc<Connection>,
    label: String,
    class: PriorityClass,
) {
    let opened = conn.open_stream(class, &label).await;
    let mut core = lock(&shared.core);
    let reply = match opened {
        Ok(stream) => match shared.add_stream(&mut core, no, stream, true) {
            Some(handle) => json!({"re": id, "handle": handle}),
            None => error(&id, "no_conn", "the connection closed"),
        },
        Err(NetError::StreamLimit) => error(
            &id,
            "stream_limit",
            "too many open streams; open it once one ends",
        ),
        Err(e @ NetError::Closed(_)) => error(&id, "no_conn", e.to_string()),
        Err(e) => error(&id, "refused", e.to_string()),
    };
    // The reply goes before the stream's first credit.
    core.out.json(&reply);
    core.regrant(&shared.limits);
    shared.queued(&core);
}

/// Engine to app: read only while the app's credit covers what is
/// buffered plus the read-ahead.
async fn rx_pump(shared: Arc<Shared>, handle: u32, mut reader: StreamReader, wake: Arc<Notify>) {
    loop {
        loop {
            match shared.may_read(handle) {
                None => return,
                Some(true) => break,
                Some(false) => {}
            }
            tokio::select! {
                () = wake.notified() => {}
                code = reader.reset_by_peer() => {
                    shared.rx_reset(handle, code);
                    return;
                }
            }
        }
        match reader.read().await {
            Ok(Some(bytes)) => shared.rx_data(handle, &bytes),
            Ok(None) => {
                shared.rx_fin(handle);
                break;
            }
            Err(NetError::StreamReset(code)) => {
                shared.rx_reset(handle, code);
                return;
            }
            // The connection closed: `conn.down` covers its streams.
            Err(_) => return,
        }
    }
    // Past FIN the peer may still reset the stream (its other half may be
    // open). Hold the reader only while the stream lives here: its place
    // in the stream caps is kept until the reader goes.
    while shared.has(handle) {
        tokio::select! {
            () = wake.notified() => {}
            code = reader.reset_by_peer() => {
                shared.rx_reset(handle, code);
                return;
            }
        }
    }
}

/// App to engine, in order; FIN after the last byte.
async fn tx_pump(
    shared: Arc<Shared>,
    handle: u32,
    writer: StreamWriter,
    mut rx: mpsc::UnboundedReceiver<Chunk>,
) {
    while let Some(chunk) = rx.recv().await {
        if !chunk.bytes.is_empty() {
            let n = chunk.bytes.len() as u64;
            if writer.write(&chunk.bytes).await.is_err() {
                break;
            }
            shared.tx_took(handle, n);
        }
        if chunk.fin {
            writer.finish();
            break;
        }
    }
    shared.tx_ended(handle);
}

/// `ssh.*` (Phase 1b §3, §7): run off the reader, the reply queued when
/// done. A wait in the connection window is announced as `ssh.waiting`.
async fn ssh_op(shared: Arc<Shared>, id: Value, op: String, map: Map<String, Value>) {
    let ssh = shared.ssh.clone();
    let events = shared.clone();
    let mut done = ssh.handle(&op, &map, move |ev| events.event(ev)).await;
    if op == "ssh.forget" && done.is_ok() {
        // The route's address and approvals go too (§1.3).
        let id = map.get("route_id").and_then(Value::as_str).unwrap_or("");
        if let Err(e) = paths::forget_address(&shared, &format!("ssh://mousse-{id}")) {
            done = Err(crate::ssh::Fail {
                error: "store_failed",
                reason: e.to_string(),
            });
        }
    }
    let reply = match done {
        Ok(mut reply) => {
            if let Some(obj) = reply.as_object_mut() {
                obj.insert("re".into(), id);
            }
            reply
        }
        Err(f) => error(&id, f.error, f.reason),
    };
    shared.event(reply);
}

/// Debug builds only: `test.ssh_dial {route_id, selector, identity,
/// within_ms?}` opens an outbound path to the paired host `identity` over
/// the SSH route alone, as the caller's `ssh` tier will, and announces it
/// with `conn.up`. Checks use it to drive `ssh-stdio` end to end.
#[cfg(debug_assertions)]
async fn ssh_dial_op(shared: Arc<Shared>, id: Value, map: Map<String, Value>) {
    let field = |k: &str| map.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    let pin = match mousse_net_io::store::identity_from_hex(&field("identity")) {
        Ok(pin) => pin,
        Err(_) => {
            shared.event(error(
                &id,
                "bad_request",
                "test.ssh_dial needs identity (hex)",
            ));
            return;
        }
    };
    let within = std::time::Duration::from_millis(
        map.get("within_ms")
            .and_then(Value::as_u64)
            .unwrap_or(20_000),
    );
    let deadline = tokio::time::Instant::now() + within;
    let route_id = field("route_id");
    let events = shared.clone();
    let host = route_id.clone();
    let opened = shared
        .ssh
        .dial(&route_id, &field("selector"), within, move |wait| {
            events.event(json!({
                "ev": "ssh.waiting",
                "route_id": host,
                "ms": u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
            }))
        })
        .await;
    let gen = shared.peer_gen(&pin);
    let dialled = match opened {
        Ok(pipe) => match tokio::time::timeout_at(deadline, shared.caller.dial(pipe, pin)).await {
            Ok(got) => got,
            Err(_) => Err(NetError::Timeout("ssh dial")),
        },
        Err(e) => Err(e),
    };
    let reply = match dialled {
        Ok(conn) => {
            let fields = json!({"dir": "out", "route": {"kind": "ssh", "class": "ssh"}});
            match shared.add_outbound(conn, gen, fields) {
                Ok(no) => json!({"re": id, "conn": no}),
                Err(_) => error(&id, "paused", "networking is paused"),
            }
        }
        Err(NetError::Ssh { reason, detail }) => error(&id, reason.name(), detail),
        Err(e) => error(&id, "unreachable", e.to_string()),
    };
    shared.event(reply);
}
