//! `serve`: run this endpoint's host. Accepts connections, answers the
//! local control channel (invite, grants, remove, stop) and runs terminal
//! channels for authorized peers.
//!
//! An approval question names one request: the joining connection and the
//! device shown. The answer must name the same request, so an answer never
//! applies to a different device or a newer request.
//!
//! **Where it listens (Phase 1b §1.5).** With `<state>/routes.json`, the
//! listener binds the addresses it selects, one TCP socket each, all on the
//! kept port ([`RoutesConfig::bind_plan`]); the ones that do not bind are
//! listed as `unbound` and tried again when the interfaces change. When the
//! interface watcher sees a selected address appear or go (LAN off), only
//! that socket opens or closes, and closing it closes the connections it
//! accepted. Only served addresses are advertised. Without the file the
//! listener binds `--listen-ip`, as in 1a.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mousse_net_core::grants::{GrantId, Role};
use mousse_net_core::identity::{IdentityPublicKey, SoftwareKey};
use mousse_net_core::pairing::{CpaceExchangeFactory, InvitationId, InvitationKind};
use mousse_net_core::ErrorCode;
use mousse_net_io::discovery::{Advertiser, CachedBrowse};
use mousse_net_io::pipe::ws::{self, WsTarget};
use mousse_net_io::pipe::{accept_tcp, route_from_addr, route_uri, Pipe, RouteKind};
use mousse_net_io::rng::{os_rng, random_bytes};
use mousse_net_io::routes::{RoutesConfig, RoutesStore};
use mousse_net_io::store::{hex, short_id};
use mousse_net_io::{
    ApprovalRequest, Caller, Host, HostConfig, HostEvent, ListenerKind, PortChoice, PreAuthSlot,
    SharedSigner,
};
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Notify};

use crate::ipc::{self, Channel, ControlListener};
use crate::term;

/// `serve` options.
pub struct ServeOptions {
    pub name: String,
    pub listen_ip: IpAddr,
    pub port: Option<u16>,
    pub mdns: bool,
    /// `--app`: the app channel on stdin and stdout.
    pub app: bool,
    /// `--ws-port`: run the loopback `ws` listener for a tunnel client on
    /// this port (0: any; Phase 1b §4.1). It also runs on the kept ws
    /// port in app mode and when `tunnels` is configured.
    pub ws_port: Option<u16>,
    /// `--tunnel`: public `wss` URLs of the owner's tunnels to this
    /// listener, advertised in tickets.
    pub tunnels: Vec<String>,
}

/// A deliberate defect for the cross-machine must-fail control, read from
/// `MOUSSE_HELPER_BREAK`. Only control builds (never release) honour it.
fn break_mode() -> Option<String> {
    mousse_net_io::CONTROL?;
    std::env::var("MOUSSE_HELPER_BREAK").ok()
}

/// What the listener serves now, for `hello`, tickets and `routes.config`.
#[derive(Clone, Debug, Default)]
pub struct ListenState {
    /// The routes advertised in tickets and pairback routes.
    pub routes: Vec<String>,
    /// Selected addresses that could not be bound.
    pub unbound: Vec<IpAddr>,
    /// The routes config in effect: `routes.json`, or what the command line
    /// gave when there is none.
    pub config: RoutesConfig,
    /// The port every socket listens on.
    pub port: u16,
    /// The addresses bound now.
    pub bound: Vec<IpAddr>,
    /// `--listen-ip` when no `routes.json` chose the addresses: the
    /// listener then serves what [`route_hints`] lists for it, whatever
    /// `config.lan` says.
    pub listen_ip: Option<IpAddr>,
    /// Tunnels given on the command line (`--tunnel`), advertised besides
    /// the config's.
    pub extra: Vec<String>,
    /// This app's active managed tunnel, only for the lifetime of the helper.
    pub managed_tunnel: Option<String>,
}

impl ListenState {
    /// Advertise what `config` selects for the sockets bound now, plus the
    /// command line's tunnels.
    pub fn readvertise(&mut self, interfaces: &[IpAddr]) {
        let mut routes = self.config.advertised(interfaces, &self.bound, self.port);
        for t in &self.extra {
            if !routes.contains(t) {
                routes.push(t.clone());
            }
        }
        if let Some(managed) = &self.managed_tunnel {
            routes.retain(|route| route != managed);
            // Reserve one ticket slot without changing the saved owner routes.
            routes.truncate(mousse_net_core::pairing::MAX_ROUTES - 1);
            routes.push(managed.clone());
        }
        self.routes = routes;
    }
}

/// The listen state, shared by the accept loop and the app channel.
pub type SharedListen = Arc<Mutex<ListenState>>;

/// One accepted TCP connection: the pipe, the peer, and a signal that its
/// socket closed.
type Accepted = (TcpStream, SocketAddr, watch::Receiver<bool>);

/// One listening TCP socket. Dropping it stops accepting and tells the
/// connections it accepted to close.
struct Socket {
    task: tokio::task::JoinHandle<()>,
    closing: watch::Sender<bool>,
}

impl Socket {
    fn open(listener: TcpListener, accepted: mpsc::UnboundedSender<Accepted>) -> Self {
        let (closing, signal) = watch::channel(false);
        let task = tokio::spawn(async move {
            loop {
                match accept_tcp(&listener).await {
                    Ok((pipe, addr)) => {
                        if accepted.send((pipe, addr, signal.clone())).is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        print_line(format!("accept failed: {e}"));
                        tokio::task::yield_now().await;
                    }
                }
            }
        });
        Self { task, closing }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.task.abort();
        let _ = self.closing.send(true);
    }
}

/// Open the sockets `config` selects for `interfaces` that are not open
/// yet, close the ones it no longer selects. Returns the unbound ones.
async fn reconcile(
    config: &RoutesConfig,
    interfaces: &[IpAddr],
    port: u16,
    sockets: &mut HashMap<IpAddr, Socket>,
    accepted: &mpsc::UnboundedSender<Accepted>,
) -> Vec<IpAddr> {
    let want = config.bind_plan(interfaces);
    sockets.retain(|ip, _| {
        let keep = want.contains(ip);
        if !keep {
            print_line(format!("stopped listening on {ip}"));
        }
        keep
    });
    let mut unbound = Vec::new();
    for ip in want {
        if sockets.contains_key(&ip) {
            continue;
        }
        match TcpListener::bind(SocketAddr::new(ip, port)).await {
            Ok(listener) => {
                print_line(format!("listening on {ip}:{port}"));
                sockets.insert(ip, Socket::open(listener, accepted.clone()));
            }
            Err(e) => {
                print_line(format!("could not listen on {ip}:{port}: {e}"));
                unbound.push(ip);
            }
        }
    }
    unbound
}

struct State {
    host: Host,
    listen: SharedListen,
    token: String,
    /// The identity tickets name. Differs from the TLS identity only in the
    /// `wrong-identity` control.
    ticket_identity: IdentityPublicKey,
    waiters: Mutex<HashMap<InvitationId, mpsc::UnboundedSender<Value>>>,
    /// Approval questions waiting for an answer, by request id.
    pending: Mutex<HashMap<String, ApprovalRequest>>,
    stop: Notify,
}

/// Route hints for a listener on `ip`:`port`. An unspecified address
/// expands to this machine's LAN addresses.
pub fn route_hints(ip: IpAddr, port: u16) -> Vec<String> {
    let addrs: Vec<IpAddr> = if ip.is_unspecified() {
        if_addrs::get_if_addrs()
            .map(|ifaces| ifaces.iter().map(|i| i.ip()).collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut out = served_hints(ip, port, &addrs);
    out.truncate(8);
    out
}

/// Every route hint a listener on `ip`:`port` serves, uncapped and sorted:
/// `ip` itself, or for an unspecified address each usable one of `addrs`
/// (no loopback or link-local; IPv6 only for an IPv6 listener).
/// [`route_hints`] is this list cut to eight.
pub fn served_hints(ip: IpAddr, port: u16, addrs: &[IpAddr]) -> Vec<String> {
    if !ip.is_unspecified() {
        return vec![route_uri(&route_from_addr(SocketAddr::new(ip, port)))];
    }
    let mut out = Vec::new();
    for &addr in addrs {
        if addr.is_loopback() {
            continue;
        }
        let usable = match addr {
            IpAddr::V4(v4) => !v4.is_link_local(),
            IpAddr::V6(v6) => ip.is_ipv6() && !v6.is_unicast_link_local(),
        };
        if usable {
            out.push(route_uri(&route_from_addr(SocketAddr::new(addr, port))));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn print_line(line: impl AsRef<str>) {
    crate::applog::line(line);
}

/// Run step 1 and step 2 on an inbound pipe that holds `slot`; the host
/// keeps the place until the connection is live or closed. `None` if it
/// was refused.
async fn accept_holding<P: Pipe>(
    host: &Host,
    pipe: P,
    addr: SocketAddr,
    slot: PreAuthSlot,
) -> Option<mousse_net_io::Connection> {
    let conn = match host.accept_admitted(pipe, slot).await {
        Ok(conn) => conn,
        Err(e) => {
            print_line(format!("refused {addr}: {e}"));
            return None;
        }
    };
    // Bounded: the handshake by HANDSHAKE_TIMEOUT_MS, step 2 by
    // JOIN_PROOF_WAIT_MS and the invitation's own limits.
    let _ = conn.settled(true).await;
    Some(conn)
}

/// Run until stopped (Ctrl-C or the `stop` control request).
/// `opened` is an endpoint this process just created and still holds the
/// locks of (a headless first start); otherwise the endpoint is opened here.
pub async fn run(
    state_dir: &Path,
    insecure_file_key: bool,
    opts: ServeOptions,
    opened: Option<mousse_net_io::Endpoint>,
) -> Result<(), String> {
    let mut endpoint = match opened {
        Some(endpoint) => endpoint,
        None => crate::open_endpoint(state_dir, false)?,
    };
    if opts.app {
        // stdout carries only app-channel frames from here on.
        crate::applog::to_file(state_dir)?;
    }
    let key = endpoint
        .load_identity(insecure_file_key)
        .map_err(|e| e.to_string())?;
    let real_identity = endpoint.identity();
    let key_storage = key.storage();
    let (clock, manual_clock) = crate::app::clock();
    let mut config = HostConfig::for_endpoint(&endpoint, opts.name.clone(), clock.clone())
        .map_err(|e| e.to_string())?;
    config.limits = crate::limits::get().net;
    let signer: SharedSigner = match break_mode().as_deref() {
        Some("wrong-identity") => {
            // Tickets and pairing use the real key; only TLS presents
            // another one, so the joiner's pin check is what must fail.
            print_line("control: TLS presents a different identity than the tickets name");
            config.ticket_identity = Some(real_identity);
            Arc::new(SoftwareKey::generate(&mut os_rng()))
        }
        _ => Arc::new(key),
    };
    let (host, mut events) =
        Host::new(signer.clone(), config, CpaceExchangeFactory).map_err(|e| e.to_string())?;
    // Removals that were decided but maybe not saved are applied before
    // anything is accepted (Phase 1a §5.4). If that fails, networking
    // starts paused.
    let removal = crate::revoke::Removal::start(host.clone(), &endpoint.grants_dir());
    let (engine, engine_events) = crate::engine::Engine::new(
        host.clone(),
        removal.clone(),
        signer.clone(),
        clock.clone(),
        endpoint.dir().to_path_buf(),
    );
    // Plus (Phase 4): nothing is fetched before ready; the client starts
    // its background work once attached.
    // Plus judges every signed request and token on its own clock, so the
    // client keeps wall time even where a test moves the helper's clock.
    let plus = crate::plus::Plus::open(
        crate::limits::settings().plus_url.as_deref(),
        endpoint.dir(),
        Arc::new(mousse_net_io::SystemClock::new()),
        key_storage,
        endpoint.plus_key_store(),
        endpoint.endpoint_id(),
        engine.events(),
    )?;
    // `routes.json` decides where to listen; without it, `--listen-ip`.
    let stored = RoutesStore::in_dir(state_dir)
        .load()
        .map_err(|e| e.to_string())?;
    let interfaces = crate::app::interface_ips();
    let choice = match (stored.as_ref().and_then(|c| c.port), opts.port) {
        (Some(p), _) => PortChoice::Fixed(p),
        (None, None) => PortChoice::Kept,
        (None, Some(0)) => PortChoice::Auto,
        (None, Some(p)) => PortChoice::Fixed(p),
    };
    let plan = match &stored {
        Some(config) => config.bind_plan(&interfaces),
        None => vec![opts.listen_ip],
    };
    let (accepted_tx, mut accepted_rx) = mpsc::unbounded_channel::<Accepted>();
    let mut sockets: HashMap<IpAddr, Socket> = HashMap::new();
    let mut unbound: Vec<IpAddr> = Vec::new();
    let mut bound_port = None;
    for ip in &plan {
        let listener = match bound_port {
            None => endpoint.bind(*ip, choice).await,
            Some(port) => TcpListener::bind(SocketAddr::new(*ip, port))
                .await
                .map_err(mousse_net_io::NetError::from),
        };
        match listener {
            Ok(listener) => {
                let port = listener.local_addr().map_err(|e| e.to_string())?.port();
                bound_port.get_or_insert(port);
                sockets.insert(*ip, Socket::open(listener, accepted_tx.clone()));
            }
            // A selected address that is not there: the watcher retries it.
            Err(e) if stored.is_some() => {
                print_line(format!("could not listen on {ip}: {e}"));
                unbound.push(*ip);
            }
            Err(e) => return Err(format!("listen: {e}")),
        }
    }
    let port = bound_port
        .or(endpoint.fixed_port())
        .or(endpoint.kept_port())
        .ok_or("listen: no selected address could be bound and no port is kept yet")?;
    let bound: Vec<IpAddr> = sockets.keys().copied().collect();
    let mut routes = match &stored {
        Some(config) => config.advertised(&interfaces, &bound, port),
        None => route_hints(opts.listen_ip, port),
    };
    let mut extra = Vec::new();
    for tunnel in &opts.tunnels {
        let target = WsTarget::parse(tunnel)
            .filter(|t| t.secure)
            .ok_or_else(|| {
                format!("--tunnel {tunnel}: not a wss://<host>[:<port>]<path>/mousse-net/1 URL")
            })?;
        routes.push(target.uri());
        extra.push(target.uri());
    }
    let config = stored.clone().unwrap_or_else(|| RoutesConfig {
        lan: opts.listen_ip.is_unspecified(),
        ..RoutesConfig::default()
    });
    // mDNS only with LAN on (never on loopback).
    let lan_on = match &stored {
        Some(config) => config.lan,
        None => !opts.listen_ip.is_loopback(),
    };
    let listen: SharedListen = Arc::new(Mutex::new(ListenState {
        routes: routes.clone(),
        unbound: unbound.clone(),
        config: config.clone(),
        port,
        bound: bound.clone(),
        listen_ip: stored.is_none().then_some(opts.listen_ip),
        extra,
        managed_tunnel: None,
    }));
    // The loopback ws listener, for the owner's tunnel client (§4.1).
    let ws_required = opts.ws_port.is_some() || !opts.tunnels.is_empty() || config.ws_listener();
    let ws_listener = if opts.app || ws_required {
        match endpoint.bind_ws(opts.ws_port).await {
            Ok(listener) => Some(listener),
            Err(error) if ws_required => return Err(format!("ws listen: {error}")),
            Err(error) => {
                eprintln!("optional local tunnel origin unavailable: {error}");
                None
            }
        }
    } else {
        None
    };
    let ws_port = match &ws_listener {
        Some(l) => Some(l.local_addr().map_err(|e| e.to_string())?.port()),
        None => None,
    };
    let advertiser = if opts.mdns && lan_on {
        Some(
            Advertiser::start(port, clock.clone(), crate::limits::get().net.io())
                .map_err(|e| format!("mDNS: {e}"))?,
        )
    } else {
        None
    };

    // In app mode the app channel carries everything else; the control
    // listener answers only `pipe` and `status` (Phase 1b §3.3).
    let mut control = Some(ControlListener::bind(state_dir).await?);
    let token = hex(&random_bytes::<32>());
    if let Some(control) = &control {
        ipc::write_control_file(state_dir, control.addr(), &token)?;
    }

    let state = Arc::new(State {
        host: host.clone(),
        listen: listen.clone(),
        token,
        ticket_identity: real_identity,
        waiters: Mutex::new(HashMap::new()),
        pending: Mutex::new(HashMap::new()),
        stop: Notify::new(),
    });
    print_line(format!(
        "ready {} port {} build {} routes {}{}{}",
        short_id(&real_identity),
        port,
        crate::BUILD,
        routes.join(" "),
        match &advertiser {
            Some(a) => format!(" mdns {}", a.current_name()),
            None => String::new(),
        },
        match ws_port {
            Some(p) => format!(" ws_port {p}"),
            None => String::new(),
        }
    ));

    // Interface changes and wakes: announce the mDNS record again, and in
    // app mode check every connection and redial (Phase 1a §8).
    let mut net_changes = mousse_net_io::watch::watch(
        clock.clone(),
        crate::app::interface_source(),
        crate::limits::get().net.io(),
    );

    let app = if opts.app {
        // Outbound connections for the app: the same key, flow records and
        // stream places as the host.
        let mut caller = Caller::new(signer.clone(), clock.clone(), crate::limits::get().net);
        // Must-fail control: flow records in memory, so a restart gives a
        // send link its tries back.
        if cfg!(mousse_control = "joiner-records-in-memory") {
            caller.use_flow_records(Arc::new(mousse_net_io::store::MemoryFlowRecords::default()));
        } else {
            caller.use_flow_records(Arc::new(endpoint.flow_records()));
        }
        caller.use_stream_admission(host.stream_admission());
        // The ssh tier opens SSH routes set up by `ssh.resolve` (Phase 1b §3).
        let ssh = Arc::new(crate::ssh::Ssh::new(endpoint.dir()));
        caller.use_ssh_dialer(Arc::new(crate::ssh::Dialer(ssh.clone())));
        // mDNS only where the helper advertises too (never on loopback,
        // never with LAN off); debug builds may read a browse file instead.
        let browse = crate::app::browse_source(opts.mdns && lan_on).map(|source| {
            Arc::new(CachedBrowse::new(
                source,
                clock.clone(),
                crate::limits::get().net.io(),
            ))
        });
        // Renewals search from the store as it is then, with the browse
        // (Phase 1b §1.4 and §1.5).
        let lan_flaps = Arc::new(crate::app::LanFlaps::default());
        caller.use_candidates(Arc::new(crate::app::StoreCandidates {
            dir: endpoint.dir().to_path_buf(),
            policy: caller.addr_policy().clone(),
            browse: browse.clone(),
            flaps: lan_flaps.clone(),
        }));
        let info = crate::app::AppInfo {
            identity: real_identity,
            name: opts.name.clone(),
            profile: endpoint.profile_id().to_owned(),
            port,
            ws_port,
            listen: listen.clone(),
            state_dir: endpoint.dir().to_path_buf(),
            browse,
            lan_flaps,
            manual_clock,
            signer: signer.clone(),
            endpoint_id: endpoint.endpoint_id().to_owned(),
            key_storage,
            ssh,
        };
        Some(crate::app::App::start(
            host.clone(),
            Arc::new(caller),
            removal.clone(),
            info,
            engine.clone(),
            engine_events,
        ))
    } else {
        // No app: engine events are only logged.
        let mut engine_events = engine_events;
        tokio::spawn(async move {
            while let Some(event) = engine_events.recv().await {
                print_line(format!("engine: {event}"));
            }
        });
        None
    };
    // After the app, so the relay client's pairings are there (Phase 4).
    if let Some(plus) = plus {
        engine.set_plus(plus);
    }
    let app_end = async {
        match &app {
            Some(app) => app.ended().await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(app_end);
    let mut ended = None;

    loop {
        tokio::select! {
            Some((pipe, addr, closing)) = accepted_rx.recv() => {
                // A place in the TCP pool before anything is read; none
                // while paused (the removal is not saved yet).
                match host.admit(ListenerKind::Tcp, Some(addr.ip())) {
                    Err(why) => {
                        print_line(format!("dropped {addr}: {why}"));
                        drop(pipe);
                    }
                    Ok(slot) => match &app {
                        Some(app) => {
                            tokio::spawn(app_connection(host.clone(), app.clone(), pipe, addr, slot, closing));
                        }
                        None => {
                            tokio::spawn(handle_connection(host.clone(), pipe, addr, slot, closing));
                        }
                    },
                }
            },
            accepted = accept_ws(&ws_listener) => match accepted {
                // A place in the ws pool before anything is read. Control
                // (tests only): the place is taken after the upgrade.
                Ok((stream, addr)) => {
                    let slot = if cfg!(mousse_control = "ws-slot-after-headers") {
                        Ok(None)
                    } else {
                        host.admit(ListenerKind::Ws, None).map(Some)
                    };
                    match slot {
                        Err(why) => {
                            print_line(format!("dropped ws {addr}: {why}"));
                            drop(stream);
                        }
                        Ok(slot) => {
                            tokio::spawn(ws_connection(host.clone(), app.clone(), stream, addr, slot));
                        }
                    }
                }
                Err(e) => print_line(format!("ws accept failed: {e}")),
            },
            end = &mut app_end => {
                print_line(format!("app channel ended: {end:?}"));
                ended = Some(end);
                break;
            }
            ctl = accept_control(&mut control) => match ctl {
                Ok(ch) => match &app {
                    // A place in the pipe pool before anything is read;
                    // none while paused.
                    Some(app) => {
                        let slot = host.admit(ListenerKind::Pipe, None);
                        tokio::spawn(app_control_session(
                            host.clone(),
                            app.clone(),
                            state.clone(),
                            ch,
                            slot,
                        ));
                    }
                    None => {
                        tokio::spawn(control_session(state.clone(), ch));
                    }
                },
                Err(e) => print_line(format!("control channel: {e}")),
            },
            Some(change) = net_changes.recv() => {
                if let Some(advertiser) = &advertiser {
                    advertiser.refresh();
                }
                // A selected address came or went: open or close only
                // that socket (LAN on binds 0.0.0.0, which never changes).
                if stored.is_some() {
                    let interfaces = crate::app::interface_ips();
                    // The config in effect: list edits since the start
                    // apply without a restart.
                    let config = listen.lock().unwrap_or_else(|e| e.into_inner()).config.clone();
                    let unbound = reconcile(&config, &interfaces, port, &mut sockets, &accepted_tx).await;
                    let mut st = listen.lock().unwrap_or_else(|e| e.into_inner());
                    st.bound = sockets.keys().copied().collect();
                    st.unbound = unbound;
                    st.readvertise(&interfaces);
                }
                if let Some(app) = &app {
                    app.net_change(change);
                }
            }
            Some(event) = events.recv() => match &app {
                Some(app) => app.host_event(event),
                None => on_event(&state, event),
            },
            () = state.stop.notified() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    if let Some(app) = &app {
        app.close_all();
    }
    drop(sockets);
    host.close_all(ErrorCode::NoError);
    tokio::time::sleep(crate::limits::ms(crate::limits::helper().stop_linger_ms())).await;
    ipc::remove_control_file(state_dir);
    if let Some(a) = advertiser {
        a.stop();
    }
    drop(endpoint);
    print_line("stopped");
    match ended.and_then(|end| end.error()) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// The next connection to the ws listener; never without one.
async fn accept_ws(
    listener: &Option<tokio::net::TcpListener>,
) -> Result<(TcpStream, SocketAddr), mousse_net_io::NetError> {
    match listener {
        Some(listener) => accept_tcp(listener).await,
        None => std::future::pending().await,
    }
}

/// One connection to the ws listener: the upgrade under its caps and
/// checks, then step 1 and step 2 over the ws pipe.
async fn ws_connection(
    host: Host,
    app: Option<crate::app::App>,
    stream: TcpStream,
    addr: SocketAddr,
    slot: Option<PreAuthSlot>,
) {
    let fence = host.clone();
    let accepted = ws::accept(stream, crate::limits::get().net.io(), move || {
        fence.fence_covers(ListenerKind::Ws)
    })
    .await;
    let pipe = match accepted {
        Ok(pipe) => pipe,
        Err(refusal) => {
            print_line(format!("refused ws {addr}: {refusal}"));
            return;
        }
    };
    let slot = match slot {
        Some(slot) => slot,
        None => match host.admit(ListenerKind::Ws, None) {
            Ok(slot) => slot,
            Err(why) => {
                print_line(format!("dropped ws {addr}: {why}"));
                return;
            }
        },
    };
    let Some(conn) = accept_holding(&host, pipe, addr, slot).await else {
        return;
    };
    match app {
        Some(app) => {
            app.inbound(conn, RouteKind::Ws, None, None).await;
        }
        None => serve_streams(&host, conn, addr).await,
    }
}

/// The next control connection.
async fn accept_control(control: &mut Option<ControlListener>) -> Result<Channel, String> {
    match control {
        Some(control) => control.accept().await,
        None => std::future::pending().await,
    }
}

/// App mode: an inbound connection goes to the app once it is live.
async fn app_connection(
    host: Host,
    app: crate::app::App,
    pipe: TcpStream,
    addr: SocketAddr,
    slot: PreAuthSlot,
    closing: watch::Receiver<bool>,
) {
    // The listener's own address: a check's class map names its port.
    let local = pipe.local_addr().ok();
    if let Some(conn) = accept_holding(&host, pipe, addr, slot).await {
        if let Some(no) = app.inbound(conn, RouteKind::Tcp, Some(addr), local).await {
            app.close_with_socket(no, closing);
        }
    }
}

async fn handle_connection(
    host: Host,
    pipe: TcpStream,
    addr: SocketAddr,
    slot: PreAuthSlot,
    mut closing: watch::Receiver<bool>,
) {
    let Some(conn) = accept_holding(&host, pipe, addr, slot).await else {
        return;
    };
    // The socket that accepted it closing ends it too.
    tokio::select! {
        () = serve_streams(&host, conn, addr) => {}
        _ = closing.wait_for(|closed| *closed) => {}
    }
}

/// The roles standalone `serve` opens a terminal for. A terminal is a shell
/// as this user, so only the owner's own devices get one.
pub const TERMINAL_ROLES: &[&str] = &[Role::OWNER];

/// Whether standalone `serve` opens a terminal for `conn` now: it is live
/// under a served grant whose role [`TERMINAL_ROLES`] names. Read when the
/// stream arrives, so an edit made since the connection came up counts.
fn may_open_terminal(host: &Host, conn: &mousse_net_io::Connection) -> bool {
    // Must-fail control (tests only): the role is not looked at.
    host.grant_of(conn.id()).is_some_and(|g| {
        cfg!(mousse_control = "restricted-grant-opens-standalone-terminal")
            || TERMINAL_ROLES.contains(&g.role.as_str())
    })
}

/// Standalone `serve`: terminals (for [`TERMINAL_ROLES`]) and
/// `helper-info` for a live connection.
async fn serve_streams(host: &Host, conn: mousse_net_io::Connection, addr: SocketAddr) {
    let peer = short_id(conn.peer());
    print_line(format!("connected {peer} from {addr}"));
    while let Some(stream) = conn.accept_stream().await {
        if stream.label() == term::LABEL {
            if !may_open_terminal(host, &conn) {
                stream.writer.reset(ErrorCode::RefusedStream);
                continue;
            }
            tokio::spawn(term::serve(stream));
        } else if stream.label() == INFO_LABEL {
            tokio::spawn(send_info(stream));
        } else {
            stream.writer.reset(ErrorCode::RefusedStream);
        }
    }
    let reason = conn.closed().await;
    print_line(format!("closed {peer}: {reason}"));
}

/// The stream label on which a paired caller asks for this host's build.
pub const INFO_LABEL: &str = "helper-info";

/// Answer a `helper-info` stream: `{"build": ...}`, then finish.
///
/// The request is the stream itself, so the caller finishes its side right
/// after opening it. The answer goes out once that `FIN` arrives: both
/// halves then end cleanly and the stream does not stay half open. A
/// requester that sends data or does not finish in time gets the stream
/// reset instead.
pub(crate) async fn send_info(stream: mousse_net_io::MuxStream) {
    let (mut reader, writer) = stream.split();
    // `INFO_REQUEST_WAIT_MS` to finish the (empty) request.
    let wait = crate::limits::ms(crate::limits::helper().info_request_wait_ms());
    let request_ended = tokio::time::timeout(wait, reader.read()).await;
    if !matches!(request_ended, Ok(Ok(None))) {
        writer.reset(ErrorCode::ProtocolError);
        return;
    }
    let line = json!({"build": crate::BUILD}).to_string();
    if writer.write(line.as_bytes()).await.is_ok() {
        writer.finish();
    }
}

/// The id of one approval question: the joining connection and the full
/// fingerprint of the device shown.
fn request_id(req: &ApprovalRequest) -> String {
    format!("{}-{}", req.conn.0, hex(&req.joiner.fingerprint()))
}

fn on_event(state: &State, event: HostEvent) {
    let waiter = |id: &InvitationId| state.waiters.lock().ok().and_then(|w| w.get(id).cloned());
    match event {
        HostEvent::ApprovalRequested(req) => {
            let device = short_id(&req.joiner);
            match waiter(&req.invitation) {
                Some(tx) => {
                    let id = request_id(&req);
                    print_line(format!(
                        "approval requested for {} ({device}) request {id}",
                        crate::printable(&req.name)
                    ));
                    let _ = tx.send(json!({
                        "event": "approval",
                        "request": id,
                        "name": req.name,
                        "device": device,
                    }));
                    if let Ok(mut p) = state.pending.lock() {
                        p.insert(id, req);
                    }
                }
                None => {
                    print_line(format!(
                        "approval needed for {} ({device}) but no invite is waiting; declining",
                        crate::printable(&req.name)
                    ));
                    state.host.decline(&req.invitation);
                }
            }
        }
        HostEvent::ShowCode {
            invitation, code, ..
        } => {
            // Only the inviting command shows the code; it is never logged.
            if let Some(tx) = waiter(&invitation) {
                let _ = tx.send(json!({"event": "code", "code": code.as_str()}));
            }
        }
        HostEvent::Enrolled {
            invitation,
            grant,
            identity,
            role,
        } => {
            print_line(format!(
                "enrolled grant {} {} as {}",
                grant.0,
                short_id(&identity),
                role.as_str()
            ));
            if let Some(tx) = waiter(&invitation) {
                let _ = tx.send(
                    json!({"event": "enrolled", "grant": grant.0, "device": short_id(&identity)}),
                );
            }
        }
        HostEvent::InvitationEnded { invitation, reason } => {
            print_line(format!("invitation ended: {reason:?}"));
            if let Some(tx) = waiter(&invitation) {
                let _ = tx.send(json!({"event": "ended", "reason": format!("{reason:?}")}));
            }
        }
        HostEvent::ChannelsClosed { grant, connections } => {
            print_line(format!(
                "grant {} closed {connections} connection(s)",
                grant.0
            ));
        }
        HostEvent::RoleChanged {
            grant,
            role,
            revision,
        } => print_line(format!(
            "grant {} is {} now (revision {revision})",
            grant.0,
            role.as_str()
        )),
        HostEvent::StoreFailed(e) => print_line(format!("saving grants failed: {e}")),
    }
}

fn reply_error(msg: impl Into<String>) -> Value {
    json!({"error": msg.into()})
}

fn grants_json(host: &Host) -> Value {
    let list: Vec<Value> = host
        .grants()
        .into_iter()
        .map(|g| {
            json!({
                "id": g.id.0,
                "name": g.name,
                "device": short_id(&g.identity),
                "role": format!("{:?}", g.role),
                "granted_at": g.granted_at.secs(),
                "connections": host.connections_for(g.id),
            })
        })
        .collect();
    json!({ "grants": list })
}

async fn control_session(state: Arc<State>, mut ch: Channel) {
    let Ok(Some(request)) = ch.recv_first().await else {
        return;
    };
    let token = request.get("token").and_then(Value::as_str).unwrap_or("");
    if !ipc::token_matches(token, &state.token) {
        let _ = ch.send(&reply_error("bad control token")).await;
        return;
    }
    let cmd = request.get("cmd").and_then(Value::as_str).unwrap_or("");
    let reply = match cmd {
        "status" => json!({
            "device": short_id(&state.ticket_identity),
            "identity": hex(state.ticket_identity.as_bytes()),
            "routes": state.listen.lock().unwrap_or_else(|e| e.into_inner()).routes,
            "build": crate::BUILD,
        }),
        "grants" => grants_json(&state.host),
        "remove" => {
            let Some(id) = request.get("grant").and_then(Value::as_u64) else {
                let _ = ch.send(&reply_error("remove needs a grant id")).await;
                return;
            };
            let deny = request
                .get("deny")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let grant = state
                .host
                .grants()
                .into_iter()
                .find(|g| g.id == GrantId(id));
            let saved = match &grant {
                None => Ok(false),
                Some(g) if deny => state.host.deny(g.identity).map(|()| true),
                Some(_) => state.host.remove_grant(GrantId(id)),
            };
            match (grant, saved) {
                (None, _) | (_, Ok(false)) => reply_error(format!("no grant {id}")),
                (Some(_), Ok(true)) => json!({"removed": id, "denied": deny}),
                (Some(_), Err(e)) => reply_error(format!(
                    "grant {id} no longer has access, but saving that failed ({e}); \
                     the host keeps retrying, and if it stops before a retry works \
                     the grant is back after a restart"
                )),
            }
        }
        "stop" => {
            let _ = ch.send(&json!({"stopping": true})).await;
            state.stop.notify_one();
            return;
        }
        "invite" => {
            let link = request
                .get("link")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            invite_session(&state, &mut ch, link).await;
            return;
        }
        other => reply_error(format!("unknown command {other:?}")),
    };
    let _ = ch.send(&reply).await;
}

/// App mode's control connection (Phase 1b §3.3): it holds a pipe pool
/// place from accept (`slot`), and answers only `pipe` and `status`.
/// `pipe` hands the stream, with whatever the line reader already holds,
/// to the host as an inbound connection; the place passes on with it.
async fn app_control_session(
    host: Host,
    app: crate::app::App,
    state: Arc<State>,
    mut ch: Channel,
    slot: Result<PreAuthSlot, mousse_net_io::Refusal>,
) {
    let slot = match slot {
        Ok(slot) => slot,
        Err(why) => {
            print_line(format!("refused pipe: {why}"));
            let _ = ch
                .send(&json!({"error": "refused", "reason": why.to_string()}))
                .await;
            return;
        }
    };
    let Ok(Some(request)) = ch.recv_first().await else {
        return;
    };
    let token = request.get("token").and_then(Value::as_str).unwrap_or("");
    // Control (tests only): a pipe is handed over without the token.
    let token_ok = ipc::token_matches(token, &state.token);
    let cmd = request.get("cmd").and_then(Value::as_str).unwrap_or("");
    if cmd == "pipe" && (token_ok || cfg!(mousse_control = "pipe-no-token")) {
        if ch.send(&json!({"ok": true})).await.is_err() {
            return;
        }
        let pipe = ch.into_pipe();
        let conn = match host.accept_admitted(pipe, slot).await {
            Ok(conn) => conn,
            Err(e) => {
                print_line(format!("refused pipe: {e}"));
                return;
            }
        };
        app.inbound(conn, RouteKind::Ssh, None, None).await;
        return;
    }
    drop(slot);
    let reply = if !token_ok {
        json!({"error": "refused", "reason": "bad control token"})
    } else if cmd == "status" {
        json!({
            "device": short_id(&state.ticket_identity),
            "identity": hex(state.ticket_identity.as_bytes()),
            "build": crate::BUILD,
            "app": true,
        })
    } else {
        reply_error("This profile is run by Mousse; use mousse-cli net-engine")
    };
    let _ = ch.send(&reply).await;
}

/// One invitation, from ticket to enrolment. In person, the approval
/// question is answered over the control channel; with a send link, each
/// fresh code is sent to the inviting command to show.
async fn invite_session(state: &State, ch: &mut Channel, link: bool) {
    let kind = if link {
        InvitationKind::SendLink
    } else {
        InvitationKind::InPerson
    };
    let routes = state
        .listen
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .routes
        .clone();
    let created = match state.host.invite(kind, routes.clone()) {
        Ok(c) => c,
        Err(e) => {
            let _ = ch.send(&reply_error(e.to_string())).await;
            return;
        }
    };
    let invitation = created.ticket.invitation;
    let fragment = created.fragment;
    let (tx, mut rx) = mpsc::unbounded_channel();
    if let Ok(mut w) = state.waiters.lock() {
        w.insert(invitation, tx);
    }
    let sent = ch
        .send(&json!({"ticket": fragment, "routes": routes, "expires_at": created.ticket.expires_at.secs()}))
        .await;
    let mut finished = sent.is_err();
    while !finished {
        tokio::select! {
            event = rx.recv() => match event {
                Some(event) => {
                    let last = matches!(event.get("event").and_then(Value::as_str), Some("enrolled" | "ended"));
                    if ch.send(&event).await.is_err() || last {
                        finished = true;
                    }
                }
                None => finished = true,
            },
            answer = ch.recv() => match answer {
                Ok(Some(msg)) => {
                    let yes = msg.get("answer").and_then(Value::as_bool).unwrap_or(false);
                    let id = msg.get("request").and_then(Value::as_str).unwrap_or("");
                    // Only the exact request the answer names, and only one
                    // of this invitation's.
                    let req = state.pending.lock().ok().and_then(|mut p| {
                        match p.get(id) {
                            Some(r) if r.invitation == invitation => p.remove(id),
                            _ => None,
                        }
                    });
                    match req {
                        Some(req) if yes => {
                            if let Err(e) = state.host.approve(&req) {
                                let _ = ch
                                    .send(&json!({"event": "stale", "request": id, "error": e.to_string()}))
                                    .await;
                            }
                        }
                        Some(_) => state.host.decline(&invitation),
                        None => {
                            let _ = ch
                                .send(&json!({"event": "stale", "request": id, "error": "no such approval request is waiting"}))
                                .await;
                        }
                    }
                }
                // The inviting command went away: the invitation ends.
                _ => {
                    state.host.cancel(&invitation);
                    finished = true;
                }
            },
        }
    }
    if let Ok(mut w) = state.waiters.lock() {
        w.remove(&invitation);
    }
    if let Ok(mut p) = state.pending.lock() {
        p.retain(|_, r| r.invitation != invitation);
    }
}

/// The default state directory: `.mousse-helper` in the user's home.
pub fn default_state_dir() -> PathBuf {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".mousse-helper")
}
