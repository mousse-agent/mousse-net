//! `serve`: run this endpoint's host. Accepts connections, answers the
//! local control channel (invite, grants, remove, stop) and runs terminal
//! channels for authorized peers.
//!
//! An approval question names one request: the joining connection and the
//! device shown. The answer must name the same request, so an answer never
//! applies to a different device or a newer request.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mousse_net_core::grants::GrantId;
use mousse_net_core::identity::{IdentityPublicKey, SoftwareKey};
use mousse_net_core::pairing::{CpaceExchangeFactory, InvitationId, InvitationKind};
use mousse_net_core::ErrorCode;
use mousse_net_io::discovery::{Advertiser, CachedBrowse};
use mousse_net_io::pipe::ws::{self, WsTarget};
use mousse_net_io::pipe::{accept_tcp, route_from_addr, route_uri, Pipe};
use mousse_net_io::rng::{os_rng, random_bytes};
use mousse_net_io::store::{hex, short_id};
use mousse_net_io::{
    ApprovalRequest, Caller, Host, HostConfig, HostEvent, ListenerKind, PortChoice, PreAuthSlot,
    SharedSigner,
};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};

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
    /// this port (0: any; Phase 1b §4.1). It also runs, on the kept ws
    /// port, while `tunnels` is not empty.
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

struct State {
    host: Host,
    routes: Vec<String>,
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
    if !ip.is_unspecified() {
        return vec![route_uri(&route_from_addr(SocketAddr::new(ip, port)))];
    }
    let mut out = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            let addr = iface.ip();
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
    }
    out.sort();
    out.dedup();
    out.truncate(8);
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
pub async fn run(
    state_dir: &Path,
    insecure_file_key: bool,
    opts: ServeOptions,
) -> Result<(), String> {
    let mut endpoint = crate::open_endpoint(state_dir, false)?;
    if opts.app {
        // stdout carries only app-channel frames from here on.
        crate::applog::to_file(state_dir)?;
    }
    let key = endpoint
        .load_identity(insecure_file_key)
        .map_err(|e| e.to_string())?;
    let real_identity = endpoint.identity();
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
    let choice = match opts.port {
        None => PortChoice::Kept,
        Some(0) => PortChoice::Auto,
        Some(p) => PortChoice::Fixed(p),
    };
    let listener = endpoint
        .bind(opts.listen_ip, choice)
        .await
        .map_err(|e| format!("listen: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let mut routes = route_hints(opts.listen_ip, port);
    for tunnel in &opts.tunnels {
        let target = WsTarget::parse(tunnel)
            .filter(|t| t.secure)
            .ok_or_else(|| {
                format!("--tunnel {tunnel}: not a wss://<host>[:<port>]<path>/mousse-net/1 URL")
            })?;
        routes.push(target.uri());
    }
    // The loopback ws listener, for the owner's tunnel client (§4.1).
    let ws_listener = if opts.ws_port.is_some() || !opts.tunnels.is_empty() {
        Some(
            endpoint
                .bind_ws(opts.ws_port)
                .await
                .map_err(|e| format!("ws listen: {e}"))?,
        )
    } else {
        None
    };
    let ws_port = match &ws_listener {
        Some(l) => Some(l.local_addr().map_err(|e| e.to_string())?.port()),
        None => None,
    };
    let advertiser = if opts.mdns && !opts.listen_ip.is_loopback() {
        Some(
            Advertiser::start(port, clock.clone(), crate::limits::get().net.io())
                .map_err(|e| format!("mDNS: {e}"))?,
        )
    } else {
        None
    };

    // The app channel replaces the control listener in app mode.
    let mut control = if opts.app {
        None
    } else {
        Some(ControlListener::bind(state_dir).await?)
    };
    let token = hex(&random_bytes::<32>());
    if let Some(control) = &control {
        ipc::write_control_file(state_dir, control.addr(), &token)?;
    }

    let state = Arc::new(State {
        host: host.clone(),
        routes: routes.clone(),
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
        let info = crate::app::AppInfo {
            identity: real_identity,
            name: opts.name.clone(),
            profile: endpoint.profile_id().to_owned(),
            port,
            ws_port,
            routes: routes.clone(),
            state_dir: endpoint.dir().to_path_buf(),
            // mDNS only where the helper advertises too (never on
            // loopback); debug builds may read a browse file instead.
            browse: crate::app::browse_source(opts.mdns && !opts.listen_ip.is_loopback()).map(
                |source| {
                    Arc::new(CachedBrowse::new(
                        source,
                        clock.clone(),
                        crate::limits::get().net.io(),
                    ))
                },
            ),
            manual_clock,
        };
        Some(crate::app::App::start(
            host.clone(),
            Arc::new(caller),
            removal.clone(),
            info,
        ))
    } else {
        None
    };
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
            accepted = accept_tcp(&listener) => match accepted {
                // A place in the TCP pool before anything is read; none
                // while paused (the removal is not saved yet).
                Ok((pipe, addr)) => match host.admit(ListenerKind::Tcp, Some(addr.ip())) {
                    Err(why) => {
                        print_line(format!("dropped {addr}: {why}"));
                        drop(pipe);
                    }
                    Ok(slot) => match &app {
                        Some(app) => {
                            tokio::spawn(app_connection(host.clone(), app.clone(), pipe, addr, slot));
                        }
                        None => {
                            tokio::spawn(handle_connection(host.clone(), pipe, addr, slot));
                        }
                    },
                },
                Err(e) => print_line(format!("accept failed: {e}")),
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
                Ok(ch) => {
                    tokio::spawn(control_session(state.clone(), ch));
                }
                Err(e) => print_line(format!("control channel: {e}")),
            },
            Some(change) = net_changes.recv() => {
                if let Some(advertiser) = &advertiser {
                    advertiser.refresh();
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
        Some(app) => app.inbound(conn).await,
        None => serve_streams(conn, addr).await,
    }
}

/// The next control connection; never, in app mode.
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
) {
    if let Some(conn) = accept_holding(&host, pipe, addr, slot).await {
        app.inbound(conn).await;
    }
}

async fn handle_connection(host: Host, pipe: TcpStream, addr: SocketAddr, slot: PreAuthSlot) {
    let Some(conn) = accept_holding(&host, pipe, addr, slot).await else {
        return;
    };
    serve_streams(conn, addr).await;
}

/// Standalone `serve`: terminals and `helper-info` for a live connection.
async fn serve_streams(conn: mousse_net_io::Connection, addr: SocketAddr) {
    let peer = short_id(conn.peer());
    print_line(format!("connected {peer} from {addr}"));
    while let Some(stream) = conn.accept_stream().await {
        if stream.label() == term::LABEL {
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
        } => {
            print_line(format!(
                "enrolled grant {} {}",
                grant.0,
                short_id(&identity)
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
            "routes": state.routes,
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

/// One invitation, from ticket to enrolment. In person, the approval
/// question is answered over the control channel; with a send link, each
/// fresh code is sent to the inviting command to show.
async fn invite_session(state: &State, ch: &mut Channel, link: bool) {
    let kind = if link {
        InvitationKind::SendLink
    } else {
        InvitationKind::InPerson
    };
    let created = match state.host.invite(kind, state.routes.clone()) {
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
        .send(&json!({"ticket": fragment, "routes": state.routes, "expires_at": created.ticket.expires_at.secs()}))
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
