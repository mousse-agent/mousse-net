//! The caller side of the helper: join a host with a ticket, list paired
//! hosts, open terminals, and the cross-machine slice check.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mousse_net_core::pairing::{Arrival, InvitationKind, Route, Ticket, CODE_FAILED_MESSAGE};
use mousse_net_core::session_cert::CertError;
use mousse_net_core::ErrorCode;
use mousse_net_io::pipe::{connect_tcp_within, parse_route, route_uri};
use mousse_net_io::store::{hex, short_id, PeerRecord, PeerStore};
use mousse_net_io::{
    Caller, CloseReason, CodeEntry, Connection, Endpoint, JoinOutcome, NetError, Step1Failures,
    SystemClock,
};
use serde_json::json;

use crate::term::{self, ClientEnd};

/// An open endpoint and its caller.
pub struct CallerSide {
    pub endpoint: Endpoint,
    pub caller: Caller,
}

impl CallerSide {
    /// Open the endpoint in `dir` (taking its lock) and load its key.
    /// Pairing flow records (attempts left per ticket) live in the
    /// endpoint's owner-only state, so they survive a restart.
    pub fn open(dir: &Path, insecure_file_key: bool) -> Result<Self, String> {
        let endpoint = crate::open_endpoint(dir, true)?;
        let key = endpoint
            .load_identity(insecure_file_key)
            .map_err(|e| e.to_string())?;
        let mut caller = Caller::new(
            Arc::new(key),
            Arc::new(SystemClock::new()),
            crate::limits::get().net,
        );
        caller.use_flow_records(Arc::new(endpoint.flow_records()));
        Ok(Self { endpoint, caller })
    }

    fn peers(&self) -> PeerStore {
        PeerStore::in_dir(self.endpoint.dir())
    }
}

/// Parse a ticket given as the bare fragment or as a link with `#`.
pub fn parse_ticket(text: &str) -> Result<Ticket, String> {
    let fragment = text.trim().rsplit('#').next().unwrap_or("");
    Ticket::from_fragment(fragment).map_err(|e| format!("bad ticket: {e:?}"))
}

/// How long a TCP connect may take (`CONNECT_TIMEOUT_MS`).
fn connect_timeout() -> Duration {
    crate::limits::ms(crate::limits::get().net.io().connect_timeout_ms())
}

/// Wall-clock now, in Unix seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Routes typed on the command line: each must parse.
fn parse_routes(list: &[String]) -> Result<Vec<Route>, String> {
    list.iter()
        .map(|r| parse_route(r).map_err(|e| e.to_string()))
        .collect()
}

/// Routes from a ticket or the peer store: hints this version cannot use
/// (unknown or reserved schemes, mDNS names without a browser) are skipped.
fn usable_routes(hints: &[String]) -> Vec<Route> {
    hints
        .iter()
        .filter_map(|h| Route::parse(h).ok())
        .filter(|r| matches!(r, Route::Tcp { .. }))
        .collect()
}

/// Asks for the send-link code on the terminal.
pub struct TypedCode;

impl CodeEntry for TypedCode {
    async fn code(&mut self, retry: Option<u8>) -> Option<String> {
        match retry {
            None => println!("Type the 6-digit code shown on the host:"),
            Some(left) => {
                println!("{CODE_FAILED_MESSAGE}");
                println!(
                    "Type the new code shown on the host ({left} {} left):",
                    if left == 1 { "try" } else { "tries" }
                );
            }
        }
        tokio::task::spawn_blocking(|| {
            let mut line = String::new();
            match std::io::stdin().read_line(&mut line) {
                Ok(0) | Err(_) => None,
                Ok(_) => Some(line.trim().to_owned()),
            }
        })
        .await
        .ok()
        .flatten()
    }
}

/// A failed step: what happened, and one word for why (`pin_mismatch`,
/// `grant_revoked`, ...), as test results record it.
#[derive(Debug)]
pub struct Failure {
    pub text: String,
    pub reason: String,
}

impl Failure {
    fn new(text: impl Into<String>, reason: &str) -> Self {
        Self {
            text: text.into(),
            reason: reason.into(),
        }
    }

    fn of(e: &NetError) -> Self {
        Self {
            text: describe(e),
            reason: reason_of(e),
        }
    }
}

impl From<Failure> for String {
    fn from(f: Failure) -> Self {
        f.text
    }
}

/// One lowercase word for why a connection failed or closed.
pub fn reason_of(e: &NetError) -> String {
    match e {
        NetError::PeerCertificate(mousse_net_core::session_cert::CertError::PinMismatch) => {
            "pin_mismatch".into()
        }
        NetError::PeerCertificate(_) => "peer_certificate".into(),
        NetError::Closed(reason) => match reason.code() {
            Some(code) => code.name().to_lowercase(),
            None => "connection_dropped".into(),
        },
        NetError::Join(e) => match e.code() {
            Some(code) => code.name().to_lowercase(),
            None => "pairing_refused".into(),
        },
        NetError::Store(_) => "store".into(),
        NetError::Tls(_) => "tls".into(),
        NetError::Timeout(_) => "timeout".into(),
        NetError::Io(_) => "unreachable".into(),
        _ => "error".into(),
    }
}

/// The name a joining device sends in its join proof (wire.md 10.3): with
/// a send link the computer name only, since the far end has not yet shown
/// it is the real host; in person the name chosen (default: the computer
/// name).
pub fn join_name(ticket: &Ticket, chosen: Option<String>, computer: String) -> String {
    match (ticket.kind, chosen) {
        (InvitationKind::SendLink, Some(_)) => {
            println!("a send link sends only this computer's name; --name is not used");
            computer
        }
        (_, chosen) => chosen.unwrap_or(computer),
    }
}

/// Pair with the host in `ticket`, trying `routes` (default: the ticket's).
/// `arrival` says how the ticket reached this device: an in-person ticket
/// pairs only from a scan of the host's screen. Stores the host's pin on
/// success.
pub async fn join(
    side: &CallerSide,
    ticket: &Ticket,
    arrival: Arrival,
    name: &str,
    routes: &[String],
) -> Result<(Connection, PeerRecord), Failure> {
    if ticket.kind == InvitationKind::InPerson && arrival == Arrival::Link {
        return Err(Failure::new(
            "this is an in-person ticket: scan it from the host's screen (pass --in-person \
             only when you did); a ticket sent another way cannot pair (PAIRING_FAILED)",
            "pairing_failed",
        ));
    }
    let candidates = if routes.is_empty() {
        usable_routes(&ticket.routes)
    } else {
        parse_routes(routes).map_err(|e| Failure::new(e, "bad_route"))?
    };
    if candidates.is_empty() {
        return Err(Failure::new(
            "the ticket has no usable address; pass --route tcp://host:port",
            "no_route",
        ));
    }
    // A send link may end "already paired" only for a host pinned before.
    let pinned = side.peers().load().is_ok_and(|ps| {
        ps.iter()
            .any(|p| p.pin().ok() == Some(ticket.host_identity))
    });
    if ticket.kind == InvitationKind::SendLink {
        println!("joining with a link; the code is shown on the host");
    } else {
        println!("joining; the host owner is asked to confirm");
    }
    let mut last = Failure::new("no route answered", "unreachable");
    // Any step 1 failure on an address means "try the next one"; one is
    // shown only when no address passed (wire.md 5.4).
    let mut step1 = Step1Failures::default();
    for route in &candidates {
        let hint = route_uri(route);
        let pipe = match connect_tcp_within(route, connect_timeout()).await {
            Ok(p) => p,
            Err(e) => {
                last = Failure::new(format!("{hint}: {e}"), "unreachable");
                continue;
            }
        };
        // If the connection drops before PAIRED, the join reconnects here
        // to learn whether the host enrolled this device.
        let redial = || connect_tcp_within(route, connect_timeout());
        match side
            .caller
            .join_with_redial(pipe, ticket, arrival, name, &mut TypedCode, pinned, redial)
            .await
        {
            Ok((conn, outcome)) => {
                // Built from the stored record as it is under the lock, so
                // a write by another process meanwhile is not undone.
                let mut stored = None;
                side.peers()
                    .update(|peers| {
                        let existing = peers
                            .iter()
                            .find(|p| p.pin().ok() == Some(ticket.host_identity));
                        let (host_name, role) = match outcome {
                            JoinOutcome::Paired(host) => (host.name, format!("{:?}", host.role)),
                            JoinOutcome::AlreadyPaired => match existing {
                                Some(p) => (p.name.clone(), p.role.clone()),
                                None => (short_id(&ticket.host_identity), "unknown".into()),
                            },
                        };
                        let record = PeerRecord {
                            name: host_name,
                            identity: hex(ticket.host_identity.as_bytes()),
                            role,
                            routes: ticket.routes.clone(),
                            last_route: Some(hint.clone()),
                            paired_at: now_secs(),
                        };
                        peers.retain(|p| p.pin().ok() != Some(ticket.host_identity));
                        peers.push(record.clone());
                        stored = Some(record);
                    })
                    .map_err(|e| Failure::new(e.to_string(), "store"))?;
                let record = stored.expect("the update ran");
                // The pin is stored: the join's outcome is no longer pending.
                side.caller
                    .pin_stored(ticket)
                    .map_err(|e| Failure::new(e.to_string(), "store"))?;
                side.caller
                    .remember_routes(ticket.host_identity, vec![route.clone()]);
                return Ok((conn, record));
            }
            // Another endpoint at this address: try the next one.
            Err(NetError::PeerCertificate(CertError::PinMismatch)) => {
                step1.note(CertError::PinMismatch);
                last = Failure::new(
                    format!("{hint}: another device answered (pin mismatch)"),
                    "pin_mismatch",
                );
            }
            // Any other certificate failure: the next address may pass.
            Err(NetError::PeerCertificate(e)) => {
                step1.note(e);
                last = Failure::of(&NetError::PeerCertificate(e));
            }
            // A step 1 failure of another kind (TLS, timeout, no answer):
            // the next address may pass too.
            Err(e) if e.is_step1() => {
                last = Failure::new(format!("{hint}: {}", describe(&e)), &reason_of(&e));
            }
            Err(e) => return Err(Failure::of(&e)),
        }
    }
    match step1.report() {
        Some(e) => Err(Failure::of(&e)),
        None => Err(last),
    }
}

/// A readable reason for a failed or closed connection.
pub fn describe(e: &NetError) -> String {
    match e {
        NetError::Closed(reason) => describe_close(reason),
        NetError::PeerCertificate(c) => format!("the host's identity was refused: {c}"),
        NetError::Join(e) => match e.code() {
            Some(code) => format!("pairing: {e} ({})", code.name().to_uppercase()),
            None => format!("pairing: {e}"),
        },
        other => other.to_string(),
    }
}

fn describe_close(reason: &CloseReason) -> String {
    match reason.code() {
        Some(ErrorCode::GrantRevoked) => "the host removed this device (GRANT_REVOKED)".into(),
        Some(ErrorCode::NotAuthorized) => {
            "the host does not know this device (NOT_AUTHORIZED)".into()
        }
        Some(ErrorCode::InvitationInvalid) => {
            "the ticket is used, expired or unknown (INVITATION_INVALID)".into()
        }
        Some(ErrorCode::PairingDeclined) => "the host owner said no (PAIRING_DECLINED)".into(),
        Some(ErrorCode::AttemptsExhausted) => format!(
            "{CODE_FAILED_MESSAGE} No tries are left; the invitation ended (ATTEMPTS_EXHAUSTED)"
        ),
        _ => format!("connection closed: {reason}"),
    }
}

/// Find a paired host by name or by the start of its fingerprint.
pub fn find_peer(side: &CallerSide, query: &str) -> Result<PeerRecord, String> {
    let peers = side.peers().load().map_err(|e| e.to_string())?;
    let matches: Vec<PeerRecord> = peers
        .into_iter()
        .filter(|p| {
            p.name == query
                || p.pin()
                    .map(|pin| short_id(&pin).starts_with(&query.to_lowercase()))
                    .unwrap_or(false)
        })
        .collect();
    match matches.len() {
        0 => Err(format!("no paired host matches {query:?}")),
        1 => Ok(matches.into_iter().next().unwrap_or_else(|| unreachable!())),
        _ => Err(format!(
            "{query:?} matches more than one host; use its device id"
        )),
    }
}

/// Dial a paired host. A candidate address with another identity is
/// skipped; the stored pin never changes.
pub async fn dial(
    side: &CallerSide,
    peer: &PeerRecord,
    routes: &[String],
) -> Result<Connection, String> {
    let pin = peer.pin().map_err(|e| e.to_string())?;
    let candidates = if routes.is_empty() {
        usable_routes(&peer.routes_to_try())
    } else {
        parse_routes(routes)?
    };
    let (conn, used) = side
        .caller
        .dial_candidates(&candidates, pin)
        .await
        .map_err(|e| describe(&e))?;
    // Only the route is noted, on the record as stored now: a re-pair of
    // this host meanwhile keeps its name, role and routes.
    let _ = side.peers().note_route(&pin, route_uri(&used));
    Ok(conn)
}

/// `peers`: the hosts this endpoint paired with.
pub fn print_peers(dir: &Path) -> Result<(), String> {
    let peers = PeerStore::in_dir(dir).load().map_err(|e| e.to_string())?;
    if peers.is_empty() {
        println!("no paired hosts");
    }
    for p in peers {
        let id = p.pin().map(|k| short_id(&k)).unwrap_or_default();
        println!(
            "{id}  {}  {}  {}",
            crate::printable(&p.name),
            p.role,
            p.routes_to_try().join(" ")
        );
    }
    Ok(())
}

/// `term`: returns the process exit code.
pub async fn term(side: &CallerSide, query: &str, routes: &[String], argv: Vec<String>) -> i32 {
    let peer = match find_peer(side, query) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let conn = match dial(side, &peer, routes).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("refused: {e}");
            return 2;
        }
    };
    match term::run_client(&conn, argv).await {
        Ok(ClientEnd::Exited(code)) => code,
        Ok(ClientEnd::Closed(e)) | Err(e) => {
            eprintln!("\r\nclosed: {}", describe(&e));
            3
        }
    }
}

/// Options for the cross-machine slice check.
pub struct SliceCheck {
    pub ticket: String,
    /// How the ticket reached this device.
    pub arrival: Arrival,
    /// The name chosen with --name (see [`join_name`]).
    pub name: Option<String>,
    pub routes: Vec<String>,
    pub command: Vec<String>,
    pub removal_timeout: Duration,
    pub out: Option<std::path::PathBuf>,
    pub control: Option<String>,
    /// The host's build as its `serve` printed it, for runs that never get
    /// to ask the host (a control that fails before pairing).
    pub host_build: Option<String>,
    pub target: String,
}

struct Steps {
    lines: Vec<String>,
    ok: bool,
    /// Why the first failed step failed.
    reason: Option<String>,
    /// The host's build, as the host reported it.
    host_build: Option<String>,
}

impl Steps {
    fn pass(&mut self, line: String) {
        println!("PASS {line}");
        self.lines.push(format!("PASS {line}"));
    }

    fn fail(&mut self, line: String, reason: &str) {
        let line = format!("{line} reason={reason}");
        println!("FAIL {line}");
        self.lines.push(format!("FAIL {line}"));
        self.ok = false;
        self.reason.get_or_insert_with(|| reason.to_owned());
    }
}

/// Run the slice from this side against a host that is serving with an
/// open invitation: pair, run a command in a terminal, keep a terminal open
/// until the host removes this device, then check a new connection is
/// refused. Writes a result file for the owner test kit.
pub async fn slice_check(side: &CallerSide, opts: SliceCheck) -> i32 {
    let mut steps = Steps {
        lines: Vec::new(),
        ok: true,
        reason: None,
        host_build: None,
    };
    run_slice(side, &opts, &mut steps).await;
    // The host's own report wins; the operator's copy fills in when the run
    // never got that far, and must agree when both exist.
    let host_build = match (steps.host_build.clone(), opts.host_build.clone()) {
        (Some(reported), Some(given)) if reported != given => {
            steps.fail(
                format!(
                    "the host reports build {}, not {}",
                    crate::printable(&reported),
                    crate::printable(&given)
                ),
                "host_build_mismatch",
            );
            Some(reported)
        }
        (reported, given) => reported.or(given),
    };
    let outcome = if steps.ok { "PASS" } else { "FAIL" };
    let mut result = json!({
        "check": "phase0.thin-slice-cross-machine",
        "target": opts.target,
        "outcome": outcome,
        "details": steps.lines.join("; "),
        // `build` is the caller's, this binary's.
        "build": crate::BUILD,
        "caller_build": crate::BUILD,
    });
    match host_build {
        Some(b) => result["host_build"] = json!(b),
        None => println!("NOTE the host's build is unknown (pass --host-build)"),
    }
    if let Some(reason) = &steps.reason {
        result["reason"] = json!(reason);
    }
    if let Some(control) = &opts.control {
        result["control"] = json!(control);
    }
    let text = serde_json::to_string_pretty(&result).unwrap_or_default();
    match &opts.out {
        Some(path) => {
            if let Err(e) = mousse_net_io::store::write_atomic(path, text.as_bytes()) {
                eprintln!("cannot write {}: {e}", path.display());
                return 2;
            }
            println!("result written to {}", path.display());
        }
        None => println!("{text}"),
    }
    println!("RESULT {outcome}");
    if steps.ok {
        0
    } else {
        1
    }
}

async fn run_slice(side: &CallerSide, opts: &SliceCheck, steps: &mut Steps) {
    let ticket = match parse_ticket(&opts.ticket) {
        Ok(t) => t,
        Err(e) => return steps.fail(format!("ticket: {e}"), "bad_ticket"),
    };
    let what = match ticket.kind {
        InvitationKind::SendLink => "pair with a send link",
        _ => "pair in person",
    };
    let name = join_name(&ticket, opts.name.clone(), crate::computer_name());
    let (conn, peer) = match join(side, &ticket, opts.arrival, &name, &opts.routes).await {
        Ok(v) => v,
        Err(e) => return steps.fail(format!("{what}: {}", e.text), &e.reason),
    };
    steps.pass(format!(
        "paired with {} ({}) via {} using {}",
        crate::printable(&peer.name),
        short_id(&ticket.host_identity),
        peer.last_route.clone().unwrap_or_default(),
        conn.kx_group()
    ));
    match host_build(&conn).await {
        Ok(build) => {
            steps.pass(format!("the host runs build {}", crate::printable(&build)));
            steps.host_build = Some(build);
        }
        Err(e) => return steps.fail(format!("ask the host for its build: {e}"), "host_build"),
    }

    match capture(&conn, opts.command.clone()).await {
        Ok((0, output)) if !output.trim().is_empty() => {
            let first = output
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .unwrap_or("");
            steps.pass(format!(
                "terminal ran {:?}: {}",
                opts.command.join(" "),
                crate::printable(first)
            ));
        }
        Ok((code, output)) => {
            return steps.fail(
                format!("terminal command exited {code}: {:?}", output.trim()),
                "command_failed",
            )
        }
        Err(e) => return steps.fail(format!("terminal: {e}"), "terminal"),
    }

    // A live terminal that the removal must close.
    let stream = match conn
        .open_stream(
            mousse_net_core::mux::PriorityClass::Interactive,
            term::LABEL,
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            return steps.fail(
                format!("open a second terminal: {}", describe(&e)),
                &reason_of(&e),
            )
        }
    };
    let (mut rd, wr) = stream.split();
    let open = term::Frame::Open {
        cols: 80,
        rows: 24,
        argv: Vec::new(),
    };
    if let Err(e) = wr.write(&open.encode()).await {
        return steps.fail(
            format!("open a second terminal: {}", describe(&e)),
            &reason_of(&e),
        );
    }
    println!(
        "WAITING remove this device on the host (grant for {:?}) within {} s",
        name,
        opts.removal_timeout.as_secs()
    );
    let drain = async {
        loop {
            match rd.read().await {
                Ok(Some(_)) => continue,
                Ok(None) => return None,
                Err(e) => return Some(e),
            }
        }
    };
    match tokio::time::timeout(opts.removal_timeout, drain).await {
        Ok(Some(NetError::Closed(reason))) if reason.code() == Some(ErrorCode::GrantRevoked) => {
            steps.pass("removal closed the live terminal with GRANT_REVOKED".into())
        }
        Ok(Some(e)) => {
            return steps.fail(
                format!("the terminal ended another way: {}", describe(&e)),
                &reason_of(&e),
            )
        }
        Ok(None) => {
            return steps.fail(
                "the terminal ended before the removal".into(),
                "ended_early",
            )
        }
        Err(_) => return steps.fail("no removal within the time limit".into(), "timeout"),
    }
    drop(conn);

    match dial(side, &peer, &opts.routes).await {
        Ok(_) => steps.fail(
            "a new connection was accepted after the removal".into(),
            "still_authorized",
        ),
        Err(e) if e.contains("NOT_AUTHORIZED") => {
            steps.pass(format!("a new connection was refused: {e}"))
        }
        Err(e) => steps.fail(
            format!("a new connection failed another way: {e}"),
            "refused_otherwise",
        ),
    }
}

/// Ask the host for its build over a `helper-info` stream.
async fn host_build(conn: &Connection) -> Result<String, String> {
    let stream = conn
        .open_stream(
            mousse_net_core::mux::PriorityClass::Interactive,
            crate::serve::INFO_LABEL,
        )
        .await
        .map_err(|e| describe(&e))?;
    let (mut rd, wr) = stream.split();
    // The request is the stream itself: nothing more is sent, so the
    // request side ends here and the host sees a clean FIN.
    wr.finish();
    let limits = crate::limits::helper();
    let max = usize::try_from(limits.info_answer_max_bytes()).unwrap_or(usize::MAX);
    let read = async {
        let mut bytes = Vec::new();
        while let Some(chunk) = rd.read().await.map_err(|e| describe(&e))? {
            bytes.extend(chunk);
            if bytes.len() > max {
                return Err("the host's answer is too long".to_string());
            }
        }
        Ok(bytes)
    };
    let wait = crate::limits::ms(limits.info_answer_wait_ms());
    let bytes = tokio::time::timeout(wait, read)
        .await
        .map_err(|_| format!("no answer in {}", crate::limits::describe(wait)))??;
    let info: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("bad answer: {e}"))?;
    info.get("build")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "the answer names no build".into())
}

/// Run `argv` in a terminal on `conn` and collect its output.
async fn capture(conn: &Connection, argv: Vec<String>) -> Result<(i32, String), String> {
    let stream = conn
        .open_stream(
            mousse_net_core::mux::PriorityClass::Interactive,
            term::LABEL,
        )
        .await
        .map_err(|e| describe(&e))?;
    let (mut rd, wr) = stream.split();
    let open = term::Frame::Open {
        cols: 200,
        rows: 50,
        argv,
    };
    wr.write(&open.encode()).await.map_err(|e| describe(&e))?;
    let mut dec = term::Decoder::default();
    let mut output = Vec::new();
    let read = async {
        loop {
            match rd.read().await.map_err(|e| describe(&e))? {
                None => return Err("the terminal ended without an exit code".to_string()),
                Some(bytes) => {
                    dec.push(&bytes);
                    while let Some(frame) = dec.next_frame()? {
                        match frame {
                            term::Frame::Data(d) => output.extend(d),
                            term::Frame::Exit(code) => return Ok(code),
                            _ => return Err("unexpected terminal frame".into()),
                        }
                    }
                }
            }
        }
    };
    let wait = crate::limits::ms(crate::limits::helper().capture_wait_ms());
    let code = tokio::time::timeout(wait, read).await.map_err(|_| {
        format!(
            "the command did not finish in {}",
            crate::limits::describe(wait)
        )
    })??;
    Ok((code, String::from_utf8_lossy(&output).into_owned()))
}
