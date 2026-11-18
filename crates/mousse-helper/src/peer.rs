//! The caller side of the helper: join a host with a ticket, list paired
//! hosts, open terminals, and the cross-machine slice check.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mousse_net_core::pairing::{InvitationKind, Route, Ticket};
use mousse_net_core::ErrorCode;
use mousse_net_io::pipe::{connect_tcp, parse_route, route_uri};
use mousse_net_io::store::{hex, short_id, PeerRecord, PeerStore};
use mousse_net_io::{
    Caller, CloseReason, CodeEntry, Connection, Endpoint, JoinOutcome, NetError, SystemClock,
    TlsPolicy,
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
    pub fn open(dir: &Path, insecure_file_key: bool) -> Result<Self, String> {
        let endpoint = crate::open_endpoint(dir, true)?;
        let key = endpoint
            .load_identity(insecure_file_key)
            .map_err(|e| e.to_string())?;
        let caller = Caller::new(
            Arc::new(key),
            Arc::new(SystemClock::new()),
            TlsPolicy::default(),
        );
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

fn now_secs() -> u64 {
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
            Some(left) => println!(
                "Wrong code. Type the new code shown on the host ({left} {} left):",
                if left == 1 { "try" } else { "tries" }
            ),
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

/// Pair with the host in `ticket`, trying `routes` (default: the ticket's).
/// Stores the host's pin on success.
pub async fn join(
    side: &CallerSide,
    ticket: &Ticket,
    name: &str,
    routes: &[String],
) -> Result<(Connection, PeerRecord), String> {
    let candidates = if routes.is_empty() {
        usable_routes(&ticket.routes)
    } else {
        parse_routes(routes)?
    };
    if candidates.is_empty() {
        return Err("the ticket has no usable address; pass --route tcp://host:port".into());
    }
    if ticket.kind == InvitationKind::SendLink {
        println!("joining with a link; the code is shown on the host");
    } else {
        println!("joining; the host owner is asked to confirm");
    }
    let mut last = String::from("no route answered");
    for route in &candidates {
        let hint = route_uri(route);
        let pipe = match connect_tcp(route).await {
            Ok(p) => p,
            Err(e) => {
                last = format!("{hint}: {e}");
                continue;
            }
        };
        match side
            .caller
            .join_with_code(pipe, ticket, name, &mut TypedCode)
            .await
        {
            Ok((conn, outcome)) => {
                let existing = side.peers().load().ok().and_then(|ps| {
                    ps.into_iter()
                        .find(|p| p.pin().ok() == Some(ticket.host_identity))
                });
                let (host_name, role) = match outcome {
                    JoinOutcome::Paired(host) => (host.name, format!("{:?}", host.role)),
                    JoinOutcome::AlreadyPaired => match &existing {
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
                side.peers()
                    .upsert(record.clone())
                    .map_err(|e| e.to_string())?;
                return Ok((conn, record));
            }
            // Another endpoint at this address: try the next one.
            Err(NetError::PeerCertificate(
                mousse_net_core::session_cert::CertError::PinMismatch,
            )) => {
                last = format!("{hint}: another device answered (pin mismatch)");
            }
            Err(e) => return Err(describe(&e)),
        }
    }
    Err(last)
}

/// A readable reason for a failed or closed connection.
pub fn describe(e: &NetError) -> String {
    match e {
        NetError::Closed(reason) => describe_close(reason),
        NetError::PeerCertificate(c) => format!("the host's identity was refused: {c}"),
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
        Some(ErrorCode::AttemptsExhausted) => {
            "too many wrong codes; the invitation ended (ATTEMPTS_EXHAUSTED)".into()
        }
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
    let mut record = peer.clone();
    record.last_route = Some(route_uri(&used));
    let _ = side.peers().upsert(record);
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
            p.name,
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
    pub name: String,
    pub routes: Vec<String>,
    pub command: Vec<String>,
    pub removal_timeout: Duration,
    pub out: Option<std::path::PathBuf>,
    pub control: Option<String>,
    pub build: Option<String>,
    pub target: String,
}

struct Steps {
    lines: Vec<String>,
    ok: bool,
}

impl Steps {
    fn pass(&mut self, line: String) {
        println!("PASS {line}");
        self.lines.push(format!("PASS {line}"));
    }

    fn fail(&mut self, line: String) {
        println!("FAIL {line}");
        self.lines.push(format!("FAIL {line}"));
        self.ok = false;
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
    };
    run_slice(side, &opts, &mut steps).await;
    let outcome = if steps.ok { "PASS" } else { "FAIL" };
    let mut result = json!({
        "check": "phase0.thin-slice-cross-machine",
        "target": opts.target,
        "outcome": outcome,
        "details": steps.lines.join("; "),
    });
    if let Some(build) = opts.build.clone().or_else(build_id) {
        result["build"] = json!(build);
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
        Err(e) => return steps.fail(format!("ticket: {e}")),
    };
    let (conn, peer) = match join(side, &ticket, &opts.name, &opts.routes).await {
        Ok(v) => v,
        Err(e) => return steps.fail(format!("pair in person: {e}")),
    };
    steps.pass(format!(
        "paired with {} ({}) via {} using {}",
        peer.name,
        short_id(&ticket.host_identity),
        peer.last_route.clone().unwrap_or_default(),
        conn.kx_group()
    ));

    match capture(&conn, opts.command.clone()).await {
        Ok((0, output)) if !output.trim().is_empty() => {
            let first = output
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .unwrap_or("");
            steps.pass(format!(
                "terminal ran {:?}: {first}",
                opts.command.join(" ")
            ));
        }
        Ok((code, output)) => {
            return steps.fail(format!(
                "terminal command exited {code}: {:?}",
                output.trim()
            ))
        }
        Err(e) => return steps.fail(format!("terminal: {e}")),
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
        Err(e) => return steps.fail(format!("open a second terminal: {}", describe(&e))),
    };
    let (mut rd, wr) = stream.split();
    let open = term::Frame::Open {
        cols: 80,
        rows: 24,
        argv: Vec::new(),
    };
    if let Err(e) = wr.write(&open.encode()).await {
        return steps.fail(format!("open a second terminal: {}", describe(&e)));
    }
    println!(
        "WAITING remove this device on the host (grant for {:?}) within {} s",
        opts.name,
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
            return steps.fail(format!("the terminal ended another way: {}", describe(&e)))
        }
        Ok(None) => return steps.fail("the terminal ended before the removal".into()),
        Err(_) => return steps.fail("no removal within the time limit".into()),
    }
    drop(conn);

    match dial(side, &peer, &opts.routes).await {
        Ok(_) => steps.fail("a new connection was accepted after the removal".into()),
        Err(e) if e.contains("NOT_AUTHORIZED") => {
            steps.pass(format!("a new connection was refused: {e}"))
        }
        Err(e) => steps.fail(format!("a new connection failed another way: {e}")),
    }
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
    let code = tokio::time::timeout(Duration::from_secs(30), read)
        .await
        .map_err(|_| "the command did not finish in 30 s".to_string())??;
    Ok((code, String::from_utf8_lossy(&output).into_owned()))
}

/// `<commit>[-dirty]+<profile>` for the checkout in the current directory,
/// if git is available.
fn build_id() -> Option<String> {
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
    };
    let commit = git(&["rev-parse", "HEAD"])?;
    let dirty = !git(&["status", "--porcelain", "--untracked-files=no"])?.is_empty();
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    Some(format!(
        "{commit}{}+{profile}",
        if dirty { "-dirty" } else { "" }
    ))
}
