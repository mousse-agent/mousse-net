//! The caller side of the helper: join a host with a ticket, list paired
//! hosts, open terminals, and the cross-machine slice check.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mousse_net_core::pairing::{Arrival, InvitationKind, Route, Ticket, CODE_FAILED_MESSAGE};
use mousse_net_core::session_cert::CertError;
use mousse_net_core::ErrorCode;
use mousse_net_io::pipe::{route_uri, AddrClass, AddrPolicy, BoxPipe, LocalRoute, RouteKind};
use mousse_net_io::store::{
    hex, is_stale, short_id, Approval, ApprovalStore, CompletionRecord, CompletionRelay,
    CompletionStore, PeerRecord, PeerStore, PeersLock, APPROVAL_SOURCE_TICKET, COMPLETION_PAIRED,
};
use mousse_net_io::{
    Caller, CloseReason, CodeEntry, Connection, Endpoint, JoinOutcome, NetError, Reached,
    Step1Failures, SystemClock,
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

/// Wall-clock now, in Unix seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Routes typed on the command line by the owner: each must parse.
fn parse_routes(list: &[String]) -> Result<Vec<LocalRoute>, String> {
    list.iter()
        .map(|r| LocalRoute::parse(r).map_err(|e| e.to_string()))
        .collect()
}

/// Routes the owner typed: each must parse and name no forbidden address.
fn owner_routes(policy: &AddrPolicy, list: &[String]) -> Result<Vec<LocalRoute>, String> {
    let routes = parse_routes(list)?;
    match routes.iter().find(|r| policy.names_forbidden(r)) {
        Some(r) => Err(format!("{r} names an address that is never dialled")),
        None => Ok(routes),
    }
}

/// How a hint is shown when the owner is asked to approve it.
fn hint_label(policy: &AddrPolicy, route: &LocalRoute) -> String {
    let class = match (route, route.ip(), route.port()) {
        (LocalRoute::Wss { .. }, _, _) => "Tunnel",
        (_, Some(ip), Some(port)) => match policy.class_of(std::net::SocketAddr::new(ip, port)) {
            AddrClass::Lan => "LAN",
            AddrClass::Tailnet => "Tailnet",
            AddrClass::Public => "Internet",
            AddrClass::Forbidden => "never dialled",
        },
        _ => "a name",
    };
    format!("{route} ({class})")
}

/// The ticket's hints beyond the automatic rule that the owner approves
/// (Phase 1b §1.3, §8): asked on the terminal, `y` to dial them too.
/// Without a terminal none is approved, and the ones left out are named.
fn approve_hints(policy: &AddrPolicy, ticket: &Ticket) -> Vec<String> {
    use std::io::IsTerminal;
    let all: Vec<String> = usable_routes(&ticket.routes)
        .iter()
        .map(LocalRoute::uri)
        .collect();
    let extra: Vec<LocalRoute> = crate::app::ticket_candidates(policy, &ticket.routes, &all)
        .into_iter()
        .filter(|r| !policy.automatic(r))
        .collect();
    if extra.is_empty() {
        return Vec::new();
    }
    let listed: Vec<String> = extra.iter().map(|r| hint_label(policy, r)).collect();
    if !std::io::stdin().is_terminal() {
        println!(
            "not dialled without approval (run on a terminal to approve): {}",
            listed.join(", ")
        );
        return Vec::new();
    }
    println!("The ticket also lists: {}", listed.join(", "));
    println!("Dial these too? [y/N]");
    let mut line = String::new();
    let yes = std::io::stdin().read_line(&mut line).is_ok() && line.trim() == "y";
    if yes {
        extra.iter().map(LocalRoute::uri).collect()
    } else {
        Vec::new()
    }
}

/// Keep the hints the owner approved as `ticket` approvals for the host.
fn store_approvals(
    peers: &PeerStore,
    ticket: &Ticket,
    approved: &[String],
) -> Result<(), NetError> {
    let identity = hex(ticket.host_identity.as_bytes());
    let at = now_secs();
    let entries: Vec<Approval> = approved
        .iter()
        .map(|d| Approval {
            identity: identity.clone(),
            destination: d.clone(),
            source: APPROVAL_SOURCE_TICKET.into(),
            at,
        })
        .collect();
    let held = peers.lock()?;
    ApprovalStore::in_dir(peers.dir()).add(&held, &entries)
}

/// Routes from a ticket or the peer store: hints this version cannot use
/// (unknown or reserved schemes, mDNS names without a browser) are skipped.
pub(crate) fn usable_routes(hints: &[String]) -> Vec<LocalRoute> {
    hints
        .iter()
        .filter_map(|h| Route::parse(h).ok().and_then(LocalRoute::from_route))
        .collect()
}

/// The relay writes of a link completion record (pairing-flow design §9),
/// made under the peers lock `held`, after the host's row and approvals.
pub(crate) type ReplayRelay<'a> =
    dyn Fn(&PeersLock<'_>, &CompletionRecord) -> Result<(), NetError> + Send + Sync + 'a;

/// Readies a link join's relay writes under the peers lock, at the PAIRED
/// time (Unix seconds): fills in the relay part's pairing number and tag
/// expiry, if there is a relay part. It writes nothing.
pub(crate) type PrepareRelay<'a> = dyn Fn(&PeersLock<'_>, u64, Option<&mut CompletionRelay>) -> Result<(), NetError>
    + Send
    + Sync
    + 'a;

/// An app's "Send link" join ([`join_routes`]).
pub(crate) struct LinkJoin<'a> {
    /// The destinations the owner approved at Connect.
    pub approved: &'a [String],
    /// The relay part of the completion record, with the sealed tag; the
    /// tag is kept only if the join goes through a relay.
    pub relay: Option<CompletionRelay>,
    /// Numbers the relay part once the pairing is made.
    pub prepare: &'a PrepareRelay<'a>,
    /// Makes the relay writes of a completion record.
    pub replay: &'a ReplayRelay<'a>,
}

/// Where a join dials: a route of this computer's own, or a relay with the
/// ticket's invitation tag (Phase 3 B.7).
pub(crate) enum JoinRoute {
    Local(LocalRoute),
    Relay {
        route: mousse_net_core::relay_endpoint::RelayRoute,
        tag: [u8; 32],
    },
}

impl JoinRoute {
    fn hint(&self) -> String {
        match self {
            JoinRoute::Local(route) => route.uri(),
            JoinRoute::Relay { route, .. } => route.to_hint(),
        }
    }

    fn order(&self) -> u8 {
        match self {
            JoinRoute::Local(route) => match route.kind() {
                RouteKind::Tcp => 0,
                RouteKind::Ws => 1,
                RouteKind::Ssh => 2,
            },
            JoinRoute::Relay { .. } => 3,
        }
    }

    /// A pipe to the host on this route, and how it was reached.
    async fn open(&self, caller: &Caller) -> Result<(BoxPipe, JoinedVia), NetError> {
        match self {
            JoinRoute::Local(route) => {
                let (pipe, class) = caller.open_route(route).await?;
                let reached = Reached {
                    route: route.clone(),
                    class,
                };
                Ok((pipe, JoinedVia::Local(reached)))
            }
            JoinRoute::Relay { route, tag } => {
                let pipe = crate::app::dial_join_route(caller.addr_policy(), route, *tag).await?;
                Ok((Box::new(pipe), JoinedVia::Relay(route.clone())))
            }
        }
    }
}

/// How a join reached its host.
pub(crate) enum JoinedVia {
    Local(Reached),
    Relay(mousse_net_core::relay_endpoint::RelayRoute),
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
        // A ticket past its expiry, refused before dialling.
        NetError::Join(mousse_net_core::pairing::JoinerError::Expired) => "expired".into(),
        NetError::Join(e) => match e.code() {
            Some(code) => code.name().to_lowercase(),
            None => "pairing_refused".into(),
        },
        NetError::Store(_) => "store".into(),
        NetError::Tls(_) => "tls".into(),
        NetError::Timeout(_) => "timeout".into(),
        NetError::Io(_) => "unreachable".into(),
        NetError::Relay(e) => e.word().into(),
        NetError::Forbidden(_) => "forbidden_address".into(),
        // An ssh try names its own reason (Phase 1b §3.5).
        NetError::Ssh { reason, .. } => reason.name().into(),
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

/// A finished join.
pub struct Joined {
    /// The connection the join ended on.
    pub conn: Connection,
    /// The host as stored.
    pub record: PeerRecord,
    /// The host answered that this device already had access, which this
    /// ticket did not give: the role stored is the one from before (or
    /// `unknown`), not confirmed by this join.
    pub already_paired: bool,
}

/// The line `join` prints for `joined`.
pub fn joined_line(joined: &Joined, host: &mousse_net_core::identity::IdentityPublicKey) -> String {
    outcome_line(&joined.record.name, joined.already_paired, host)
}

fn outcome_line(
    name: &str,
    already_paired: bool,
    host: &mousse_net_core::identity::IdentityPublicKey,
) -> String {
    let who = format!("{} ({})", crate::printable(name), short_id(host));
    if already_paired {
        format!("already paired with {who}: access as before; the role is not confirmed")
    } else {
        format!("paired with {who}")
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
) -> Result<Joined, Failure> {
    if ticket.kind == InvitationKind::InPerson && arrival == Arrival::Link {
        return Err(Failure::new(
            "this is an in-person ticket: it pairs only when scanned from the host's screen \
             in the app; a ticket given here counts as sent and cannot pair (PAIRING_FAILED)",
            "pairing_failed",
        ));
    }
    // The same policy as the app's (Phase 1b §1.3): addresses the owner
    // typed, or the ticket's hints under the automatic rule plus the ones
    // the owner approves here.
    let policy = side.caller.addr_policy().clone();
    let mut approved = Vec::new();
    let candidates = if routes.is_empty() {
        approved = approve_hints(&policy, ticket);
        crate::app::ticket_candidates(&policy, &ticket.routes, &approved)
    } else {
        owner_routes(&policy, routes).map_err(|e| Failure::new(e, "bad_route"))?
    };
    if candidates.is_empty() {
        return Err(Failure::new(
            "the ticket has no usable address; pass --route tcp://host:port",
            "no_route",
        ));
    }
    if ticket.kind == InvitationKind::SendLink {
        println!("joining with a link; the code is shown on the host");
    } else {
        println!("joining; the host owner is asked to confirm");
    }
    let candidates: Vec<JoinRoute> = candidates.into_iter().map(JoinRoute::Local).collect();
    let (conn, record, already_paired, _) = join_routes(
        &side.caller,
        &side.peers(),
        ticket,
        arrival,
        name,
        &candidates,
        false,
        None,
        &mut TypedCode,
        |_| {},
        || true,
    )
    .await?;
    if !already_paired && !approved.is_empty() {
        store_approvals(&side.peers(), ticket, &approved)
            .map_err(|e| Failure::new(e.to_string(), "store"))?;
    }
    Ok(Joined {
        conn,
        record,
        already_paired,
    })
}

/// Pair with the host in `ticket`, trying each of `candidates` in turn.
/// Stores the host's pin on success and returns the connection, the stored
/// record and whether the device was already paired (the role this ticket
/// offered is then not in effect).
///
/// `consented`: the app recorded this join before starting it (Phase 1a
/// §5.1), so the ticket's host counts as pinned and a join past the
/// ticket's expiry learns whether a lost `PAIRED` enrolled it. Otherwise a
/// send link may end "already paired" only for a host pinned before.
///
/// `link`: an app join of a "Send link" ticket (Phase 1b §5.4), with the
/// destinations the owner approved at Connect. It never takes the
/// consented path: `consented` is ignored, the host counts as pinned only
/// if `peers.json` held its pin before the join, and a ticket past its
/// expiry is learned only from a pending record the flow store holds.
/// Only a `PAIRED` for the ticket completes it: a completion record is
/// written first, then the pin, the approvals and the settled mark. An
/// "already paired" answer is existing access only and changes nothing
/// stored.
///
/// `wanted`: false once the host was removed since the join started. It is
/// asked under the peers lock, just before anything is stored, and a
/// removal answers it under the same lock: a join either stores before the
/// removal (which then removes what it stored) or stores nothing.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn join_routes<C: CodeEntry>(
    caller: &Caller,
    peers: &PeerStore,
    ticket: &Ticket,
    arrival: Arrival,
    name: &str,
    candidates: &[JoinRoute],
    consented: bool,
    link: Option<LinkJoin<'_>>,
    codes: &mut C,
    mut progress: impl FnMut(&str),
    wanted: impl Fn() -> bool,
) -> Result<(Connection, PeerRecord, bool, JoinedVia), Failure> {
    let held = peers.load().is_ok_and(|ps| {
        ps.iter()
            .any(|p| p.pin().ok() == Some(ticket.host_identity))
    });
    let link = link.filter(|_| ticket.kind == InvitationKind::SendLink);
    let (pinned, resume) = match link {
        None => (consented || held, consented),
        // Must-fail controls: the app's consent counts as a pin, or makes
        // up a pending outcome past the ticket's expiry.
        Some(_) => (
            held || (consented && cfg!(mousse_control = "journal-pins-link")),
            consented && cfg!(mousse_control = "fabricate-pending-kind2"),
        ),
    };
    // Refusals the ticket and its flow record already give come before
    // any dial: an expired ticket, no tries left, the wrong arrival.
    caller
        .check_join(ticket, arrival, name, resume)
        .map_err(|e| Failure::of(&e))?;
    let mut last = Failure::new("no route answered", "unreachable");
    // Any step 1 failure on an address means "try the next one"; one is
    // shown only when no address passed (wire.md 5.4).
    let mut step1 = Step1Failures::default();
    // Pipe-generic (Phase 1b §1.4): `tcp` candidates first, then `ws`/`wss`,
    // then `ssh`, each pipe from `Caller::open_route` (resolved once, the
    // classified address dialled); then the relays (Phase 3 B.7).
    let mut ordered: Vec<&JoinRoute> = candidates.iter().collect();
    ordered.sort_by_key(|r| r.order());
    for route in ordered {
        let hint = route.hint();
        progress(&hint);
        let (pipe, reached) = match route.open(caller).await {
            Ok(p) => p,
            Err(e) => {
                last = Failure::new(format!("{hint}: {e}"), &reason_of(&e));
                continue;
            }
        };
        // If the connection drops before PAIRED, the join reconnects the
        // same way to learn whether the host enrolled this device.
        let redial = || async { route.open(caller).await.map(|(pipe, _)| pipe) };
        let joined = if resume {
            caller
                .join_pinned_with_redial(pipe, ticket, arrival, name, codes, redial)
                .await
        } else {
            caller
                .join_with_redial(pipe, ticket, arrival, name, codes, pinned, redial)
                .await
        };
        let joined = match (joined, &link) {
            (Ok((conn, outcome)), Some(link)) => {
                let via_relay = matches!(route, JoinRoute::Relay { .. });
                let (record, already) = match finish_link(
                    caller, peers, ticket, &hint, link, via_relay, outcome, &wanted,
                ) {
                    Ok(done) => done,
                    Err(f) => {
                        conn.close(ErrorCode::Cancelled);
                        return Err(f);
                    }
                };
                if let JoinRoute::Local(route) = route {
                    caller.remember_local_routes(ticket.host_identity, vec![route.clone()]);
                }
                return Ok((conn, record, already, reached));
            }
            (joined, _) => joined,
        };
        match joined {
            Ok((conn, outcome)) => {
                let already = matches!(outcome, JoinOutcome::AlreadyPaired);
                // Built from the stored record as it is under the lock, so
                // a write by another process meanwhile is not undone.
                let mut stored = None;
                let store = |e: NetError| Failure::new(e.to_string(), "store");
                let held = match peers.lock() {
                    Ok(held) if wanted() => held,
                    Ok(held) => {
                        drop(held);
                        conn.close(ErrorCode::Cancelled);
                        return Err(removed_meanwhile(caller, &ticket.hash()));
                    }
                    Err(e) => return Err(store(e)),
                };
                held.update(|peers| {
                    let existing = peers
                        .iter()
                        .find(|p| p.pin().ok() == Some(ticket.host_identity));
                    let (host_name, role) = match outcome {
                        JoinOutcome::Paired(host) => (host.name, host.role.as_str().to_owned()),
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
                        addresses: existing.map(|p| p.addresses.clone()).unwrap_or_default(),
                        offered: existing.map(|p| p.offered.clone()).unwrap_or_default(),
                        paired_at: now_secs(),
                    };
                    peers.retain(|p| p.pin().ok() != Some(ticket.host_identity));
                    peers.push(record.clone());
                    stored = Some(record);
                })
                .map_err(store)?;
                drop(held);
                let record = stored.expect("the update ran");
                // The pin is stored: the join's outcome is no longer pending.
                caller
                    .pin_stored(ticket)
                    .map_err(|e| Failure::new(e.to_string(), "store"))?;
                if let JoinRoute::Local(route) = route {
                    caller.remember_local_routes(ticket.host_identity, vec![route.clone()]);
                }
                return Ok((conn, record, already, reached));
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

/// Test hooks (debug builds): `MOUSSE_HELPER_TEST_CRASH=<point>` stops the
/// helper at once at that point, as a crash would.
/// `MOUSSE_HELPER_TEST_HOLD=<point>=<file>` holds it there instead: it
/// creates `<file>` and waits until the test deletes it (60 s at most).
pub(crate) fn crash_point(point: &str) {
    #[cfg(debug_assertions)]
    {
        if std::env::var("MOUSSE_HELPER_TEST_CRASH").as_deref() == Ok(point) {
            std::process::exit(86);
        }
        if let Ok(hold) = std::env::var("MOUSSE_HELPER_TEST_HOLD") {
            if let Some(file) = hold.strip_prefix(point).and_then(|r| r.strip_prefix('=')) {
                let file = Path::new(file);
                if std::fs::write(file, point).is_ok() {
                    let until = std::time::Instant::now() + Duration::from_secs(60);
                    while file.exists() && std::time::Instant::now() < until {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        }
    }
    let _ = point;
}

/// The end of an app's "Send link" join (Phase 1b §5.4 and §3.6). The
/// completion record also holds the writes for the ticket's approved relay
/// routes, with the sealed tag when the join went through a relay
/// (`via_relay`), so they are replayed with the rest (pairing-flow design
/// §9). The relay part takes the pairing's number under the same peers
/// lock.
#[allow(clippy::too_many_arguments)]
fn finish_link(
    caller: &Caller,
    peers: &PeerStore,
    ticket: &Ticket,
    hint: &str,
    link: &LinkJoin<'_>,
    via_relay: bool,
    outcome: JoinOutcome,
    wanted: &impl Fn() -> bool,
) -> Result<(PeerRecord, bool), Failure> {
    let approved = link.approved;
    let store = |e: NetError| Failure::new(e.to_string(), "store");
    let hash = ticket.hash();
    let identity = hex(ticket.host_identity.as_bytes());
    let existing = peers
        .load()
        .map_err(store)?
        .into_iter()
        .find(|p| p.identity == identity);
    let host = match outcome {
        JoinOutcome::Paired(host) => host,
        JoinOutcome::AlreadyPaired => {
            // Existing access, not this ticket's: no completion record, and
            // the stored row stays as it is.
            caller.settle_stored(&hash).map_err(store)?;
            let record = existing.unwrap_or(PeerRecord {
                name: short_id(&ticket.host_identity),
                identity,
                role: "unknown".into(),
                routes: Vec::new(),
                last_route: None,
                addresses: Vec::new(),
                offered: Vec::new(),
                paired_at: 0,
            });
            return Ok((record, true));
        }
    };
    crash_point("link-paired");
    let now = caller.now().secs();
    let peer = PeerRecord {
        name: host.name,
        identity: identity.clone(),
        role: host.role.as_str().to_owned(),
        routes: ticket.routes.clone(),
        last_route: Some(hint.to_owned()),
        addresses: existing.map(|p| p.addresses).unwrap_or_default(),
        offered: Vec::new(),
        paired_at: now,
    };
    let mut done = CompletionRecord {
        ticket_hash: hex(&hash),
        host_identity: identity,
        outcome: COMPLETION_PAIRED.into(),
        peer: peer.clone(),
        approvals: ticket_approvals(ticket, approved, now),
        expires_at: ticket.expires_at.secs(),
        at: now,
        relay: link.relay.clone().map(|mut relay| {
            if !via_relay {
                relay.join_tag = None;
            }
            relay
        }),
    };
    // The record, the row and the approvals are written under one peers
    // lock, checked against a removal of the host under it: a removal
    // meanwhile would otherwise be undone by the replay, or drop the
    // record before it and leave this join's path to a removed host.
    let held = peers.lock().map_err(store)?;
    // Must-fail control: the host's removal during the join is not seen.
    if !wanted() && !cfg!(mousse_control = "join-ignores-removal") {
        drop(held);
        return Err(removed_meanwhile(caller, &hash));
    }
    // The pairing's number, and the tag's expiry from the PAIRED time.
    (link.prepare)(&held, now, done.relay.as_mut()).map_err(store)?;
    // Must-fail control: the pin is saved with no completion record first.
    if cfg!(mousse_control = "no-completion-record") {
        crash_point("link-done-saved");
        held.update(|list| merge_peer(list, peer.clone()))
            .map_err(store)?;
        ApprovalStore::in_dir(peers.dir())
            .add(&held, &done.approvals)
            .map_err(store)?;
    } else {
        CompletionStore::in_dir(peers.dir())
            .save(&done)
            .map_err(store)?;
        crash_point("link-done-saved");
        if replay_held(peers.dir(), &held, &hash, true, None, link.replay)
            .map_err(store)?
            .is_none()
        {
            drop(held);
            return Err(removed_meanwhile(caller, &hash));
        }
    }
    drop(held);
    caller.settle_stored(&hash).map_err(store)?;
    Ok((peer, false))
}

/// The join's host was removed (`peer.forget`) while it ran: nothing is
/// stored and its connection is closed. The outcome is learned all the
/// same, so the join's pending mark is cleared and its ticket let go: a
/// repeat of the ticket then cannot learn `PAIRED` from the host's receipt
/// and bring the removed host back.
fn removed_meanwhile(caller: &Caller, ticket_hash: &[u8; 32]) -> Failure {
    // Must-fail control: the pending mark and the ticket's hold stay.
    if !cfg!(mousse_control = "removal-leaves-pending") {
        if let Err(e) = caller.settle_stored(ticket_hash) {
            return Failure::new(e.to_string(), "store");
        }
    }
    Failure::new(
        "the host was removed while this device was joining it",
        "forgotten",
    )
}

/// The approvals a link join stores: each approved destination that is one
/// of the ticket's hints, canonical. Any other is ignored.
fn ticket_approvals(ticket: &Ticket, approved: &[String], now: u64) -> Vec<Approval> {
    let canonical = |text: &str| match Route::parse(text) {
        Ok(route) => route_uri(&route),
        Err(_) => text.to_owned(),
    };
    let hints: Vec<String> = ticket.routes.iter().map(|h| canonical(h)).collect();
    let mut out: Vec<Approval> = Vec::new();
    for a in approved {
        let destination = canonical(a);
        if hints.contains(&destination) && !out.iter().any(|o| o.destination == destination) {
            out.push(Approval {
                identity: hex(ticket.host_identity.as_bytes()),
                destination,
                source: APPROVAL_SOURCE_TICKET.into(),
                at: now,
            });
        }
    }
    out
}

/// Put `record` in place of the stored row for its host, keeping the
/// addresses the owner set on that row.
fn merge_peer(list: &mut Vec<PeerRecord>, mut record: PeerRecord) {
    if let Some(old) = list.iter().find(|p| p.identity == record.identity) {
        if !old.addresses.is_empty() {
            record.addresses = old.addresses.clone();
        }
    }
    list.retain(|p| p.identity != record.identity);
    list.push(record);
}

/// Make the writes of the completion record for `ticket_hash` again, under
/// the peers lock: the host's row in `peers.json` (merged as the join
/// merges it), then its approvals, then its relay writes (`relay`). Each
/// is idempotent, and an error stops the replay, so the record is only
/// reported done once all of them are stored. Returns the record, or
/// `None` if there is none: never made, acknowledged, dropped by a
/// removal of its host, or past `stale` (`(now, keep_secs)`), in which
/// case it is deleted here. `full`: false only for the `done-pin-only`
/// must-fail control, which saves the pin without routes or approvals.
pub(crate) fn replay_completion(
    dir: &Path,
    ticket_hash: &[u8; 32],
    full: bool,
    stale: Option<(u64, u64)>,
    relay: &ReplayRelay<'_>,
) -> Result<Option<CompletionRecord>, NetError> {
    let peers = PeerStore::in_dir(dir);
    let held = peers.lock()?;
    replay_held(dir, &held, ticket_hash, full, stale, relay)
}

/// [`replay_completion`], under the peers lock `held`.
fn replay_held(
    dir: &Path,
    held: &PeersLock<'_>,
    ticket_hash: &[u8; 32],
    full: bool,
    stale: Option<(u64, u64)>,
    relay: &ReplayRelay<'_>,
) -> Result<Option<CompletionRecord>, NetError> {
    let records = CompletionStore::in_dir(dir);
    let Some(record) = records.load(ticket_hash)? else {
        return Ok(None);
    };
    if let Some((now, keep)) = stale {
        if is_stale(&record, now, keep) {
            records.remove(ticket_hash)?;
            return Ok(None);
        }
    }
    let mut peer = record.peer.clone();
    if !full {
        peer.routes.clear();
        peer.last_route = None;
    }
    held.update(|list| merge_peer(list, peer))?;
    if full {
        ApprovalStore::in_dir(dir).add(held, &record.approvals)?;
        crash_point("link-row-saved");
        relay(held, &record)?;
    }
    Ok(Some(record))
}

/// The host `identity` (hex) was removed (`peer.forget`, or a removal of
/// its grant): delete its approvals and every completion record naming it,
/// under the peers lock, so no replay brings it back. Returns their
/// tickets, whose pending marks the caller clears once the lock is
/// released. `held` is the peers lock the removal holds.
pub(crate) fn drop_completions(
    dir: &Path,
    held: &PeersLock<'_>,
    identity: &str,
) -> Result<Vec<[u8; 32]>, NetError> {
    // Must-fail control: the records stay, and a later replay restores
    // the removed host.
    if cfg!(mousse_control = "replay-after-removal") {
        return Ok(Vec::new());
    }
    ApprovalStore::in_dir(dir).remove_identity(held, identity)?;
    CompletionStore::in_dir(dir).remove_naming(held, identity)
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
    // The same policy as the app's: the stored routes the automatic rule or
    // an approval allows, or the addresses the owner typed.
    let policy = side.caller.addr_policy().clone();
    let candidates = if routes.is_empty() {
        crate::app::stored_search(&policy, side.endpoint.dir(), peer).candidates
    } else {
        owner_routes(&policy, routes)?
    };
    let (conn, used) = side
        .caller
        .search(mousse_net_io::Search::of(candidates), pin)
        .await
        .map_err(|e| describe(&e))?;
    // Only the route is noted, on the record as stored now: a re-pair of
    // this host meanwhile keeps its name, role and routes.
    let _ = side.peers().note_route(&pin, used.route.uri());
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
    let joined = match join(side, &ticket, opts.arrival, &name, &opts.routes).await {
        Ok(v) => v,
        Err(e) => return steps.fail(format!("{what}: {}", e.text), &e.reason),
    };
    steps.pass(format!(
        "{} via {} using {}",
        joined_line(&joined, &ticket.host_identity),
        joined.record.last_route.clone().unwrap_or_default(),
        joined.conn.kx_group()
    ));
    let Joined {
        conn, record: peer, ..
    } = joined;
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

#[cfg(test)]
mod tests {
    use mousse_net_core::grants::OwnerRef;
    use mousse_net_core::identity::SoftwareKey;
    use mousse_net_core::pairing::CpaceExchangeFactory;
    use mousse_net_io::keystore::KeyStorage;
    use mousse_net_io::rng::{os_rng, random_bytes};
    use mousse_net_io::{Host, HostConfig, HostEvent, Limits};

    use super::*;

    /// A host on loopback that says yes to every in-person join; returns
    /// it and its route.
    async fn approving_host() -> (Host, String) {
        let config = HostConfig {
            name: "desk".into(),
            state_dir: None,
            owner: OwnerRef::from_bytes([1; OwnerRef::LEN]),
            limits: Limits::DEFAULT,
            clock: Arc::new(SystemClock::new()),
            ticket_identity: None,
            streams: None,
        };
        let key = Arc::new(SoftwareKey::generate(&mut os_rng()));
        let (host, mut events) = Host::new(key, config, CpaceExchangeFactory).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let route = format!("tcp://{}", listener.local_addr().unwrap());
        let accepting = host.clone();
        tokio::spawn(async move {
            // The connections stay open while their tasks are held.
            let mut held = Vec::new();
            while let Ok((tcp, _)) = listener.accept().await {
                let host = accepting.clone();
                held.push(tokio::spawn(async move { host.accept(tcp).await }));
            }
        });
        let approving = host.clone();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                if let HostEvent::ApprovalRequested(request) = event {
                    let _ = approving.approve(&request);
                }
            }
        });
        (host, route)
    }

    /// An "already paired" answer is not reported as a pairing, and says
    /// the role was not confirmed.
    #[test]
    fn already_paired_prints_as_access_from_before() {
        let host = SoftwareKey::generate(&mut os_rng()).public_key();
        let id = short_id(&host);
        assert_eq!(
            outcome_line("desk", false, &host),
            format!("paired with desk ({id})")
        );
        assert_eq!(
            outcome_line("desk", true, &host),
            format!("already paired with desk ({id}): access as before; the role is not confirmed")
        );
    }

    /// `term` read the host's record, then the host was paired again (a
    /// new name and role) before the dial noted the route it used: the
    /// re-pair stays, and the route is noted on it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dial_keeps_a_re_pair_that_landed_after_the_record_was_read() {
        let dir =
            std::env::temp_dir().join(format!("mousse-helper-dial-{}", hex(&random_bytes::<6>())));
        Endpoint::create(&dir, None, KeyStorage::InsecureFile).unwrap();
        let side = CallerSide::open(&dir, true).unwrap();
        let (host, route) = approving_host().await;
        let created = host
            .invite(InvitationKind::InPerson, vec![route.clone()])
            .unwrap();
        let ticket = Ticket::from_fragment(&created.fragment).unwrap();
        let Ok(joined) = join(&side, &ticket, Arrival::InAppScan, "laptop", &[]).await else {
            panic!("the join failed");
        };
        drop(joined);

        let read = side.peers().load().unwrap().remove(0);
        let mut again = read.clone();
        again.name = "desk again".into();
        again.role = "Member".into();
        again.last_route = None;
        side.peers().upsert(again).unwrap();

        let Ok(_conn) = dial(&side, &read, &[]).await else {
            panic!("the dial failed");
        };
        let now = side.peers().load().unwrap();
        assert_eq!(now.len(), 1);
        assert_eq!(
            (now[0].name.as_str(), now[0].role.as_str()),
            ("desk again", "Member")
        );
        assert_eq!(now[0].last_route.as_deref(), Some(route.as_str()));
        drop(side);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
