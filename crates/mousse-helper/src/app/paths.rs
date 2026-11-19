//! Reaching paired hosts (Phase 1a §5.3 and §6; Phase 1b §1.3 and §1.4).
//!
//! - **Who may supply what (§1.3).** A ticket hint or a route a host sends
//!   when it pairs back (`peer.add {routes}`) is dialled only under 1a's
//!   automatic rule: a `tcp` route to an IP literal of class `lan` (debug
//!   builds: loopback too). A ticket's other `tcp` and `wss` hints are
//!   dialled only when the owner approved them at Connect (`join
//!   {approved}`); its plain `ws` and `ssh` hints are skipped. Other
//!   pairback routes are kept as suggestions (`peer.add {offered}`), never
//!   dialled. The owner's own addresses (`peer.addresses.set`) may be of
//!   any kind; none may name a `forbidden` address.
//! - **Approvals.** `<state>/approvals.json` holds every destination
//!   dialled beyond the automatic rule, with its source: `ticket` (added
//!   when an approved join succeeds) or `owner` (`peer.addresses.set` adds
//!   its own and drops the ones it no longer lists). `peer.forget` and
//!   `grant.remove` drop the peer's. A store from 1.0 has no file, so its
//!   routes count only under the automatic rule.
//! - **Candidates**, built from the store for every search, renewals
//!   included: the last working route, the owner's addresses, the hints;
//!   each must pass the automatic rule or have an approval for that peer,
//!   the last working route too. The browse source (mDNS, cached) runs
//!   beside the search and what it finds joins the `tcp` tier, under the
//!   automatic rule only.
//! - **Dialling** is [`Caller::search`](mousse_net_io::Caller::search):
//!   bounded tiers, a pin mismatch moves on, the host's own refusal stops
//!   the search. Any change to a host's addresses or approvals bumps the
//!   caller's route generation for it ([`Caller::forget_routes`]), and a
//!   last working route that lost its approval is dropped.
//! - **Keep connected.** Once the app said `hello`, the helper keeps one
//!   outbound path to every paired host. A host that cannot be reached is
//!   tried again after `KEEP_RETRY_FIRST_MS`, doubling up to
//!   `KEEP_RETRY_MAX_MS`; each failure is a `dial.failed` event. A host
//!   that refuses this device (`not_authorized`, `grant_revoked`) is not
//!   tried again until something changes: `dial`, `peer.add`,
//!   `peer.addresses.set`, networking resuming, or a restart.
//! - **Browse file.** Debug builds read hosts from the file named by
//!   `MOUSSE_HELPER_BROWSE_FILE` instead of mDNS: one `ip:port` per line.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::pairing::Route;
use mousse_net_io::discovery::BrowseSource;
use mousse_net_io::pipe::{AddrPolicy, LocalRoute, RouteKind};
use mousse_net_io::store::{
    hex, identity_from_hex, short_id, Approval, ApprovalStore, PeerRecord, PeerStore,
    APPROVAL_SOURCE_OWNER,
};
use mousse_net_io::{CandidateSource, Connection, NetError, Reached, Search};
use serde_json::{json, Map, Value};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::{error, Shared};
use crate::applog;

/// Whether a route a peer supplied (a ticket hint or a pairback route) may
/// be dialled without the owner's approval: 1a's automatic rule.
pub fn peer_route_ok(policy: &AddrPolicy, route: &LocalRoute) -> bool {
    if cfg!(mousse_control = "public-routes") {
        // The control build takes any TCP address.
        return matches!(route, LocalRoute::Tcp { .. });
    }
    if cfg!(mousse_control = "peer-ssh-routes") && route.kind() == RouteKind::Ssh {
        // The control build lets a peer name an ssh target.
        return true;
    }
    policy.automatic(route)
}

/// The routes in `approved` (`join {approved}`), in canonical form; text
/// that is not a route is left out.
pub fn canonical_list(value: Option<&Value>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in value.and_then(Value::as_array).into_iter().flatten() {
        if let Some(route) = v.as_str().and_then(|t| LocalRoute::parse(t).ok()) {
            if !out.contains(&route.uri()) {
                out.push(route.uri());
            }
        }
    }
    out
}

/// The hints of a ticket this helper may dial (§1.3): those under the
/// automatic rule, and `tcp` or `wss` hints the owner approved at Connect
/// that name no forbidden address. Plain `ws` and `ssh` hints are reserved
/// on the wire and skipped.
pub fn ticket_candidates(
    policy: &AddrPolicy,
    hints: &[String],
    approved: &[String],
) -> Vec<LocalRoute> {
    let mut out: Vec<LocalRoute> = Vec::new();
    for hint in hints {
        let route = match Route::parse(hint).ok().and_then(LocalRoute::from_route) {
            Some(route) => route,
            // The control build reads a plain ws hint as an owner's route.
            None if cfg!(mousse_control = "plain-ws-from-ticket") => {
                match LocalRoute::parse(hint) {
                    Ok(route) if route.kind() == RouteKind::Ws => route,
                    _ => continue,
                }
            }
            None => continue,
        };
        let approved = approved.contains(&route.uri())
            // The control build dials any TCP hint without approval.
            || (cfg!(mousse_control = "unapproved-public") && route.kind() == RouteKind::Tcp);
        let ok = peer_route_ok(policy, &route) || (approved && !policy.names_forbidden(&route));
        if ok && !out.contains(&route) {
            out.push(route);
        }
    }
    out
}

/// A list of route texts from the app channel, each parsed.
fn route_list(value: Option<&Value>) -> Result<Vec<LocalRoute>, String> {
    let list = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(list)) => list,
        Some(_) => return Err("routes is a list of route hints".into()),
    };
    let mut out: Vec<LocalRoute> = Vec::new();
    for r in list {
        let route = r
            .as_str()
            .and_then(|t| LocalRoute::parse(t).ok())
            .ok_or_else(|| format!("not a route: {r}"))?;
        if !out.contains(&route) {
            out.push(route);
        }
    }
    Ok(out)
}

/// The routes a host sends when it pairs back (`peer.add {routes}`): 1a's
/// automatic rule only. The error names the first that is not.
pub fn parse_routes(policy: &AddrPolicy, value: Option<&Value>) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for route in route_list(value)? {
        if !peer_route_ok(policy, &route) {
            return Err(format!(
                "{} is not a private-range address (10/8, 172.16/12, 192.168/16, \
                 169.254/16 or fc00::/7)",
                route.uri()
            ));
        }
        out.push(route.uri());
    }
    Ok(out)
}

/// The other routes a host offered when it paired back (`peer.add
/// {offered}`): `tcp` or `wss` naming no forbidden address, kept as
/// suggestions. A peer never names a plain `ws` or an `ssh` route.
pub fn parse_offered(policy: &AddrPolicy, value: Option<&Value>) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for route in route_list(value)? {
        let kind_ok = matches!(route, LocalRoute::Tcp { .. } | LocalRoute::Wss { .. })
            || (cfg!(mousse_control = "peer-ssh-routes") && route.kind() == RouteKind::Ssh);
        if !kind_ok {
            return Err(format!(
                "{} is not a route a peer may offer (tcp or wss only)",
                route.uri()
            ));
        }
        if policy.names_forbidden(&route) {
            return Err(format!(
                "{} names an address that is never dialled",
                route.uri()
            ));
        }
        out.push(route.uri());
    }
    Ok(out)
}

/// The owner's addresses (`peer.addresses.set`): any kind, none naming a
/// forbidden address. The error is `(error, reason)`.
pub fn parse_owner_routes(
    policy: &AddrPolicy,
    value: Option<&Value>,
) -> Result<Vec<String>, (&'static str, String)> {
    let mut out = Vec::new();
    for route in route_list(value).map_err(|e| ("bad_route", e))? {
        if policy.names_forbidden(&route) {
            return Err((
                "forbidden_address",
                format!("{} names an address that is never dialled", route.uri()),
            ));
        }
        out.push(route.uri());
    }
    Ok(out)
}

/// What may be dialled for one peer beyond the automatic rule.
struct Allowed {
    approvals: Vec<Approval>,
    /// The control build counts a 1.0 store's routes as approved.
    trust_stored: bool,
}

impl Allowed {
    fn load(dir: &Path) -> Self {
        let store = ApprovalStore::in_dir(dir);
        Self {
            approvals: store.load().unwrap_or_default(),
            trust_stored: cfg!(mousse_control = "upgrade-trusts-routes") && !store.exists(),
        }
    }

    /// Whether `route` may be dialled for the peer `identity`.
    fn allows(&self, policy: &AddrPolicy, identity: &str, route: &LocalRoute) -> bool {
        if policy.automatic(route) {
            return true;
        }
        if policy.names_forbidden(route) {
            return false;
        }
        let uri = route.uri();
        self.trust_stored
            || self
                .approvals
                .iter()
                .any(|a| a.identity == identity && a.destination == uri)
    }
}

/// A stored route: an owner's address of any kind, or a hint by the
/// wire's grammar.
fn stored_route(text: &str, owner: bool) -> Option<LocalRoute> {
    if owner {
        LocalRoute::parse(text).ok()
    } else {
        Route::parse(text).ok().and_then(LocalRoute::from_route)
    }
}

/// The search for `record`'s host from the store as it is now, without
/// the browse: the last working route, the owner's addresses, the hints,
/// each allowed by the automatic rule or an approval.
pub fn stored_search(policy: &AddrPolicy, dir: &Path, record: &PeerRecord) -> Search {
    let allowed = Allowed::load(dir);
    let may = |route: &LocalRoute| allowed.allows(policy, &record.identity, route);
    let last = record
        .last_route
        .as_deref()
        .and_then(|r| stored_route(r, true))
        // The control build dials the last working route unchecked.
        .filter(|r| cfg!(mousse_control = "unapproved-last-route") || may(r));
    let ssh_first = last.as_ref().is_some_and(|r| r.kind() == RouteKind::Ssh);
    let mut out: Vec<LocalRoute> = last.into_iter().collect();
    if cfg!(mousse_control = "no-rediscovery") && !out.is_empty() {
        // The control build tries only the last working route. A pairing
        // that has none yet (its first dial) still uses its addresses, so
        // the control breaks finding a host that moved and nothing else.
        return Search {
            candidates: out,
            ssh_first,
            later: None,
        };
    }
    let owner = record.addresses.iter().map(|r| (r, true));
    let hints = record.routes.iter().map(|r| (r, false));
    for (text, is_owner) in owner.chain(hints) {
        if let Some(route) = stored_route(text, is_owner) {
            if may(&route) && !out.contains(&route) {
                out.push(route);
            }
        }
    }
    Search {
        candidates: out,
        ssh_first,
        later: None,
    }
}

/// Renewals build their search from the store, as every dial does.
pub struct StoreCandidates {
    pub dir: PathBuf,
    pub policy: AddrPolicy,
}

impl CandidateSource for StoreCandidates {
    fn search(&self, pin: &IdentityPublicKey) -> Search {
        let key = hex(pin.as_bytes());
        PeerStore::in_dir(&self.dir)
            .load()
            .ok()
            .and_then(|peers| peers.into_iter().find(|p| p.identity == key))
            .map(|record| stored_search(&self.policy, &self.dir, &record))
            .unwrap_or_default()
    }
}

/// After the approvals of `identity` changed: drop its last working route
/// if that lost its approval, and bump the caller's route generation.
pub(super) fn approvals_changed(shared: &Shared, identity: &IdentityPublicKey) {
    let dir = &shared.info.state_dir;
    let policy = shared.caller.addr_policy().clone();
    let allowed = Allowed::load(dir);
    let key = hex(identity.as_bytes());
    let _ = PeerStore::in_dir(dir).update(|list| {
        if let Some(p) = list.iter_mut().find(|p| p.identity == key) {
            // The control build keeps a last route that lost its approval.
            let keep = cfg!(mousse_control = "unapproved-last-route")
                || p.last_route
                    .as_deref()
                    .and_then(|r| stored_route(r, true))
                    .is_some_and(|r| allowed.allows(&policy, &key, &r));
            if !keep {
                p.last_route = None;
            }
        }
    });
    shared.caller.forget_routes(Some(identity));
}

/// Reach `record`'s host: the stored candidates, with what the browse
/// source finds joining as it arrives. Returns the live connection and how
/// it was reached.
async fn reach(shared: &Shared, record: &PeerRecord) -> Result<(Connection, Reached), NetError> {
    let pin = record.pin()?;
    let policy = shared.caller.addr_policy().clone();
    let mut search = stored_search(&policy, &shared.info.state_dir, record);
    let browse = shared
        .info
        .browse
        .clone()
        .filter(|_| !cfg!(mousse_control = "no-rediscovery"));
    if let Some(browse) = browse {
        search.later = Some(Box::pin(async move {
            match browse.addresses().await {
                Ok(found) => found
                    .into_iter()
                    .map(LocalRoute::tcp)
                    .filter(|r| policy.automatic(r))
                    .collect(),
                Err(e) => {
                    applog::line(format!("browse failed: {e}"));
                    Vec::new()
                }
            }
        }));
    }
    shared.caller.search(search, pin).await
}

/// `{kind, class}` for `conn.up`.
pub fn route_json(reached: &Reached) -> Value {
    json!({"kind": reached.route.kind().name(), "class": reached.class.name()})
}

/// `approvals.list {identity?}`.
pub fn list_approvals(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let only = map
        .get("identity")
        .and_then(Value::as_str)
        .map(str::to_lowercase);
    match ApprovalStore::in_dir(&shared.info.state_dir).load() {
        Ok(list) => {
            let list: Vec<Value> = list
                .into_iter()
                .filter(|a| only.as_ref().is_none_or(|i| *i == a.identity))
                .map(|a| {
                    json!({
                        "identity": a.identity,
                        "destination": a.destination,
                        "source": a.source,
                        "at": a.at,
                    })
                })
                .collect();
            json!({"re": id, "approvals": list})
        }
        Err(e) => error(id, "store_failed", e.to_string()),
    }
}

/// Why a dial ended without a new connection.
pub enum DialError {
    NoPeer(String),
    Paused,
    Failed(NetError),
    /// Another dial to the host ended this way while this one waited its
    /// turn.
    Same(Failure),
}

/// How a dial failed, kept for the dials that waited behind it.
#[derive(Clone, Debug)]
pub struct Failure {
    pub why: String,
    pub reason: String,
}

impl Failure {
    fn of(e: &NetError) -> Self {
        Failure {
            why: crate::peer::reason_of(e),
            reason: crate::peer::describe(e),
        }
    }
}

/// What a dial gave.
pub struct Dialled {
    /// The connection's number.
    pub conn: u64,
    /// It was up already (opened by another dial meanwhile).
    pub already: bool,
}

/// One dial at a time per host, so the keeper and `dial` never open two
/// paths at once.
#[derive(Default)]
pub struct Keep {
    locks: Mutex<HashMap<IdentityPublicKey, Arc<tokio::sync::Mutex<()>>>>,
    kicks: Mutex<Option<mpsc::UnboundedSender<Kick>>>,
    /// Per host: how many dials have ended, and how the last one failed.
    ends: Mutex<HashMap<IdentityPublicKey, (u64, Option<Failure>)>>,
}

/// Something the keeper should look at.
#[derive(Clone, Copy, Debug)]
pub enum Kick {
    /// Connections changed: dial hosts with none that are due.
    Look,
    /// Try now and start the waits over: one host, or all of them.
    Reset(Option<IdentityPublicKey>),
}

impl Keep {
    fn lock_for(&self, pin: IdentityPublicKey) -> Arc<tokio::sync::Mutex<()>> {
        self.locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(pin)
            .or_default()
            .clone()
    }

    fn ended(&self, pin: IdentityPublicKey) -> (u64, Option<Failure>) {
        self.ends
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&pin)
            .cloned()
            .unwrap_or((0, None))
    }

    fn note_end(&self, pin: IdentityPublicKey, failure: Option<Failure>) {
        let mut ends = self.ends.lock().unwrap_or_else(|e| e.into_inner());
        let entry = ends.entry(pin).or_insert((0, None));
        *entry = (entry.0 + 1, failure);
    }

    /// Tell the keeper (once it runs).
    pub fn kick(&self, kick: Kick) {
        if let Some(tx) = self
            .kicks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            let _ = tx.send(kick);
        }
    }
}

/// The outbound connections to `pin`, by number.
/// The outbound connections to `pin`, oldest first: while a renewed path
/// waits for `path.reopened`, the older one is still current.
fn outbound(shared: &Shared, pin: &IdentityPublicKey) -> Vec<u64> {
    let mut out: Vec<u64> = super::lock(&shared.core)
        .conns
        .iter()
        .filter(|(_, e)| !e.inbound && e.identity == *pin)
        .map(|(no, _)| *no)
        .collect();
    out.sort_unstable();
    out
}

/// The role the stored record of `pin` names, as `conn.up` shows it.
pub(super) fn stored_role(shared: &Shared, pin: &IdentityPublicKey) -> Value {
    find_peer(shared, pin)
        .map(|record| json!(super::pairing::role_text(&record.role)))
        .unwrap_or(Value::Null)
}

pub(super) fn find_peer(shared: &Shared, pin: &IdentityPublicKey) -> Result<PeerRecord, DialError> {
    let key = hex(pin.as_bytes());
    PeerStore::in_dir(&shared.info.state_dir)
        .load()
        .map_err(|e| DialError::NoPeer(e.to_string()))?
        .into_iter()
        .find(|p| p.identity == key)
        .ok_or_else(|| DialError::NoPeer("not paired with that identity".into()))
}

/// Open an outbound path to the paired host `pin` and announce it with
/// `conn.up`. `fresh`: the app asked (`dial`), so a path is opened even if
/// one is up, unless another dial opened one while this one waited its
/// turn; if that other dial failed instead, its failure is the answer (it
/// ended after the app asked, and a host that refuses this device makes
/// each dial wait out its proof window: dialing again would double the
/// wait). Otherwise (the keeper) any outbound path will do.
pub async fn dial(
    shared: &Arc<Shared>,
    pin: IdentityPublicKey,
    fresh: bool,
) -> Result<Dialled, DialError> {
    // Read before the stored record: a forget after this point keeps the
    // path this dial opens from being published.
    let gen = shared.peer_gen(&pin);
    let before: HashSet<u64> = outbound(shared, &pin).into_iter().collect();
    let ended_before = shared.keep.ended(pin).0;
    let lock = shared.keep.lock_for(pin);
    let _turn = lock.lock().await;
    let now = outbound(shared, &pin);
    let reuse = if fresh {
        now.into_iter().find(|no| !before.contains(no))
    } else {
        now.into_iter().next()
    };
    if let Some(conn) = reuse {
        return Ok(Dialled {
            conn,
            already: true,
        });
    }
    if fresh && !cfg!(mousse_control = "dial-again-behind") {
        if let (ended, Some(failure)) = shared.keep.ended(pin) {
            if ended > ended_before {
                return Err(DialError::Same(failure));
            }
        }
    }
    if shared.removal.is_paused() {
        return Err(DialError::Paused);
    }
    let record = find_peer(shared, &pin)?;
    let reached = reach(shared, &record).await;
    shared
        .keep
        .note_end(pin, reached.as_ref().err().map(Failure::of));
    let (conn, used) = reached.map_err(DialError::Failed)?;
    // Only the route is noted, on the record as stored now.
    let _ = PeerStore::in_dir(&shared.info.state_dir).note_route(&pin, used.route.uri());
    applog::line(format!(
        "connected {} (out) at {}",
        short_id(&pin),
        used.route
    ));
    let role = super::pairing::role_text(&record.role);
    let fields = json!({"dir": "out", "role": role, "route": route_json(&used)});
    let no = match shared.add_outbound(conn, gen, fields) {
        Ok(no) => no,
        Err(super::Stale::Paused) => return Err(DialError::Paused),
        Err(super::Stale::Forgotten) => {
            return Err(DialError::NoPeer("forgotten while the path opened".into()))
        }
    };
    Ok(Dialled {
        conn: no,
        already: false,
    })
}

/// `dial {identity}`.
pub async fn dial_op(shared: Arc<Shared>, id: Value, identity: String) {
    let reply = match identity_from_hex(&identity) {
        Err(_) => error(&id, "bad_request", "dial needs identity (hex)"),
        Ok(pin) => {
            shared.keep.kick(Kick::Reset(Some(pin)));
            match dial(&shared, pin, true).await {
                Ok(d) => json!({"re": id, "conn": d.conn, "already": d.already}),
                Err(DialError::NoPeer(why)) => error(&id, "no_peer", why),
                Err(DialError::Paused) => super::pairing::paused(&shared, &id),
                Err(DialError::Failed(e)) => json!({
                    "re": id,
                    "error": "unreachable",
                    "reason": crate::peer::describe(&e),
                    "why": crate::peer::reason_of(&e),
                }),
                Err(DialError::Same(f)) => json!({
                    "re": id,
                    "error": "unreachable",
                    "reason": f.reason,
                    "why": f.why,
                }),
            }
        }
    };
    shared.event(reply);
}

/// `peer.addresses.set {identity, routes}`: the addresses the owner added
/// for a paired host, in place of the ones before. Any route kind; none
/// may name a forbidden address. Each becomes an `owner` approval, and the
/// owner approvals it no longer lists go.
pub fn set_addresses(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let identity = match map
        .get("identity")
        .and_then(Value::as_str)
        .map(identity_from_hex)
    {
        Some(Ok(identity)) => identity,
        _ => return error(id, "bad_request", "peer.addresses.set needs identity (hex)"),
    };
    // An SSH address set up by `ssh.resolve` comes as `{route_id,
    // selector, shell}` (§7); it is stored as its route's own alias,
    // `ssh://mousse-<route_id>`, which the ssh tier's dialer opens.
    let given = match map.get("routes") {
        Some(Value::Array(list)) => {
            let mut out = Vec::with_capacity(list.len());
            for entry in list {
                match entry {
                    Value::Object(fields) => match shared.ssh.bind(fields) {
                        Ok(uri) => out.push(Value::String(uri)),
                        Err(f) => return error(id, f.error, f.reason),
                    },
                    other => out.push(other.clone()),
                }
            }
            Some(Value::Array(out))
        }
        other => other.cloned(),
    };
    let routes = match parse_owner_routes(shared.caller.addr_policy(), given.as_ref()) {
        Ok(routes) => routes,
        Err((code, e)) => return error(id, code, e),
    };
    let key = hex(identity.as_bytes());
    let dir = &shared.info.state_dir;
    let at = crate::peer::now_secs();
    // The row and its owner approvals change together, under the peers
    // lock.
    let store = PeerStore::in_dir(dir);
    let changed = store.lock().and_then(|held| {
        if !held.load()?.iter().any(|p| p.identity == key) {
            return Ok(false);
        }
        ApprovalStore::in_dir(dir).update(&held, |list| {
            list.retain(|a| {
                a.identity != key
                    || a.source != APPROVAL_SOURCE_OWNER
                    || routes.contains(&a.destination)
            });
            for r in &routes {
                let has = list.iter().any(|a| {
                    a.identity == key && a.source == APPROVAL_SOURCE_OWNER && a.destination == *r
                });
                if !has {
                    list.push(Approval {
                        identity: key.clone(),
                        destination: r.clone(),
                        source: APPROVAL_SOURCE_OWNER.into(),
                        at,
                    });
                }
            }
        })?;
        held.update(|list| {
            if let Some(p) = list.iter_mut().find(|p| p.identity == key) {
                p.addresses = routes.clone();
            }
        })?;
        Ok(true)
    });
    match changed {
        Err(e) => error(id, "store_failed", e.to_string()),
        Ok(false) => error(id, "no_peer", "not paired with that identity"),
        Ok(true) => {
            approvals_changed(shared, &identity);
            shared.keep.kick(Kick::Reset(Some(identity)));
            json!({"re": id, "routes": routes})
        }
    }
}

/// When a host may be dialled again.
struct Retry {
    due: Instant,
    wait: Duration,
    /// The host refused this device: wait for a reset.
    parked: bool,
    running: bool,
}

/// Whether the host itself refused this device.
fn refused(e: &NetError) -> bool {
    matches!(
        crate::peer::reason_of(e).as_str(),
        "not_authorized" | "grant_revoked"
    )
}

/// Keep one outbound path to every paired host (§6). Runs from the first
/// `hello` until the channel ends.
pub async fn keep_connected(shared: Arc<Shared>) {
    let (tx, mut kicks) = mpsc::unbounded_channel();
    *shared.keep.kicks.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
    let limits = shared.limits;
    let first = crate::limits::ms(limits.keep_retry_first_ms());
    let longest = crate::limits::ms(limits.keep_retry_max_ms());
    let (done_tx, mut done) =
        mpsc::unbounded_channel::<(IdentityPublicKey, Result<(), NetError>)>();
    let mut hosts: HashMap<IdentityPublicKey, Retry> = HashMap::new();
    // Wait for the first kick: the app said hello.
    if kicks.recv().await.is_none() {
        return;
    }
    loop {
        let now = Instant::now();
        if !shared.removal.is_paused() {
            let peers = PeerStore::in_dir(&shared.info.state_dir)
                .load()
                .unwrap_or_default();
            let pins: Vec<IdentityPublicKey> = peers.iter().filter_map(|p| p.pin().ok()).collect();
            hosts.retain(|pin, r| r.running || pins.contains(pin));
            for pin in pins {
                let retry = hosts.entry(pin).or_insert(Retry {
                    due: now,
                    wait: first,
                    parked: false,
                    running: false,
                });
                if retry.running || retry.parked || now < retry.due {
                    continue;
                }
                if !outbound(&shared, &pin).is_empty() {
                    continue;
                }
                retry.running = true;
                let (shared, done_tx) = (shared.clone(), done_tx.clone());
                tokio::spawn(async move {
                    // Paused or forgotten meanwhile: nothing to report.
                    let result = match dial(&shared, pin, false).await {
                        Err(DialError::Failed(e)) => Err(e),
                        _ => Ok(()),
                    };
                    let _ = done_tx.send((pin, result));
                });
            }
        }
        let next = hosts
            .values()
            .filter(|r| !r.running && !r.parked)
            .map(|r| r.due)
            .filter(|due| *due > now)
            .min();
        let sleep = async {
            match next {
                Some(due) => tokio::time::sleep_until(due).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            kick = kicks.recv() => match kick {
                None => return,
                Some(Kick::Look) => {}
                Some(Kick::Reset(which)) => {
                    for (pin, r) in hosts.iter_mut() {
                        if which.is_none_or(|w| w == *pin) {
                            r.due = Instant::now();
                            r.wait = first;
                            r.parked = false;
                        }
                    }
                }
            },
            Some((pin, result)) = done.recv() => {
                let Some(r) = hosts.get_mut(&pin) else { continue };
                r.running = false;
                match result {
                    // Up: if it drops, the next try is after the first wait.
                    Ok(()) => {
                        r.wait = first;
                        r.due = Instant::now() + first;
                    }
                    Err(e) => {
                        let parked = refused(&e);
                        r.parked = parked;
                        r.due = Instant::now() + r.wait;
                        let retry_ms = (!parked).then_some(r.wait.as_millis() as u64);
                        r.wait = (r.wait * 2).min(longest);
                        applog::line(format!("dial {} failed: {e}", short_id(&pin)));
                        shared.event(json!({
                            "ev": "dial.failed",
                            "identity": hex(pin.as_bytes()),
                            "why": crate::peer::reason_of(&e),
                            "reason": crate::peer::describe(&e),
                            "retry_ms": retry_ms,
                        }));
                    }
                }
            }
            () = sleep => {}
        }
    }
}

#[cfg(debug_assertions)]
struct FileBrowse(std::path::PathBuf);

#[cfg(debug_assertions)]
impl BrowseSource for FileBrowse {
    fn browse(&self, _wait: Duration) -> mousse_net_io::discovery::BrowseFuture<'_> {
        Box::pin(async move {
            let text = std::fs::read_to_string(&self.0).unwrap_or_default();
            Ok(text
                .lines()
                .map(|l| l.trim().trim_start_matches("tcp://"))
                .filter_map(|l| l.parse().ok())
                .collect())
        })
    }
}

/// The browse source: in debug builds the file named by
/// `MOUSSE_HELPER_BROWSE_FILE` if set, else mDNS when `mdns` (never on a
/// loopback-only helper), else none.
pub fn browse_source(mdns: bool) -> Option<Arc<dyn BrowseSource>> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("MOUSSE_HELPER_BROWSE_FILE") {
        return Some(Arc::new(FileBrowse(path.into())));
    }
    mdns.then(|| Arc::new(mousse_net_io::discovery::MdnsBrowse) as Arc<dyn BrowseSource>)
}

/// `ssh.forget`: the route's address `uri` leaves every peer's owner
/// addresses, and its approvals go with it (§1.3).
pub(super) fn forget_address(shared: &Shared, uri: &str) -> Result<(), NetError> {
    let dir = &shared.info.state_dir;
    let mut touched: Vec<String> = Vec::new();
    PeerStore::in_dir(dir).lock().and_then(|held| {
        ApprovalStore::in_dir(dir).update(&held, |list| {
            list.retain(|a| {
                if a.destination == uri {
                    touched.push(a.identity.clone());
                    false
                } else {
                    true
                }
            });
        })?;
        held.update(|list| {
            for p in list.iter_mut() {
                if p.addresses.iter().any(|a| a == uri) {
                    p.addresses.retain(|a| a != uri);
                    touched.push(p.identity.clone());
                }
            }
        })
    })?;
    touched.sort();
    touched.dedup();
    for key in touched {
        if let Ok(identity) = identity_from_hex(&key) {
            approvals_changed(shared, &identity);
        }
    }
    Ok(())
}
