//! Reaching paired hosts (Phase 1a §5.3 and §6).
//!
//! - **Private ranges.** Every address a peer or the owner supplies (ticket
//!   hints, `peer.add` routes from a pairback, `peer.addresses.set`) must be
//!   a `tcp://` route to an IP in a private range; anything else is
//!   refused with `bad_route` (hints are skipped). Debug builds also take
//!   loopback, so tests run on one computer without listening on the LAN.
//! - **Candidates**, in order: the route that last worked, the addresses
//!   the owner added, the hints. They live in `peers.json`. When none of
//!   them answers as the host, the browse source (mDNS, cached) is asked
//!   and the addresses it found are tried too.
//! - **Dialling** is [`Caller::dial_candidates`](mousse_net_io::Caller):
//!   several at once, a pin mismatch moves on, the host's own refusal
//!   stops the search.
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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::pairing::Route;
use mousse_net_io::discovery::BrowseSource;
use mousse_net_io::pipe::{is_private_route, route_from_addr, route_ip, route_uri};
use mousse_net_io::store::{hex, identity_from_hex, short_id, PeerRecord, PeerStore};
use mousse_net_io::{Connection, NetError};
use serde_json::{json, Map, Value};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::{error, Shared};
use crate::applog;

/// Whether an address a peer or the owner supplied may be stored and
/// dialled (§5.3).
pub fn allowed_route(route: &Route) -> bool {
    if cfg!(mousse_control = "public-routes") {
        // The control build takes any TCP address.
        return matches!(route, Route::Tcp { .. });
    }
    is_private_route(route)
        || (cfg!(debug_assertions) && route_ip(route).is_some_and(|ip| ip.is_loopback()))
}

/// The hints of a ticket this helper may dial.
pub fn ticket_routes(hints: &[String]) -> Vec<Route> {
    crate::peer::usable_routes(hints)
        .into_iter()
        .filter(allowed_route)
        .collect()
}

/// Routes given on the app channel: a list of hints, each a `tcp://`
/// route in a private range. The error names the first that is not.
pub fn parse_routes(value: Option<&Value>) -> Result<Vec<String>, String> {
    let list = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(list)) => list,
        Some(_) => return Err("routes is a list of route hints".into()),
    };
    let mut out = Vec::new();
    for r in list {
        let route = match r.as_str().map(Route::parse) {
            Some(Ok(route)) => route,
            _ => return Err(format!("not a route: {r}")),
        };
        if !allowed_route(&route) {
            return Err(format!(
                "{} is not a private-range address (10/8, 172.16/12, 192.168/16, \
                 169.254/16 or fc00::/7)",
                route_uri(&route)
            ));
        }
        let uri = route_uri(&route);
        if !out.contains(&uri) {
            out.push(uri);
        }
    }
    Ok(out)
}

/// Where to look for `record`'s host before browsing: the last working
/// route, then the owner's addresses, then the hints.
fn stored_candidates(record: &PeerRecord) -> Vec<Route> {
    let last = record
        .last_route
        .as_deref()
        .and_then(|r| Route::parse(r).ok())
        .filter(|r| matches!(r, Route::Tcp { .. }));
    let mut out: Vec<Route> = last.into_iter().collect();
    if cfg!(mousse_control = "no-rediscovery") && !out.is_empty() {
        // The control build tries only the last working route. A pairing
        // that has none yet (its first dial) still uses its addresses, so
        // the control breaks finding a host that moved and nothing else.
        return out;
    }
    for hint in record.addresses.iter().chain(&record.routes) {
        if let Ok(route) = Route::parse(hint) {
            if allowed_route(&route) && !out.contains(&route) {
                out.push(route);
            }
        }
    }
    out
}

/// How a dial reached its host.
enum Reached {
    Direct(Route),
    Relay(mousse_net_core::relay_endpoint::RelayRoute),
}

/// Reach `record`'s host: direct routes and browse first, then its relay
/// routes (Phase 3 B.6, B.11). A refusal by the host itself ends it.
async fn reach(shared: &Shared, record: &PeerRecord) -> Result<(Connection, Reached), NetError> {
    let direct = reach_direct(shared, record).await;
    let first = match direct {
        Ok((conn, route)) => return Ok((conn, Reached::Direct(route))),
        Err(e @ NetError::Closed(_)) => return Err(e),
        Err(e) => e,
    };
    let pin = record.pin()?;
    if super::relay::candidates(shared, &pin).is_empty() {
        return Err(first);
    }
    match super::relay::reach(shared, &pin).await {
        Ok((conn, route)) => Ok((conn, Reached::Relay(route))),
        Err(e @ NetError::Closed(_)) => Err(e),
        Err(_) => Err(first),
    }
}

/// Reach `record`'s host directly: the stored candidates, then what the
/// browse source finds. Returns the live connection and the route it used.
async fn reach_direct(
    shared: &Shared,
    record: &PeerRecord,
) -> Result<(Connection, Route), NetError> {
    let pin = record.pin()?;
    let stored = stored_candidates(record);
    let first = match shared.caller.dial_candidates(&stored, pin).await {
        Ok(found) => return Ok(found),
        // The host itself refused: no other address changes that.
        Err(e @ NetError::Closed(_)) => return Err(e),
        Err(e) => e,
    };
    let Some(browse) = shared
        .info
        .browse
        .as_ref()
        .filter(|_| !cfg!(mousse_control = "no-rediscovery"))
    else {
        return Err(first);
    };
    let found = match browse.addresses().await {
        Ok(found) => found,
        Err(e) => {
            applog::line(format!("browse failed: {e}"));
            return Err(first);
        }
    };
    let more: Vec<Route> = found
        .into_iter()
        .map(route_from_addr)
        .filter(|r| !stored.contains(r))
        .collect();
    if more.is_empty() {
        return Err(first);
    }
    match shared.caller.dial_candidates(&more, pin).await {
        Ok((conn, used)) => {
            // Renewals try the stored candidates too, after this one.
            let mut order = vec![used.clone()];
            order.extend(stored.into_iter().chain(more).filter(|r| *r != used));
            shared.caller.remember_routes(pin, order);
            Ok((conn, used))
        }
        Err(e @ NetError::Closed(_)) => Err(e),
        Err(_) => Err(first),
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
    let role = super::pairing::role_text(&record.role);
    let mut fields = json!({"dir": "out", "role": role});
    let via = match used {
        Reached::Direct(used) => {
            // Only the route is noted, on the record as stored now.
            let _ = PeerStore::in_dir(&shared.info.state_dir).note_route(&pin, route_uri(&used));
            applog::line(format!(
                "connected {} (out) at {}",
                short_id(&pin),
                route_uri(&used)
            ));
            None
        }
        Reached::Relay(route) => {
            applog::line(format!(
                "connected {} (out) through relay {}",
                short_id(&pin),
                route.endpoint
            ));
            fields["route"] = super::relay::route_json(&route, false);
            Some(route)
        }
    };
    let no = match shared.add_outbound(conn, gen, fields) {
        Ok(no) => no,
        Err(super::Stale::Paused) => return Err(DialError::Paused),
        Err(super::Stale::Forgotten) => {
            return Err(DialError::NoPeer("forgotten while the path opened".into()))
        }
    };
    if let Some(route) = via {
        shared.set_via(no, route);
    }
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
/// for a paired host, in place of the ones before. Each must be in a
/// private range.
pub fn set_addresses(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let identity = match map
        .get("identity")
        .and_then(Value::as_str)
        .map(identity_from_hex)
    {
        Some(Ok(identity)) => identity,
        _ => return error(id, "bad_request", "peer.addresses.set needs identity (hex)"),
    };
    let routes = match parse_routes(map.get("routes")) {
        Ok(routes) => routes,
        Err(e) => return error(id, "bad_route", e),
    };
    let key = hex(identity.as_bytes());
    let mut found = false;
    let updated = PeerStore::in_dir(&shared.info.state_dir).update(|list| {
        if let Some(p) = list.iter_mut().find(|p| p.identity == key) {
            found = true;
            p.addresses = routes.clone();
        }
    });
    match updated {
        Err(e) => error(id, "store_failed", e.to_string()),
        Ok(()) if !found => error(id, "no_peer", "not paired with that identity"),
        Ok(()) => {
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
