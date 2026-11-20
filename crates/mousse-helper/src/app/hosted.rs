//! Hosted relays from Plus (Phase 4: §B.4, §B.10, §B.11, A.7, A.8): this
//! computer as a target on the relay fleet Plus runs, beside the owner's
//! own relays.
//!
//! **Home relay.** While this endpoint is linked to Plus, the helper reads
//! the fleet (`/v1/relays`, every `MOUSSE_NET_PLUS_FLEET_REFRESH_SECS` and at
//! once when its relay cannot be reached) and keeps one home relay: a
//! registration key per handle derived from the relay seed with a salt in
//! `hosted.json`, an admission token for each handle, `REGISTER` with the
//! token and the prefetch threshold, the same allow-set as the own relays,
//! and accept legs for `INCOMING`. The newest handle on the home relay is
//! the one Plus funds: its lease driver ([`crate::plus::lease`]) asks Plus
//! for blocks, presents them with `LEASE`, and follows `LEASE_STATUS`. The
//! token is renewed with `ADMIT` halfway through its window.
//!
//! **Handle rotation (§B.4).** Every `MOUSSE_NET_HANDLE_ROTATE_SECS` a new
//! key registers with its own token; the old one stays registered and in
//! the manifest for `MOUSSE_NET_MANIFEST_OVERLAP_SECS`, keeping what it
//! holds but asking for nothing, then sends `RELEASE` and ends.
//!
//! **Moving (§B.11).** When the home relay leaves the fleet, the first other
//! relay is staged (registered, no blocks, in the manifest); the cutover
//! comes after `MOUSSE_NET_VIA_RELAY_MOVE_STAGE_SECS`, or at once if the old
//! relay is gone: the old registrations `RELEASE` and end, the old route
//! leaves the manifest, and only then is the new relay funded
//! ([`crate::plus::relay_move`]).
//!
//! **Directory slots (§B.12).** A caller whose routes all fail reads the
//! host's directory slot (at most once per `MOUSSE_NET_PLUS_SLOT_READ_SECS`)
//! and keeps the manifest in it if the pinned host signed it and it is
//! newer: rotated and moved routes reach a caller that was offline through
//! the whole overlap.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use mousse_net_core::identity::{IdentityPublicKey, SoftwareKey};
use mousse_net_core::manifest::{ManifestRoute, MANIFEST_ENDPOINTS_MAX};
use mousse_net_core::relay::{RefuseReason, RelayClientKey, RelayId};
use mousse_net_core::relay_endpoint::{derive_key, RelayEndpoint, REGISTRATION_KEY_INFO};
use mousse_net_io::relay::{Proof, RelayError, TargetCommand, TargetEvent, TargetLink};
use mousse_net_io::rng::random_bytes;
use mousse_net_io::store::{hex, identity_from_hex, unhex, write_atomic};
use mousse_net_io::SystemClock;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{mpsc, watch};

use super::super::relay_store::{fixed, OldKey};
use super::{guard, limits, now, resolve, Run, Shared};
use crate::applog;
use crate::plus::lease::{self, Registration, RelayCommand, RelayEvent, StatusEntry};
use crate::plus::proto::{AdmissionToken, Class};
use crate::plus::relay_move::{MoveAction, RelayMove};
use crate::plus::{Failure, Plus};

/// The hosted relay state, in the endpoint's folder.
pub const HOSTED_FILE: &str = "hosted.json";

/// One hosted relay this endpoint registers on.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostedRelay {
    /// Relay id (hex).
    pub relay: String,
    /// The relay's identity key (hex, 65 bytes), from Plus's fleet.
    pub relay_key: String,
    /// Where it listens (`host:port`), from the fleet.
    pub endpoints: Vec<String>,
    /// Its region label.
    #[serde(default)]
    pub region: String,
    /// The current registration key's salt (hex).
    pub salt: String,
    /// When the current key started (rotation), or the relay was staged.
    pub since: u64,
    /// Older keys still in their overlap.
    #[serde(default)]
    pub old: Vec<OldKey>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct HostedFile {
    version: u32,
    /// The funded relay.
    #[serde(default)]
    home: Option<HostedRelay>,
    /// A move's new relay, while staged.
    #[serde(default)]
    staged: Option<HostedRelay>,
}

/// What a registration does with blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// The newest handle on the home relay: Plus funds it.
    Funded,
    /// An older handle, or a staged relay: keeps what it holds.
    Unfunded,
    /// `RELEASE` what it holds and end.
    Release,
}

/// One relay of the fleet, as Plus lists it.
#[derive(Clone, Debug)]
struct FleetRelay {
    relay: String,
    relay_key: String,
    region: String,
    endpoints: Vec<String>,
}

/// The hosted client's memory, in the relay state.
#[derive(Default)]
pub struct Runtime {
    /// Each running registration's role, by salt, with its relay.
    roles: HashMap<String, (String, watch::Sender<Role>)>,
    /// Salts whose registration is live.
    live: HashSet<String>,
    fleet: Option<Vec<FleetRelay>>,
    fleet_at: Option<u64>,
    /// Read the fleet again at the next step (a registration failed).
    refresh: bool,
    moving: Option<RelayMove>,
    /// The home relay waits for these old relays' runs to end before Plus
    /// funds it (A.8: one funded relay).
    fund_after: Option<String>,
    /// When each host's slot was last read (caller side).
    slot_reads: HashMap<String, u64>,
}

fn file_path(shared: &Shared) -> std::path::PathBuf {
    shared.info.state_dir.join(HOSTED_FILE)
}

fn load(shared: &Shared) -> HostedFile {
    std::fs::read(file_path(shared))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save(shared: &Shared, file: &HostedFile) {
    let mut f = file.clone();
    f.version = 1;
    match serde_json::to_vec(&f) {
        Ok(bytes) => {
            if let Err(e) = write_atomic(&file_path(shared), &bytes) {
                applog::line(format!("hosted relays: saving failed: {e}"));
            }
        }
        Err(e) => applog::line(format!("hosted relays: {e}")),
    }
}

fn new_salt() -> String {
    hex(&random_bytes::<16>())
}

fn registration_key(shared: &Shared, salt: &str) -> Result<SoftwareKey, String> {
    let salt = unhex(salt).map_err(|e| e.to_string())?;
    derive_key(shared.relay.seed()?, REGISTRATION_KEY_INFO, &salt).map_err(|e| e.to_string())
}

fn endpoints(relay: &HostedRelay) -> Vec<RelayEndpoint> {
    relay
        .endpoints
        .iter()
        .filter_map(|e| RelayEndpoint::parse(e))
        .take(MANIFEST_ENDPOINTS_MAX)
        .collect()
}

/// The routes the hosted relays add to this host's manifest: the home
/// relay's current handle and those still in their overlap, and a staged
/// relay's handle.
pub fn manifest_routes(shared: &Shared) -> Vec<ManifestRoute> {
    let file = load(shared);
    let t = now();
    let mut routes = Vec::new();
    for relay in file.home.iter().chain(file.staged.iter()) {
        let Ok(key) = identity_from_hex(&relay.relay_key) else {
            continue;
        };
        let eps = endpoints(relay);
        if eps.is_empty() {
            continue;
        }
        let id = RelayId::of(&key);
        let salts = std::iter::once(relay.salt.clone()).chain(
            relay
                .old
                .iter()
                .filter(|o| o.until > t)
                .map(|o| o.salt.clone()),
        );
        for salt in salts {
            let Ok(reg) = registration_key(shared, &salt) else {
                continue;
            };
            routes.push(ManifestRoute {
                relay_key: key,
                endpoints: eps.clone(),
                handle: RelayClientKey::new(reg).handle(&id),
                region: relay.region.clone(),
            });
        }
    }
    routes
}

/// The approved destination of a hosted relay, by id.
pub fn destination_of(shared: &Shared, relay: &str) -> Option<String> {
    let file = load(shared);
    file.home
        .iter()
        .chain(file.staged.iter())
        .find(|r| r.relay == relay)
        .and_then(|r| endpoints(r).into_iter().next())
        .map(|e| e.destination())
}

/// Keep the hosted relays while Plus is set up and linked. Runs for the
/// life of the channel.
pub async fn run(shared: Arc<Shared>) {
    if shared.relay.seed().is_err() {
        return;
    }
    let mut tick = tokio::time::interval(crate::limits::ms(limits().via_relay_check_ms()));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let Some(plus) = shared.engine.plus().cloned() else {
            continue;
        };
        if !plus.is_linked() {
            stop_all(&shared);
            continue;
        }
        step(&shared, &plus).await;
    }
}

fn stop_all(shared: &Shared) {
    let mut rt = guard(&shared.relay.hosted);
    for (_, role) in rt.roles.values() {
        role.send_replace(Role::Release);
    }
    rt.fleet = None;
    rt.fleet_at = None;
}

async fn read_fleet(shared: &Shared, plus: &Plus) {
    let t = now();
    let due = {
        let rt = guard(&shared.relay.hosted);
        rt.refresh
            || rt
                .fleet_at
                .is_none_or(|at| t >= at.saturating_add(limits().plus_fleet_refresh_secs()))
    };
    if !due {
        return;
    }
    match plus.relays().await {
        Ok(list) => {
            let fleet = list
                .into_iter()
                .filter_map(|(key, region, endpoints)| {
                    let key = identity_from_hex(&hex(&key)).ok()?;
                    Some(FleetRelay {
                        relay: hex(&RelayId::of(&key).0),
                        relay_key: hex(key.as_bytes()),
                        region,
                        endpoints,
                    })
                })
                .collect();
            let mut rt = guard(&shared.relay.hosted);
            rt.fleet = Some(fleet);
            rt.fleet_at = Some(t);
            rt.refresh = false;
        }
        Err(e) => applog::line(format!("hosted relays: reading the fleet failed: {e}")),
    }
}

fn new_relay(f: &FleetRelay, t: u64) -> HostedRelay {
    HostedRelay {
        relay: f.relay.clone(),
        relay_key: f.relay_key.clone(),
        endpoints: f.endpoints.clone(),
        region: f.region.clone(),
        salt: new_salt(),
        since: t,
        old: Vec::new(),
    }
}

/// One pass: the fleet, the home relay, a move, rotation and overlaps,
/// then the registrations that should run.
async fn step(shared: &Arc<Shared>, plus: &Arc<Plus>) {
    read_fleet(shared, plus).await;
    let Some(fleet) = guard(&shared.relay.hosted).fleet.clone() else {
        return;
    };
    let t = now();
    let h = limits();
    let mut file = load(shared);
    let before = file.clone_parts();
    let mut releases: Vec<String> = Vec::new();
    let mut events = Vec::new();
    {
        let mut rt = guard(&shared.relay.hosted);
        if file.home.is_none() {
            file.home = fleet.first().map(|f| new_relay(f, t));
        }
        // The home relay left the fleet: stage the first other one.
        if let Some(home) = &file.home {
            let listed = fleet.iter().any(|f| f.relay == home.relay);
            if !listed && file.staged.is_none() {
                if let Some(next) = fleet.iter().find(|f| f.relay != home.relay) {
                    let staged = new_relay(next, t);
                    let mut mv = RelayMove::new(h.via_relay_move_stage_secs());
                    let to = fixed::<32>(&staged.relay).unwrap_or_default();
                    for action in mv.staged(to, t) {
                        if let MoveAction::FundNew(_) = action {
                            // Only the fund-two-relays control asks for this
                            // while the old relay still holds blocks.
                            rt.fund_after = None;
                        }
                    }
                    rt.moving = Some(mv);
                    file.staged = Some(staged);
                }
            }
        }
        // Cut over when the stage ends, or at once if the old relay is gone.
        let home_live = file.home.as_ref().is_some_and(|home| {
            std::iter::once(&home.salt)
                .chain(home.old.iter().map(|o| &o.salt))
                .any(|s| rt.live.contains(s))
        });
        if let (Some(home), Some(mv)) = (file.home.clone(), rt.moving.as_mut()) {
            for action in mv.tick(t, !home_live) {
                match action {
                    MoveAction::ReleaseOld => {
                        releases.push(home.salt.clone());
                        releases.extend(home.old.iter().map(|o| o.salt.clone()));
                    }
                    MoveAction::DropOldRoute => {
                        if let Some(mut staged) = file.staged.take() {
                            staged.since = t;
                            file.home = Some(staged);
                        }
                    }
                    MoveAction::Interrupted => {
                        events.push(json!({"ev": "plus.relay.moving", "from": home.relay}));
                    }
                    MoveAction::FundNew(_) => rt.fund_after = Some(home.relay.clone()),
                    MoveAction::Done(_) => {}
                }
            }
        }
        // Rotation, and the end of old handles' overlaps.
        if let Some(home) = file.home.as_mut() {
            if file.staged.is_none() && t >= home.since.saturating_add(h.handle_rotate_secs()) {
                let old = std::mem::replace(&mut home.salt, new_salt());
                home.old.push(OldKey {
                    salt: old,
                    until: t.saturating_add(h.manifest_overlap_secs()),
                });
                home.since = t;
            }
            for o in home.old.iter().filter(|o| o.until <= t) {
                releases.push(o.salt.clone());
            }
            home.old.retain(|o| o.until > t);
        }
        // Plus funds the new relay only once the old relay's runs ended
        // (their `RELEASE` sent), so one relay holds blocks at a time.
        if let Some(old) = rt.fund_after.clone() {
            let old_running = rt.roles.values().any(|(relay, _)| *relay == old);
            if !old_running {
                rt.fund_after = None;
                if let Some(mv) = rt.moving.as_mut() {
                    for action in mv.funded() {
                        if let MoveAction::Done(_) = action {
                            events.push(json!({"ev": "plus.relay.moved"}));
                        }
                    }
                }
                rt.moving = None;
            }
        }
    }
    if file.clone_parts() != before {
        save(shared, &file);
    }
    for e in events {
        shared.event(e);
    }
    ensure_runs(shared, plus, &file, &releases);
    super::rebuild_manifest(shared);
}

impl HostedFile {
    fn clone_parts(&self) -> (Option<HostedRelay>, Option<HostedRelay>) {
        (self.home.clone(), self.staged.clone())
    }
}

/// Start the registrations that should run and give each its role; those
/// in `releases` (and any no longer wanted) release and end.
fn ensure_runs(shared: &Arc<Shared>, plus: &Arc<Plus>, file: &HostedFile, releases: &[String]) {
    let mut wanted: Vec<(HostedRelay, String, Role)> = Vec::new();
    let funding_waits = guard(&shared.relay.hosted).fund_after.is_some();
    if let Some(home) = &file.home {
        let role = if funding_waits {
            Role::Unfunded
        } else {
            Role::Funded
        };
        wanted.push((home.clone(), home.salt.clone(), role));
        for o in &home.old {
            wanted.push((home.clone(), o.salt.clone(), Role::Unfunded));
        }
    }
    if let Some(staged) = &file.staged {
        wanted.push((staged.clone(), staged.salt.clone(), Role::Unfunded));
    }
    let mut start = Vec::new();
    {
        let rt = guard(&shared.relay.hosted);
        for (salt, (_, role)) in rt.roles.iter() {
            let keep = wanted.iter().find(|(_, s, _)| s == salt);
            let next = match keep {
                Some((_, _, r)) if !releases.contains(salt) => *r,
                _ => Role::Release,
            };
            if *role.borrow() != Role::Release {
                role.send_if_modified(|r| {
                    let changed = *r != next;
                    *r = next;
                    changed
                });
            }
        }
        for (relay, salt, role) in wanted {
            if !rt.roles.contains_key(&salt) && !releases.contains(&salt) {
                start.push((relay, salt, role));
            }
        }
    }
    for (relay, salt, role) in start {
        start_run(shared, plus, &relay, salt, role);
    }
}

fn start_run(
    shared: &Arc<Shared>,
    plus: &Arc<Plus>,
    relay: &HostedRelay,
    salt: String,
    role: Role,
) {
    let Ok(key) = registration_key(shared, &salt) else {
        return;
    };
    let (role_tx, role_rx) = watch::channel(role);
    let (commands, commands_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(registration(
        shared.clone(),
        plus.clone(),
        relay.clone(),
        salt.clone(),
        key,
        role_rx,
        commands_rx,
    ));
    guard(&shared.relay.runs)
        .entry(relay.relay.clone())
        .or_default()
        .push(Run {
            salt: salt.clone(),
            commands,
            task: task.abort_handle(),
        });
    guard(&shared.relay.hosted)
        .roles
        .insert(salt, (relay.relay.clone(), role_tx));
}

/// One hosted registration (one key on one relay), kept up until it
/// releases or its role sender goes.
async fn registration(
    shared: Arc<Shared>,
    plus: Arc<Plus>,
    relay: HostedRelay,
    salt: String,
    key: SoftwareKey,
    mut role: watch::Receiver<Role>,
    mut commands: mpsc::UnboundedReceiver<TargetCommand>,
) {
    let h = limits();
    let first_wait = crate::limits::ms(h.via_relay_retry_first_ms());
    let longest = crate::limits::ms(h.via_relay_retry_max_ms());
    let mut wait = first_wait;
    let reg_key = Arc::new(RelayClientKey::new(key.clone()));
    let id = fixed::<32>(&relay.relay).map(RelayId);
    let mut token: Option<AdmissionToken> = None;
    while let Some(id) = id {
        if *role.borrow() == Role::Release {
            break;
        }
        let t = crate::peer::now_secs();
        if token.as_ref().is_none_or(|tk| tk.not_after <= t) {
            match plus.admission(&id.0, &key).await {
                Ok(tk) => token = Some(tk),
                Err(e) => {
                    applog::line(format!("hosted relay: no admission token: {e}"));
                    let pause = e.retry_after().unwrap_or(wait);
                    tokio::time::sleep(pause).await;
                    wait = (wait * 2).min(longest);
                    continue;
                }
            }
        }
        let Some(tk) = token.clone() else { continue };
        match register(&shared, &relay, id, reg_key.clone(), tk.envelope.clone()).await {
            Ok(link) => {
                wait = first_wait;
                let end = hold(
                    &shared,
                    &plus,
                    &relay,
                    &salt,
                    &key,
                    link,
                    &mut role,
                    &mut commands,
                    &mut token,
                )
                .await;
                applog::line(format!("hosted relay registration ended: {end}"));
                if *role.borrow() == Role::Release {
                    break;
                }
                // Closed unfunded past the token's window: a new token.
                if matches!(end, RelayError::Closed(Some(4004))) {
                    token = None;
                }
            }
            // Refused for `not before`, or before the relay's first Plus
            // answer: the same token a moment later (A.9 duty 9).
            Err(RelayError::Refused(RefuseReason::Admission)) => {
                tokio::time::sleep(crate::limits::ms(h.plus_not_before_retry_ms())).await;
                continue;
            }
            Err(e) => {
                applog::line(format!("hosted relay {}: {e}", relay.relay));
                guard(&shared.relay.hosted).refresh = true;
            }
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(longest);
    }
    // Gone: forget the run.
    {
        let mut rt = guard(&shared.relay.hosted);
        rt.live.remove(&salt);
        rt.roles.remove(&salt);
    }
    let mut runs = guard(&shared.relay.runs);
    if let Some(list) = runs.get_mut(&relay.relay) {
        list.retain(|r| r.salt != salt);
        if list.is_empty() {
            runs.remove(&relay.relay);
        }
    }
}

async fn register(
    shared: &Shared,
    relay: &HostedRelay,
    id: RelayId,
    key: Arc<RelayClientKey>,
    token: Vec<u8>,
) -> Result<TargetLink, RelayError> {
    let threshold = u8::try_from(limits().plus_prefetch_percent()).unwrap_or(50);
    let mut last = RelayError::Unreachable;
    for endpoint in endpoints(relay) {
        // A Plus relay is a peer-supplied destination for nobody: the host
        // registers there, so only public or tailnet addresses (debug
        // builds also take loopback).
        let addrs = match resolve(shared.caller.addr_policy(), &endpoint, false).await {
            Ok(a) => a,
            Err(e) => {
                last = e;
                continue;
            }
        };
        for addr in addrs {
            let proof = Proof::Hosted {
                token: token.clone(),
                threshold,
            };
            match TargetLink::register(&addr, id, key.clone(), proof, super::dial_within()).await {
                Ok(link) => return Ok(link),
                Err(e) => last = e,
            }
        }
    }
    Err(last)
}

fn status_entry(e: &mousse_net_core::relay::msg::LeaseStatusEntry) -> Option<StatusEntry> {
    Some(StatusEntry {
        lease_id: e.lease,
        class: Class::from_code(e.class as u64)?,
        used: e.used,
        bytes: e.bytes,
        state: e.state,
    })
}

/// When to renew a token: halfway through its window.
fn renew_in(token: &AdmissionToken) -> Duration {
    let t = crate::peer::now_secs();
    let at = token.not_before + token.not_after.saturating_sub(token.not_before) / 2;
    Duration::from_secs(at.saturating_sub(t).max(1))
}

/// Keep one live hosted registration until it ends, or until it released
/// what it held.
#[allow(clippy::too_many_arguments)]
async fn hold(
    shared: &Arc<Shared>,
    plus: &Arc<Plus>,
    relay: &HostedRelay,
    salt: &str,
    key: &SoftwareKey,
    link: TargetLink,
    role: &mut watch::Receiver<Role>,
    commands: &mut mpsc::UnboundedReceiver<TargetCommand>,
    token: &mut Option<AdmissionToken>,
) -> RelayError {
    let h = limits();
    let id = link.handle();
    let reg = Registration {
        relay_id: fixed::<32>(&relay.relay).unwrap_or_default(),
        boot_id: link.boot_id(),
        handle: id,
    };
    guard(&shared.relay.hosted).live.insert(salt.to_owned());
    let (events_tx, mut events) = mpsc::unbounded_channel();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let run = link.run(
        shared.relay.allow.subscribe(),
        cmd_rx,
        events_tx,
        crate::limits::ms(h.via_relay_keepalive_ms()),
        crate::limits::ms(h.via_relay_idle_ms()),
        h.via_relay_accept_legs() as usize,
    );
    tokio::pin!(run);
    let (lease_tx, lease_rx) = mpsc::unbounded_channel();
    let (lcmd_tx, mut lcmd_rx) = mpsc::unbounded_channel();
    let now_role = *role.borrow_and_update();
    tokio::spawn(lease::run_funded(
        plus.clone(),
        reg,
        now_role == Role::Funded,
        lease_rx,
        lcmd_tx,
        shared.engine.events(),
        Arc::new(SystemClock::new()),
    ));
    let mut releasing = now_role == Role::Release;
    if releasing {
        let _ = lease_tx.send(RelayEvent::ReleaseAll);
    }
    let (renewed_tx, mut renewed) = mpsc::unbounded_channel::<Result<AdmissionToken, Failure>>();
    let mut renew_at =
        tokio::time::Instant::now() + token.as_ref().map_or(Duration::from_secs(60), renew_in);
    let mut renewing = false;
    let mut lease_done = false;
    let mut role_gone = false;
    let mut done_at: Option<tokio::time::Instant> = None;
    let end = loop {
        tokio::select! {
            end = &mut run => break end,
            Some(cmd) = commands.recv() => {
                let _ = cmd_tx.send(cmd);
            }
            Some(event) = events.recv() => match event {
                TargetEvent::Incoming { circuit, class, caller, pipe } => {
                    tokio::spawn(super::accept_incoming(
                        shared.clone(),
                        relay.relay.clone(),
                        salt.to_owned(),
                        circuit,
                        caller.is_none(),
                        class,
                        pipe,
                    ));
                }
                TargetEvent::AcceptFailed { error, .. } => {
                    applog::line(format!("hosted relay accept leg failed: {error}"));
                }
                // Hosted relays rotate handles, not by SUCCESSOR.
                TargetEvent::AllowSetOk { .. } | TargetEvent::ChainFull => {}
                TargetEvent::LeaseStatus(entries) => {
                    let entries = entries.iter().filter_map(status_entry).collect();
                    let _ = lease_tx.send(RelayEvent::Status(entries));
                }
            },
            lc = lcmd_rx.recv(), if !lease_done => match lc {
                Some(RelayCommand::Lease(block)) => {
                    let _ = cmd_tx.send(TargetCommand::Lease(block));
                }
                Some(RelayCommand::Release(ids)) => {
                    let _ = cmd_tx.send(TargetCommand::Release(ids));
                }
                // The lease driver ended: after a release, give the
                // registration a moment to send it, then end.
                None => {
                    lease_done = true;
                    if releasing {
                        done_at = Some(tokio::time::Instant::now() + Duration::from_millis(500));
                    }
                }
            },
            changed = role.changed(), if !role_gone => {
                let next = if changed.is_ok() { *role.borrow_and_update() } else { Role::Release };
                match next {
                    Role::Funded => { let _ = lease_tx.send(RelayEvent::Funded(true)); }
                    Role::Unfunded => { let _ = lease_tx.send(RelayEvent::Funded(false)); }
                    Role::Release => {
                        if !releasing {
                            releasing = true;
                            let _ = lease_tx.send(RelayEvent::ReleaseAll);
                        }
                    }
                }
                if changed.is_err() {
                    // Nobody keeps this run: it releases and ends.
                    role_gone = true;
                }
            }
            () = tokio::time::sleep_until(renew_at), if !renewing => {
                renewing = true;
                let plus = plus.clone();
                let key = key.clone();
                let relay_id = reg.relay_id;
                let tx = renewed_tx.clone();
                tokio::spawn(async move {
                    let _ = tx.send(plus.admission(&relay_id, &key).await);
                });
            }
            Some(got) = renewed.recv() => {
                renewing = false;
                match got {
                    Ok(tk) => {
                        let _ = cmd_tx.send(TargetCommand::Admit(tk.envelope.clone()));
                        renew_at = tokio::time::Instant::now() + renew_in(&tk);
                        *token = Some(tk);
                    }
                    Err(e) => {
                        applog::line(format!("hosted relay: renewing the token failed: {e}"));
                        renew_at = tokio::time::Instant::now()
                            + e.retry_after().unwrap_or(crate::limits::ms(h.plus_retry_first_ms()));
                    }
                }
            }
            () = async {
                match done_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => break RelayError::Closed(None),
        }
    };
    let _ = lease_tx.send(RelayEvent::Closed);
    guard(&shared.relay.hosted).live.remove(salt);
    end
}

// ---------------------------------------------------------------------------
// Caller: a host's directory slot

/// No route reached `pin`: read its directory slot and keep the manifest in
/// it if the pinned host signed it and it is newer. Returns whether a newer
/// manifest came. At most once per `MOUSSE_NET_PLUS_SLOT_READ_SECS` a host.
pub async fn from_slot(shared: &Shared, pin: &IdentityPublicKey) -> bool {
    let Some(plus) = shared.engine.plus().cloned() else {
        return false;
    };
    let Some(secret) = super::caller_pair_secret(shared, pin) else {
        return false;
    };
    let key = hex(pin.as_bytes());
    let t = now();
    {
        let mut rt = guard(&shared.relay.hosted);
        if rt
            .slot_reads
            .get(&key)
            .is_some_and(|at| t < at.saturating_add(limits().plus_slot_read_secs()))
        {
            return false;
        }
        rt.slot_reads.insert(key, t);
    }
    match crate::engine::mailbox::read_slot(&plus, pin, &secret).await {
        Ok((manifest, _inbox)) => super::take_manifest(shared, pin, &manifest),
        Err(e) => {
            applog::line(format!("no manifest from the directory slot: {e}"));
            false
        }
    }
}
