//! Moving a live path to the LAN (Phase 1b §1.4).
//!
//! A paired host reached any way but the LAN (tailnet, internet, tunnel,
//! SSH) is probed on its LAN candidates in the background, and a LAN path
//! that answers as the host takes over: it is announced with `conn.up` and
//! `path.reopen {from}`, and the app moves its streams with
//! `path.reopened`, as for a renewal. The old path stays current until
//! then. There is no round-trip race: a LAN path that passed step 1 wins.
//!
//! - **Candidates.** Only LAN ones: the stored candidates that are LAN IP
//!   literals (the automatic rule) and the browse's hosts, under the
//!   automatic rule only. A host whose LAN candidates are all another
//!   endpoint (a pin mismatch) is not reached; the live path is not
//!   touched. Nothing is browsed without a browse source: none runs with
//!   this computer's LAN off.
//! - **When.** The first probe comes `LAN_PROBE_FIRST_MS` after a host is
//!   reached another way, then after waits that double up to
//!   `LAN_PROBE_MAX_MS`, each within a fifth either way so hosts do not
//!   probe in step. A network change or a wake starts the waits over. At
//!   most `LAN_PROBE_PARALLEL` probes run at once, one per host.
//! - **One at a time.** A probe takes the host's dial turn and the
//!   caller's path turn without waiting: while a dial, a renewal or
//!   another candidate path is in progress it skips that round. It checks
//!   the pause, the host's generation (a forget), its route generation (an
//!   edit of its addresses or approvals) and that the old path is still up
//!   before it switches; otherwise the new path is closed.
//! - **Flapping.** A LAN path that ends within `LAN_STABLE_MS` of coming up
//!   holds probes off for `LAN_FLAP_COOLDOWN_MS`, doubling with each such
//!   end up to `LAN_FLAP_COOLDOWN_MAX_MS`; one that lasts resets it. When
//!   the LAN path ends, the keeper dials again as always (LAN first).
//! - **Relayed hosts** are left to the relay's own upgrade, which dials
//!   LAN first too.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_io::pipe::LocalRoute;
use mousse_net_io::store::{short_id, PeerRecord, PeerStore};
use mousse_net_io::{is_lan_route, RouteClass, Search};
use tokio::sync::Notify;
use tokio::time::Instant;

use super::{paths, Shared};
use crate::applog;

/// One host's probes.
struct Host {
    due: Instant,
    wait: Duration,
    running: bool,
}

/// One host's LAN flaps.
#[derive(Clone, Copy)]
struct Flaps {
    /// No probe before this.
    until: Instant,
    /// The hold-off the next flap sets.
    next: Duration,
}

/// The probes' state, shared with the keeper.
#[derive(Default)]
pub struct Lan {
    hosts: Mutex<HashMap<IdentityPublicKey, Host>>,
    flaps: Mutex<HashMap<IdentityPublicKey, Flaps>>,
    wake: Notify,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// `wait`, within a fifth either way.
fn jitter(wait: Duration) -> Duration {
    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    // 80 % to 120 %.
    let percent = 80 + random % 41;
    wait * u32::try_from(percent).unwrap_or(100) / 100
}

impl Lan {
    /// Look again: paths changed.
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// A network change or a wake: every host is probed again soon, its
    /// waits started over (a flap hold-off still holds).
    pub fn rearm(&self, first: Duration) {
        let now = Instant::now();
        for host in lock(&self.hosts).values_mut() {
            host.wait = first;
            host.due = now + jitter(first.min(Duration::from_millis(500)));
        }
        self.wake();
    }

    /// A LAN path to `pin` ended after `lasted`.
    pub fn lan_down(
        &self,
        pin: IdentityPublicKey,
        lasted: Duration,
        limits: &crate::limits::HelperLimits,
    ) {
        let stable = crate::limits::ms(limits.lan_stable_ms());
        let first = crate::limits::ms(limits.lan_flap_cooldown_ms());
        let longest = crate::limits::ms(limits.lan_flap_cooldown_max_ms());
        let mut flaps = lock(&self.flaps);
        if lasted >= stable {
            flaps.remove(&pin);
            return;
        }
        let entry = flaps.entry(pin).or_insert(Flaps {
            until: Instant::now(),
            next: first,
        });
        entry.until = Instant::now() + entry.next;
        applog::line(format!(
            "LAN path to {} ended after {lasted:?}: no LAN probe for {:?}",
            short_id(&pin),
            entry.next
        ));
        entry.next = (entry.next * 2).min(longest);
    }

    fn held_off(&self, pin: &IdentityPublicKey, now: Instant) -> Option<Instant> {
        lock(&self.flaps)
            .get(pin)
            .map(|f| f.until)
            .filter(|until| *until > now)
    }
}

/// What the app has to `pin` now: the oldest outbound path that is not on
/// the LAN, if the host has no LAN path and no path waiting to be
/// reopened. A relayed path counts only while the relay's own upgrade is
/// not running.
fn off_lan(shared: &Shared, pin: &IdentityPublicKey) -> Option<u64> {
    let upgrading = shared
        .keep
        .upgrading
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(pin);
    let core = super::lock(&shared.core);
    let mut out: Vec<(u64, &super::ConnEntry)> = core
        .conns
        .iter()
        .filter(|(_, e)| !e.inbound && e.identity == *pin)
        .map(|(no, e)| (*no, e))
        .collect();
    out.sort_unstable_by_key(|(no, _)| *no);
    if out.is_empty()
        || out
            .iter()
            .any(|(_, e)| e.reopen || e.class.as_deref() == Some(RouteClass::Lan.name()))
    {
        return None;
    }
    let (no, entry) = out[0];
    if entry.via.is_some() && upgrading {
        return None;
    }
    Some(no)
}

/// The LAN candidates of `record`'s host: its stored LAN literals, then
/// what the browse finds (a fresh cache, else a new browse).
async fn candidates(shared: &Shared, record: &PeerRecord) -> Vec<LocalRoute> {
    let policy = shared.caller.addr_policy();
    let mut out: Vec<LocalRoute> = paths::stored_search(policy, &shared.info.state_dir, record)
        .candidates
        .into_iter()
        .filter(|r| is_lan_route(policy, r))
        .collect();
    if let Some(browse) = &shared.info.browse {
        let found = match browse.cached() {
            Some(found) => found,
            None => browse.addresses().await.unwrap_or_default(),
        };
        for route in found.into_iter().map(LocalRoute::tcp) {
            if policy.automatic(&route) && !out.contains(&route) {
                out.push(route);
            }
        }
    }
    out
}

/// How a probe ended.
enum Probed {
    /// The host is moving to a LAN path.
    Moved,
    /// No LAN path came up.
    Nothing,
    /// Something else was bringing up a path: try again soon.
    Busy,
}

/// Probe `pin`'s LAN candidates while the path `from` carries it.
async fn probe(shared: &Arc<Shared>, pin: IdentityPublicKey, from: u64) -> Probed {
    let gen = shared.peer_gen(&pin);
    let Ok(_dial) = shared.keep.lock_for(pin).try_lock_owned() else {
        return Probed::Busy;
    };
    let Some(_turn) = shared.caller.try_path_turn(&pin) else {
        return Probed::Busy;
    };
    let routes_gen = shared.caller.route_generation(&pin);
    // Paused, forgotten, or its addresses or approvals edited meanwhile.
    let fenced = |shared: &Shared| {
        shared.removal.is_paused()
            || shared.peer_gen(&pin) != gen
            || shared.caller.route_generation(&pin) != routes_gen
    };
    if fenced(shared) || off_lan(shared, &pin) != Some(from) {
        return Probed::Busy;
    }
    let Ok(record) = paths::find_peer(shared, &pin) else {
        return Probed::Nothing;
    };
    let lan = candidates(shared, &record).await;
    if lan.is_empty() || fenced(shared) {
        return Probed::Nothing;
    }
    let (conn, used) = match shared.caller.search(Search::of(lan), pin).await {
        Ok(found) => found,
        Err(_) => return Probed::Nothing,
    };
    if used.class != RouteClass::Lan || fenced(shared) {
        conn.close(mousse_net_core::ErrorCode::Cancelled);
        return Probed::Nothing;
    }
    // If the old path ended meanwhile, this one is simply the host's path.
    paths::switch_to(shared, pin, from, gen, conn, &used, &record);
    Probed::Moved
}

/// Probe every host reached off the LAN, for as long as the channel runs.
pub async fn run(shared: Arc<Shared>) {
    let limits = shared.limits;
    let first = crate::limits::ms(limits.lan_probe_first_ms());
    let longest = crate::limits::ms(limits.lan_probe_max_ms());
    let parallel = usize::try_from(limits.lan_probe_parallel())
        .unwrap_or(1)
        .max(1);
    let (done_tx, mut done) = tokio::sync::mpsc::unbounded_channel::<(IdentityPublicKey, Probed)>();
    let lan = &shared.keep.lan;
    loop {
        let now = Instant::now();
        // The control build never moves a live path to the LAN.
        if !shared.removal.is_paused() && !cfg!(mousse_control = "no-lan-upgrade") {
            let pins: Vec<IdentityPublicKey> = PeerStore::in_dir(&shared.info.state_dir)
                .load()
                .unwrap_or_default()
                .iter()
                .filter_map(|p| p.pin().ok())
                .collect();
            let mut hosts = lock(&lan.hosts);
            let mut running = hosts.values().filter(|h| h.running).count();
            // Hosts with no path off the LAN start over when they have one.
            hosts.retain(|pin, h| {
                h.running || (pins.contains(pin) && off_lan(&shared, pin).is_some())
            });
            for pin in pins {
                let Some(from) = off_lan(&shared, &pin) else {
                    continue;
                };
                let host = hosts.entry(pin).or_insert_with(|| Host {
                    due: now + jitter(first),
                    wait: first,
                    running: false,
                });
                if host.running || now < host.due || running >= parallel {
                    continue;
                }
                if let Some(until) = lan.held_off(&pin, now) {
                    host.due = until;
                    continue;
                }
                host.running = true;
                running += 1;
                let (shared, done_tx) = (shared.clone(), done_tx.clone());
                tokio::spawn(async move {
                    let probed = probe(&shared, pin, from).await;
                    let _ = done_tx.send((pin, probed));
                });
            }
        }
        let next = lock(&lan.hosts)
            .values()
            .filter(|h| !h.running)
            .map(|h| h.due)
            .filter(|due| *due > now)
            .min();
        let sleep = async {
            match next {
                Some(due) => tokio::time::sleep_until(due).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = lan.wake.notified() => {}
            Some((pin, probed)) = done.recv() => {
                let mut hosts = lock(&lan.hosts);
                if let Some(host) = hosts.get_mut(&pin) {
                    host.running = false;
                    match probed {
                        Probed::Moved => {
                            hosts.remove(&pin);
                        }
                        Probed::Nothing => {
                            host.wait = (host.wait * 2).min(longest);
                            host.due = Instant::now() + jitter(host.wait);
                        }
                        Probed::Busy => host.due = Instant::now() + jitter(first),
                    }
                }
            }
            () = sleep => {}
        }
    }
}
