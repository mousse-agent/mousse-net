//! Relays on the app channel (Phase 3 §B.4 to §B.12): this computer as a
//! relay target, and as a caller that reaches its hosts through theirs.
//!
//! **Own relays (target).** `relay.enroll {link}` dials the relay pinned to
//! the link's relay id and sends `ENROLL` with a new registration key;
//! pasting the link is also the owner's approval of that destination. Each
//! own relay keeps a registration (`REGISTER` after the first), started in
//! the background after ready and made again with backoff
//! (`VIA_RELAY_RETRY_*`). Every `INCOMING` gets an accept leg on a new
//! connection, and the spliced pipe runs the host side of a peer session
//! like any inbound connection.
//!
//! **Allow-set.** One set for every own relay: the caller key fingerprints
//! of live grants, oldest grant first, at most 256 (a pairing past the
//! 256th has none and its row says so), the tag hashes of open invitations
//! that carry a relay hint, and recovery entries (§B.7). It is computed
//! from the host's grants in memory and pushed after every change: a
//! journaled removal, a pairing, a caller key, an invitation opening or
//! ending. A replayed removal is applied before any registration starts.
//!
//! **Per-pairing material** (§B.12, wire minor 1): the caller opens
//! `mousse-keys` with its caller key for this host and keeps the pair
//! secret the host answers. The host opens `mousse-manifest` with its
//! signed manifest on each inbound connection once the caller has opened a
//! stream, and again on every change.
//!
//! **Calling through a relay.** After direct routes and browse, the dial
//! tries relay routes: the manifest's (fresh first, stale last) and those
//! of the ticket this device joined with. A route is dialled only when its
//! destination (`relay://host:port`) is approved for that host: by the
//! ticket at Connect, by the owner, or by the owner allowing a manifest
//! route (`peer.relay.allow`). Its addresses must classify as public or
//! tailnet (debug builds also take loopback). Bulk streams on a relay
//! connection go over a second relay call of class bulk with its own peer
//! session.
//!
//! **Keys.** Registration keys, caller keys and pair secrets are derived
//! from the endpoint's relay seed (kept where its identity is kept) with
//! salts in the state files ([`super::relay_store`]). Caller keys are per
//! host. What a caller is given (a host's pair secret, a ticket's
//! invitation tag) is sealed under a key from the same seed. A key
//! rotation is journaled and finished across restarts: the old key stays
//! current until the relay has registered the new one.
//!
//! **Ending paths.** Disallowing a relay destination closes the paths to
//! that host through it (and every dial checks the approval as it is
//! then); removing an own relay closes the sessions through it.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use mousse_net_core::grants::GrantId;
use mousse_net_core::identity::{IdentityPublicKey, IdentityRecord, PublicKey};
use mousse_net_core::manifest::{Envelope, Manifest, ManifestRoute, MANIFEST_ROUTES_MAX};
use mousse_net_core::mux::PriorityClass;
use mousse_net_core::pairing::{InvitationId, Ticket};
use mousse_net_core::pairmail::{self, PairSecret};
use mousse_net_core::relay::msg::{
    InvitationEntry, ALLOW_CALLERS_MAX, ALLOW_INVITATIONS_MAX, RELAY_MESSAGE_MAX,
};
use mousse_net_core::relay::proof::{invitation_tag, tag_hash};
use mousse_net_core::relay::{Class, EnrollmentLink, RelayClientKey, RelayId, RelayLimits};
use mousse_net_core::relay_endpoint::{
    decode_keys_answer, decode_keys_request, derive_key, derive_secret, encode_keys_answer,
    encode_keys_request, RelayEndpoint, RelayRoute, CALLER_KEY_INFO, PAIR_SECRET_INFO,
    REGISTRATION_KEY_INFO,
};
use mousse_net_core::{ConnectionId, ErrorCode};
use mousse_net_io::pipe::{test_egress, AddrClass, AddrPolicy};
use mousse_net_io::relay::{
    dial_call, dial_join, AllowSet, Proof, RelayAddr, RelayError, TargetCommand, TargetEvent,
    TargetLink, WsPipe,
};
use mousse_net_io::rng::random_bytes;

use crate::engine::stream as engine_stream;
use mousse_net_io::store::{
    hex, identity_from_hex, short_id, unhex, Approval, ApprovalStore, PeerStore,
};
use mousse_net_io::{ConnStatus, Connection, MuxStream, NetError};
use serde_json::{json, Map, Value};
use tokio::sync::{mpsc, watch};
use tokio::task::AbortHandle;
use zeroize::Zeroizing;

use super::relay_store::{
    fixed, Files, GrantKey, OldKey, OwnRelay, PeerRelay, PendingKey, Recovery,
};

/// Hosted relays from Plus (Phase 4).
#[path = "hosted.rs"]
pub mod hosted;
use super::{error, AppInfo, Shared};
use crate::applog;

/// The engine stream a caller opens to enroll its caller key.
pub const KEYS_LABEL: &str = "mousse-keys";
/// The engine stream a host opens to send its manifest.
pub const MANIFEST_LABEL: &str = "mousse-manifest";
/// The wire minor version that has both.
pub const KEYS_MINOR: u64 = 1;

/// The clock skew every check allows (wire.md 5.3): an old key leaves the
/// manifest this much before the relay could drop it.
const CLOCK_SKEW_SECS: u64 = 600;

/// The requests this module answers.
pub const OPS: [&str; 6] = [
    "relay.enroll",
    "relay.list",
    "relay.remove",
    "relay.rotate",
    "peer.relay.allow",
    "peer.relay.disallow",
];

/// A join circuit: the relay, the registration's salt and the circuit id.
type JoinCircuit = (String, String, [u8; 16]);

/// Where one of this computer's relays stands.
#[derive(Clone, Debug, Default)]
struct Status {
    state: &'static str,
    reason: Option<String>,
    retry_ms: Option<u64>,
}

/// A running registration: one per own relay and key.
struct Run {
    salt: String,
    commands: mpsc::UnboundedSender<TargetCommand>,
    task: AbortHandle,
}

/// An open invitation that carries a relay hint.
#[derive(Clone)]
struct OpenInvite {
    invitation: InvitationId,
    tag_hash: [u8; 32],
    expires_at: u64,
}

/// The relay side of one app channel.
pub struct State {
    seed: Result<Zeroizing<[u8; 32]>, String>,
    files: Files,
    /// File read-change-write steps run one at a time.
    io: Mutex<()>,
    allow: watch::Sender<AllowSet>,
    runs: Mutex<HashMap<String, Vec<Run>>>,
    status: Mutex<HashMap<String, Status>>,
    invites: Mutex<Vec<OpenInvite>>,
    /// Inbound connections that came on a join circuit: the relay, the
    /// registration's salt and the circuit (for `PROMOTE`).
    join_circuits: Mutex<HashMap<ConnectionId, JoinCircuit>>,
    /// This host's current signed manifest.
    manifest: Mutex<Option<(Manifest, Envelope)>>,
    /// Inbound connections (by number) that got the current manifest.
    manifest_sent: Mutex<HashSet<u64>>,
    /// Bulk companions of relay connections, by the main one's number.
    bulk: tokio::sync::Mutex<HashMap<u64, Arc<Connection>>>,
    /// Inbound sessions through each own relay (by relay id), by
    /// connection number, so removing the relay ends them.
    sessions: Mutex<HashMap<String, HashSet<u64>>>,
    /// The hosted relays' registrations (Phase 4).
    hosted: Mutex<hosted::Runtime>,
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The app's manual clock in debug builds that run on one (`test.clock`
/// moves it), so manifest expiry and overlaps can be tested.
static MANUAL: std::sync::OnceLock<Arc<mousse_net_io::ManualClock>> = std::sync::OnceLock::new();

fn now() -> u64 {
    use mousse_net_io::Clock;
    match MANUAL.get() {
        Some(clock) => clock.now().secs(),
        None => crate::peer::now_secs(),
    }
}

impl State {
    pub fn new(info: &AppInfo) -> Self {
        let seed = mousse_net_io::keystore::relay_seed(
            &info.state_dir,
            &info.endpoint_id,
            info.key_storage,
        )
        .map_err(|e| e.to_string());
        if let Err(e) = &seed {
            applog::line(format!("relays are off: the relay seed failed ({e})"));
        }
        if let Some(clock) = &info.manual_clock {
            let _ = MANUAL.set(clock.clone());
        }
        let (allow, _) = watch::channel(AllowSet::default());
        Self {
            seed,
            files: Files::in_dir(&info.state_dir),
            io: Mutex::new(()),
            allow,
            runs: Mutex::new(HashMap::new()),
            status: Mutex::new(HashMap::new()),
            invites: Mutex::new(Vec::new()),
            join_circuits: Mutex::new(HashMap::new()),
            manifest: Mutex::new(None),
            manifest_sent: Mutex::new(HashSet::new()),
            bulk: tokio::sync::Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            hosted: Mutex::new(hosted::Runtime::default()),
        }
    }

    fn seed(&self) -> Result<&[u8; 32], String> {
        self.seed.as_ref().map(|s| &**s).map_err(Clone::clone)
    }

    fn key(&self, info: &str, salt: &str) -> Result<Arc<RelayClientKey>, String> {
        let salt = unhex(salt).map_err(|e| e.to_string())?;
        derive_key(self.seed()?, info, &salt)
            .map(|k| Arc::new(RelayClientKey::new(k)))
            .map_err(|e| e.to_string())
    }
}

fn limits() -> &'static crate::limits::HelperLimits {
    crate::limits::helper()
}

fn dial_within() -> Duration {
    crate::limits::ms(limits().via_relay_dial_ms())
}

// ---------------------------------------------------------------------------
// Address classes (Phase 1b §1.2)

/// Whether a relay endpoint address of `class` may be dialled. The owner's
/// own relay (`own`) may be any class the policy dials; a peer's relay
/// route only public or tailnet (§B.11), so a host's ticket or manifest
/// cannot point its callers at their LAN. Debug builds also take loopback,
/// for tests on one computer.
fn relay_class_ok(class: AddrClass, own: bool, loopback: bool) -> bool {
    match class {
        AddrClass::Forbidden => false,
        AddrClass::Public | AddrClass::Tailnet => true,
        AddrClass::Lan => own || (loopback && cfg!(debug_assertions)),
    }
}

/// Resolve an endpoint once and keep the addresses that may be dialled,
/// each classed by the caller's address policy (Phase 1b §1.2). A check's
/// egress fence (debug builds) applies here too.
async fn resolve(
    policy: &AddrPolicy,
    endpoint: &RelayEndpoint,
    own: bool,
) -> Result<Vec<RelayAddr>, RelayError> {
    let fenced = |e: NetError| RelayError::Io(std::io::Error::other(e.to_string()));
    let name = match &endpoint.host {
        mousse_net_core::relay_endpoint::EndpointHost::Dns(name) => Some(name.clone()),
        _ => None,
    };
    let addrs: Vec<SocketAddr> = match &name {
        Some(name) => {
            test_egress::check_name(name, endpoint.port).map_err(fenced)?;
            tokio::net::lookup_host((name.as_str(), endpoint.port))
                .await
                .map_err(RelayError::Io)?
                .collect()
        }
        None => match endpoint.host_text().parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, endpoint.port)],
            Err(_) => Vec::new(),
        },
    };
    let mut out = Vec::new();
    let mut fence = None;
    for addr in addrs {
        let class = policy.class_of(addr);
        let loopback = addr.ip().to_canonical().is_loopback();
        if !relay_class_ok(class, own, loopback) {
            continue;
        }
        if let Err(e) = test_egress::check_ip(addr.ip(), addr.port()) {
            fence = Some(fenced(e));
            continue;
        }
        out.push(RelayAddr {
            addr,
            name: name.clone(),
        });
    }
    match (out.is_empty(), fence) {
        (true, Some(e)) => Err(e),
        _ => Ok(out),
    }
}

// ---------------------------------------------------------------------------
// Approvals

/// Where an approval came from, beside Phase 1b's `ticket` and `owner`: a
/// relay route in a host's manifest the owner approved (Phase 3 §B.11).
pub const APPROVAL_SOURCE_MANIFEST: &str = "manifest";

/// Every approval in `approvals.json` (Phase 1b §1.3), the relay ones
/// included.
fn approvals(shared: &Shared) -> Vec<Approval> {
    ApprovalStore::in_dir(&shared.info.state_dir)
        .load()
        .unwrap_or_default()
}

/// Whether `destination` is approved for the host `pin`: an entry for that
/// host, or the owner's own relay (approved by pasting its link).
fn approved(shared: &Shared, pin: &IdentityPublicKey, destination: &str) -> bool {
    let list = approvals(shared);
    let pin = hex(pin.as_bytes());
    let me = hex(shared.info.identity.as_bytes());
    let exact = list.iter().any(|a| {
        a.destination == destination
            && (a.identity == pin || (a.identity == me && a.source == "owner"))
    });
    if exact {
        return true;
    }
    // The control build approves every relay destination of a host once
    // one is approved.
    cfg!(mousse_control = "blanket-approval")
        && list
            .iter()
            .any(|a| a.identity == pin && a.destination.starts_with("relay://"))
}

/// Approve `destination` for `identity` (hex), unless it is already. Like
/// every approval change, under the peers lock.
fn add_approval(
    shared: &Shared,
    identity: &str,
    destination: &str,
    source: &str,
) -> Result<(), String> {
    let peers = PeerStore::in_dir(&shared.info.state_dir);
    let held = peers.lock().map_err(|e| e.to_string())?;
    ApprovalStore::in_dir(&shared.info.state_dir)
        .add(
            &held,
            &[Approval {
                identity: identity.into(),
                destination: destination.into(),
                source: source.into(),
                at: now(),
            }],
        )
        .map_err(|e| e.to_string())
}

/// Drop the approval of `destination` for `identity`; whether there was one.
fn remove_approval(shared: &Shared, identity: &str, destination: &str) -> Result<bool, String> {
    let peers = PeerStore::in_dir(&shared.info.state_dir);
    let held = peers.lock().map_err(|e| e.to_string())?;
    ApprovalStore::in_dir(&shared.info.state_dir)
        .update(&held, |list| {
            list.retain(|a| !(a.identity == identity && a.destination == destination))
        })
        .map_err(|e| e.to_string())
}

/// `peer.forget` and a removal delete that peer's entries (Phase 1b §1.3);
/// a forget also drops what this device keeps about the host's relays.
pub fn forget_peer(shared: &Shared, pin: &IdentityPublicKey) {
    let key = hex(pin.as_bytes());
    if let Ok(held) = PeerStore::in_dir(&shared.info.state_dir).lock() {
        let _ = ApprovalStore::in_dir(&shared.info.state_dir).remove_identity(&held, &key);
    }
    let _io = guard(&shared.relay.io);
    if let Ok(mut file) = shared.relay.files.peers() {
        file.peers.retain(|p| p.identity != key);
        let _ = shared.relay.files.save_peers(file);
    }
}

// ---------------------------------------------------------------------------
// Own relays: registration

fn status_json(shared: &Shared, relay: &OwnRelay) -> Value {
    let st = guard(&shared.relay.status)
        .get(&relay.relay)
        .cloned()
        .unwrap_or(Status {
            state: "connecting",
            ..Status::default()
        });
    let destination = RelayEndpoint::parse(&relay.endpoint).map(|e| e.destination());
    let listed = shared.relay.allow.borrow().callers.len();
    json!({
        "id": relay.relay,
        "endpoint": relay.endpoint,
        "destination": destination,
        "state": st.state,
        "reason": st.reason,
        "retry_ms": st.retry_ms,
        "callers": listed,
        "callers_max": ALLOW_CALLERS_MAX,
        "added_at": relay.added_at,
        "rotated_at": relay.rotated_at,
        "rotating_until": relay.old.iter().map(|o| o.until).max(),
        "new_key_pending": relay.pending.as_ref().is_some_and(|p| !p.cancelled),
        "cancelling": relay.pending.as_ref().is_some_and(|p| p.cancelled),
        "chain_full": relay.chain_full,
        "chain_full_until": relay.chain_until.filter(|_| relay.chain_full),
    })
}

fn set_status(shared: &Shared, relay: &str, status: Status) {
    guard(&shared.relay.status).insert(relay.to_owned(), status);
    let Ok(file) = shared.relay.files.relays() else {
        return;
    };
    if let Some(r) = file.relays.iter().find(|r| r.relay == relay) {
        shared.event(json!({"ev": "relay.state", "relay": status_json(shared, r)}));
    }
}

/// Start every own relay's registrations, then keep the allow-set and the
/// manifest current. Runs for the life of the channel.
pub async fn run(shared: Arc<Shared>) {
    if shared.relay.seed().is_err() {
        return;
    }
    let relays = shared.relay.files.relays().unwrap_or_default();
    refresh_allow(&shared);
    for relay in relays.relays {
        let t = now();
        start_registration(&shared, &relay, relay.salt.clone(), None);
        for old in relay.old.iter().filter(|o| o.until > t) {
            start_registration(&shared, &relay, old.salt.clone(), None);
        }
        // A rotation the relay had not taken before a restart goes on.
        if relay.pending.is_some() {
            tokio::spawn(finish_rotation(shared.clone(), relay.relay.clone()));
        }
    }
    rebuild_manifest(&shared);
    let mut removals = shared.removal.removed();
    let mut tick = tokio::time::interval(crate::limits::ms(limits().via_relay_check_ms()));
    loop {
        tokio::select! {
            changed = removals.changed() => {
                if changed.is_err() {
                    return;
                }
                on_removal(&shared).await;
            }
            _ = tick.tick() => {
                refresh_allow(&shared);
                end_overlaps(&shared);
                renew_manifest(&shared);
            }
        }
    }
}

/// After a journaled removal: the allow-set without the removed grant goes
/// to every relay, which closes exactly that caller's circuits.
async fn on_removal(shared: &Arc<Shared>) {
    if cfg!(mousse_control = "close-all-on-removal") {
        // The control build drops every caller, then lists the rest again:
        // everyone's circuits close.
        shared.relay.allow.send_replace(AllowSet::default());
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    prune_keys(shared);
    refresh_allow(shared);
    // The removed pairing's slot and deposit token go now (Phase 4 E-L3).
    shared.engine.mail_kick();
}

fn start_registration(
    shared: &Arc<Shared>,
    relay: &OwnRelay,
    salt: String,
    first: Option<TargetLink>,
) {
    let Ok(key) = shared.relay.key(REGISTRATION_KEY_INFO, &salt) else {
        return;
    };
    let (commands, commands_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(registration(
        shared.clone(),
        relay.clone(),
        salt.clone(),
        key,
        first,
        commands_rx,
    ));
    guard(&shared.relay.runs)
        .entry(relay.relay.clone())
        .or_default()
        .push(Run {
            salt,
            commands,
            task: task.abort_handle(),
        });
}

fn stop_registrations(shared: &Shared, relay: &str, salt: Option<&str>) {
    let mut runs = guard(&shared.relay.runs);
    if let Some(list) = runs.get_mut(relay) {
        list.retain(|r| {
            let stop = salt.is_none_or(|s| s == r.salt);
            if stop {
                r.task.abort();
            }
            !stop
        });
        if list.is_empty() {
            runs.remove(relay);
        }
    }
}

/// One registration (one key on one own relay), kept up until aborted.
async fn registration(
    shared: Arc<Shared>,
    relay: OwnRelay,
    salt: String,
    key: Arc<RelayClientKey>,
    mut first: Option<TargetLink>,
    mut commands: mpsc::UnboundedReceiver<TargetCommand>,
) {
    let Some(endpoint) = RelayEndpoint::parse(&relay.endpoint) else {
        return;
    };
    let Some(id) = fixed::<32>(&relay.relay).map(RelayId) else {
        return;
    };
    // Only the current key's registration reports the relay's state.
    let current = || {
        shared
            .relay
            .files
            .relays()
            .ok()
            .and_then(|f| f.relays.into_iter().find(|r| r.relay == relay.relay))
            .is_some_and(|r| r.salt == salt)
    };
    let h = limits();
    let first_wait = crate::limits::ms(h.via_relay_retry_first_ms());
    let longest = crate::limits::ms(h.via_relay_retry_max_ms());
    let mut wait = first_wait;
    loop {
        let link = match first.take() {
            Some(link) => Ok(link),
            None => {
                if current() {
                    set_status(
                        &shared,
                        &relay.relay,
                        Status {
                            state: "connecting",
                            ..Status::default()
                        },
                    );
                }
                register(&shared, &endpoint, id, key.clone()).await
            }
        };
        let error = match link {
            Ok(link) => {
                wait = first_wait;
                if current() {
                    set_status(
                        &shared,
                        &relay.relay,
                        Status {
                            state: "registered",
                            ..Status::default()
                        },
                    );
                }
                note_relay_key(&shared, &relay.relay, link.relay_key());
                hold(&shared, &relay.relay, &salt, link, &mut commands).await
            }
            Err(e) => e,
        };
        let refused = matches!(error, RelayError::Refused(_))
            || matches!(error, RelayError::Closed(Some(4000)));
        applog::line(format!(
            "relay {} registration ended: {error}",
            relay.endpoint
        ));
        if current() {
            set_status(
                &shared,
                &relay.relay,
                Status {
                    state: if refused { "refused" } else { "retrying" },
                    reason: Some(error.word().into()),
                    retry_ms: Some(wait.as_millis() as u64),
                },
            );
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(longest);
    }
}

async fn register(
    shared: &Shared,
    endpoint: &RelayEndpoint,
    id: RelayId,
    key: Arc<RelayClientKey>,
) -> Result<TargetLink, RelayError> {
    // The owner pasted this endpoint: any class it resolves to is theirs.
    let addrs = resolve(shared.caller.addr_policy(), endpoint, true).await?;
    let mut last = RelayError::Unreachable;
    for addr in addrs {
        match TargetLink::register(&addr, id, key.clone(), Proof::Register, dial_within()).await {
            Ok(link) => return Ok(link),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Keep one live registration until it ends.
async fn hold(
    shared: &Arc<Shared>,
    relay: &str,
    salt: &str,
    link: TargetLink,
    commands: &mut mpsc::UnboundedReceiver<TargetCommand>,
) -> RelayError {
    let h = limits();
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
    loop {
        tokio::select! {
            end = &mut run => return end,
            Some(cmd) = commands.recv() => {
                let _ = cmd_tx.send(cmd);
            }
            Some(event) = events.recv() => match event {
                TargetEvent::Incoming { circuit, class, caller, pipe } => {
                    tokio::spawn(accept_incoming(
                        shared.clone(),
                        relay.to_owned(),
                        salt.to_owned(),
                        circuit,
                        caller.is_none(),
                        class,
                        pipe,
                    ));
                }
                TargetEvent::AcceptFailed { error, .. } => {
                    applog::line(format!("relay accept leg failed: {error}"));
                }
                TargetEvent::AllowSetOk { .. } => {}
                TargetEvent::ChainFull => chain_full(shared, relay),
                // Own relays are self-hosted: no leases.
                TargetEvent::LeaseStatus(_) => {}
            },
        }
    }
}

/// The relay refused a `SUCCESSOR` as `chain_full`. That is final for
/// the rotation: the new key is dropped (the relay took no `SUCCESSOR`,
/// so it never knew it), the current key stays, and the owner sees why.
/// The registration itself goes on.
fn chain_full(shared: &Arc<Shared>, relay: &str) {
    if cfg!(mousse_control = "chain-full-ignored") {
        return;
    }
    let updated = {
        let _io = guard(&shared.relay.io);
        let Ok(mut file) = shared.relay.files.relays() else {
            return;
        };
        let Some(r) = file.relays.iter_mut().find(|r| r.relay == relay) else {
            return;
        };
        r.pending = None;
        r.chain_full = true;
        let r = r.clone();
        if shared.relay.files.save_relays(file).is_err() {
            return;
        }
        r
    };
    applog::line(format!(
        "relay {} holds as many keys as it allows; the new key was dropped",
        updated.endpoint
    ));
    shared.event(json!({"ev": "relay.state", "relay": status_json(shared, &updated)}));
}

fn note_relay_key(shared: &Arc<Shared>, relay: &str, key: Option<PublicKey>) {
    let Some(key) = key else {
        return;
    };
    let changed = {
        let _io = guard(&shared.relay.io);
        let Ok(mut file) = shared.relay.files.relays() else {
            return;
        };
        let Some(r) = file.relays.iter_mut().find(|r| r.relay == relay) else {
            return;
        };
        let text = hex(key.as_bytes());
        if r.relay_key.as_deref() == Some(text.as_str()) {
            false
        } else {
            r.relay_key = Some(text);
            let _ = shared.relay.files.save_relays(file);
            true
        }
    };
    if changed {
        rebuild_manifest(shared);
    }
}

/// A spliced circuit: the host side of a peer session runs on it.
async fn accept_incoming(
    shared: Arc<Shared>,
    relay: String,
    salt: String,
    circuit: [u8; 16],
    join: bool,
    class: Class,
    pipe: Box<WsPipe>,
) {
    let conn = match shared.host.accept(pipe).await {
        Ok(conn) => conn,
        Err(e) => {
            applog::line(format!("refused a relay circuit: {e}"));
            return;
        }
    };
    if join {
        guard(&shared.relay.join_circuits).insert(conn.id(), (relay.clone(), salt, circuit));
        let status = conn.settled(true).await;
        if matches!(status, ConnStatus::Live) && !recovery_allows(&shared, &conn) {
            // A join circuit admits a pairing, or the grant a consumed
            // invitation made coming back to finish (§B.7); nobody else.
            applog::line(format!(
                "closed a join circuit from {}: not the grant of a recovery entry",
                short_id(conn.peer())
            ));
            conn.close(ErrorCode::InvitationInvalid);
            guard(&shared.relay.join_circuits).remove(&conn.id());
            return;
        }
    }
    let destination = destination_of(&shared, &relay);
    let id = conn.id();
    let app = super::App {
        shared: shared.clone(),
    };
    let class = if class == Class::Bulk {
        "relay_bulk"
    } else {
        "relay"
    };
    let no = app
        .inbound_on(
            conn,
            json!({"kind": "relay", "class": class, "destination": destination}),
        )
        .await;
    guard(&shared.relay.join_circuits).remove(&id);
    if let Some(no) = no {
        guard(&shared.relay.sessions)
            .entry(relay.clone())
            .or_default()
            .insert(no);
        // Removed meanwhile: the session goes with the relay.
        if destination_of(&shared, &relay).is_none() {
            close_sessions(&shared, &relay);
        }
    }
}

/// End every inbound session through the own relay `relay`.
fn close_sessions(shared: &Shared, relay: &str) {
    let numbers = guard(&shared.relay.sessions)
        .remove(relay)
        .unwrap_or_default();
    let conns: Vec<Arc<Connection>> = {
        let core = super::lock(&shared.core);
        numbers
            .iter()
            .filter_map(|no| core.conns.get(no).map(|e| e.conn.clone()))
            .collect()
    };
    for conn in conns {
        conn.close(ErrorCode::Cancelled);
    }
}

/// Close the outbound paths to `pin` through `destination`; their bulk
/// companions go with them.
fn close_relay_paths(shared: &Shared, pin: &IdentityPublicKey, destination: &str) {
    let conns: Vec<Arc<Connection>> = super::lock(&shared.core)
        .conns
        .values()
        .filter(|e| {
            !e.inbound
                && e.identity == *pin
                && e.via
                    .as_ref()
                    .is_some_and(|r| r.endpoint.destination() == destination)
        })
        .map(|e| e.conn.clone())
        .collect();
    for conn in conns {
        conn.close(ErrorCode::Cancelled);
    }
}

fn destination_of(shared: &Shared, relay: &str) -> Option<String> {
    let own = shared
        .relay
        .files
        .relays()
        .ok()
        .and_then(|f| f.relays.into_iter().find(|r| r.relay == relay))
        .and_then(|r| RelayEndpoint::parse(&r.endpoint))
        .map(|e| e.destination());
    own.or_else(|| hosted::destination_of(shared, relay))
}

/// Whether a live connection on a join circuit belongs there: its grant's
/// enrollment receipt is a relay invitation, either the one this circuit
/// just enrolled or a consumed one still listed for recovery.
fn recovery_allows(shared: &Shared, conn: &Connection) -> bool {
    if cfg!(mousse_control = "recovery-makes-grant") {
        // The control build lets any identity ride a recovery circuit.
        return true;
    }
    let Some(grant) = shared.host.grant_of(conn.id()) else {
        return false;
    };
    let Some(receipt) = grant.enrolled_by else {
        return false;
    };
    if guard(&shared.relay.invites)
        .iter()
        .any(|i| i.invitation == receipt)
    {
        return true;
    }
    let t = now();
    let receipt = hex(&receipt.0);
    shared.relay.files.grants().is_ok_and(|f| {
        f.recovery
            .iter()
            .any(|r| r.grant == grant.id.0 && r.invitation == receipt && r.expires_at > t)
    })
}

// ---------------------------------------------------------------------------
// Allow-set

/// Caller keys of live grants, oldest grant first, capped at 256; then the
/// fingerprints past the cap (for the "limit 256" note).
fn listed_callers(shared: &Shared) -> (Vec<(u64, [u8; 32])>, Vec<u64>) {
    let mut grants = shared.host.grants();
    grants.sort_by_key(|g| g.id.0);
    let keys = shared.relay.files.grants().unwrap_or_default().keys;
    let mut listed = Vec::new();
    let mut over = Vec::new();
    for g in grants {
        let identity = hex(g.identity.as_bytes());
        let Some(k) = keys
            .iter()
            .find(|k| k.grant == g.id.0 && k.identity == identity)
        else {
            continue;
        };
        let Some(fp) = fixed::<32>(&k.caller) else {
            continue;
        };
        if listed.len() < ALLOW_CALLERS_MAX {
            listed.push((g.id.0, fp));
        } else {
            over.push(g.id.0);
        }
    }
    (listed, over)
}

/// The grant's relay entry, as `grants.list` shows it: `listed`, `limit`
/// (past the 256th) or `no_key` (no caller key enrolled yet).
pub fn grant_status(shared: &Shared, grant: u64) -> &'static str {
    let (listed, over) = listed_callers(shared);
    if listed.iter().any(|(g, _)| *g == grant) {
        "listed"
    } else if over.contains(&grant) {
        "limit"
    } else {
        "no_key"
    }
}

fn compute_allow(shared: &Shared) -> AllowSet {
    let (listed, _) = listed_callers(shared);
    let t = now();
    let mut invitations: Vec<InvitationEntry> = guard(&shared.relay.invites)
        .iter()
        .filter(|i| i.expires_at > t)
        .map(|i| InvitationEntry {
            tag_hash: i.tag_hash,
            expires_at: i.expires_at,
        })
        .collect();
    if !cfg!(mousse_control = "no-pairing-recovery") {
        let grants: HashSet<u64> = shared.host.grants().iter().map(|g| g.id.0).collect();
        let keyed: HashSet<u64> = listed.iter().map(|(g, _)| *g).collect();
        for r in shared.relay.files.grants().unwrap_or_default().recovery {
            if r.expires_at > t && grants.contains(&r.grant) && !keyed.contains(&r.grant) {
                if let Some(tag_hash) = fixed::<32>(&r.tag_hash) {
                    invitations.push(InvitationEntry {
                        tag_hash,
                        expires_at: r.expires_at,
                    });
                }
            }
        }
    }
    invitations.truncate(ALLOW_INVITATIONS_MAX);
    AllowSet {
        callers: listed.into_iter().map(|(_, fp)| fp).collect(),
        invitations,
    }
}

/// Push the allow-set to every own relay if it changed.
pub fn refresh_allow(shared: &Shared) {
    let set = compute_allow(shared);
    shared.relay.allow.send_if_modified(|current| {
        if *current == set {
            false
        } else {
            *current = set;
            true
        }
    });
}

/// Drop caller keys and recovery entries of grants that are gone.
fn prune_keys(shared: &Shared) {
    let live: HashSet<(u64, String)> = shared
        .host
        .grants()
        .iter()
        .map(|g| (g.id.0, hex(g.identity.as_bytes())))
        .collect();
    let ids: HashSet<u64> = live.iter().map(|(g, _)| *g).collect();
    let _io = guard(&shared.relay.io);
    let Ok(mut file) = shared.relay.files.grants() else {
        return;
    };
    let before = (file.keys.len(), file.recovery.len());
    file.keys
        .retain(|k| live.contains(&(k.grant, k.identity.clone())));
    let t = now();
    file.recovery
        .retain(|r| ids.contains(&r.grant) && r.expires_at > t);
    if before != (file.keys.len(), file.recovery.len()) {
        let _ = shared.relay.files.save_grants(file);
    }
}

// ---------------------------------------------------------------------------
// Invitations

/// The `relay://` hints of this computer's registered relays, for tickets.
pub fn ticket_hints(shared: &Shared) -> Vec<String> {
    let Ok(file) = shared.relay.files.relays() else {
        return Vec::new();
    };
    let st = guard(&shared.relay.status);
    file.relays
        .iter()
        .filter(|r| st.get(&r.relay).is_some_and(|s| s.state == "registered"))
        .filter_map(|r| {
            let endpoint = RelayEndpoint::parse(&r.endpoint)?;
            let relay = RelayId(fixed::<32>(&r.relay)?);
            let key = shared.relay.key(REGISTRATION_KEY_INFO, &r.salt).ok()?;
            Some(
                RelayRoute {
                    endpoint,
                    relay,
                    handle: key.handle(&relay),
                }
                .to_hint(),
            )
        })
        .collect()
}

/// A new invitation whose ticket carries a relay hint: list its tag.
pub fn on_invite(shared: &Shared, ticket: &Ticket) {
    if !ticket
        .routes
        .iter()
        .any(|r| RelayRoute::parse_hint(r).is_some())
    {
        return;
    }
    let tag = invitation_tag(&ticket.invitation, &ticket.secret);
    guard(&shared.relay.invites).push(OpenInvite {
        invitation: ticket.invitation,
        tag_hash: tag_hash(&tag),
        expires_at: ticket.expires_at.secs(),
    });
    refresh_allow(shared);
}

/// Pairing ended an invitation: an enrolled one keeps its tag listed as a
/// recovery entry until the new grant's caller key arrives (§B.7).
pub fn on_enrolled(shared: &Shared, invitation: &InvitationId, grant: u64) {
    let open = guard(&shared.relay.invites)
        .iter()
        .find(|i| i.invitation == *invitation)
        .cloned();
    if let Some(open) = &open {
        if !cfg!(mousse_control = "no-pairing-recovery") {
            let _io = guard(&shared.relay.io);
            if let Ok(mut file) = shared.relay.files.grants() {
                file.recovery.retain(|r| r.grant != grant);
                file.recovery.push(Recovery {
                    invitation: hex(&invitation.0),
                    tag_hash: hex(&open.tag_hash),
                    grant,
                    expires_at: now() + limits().via_relay_rejoin_secs(),
                });
                let _ = shared.relay.files.save_grants(file);
            }
        }
    }
    // Only now: a circuit checked meanwhile finds the invitation in one
    // list or the other.
    guard(&shared.relay.invites).retain(|i| i.invitation != *invitation);
    refresh_allow(shared);
}

/// An invitation ended without pairing: its tag goes.
pub fn on_invitation_ended(shared: &Shared, invitation: &InvitationId) {
    guard(&shared.relay.invites).retain(|i| i.invitation != *invitation);
    refresh_allow(shared);
}

// ---------------------------------------------------------------------------
// Sealed secrets in `relay-peers.json`

/// HKDF info of the keys that seal what a caller keeps of a host's.
const SEAL_INFO: &str = "mousse-relay-seal-v1";
/// What is sealed: the host's pair secret.
const SEALED_PAIR_SECRET: &str = "pair-secret";
/// What is sealed: the ticket's invitation tag.
const SEALED_JOIN_TAG: &str = "join-tag";

/// The key sealing `what` of the host `pin`: from the relay seed, which is
/// kept where the identity key is, so no relay secret is in a plain file.
fn seal_key(
    shared: &Shared,
    pin: &IdentityPublicKey,
    what: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut salt = pin.as_bytes().to_vec();
    salt.extend_from_slice(what.as_bytes());
    Ok(derive_secret(shared.relay.seed()?, SEAL_INFO, &salt))
}

/// `secret` sealed (XChaCha20-Poly1305, a fresh nonce), as hex.
fn seal_secret(
    shared: &Shared,
    pin: &IdentityPublicKey,
    what: &str,
    secret: &[u8; 32],
) -> Result<String, String> {
    let key = seal_key(shared, pin, what)?;
    let nonce = random_bytes::<{ pairmail::NONCE_LEN }>();
    Ok(hex(&pairmail::seal(&key, nonce, secret)))
}

/// A secret sealed by [`seal_secret`], if it opens.
fn open_secret(
    shared: &Shared,
    pin: &IdentityPublicKey,
    what: &str,
    sealed: Option<&str>,
) -> Option<Zeroizing<[u8; 32]>> {
    let key = seal_key(shared, pin, what).ok()?;
    let bytes = unhex(sealed?).ok()?;
    let plain = pairmail::open(&key, &bytes).ok()?;
    let secret: [u8; 32] = plain.as_slice().try_into().ok()?;
    Some(Zeroizing::new(secret))
}

// ---------------------------------------------------------------------------
// Pairings for the Plus mailbox (Phase 4)

/// What the relay client knows that Phase 4's mailbox needs: each grant's
/// pair secret, the secret each host sent, and this host's manifest.
pub struct Pairs(pub std::sync::Weak<Shared>);

impl crate::engine::mailbox::PairSource for Pairs {
    fn host_pairings(&self) -> Vec<(GrantId, IdentityPublicKey, PairSecret)> {
        let Some(shared) = self.0.upgrade() else {
            return Vec::new();
        };
        let Ok(seed) = shared.relay.seed() else {
            return Vec::new();
        };
        let keys = shared.relay.files.grants().unwrap_or_default().keys;
        shared
            .host
            .grants()
            .into_iter()
            .filter_map(|g| {
                let identity = hex(g.identity.as_bytes());
                let k = keys
                    .iter()
                    .find(|k| k.grant == g.id.0 && k.identity == identity)?;
                let salt = unhex(&k.salt).ok()?;
                let secret = derive_secret(seed, PAIR_SECRET_INFO, &salt);
                Some((g.id, g.identity, PairSecret::from_bytes(*secret)))
            })
            .collect()
    }

    fn caller_secret(&self, pin: &IdentityPublicKey) -> Option<PairSecret> {
        caller_pair_secret(&*self.0.upgrade()?, pin)
    }

    fn keep_manifest(&self, pin: &IdentityPublicKey, envelope: &[u8]) {
        if let Some(shared) = self.0.upgrade() {
            take_manifest(&shared, pin, envelope);
        }
    }

    fn manifest(&self) -> Option<Vec<u8>> {
        let shared = self.0.upgrade()?;
        let manifest = guard(&shared.relay.manifest);
        manifest.as_ref().map(|(_, envelope)| envelope.encode())
    }
}

/// Caller: the pair secret the host `pin` sent on `mousse-keys`.
fn caller_pair_secret(shared: &Shared, pin: &IdentityPublicKey) -> Option<PairSecret> {
    let key = hex(pin.as_bytes());
    let file = shared.relay.files.peers().ok()?;
    let entry = file.peers.iter().find(|p| p.identity == key)?;
    let secret = open_secret(
        shared,
        pin,
        SEALED_PAIR_SECRET,
        entry.pair_secret.as_deref(),
    )?;
    Some(PairSecret::from_bytes(*secret))
}

// ---------------------------------------------------------------------------
// `mousse-keys` and `mousse-manifest`

/// The one message (wire.md 9.5: length-prefixed CBOR) the peer sends on
/// an engine stream, if it comes in time and is at most `max` bytes.
async fn read_one(stream: mousse_net_io::StreamReader, max: usize) -> Option<Vec<u8>> {
    let mut reader = engine_stream::MessageReader::new(stream);
    match reader.next_within(dial_within()).await {
        Ok(Some(message)) if message.len() <= max => Some(message),
        _ => None,
    }
}

/// Host: a caller enrolls its caller key for this pairing.
pub async fn serve_keys(shared: Arc<Shared>, conn: Arc<Connection>, stream: MuxStream) {
    let (reader, writer) = stream.split();
    let peer = short_id(conn.peer());
    let refuse = |code: ErrorCode, why: &str| {
        applog::line(format!("refused a caller key from {peer}: {why}"));
        writer.reset(code);
    };
    let Some(request) = read_one(reader, 256).await else {
        refuse(ErrorCode::ProtocolError, "no complete request");
        return;
    };
    let Ok(caller_key) = decode_keys_request(&request) else {
        refuse(ErrorCode::ProtocolError, "malformed request");
        return;
    };
    let Some(grant) = shared.host.grant_of(conn.id()) else {
        refuse(ErrorCode::RefusedStream, "no live grant on the connection");
        return;
    };
    let Ok(seed) = shared.relay.seed() else {
        refuse(ErrorCode::RefusedStream, "no relay seed");
        return;
    };
    let identity = hex(grant.identity.as_bytes());
    let fp = caller_key.fingerprint();
    let salt = {
        let _io = guard(&shared.relay.io);
        let mut file = match shared.relay.files.grants() {
            Ok(file) => file,
            Err(e) => {
                refuse(ErrorCode::InternalError, &e);
                return;
            }
        };
        // A new pairing of the same device replaces both (§B.12); the same
        // grant keeps its pair secret.
        let salt = file
            .keys
            .iter()
            .find(|k| k.grant == grant.id.0 && k.identity == identity)
            .map(|k| k.salt.clone())
            .unwrap_or_else(|| hex(&random_bytes::<16>()));
        file.keys
            .retain(|k| k.identity != identity && k.grant != grant.id.0);
        file.keys.push(GrantKey {
            grant: grant.id.0,
            identity,
            caller: hex(&fp),
            salt: salt.clone(),
            at: now(),
        });
        file.recovery.retain(|r| r.grant != grant.id.0);
        if let Err(e) = shared.relay.files.save_grants(file) {
            refuse(ErrorCode::InternalError, &e);
            return;
        }
        salt
    };
    let Ok(salt_bytes) = unhex(&salt) else {
        refuse(ErrorCode::InternalError, "a stored salt is not hex");
        return;
    };
    let secret = derive_secret(seed, PAIR_SECRET_INFO, &salt_bytes);
    if engine_stream::write(&writer, &encode_keys_answer(&secret))
        .await
        .is_ok()
    {
        writer.finish();
    }
    refresh_allow(&shared);
    // The new pairing gets its directory slot and deposit token now.
    shared.engine.mail_kick();
    // A join circuit becomes this caller's circuit, after the allow-set
    // that lists it (§B.7).
    let circuit = guard(&shared.relay.join_circuits).get(&conn.id()).cloned();
    if let Some((relay, salt, circuit)) = circuit {
        if let Some(run) = guard(&shared.relay.runs)
            .get(&relay)
            .and_then(|runs| runs.iter().find(|r| r.salt == salt))
        {
            let _ = run.commands.send(TargetCommand::Promote {
                circuit,
                caller: fp,
            });
        }
    }
    applog::line(format!("caller key enrolled for grant {}", grant.id.0));
}

fn peer_entry(shared: &Shared, pin: &IdentityPublicKey) -> Result<PeerRelay, String> {
    let key = hex(pin.as_bytes());
    let _io = guard(&shared.relay.io);
    let mut file = shared.relay.files.peers()?;
    if let Some(p) = file.peers.iter().find(|p| p.identity == key) {
        return Ok(p.clone());
    }
    let entry = PeerRelay {
        identity: key,
        salt: hex(&random_bytes::<16>()),
        ..PeerRelay::default()
    };
    file.peers.push(entry.clone());
    shared.relay.files.save_peers(file)?;
    Ok(entry)
}

fn update_peer(
    shared: &Shared,
    pin: &IdentityPublicKey,
    change: impl FnOnce(&mut PeerRelay),
) -> Result<(), String> {
    peer_entry(shared, pin)?;
    let key = hex(pin.as_bytes());
    let _io = guard(&shared.relay.io);
    let mut file = shared.relay.files.peers()?;
    if let Some(p) = file.peers.iter_mut().find(|p| p.identity == key) {
        change(p);
    }
    shared.relay.files.save_peers(file)
}

/// This device's caller key for the host `pin` (one per pairing).
fn caller_key(shared: &Shared, pin: &IdentityPublicKey) -> Result<Arc<RelayClientKey>, String> {
    if cfg!(mousse_control = "shared-caller-key") {
        // The control build uses one caller key for every host.
        return shared.relay.key(CALLER_KEY_INFO, "");
    }
    let entry = peer_entry(shared, pin)?;
    shared.relay.key(CALLER_KEY_INFO, &entry.salt)
}

/// The fingerprint of this device's caller key for `pin` (tests and
/// `peers.list`).
pub fn caller_fingerprint(shared: &Shared, pin: &IdentityPublicKey) -> Option<String> {
    caller_key(shared, pin)
        .ok()
        .map(|k| hex(&k.public_key().fingerprint()))
}

/// Caller: on every new outbound connection, enroll the caller key, beside
/// the app's streams (an engine stream takes an engine place, not one of
/// the app's). The host keeps the same pair secret for the same grant, so
/// this only confirms a key it has; it fills in an answer that is missing,
/// heals a host that lost its copy, and is a caller stream, after which
/// the host may open `mousse-manifest` (the engine lets a host open
/// streams only once its caller has opened one).
pub async fn ensure_keys(shared: &Arc<Shared>, conn: &Connection) {
    if shared.relay.seed().is_err() {
        return;
    }
    // Debug builds: a test holds the caller key back, as if the circuit
    // dropped before `mousse-keys` (relay-only pairing recovery, B.7).
    #[cfg(debug_assertions)]
    if std::env::var_os("MOUSSE_HELPER_TEST_NO_KEYS").is_some() {
        return;
    }
    let pin = *conn.peer();
    let failed = |why: String| {
        applog::line(format!(
            "sending the caller key to {} failed: {why}",
            short_id(&pin)
        ));
    };
    let had = match peer_entry(shared, &pin) {
        Ok(p) => open_secret(shared, &pin, SEALED_PAIR_SECRET, p.pair_secret.as_deref()),
        Err(e) => return failed(e),
    };
    let key = match caller_key(shared, &pin) {
        Ok(k) => k,
        Err(e) => return failed(e),
    };
    // Bounded, like a dial.
    let exchange = async {
        // A host from before minor 1 has no `mousse-keys`.
        if conn.hello_minor().await.unwrap_or(0) < KEYS_MINOR {
            return Err("the host has no relay keys".to_owned());
        }
        let stream = conn
            .open_stream(PriorityClass::Interactive, KEYS_LABEL)
            .await
            .map_err(|e| e.to_string())?;
        let (reader, writer) = stream.split();
        engine_stream::write(&writer, &encode_keys_request(&key.public_key()))
            .await
            .map_err(|e| e.to_string())?;
        writer.finish();
        read_one(reader, 256)
            .await
            .ok_or_else(|| "no answer".to_owned())
    };
    let answer = match tokio::time::timeout(dial_within(), exchange).await {
        Ok(Ok(answer)) => answer,
        Ok(Err(e)) => return failed(e),
        Err(_) => return failed("no answer in time".into()),
    };
    let Ok(secret) = decode_keys_answer(&answer) else {
        return failed("malformed answer".into());
    };
    let secret = Zeroizing::new(secret);
    if had.is_some_and(|h| *h == *secret) {
        return;
    }
    let sealed = match seal_secret(shared, &pin, SEALED_PAIR_SECRET, &secret) {
        Ok(sealed) => sealed,
        Err(e) => return failed(e),
    };
    let stored = update_peer(shared, &pin, |p| {
        p.pair_secret = Some(sealed);
        p.join_tag = None;
    });
    if let Err(e) = &stored {
        failed(e.clone());
    }
    if stored.is_ok() {
        applog::line(format!("caller key enrolled with {}", short_id(&pin)));
        shared.event(json!({"ev": "peer.keys", "identity": hex(pin.as_bytes())}));
    }
}

/// Host: send the current manifest on an inbound connection (once the
/// caller has opened a stream on it).
pub fn send_manifest(shared: &Arc<Shared>, no: u64, conn: Arc<Connection>) {
    if guard(&shared.relay.manifest).is_none() {
        return;
    }
    let shared = shared.clone();
    tokio::spawn(async move {
        // A caller from before minor 1 resets streams a host opens.
        if conn.hello_minor().await.unwrap_or(0) < KEYS_MINOR {
            return;
        }
        let Some((_, envelope)) = guard(&shared.relay.manifest).clone() else {
            return;
        };
        if !guard(&shared.relay.manifest_sent).insert(no) {
            return;
        }
        if let Ok(stream) = conn
            .open_stream(PriorityClass::Interactive, MANIFEST_LABEL)
            .await
        {
            let (_reader, writer) = stream.split();
            if engine_stream::write(&writer, &envelope.encode())
                .await
                .is_ok()
            {
                writer.finish();
            }
        }
    });
}

/// A connection went down: forget what was sent on it.
pub fn conn_gone(shared: &Shared, no: u64) {
    guard(&shared.relay.manifest_sent).remove(&no);
    for list in guard(&shared.relay.sessions).values_mut() {
        list.remove(&no);
    }
}

fn broadcast_manifest(shared: &Arc<Shared>) {
    guard(&shared.relay.manifest_sent).clear();
    let inbound: Vec<(u64, Arc<Connection>)> = super::lock(&shared.core)
        .conns
        .iter()
        .filter(|(_, e)| e.inbound && e.caller_opened)
        .map(|(no, e)| (*no, e.conn.clone()))
        .collect();
    for (no, conn) in inbound {
        send_manifest(shared, no, conn);
    }
}

/// The routes this host's manifest lists: each own relay with a known key,
/// the current registration and the old ones still in their overlap.
fn manifest_routes(shared: &Shared) -> Vec<ManifestRoute> {
    let Ok(file) = shared.relay.files.relays() else {
        return Vec::new();
    };
    let t = now();
    let mut routes = Vec::new();
    for r in &file.relays {
        let (Some(endpoint), Some(key)) = (
            RelayEndpoint::parse(&r.endpoint),
            r.relay_key
                .as_deref()
                .and_then(|k| identity_from_hex(k).ok()),
        ) else {
            continue;
        };
        let id = RelayId::of(&key);
        let mut salts = vec![r.salt.clone()];
        if !cfg!(mousse_control = "no-overlap") {
            salts.extend(r.old.iter().filter(|o| o.until > t).map(|o| o.salt.clone()));
        }
        for salt in salts {
            let Ok(reg) = shared.relay.key(REGISTRATION_KEY_INFO, &salt) else {
                continue;
            };
            routes.push(ManifestRoute {
                relay_key: key,
                endpoints: vec![endpoint.clone()],
                handle: reg.handle(&id),
                region: String::new(),
            });
        }
    }
    routes.extend(hosted::manifest_routes(shared));
    routes.truncate(MANIFEST_ROUTES_MAX);
    routes
}

/// Make and sign a new manifest if the routes changed, and send it.
pub fn rebuild_manifest(shared: &Arc<Shared>) {
    let routes = manifest_routes(shared);
    let same = guard(&shared.relay.manifest)
        .as_ref()
        .is_some_and(|(m, _)| m.routes == routes);
    if same || (routes.is_empty() && guard(&shared.relay.manifest).is_none()) {
        return;
    }
    issue_manifest(shared, routes);
}

/// Issue the manifest again before it goes stale.
fn renew_manifest(shared: &Arc<Shared>) {
    let due = guard(&shared.relay.manifest)
        .as_ref()
        .is_some_and(|(m, _)| now() + limits().manifest_lifetime_secs() / 2 > m.expires_at);
    if due {
        issue_manifest(shared, manifest_routes(shared));
    }
}

fn issue_manifest(shared: &Arc<Shared>, routes: Vec<ManifestRoute>) {
    let sequence = {
        let _io = guard(&shared.relay.io);
        let Ok(mut file) = shared.relay.files.relays() else {
            return;
        };
        file.manifest_sequence += 1;
        let sequence = file.manifest_sequence;
        if shared.relay.files.save_relays(file).is_err() {
            return;
        }
        sequence
    };
    let t = now();
    let manifest = Manifest {
        host: shared.info.identity,
        sequence,
        issued_at: t,
        expires_at: t + limits().manifest_lifetime_secs(),
        routes,
    };
    let Ok(record) = IdentityRecord::manifest(&manifest) else {
        return;
    };
    let signature = match shared.info.signer.sign(&record) {
        Ok(s) => s,
        Err(e) => {
            applog::line(format!("signing the manifest failed: {e}"));
            return;
        }
    };
    let envelope = Manifest::seal(&record, signature);
    *guard(&shared.relay.manifest) = Some((manifest, envelope));
    broadcast_manifest(shared);
    // Every pairing's directory slot carries the new manifest (§B.12).
    shared.engine.mail_kick();
}

/// Caller: the host sent its manifest. Kept if it is signed by the pin and
/// newer than the one kept.
pub async fn read_manifest(shared: Arc<Shared>, pin: IdentityPublicKey, stream: MuxStream) {
    let (reader, writer) = stream.split();
    let Some(bytes) = read_one(reader, RELAY_MESSAGE_MAX).await else {
        writer.reset(ErrorCode::ProtocolError);
        return;
    };
    writer.finish();
    take_manifest(&shared, &pin, &bytes);
}

/// Caller: keep `bytes`, a manifest from the session or from the host's
/// directory slot, if the pinned host signed it and it is newer than the
/// one kept. Returns whether it was kept.
fn take_manifest(shared: &Shared, pin: &IdentityPublicKey, bytes: &[u8]) -> bool {
    let pin = *pin;
    let manifest = match Envelope::decode(bytes)
        .map_err(|e| e.to_string())
        .and_then(|env| Manifest::open(&env, &pin).map_err(|e| e.to_string()))
    {
        Ok(m) => m,
        Err(e) => {
            applog::line(format!("refused a manifest from {}: {e}", short_id(&pin)));
            return false;
        }
    };
    let mut newer = false;
    let mut before = None;
    let _ = update_peer(shared, &pin, |p| {
        if manifest.sequence > p.sequence {
            before = stored_manifest(p, &pin);
            p.sequence = manifest.sequence;
            p.manifest = Some(hex(bytes));
            newer = true;
        }
    });
    if !newer {
        return false;
    }
    if cfg!(mousse_control = "prompt-on-key-change") {
        // The control build treats a new relay key or handle at an
        // approved destination as a new destination.
        let known: Vec<_> = before
            .iter()
            .flat_map(|m| m.routes.iter().map(|r| r.handle))
            .collect();
        for r in &manifest.routes {
            if !known.contains(&r.handle) {
                for e in &r.endpoints {
                    let _ = remove_approval(shared, &hex(pin.as_bytes()), &e.destination());
                }
            }
        }
    }
    let mut offered = Vec::new();
    for r in &manifest.routes {
        for e in &r.endpoints {
            let destination = e.destination();
            if !approved(shared, &pin, &destination) && !offered.contains(&destination) {
                offered.push(destination);
            }
        }
    }
    shared.event(json!({
        "ev": "peer.manifest",
        "identity": hex(pin.as_bytes()),
        "manifest": manifest_json(&manifest),
    }));
    for destination in offered {
        shared.event(json!({
            "ev": "peer.relay.offered",
            "identity": hex(pin.as_bytes()),
            "destination": destination,
        }));
    }
    true
}

fn manifest_json(m: &Manifest) -> Value {
    json!({
        "sequence": m.sequence,
        "issued_at": m.issued_at,
        "expires_at": m.expires_at,
        "stale": m.is_stale(now()),
    })
}

fn stored_manifest(entry: &PeerRelay, pin: &IdentityPublicKey) -> Option<Manifest> {
    let bytes = unhex(entry.manifest.as_deref()?).ok()?;
    let env = Envelope::decode(&bytes).ok()?;
    Manifest::open(&env, pin).ok()
}

// ---------------------------------------------------------------------------
// Calling through relays

/// A relay route this device may dial for a host.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub route: RelayRoute,
}

/// The relay routes to try for `pin`, approved and in order: the fresh
/// manifest's, the ticket's, then the stale manifest's.
pub fn candidates(shared: &Shared, pin: &IdentityPublicKey) -> Vec<Candidate> {
    let Ok(entry) = peer_entry(shared, pin) else {
        return Vec::new();
    };
    let t = now();
    let mut fresh = Vec::new();
    let mut stale = Vec::new();
    if let Some(m) = stored_manifest(&entry, pin) {
        let is_stale = m.is_stale(t);
        for r in &m.routes {
            for route in r.routes() {
                let ok = cfg!(mousse_control = "manifest-unapproved")
                    || approved(shared, pin, &route.endpoint.destination());
                if !ok {
                    continue;
                }
                if is_stale {
                    if !cfg!(mousse_control = "stale-manifest-dropped") {
                        stale.push(Candidate { route });
                    }
                } else {
                    fresh.push(Candidate { route });
                }
            }
        }
    }
    for hint in &entry.ticket_routes {
        if let Some(route) = RelayRoute::parse_hint(hint) {
            if approved(shared, pin, &route.endpoint.destination())
                && !fresh.iter().any(|c| c.route == route)
            {
                fresh.push(Candidate { route });
            }
        }
    }
    fresh.extend(stale);
    fresh
}

/// Dial one relay route to `pin`: `CALL` with the caller key (or `JOIN`
/// with the ticket's tag until the host answered `mousse-keys`), then the
/// peer TLS pinned to the host.
pub async fn dial_route(
    shared: &Shared,
    pin: &IdentityPublicKey,
    route: &RelayRoute,
    class: Class,
) -> Result<Connection, NetError> {
    // Every dial, a bulk companion's too, needs the approval as it is now.
    let destination = route.endpoint.destination();
    if !cfg!(mousse_control = "manifest-unapproved") && !approved(shared, pin, &destination) {
        return Err(NetError::Forbidden(format!(
            "{destination} is not approved for this host"
        )));
    }
    let entry = peer_entry(shared, pin).map_err(NetError::Store)?;
    let key = caller_key(shared, pin).map_err(NetError::Store)?;
    let join_tag = entry
        .pair_secret
        .is_none()
        .then(|| open_secret(shared, pin, SEALED_JOIN_TAG, entry.join_tag.as_deref()))
        .flatten();
    let addrs = resolve(shared.caller.addr_policy(), &route.endpoint, false).await?;
    if addrs.is_empty() {
        return Err(NetError::Relay(RelayError::Unreachable));
    }
    let mut last = NetError::Relay(RelayError::Unreachable);
    for addr in addrs {
        let pipe = match join_tag {
            Some(ref tag) if class == Class::Interactive => {
                dial_join(&addr, route.relay, route.handle, **tag, dial_within()).await
            }
            _ => dial_call(&addr, route.relay, route.handle, &key, class, dial_within()).await,
        };
        let pipe = match pipe {
            Ok(p) => p,
            Err(e) => {
                last = NetError::Relay(e);
                continue;
            }
        };
        match tokio::time::timeout(dial_within(), shared.caller.dial(pipe, *pin)).await {
            Ok(Ok(conn)) => return Ok(conn),
            Ok(Err(e)) => last = e,
            Err(_) => last = NetError::Timeout("peer TLS through the relay"),
        }
    }
    Err(last)
}

/// After every direct route failed: the relay routes, in order.
pub async fn reach(
    shared: &Shared,
    pin: &IdentityPublicKey,
) -> Result<(Connection, RelayRoute), NetError> {
    let mut last = None;
    for c in candidates(shared, pin) {
        match dial_route(shared, pin, &c.route, Class::Interactive).await {
            Ok(conn) => return Ok((conn, c.route)),
            // The host itself refused: no other route changes that.
            Err(e @ NetError::Closed(_)) => return Err(e),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or(NetError::Relay(RelayError::Unreachable)))
}

/// The connection.up route object of a relay route.
pub fn route_json(route: &RelayRoute, bulk: bool) -> Value {
    json!({
        "kind": "relay",
        "class": if bulk { "relay_bulk" } else { "relay" },
        "destination": route.endpoint.destination(),
        "relay": hex(&route.relay.0),
    })
}

/// The bulk companion of the relay connection `no`: a second call of class
/// bulk with its own peer session (§B.6).
pub async fn bulk_companion(
    shared: &Arc<Shared>,
    no: u64,
    pin: IdentityPublicKey,
    route: RelayRoute,
) -> Result<Arc<Connection>, NetError> {
    let mut bulk = shared.relay.bulk.lock().await;
    if let Some(conn) = bulk.get(&no) {
        if !matches!(conn.status(), ConnStatus::Closed(_)) {
            return Ok(conn.clone());
        }
    }
    let conn = Arc::new(dial_route(shared, &pin, &route, Class::Bulk).await?);
    bulk.insert(no, conn.clone());
    // The host opens nothing on it the caller wants.
    let watch = conn.clone();
    tokio::spawn(async move {
        while let Some(stream) = watch.accept_stream().await {
            stream.writer.reset(ErrorCode::RefusedStream);
        }
    });
    Ok(conn)
}

/// The main connection `no` went down: its companion goes too.
pub async fn drop_companion(shared: &Shared, no: u64) {
    if let Some(conn) = shared.relay.bulk.lock().await.remove(&no) {
        conn.close(ErrorCode::NoError);
    }
}

// ---------------------------------------------------------------------------
// Joining through a relay

/// The ticket's relay routes the owner approved at Connect.
pub fn join_candidates(ticket: &Ticket, approved: &[String]) -> Vec<(RelayRoute, [u8; 32])> {
    let tag = invitation_tag(&ticket.invitation, &ticket.secret);
    ticket
        .routes
        .iter()
        .filter_map(|h| RelayRoute::parse_hint(h))
        .filter(|r| approved.contains(&r.endpoint.destination()))
        .map(|r| (r, tag))
        .collect()
}

/// Dial a join circuit for `route`.
pub async fn dial_join_route(
    policy: &AddrPolicy,
    route: &RelayRoute,
    tag: [u8; 32],
) -> Result<WsPipe, NetError> {
    let addrs = resolve(policy, &route.endpoint, false).await?;
    let mut last = NetError::Relay(RelayError::Unreachable);
    for addr in addrs {
        match dial_join(&addr, route.relay, route.handle, tag, dial_within()).await {
            Ok(pipe) => return Ok(pipe),
            Err(e) => last = NetError::Relay(e),
        }
    }
    Err(last)
}

/// A join through `route` finished: keep the route, its approval and the
/// tag (until the host answers `mousse-keys`).
pub fn after_join(shared: &Shared, ticket: &Ticket, route: &RelayRoute, tag: [u8; 32]) {
    let pin = ticket.host_identity;
    let hint = route.to_hint();
    let sealed = seal_secret(shared, &pin, SEALED_JOIN_TAG, &tag).ok();
    let _ = update_peer(shared, &pin, |p| {
        if !p.ticket_routes.contains(&hint) {
            p.ticket_routes.push(hint.clone());
        }
        if p.pair_secret.is_none() {
            p.join_tag = sealed;
        }
    });
    let _ = add_approval(
        shared,
        &hex(pin.as_bytes()),
        &route.endpoint.destination(),
        "ticket",
    );
}

/// A ticket's relay hints the owner approved at Connect, kept with the
/// host even when the join went another way.
pub fn approve_ticket_routes(shared: &Shared, ticket: &Ticket, approved: &[String]) {
    for (route, _) in join_candidates(ticket, approved) {
        let hint = route.to_hint();
        let _ = update_peer(shared, &ticket.host_identity, |p| {
            if !p.ticket_routes.contains(&hint) {
                p.ticket_routes.push(hint.clone());
            }
        });
        let _ = add_approval(
            shared,
            &hex(ticket.host_identity.as_bytes()),
            &route.endpoint.destination(),
            "ticket",
        );
    }
}

// ---------------------------------------------------------------------------
// `peers.list` and `grants.list` additions

/// What `peers.list` shows about a host's relays.
pub fn peer_json(shared: &Shared, pin: &IdentityPublicKey) -> Value {
    let Ok(entry) = peer_entry(shared, pin) else {
        return Value::Null;
    };
    let manifest = stored_manifest(&entry, pin);
    let mut routes = Vec::new();
    let mut seen = HashSet::new();
    let approvals = approvals(shared);
    let pin_hex = hex(pin.as_bytes());
    let mut push = |destination: String, relay: &RelayId, from: &str| {
        if !seen.insert(destination.clone()) {
            return;
        }
        let source = approvals
            .iter()
            .find(|a| a.identity == pin_hex && a.destination == destination)
            .map(|a| a.source.clone());
        routes.push(json!({
            "destination": destination,
            "relay": hex(&relay.0),
            "from": from,
            "approved": approved(shared, pin, &destination),
            "source": source,
        }));
    };
    if let Some(m) = &manifest {
        for r in &m.routes {
            for e in &r.endpoints {
                push(e.destination(), &r.relay(), "manifest");
            }
        }
    }
    for hint in &entry.ticket_routes {
        if let Some(r) = RelayRoute::parse_hint(hint) {
            push(r.endpoint.destination(), &r.relay, "ticket");
        }
    }
    json!({
        "routes": routes,
        "manifest": manifest.as_ref().map(manifest_json),
        "keys": entry.pair_secret.is_some(),
        "caller": caller_fingerprint(shared, pin),
    })
}

// ---------------------------------------------------------------------------
// Requests

fn str_field<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

/// Answer one request in [`OPS`].
pub fn on_request(shared: &Arc<Shared>, id: Value, op: &str, map: &Map<String, Value>) {
    let reply = match op {
        "relay.enroll" => match str_field(map, "link").map(EnrollmentLink::parse) {
            Some(Ok(link)) => {
                tokio::spawn(enroll(shared.clone(), id, link));
                return;
            }
            _ => error(&id, "bad_link", "That isn't a relay link"),
        },
        "relay.list" => {
            let relays = shared.relay.files.relays().unwrap_or_default().relays;
            let list: Vec<Value> = relays.iter().map(|r| status_json(shared, r)).collect();
            json!({"re": id, "relays": list, "available": shared.relay.seed().is_ok()})
        }
        "relay.remove" => match str_field(map, "relay") {
            Some(relay) => remove_relay(shared, &id, relay),
            None => error(&id, "bad_request", "relay.remove needs relay (its id)"),
        },
        "relay.rotate" => match str_field(map, "relay") {
            Some(relay) if map.get("cancel").and_then(Value::as_bool) == Some(true) => {
                cancel_rotation(shared, &id, relay)
            }
            Some(relay) => rotate(shared, &id, relay),
            None => error(&id, "bad_request", "relay.rotate needs relay (its id)"),
        },
        "peer.relay.allow" | "peer.relay.disallow" => {
            let identity = str_field(map, "identity").map(identity_from_hex);
            let destination = str_field(map, "destination")
                .and_then(RelayEndpoint::from_destination)
                .map(|e| e.destination());
            match (identity, destination) {
                (Some(Ok(pin)), Some(destination)) => {
                    let key = hex(pin.as_bytes());
                    let done = if op == "peer.relay.allow" {
                        add_approval(shared, &key, &destination, APPROVAL_SOURCE_MANIFEST)
                            .map(|()| true)
                    } else {
                        remove_approval(shared, &key, &destination)
                    };
                    match done {
                        Ok(changed) => {
                            if op == "peer.relay.allow" {
                                shared.keep.kick(super::paths::Kick::Reset(Some(pin)));
                            } else if !cfg!(mousse_control = "disallow-keeps-paths") {
                                // Paths through it end now, not only new dials.
                                close_relay_paths(shared, &pin, &destination);
                            }
                            json!({"re": id, "changed": changed})
                        }
                        Err(e) => error(&id, "store_failed", e),
                    }
                }
                _ => error(
                    &id,
                    "bad_request",
                    format!("{op} needs identity (hex) and destination (relay://host:port)"),
                ),
            }
        }
        other => error(&id, "unknown_op", format!("unknown op {other:?}")),
    };
    shared.event(reply);
}

/// `relay.enroll {link}`: register on the relay with a new key and the
/// link's code, keep it, and approve its destination.
async fn enroll(shared: Arc<Shared>, id: Value, link: EnrollmentLink) {
    let reply = match enroll_inner(&shared, &link).await {
        Ok(relay) => json!({"re": id, "relay": relay}),
        Err((e, reason)) => error(&id, e, reason),
    };
    shared.event(reply);
}

async fn enroll_inner(
    shared: &Arc<Shared>,
    link: &EnrollmentLink,
) -> Result<Value, (&'static str, String)> {
    if shared.relay.seed().is_err() {
        return Err(("unavailable", "Relays need the keystore".into()));
    }
    let relay_hex = hex(&link.relay.0);
    let endpoint = RelayEndpoint::from_route_host(link.host.clone(), link.port);
    if shared
        .relay
        .files
        .relays()
        .is_ok_and(|f| f.relays.iter().any(|r| r.relay == relay_hex))
    {
        return Err(("already", "This relay is already set up".into()));
    }
    let salt = hex(&random_bytes::<16>());
    let key = shared
        .relay
        .key(REGISTRATION_KEY_INFO, &salt)
        .map_err(|e| ("store_failed", e))?;
    let addrs = resolve(shared.caller.addr_policy(), &endpoint, true)
        .await
        .map_err(|e| (e.word(), e.to_string()))?;
    let mut last = RelayError::Unreachable;
    let mut registered = None;
    for addr in addrs {
        match TargetLink::register(
            &addr,
            link.relay,
            key.clone(),
            Proof::Enroll(link.code),
            dial_within(),
        )
        .await
        {
            Ok(l) => {
                registered = Some(l);
                break;
            }
            Err(e) => last = e,
        }
    }
    let Some(target) = registered else {
        return Err((last.word(), last.to_string()));
    };
    let relay = OwnRelay {
        endpoint: endpoint.to_string(),
        relay: relay_hex,
        relay_key: target.relay_key().map(|k| hex(k.as_bytes())),
        salt: salt.clone(),
        old: Vec::new(),
        added_at: now(),
        rotated_at: None,
        pending: None,
        chain_full: false,
        chain_until: None,
    };
    {
        let _io = guard(&shared.relay.io);
        let mut file = shared
            .relay
            .files
            .relays()
            .map_err(|e| ("store_failed", e))?;
        file.relays.push(relay.clone());
        shared
            .relay
            .files
            .save_relays(file)
            .map_err(|e| ("store_failed", e))?;
    }
    let me = hex(shared.info.identity.as_bytes());
    let _ = add_approval(shared, &me, &endpoint.destination(), "owner");
    guard(&shared.relay.status).insert(
        relay.relay.clone(),
        Status {
            state: "registered",
            ..Status::default()
        },
    );
    start_registration(shared, &relay, salt, Some(target));
    rebuild_manifest(shared);
    applog::line(format!("relay {} added", relay.endpoint));
    Ok(status_json(shared, &relay))
}

fn remove_relay(shared: &Arc<Shared>, id: &Value, relay: &str) -> Value {
    let relay = relay.to_lowercase();
    let removed = {
        let _io = guard(&shared.relay.io);
        let Ok(mut file) = shared.relay.files.relays() else {
            return error(id, "store_failed", "Couldn't read the relay list");
        };
        let found = file.relays.iter().find(|r| r.relay == relay).cloned();
        file.relays.retain(|r| r.relay != relay);
        if let Err(e) = shared.relay.files.save_relays(file) {
            return error(id, "store_failed", e);
        }
        found
    };
    let Some(found) = removed else {
        return error(id, "no_relay", "No such relay");
    };
    stop_registrations(shared, &relay, None);
    if !cfg!(mousse_control = "remove-keeps-sessions") {
        close_sessions(shared, &relay);
    }
    guard(&shared.relay.status).remove(&relay);
    if let Some(e) = RelayEndpoint::parse(&found.endpoint) {
        let me = hex(shared.info.identity.as_bytes());
        let _ = remove_approval(shared, &me, &e.destination());
    }
    rebuild_manifest(shared);
    json!({"re": id, "removed": true})
}

/// `relay.rotate {id}` ("New relay key", §B.4, self mode). The new key is
/// journaled first (`pending`); the current key stays current. Then
/// [`finish_rotation`] has the current key vouch for it with `SUCCESSOR`
/// until the new key registers, and only then makes it current, with the
/// old key kept registered and in the manifest through the overlap. While
/// the relay's key chain is known to be full it is refused at once.
fn rotate(shared: &Arc<Shared>, id: &Value, relay: &str) -> Value {
    let relay = relay.to_lowercase();
    if shared.relay.seed().is_err() {
        return error(id, "unavailable", "Relays need the keystore");
    }
    if guard(&shared.relay.status)
        .get(&relay)
        .is_none_or(|s| s.state != "registered")
    {
        return error(
            id,
            "not_registered",
            "The relay isn't connected; try again once it is",
        );
    }
    let updated = {
        let _io = guard(&shared.relay.io);
        let Ok(mut file) = shared.relay.files.relays() else {
            return error(id, "store_failed", "Couldn't read the relay list");
        };
        let Some(r) = file.relays.iter_mut().find(|r| r.relay == relay) else {
            return error(id, "no_relay", "No such relay");
        };
        if r.pending.is_some() {
            return error(id, "rotating", "A new key is already on its way");
        }
        if r.chain_full && r.chain_until.is_some_and(|t| t > now()) {
            return error(
                id,
                "chain_full",
                "The relay holds as many keys as it allows; try again once the old key leaves",
            );
        }
        r.chain_full = false;
        r.pending = Some(PendingKey {
            salt: hex(&random_bytes::<16>()),
            since: now(),
            cancelled: false,
        });
        let r = r.clone();
        if let Err(e) = shared.relay.files.save_relays(file) {
            return error(id, "store_failed", e);
        }
        r
    };
    tokio::spawn(finish_rotation(shared.clone(), relay));
    json!({"re": id, "relay": status_json(shared, &updated)})
}

/// `relay.rotate {relay, cancel: true}`: stop a pending rotation. The
/// current key stays. No more `SUCCESSOR`s are sent; [`finish_rotation`]
/// drops the new key once the relay refuses it, and commits it if the
/// relay took one already sent.
fn cancel_rotation(shared: &Arc<Shared>, id: &Value, relay: &str) -> Value {
    let relay = relay.to_lowercase();
    let updated = {
        let _io = guard(&shared.relay.io);
        let Ok(mut file) = shared.relay.files.relays() else {
            return error(id, "store_failed", "Couldn't read the relay list");
        };
        let Some(r) = file.relays.iter_mut().find(|r| r.relay == relay) else {
            return error(id, "no_relay", "No such relay");
        };
        let Some(pending) = r.pending.as_mut() else {
            return error(id, "not_rotating", "No new key is on its way");
        };
        pending.cancelled = true;
        let r = r.clone();
        if let Err(e) = shared.relay.files.save_relays(file) {
            return error(id, "store_failed", e);
        }
        r
    };
    shared.event(json!({"ev": "relay.state", "relay": status_json(shared, &updated)}));
    json!({"re": id, "relay": status_json(shared, &updated)})
}

/// The pending key of `relay`, as stored now.
fn stored_pending(shared: &Shared, relay: &str) -> Option<PendingKey> {
    shared
        .relay
        .files
        .relays()
        .ok()?
        .relays
        .into_iter()
        .find(|r| r.relay == relay)?
        .pending
}

/// A cancelled rotation the relay refused: it took no `SUCCESSOR`, so the
/// new key is dropped.
fn drop_cancelled(shared: &Arc<Shared>, relay: &str, salt: &str) {
    let updated = {
        let _io = guard(&shared.relay.io);
        let Ok(mut file) = shared.relay.files.relays() else {
            return;
        };
        let Some(r) = file.relays.iter_mut().find(|r| r.relay == relay) else {
            return;
        };
        if r.pending.as_ref().is_none_or(|p| p.salt != salt) {
            return;
        }
        r.pending = None;
        let r = r.clone();
        if shared.relay.files.save_relays(file).is_err() {
            return;
        }
        r
    };
    shared.event(json!({"ev": "relay.state", "relay": status_json(shared, &updated)}));
}

/// Take the pending rotation of `relay` to its end: register the new key;
/// while the relay refuses it, have the current registration send
/// `SUCCESSOR` again; once it registers, make it current. The relay gives
/// no other acknowledgement, and a `SUCCESSOR` it already took is refused,
/// so one is sent only after a refusal of the new key.
async fn finish_rotation(shared: Arc<Shared>, relay: String) {
    let wait = crate::limits::ms(limits().via_relay_rotation_retry_ms());
    loop {
        let Some(r) = shared
            .relay
            .files
            .relays()
            .ok()
            .and_then(|f| f.relays.into_iter().find(|r| r.relay == relay))
        else {
            return;
        };
        let Some(pending) = r.pending.clone() else {
            return;
        };
        let (Some(endpoint), Some(id), Ok(new_key)) = (
            RelayEndpoint::parse(&r.endpoint),
            fixed::<32>(&r.relay).map(RelayId),
            shared.relay.key(REGISTRATION_KEY_INFO, &pending.salt),
        ) else {
            return;
        };
        match register(&shared, &endpoint, id, new_key.clone()).await {
            Ok(link) => {
                commit_rotation(&shared, &relay, &pending, link);
                return;
            }
            Err(RelayError::Refused(_)) => {
                // Cancelled, and the relay took no SUCCESSOR: drop the key.
                // A SUCCESSOR sent just before the cancel had a full wait
                // to arrive before this try.
                if pending.cancelled {
                    drop_cancelled(&shared, &relay, &pending.salt);
                    return;
                }
                // Not taken yet: the current key vouches for it (again),
                // unless the rotation ended or was cancelled meanwhile.
                if stored_pending(&shared, &relay) != Some(pending.clone()) {
                    continue;
                }
                let registered = guard(&shared.relay.status)
                    .get(&relay)
                    .is_some_and(|s| s.state == "registered");
                let current = guard(&shared.relay.runs).get(&relay).and_then(|runs| {
                    runs.iter()
                        .find(|run| run.salt == r.salt)
                        .map(|run| run.commands.clone())
                });
                if let (true, Some(commands)) = (registered, current) {
                    let _ = commands.send(TargetCommand::Successor { new_key });
                }
            }
            Err(e) => applog::line(format!("relay {} new key: {e}", r.endpoint)),
        }
        tokio::time::sleep(wait).await;
    }
}

/// The new key registered: it becomes current, and the old key stays
/// registered and in the manifest until its overlap ends. The overlap
/// counts from the rotation's start, before any `SUCCESSOR`, less the
/// clock skew, so the old route leaves the manifest before the relay drops
/// the old key: the overlap is the smaller of `MANIFEST_OVERLAP_SECS` and
/// the relay's `RELAY_SUCCESSOR_OVERLAP_SECS`, which the new key's
/// `REGISTERED` carries. A cancelled rotation the relay took anyway
/// commits too: the relay will drop the current key.
fn commit_rotation(shared: &Arc<Shared>, relay: &str, pending: &PendingKey, link: TargetLink) {
    let committed = {
        let _io = guard(&shared.relay.io);
        let Ok(mut file) = shared.relay.files.relays() else {
            return;
        };
        let Some(r) = file.relays.iter_mut().find(|r| r.relay == relay) else {
            return;
        };
        if r.pending.as_ref().is_none_or(|p| p.salt != pending.salt) {
            return;
        }
        let relay_overlap = link.successor_overlap();
        let overlap = if cfg!(mousse_control = "relay-overlap-ignored") {
            limits().manifest_overlap_secs()
        } else {
            limits()
                .manifest_overlap_secs()
                .min(relay_overlap.unwrap_or(u64::MAX))
        };
        // The control build drops the old key at once: no overlap.
        let until = if cfg!(mousse_control = "no-overlap") {
            now()
        } else {
            (pending.since + overlap).saturating_sub(CLOCK_SKEW_SECS)
        };
        // The relay took the SUCCESSOR by now, so it drops the old key by
        // now plus its overlap (its most when it did not say).
        let dropped_by = now()
            + relay_overlap.unwrap_or(RelayLimits::DEFAULT.successor_overlap_secs())
            + CLOCK_SKEW_SECS;
        r.chain_until = Some(r.chain_until.unwrap_or(0).max(dropped_by));
        r.chain_full = false;
        let old = std::mem::replace(&mut r.salt, pending.salt.clone());
        r.old.push(OldKey { salt: old, until });
        r.rotated_at = Some(now());
        r.pending = None;
        let r = r.clone();
        if shared.relay.files.save_relays(file).is_err() {
            return;
        }
        r
    };
    start_registration(shared, &committed, committed.salt.clone(), Some(link));
    set_status(
        shared,
        relay,
        Status {
            state: "registered",
            ..Status::default()
        },
    );
    end_overlaps(shared);
    rebuild_manifest(shared);
    applog::line(format!("relay {} has the new key", committed.endpoint));
}

/// Old keys whose overlap ended leave the manifest and stop registering.
fn end_overlaps(shared: &Arc<Shared>) {
    let t = now();
    let ended: Vec<(String, String)> = {
        let _io = guard(&shared.relay.io);
        let Ok(mut file) = shared.relay.files.relays() else {
            return;
        };
        let mut ended = Vec::new();
        for r in &mut file.relays {
            for o in r.old.iter().filter(|o| o.until <= t) {
                ended.push((r.relay.clone(), o.salt.clone()));
            }
            r.old.retain(|o| o.until > t);
        }
        if !ended.is_empty() {
            let _ = shared.relay.files.save_relays(file);
        }
        ended
    };
    for (relay, salt) in &ended {
        stop_registrations(shared, relay, Some(salt));
    }
    if !ended.is_empty() {
        rebuild_manifest(shared);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_s_relay_route_dials_only_public_or_tailnet_addresses() {
        for own in [false, true] {
            assert!(relay_class_ok(AddrClass::Public, own, false));
            assert!(relay_class_ok(AddrClass::Tailnet, own, false));
            assert!(!relay_class_ok(AddrClass::Forbidden, own, true));
        }
        assert!(!relay_class_ok(AddrClass::Lan, false, false));
        assert!(relay_class_ok(AddrClass::Lan, true, false));
        assert_eq!(
            relay_class_ok(AddrClass::Lan, false, true),
            cfg!(debug_assertions)
        );
    }
}
