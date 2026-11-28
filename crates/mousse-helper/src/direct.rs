//! Pair with IP on this helper (`docs/pair-with-ip-design.md` §1.4 step 9,
//! §1.6 and §4): what a joiner stores when the host's `PAIRED` arrives, the
//! completion records `join.status` lists by invitation, and the rule that
//! keeps every Pair with IP operation off until the wire speaks minor 4.
//!
//! - **Pins** ([`DirectStore`], the io joiner's `DirectPins`): under the
//!   peers lock, the host's row (its pin, name and role) with the typed
//!   address as an owner address, an owner approval for that address when
//!   the automatic rule does not cover it (a tailnet address), then the
//!   completion record keyed by the invitation, each written durably
//!   before the join is reported paired. A crash part way leaves the
//!   joiner's pending record, so the next recovery stores it all again.
//! - **Completion records** in `direct-joins/<invitation>.done`: listed by
//!   `join.status {}`, dropped by `join.ack {invitation}` and by a removal
//!   of the host.
//! - **The gate** ([`enabled`]): every Pair with IP operation answers
//!   `unsupported` unless this build speaks wire minor 4, which a release
//!   build does only once `PROTOCOL_MINOR_VERSION` is 4; a debug build
//!   speaks it with `MOUSSE_NET_TEST_HELLO_MINOR=4`.
//! - **The code** is never logged and never put in an error message: store
//!   errors of the joiner's records name files after the code's lookup, so
//!   they are reported in fixed words, never by their text.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use mousse_net_core::control::DIRECT_MINOR_VERSION;
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::pairing::{DirectAddress, DirectPaired, InvitationId};
use mousse_net_io::pipe::{AddrPolicy, LocalRoute};
use mousse_net_io::store::{
    hex, unhex, write_atomic, Approval, ApprovalStore, PeerRecord, PeerStore, PeersLock,
    APPROVAL_SOURCE_OWNER,
};
use mousse_net_io::tls::DeniedCheck;
use mousse_net_io::{DirectPins, DirectRecordStore, DirectRecords, DirectSetup, NetError};
use serde::{Deserialize, Serialize};

/// Whether Pair with IP is on: this build speaks wire minor 4. Must-fail
/// control (tests only): always on.
pub fn enabled() -> bool {
    cfg!(mousse_control = "direct-ops-ungated")
        || mousse_net_io::conn::local_minor() >= DIRECT_MINOR_VERSION
}

/// The reason given with `unsupported`.
pub const UNSUPPORTED: &str = "Pair with IP needs wire minor 4, which this helper does not speak";

/// The typed address as the owner route it is stored as: `tcp://<address>`.
/// `None` when the address policy never dials it (unspecified, multicast,
/// reserved and documentation ranges, loopback outside tests).
pub fn owner_route(policy: &AddrPolicy, address: &DirectAddress) -> Option<LocalRoute> {
    let route = LocalRoute::parse(&format!("tcp://{address}")).ok()?;
    (!policy.names_forbidden(&route)).then_some(route)
}

/// The typed address, parsed with the route grammar and checked against
/// the address policy as an owner route is (`peer.addresses.set`): what the
/// person typed counts as approved, unless it is never dialled.
pub fn typed_address(policy: &AddrPolicy, text: &str) -> Result<DirectAddress, &'static str> {
    let address =
        DirectAddress::parse(text).ok_or("the address is not an IP address and a port")?;
    match owner_route(policy, &address) {
        Some(_) => Ok(address),
        None => Err("that address is never dialled"),
    }
}

/// One completed Pair with IP join, kept until the app acknowledges it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectCompletion {
    /// The invitation id `I` (hex).
    pub invitation: String,
    /// The host's identity (hex SEC1).
    pub host_identity: String,
    /// The host's name, from `PAIRED`.
    pub name: String,
    /// The role it granted.
    pub role: String,
    /// The typed address, stored as an owner address.
    pub route: String,
    /// When the join finished (Unix seconds).
    pub at: u64,
}

impl DirectCompletion {
    /// As `join.status` lists it.
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "invitation": self.invitation,
            "identity": self.host_identity,
            "name": self.name,
            "role": self.role,
            "route": self.route,
        })
    }
}

/// The completion records in `direct-joins/` of one state directory.
#[derive(Clone, Debug)]
pub struct Completions {
    dir: PathBuf,
}

impl Completions {
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            dir: dir.join("direct-joins"),
        }
    }

    fn path(&self, invitation: &InvitationId) -> PathBuf {
        self.dir.join(format!("{}.done", hex(&invitation.0)))
    }

    /// Every record that reads, oldest first.
    pub fn list(&self) -> Result<Vec<DirectCompletion>, NetError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(store_err(&self.dir, e)),
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".done")) else {
                continue;
            };
            let Ok(bytes) = fs::read(entry.path()) else {
                continue;
            };
            match serde_json::from_slice::<DirectCompletion>(&bytes) {
                Ok(record) if record.invitation == stem => out.push(record),
                _ => continue,
            }
        }
        out.sort_by_key(|r| r.at);
        Ok(out)
    }

    /// Write `record` durably, replacing any for its invitation.
    fn save(&self, invitation: &InvitationId, record: &DirectCompletion) -> Result<(), NetError> {
        mousse_net_io::private::make_private_dir_durably(&self.dir)
            .map_err(|e| store_err(&self.dir, e))?;
        let path = self.path(invitation);
        let bytes = serde_json::to_vec_pretty(record).map_err(|e| store_err(&path, e))?;
        write_atomic(&path, &bytes)
    }

    /// Drop the record of `invitation`, durably. Returns whether there was
    /// one.
    pub fn remove(&self, invitation: &InvitationId) -> Result<bool, NetError> {
        let path = self.path(invitation);
        match fs::remove_file(&path) {
            Ok(()) => {
                mousse_net_io::private::sync_dir(&self.dir).map_err(|e| store_err(&self.dir, e))?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(store_err(&path, e)),
        }
    }

    /// Drop every record naming the host `identity` (hex), under the peers
    /// lock: the host was removed, and `join.status` must not list it.
    pub fn remove_naming(&self, _held: &PeersLock<'_>, identity: &str) -> Result<(), NetError> {
        for record in self.list()? {
            if record.host_identity == identity {
                if let Some(invitation) = parse_invitation(&record.invitation) {
                    self.remove(&invitation)?;
                }
            }
        }
        Ok(())
    }
}

/// Whether a join that started earlier may still store `identity`, checked
/// under the peers lock: `Some(peer generation)` when it may (the
/// generation a path it publishes must still match), `None` when the host
/// was removed meanwhile (`peer.forget`, or a removal of its grant here).
pub type JoinFence = Arc<dyn Fn(&IdentityPublicKey) -> Option<u64> + Send + Sync>;

/// The joiner's Pair with IP writes in one state directory.
pub struct DirectStore {
    dir: PathBuf,
    policy: AddrPolicy,
    fence: Option<JoinFence>,
    /// The peer generation each stored host had when it was stored.
    stored: Mutex<HashMap<IdentityPublicKey, u64>>,
    /// A store was refused because its host was removed meanwhile.
    fenced: AtomicBool,
}

impl DirectStore {
    pub fn new(dir: &Path, policy: AddrPolicy, fence: Option<JoinFence>) -> Self {
        Self {
            dir: dir.to_path_buf(),
            policy,
            fence,
            stored: Mutex::new(HashMap::new()),
            fenced: AtomicBool::new(false),
        }
    }

    /// The peer generation `identity` had when this store wrote it.
    pub fn stored_gen(&self, identity: &IdentityPublicKey) -> Option<u64> {
        self.stored
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(identity)
            .copied()
    }

    /// Whether a store was refused because its host was removed while the
    /// join ran.
    pub fn was_fenced(&self) -> bool {
        self.fenced.load(Ordering::SeqCst)
    }

    fn store_paired(&self, paired: &DirectPaired) -> Result<(), NetError> {
        let route = owner_route(&self.policy, &paired.address)
            .ok_or_else(|| NetError::Store("the typed address is never dialled".into()))?
            .uri();
        let identity = hex(paired.identity.as_bytes());
        let role = paired.role.as_str().to_owned();
        let at = crate::peer::now_secs();
        let peers = PeerStore::in_dir(&self.dir);
        let held = peers.lock()?;
        // Under the peers lock, which a removal advances the generations
        // under: the join stores before the removal or not at all.
        // Must-fail control (tests only): not checked.
        let gen = match &self.fence {
            Some(fence) if !cfg!(mousse_control = "direct-pin-after-removal") => {
                match fence(&paired.identity) {
                    Some(gen) => Some(gen),
                    None => {
                        self.fenced.store(true, Ordering::SeqCst);
                        return Err(NetError::Refused(
                            "the host was removed while the join ran".into(),
                        ));
                    }
                }
            }
            Some(fence) => fence(&paired.identity).or(Some(0)),
            None => None,
        };
        held.update(
            |list| match list.iter_mut().find(|p| p.identity == identity) {
                Some(p) => {
                    p.name = paired.name.clone();
                    p.role = role.clone();
                    if !p.addresses.contains(&route) {
                        p.addresses.push(route.clone());
                    }
                }
                None => list.push(PeerRecord {
                    name: paired.name.clone(),
                    identity: identity.clone(),
                    role: role.clone(),
                    routes: Vec::new(),
                    last_route: None,
                    addresses: vec![route.clone()],
                    offered: Vec::new(),
                    paired_at: at,
                }),
            },
        )?;
        // A LAN literal needs no approval; a tailnet (or other) address is
        // the owner's, approved by typing it.
        let automatic = LocalRoute::parse(&route).is_ok_and(|r| self.policy.automatic(&r));
        if !automatic {
            ApprovalStore::in_dir(&self.dir).add(
                &held,
                &[Approval {
                    identity: identity.clone(),
                    destination: route.clone(),
                    source: APPROVAL_SOURCE_OWNER.into(),
                    at,
                }],
            )?;
        }
        // Must-fail control (tests only): the pin alone, with no completion
        // record for `join.status`.
        if cfg!(mousse_control = "direct-done-pin-only") {
            return Ok(());
        }
        let record = DirectCompletion {
            invitation: hex(&paired.invitation.0),
            host_identity: identity,
            name: paired.name.clone(),
            role,
            route,
            at,
        };
        Completions::in_dir(&self.dir).save(&paired.invitation, &record)?;
        if let Some(gen) = gen {
            self.stored
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(paired.identity, gen);
        }
        Ok(())
    }
}

impl DirectPins for DirectStore {
    fn store(&self, paired: &DirectPaired) -> Result<(), NetError> {
        self.store_paired(paired)
    }
}

/// What a Pair with IP join uses in `dir`: the records on disk, the pins
/// written by the returned [`DirectStore`] (fenced by `fence` against a
/// removal of the host while the join runs), and the profile's denied
/// identities.
pub fn setup(
    dir: &Path,
    policy: AddrPolicy,
    denied: DeniedCheck,
    fence: Option<JoinFence>,
) -> (DirectSetup, Arc<DirectStore>) {
    let store = Arc::new(DirectStore::new(dir, policy, fence));
    let setup = DirectSetup {
        records: Arc::new(DirectRecordStore::in_dir(dir)),
        pins: store.clone(),
        denied,
    };
    (setup, store)
}

/// Delete, durably, every kept Pair with IP pending record whose host is
/// `identity` (hex), under the peers lock: the host was removed, and no
/// recovery, now or after a restart, may pair with it again. A running flow
/// on such a record finds it gone at its next write and ends. Must-fail
/// control (tests only): the records stay.
pub fn forget_pending(dir: &Path, _held: &PeersLock<'_>, identity: &str) -> Result<(), NetError> {
    if cfg!(mousse_control = "direct-pending-outlives-removal") {
        return Ok(());
    }
    let records = DirectRecordStore::in_dir(dir);
    let found = records.pending_slots()?;
    for slot in found.slots {
        // A record that does not read is never recovered (its recovery
        // fails and keeps it), so it pairs with nobody; it stays.
        let Ok((_, pending)) = records.load(&slot.lookup, &slot.address) else {
            continue;
        };
        if let Some(p) = pending.filter(|p| hex(p.host.as_bytes()) == identity) {
            records.swap_pending(&slot.lookup, &slot.address, Some(&p), None)?;
        }
    }
    Ok(())
}

/// Wipe the `code` field of an app or control message (a Pair with IP
/// code, or a link's 6-digit code) once it was serialized or read: the
/// string's bytes are overwritten before it is freed. Copies serde made
/// while parsing (its scratch buffer for escaped strings) are out of
/// reach.
pub fn wipe_code(value: &mut serde_json::Value) {
    use zeroize::Zeroize;
    if let Some(serde_json::Value::String(code)) = value.get_mut("code") {
        code.zeroize();
    }
}

/// A request map whose `code` field is wiped when it is dropped, however
/// the request was answered.
pub struct WipeCode(pub serde_json::Map<String, serde_json::Value>);

impl std::ops::Deref for WipeCode {
    type Target = serde_json::Map<String, serde_json::Value>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl WipeCode {
    /// The map, for a request handled on a task of its own (one with no
    /// code to wipe).
    pub fn take(mut self) -> serde_json::Map<String, serde_json::Value> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for WipeCode {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(serde_json::Value::String(code)) = self.0.get_mut("code") {
            code.zeroize();
        }
    }
}

/// An invitation id given in hex.
pub fn parse_invitation(text: &str) -> Option<InvitationId> {
    let bytes = unhex(text).ok()?;
    Some(InvitationId(bytes.try_into().ok()?))
}

fn store_err(path: &Path, e: impl std::fmt::Display) -> NetError {
    NetError::Store(format!("{}: {e}", path.display()))
}

/// Read the code from a prompt on this terminal, never from an argument or
/// the environment, so it does not land in shell history. `None` at the end
/// of input.
fn prompt_code() -> Option<zeroize::Zeroizing<String>> {
    use std::io::{BufRead, Write};
    print!("Type the code shown on the host: ");
    let _ = std::io::stdout().flush();
    let mut line = zeroize::Zeroizing::new(String::new());
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line),
    }
}

/// `mousse-helper join-direct <address>`: pair with the host at the typed
/// address, the code read from a prompt. Prints where it stands, this
/// device's short id while it waits for Allow, and the host once paired;
/// a first stream (the host's build) commits the host's grant.
pub async fn join_cli(
    side: &crate::peer::CallerSide,
    address: &str,
    name: &str,
) -> Result<String, String> {
    use mousse_net_core::pairing::{DirectEnd, DirectJoinerState};
    use mousse_net_io::store::{short_id, GrantStore};
    use mousse_net_io::{DirectDialFailure, DirectJoinEvent};

    if !enabled() {
        return Err(UNSUPPORTED.into());
    }
    let dir = side.endpoint.dir().to_path_buf();
    let policy = side.caller.addr_policy().clone();
    let address = typed_address(&policy, address).map_err(str::to_owned)?;
    // A far end this profile denied is refused before this device's
    // certificate goes out, so a deny list that does not read stops the
    // join before anything is asked or dialled. Must-fail control (tests
    // only): taken as empty.
    let denied = match GrantStore::in_dir(&dir).load() {
        Ok(table) => Some(table),
        Err(_) if cfg!(mousse_control = "direct-cli-denied-unread") => None,
        Err(_) => {
            return Err(
                "this device's grant list could not be read, so the join was not started".into(),
            )
        }
    };
    let code = tokio::task::spawn_blocking(prompt_code)
        .await
        .ok()
        .flatten()
        .ok_or("no code was typed")?;
    let denied: DeniedCheck = Arc::new(move |identity| {
        denied
            .as_ref()
            .is_some_and(|table| table.is_denied(identity))
    });
    let (setup, _) = setup(&dir, policy, denied, None);
    let started = side
        .caller
        .join_direct(&setup, &address.to_string(), code.trim(), name);
    drop(code);
    let mut join = started.map_err(|e| e.to_string())?;
    let mine = short_id(&side.caller.identity());
    let mut watch = join.state();
    let mut shown: Option<DirectJoinerState> = None;
    let mut watching = true;
    let mut paired = None;
    loop {
        tokio::select! {
            event = join.event() => match event {
                Some(DirectJoinEvent::Paired(p)) => paired = Some(p),
                Some(DirectJoinEvent::Away) => println!("the connection dropped; reconnecting"),
                Some(_) => {}
                None => break,
            },
            changed = watch.changed(), if watching => {
                if changed.is_err() {
                    watching = false;
                    continue;
                }
                let now = *watch.borrow_and_update();
                if shown == Some(now) {
                    continue;
                }
                shown = Some(now);
                match now {
                    DirectJoinerState::Connecting => println!("connecting to {address}"),
                    DirectJoinerState::Exchanging => println!("checking the code"),
                    DirectJoinerState::AwaitingAllow => println!(
                        "waiting for Allow on the host; this device is {mine}"
                    ),
                    _ => {}
                }
            }
        }
    }
    let joined = join.finish().await.map_err(|_| {
        "a Pair with IP record could not be read or stored; nothing was paired".to_string()
    })?;
    let attempts = |left: u8| format!("{left} {} left", if left == 1 { "try" } else { "tries" });
    let text = match joined.end {
        DirectEnd::Paired => {
            let p = paired.ok_or("the pairing was not stored")?;
            let who = format!("{} ({})", crate::printable(&p.name), short_id(&p.identity));
            return Ok(match &joined.connection {
                Some(conn) => match crate::peer::host_build(conn).await {
                    Ok(build) => format!("paired with {who}, build {build}"),
                    Err(e) => format!("paired with {who} (its build: {e})"),
                },
                None => format!("paired with {who}"),
            });
        }
        DirectEnd::CodeFailed { attempts_left } => {
            format!("the code didn't work ({})", attempts(attempts_left))
        }
        DirectEnd::NotReceived { attempts_left } => format!(
            "the connection dropped before the code arrived; connect again ({})",
            attempts(attempts_left)
        ),
        DirectEnd::AttemptsExhausted => "no tries left for this code; ask for a new one".into(),
        DirectEnd::NeedsUpdate => "that computer runs an older Mousse; update it".into(),
        DirectEnd::OwnDevice => "that address is this device".into(),
        DirectEnd::Cancelled => "cancelled".into(),
        DirectEnd::Busy => "another join with this code is running on this device".into(),
        DirectEnd::Closed(Some(code)) => match code {
            mousse_net_core::ErrorCode::InvitationInvalid => {
                "no open invitation at that address; check the address and code, or ask for a new code".into()
            }
            mousse_net_core::ErrorCode::PairingDeclined => "the host owner declined".into(),
            mousse_net_core::ErrorCode::InternalError => "that computer is busy; try again".into(),
            other => format!("the connection closed ({})", other.name()),
        },
        DirectEnd::Closed(None) => match joined.dial {
            Some(DirectDialFailure::NotMousse) => "can't reach Mousse at that address".into(),
            _ => "can't reach that address".into(),
        },
        other => format!("pairing ended: {other:?}"),
    };
    Err(text)
}
