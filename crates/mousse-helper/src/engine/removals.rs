//! "Remove on all my hosts" (Phase 4, design Part D), both sides.
//!
//! **Host side.** To every caller whose grant has role `owner`, on wire
//! minor 2, the host opens `mousse-grants` once the caller has opened a
//! stream, and sends its grant list then and on every change. A caller's
//! `mousse-removal` carries one signed removal; the host decides it under
//! its admission lock ([`crate::revoke::Removal::apply_signed`]) and
//! answers `{1: removal id, 2: result}`.
//!
//! **Admin side.** The admin device's hosts are the peers whose `PAIRED`
//! gave it role `owner`. It keeps each host's last grant list. When the user
//! removes device X, a removal is signed for each host whose last list named
//! a grant for X, naming that grant id, and only for hosts the user
//! confirmed. A host whose list did not name X gets nothing ("Not known on
//! <host>"); if a later list from it names X, the app is asked again. Each
//! removal is signed once and resent with the same bytes on every session
//! until the host answers, or by mail (Part D.3), until
//! `MOUSSE_NET_REMOVAL_MAX_AGE_SECS` passes.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mousse_net_core::grants::GrantId;
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::PriorityClass;
use mousse_net_core::removal::{
    GrantList, Removal as RemovalRecord, RemovalAnswer, RemovalId, RemovalResult, SignedRemoval,
    GRANTS_LABEL, REMOVAL_LABEL, REMOVAL_MIN_MINOR,
};
use mousse_net_core::ErrorCode;
use mousse_net_io::rng::random_bytes;
use mousse_net_io::store::{hex, identity_from_hex, short_id, unhex, write_atomic, PeerStore};
use mousse_net_io::{Connection, MuxStream};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::stream::{self, MessageReader};
use super::Engine;
use crate::applog;
use crate::limits::{helper, ms};

/// The admin side's file, in the endpoint's folder.
pub const ADMIN_FILE: &str = "removals-sent.json";

// ---------------------------------------------------------------------------
// Host side
// ---------------------------------------------------------------------------

/// Answer one `mousse-removal` stream: read the signed removal, apply it,
/// answer and finish. A malformed message resets the stream.
pub async fn serve_removal(engine: Arc<Engine>, stream: MuxStream) {
    let (reader, writer) = stream.split();
    let mut reader = MessageReader::new(reader);
    let wait = ms(helper().removal_answer_wait_ms());
    let message = match reader.next_within(wait).await {
        Ok(Some(m)) => m,
        _ => {
            writer.reset(ErrorCode::ProtocolError);
            return;
        }
    };
    let answer = match engine.apply_removal(&message) {
        Ok(answer) => answer,
        Err(why) => {
            applog::line(format!("a removal was not applied: {why}"));
            writer.reset(ErrorCode::InternalError);
            return;
        }
    };
    if stream::write(&writer, &answer.encode()).await.is_ok() {
        writer.finish();
    }
}

/// Whether the caller of `conn` gets the grant list: its grant has role
/// `owner`. Must-fail control (tests only): any granted caller does, so a
/// demoted owner keeps getting it.
fn gets_grant_list(engine: &Engine, conn: &Connection) -> bool {
    if cfg!(mousse_control = "demoted-owner-keeps-grants") {
        return engine.host.grant_of(conn.id()).is_some();
    }
    engine.is_owner_conn(conn)
}

/// Send this host's grant list on `mousse-grants` to the caller of the
/// inbound connection `conn`, once `opened` says the caller has opened a
/// stream, and again on every change, while the caller's grant has role
/// `owner` and the connection lasts.
pub async fn publish_grants(
    engine: Arc<Engine>,
    conn: Arc<Connection>,
    mut opened: tokio::sync::watch::Receiver<bool>,
) {
    if opened.wait_for(|o| *o).await.is_err() {
        return;
    }
    if conn.minor().unwrap_or(0) < REMOVAL_MIN_MINOR || !gets_grant_list(&engine, &conn) {
        return;
    }
    let mut changes = engine.host.grants_changed();
    let stream = match conn
        .open_stream(PriorityClass::Interactive, GRANTS_LABEL)
        .await
    {
        Ok(s) => s,
        Err(_) => return,
    };
    // Held weakly from here: the stream never keeps the connection open.
    let conn = Arc::downgrade(&conn);
    let (_reader, writer) = stream.split();
    loop {
        changes.borrow_and_update();
        // A demotion closes the connection with `CANCELLED` under the host
        // lock (which drops what was queued on it), and the edit is
        // answered only once nothing queued can leave, so a list written
        // after this check passed cannot reach a demoted caller; a change
        // seen here ends the stream.
        let owner = conn.upgrade().is_some_and(|c| gets_grant_list(&engine, &c));
        if !owner {
            writer.reset(ErrorCode::Cancelled);
            return;
        }
        let list = GrantList::of(engine.host.grants().iter());
        if stream::write(&writer, &list.encode()).await.is_err() {
            return;
        }
        tokio::select! {
            changed = changes.changed() => if changed.is_err() { return },
            () = writer.closing() => return,
        }
    }
}

// ---------------------------------------------------------------------------
// Admin side: stored state
// ---------------------------------------------------------------------------

/// A host's last grant list, as stored.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct StoredList {
    /// `(identity hex, grant id, role, name)`.
    pub grants: Vec<(String, u64, String, String)>,
    /// When it arrived.
    pub at: u64,
}

impl StoredList {
    fn grant_for(&self, identity: &str) -> Option<u64> {
        self.grants.iter().find(|g| g.0 == identity).map(|g| g.1)
    }
}

/// One removal made on this device, for one host.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// Removal id (hex).
    pub id: String,
    /// The host (hex identity).
    pub host: String,
    /// The removed device (hex identity).
    pub removed: String,
    /// The removed device's name, as the user saw it.
    pub name: String,
    /// Its grant id on the host.
    pub grant: u64,
    /// The signed envelope (hex), the same bytes on every resend.
    pub envelope: String,
    /// When it was signed.
    pub issued_at: u64,
    /// `waiting`, `sent`, `quota`, `delivered`, `done` or `expired`.
    pub state: String,
    /// For `done`: `applied`, `stale` or `refused`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// For mail: the Plus message id (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Device X was removed while some hosts' lists did not name it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    /// The removed device (hex identity).
    pub removed: String,
    /// Its name.
    pub name: String,
    /// Hosts whose list did not name it when the user acted.
    pub unknown: Vec<String>,
    /// Hosts whose later list named it, with that grant id: the app asks
    /// again ("<X> is also on <host>. Remove it there?").
    #[serde(default)]
    pub asks: Vec<(String, u64)>,
    /// When the user acted.
    pub at: u64,
}

#[derive(Serialize, Deserialize, Default)]
struct AdminFile {
    version: u32,
    #[serde(default)]
    lists: BTreeMap<String, StoredList>,
    #[serde(default)]
    items: Vec<Item>,
    #[serde(default)]
    intents: Vec<Intent>,
}

/// The admin side's store.
pub struct AdminStore {
    path: PathBuf,
}

impl AdminStore {
    /// `removals-sent.json` in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join(ADMIN_FILE),
        }
    }

    fn load(&self) -> Result<AdminFile, String> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", self.path.display()))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(AdminFile::default()),
            Err(e) => Err(format!("{}: {e}", self.path.display())),
        }
    }

    fn save(&self, file: &AdminFile) -> Result<(), String> {
        let mut file_out = AdminFile {
            version: 1,
            lists: file.lists.clone(),
            items: file.items.clone(),
            intents: file.intents.clone(),
        };
        file_out
            .intents
            .retain(|i| !i.unknown.is_empty() || !i.asks.is_empty());
        let bytes = serde_json::to_vec(&file_out).map_err(|e| e.to_string())?;
        write_atomic(&self.path, &bytes).map_err(|e| e.to_string())
    }
}

fn item_json(item: &Item) -> Value {
    let mut v = json!({
        "id": item.id,
        "host": item.host,
        "removed": item.removed,
        "name": item.name,
        "grant": item.grant,
        "state": item.state,
        "issued_at": item.issued_at,
    });
    if let Some(r) = &item.result {
        v["result"] = json!(r);
    }
    v
}

/// The states a removal can still change from.
fn open_state(state: &str) -> bool {
    matches!(state, "waiting" | "sent" | "quota" | "delivered")
}

// ---------------------------------------------------------------------------
// Admin side: operations
// ---------------------------------------------------------------------------

impl Engine {
    fn admin(&self) -> AdminStore {
        AdminStore::in_dir(&self.state_dir)
    }

    /// The hosts where this device has role `owner`: `(identity, name)`.
    pub fn owner_hosts(&self) -> Vec<(IdentityPublicKey, String)> {
        PeerStore::in_dir(&self.state_dir)
            .load()
            .unwrap_or_default()
            .into_iter()
            .filter(|p| crate::app::role_is_owner(&p.role))
            .filter_map(|p| p.pin().ok().map(|pin| (pin, p.name)))
            .collect()
    }

    /// A grant list from `host` arrived on `mousse-grants`. Kept only if
    /// `host` gave this device role `owner`. Asks the app again for any
    /// removal the user made while this host's list did not name the
    /// device.
    pub fn on_grant_list(self: &Arc<Self>, host: &IdentityPublicKey, list: &GrantList) {
        if !self.owner_hosts().iter().any(|(h, _)| h == host) {
            return;
        }
        let _admin = self.admin_lock.lock().unwrap_or_else(|e| e.into_inner());
        let store = self.admin();
        let Ok(mut file) = store.load() else {
            return;
        };
        let host_hex = hex(host.as_bytes());
        file.lists.insert(
            host_hex.clone(),
            StoredList {
                grants: list
                    .grants
                    .iter()
                    .map(|g| {
                        (
                            hex(g.identity.as_bytes()),
                            g.grant.0,
                            g.role.as_str().to_owned(),
                            g.name.clone(),
                        )
                    })
                    .collect(),
                at: self.clock.now().secs(),
            },
        );
        let mut asks = Vec::new();
        let mut auto = Vec::new();
        for intent in &mut file.intents {
            if !intent.unknown.contains(&host_hex) {
                continue;
            }
            let Ok(removed) = identity_from_hex(&intent.removed) else {
                continue;
            };
            if let Some(grant) = list.grant_for(&removed) {
                if cfg!(mousse_control = "auto-send-unknown") {
                    // Must-fail control (tests only): queue the removal
                    // without asking.
                    auto.push((removed, intent.name.clone(), *host, grant));
                    continue;
                }
                // Ask only once per grant id.
                if !intent
                    .asks
                    .iter()
                    .any(|a| a.0 == host_hex && a.1 == grant.0)
                {
                    intent.asks.push((host_hex.clone(), grant.0));
                    asks.push(json!({
                        "ev": "removal.ask",
                        "identity": intent.removed,
                        "name": intent.name,
                        "host": host_hex,
                        "grant": grant.0,
                    }));
                }
            }
        }
        if store.save(&file).is_ok() {
            for ask in asks {
                self.event(ask);
            }
        }
        drop(_admin);
        for (removed, name, host, grant) in auto {
            let _ = self.removal_confirm(&removed, &name, &[(host, grant)]);
        }
    }

    /// `removal.plan {identity}`: for each owner host, the grant id its
    /// last list named for the device, or none ("Not known on <host>").
    pub fn removal_plan(&self, removed: &IdentityPublicKey) -> Result<Value, String> {
        let file = self.admin().load()?;
        let removed = hex(removed.as_bytes());
        let hosts: Vec<Value> = self
            .owner_hosts()
            .into_iter()
            .filter(|(h, _)| hex(h.as_bytes()) != removed)
            .map(|(h, name)| {
                let host_hex = hex(h.as_bytes());
                let list = file.lists.get(&host_hex);
                json!({
                    "host": host_hex,
                    "name": name,
                    "grant": list.and_then(|l| l.grant_for(&removed)),
                    "list_at": list.map(|l| l.at),
                })
            })
            .collect();
        Ok(json!({ "hosts": hosts }))
    }

    /// `removal.confirm {identity, name, hosts: [{host, grant}]}`: sign one
    /// removal per confirmed host and grant id, and remember the owner
    /// hosts that did not know the device so a later list asks again.
    pub fn removal_confirm(
        self: &Arc<Self>,
        removed: &IdentityPublicKey,
        name: &str,
        confirmed: &[(IdentityPublicKey, GrantId)],
    ) -> Result<Value, String> {
        let now = self.clock.now();
        let mut made = Vec::new();
        let reply = {
            let _admin = self.admin_lock.lock().unwrap_or_else(|e| e.into_inner());
            let store = self.admin();
            let mut file = store.load()?;
            let owner_hosts = self.owner_hosts();
            let removed_hex = hex(removed.as_bytes());
            for (host, grant) in confirmed {
                if !owner_hosts.iter().any(|(h, _)| h == host) {
                    return Err(format!(
                        "{} did not make this device an owner",
                        short_id(host)
                    ));
                }
                let host_hex = hex(host.as_bytes());
                // One open removal per host and grant: a repeat confirm is
                // the same removal.
                if let Some(existing) = file.items.iter().find(|i| {
                    i.host == host_hex
                        && i.removed == removed_hex
                        && i.grant == grant.0
                        && i.state != "expired"
                }) {
                    made.push(existing.clone());
                    continue;
                }
                let record = RemovalRecord {
                    signer: self.signer.public_key(),
                    recipient: *host,
                    removed: *removed,
                    grant: *grant,
                    id: RemovalId(random_bytes::<16>()),
                    issued_at: now,
                };
                let signed =
                    SignedRemoval::sign(record, &*self.signer).map_err(|e| e.to_string())?;
                let item = Item {
                    id: hex(&signed.removal().id.0),
                    host: host_hex,
                    removed: removed_hex.clone(),
                    name: name.to_owned(),
                    grant: grant.0,
                    envelope: hex(&signed.encode()),
                    issued_at: now.secs(),
                    state: "waiting".into(),
                    result: None,
                    message: None,
                };
                file.items.push(item.clone());
                made.push(item);
            }
            // Owner hosts not confirmed whose last list did not name the
            // device: a later list that names it asks again.
            let unknown: Vec<String> = owner_hosts
                .iter()
                .map(|(h, _)| hex(h.as_bytes()))
                .filter(|h| *h != removed_hex)
                .filter(|h| !confirmed.iter().any(|(c, _)| hex(c.as_bytes()) == *h))
                .filter(|h| {
                    file.lists
                        .get(h)
                        .and_then(|l| l.grant_for(&removed_hex))
                        .is_none()
                })
                .collect();
            if !unknown.is_empty() {
                file.intents.retain(|i| i.removed != removed_hex);
                file.intents.push(Intent {
                    removed: removed_hex.clone(),
                    name: name.to_owned(),
                    unknown: unknown.clone(),
                    asks: Vec::new(),
                    at: now.secs(),
                });
            }
            store.save(&file)?;
            json!({
                "removals": made.iter().map(item_json).collect::<Vec<_>>(),
                "unknown": unknown,
            })
        };
        for item in &made {
            self.wake_delivery(item);
        }
        Ok(reply)
    }

    /// `removal.ask.answer {identity, host, grant, yes}`: the user's answer
    /// to "<X> is also on <host>. Remove it there?".
    pub fn removal_ask_answer(
        self: &Arc<Self>,
        removed: &IdentityPublicKey,
        host: &IdentityPublicKey,
        grant: GrantId,
        yes: bool,
    ) -> Result<Value, String> {
        let removed_hex = hex(removed.as_bytes());
        let host_hex = hex(host.as_bytes());
        let name = {
            let _admin = self.admin_lock.lock().unwrap_or_else(|e| e.into_inner());
            let store = self.admin();
            let mut file = store.load()?;
            let Some(intent) = file.intents.iter_mut().find(|i| i.removed == removed_hex) else {
                return Err("nothing was asked for that device".into());
            };
            if !intent
                .asks
                .iter()
                .any(|a| a.0 == host_hex && a.1 == grant.0)
            {
                return Err("that host and grant were not asked about".into());
            }
            intent.asks.retain(|a| a.0 != host_hex);
            intent.unknown.retain(|h| *h != host_hex);
            let name = intent.name.clone();
            store.save(&file)?;
            name
        };
        if !yes {
            return Ok(json!({ "removals": [] }));
        }
        self.removal_confirm(removed, &name, &[(*host, grant)])
    }

    /// `removal.list`: every removal and open question.
    pub fn removal_list(&self) -> Result<Value, String> {
        self.expire_old();
        let file = self.admin().load()?;
        let asks: Vec<Value> = file
            .intents
            .iter()
            .flat_map(|i| {
                i.asks.iter().map(move |(host, grant)| {
                    json!({"identity": i.removed, "name": i.name, "host": host, "grant": grant})
                })
            })
            .collect();
        Ok(json!({
            "removals": file.items.iter().map(item_json).collect::<Vec<_>>(),
            "asks": asks,
        }))
    }

    /// Items past `MOUSSE_NET_REMOVAL_MAX_AGE_SECS` are dropped: "Couldn't
    /// remove from <host>; remove it there".
    fn expire_old(&self) {
        let now = self.clock.now().secs();
        let max_age = helper().removal_max_age_secs();
        let _admin = self.admin_lock.lock().unwrap_or_else(|e| e.into_inner());
        let store = self.admin();
        let Ok(mut file) = store.load() else {
            return;
        };
        let mut events = Vec::new();
        for item in &mut file.items {
            if open_state(&item.state) && item.issued_at.saturating_add(max_age) < now {
                item.state = "expired".into();
                events.push(item_json(item));
            }
        }
        if !events.is_empty() && store.save(&file).is_ok() {
            for mut e in events {
                e["ev"] = json!("removal.state");
                self.event(e);
            }
        }
    }

    /// Update one item and tell the app.
    pub(super) fn set_item_state(
        &self,
        id: &str,
        state: &str,
        result: Option<RemovalResult>,
        message: Option<String>,
    ) {
        let _admin = self.admin_lock.lock().unwrap_or_else(|e| e.into_inner());
        let store = self.admin();
        let Ok(mut file) = store.load() else {
            return;
        };
        let Some(item) = file.items.iter_mut().find(|i| i.id == id) else {
            return;
        };
        if !open_state(&item.state) {
            return;
        }
        item.state = state.into();
        item.result = result.map(|r| r.name().into());
        if message.is_some() {
            item.message = message;
        }
        let mut event = item_json(item);
        if store.save(&file).is_ok() {
            event["ev"] = json!("removal.state");
            self.event(event);
        }
    }

    /// Every open removal, oldest first.
    pub(super) fn all_open_items(&self) -> Vec<Item> {
        self.expire_old();
        self.admin()
            .load()
            .map(|f| {
                f.items
                    .into_iter()
                    .filter(|i| open_state(&i.state))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// After the mailbox and directory are in line with the grants: the
    /// cleanup of every applied removal whose grant is gone is done.
    pub(super) fn cleanup_after_sync(&self) {
        let Ok(entries) = self.removal.removals().load() else {
            return;
        };
        let grants = self.host.grants();
        for e in entries.iter().filter(|e| e.cleanup) {
            if e.grant.is_some_and(|g| grants.iter().all(|x| x.id.0 != g)) {
                let _ = self.removal.cleanup_done(&e.id);
            }
        }
    }

    /// Open removals for `host`, oldest first.
    pub(super) fn open_items(&self, host: &IdentityPublicKey) -> Vec<Item> {
        let host_hex = hex(host.as_bytes());
        self.admin()
            .load()
            .map(|f| {
                f.items
                    .into_iter()
                    .filter(|i| i.host == host_hex && open_state(&i.state))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn wake_delivery(self: &Arc<Self>, item: &Item) {
        let Ok(host) = identity_from_hex(&item.host) else {
            return;
        };
        for conn in self.outbound_conns(&host) {
            tokio::spawn(deliver(self.clone(), conn));
        }
        self.mail_kick();
    }
}

/// A grant list arrived on the outbound connection `conn`'s `mousse-grants`
/// stream: keep each one.
pub async fn receive_grants(engine: Arc<Engine>, conn: Arc<Connection>, stream: MuxStream) {
    let host = *conn.peer();
    let (reader, writer) = stream.split();
    let mut reader = MessageReader::new(reader);
    loop {
        match reader.next().await {
            Ok(Some(message)) => match GrantList::decode(&message) {
                Ok(list) => engine.on_grant_list(&host, &list),
                Err(_) => {
                    writer.reset(ErrorCode::ProtocolError);
                    return;
                }
            },
            Ok(None) | Err(_) => return,
        }
    }
}

/// Send every open removal for the host of the outbound connection `conn`
/// on `mousse-removal`, one stream each, and record each answer. One
/// delivery runs per host at a time.
pub async fn deliver(engine: Arc<Engine>, conn: Arc<Connection>) {
    if conn.minor().unwrap_or(0) < REMOVAL_MIN_MINOR {
        return;
    }
    let host = *conn.peer();
    let Some(_turn) = engine.delivery_turn(host) else {
        return;
    };
    engine.expire_old();
    let wait = ms(helper().removal_answer_wait_ms());
    for item in engine.open_items(&host) {
        let Ok(envelope) = unhex(&item.envelope) else {
            continue;
        };
        let Ok(stream) = conn
            .open_stream(PriorityClass::Interactive, REMOVAL_LABEL)
            .await
        else {
            return;
        };
        let (reader, writer) = stream.split();
        if stream::write(&writer, &envelope).await.is_err() {
            return;
        }
        writer.finish();
        let mut reader = MessageReader::new(reader);
        let answer = match reader.next_within(wait).await {
            Ok(Some(bytes)) => RemovalAnswer::decode(&bytes).ok(),
            _ => None,
        };
        match answer {
            Some(a) if hex(&a.id.0) == item.id => {
                applog::line(format!(
                    "removal on {}: {}",
                    short_id(&host),
                    a.result.name()
                ));
                engine.set_item_state(&item.id, "done", Some(a.result), None);
            }
            // No answer, or not for this removal: it stays open and is sent
            // again on the next session.
            _ => return,
        }
    }
}

impl Engine {
    /// Decide a signed removal that arrived on a session or by mail, and
    /// the answer to send.
    pub fn apply_removal(&self, envelope: &[u8]) -> Result<RemovalAnswer, ApplyError> {
        let signed =
            SignedRemoval::decode(envelope).map_err(|e| ApplyError::NotARemoval(e.to_string()))?;
        let result = self
            .removal
            .apply_signed(
                &signed,
                self.clock.now().secs(),
                helper().removal_max_age_secs(),
                crate::limits::get().net.core().clock_skew_secs(),
            )
            .map_err(ApplyError::NotNow)?;
        applog::line(format!(
            "removal of {} by {}: {}",
            short_id(&signed.removal().removed),
            short_id(&signed.removal().signer),
            result.name()
        ));
        Ok(RemovalAnswer {
            id: signed.removal().id,
            result,
        })
    }
}

/// Why a removal was not decided.
#[derive(Debug)]
pub enum ApplyError {
    /// Not a signed removal at all: nothing to keep it for.
    NotARemoval(String),
    /// A removal the host could not decide now (networking paused, the
    /// journal not written, not serving): it stays to be tried again, and
    /// a mailed one is not acknowledged.
    NotNow(String),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::NotARemoval(e) => write!(f, "not a removal: {e}"),
            ApplyError::NotNow(e) => write!(f, "not decided now: {e}"),
        }
    }
}
