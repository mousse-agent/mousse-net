//! Local state files: the host's grant table, the caller's paired hosts and
//! the joiner's flow records.
//!
//! Every write goes to a temporary file in the same directory, is flushed to
//! disk, then renamed over the old file, so a crash leaves either the old or
//! the new contents. On Unix the files are readable by the owner only.
//!
//! Files that several processes on one endpoint update (`peers.json`, the
//! joiner's flow records) are read, changed and written under an OS file
//! lock, which the OS releases when the process holding it dies.
//!
//! An enrollment is recorded as pending (`grants-pending.json`) before the
//! grant table that holds it replaces the old one, and the record is
//! cleared only once that table is saved. Loading the table drops every
//! grant still recorded as pending, so an enrollment the host reported as
//! failed is never honored after a restart, whatever step failed.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mousse_net_core::grants::{Denial, Grant, GrantId, GrantSource, GrantTable, OwnerRef, Role};
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::pairing::{InvitationId, JoinerRecord};
use mousse_net_core::UnixTime;
use serde::{Deserialize, Serialize};

use crate::error::NetError;
use crate::rng::random_bytes;

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    out
}

/// The grants file format. Version 2 added `next_grant_id`.
const GRANT_FILE_VERSION: u32 = 2;

/// A 16-byte owner (profile id) from hex.
pub fn owner_from_hex(text: &str) -> Option<OwnerRef> {
    let bytes: [u8; OwnerRef::LEN] = unhex(text).ok()?.try_into().ok()?;
    Some(OwnerRef::from_bytes(bytes))
}

/// Parse lowercase or uppercase hex.
pub fn unhex(text: &str) -> Result<Vec<u8>, NetError> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(NetError::Store("odd-length hex".into()));
    }
    let digit = |c: u8| -> Result<u8, NetError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(NetError::Store("bad hex digit".into())),
        }
    };
    bytes
        .chunks(2)
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

/// Parse a hex identity key.
pub fn identity_from_hex(text: &str) -> Result<IdentityPublicKey, NetError> {
    IdentityPublicKey::from_sec1(&unhex(text)?).map_err(|e| NetError::Store(e.to_string()))
}

/// A short display form of an identity: the first 8 bytes of its fingerprint.
pub fn short_id(identity: &IdentityPublicKey) -> String {
    hex(&identity.fingerprint()[..8])
}

/// Write `bytes` to `path` atomically (temp file, flush, rename).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), NetError> {
    write_atomic_checked(path, bytes).map_err(|f| f.error)
}

/// A failed [`write_atomic_checked`].
#[derive(Debug)]
pub struct WriteFailure {
    /// What failed.
    pub error: NetError,
    /// The rename was made and only making it durable failed: the new
    /// content is at the path now and may or may not survive a power loss.
    /// Otherwise the file is as it was.
    pub in_place: bool,
}

/// [`write_atomic`], telling a failure that left the file as it was from
/// one after the rename, whose outcome is not known.
pub fn write_atomic_checked(path: &Path, bytes: &[u8]) -> Result<(), WriteFailure> {
    let failed = |error| WriteFailure {
        error,
        in_place: false,
    };
    let dir = path
        .parent()
        .ok_or_else(|| failed(NetError::Store(format!("{} has no parent", path.display()))))?;
    fs::create_dir_all(dir).map_err(|e| failed(store_err(dir, e)))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| failed(NetError::Store(format!("bad file name {}", path.display()))))?;
    let tmp = dir.join(format!(".{name}.tmp-{}", hex(&random_bytes::<6>())));
    let mut renaming = false;
    let result = (|| -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        // Owner-only before any byte is written, wherever the folder is.
        crate::private::restrict_file(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        renaming = true;
        crate::private::replace_durably(&tmp, path)
    })();
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            // The temporary file is gone only if the rename was made.
            let in_place = renaming && !tmp.exists();
            if !in_place {
                let _ = fs::remove_file(&tmp);
            }
            Err(WriteFailure {
                error: store_err(path, e),
                in_place,
            })
        }
    }
}

fn store_err(path: &Path, e: std::io::Error) -> NetError {
    NetError::Store(format!("{}: {e}", path.display()))
}

/// Open (creating it if needed) the lock file at `path`.
fn open_lock(path: &Path) -> Result<File, NetError> {
    File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .map_err(|e| store_err(path, e))
}

/// Hold the lock file at `path`, waiting for any other holder.
fn hold_lock(path: &Path) -> Result<File, NetError> {
    let file = open_lock(path)?;
    file.lock().map_err(|e| store_err(path, e))?;
    Ok(file)
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, NetError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(store_err(path, e)),
    }
}

#[derive(Serialize, Deserialize)]
struct GrantRecord {
    id: u64,
    identity: String,
    name: String,
    role: String,
    source: String,
    authorizing_owner: String,
    granted_at: u64,
    expires_at: Option<u64>,
    /// The enrollment receipt: the hex id of the invitation whose pairing
    /// made this grant (wire.md 7). Absent for a grant made another way,
    /// and in files written before receipts were kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    enrolled_by: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct DenialRecord {
    identity: String,
    denied_at: u64,
}

#[derive(Serialize, Deserialize)]
struct GrantFile {
    version: u32,
    /// Grant ids are never reused: the next id survives restarts even when
    /// the grant that last used an id was removed.
    next_grant_id: u64,
    grants: Vec<GrantRecord>,
    denials: Vec<DenialRecord>,
}

/// An enrollment saved in the grant table and not yet committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingEnrollment {
    /// The new grant.
    pub grant: GrantId,
    /// The enrolled device.
    pub identity: IdentityPublicKey,
    /// The invitation that enrolled it.
    pub invitation: InvitationId,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PendingRecord {
    grant: u64,
    identity: String,
    invitation: String,
}

impl PendingRecord {
    fn of(e: &PendingEnrollment) -> Self {
        Self {
            grant: e.grant.0,
            identity: hex(e.identity.as_bytes()),
            invitation: hex(&e.invitation.0),
        }
    }

    /// Whether `grant` is the one this enrollment made.
    fn made(&self, grant: &Grant) -> bool {
        self.grant == grant.id.0
            && self.identity == hex(grant.identity.as_bytes())
            && grant
                .enrolled_by
                .is_some_and(|i| self.invitation == hex(&i.0))
    }
}

#[derive(Serialize, Deserialize, Default)]
struct PendingFile {
    version: u32,
    enrollments: Vec<PendingRecord>,
}

/// The host's grant table on disk, and the enrollments not yet committed.
#[derive(Clone, Debug)]
pub struct GrantStore {
    path: PathBuf,
    pending: PathBuf,
}

impl GrantStore {
    /// `grants.json` in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join("grants.json"),
            pending: dir.join("grants-pending.json"),
        }
    }

    /// The file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Where the enrollments not yet committed are recorded.
    pub fn pending_path(&self) -> &Path {
        &self.pending
    }

    fn load_pending(&self) -> Result<Vec<PendingRecord>, NetError> {
        let Some(bytes) = read_optional(&self.pending)? else {
            return Ok(Vec::new());
        };
        let file: PendingFile =
            serde_json::from_slice(&bytes).map_err(|e| store_err(&self.pending, e.into()))?;
        Ok(file.enrollments)
    }

    fn write_pending(&self, enrollments: Vec<PendingRecord>) -> Result<(), NetError> {
        let file = PendingFile {
            version: 1,
            enrollments,
        };
        let bytes =
            serde_json::to_vec_pretty(&file).map_err(|e| store_err(&self.pending, e.into()))?;
        write_atomic(&self.pending, &bytes)
    }

    /// Record `enrollments` as pending, durably, before the table that
    /// holds them is saved. Until [`GrantStore::commit_enrollments`], a
    /// load drops their grants. Earlier records stay.
    pub fn begin_enrollments(&self, enrollments: &[PendingEnrollment]) -> Result<(), NetError> {
        let mut records = self.load_pending()?;
        for e in enrollments {
            let record = PendingRecord::of(e);
            if !records.contains(&record) {
                records.push(record);
            }
        }
        self.write_pending(records)
    }

    /// The table saved last holds exactly what the host has in force: no
    /// enrollment is pending any more. Writes only if one was recorded.
    pub fn commit_enrollments(&self) -> Result<(), NetError> {
        if self.load_pending()?.is_empty() {
            return Ok(());
        }
        self.write_pending(Vec::new())
    }

    /// Load the table; a missing file is an empty table.
    pub fn load(&self) -> Result<GrantTable, NetError> {
        let Some(bytes) = read_optional(&self.path)? else {
            return Ok(GrantTable::new());
        };
        let file: GrantFile =
            serde_json::from_slice(&bytes).map_err(|e| store_err(&self.path, e.into()))?;
        if file.version != GRANT_FILE_VERSION {
            return Err(NetError::Store(format!(
                "{}: unsupported version {}",
                self.path.display(),
                file.version
            )));
        }
        let bad = |what: &str| NetError::Store(format!("{}: bad {what}", self.path.display()));
        let mut grants = Vec::with_capacity(file.grants.len());
        for g in file.grants {
            if g.source != "local" {
                return Err(bad("grant source"));
            }
            grants.push(Grant {
                id: GrantId(g.id),
                identity: identity_from_hex(&g.identity)?,
                name: g.name,
                role: Role::new(&g.role).map_err(|_| bad("role"))?,
                source: GrantSource::Local,
                authorizing_owner: owner_from_hex(&g.authorizing_owner)
                    .ok_or_else(|| bad("owner"))?,
                adopted_into: None,
                granted_at: UnixTime(g.granted_at),
                expires_at: g.expires_at.map(UnixTime),
                enrolled_by: match g.enrolled_by {
                    Some(text) => Some(InvitationId(
                        unhex(&text)
                            .ok()
                            .and_then(|b| b.try_into().ok())
                            .ok_or_else(|| bad("enrollment receipt"))?,
                    )),
                    None => None,
                },
            });
        }
        let mut denials = Vec::with_capacity(file.denials.len());
        for d in file.denials {
            denials.push(Denial {
                identity: identity_from_hex(&d.identity)?,
                denied_at: UnixTime(d.denied_at),
            });
        }
        // An enrollment saved but never committed was reported as failed:
        // its grant is not honored.
        let pending = self.load_pending()?;
        grants.retain(|g| !pending.iter().any(|p| p.made(g)));
        GrantTable::restore(grants, denials, file.next_grant_id)
            .map_err(|e| NetError::Store(format!("{}: {e}", self.path.display())))
    }

    /// Save the table atomically.
    pub fn save(&self, table: &GrantTable) -> Result<(), NetError> {
        self.save_checked(table).map_err(|f| f.error)
    }

    /// [`GrantStore::save`], telling whether a failure may have left the
    /// new table in place (see [`WriteFailure`]).
    pub fn save_checked(&self, table: &GrantTable) -> Result<(), WriteFailure> {
        let file = GrantFile {
            version: GRANT_FILE_VERSION,
            next_grant_id: table.next_grant_id(),
            grants: table
                .grants()
                .map(|g| GrantRecord {
                    id: g.id.0,
                    identity: hex(g.identity.as_bytes()),
                    name: g.name.clone(),
                    role: g.role.as_str().to_owned(),
                    source: "local".into(),
                    authorizing_owner: hex(g.authorizing_owner.as_bytes()),
                    granted_at: g.granted_at.secs(),
                    expires_at: g.expires_at.map(|t| t.secs()),
                    enrolled_by: g.enrolled_by.map(|i| hex(&i.0)),
                })
                .collect(),
            denials: table
                .denials()
                .map(|d| DenialRecord {
                    identity: hex(d.identity.as_bytes()),
                    denied_at: d.denied_at.secs(),
                })
                .collect(),
        };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| WriteFailure {
            error: store_err(&self.path, e.into()),
            in_place: false,
        })?;
        write_atomic_checked(&self.path, &bytes)
    }
}

/// A host this device paired with.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRecord {
    /// The host's display name, from `PAIRED`.
    pub name: String,
    /// The host's identity key (hex SEC1). This is the pin.
    pub identity: String,
    /// The role the host granted.
    pub role: String,
    /// Route hints from the ticket, or from the host when it paired back.
    pub routes: Vec<String>,
    /// The route that last worked.
    pub last_route: Option<String>,
    /// Addresses the owner added for this host (Phase 1a
    /// `peer.addresses.set`), tried before the hints.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    /// When pairing finished (local clock).
    pub paired_at: u64,
}

impl PeerRecord {
    /// The pinned identity.
    pub fn pin(&self) -> Result<IdentityPublicKey, NetError> {
        identity_from_hex(&self.identity)
    }

    /// Routes to try: the last working one, then the addresses the owner
    /// added, then the hints (Phase 1a §6).
    pub fn routes_to_try(&self) -> Vec<String> {
        let mut out: Vec<String> = self.last_route.iter().cloned().collect();
        for r in self.addresses.iter().chain(&self.routes) {
            if !out.contains(r) {
                out.push(r.clone());
            }
        }
        out
    }
}

#[derive(Serialize, Deserialize, Default)]
struct PeerFile {
    version: u32,
    peers: Vec<PeerRecord>,
}

/// The caller's paired hosts on disk. Every change reads, changes and
/// writes the file under an exclusive lock on `peers.lock` in the same
/// folder, so processes on one endpoint (a join storing a pin, a dial
/// noting the route that worked) never undo each other's writes.
#[derive(Clone, Debug)]
pub struct PeerStore {
    path: PathBuf,
    lock_path: PathBuf,
}

impl PeerStore {
    /// `peers.json` in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join("peers.json"),
            lock_path: dir.join("peers.lock"),
        }
    }

    /// All paired hosts.
    pub fn load(&self) -> Result<Vec<PeerRecord>, NetError> {
        let Some(bytes) = read_optional(&self.path)? else {
            return Ok(Vec::new());
        };
        let file: PeerFile =
            serde_json::from_slice(&bytes).map_err(|e| store_err(&self.path, e.into()))?;
        for p in &file.peers {
            p.pin()?;
        }
        Ok(file.peers)
    }

    /// Note that `route` reached the host pinned as `identity`: set
    /// `last_route` on its record as stored now, under the lock, and
    /// change nothing else, so a re-pair of the same host meanwhile keeps
    /// its name, role and routes. With no record for it, nothing changes.
    pub fn note_route(&self, identity: &IdentityPublicKey, route: String) -> Result<(), NetError> {
        self.update(|peers| {
            if let Some(p) = peers
                .iter_mut()
                .find(|p| p.pin().ok().as_ref() == Some(identity))
            {
                p.last_route = Some(route);
            }
        })
    }

    /// Insert or replace (by identity) one host.
    pub fn upsert(&self, record: PeerRecord) -> Result<(), NetError> {
        self.update(|peers| {
            peers.retain(|p| p.identity != record.identity);
            peers.push(record);
        })
    }

    /// Change the list with `change` and write it, all under the lock: no
    /// other writer runs between the read and the write.
    pub fn update(&self, change: impl FnOnce(&mut Vec<PeerRecord>)) -> Result<(), NetError> {
        if let Some(dir) = self.lock_path.parent() {
            fs::create_dir_all(dir).map_err(|e| store_err(dir, e))?;
        }
        let _lock = hold_lock(&self.lock_path)?;
        let mut peers = self.load()?;
        change(&mut peers);
        self.write(peers)
        // The lock goes with `_lock`.
    }

    fn write(&self, peers: Vec<PeerRecord>) -> Result<(), NetError> {
        let file = PeerFile { version: 1, peers };
        let bytes =
            serde_json::to_vec_pretty(&file).map_err(|e| store_err(&self.path, e.into()))?;
        write_atomic(&self.path, &bytes)
    }
}

/// Where a joiner keeps its flow records (wire.md 10.7): per ticket hash,
/// the code attempts left and whether an outcome is pending. Reopening a
/// link or restarting the app loads them, so neither resets the count.
pub trait FlowRecords: Send + Sync {
    /// The record kept for `ticket_hash`, if any. One that cannot be read
    /// is an error, never "none", which would reset the count.
    fn load(&self, ticket_hash: &[u8; 32]) -> Result<Option<JoinerRecord>, NetError>;
    /// Keep `record` in place of the one for its ticket hash, durably and
    /// atomically, but only if the stored record is still `expected`
    /// (`None`: no record yet). If it is not, write nothing and return an
    /// error: another flow on the same ticket wrote first, and two flows
    /// must never spend the same attempt.
    fn swap(&self, expected: Option<&JoinerRecord>, record: &JoinerRecord) -> Result<(), NetError>;
    /// Make this flow the only one on `ticket_hash` until the returned hold
    /// is dropped, or refuse at once if another flow (in this process or
    /// another) has it. A join holds it from loading the record until the
    /// outcome is settled and the pin stored; a store kept on disk must use
    /// a lock the OS releases when the holding process dies. Without it, a
    /// second flow could read the first one's pending mark and clear it
    /// before the first sent its confirmation.
    fn hold(&self, ticket_hash: &[u8; 32]) -> Result<FlowHold, NetError>;
}

/// A flow's hold on its ticket ([`FlowRecords::hold`]); released on drop.
pub struct FlowHold {
    _guard: Box<dyn Send + Sync>,
}

impl FlowHold {
    /// A hold that lasts as long as `guard` does.
    pub fn new(guard: impl Send + Sync + 'static) -> Self {
        Self {
            _guard: Box::new(guard),
        }
    }
}

impl std::fmt::Debug for FlowHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FlowHold")
    }
}

fn flow_in_progress() -> NetError {
    NetError::Refused("another pairing with this link is in progress on this device".into())
}

fn changed_under_us() -> NetError {
    NetError::Store("another pairing with the same link changed its record first".into())
}

/// Flow records kept in memory, for as long as the process runs.
#[derive(Debug, Default)]
pub struct MemoryFlowRecords {
    records: Mutex<HashMap<[u8; 32], JoinerRecord>>,
    held: Arc<Mutex<HashSet<[u8; 32]>>>,
}

/// Releases a [`MemoryFlowRecords`] hold.
struct MemoryHold {
    held: Arc<Mutex<HashSet<[u8; 32]>>>,
    ticket_hash: [u8; 32],
}

impl Drop for MemoryHold {
    fn drop(&mut self) {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.ticket_hash);
    }
}

impl FlowRecords for MemoryFlowRecords {
    fn load(&self, ticket_hash: &[u8; 32]) -> Result<Option<JoinerRecord>, NetError> {
        let map = self.records.lock().unwrap_or_else(|e| e.into_inner());
        Ok(map.get(ticket_hash).copied())
    }

    fn swap(&self, expected: Option<&JoinerRecord>, record: &JoinerRecord) -> Result<(), NetError> {
        let mut map = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if map.get(&record.ticket_hash) != expected {
            return Err(changed_under_us());
        }
        map.insert(record.ticket_hash, *record);
        Ok(())
    }

    fn hold(&self, ticket_hash: &[u8; 32]) -> Result<FlowHold, NetError> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        if !held.insert(*ticket_hash) {
            return Err(flow_in_progress());
        }
        Ok(FlowHold::new(MemoryHold {
            held: self.held.clone(),
            ticket_hash: *ticket_hash,
        }))
    }
}

/// Flow records on disk: one canonical CBOR file per ticket hash in a
/// `joins` folder that only the owner can read, each written atomically.
/// A swap holds an exclusive lock on `joins/flows.lock` while it reads,
/// compares and writes, so flows in this process and in other processes on
/// the same endpoint state take turns. A flow's hold is an exclusive lock
/// on `joins/<ticket hash>.lock`, which the OS releases if the process
/// dies.
#[derive(Clone, Debug)]
pub struct FlowRecordStore {
    dir: PathBuf,
}

impl FlowRecordStore {
    /// The `joins` folder in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            dir: dir.join("joins"),
        }
    }

    /// The file for `ticket_hash`.
    pub fn path(&self, ticket_hash: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.cbor", hex(ticket_hash)))
    }

    /// Make the folder, durably: a debit saved in a new folder must
    /// survive a power loss with it. Its parent is synced on this
    /// process's first use of the folder, whoever made it, and again after
    /// a failed sync, until one works.
    fn make_dir(&self) -> Result<(), NetError> {
        static READY: Mutex<Option<HashSet<PathBuf>>> = Mutex::new(None);
        let mut ready = READY.lock().unwrap_or_else(|e| e.into_inner());
        let ready = ready.get_or_insert_with(HashSet::new);
        if ready.contains(&self.dir) && self.dir.is_dir() {
            return Ok(());
        }
        crate::private::make_private_dir_durably(&self.dir).map_err(|e| store_err(&self.dir, e))?;
        ready.insert(self.dir.clone());
        Ok(())
    }
}

impl FlowRecords for FlowRecordStore {
    fn load(&self, ticket_hash: &[u8; 32]) -> Result<Option<JoinerRecord>, NetError> {
        let path = self.path(ticket_hash);
        let Some(bytes) = read_optional(&path)? else {
            return Ok(None);
        };
        let record = JoinerRecord::from_bytes(&bytes)
            .map_err(|e| NetError::Store(format!("{}: {e}", path.display())))?;
        if record.ticket_hash != *ticket_hash {
            return Err(NetError::Store(format!(
                "{}: the record is for another ticket",
                path.display()
            )));
        }
        Ok(Some(record))
    }

    fn swap(&self, expected: Option<&JoinerRecord>, record: &JoinerRecord) -> Result<(), NetError> {
        self.make_dir()?;
        let _lock = hold_lock(&self.dir.join("flows.lock"))?;
        if self.load(&record.ticket_hash)?.as_ref() != expected {
            return Err(changed_under_us());
        }
        write_atomic(&self.path(&record.ticket_hash), &record.to_bytes())
        // The lock goes with `_lock`.
    }

    fn hold(&self, ticket_hash: &[u8; 32]) -> Result<FlowHold, NetError> {
        self.make_dir()?;
        let path = self.dir.join(format!("{}.lock", hex(ticket_hash)));
        let file = open_lock(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(FlowHold::new(file)),
            Err(TryLockError::WouldBlock) => Err(flow_in_progress()),
            Err(TryLockError::Error(e)) => Err(store_err(&path, e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::os_rng;
    use mousse_net_core::grants::NewGrant;
    use mousse_net_core::identity::SoftwareKey;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("mousse-net-io-{tag}-{}", hex(&random_bytes::<6>())));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_flow_record_is_kept_owner_only_and_never_read_for_another_ticket() {
        let dir = temp_dir("joins");
        let store = FlowRecordStore::in_dir(&dir);
        let record = JoinerRecord {
            ticket_hash: [3; 32],
            attempts_left: 1,
            outcome_pending: true,
        };
        assert_eq!(store.load(&[3; 32]).unwrap(), None);
        store.swap(None, &record).unwrap();
        assert_eq!(store.load(&[3; 32]).unwrap(), Some(record));
        // A swap from a record that is no longer stored writes nothing.
        let spent = JoinerRecord {
            attempts_left: 0,
            ..record
        };
        assert!(store.swap(None, &spent).is_err());
        assert_eq!(store.load(&[3; 32]).unwrap(), Some(record));
        store.swap(Some(&record), &spent).unwrap();
        assert_eq!(store.load(&[3; 32]).unwrap(), Some(spent));
        assert!(crate::private::is_owner_only(&store.path(&[3; 32])).unwrap());
        assert!(crate::private::is_owner_only(&dir.join("joins")).unwrap());

        // A record filed under another ticket's name is refused, and so is
        // one that does not parse: neither reads as "no record".
        fs::copy(store.path(&[3; 32]), store.path(&[4; 32])).unwrap();
        assert!(store.load(&[4; 32]).is_err());
        fs::write(store.path(&[5; 32]), b"junk").unwrap();
        assert!(store.load(&[5; 32]).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hex_round_trips_and_rejects_junk() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(unhex("00abFF").unwrap(), vec![0x00, 0xab, 0xff]);
        assert!(unhex("0").is_err());
        assert!(unhex("zz").is_err());
    }

    #[test]
    fn grants_survive_a_save_and_load() {
        let dir = temp_dir("grants");
        let store = GrantStore::in_dir(&dir);
        assert_eq!(store.load().unwrap().grants().count(), 0);
        let mut table = GrantTable::new();
        let a = SoftwareKey::generate(&mut os_rng()).public_key();
        let b = SoftwareKey::generate(&mut os_rng()).public_key();
        let (id, _) = table
            .add(
                NewGrant {
                    identity: a,
                    name: "laptop".into(),
                    role: Role::owner(),
                    authorizing_owner: OwnerRef::from_bytes([7; 16]),
                    expires_at: Some(UnixTime(9_999)),
                    enrolled_by: Some(InvitationId([9; 16])),
                },
                UnixTime(100),
            )
            .unwrap();
        table.deny(b, UnixTime(200));
        store.save(&table).unwrap();
        let loaded = store.load().unwrap();
        let g = loaded.get(id).unwrap();
        assert_eq!(g.identity, a);
        assert_eq!(g.name, "laptop");
        assert_eq!(g.expires_at, Some(UnixTime(9_999)));
        assert_eq!(g.authorizing_owner, OwnerRef::from_bytes([7; 16]));
        assert_eq!(g.enrolled_by, Some(InvitationId([9; 16])));
        assert!(loaded.is_denied(&b));
        // No temporary files are left behind.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_removed_grant_id_is_not_reused_after_a_restart() {
        let dir = temp_dir("grant-ids");
        let store = GrantStore::in_dir(&dir);
        let new = |identity| NewGrant {
            identity,
            name: "phone".into(),
            role: Role::owner(),
            authorizing_owner: OwnerRef::from_bytes([1; 16]),
            expires_at: None,
            enrolled_by: None,
        };
        let mut table = GrantTable::new();
        let a = SoftwareKey::generate(&mut os_rng()).public_key();
        let (first, _) = table.add(new(a), UnixTime(1)).unwrap();
        table.remove(first);
        store.save(&table).unwrap();
        let mut loaded = store.load().unwrap();
        assert_eq!(loaded.grants().count(), 0);
        let b = SoftwareKey::generate(&mut os_rng()).public_key();
        let (second, _) = loaded.add(new(b), UnixTime(2)).unwrap();
        assert!(second.0 > first.0, "grant id {first:?} was reused");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_tampered_grant_file_is_refused() {
        let dir = temp_dir("tampered");
        let store = GrantStore::in_dir(&dir);
        fs::write(
            store.path(),
            br#"{"version":2,"next_grant_id":1,"grants":[{"id":0,"identity":"04ff","name":"x","role":"owner","source":"local","authorizing_owner":"o","granted_at":1,"expires_at":null}],"denials":[]}"#,
        )
        .unwrap();
        assert!(store.load().is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_flow_hold_is_exclusive_until_dropped() {
        let dir = temp_dir("holds");
        let disk = FlowRecordStore::in_dir(&dir);
        let memory = MemoryFlowRecords::default();
        let stores: [&dyn FlowRecords; 2] = [&disk, &memory];
        for store in stores {
            let first = store.hold(&[1; 32]).unwrap();
            let err = store.hold(&[1; 32]).unwrap_err();
            assert!(matches!(err, NetError::Refused(_)), "{err:?}");
            // Another ticket is not held.
            let other = store.hold(&[2; 32]).unwrap();
            drop(first);
            let again = store.hold(&[1; 32]).unwrap();
            drop((again, other));
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Writers that run at once each keep their change: none writes back a
    /// list it read before another's write.
    #[test]
    fn concurrent_peer_writers_lose_nothing() {
        let dir = temp_dir("peers-race");
        let ids: Vec<String> = (0..24)
            .map(|_| hex(SoftwareKey::generate(&mut os_rng()).public_key().as_bytes()))
            .collect();
        let start = std::sync::Barrier::new(ids.len());
        std::thread::scope(|scope| {
            for id in &ids {
                let (dir, start) = (&dir, &start);
                scope.spawn(move || {
                    // Its own store value, as another process would have.
                    let store = PeerStore::in_dir(dir);
                    start.wait();
                    store
                        .upsert(PeerRecord {
                            name: "host".into(),
                            identity: id.clone(),
                            role: "owner".into(),
                            routes: Vec::new(),
                            last_route: None,
                            addresses: Vec::new(),
                            paired_at: 1,
                        })
                        .unwrap();
                });
            }
        });
        let mut kept: Vec<String> = PeerStore::in_dir(&dir)
            .load()
            .unwrap()
            .into_iter()
            .map(|p| p.identity)
            .collect();
        kept.sort();
        let mut want = ids.clone();
        want.sort();
        assert_eq!(kept, want);
        fs::remove_dir_all(&dir).unwrap();
    }

    fn peer(id: &str, name: &str, role: &str) -> PeerRecord {
        PeerRecord {
            name: name.into(),
            identity: id.into(),
            role: role.into(),
            routes: vec!["tcp://10.0.0.2:7443".into()],
            last_route: None,
            addresses: Vec::new(),
            paired_at: 1,
        }
    }

    /// A dial that read the host's record before the host was paired
    /// again notes its route on the record as it is now: the re-pair's
    /// name and role stay, also when the two run at once.
    #[test]
    fn a_dial_never_undoes_a_re_pair_of_the_same_host() {
        let dir = temp_dir("repair-dial");
        let store = PeerStore::in_dir(&dir);
        let key = SoftwareKey::generate(&mut os_rng()).public_key();
        let id = hex(key.as_bytes());
        store.upsert(peer(&id, "old", "member")).unwrap();

        // In turn: the dial's copy is stale by the time it notes the route.
        let stale = store.load().unwrap().remove(0);
        store.upsert(peer(&id, "new", "owner")).unwrap();
        store
            .note_route(&stale.pin().unwrap(), "tcp://10.0.0.9:7443".into())
            .unwrap();
        let now = store.load().unwrap();
        assert_eq!(now.len(), 1);
        assert_eq!(
            (now[0].name.as_str(), now[0].role.as_str()),
            ("new", "owner")
        );
        assert_eq!(now[0].last_route.as_deref(), Some("tcp://10.0.0.9:7443"));

        // At once: one re-pair and several dials of the same host.
        let start = std::sync::Barrier::new(5);
        std::thread::scope(|scope| {
            let (dir, start, id) = (&dir, &start, &id);
            scope.spawn(move || {
                let store = PeerStore::in_dir(dir);
                start.wait();
                for i in 0..40 {
                    store
                        .upsert(peer(id, &format!("repair-{i}"), "owner"))
                        .unwrap();
                }
            });
            for d in 0..4 {
                scope.spawn(move || {
                    let store = PeerStore::in_dir(dir);
                    start.wait();
                    for _ in 0..40 {
                        store
                            .note_route(&key, format!("tcp://10.0.1.{d}:7443"))
                            .unwrap();
                    }
                });
            }
        });
        let now = store.load().unwrap();
        assert_eq!(now.len(), 1);
        assert_eq!(now[0].name, "repair-39");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The folder for flow records gets its parent synced on first use in
    /// a process even when another process made it, and again after a
    /// sync that failed.
    #[test]
    fn the_flow_record_folder_is_synced_on_first_use_and_after_a_failed_sync() {
        let dir = temp_dir("joins-sync");
        let store = FlowRecordStore::in_dir(&dir);
        // Made by someone else, without a sync here.
        fs::create_dir_all(dir.join("joins")).unwrap();
        crate::private::faults::fail_syncs(&dir, 1);
        let record = JoinerRecord {
            ticket_hash: [9; 32],
            attempts_left: 3,
            outcome_pending: false,
        };
        // The first use syncs, and the failed sync fails the write.
        assert!(store.swap(None, &record).is_err());
        assert_eq!(store.load(&[9; 32]).unwrap(), None);
        // The next use syncs again, and the write lands.
        store.swap(None, &record).unwrap();
        assert_eq!(store.load(&[9; 32]).unwrap(), Some(record));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A grant recorded as a pending enrollment is dropped on load until
    /// the enrollment is committed.
    #[test]
    fn a_pending_enrollment_is_not_loaded_until_committed() {
        let dir = temp_dir("pending");
        let store = GrantStore::in_dir(&dir);
        let mut table = GrantTable::new();
        let identity = SoftwareKey::generate(&mut os_rng()).public_key();
        let invitation = InvitationId([4; 16]);
        let (grant, _) = table
            .add(
                NewGrant {
                    identity,
                    name: "phone".into(),
                    role: Role::owner(),
                    authorizing_owner: OwnerRef::from_bytes([1; 16]),
                    expires_at: None,
                    enrolled_by: Some(invitation),
                },
                UnixTime(1),
            )
            .unwrap();
        store
            .begin_enrollments(&[PendingEnrollment {
                grant,
                identity,
                invitation,
            }])
            .unwrap();
        store.save(&table).unwrap();
        let loaded = store.load().unwrap();
        assert!(loaded.grants().next().is_none());
        // Its id is not given out again.
        assert_eq!(loaded.next_grant_id(), table.next_grant_id());
        store.commit_enrollments().unwrap();
        assert_eq!(store.load().unwrap().grants().count(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn peers_upsert_by_identity() {
        let dir = temp_dir("peers");
        let store = PeerStore::in_dir(&dir);
        let id = hex(SoftwareKey::generate(&mut os_rng()).public_key().as_bytes());
        let mut record = PeerRecord {
            name: "mac".into(),
            identity: id.clone(),
            role: "owner".into(),
            routes: vec!["tcp://10.0.0.2:7443".into()],
            last_route: None,
            addresses: Vec::new(),
            paired_at: 1,
        };
        store.upsert(record.clone()).unwrap();
        record.last_route = Some("tcp://10.0.0.3:7443".into());
        store.upsert(record.clone()).unwrap();
        let peers = store.load().unwrap();
        assert_eq!(peers, vec![record.clone()]);
        assert_eq!(
            record.routes_to_try(),
            vec!["tcp://10.0.0.3:7443", "tcp://10.0.0.2:7443"]
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
