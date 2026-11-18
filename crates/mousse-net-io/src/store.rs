//! Local state files: the host's grant table, the caller's paired hosts and
//! the joiner's flow records.
//!
//! Every write goes to a temporary file in the same directory, is flushed to
//! disk, then renamed over the old file, so a crash leaves either the old or
//! the new contents. On Unix the files are readable by the owner only.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
    let dir = path
        .parent()
        .ok_or_else(|| NetError::Store(format!("{} has no parent", path.display())))?;
    fs::create_dir_all(dir).map_err(|e| store_err(dir, e))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| NetError::Store(format!("bad file name {}", path.display())))?;
    let tmp = dir.join(format!(".{name}.tmp-{}", hex(&random_bytes::<6>())));
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
        crate::private::replace_durably(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(|e| store_err(path, e))
}

fn store_err(path: &Path, e: std::io::Error) -> NetError {
    NetError::Store(format!("{}: {e}", path.display()))
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

/// The host's grant table on disk.
#[derive(Clone, Debug)]
pub struct GrantStore {
    path: PathBuf,
}

impl GrantStore {
    /// `grants.json` in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join("grants.json"),
        }
    }

    /// The file path.
    pub fn path(&self) -> &Path {
        &self.path
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
        GrantTable::restore(grants, denials, file.next_grant_id)
            .map_err(|e| NetError::Store(format!("{}: {e}", self.path.display())))
    }

    /// Save the table atomically.
    pub fn save(&self, table: &GrantTable) -> Result<(), NetError> {
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
        let bytes =
            serde_json::to_vec_pretty(&file).map_err(|e| store_err(&self.path, e.into()))?;
        write_atomic(&self.path, &bytes)
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
    /// Route hints from the ticket.
    pub routes: Vec<String>,
    /// The route that last worked.
    pub last_route: Option<String>,
    /// When pairing finished (local clock).
    pub paired_at: u64,
}

impl PeerRecord {
    /// The pinned identity.
    pub fn pin(&self) -> Result<IdentityPublicKey, NetError> {
        identity_from_hex(&self.identity)
    }

    /// Routes to try, the last working one first.
    pub fn routes_to_try(&self) -> Vec<String> {
        let mut out: Vec<String> = self.last_route.iter().cloned().collect();
        for r in &self.routes {
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

/// The caller's paired hosts on disk.
#[derive(Clone, Debug)]
pub struct PeerStore {
    path: PathBuf,
}

impl PeerStore {
    /// `peers.json` in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join("peers.json"),
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

    /// Insert or replace (by identity) one host.
    pub fn upsert(&self, record: PeerRecord) -> Result<(), NetError> {
        let mut peers = self.load()?;
        peers.retain(|p| p.identity != record.identity);
        peers.push(record);
        self.save(peers)
    }

    /// Replace the whole list.
    pub fn save(&self, peers: Vec<PeerRecord>) -> Result<(), NetError> {
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
}

fn changed_under_us() -> NetError {
    NetError::Store("another pairing with the same link changed its record first".into())
}

/// Flow records kept in memory, for as long as the process runs.
#[derive(Debug, Default)]
pub struct MemoryFlowRecords(Mutex<HashMap<[u8; 32], JoinerRecord>>);

impl FlowRecords for MemoryFlowRecords {
    fn load(&self, ticket_hash: &[u8; 32]) -> Result<Option<JoinerRecord>, NetError> {
        let map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Ok(map.get(ticket_hash).copied())
    }

    fn swap(&self, expected: Option<&JoinerRecord>, record: &JoinerRecord) -> Result<(), NetError> {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if map.get(&record.ticket_hash) != expected {
            return Err(changed_under_us());
        }
        map.insert(record.ticket_hash, *record);
        Ok(())
    }
}

/// Flow records on disk: one canonical CBOR file per ticket hash in a
/// `joins` folder that only the owner can read, each written atomically.
/// A swap holds an exclusive lock on `joins/flows.lock` while it reads,
/// compares and writes, so flows in this process and in other processes on
/// the same endpoint state take turns.
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
        if !self.dir.exists() {
            crate::private::make_private_dir(&self.dir).map_err(|e| store_err(&self.dir, e))?;
        }
        let lock_path = self.dir.join("flows.lock");
        let lock = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| store_err(&lock_path, e))?;
        lock.lock().map_err(|e| store_err(&lock_path, e))?;
        if self.load(&record.ticket_hash)?.as_ref() != expected {
            return Err(changed_under_us());
        }
        write_atomic(&self.path(&record.ticket_hash), &record.to_bytes())
        // The lock goes with `lock`.
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
