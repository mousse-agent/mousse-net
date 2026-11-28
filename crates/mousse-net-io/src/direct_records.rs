//! Where a Pair with IP joiner keeps its records (wire.md 10.9, "Joiner"):
//! per typed lookup, the ledger of attempts and the lookup's hold; per typed
//! lookup and address, the pending records of codes that passed. Reopening
//! the app or starting another Connect loads them, so neither resets the
//! count nor forgets a code that passed.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mousse_net_core::pairing::{DirectAddress, DirectLedger, DirectLookup, DirectPending};

use crate::error::NetError;
use crate::store::{hex, unhex, write_atomic, FlowHold};

/// A joiner's Pair with IP records. Every write is a compare and swap: it
/// lands only if the stored record is still the one the flow last read or
/// wrote, so two flows never spend the same attempt or clear each other's
/// pending record.
pub trait DirectRecords: Send + Sync {
    /// Make this flow the only one on `lookup` until the returned hold is
    /// dropped. `None` at once when another flow (in this process or
    /// another) has it. A store kept on disk uses a lock the OS releases
    /// when the holding process dies.
    fn hold(&self, lookup: &DirectLookup) -> Result<Option<FlowHold>, NetError>;
    /// The ledger and every pending record stored under `lookup`. A record
    /// that cannot be read is an error, never "none", which would reset the
    /// count or forget a code that passed.
    fn load(
        &self,
        lookup: &DirectLookup,
    ) -> Result<(Option<DirectLedger>, Vec<DirectPending>), NetError>;
    /// Store `record` as `lookup`'s ledger if the stored one is `expected`.
    fn swap_ledger(
        &self,
        expected: Option<&DirectLedger>,
        record: &DirectLedger,
    ) -> Result<(), NetError>;
    /// Store `record` (or, with `None`, delete the record) at `lookup` and
    /// `address` if the stored one there is `expected`.
    fn swap_pending(
        &self,
        lookup: &DirectLookup,
        address: &DirectAddress,
        expected: Option<&DirectPending>,
        record: Option<&DirectPending>,
    ) -> Result<(), NetError>;
    /// Every pending record that can be read, for recovery at startup.
    fn all_pending(&self) -> Result<Vec<DirectPending>, NetError>;
}

fn changed_under_us() -> NetError {
    NetError::Store("another Pair with IP flow changed the record first".into())
}

/// Records kept in memory, for as long as the process runs.
#[derive(Debug, Default)]
pub struct MemoryDirectRecords {
    inner: Mutex<MemoryInner>,
    held: Arc<Mutex<HashSet<String>>>,
}

#[derive(Debug, Default)]
struct MemoryInner {
    ledgers: HashMap<String, DirectLedger>,
    pending: HashMap<(String, DirectAddress), DirectPending>,
}

struct MemoryHold {
    held: Arc<Mutex<HashSet<String>>>,
    lookup: String,
}

impl Drop for MemoryHold {
    fn drop(&mut self) {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.lookup);
    }
}

impl DirectRecords for MemoryDirectRecords {
    fn hold(&self, lookup: &DirectLookup) -> Result<Option<FlowHold>, NetError> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        if !held.insert(lookup.as_str().to_owned()) {
            return Ok(None);
        }
        Ok(Some(FlowHold::new(MemoryHold {
            held: self.held.clone(),
            lookup: lookup.as_str().to_owned(),
        })))
    }

    fn load(
        &self,
        lookup: &DirectLookup,
    ) -> Result<(Option<DirectLedger>, Vec<DirectPending>), NetError> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let ledger = inner.ledgers.get(lookup.as_str()).cloned();
        let mut pending: Vec<DirectPending> = inner
            .pending
            .iter()
            .filter(|((l, _), _)| l == lookup.as_str())
            .map(|(_, p)| p.clone())
            .collect();
        pending.sort_by_key(|p| p.address.to_text());
        Ok((ledger, pending))
    }

    fn swap_ledger(
        &self,
        expected: Option<&DirectLedger>,
        record: &DirectLedger,
    ) -> Result<(), NetError> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = record.lookup.as_str().to_owned();
        if inner.ledgers.get(&key) != expected {
            return Err(changed_under_us());
        }
        inner.ledgers.insert(key, record.clone());
        Ok(())
    }

    fn swap_pending(
        &self,
        lookup: &DirectLookup,
        address: &DirectAddress,
        expected: Option<&DirectPending>,
        record: Option<&DirectPending>,
    ) -> Result<(), NetError> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = (lookup.as_str().to_owned(), *address);
        if inner.pending.get(&key) != expected {
            return Err(changed_under_us());
        }
        match record {
            Some(r) => inner.pending.insert(key, r.clone()),
            None => inner.pending.remove(&key),
        };
        Ok(())
    }

    fn all_pending(&self) -> Result<Vec<DirectPending>, NetError> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Ok(inner.pending.values().cloned().collect())
    }
}

/// Records on disk, in a `direct` folder only the owner can read: the
/// ledger in `<lookup>.ledger`, each pending record in
/// `<lookup>-<address as hex>.pending`, both canonical CBOR (wire.md 10.9),
/// each written atomically. A swap holds an exclusive lock on
/// `direct/records.lock` while it reads, compares and writes; a flow's hold
/// is an exclusive lock on `direct/<lookup>.lock`, which the OS releases if
/// the process dies.
#[derive(Clone, Debug)]
pub struct DirectRecordStore {
    dir: PathBuf,
}

fn store_err(path: &Path, e: impl std::fmt::Display) -> NetError {
    NetError::Store(format!("{}: {e}", path.display()))
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, NetError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(store_err(path, e)),
    }
}

fn open_lock(path: &Path) -> Result<File, NetError> {
    File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .map_err(|e| store_err(path, e))
}

impl DirectRecordStore {
    /// The `direct` folder in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            dir: dir.join("direct"),
        }
    }

    /// The ledger file of `lookup`.
    pub fn ledger_path(&self, lookup: &DirectLookup) -> PathBuf {
        self.dir.join(format!("{}.ledger", lookup.as_str()))
    }

    /// The pending record file of `lookup` at `address`.
    pub fn pending_path(&self, lookup: &DirectLookup, address: &DirectAddress) -> PathBuf {
        self.dir.join(format!(
            "{}-{}.pending",
            lookup.as_str(),
            hex(address.to_text().as_bytes())
        ))
    }

    fn make_dir(&self) -> Result<(), NetError> {
        crate::private::make_private_dir_durably(&self.dir).map_err(|e| store_err(&self.dir, e))
    }

    fn read_ledger(&self, lookup: &DirectLookup) -> Result<Option<DirectLedger>, NetError> {
        let path = self.ledger_path(lookup);
        let Some(bytes) = read_optional(&path)? else {
            return Ok(None);
        };
        let ledger = DirectLedger::from_bytes(&bytes).map_err(|e| store_err(&path, e))?;
        if ledger.lookup != *lookup {
            return Err(store_err(&path, "the record is for another lookup"));
        }
        Ok(Some(ledger))
    }

    fn read_pending(
        &self,
        lookup: &DirectLookup,
        address: &DirectAddress,
    ) -> Result<Option<DirectPending>, NetError> {
        let path = self.pending_path(lookup, address);
        let Some(bytes) = read_optional(&path)? else {
            return Ok(None);
        };
        let pending = DirectPending::from_bytes(&bytes).map_err(|e| store_err(&path, e))?;
        if pending.lookup != *lookup || pending.address != *address {
            return Err(store_err(
                &path,
                "the record is for another lookup or address",
            ));
        }
        Ok(Some(pending))
    }

    /// The pending records' (lookup, address) by file name, `lookup` only
    /// when given.
    fn pending_names(
        &self,
        lookup: Option<&DirectLookup>,
    ) -> Result<Vec<(DirectLookup, DirectAddress)>, NetError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(store_err(&self.dir, e)),
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".pending")) else {
                continue;
            };
            let Some((l, a)) = stem.split_once('-') else {
                continue;
            };
            let Some(l) = DirectLookup::from_canonical(l) else {
                continue;
            };
            if lookup.is_some_and(|want| *want != l) {
                continue;
            }
            let address = unhex(a)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .and_then(|t| DirectAddress::parse(&t).filter(|p| p.to_text() == t));
            match address {
                Some(address) => out.push((l, address)),
                // A pending record whose name does not read is never
                // skipped silently: it may hold a code that passed.
                None => return Err(store_err(&entry.path(), "not a pending record's name")),
            }
        }
        out.sort_by_key(|(l, a)| (l.as_str().to_owned(), a.to_text()));
        Ok(out)
    }
}

impl DirectRecords for DirectRecordStore {
    fn hold(&self, lookup: &DirectLookup) -> Result<Option<FlowHold>, NetError> {
        self.make_dir()?;
        let path = self.dir.join(format!("{}.lock", lookup.as_str()));
        let file = open_lock(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(FlowHold::new(file))),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(e)) => Err(store_err(&path, e)),
        }
    }

    fn load(
        &self,
        lookup: &DirectLookup,
    ) -> Result<(Option<DirectLedger>, Vec<DirectPending>), NetError> {
        let ledger = self.read_ledger(lookup)?;
        let mut pending = Vec::new();
        for (l, address) in self.pending_names(Some(lookup))? {
            if let Some(p) = self.read_pending(&l, &address)? {
                pending.push(p);
            }
        }
        Ok((ledger, pending))
    }

    fn swap_ledger(
        &self,
        expected: Option<&DirectLedger>,
        record: &DirectLedger,
    ) -> Result<(), NetError> {
        self.make_dir()?;
        let lock_path = self.dir.join("records.lock");
        let lock = open_lock(&lock_path)?;
        lock.lock().map_err(|e| store_err(&lock_path, e))?;
        if self.read_ledger(&record.lookup)?.as_ref() != expected {
            return Err(changed_under_us());
        }
        write_atomic(&self.ledger_path(&record.lookup), &record.to_bytes())
    }

    fn swap_pending(
        &self,
        lookup: &DirectLookup,
        address: &DirectAddress,
        expected: Option<&DirectPending>,
        record: Option<&DirectPending>,
    ) -> Result<(), NetError> {
        self.make_dir()?;
        let lock_path = self.dir.join("records.lock");
        let lock = open_lock(&lock_path)?;
        lock.lock().map_err(|e| store_err(&lock_path, e))?;
        if self.read_pending(lookup, address)?.as_ref() != expected {
            return Err(changed_under_us());
        }
        let path = self.pending_path(lookup, address);
        match record {
            Some(r) => write_atomic(&path, &r.to_bytes()),
            None => match fs::remove_file(&path) {
                Ok(()) => crate::private::sync_dir(&self.dir).map_err(|e| store_err(&self.dir, e)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(store_err(&path, e)),
            },
        }
    }

    fn all_pending(&self) -> Result<Vec<DirectPending>, NetError> {
        let mut out = Vec::new();
        for (l, address) in self.pending_names(None)? {
            if let Some(p) = self.read_pending(&l, &address)? {
                out.push(p);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::os_rng;
    use mousse_net_core::identity::{IdentityPublicKey, SoftwareKey};
    use mousse_net_core::pairing::{AttemptId, InvitationId};
    use mousse_net_core::UnixTime;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mousse-net-io-{tag}-{}",
            hex(&crate::rng::random_bytes::<6>())
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn key() -> IdentityPublicKey {
        SoftwareKey::generate(&mut os_rng()).public_key()
    }

    fn pending(lookup: &DirectLookup, address: &str) -> DirectPending {
        DirectPending {
            lookup: lookup.clone(),
            host: key(),
            invitation: InvitationId([7; 16]),
            address: DirectAddress::parse(address).unwrap(),
            verified_at: UnixTime(1_790_000_000),
            cancelled: false,
            attempt: AttemptId([5; 16]),
        }
    }

    fn stores() -> Vec<(Box<dyn DirectRecords>, Option<PathBuf>)> {
        let dir = temp_dir("direct");
        vec![
            (Box::new(MemoryDirectRecords::default()), None),
            (Box::new(DirectRecordStore::in_dir(&dir)), Some(dir)),
        ]
    }

    /// Both stores: one ledger per lookup and one pending record per lookup
    /// and address, each written only over the record the writer read.
    #[test]
    fn records_are_kept_per_lookup_and_address_and_swapped_only_over_what_was_read() {
        let k7qm = DirectLookup::from_canonical("K7QM").unwrap();
        let other = DirectLookup::from_canonical("ABCD").unwrap();
        for (store, dir) in stores() {
            assert_eq!(store.load(&k7qm).unwrap(), (None, Vec::new()));
            let ledger = DirectLedger {
                lookup: k7qm.clone(),
                attempts_left: 4,
                first_debit: UnixTime(1_790_000_000),
            };
            store.swap_ledger(None, &ledger).unwrap();
            let spent = DirectLedger {
                attempts_left: 3,
                ..ledger.clone()
            };
            // Over a record that is no longer stored: nothing is written.
            assert!(store.swap_ledger(None, &spent).is_err());
            store.swap_ledger(Some(&ledger), &spent).unwrap();

            let a = pending(&k7qm, "192.168.1.20:47100");
            let b = pending(&k7qm, "[fe80::1]:47100");
            let c = pending(&other, "192.168.1.20:47100");
            store
                .swap_pending(&k7qm, &a.address, None, Some(&a))
                .unwrap();
            store
                .swap_pending(&k7qm, &b.address, None, Some(&b))
                .unwrap();
            store
                .swap_pending(&other, &c.address, None, Some(&c))
                .unwrap();
            // Another address's record is never what a write replaces.
            assert!(store
                .swap_pending(&k7qm, &a.address, Some(&b), None)
                .is_err());
            let (l, p) = store.load(&k7qm).unwrap();
            assert_eq!(l, Some(spent));
            assert_eq!(p.len(), 2);
            assert!(p.contains(&a) && p.contains(&b));
            store
                .swap_pending(&k7qm, &a.address, Some(&a), None)
                .unwrap();
            assert_eq!(store.load(&k7qm).unwrap().1, vec![b.clone()]);
            let mut all = store.all_pending().unwrap();
            all.sort_by_key(|p| p.lookup.as_str().to_owned());
            assert_eq!(all, vec![c, b]);
            if let Some(dir) = dir {
                assert!(crate::private::is_owner_only(&dir.join("direct")).unwrap());
                fs::remove_dir_all(&dir).unwrap();
            }
        }
    }

    /// The hold: one flow per lookup, given back when dropped.
    #[test]
    fn one_flow_holds_a_lookup() {
        let k7qm = DirectLookup::from_canonical("K7QM").unwrap();
        let other = DirectLookup::from_canonical("ABCD").unwrap();
        for (store, dir) in stores() {
            let held = store.hold(&k7qm).unwrap().expect("free");
            assert!(store.hold(&k7qm).unwrap().is_none());
            assert!(store.hold(&other).unwrap().is_some());
            drop(held);
            assert!(store.hold(&k7qm).unwrap().is_some());
            if let Some(dir) = dir {
                fs::remove_dir_all(&dir).unwrap();
            }
        }
    }

    /// A record that does not read, or is filed under another lookup or
    /// address, is an error, never "no record".
    #[test]
    fn a_damaged_or_misfiled_record_is_an_error() {
        let k7qm = DirectLookup::from_canonical("K7QM").unwrap();
        let dir = temp_dir("direct-bad");
        let store = DirectRecordStore::in_dir(&dir);
        let a = pending(&k7qm, "192.168.1.20:47100");
        store
            .swap_pending(&k7qm, &a.address, None, Some(&a))
            .unwrap();
        let elsewhere = DirectAddress::parse("192.168.1.21:47100").unwrap();
        fs::copy(
            store.pending_path(&k7qm, &a.address),
            store.pending_path(&k7qm, &elsewhere),
        )
        .unwrap();
        assert!(store.load(&k7qm).is_err());
        fs::write(store.pending_path(&k7qm, &elsewhere), b"junk").unwrap();
        assert!(store.load(&k7qm).is_err());
        fs::remove_file(store.pending_path(&k7qm, &elsewhere)).unwrap();
        fs::write(store.ledger_path(&k7qm), b"junk").unwrap();
        assert!(store.load(&k7qm).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
