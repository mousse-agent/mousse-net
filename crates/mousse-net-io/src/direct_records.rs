//! Where a Pair with IP joiner keeps its records (wire.md 10.9, "Joiner"):
//! per typed lookup, the ledger of attempts and the lookup's hold; per typed
//! lookup and address, the pending records of codes that passed. Reopening
//! the app or starting another Connect loads them, so neither resets the
//! count nor forgets a code that passed.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mousse_net_core::pairing::{
    AttemptId, DirectAddress, DirectLedger, DirectLookup, DirectPending,
};

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
    /// `lookup`'s ledger and the pending record at `lookup` and `address`.
    /// A record that cannot be read is an error, never "none", which would
    /// reset the count or forget a code that passed. Only these two are
    /// read: a damaged record at another address stops only its own flow.
    fn load(
        &self,
        lookup: &DirectLookup,
        address: &DirectAddress,
    ) -> Result<(Option<DirectLedger>, Option<DirectPending>), NetError>;
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
    /// Where pending records are kept, for recovery at startup: their
    /// lookup and address, and the attempt each was written by if it reads.
    /// Each flow loads and checks its own record under its lookup's hold,
    /// so a damaged record stops only its own flow. A kept file whose name
    /// is not a pending record's is listed as unreadable, never skipped.
    /// Leftovers of an interrupted delete are removed.
    fn pending_slots(&self) -> Result<PendingSlots, NetError>;
}

/// The pending records found at startup ([`DirectRecords::pending_slots`]).
#[derive(Debug, Default)]
pub struct PendingSlots {
    /// One per kept record.
    pub slots: Vec<PendingSlot>,
    /// Files kept as pending records whose names do not read: each may hold
    /// a code that passed, so each is reported.
    pub unreadable: Vec<NetError>,
}

/// A pending record found at startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSlot {
    /// The typed lookup it is kept under.
    pub lookup: DirectLookup,
    /// The typed address it is kept at.
    pub address: DirectAddress,
    /// The attempt that wrote it, or `None` when the record did not read
    /// (damaged, or the read failed): its recovery then reports the error
    /// and keeps the record, and never takes it as settled. A recovery
    /// takes only this attempt's record: one written later at the same
    /// lookup and address belongs to the flow that wrote it.
    pub attempt: Option<AttemptId>,
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
        address: &DirectAddress,
    ) -> Result<(Option<DirectLedger>, Option<DirectPending>), NetError> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let ledger = inner.ledgers.get(lookup.as_str()).cloned();
        let pending = inner
            .pending
            .get(&(lookup.as_str().to_owned(), *address))
            .cloned();
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

    fn pending_slots(&self) -> Result<PendingSlots, NetError> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut slots: Vec<PendingSlot> = inner
            .pending
            .values()
            .map(|p| PendingSlot {
                lookup: p.lookup.clone(),
                address: p.address,
                attempt: Some(p.attempt),
            })
            .collect();
        slots.sort_by_key(|s| (s.lookup.as_str().to_owned(), s.address.to_text()));
        Ok(PendingSlots {
            slots,
            unreadable: Vec::new(),
        })
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

    /// The lookup and address a pending record's file name says.
    fn read_name(stem: &str) -> Option<(DirectLookup, DirectAddress)> {
        let (l, a) = stem.split_once('-')?;
        let lookup = DirectLookup::from_canonical(l)?;
        let text = String::from_utf8(unhex(a).ok()?).ok()?;
        let address = DirectAddress::parse(&text).filter(|p| p.to_text() == text)?;
        Some((lookup, address))
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
        address: &DirectAddress,
    ) -> Result<(Option<DirectLedger>, Option<DirectPending>), NetError> {
        Ok((
            self.read_ledger(lookup)?,
            self.read_pending(lookup, address)?,
        ))
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
        match (record, expected) {
            (Some(r), _) => write_atomic(&path, &r.to_bytes()),
            (None, None) => Ok(()),
            // Deleting is a durable move out of the `.pending` names (on
            // Windows a write-through move; elsewhere a rename and a folder
            // sync), so a power loss cannot bring back a record already
            // reported gone. The moved file is removed after.
            (None, Some(_)) => {
                let gone = path.with_extension("gone");
                crate::private::replace_durably(&path, &gone).map_err(|e| store_err(&path, e))?;
                let _ = fs::remove_file(&gone);
                Ok(())
            }
        }
    }

    fn pending_slots(&self) -> Result<PendingSlots, NetError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PendingSlots::default())
            }
            Err(e) => return Err(store_err(&self.dir, e)),
        };
        let mut out = PendingSlots::default();
        for entry in entries {
            let entry = entry.map_err(|e| store_err(&self.dir, e))?;
            let path = entry.path();
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            // A delete that stopped after its durable move: the record is
            // already gone.
            if name.ends_with(".gone") {
                let _ = fs::remove_file(&path);
                continue;
            }
            let Some(stem) = name.strip_suffix(".pending") else {
                continue;
            };
            let Some((lookup, address)) = Self::read_name(stem) else {
                out.unreadable
                    .push(store_err(&path, "not a pending record's name"));
                continue;
            };
            let attempt = match fs::read(&path) {
                Ok(bytes) => DirectPending::from_bytes(&bytes)
                    .ok()
                    .filter(|p| p.lookup == lookup && p.address == address)
                    .map(|p| p.attempt),
                // Gone since the listing: settled by another flow.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => None,
            };
            out.slots.push(PendingSlot {
                lookup,
                address,
                attempt,
            });
        }
        out.slots
            .sort_by_key(|s| (s.lookup.as_str().to_owned(), s.address.to_text()));
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
            let (at_a, at_b) = (
                DirectAddress::parse("192.168.1.20:47100").unwrap(),
                DirectAddress::parse("[fe80::1]:47100").unwrap(),
            );
            assert_eq!(store.load(&k7qm, &at_a).unwrap(), (None, None));
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
            assert_eq!(
                store.load(&k7qm, &at_a).unwrap(),
                (Some(spent.clone()), Some(a.clone()))
            );
            assert_eq!(store.load(&k7qm, &at_b).unwrap().1, Some(b.clone()));
            store
                .swap_pending(&k7qm, &a.address, Some(&a), None)
                .unwrap();
            assert_eq!(store.load(&k7qm, &at_a).unwrap(), (Some(spent), None));
            let slot = |p: &DirectPending| PendingSlot {
                lookup: p.lookup.clone(),
                address: p.address,
                attempt: Some(p.attempt),
            };
            assert_eq!(
                store.pending_slots().unwrap().slots,
                vec![slot(&c), slot(&b)]
            );
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

    /// The hold is the OS's: a lookup another process holds is refused
    /// here, another lookup is not, and the hold goes when that process
    /// dies.
    #[test]
    fn a_lookup_held_by_another_process_is_refused_until_that_process_dies() {
        let k7qm = DirectLookup::from_canonical("K7QM").unwrap();
        let other = DirectLookup::from_canonical("ABCD").unwrap();
        let dir = temp_dir("direct-hold");
        let ready = dir.join("ready");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "direct_records::tests::hold_in_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("MOUSSE_TEST_HOLD_DIR", &dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        while !ready.exists() {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(60),
                "the child never took the hold"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let store = DirectRecordStore::in_dir(&dir);
        assert!(store.hold(&k7qm).unwrap().is_none());
        assert!(store.hold(&other).unwrap().is_some());
        child.kill().unwrap();
        child.wait().unwrap();
        let start = std::time::Instant::now();
        loop {
            if store.hold(&k7qm).unwrap().is_some() {
                break;
            }
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "the hold outlived its process"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The other process of the test above: holds K7QM and waits to be
    /// killed. Does nothing when run on its own.
    #[test]
    #[ignore = "run by a_lookup_held_by_another_process_is_refused_until_that_process_dies"]
    fn hold_in_child() {
        let Some(dir) = std::env::var_os("MOUSSE_TEST_HOLD_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir);
        let store = DirectRecordStore::in_dir(&dir);
        let k7qm = DirectLookup::from_canonical("K7QM").unwrap();
        let _held = store.hold(&k7qm).unwrap().expect("free");
        fs::write(dir.join("ready"), b"").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(120));
    }

    /// Deleting a pending record is a durable move: when the move fails the
    /// record is still there and the delete is not reported done.
    #[test]
    fn a_pending_record_is_deleted_only_by_a_durable_move() {
        let k7qm = DirectLookup::from_canonical("K7QM").unwrap();
        let dir = temp_dir("direct-delete");
        let store = DirectRecordStore::in_dir(&dir);
        let a = pending(&k7qm, "192.168.1.20:47100");
        store
            .swap_pending(&k7qm, &a.address, None, Some(&a))
            .unwrap();
        let path = store.pending_path(&k7qm, &a.address);
        crate::private::faults::plan_replaces(
            &path.with_extension("gone"),
            &[crate::private::faults::Fault::BeforeRename],
        );
        assert!(store
            .swap_pending(&k7qm, &a.address, Some(&a), None)
            .is_err());
        assert_eq!(store.load(&k7qm, &a.address).unwrap().1, Some(a.clone()));
        store
            .swap_pending(&k7qm, &a.address, Some(&a), None)
            .unwrap();
        assert_eq!(store.load(&k7qm, &a.address).unwrap().1, None);
        assert_eq!(
            fs::read_dir(store.dir.clone())
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .path()
                        .extension()
                        .is_some_and(|x| x == "gone" || x == "pending")
                })
                .count(),
            0
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Startup lists every kept record: a damaged one, or one whose read
    /// fails, is listed with its attempt unknown (its own flow reports it);
    /// a file whose name is not a pending record's is reported, never
    /// skipped; the leftover of an interrupted delete is removed.
    #[test]
    fn startup_lists_damaged_and_unreadable_records_and_reports_bad_names() {
        let k7qm = DirectLookup::from_canonical("K7QM").unwrap();
        let dir = temp_dir("direct-slots");
        let store = DirectRecordStore::in_dir(&dir);
        let a = pending(&k7qm, "192.168.1.20:47100");
        let b = pending(&k7qm, "192.168.1.21:47100");
        let c = pending(&k7qm, "192.168.1.22:47100");
        for p in [&a, &b, &c] {
            store
                .swap_pending(&k7qm, &p.address, None, Some(p))
                .unwrap();
        }
        // Damaged.
        fs::write(store.pending_path(&k7qm, &b.address), b"junk").unwrap();
        // A read that fails (a folder where the file should be).
        let c_path = store.pending_path(&k7qm, &c.address);
        fs::remove_file(&c_path).unwrap();
        fs::create_dir(&c_path).unwrap();
        // Not a pending record's name, under a valid lookup.
        fs::write(store.dir.join("K7QM-zz.pending"), b"junk").unwrap();
        // The leftover of a delete stopped after its durable move.
        let gone = store.pending_path(&k7qm, &a.address).with_extension("gone");
        fs::write(&gone, a.to_bytes()).unwrap();
        let found = store.pending_slots().unwrap();
        let slot = |p: &DirectPending, attempt| PendingSlot {
            lookup: k7qm.clone(),
            address: p.address,
            attempt,
        };
        assert_eq!(
            found.slots,
            vec![slot(&a, Some(a.attempt)), slot(&b, None), slot(&c, None),]
        );
        assert_eq!(found.unreadable.len(), 1, "{:?}", found.unreadable);
        assert!(!gone.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A record that does not read, or is filed under another lookup or
    /// address, is an error, never "no record". A damaged record at one
    /// address does not stop a load at another.
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
        assert!(store.load(&k7qm, &elsewhere).is_err());
        fs::write(store.pending_path(&k7qm, &elsewhere), b"junk").unwrap();
        assert!(store.load(&k7qm, &elsewhere).is_err());
        assert_eq!(store.load(&k7qm, &a.address).unwrap().1, Some(a.clone()));
        fs::remove_file(store.pending_path(&k7qm, &elsewhere)).unwrap();
        fs::write(store.ledger_path(&k7qm), b"junk").unwrap();
        assert!(store.load(&k7qm, &a.address).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
