//! Removal of a grant, journaled and fail-closed (Phase 1a §5.4).
//!
//! `grant.remove` and `grant.revoke_local` take three steps:
//!
//! 1. write `revoke {grant}` to `revoke.journal` in the state folder,
//!    durably;
//! 2. remove the grant (its connections close with `GRANT_REVOKED`) and
//!    save the grant table;
//! 3. clear the journal.
//!
//! If step 1 fails, nothing changed and the call fails. If the save in
//! step 2 fails, networking pauses: every connection closes, inbound
//! connections are dropped as they arrive and dials are refused, and the
//! helper tries again every `REMOVAL_RETRY_MS`. At start, the journal is
//! replayed before any connection is accepted; if that fails, the helper
//! starts paused. So a crash between the change and its save never lets
//! the removed peer back in.
//!
//! A removal from an owner-role device ("remove on all my hosts", Phase 4
//! Part D) takes the same path: [`Removal::apply_signed`] decides it under
//! the host's admission lock, journals the removal id, its record hash and
//! the result in `removals.journal` (durably, before anything changes), and
//! for `applied` removes the grant. That journal entry is the removal's
//! `revoke` entry too: a start replays every applied removal whose grant is
//! still in the table.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use mousse_net_core::grants::GrantId;
use mousse_net_core::removal::{Decision, Journaled, RemovalId, RemovalResult, SignedRemoval};
use mousse_net_core::ErrorCode;
use mousse_net_io::store::{hex, unhex, write_atomic};
use mousse_net_io::{Host, NetError};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::applog;

/// The journal's file name, next to the grant table.
pub const JOURNAL: &str = "revoke.journal";

#[derive(Serialize, Deserialize, Default)]
struct JournalFile {
    version: u32,
    revoke: Vec<u64>,
}

/// The removals that are decided and may not be saved yet.
pub struct Journal {
    path: PathBuf,
}

impl Journal {
    /// `revoke.journal` in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join(JOURNAL),
        }
    }

    /// The grants to remove. No journal: none.
    pub fn load(&self) -> Result<Vec<u64>, String> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice::<JournalFile>(&bytes)
                .map(|f| f.revoke)
                .map_err(|e| format!("{}: {e}", self.path.display())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(format!("{}: {e}", self.path.display())),
        }
    }

    /// Add `grant`, durably, before anything changes.
    pub fn add(&self, grant: u64) -> Result<(), String> {
        let mut revoke = self.load()?;
        if !revoke.contains(&grant) {
            revoke.push(grant);
        }
        let bytes =
            serde_json::to_vec(&JournalFile { version: 1, revoke }).map_err(|e| e.to_string())?;
        write_atomic(&self.path, &bytes).map_err(|e| e.to_string())
    }

    /// Clear it: every entry is saved in the grant table.
    pub fn clear(&self) -> Result<(), String> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{}: {e}", self.path.display())),
        }
    }
}

/// The removal journal's file name, next to the grant table.
pub const REMOVALS_JOURNAL: &str = "removals.journal";

/// One removal a host decided (Phase 4 D.4).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RemovalEntry {
    /// The removal id (hex).
    pub id: String,
    /// SHA-256 of the record bytes (hex).
    pub hash: String,
    /// `applied`, `stale` or `refused`.
    pub result: String,
    /// When it was journaled (this endpoint's clock).
    pub at: u64,
    /// For `applied`: the grant removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<u64>,
    /// For `applied`: the removed device (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<String>,
    /// For `applied`: the cleanup after the lock (relay allow-sets, the
    /// pairing's directory slot and deposit tag) is not done yet.
    #[serde(default, skip_serializing_if = "is_false")]
    pub cleanup: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl RemovalEntry {
    fn result(&self) -> Option<RemovalResult> {
        [
            RemovalResult::Applied,
            RemovalResult::Stale,
            RemovalResult::Refused,
        ]
        .into_iter()
        .find(|r| r.name() == self.result)
    }

    /// The journaled hash and result.
    pub fn journaled(&self) -> Option<Journaled> {
        let hash: [u8; 32] = unhex(&self.hash).ok()?.try_into().ok()?;
        Some(Journaled {
            record_hash: hash,
            result: self.result()?,
        })
    }
}

#[derive(Serialize, Deserialize, Default)]
struct RemovalsFile {
    version: u32,
    removals: Vec<RemovalEntry>,
}

/// Every removal id this host decided, kept for
/// `MOUSSE_NET_REMOVAL_MAX_AGE_SECS` plus the clock skew (and until its
/// cleanup is done).
pub struct RemovalJournal {
    path: PathBuf,
}

impl RemovalJournal {
    /// `removals.journal` in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join(REMOVALS_JOURNAL),
        }
    }

    /// Every entry. No journal: none.
    pub fn load(&self) -> Result<Vec<RemovalEntry>, String> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice::<RemovalsFile>(&bytes)
                .map(|f| f.removals)
                .map_err(|e| format!("{}: {e}", self.path.display())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(format!("{}: {e}", self.path.display())),
        }
    }

    /// Write `removals` durably.
    pub fn save(&self, removals: Vec<RemovalEntry>) -> Result<(), String> {
        let bytes = serde_json::to_vec(&RemovalsFile {
            version: 1,
            removals,
        })
        .map_err(|e| e.to_string())?;
        write_atomic(&self.path, &bytes).map_err(|e| e.to_string())
    }

    /// The grants of applied removals: a start removes those still in the
    /// table.
    fn applied_grants(&self) -> Result<Vec<u64>, String> {
        Ok(self
            .load()?
            .into_iter()
            .filter(|e| e.result == RemovalResult::Applied.name())
            .filter_map(|e| e.grant)
            .collect())
    }
}

/// What `grant.remove` did.
#[derive(Debug, PartialEq, Eq)]
pub enum Removed {
    /// No such grant (removed before): nothing to do.
    Gone,
    /// Removed and saved.
    Saved,
    /// Removed, journaled, but the save failed: networking is paused
    /// until a retry saves it.
    Paused,
}

/// Why `grant.remove` changed nothing.
#[derive(Debug)]
pub struct JournalFailed(pub String);

/// Removals and the pause they may cause. One per endpoint.
pub struct Removal {
    journal: Journal,
    removals: RemovalJournal,
    host: Host,
    /// Removals, replays and retries run one at a time: a save that
    /// clears the journal covers every entry in it.
    steps: Mutex<()>,
    /// `Some(reason)` while networking is paused.
    paused: watch::Sender<Option<String>>,
    /// Counts removals applied in memory (journaled first), so relay
    /// allow-sets are pushed after each one (Phase 3 §B.5).
    removed: watch::Sender<u64>,
}

impl Removal {
    /// The removals of `host`, journaled in `dir` (the grant table's
    /// folder). Replays the journal now: call it before any connection is
    /// accepted. If the replay fails, networking starts paused.
    pub fn start(host: Host, dir: &Path) -> Arc<Self> {
        let (paused, _) = watch::channel(None);
        let (removed, _) = watch::channel(0);
        let removal = Arc::new(Self {
            journal: Journal::in_dir(dir),
            removals: RemovalJournal::in_dir(dir),
            host,
            steps: Mutex::new(()),
            paused,
            removed,
        });
        if let Err(why) = removal.settle() {
            removal.pause(format!("replaying removals failed: {why}"));
        }
        removal
    }

    /// Whether networking is paused.
    pub fn is_paused(&self) -> bool {
        self.paused.borrow().is_some()
    }

    /// Why networking is paused, if it is.
    pub fn paused_reason(&self) -> Option<String> {
        self.paused.borrow().clone()
    }

    /// Changes to the pause.
    pub fn watch(&self) -> watch::Receiver<Option<String>> {
        self.paused.subscribe()
    }

    /// Changes each time a journaled removal took effect.
    pub fn removed(&self) -> watch::Receiver<u64> {
        self.removed.subscribe()
    }

    /// Remove `grant` (§5.4 step 2).
    pub fn remove(self: &Arc<Self>, grant: GrantId) -> Result<Removed, JournalFailed> {
        let _steps = self.steps.lock().unwrap_or_else(|e| e.into_inner());
        if !self.host.grants().iter().any(|g| g.id == grant) {
            return Ok(Removed::Gone);
        }
        if !cfg!(mousse_control = "no-revoke-journal") {
            self.journal.add(grant.0).map_err(JournalFailed)?;
        }
        crate::peer::crash_point("removal-journaled");
        let removed = self.host.remove_grant(grant);
        // In memory the grant is gone either way: relays hear it now.
        self.removed.send_modify(|n| *n += 1);
        match removed {
            Ok(_) => {
                if !self.is_paused() {
                    if let Err(e) = self.journal.clear() {
                        // Harmless: a replay finds the grant gone.
                        applog::line(format!("clearing the removal journal failed: {e}"));
                    }
                }
                Ok(Removed::Saved)
            }
            Err(e) => {
                self.pause(format!("saving the grant table failed: {e}"));
                Ok(Removed::Paused)
            }
        }
    }

    /// Apply a removal from an owner-role device (Phase 4 D.4) and return
    /// the result to answer. Under the host's admission lock: decide,
    /// journal the id, hash and result durably (for every result from
    /// check 3 on), and for `applied` remove the grant. A failed journal
    /// write changes nothing and is an error; a failed save of the grant
    /// table pauses networking, as for any removal.
    pub fn apply_signed(
        self: &Arc<Self>,
        signed: &SignedRemoval,
        now: u64,
        max_age_secs: u64,
        skew_secs: u64,
    ) -> Result<RemovalResult, String> {
        let _steps = self.steps.lock().unwrap_or_else(|e| e.into_inner());
        let entries = self.removals.load()?;
        let applied = self.host.apply_removal(
            signed,
            max_age_secs,
            |id: &RemovalId| {
                let id = hex(&id.0);
                entries
                    .iter()
                    .find(|e| e.id == id)
                    .and_then(RemovalEntry::journaled)
            },
            |decision: &Decision| {
                let Decision::Journal { result, grant } = *decision else {
                    return Ok(());
                };
                let keep = max_age_secs + skew_secs;
                let mut kept: Vec<RemovalEntry> = entries
                    .iter()
                    .filter(|e| e.at.saturating_add(keep) >= now || e.cleanup)
                    .cloned()
                    .collect();
                kept.push(RemovalEntry {
                    id: hex(&signed.removal().id.0),
                    hash: hex(&signed.record_hash()),
                    result: result.name().into(),
                    at: now,
                    grant: grant.map(|g| g.0),
                    removed: grant.map(|_| hex(signed.removal().removed.as_bytes())),
                    cleanup: grant.is_some(),
                });
                self.removals.save(kept)
            },
        )?;
        if let Err(e) = applied.saved {
            self.pause(format!("saving the grant table failed: {e}"));
        }
        let result = applied.decision.result();
        if result == RemovalResult::Applied {
            // Relays hear it now (Phase 3 §B.5).
            self.removed.send_modify(|n| *n += 1);
        }
        Ok(result)
    }

    /// The removal journal.
    pub fn removals(&self) -> &RemovalJournal {
        &self.removals
    }

    /// Mark the cleanup of the removal `id` done.
    pub fn cleanup_done(&self, id: &str) -> Result<(), String> {
        let _steps = self.steps.lock().unwrap_or_else(|e| e.into_inner());
        let mut entries = self.removals.load()?;
        let mut changed = false;
        for e in entries.iter_mut().filter(|e| e.id == id && e.cleanup) {
            e.cleanup = false;
            changed = true;
        }
        if changed {
            self.removals.save(entries)?;
        }
        Ok(())
    }

    /// Apply every journaled removal, save the table and clear the journal.
    fn settle(&self) -> Result<(), String> {
        let mut grants = self.journal.load()?;
        for grant in self.removals.applied_grants()? {
            if !grants.contains(&grant) && self.host.grants().iter().any(|g| g.id.0 == grant) {
                grants.push(grant);
            }
        }
        for id in &grants {
            // A grant already gone (in memory) carries on to the save.
            self.host
                .remove_grant(GrantId(*id))
                .map_err(|e: NetError| e.to_string())?;
        }
        if !grants.is_empty() || self.is_paused() || self.host.has_unsaved_changes() {
            self.host.save().map_err(|e| e.to_string())?;
        }
        self.journal.clear()
    }

    /// Pause: the host stops serving under the lock its connections
    /// register under (a handshake that ends later is closed too), and the
    /// app channel, which publishes its paths under its own lock after
    /// checking the pause, closes what it had (`watch_pause`).
    fn pause(self: &Arc<Self>, reason: String) {
        applog::line(format!("networking paused: {reason}"));
        self.host.pause(ErrorCode::InternalError);
        let first = self.paused.send_replace(Some(reason)).is_none();
        if first {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(retry(Arc::downgrade(self)));
            }
        }
    }

    /// One retry while paused: resume if it saves.
    fn retry_once(&self) -> bool {
        let _steps = self.steps.lock().unwrap_or_else(|e| e.into_inner());
        match self.settle() {
            Ok(()) => {
                applog::line("networking resumed: the grant table is saved");
                self.host.resume();
                self.paused.send_replace(None);
                true
            }
            Err(_) => false,
        }
    }
}

async fn retry(removal: Weak<Removal>) {
    let wait = crate::limits::ms(crate::limits::helper().removal_retry_ms());
    loop {
        tokio::time::sleep(wait).await;
        let Some(removal) = removal.upgrade() else {
            return;
        };
        if !removal.is_paused() || removal.retry_once() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mousse_net_core::grants::OwnerRef;
    use mousse_net_core::identity::SoftwareKey;
    use mousse_net_core::pairing::CpaceExchangeFactory;
    use mousse_net_io::rng::os_rng;
    use mousse_net_io::{HostConfig, SystemClock};

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mousse-helper-revoke-{tag}-{}-{}",
            std::process::id(),
            mousse_net_io::store::hex(&mousse_net_io::rng::random_bytes::<4>())
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn host(dir: &Path) -> Host {
        let config = HostConfig {
            name: "host".into(),
            state_dir: Some(dir.to_path_buf()),
            owner: OwnerRef::from_bytes([7; 16]),
            limits: mousse_net_io::Limits::DEFAULT,
            clock: Arc::new(SystemClock::new()),
            ticket_identity: None,
            streams: None,
        };
        let signer = Arc::new(SoftwareKey::generate(&mut os_rng()));
        Host::new(signer, config, CpaceExchangeFactory).unwrap().0
    }

    fn peer() -> mousse_net_core::identity::IdentityPublicKey {
        SoftwareKey::generate(&mut os_rng()).public_key()
    }

    /// The journal names a grant whose removal was never saved: the start
    /// removes it and saves before anything is accepted.
    #[tokio::test]
    async fn a_start_replays_a_removal_that_was_not_saved() {
        let dir = temp_dir("replay");
        let first = host(&dir);
        let (grant, _) = first.add_grant(peer(), "laptop".into(), None).unwrap();
        drop(first);
        Journal::in_dir(&dir).add(grant.id.0).unwrap();

        let second = host(&dir);
        assert_eq!(second.grants().len(), 1);
        let removal = Removal::start(second.clone(), &dir);
        assert!(!removal.is_paused());
        assert!(second.grants().is_empty());
        assert!(!dir.join(JOURNAL).exists());
        // Saved: a third start has no grant either.
        assert!(host(&dir).grants().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A journal that cannot be read keeps networking paused from the
    /// start, and the grant it may name stays unserved.
    #[tokio::test]
    async fn a_journal_that_cannot_be_replayed_starts_paused() {
        let dir = temp_dir("unreadable");
        fs::write(dir.join(JOURNAL), b"{not json").unwrap();
        let removal = Removal::start(host(&dir), &dir);
        assert!(removal.is_paused());
        fs::remove_dir_all(&dir).unwrap();
    }

    fn signed_removal(
        admin: &SoftwareKey,
        host: &Host,
        removed: mousse_net_core::identity::IdentityPublicKey,
        grant: GrantId,
        id: u8,
    ) -> SignedRemoval {
        let record = mousse_net_core::removal::Removal {
            signer: admin.public_key(),
            recipient: host.identity(),
            removed,
            grant,
            id: RemovalId([id; 16]),
            issued_at: mousse_net_core::UnixTime(now()),
        };
        SignedRemoval::sign(record, admin).unwrap()
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// A removal is journaled with its result; sending the same bytes again
    /// returns that result and changes nothing, and the same id with other
    /// bytes is refused.
    #[tokio::test]
    async fn a_removal_resend_returns_the_journaled_result() {
        let dir = temp_dir("resend");
        let host = host(&dir);
        let admin = SoftwareKey::generate(&mut os_rng());
        host.add_grant(admin.public_key(), "admin".into(), None)
            .unwrap();
        let phone = peer();
        let (grant, _) = host.add_grant(phone, "phone".into(), None).unwrap();
        let removal = Removal::start(host.clone(), &dir);
        let signed = signed_removal(&admin, &host, phone, grant.id, 1);
        let first = removal
            .apply_signed(&signed, now(), 2_592_000, 600)
            .unwrap();
        assert_eq!(first, RemovalResult::Applied);
        assert!(host.grants().iter().all(|g| g.identity != phone));
        let again = removal
            .apply_signed(&signed, now(), 2_592_000, 600)
            .unwrap();
        assert_eq!(again, RemovalResult::Applied);
        let entries = removal.removals().load().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].cleanup);
        let other = signed_removal(&admin, &host, phone, GrantId(grant.id.0 + 7), 1);
        assert_eq!(
            removal.apply_signed(&other, now(), 2_592_000, 600).unwrap(),
            RemovalResult::Refused
        );
        removal.cleanup_done(&entries[0].id).unwrap();
        assert!(!removal.removals().load().unwrap()[0].cleanup);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// An applied removal whose grant table save never happened (the
    /// process stopped after the journal write): the next start removes
    /// the grant before anything is accepted.
    #[tokio::test]
    async fn a_start_replays_an_applied_removal() {
        let dir = temp_dir("replayremoval");
        let first = host(&dir);
        let phone = peer();
        let (grant, _) = first.add_grant(phone, "phone".into(), None).unwrap();
        drop(first);
        RemovalJournal::in_dir(&dir)
            .save(vec![RemovalEntry {
                id: "00".repeat(16),
                hash: "00".repeat(32),
                result: "applied".into(),
                at: now(),
                grant: Some(grant.id.0),
                removed: Some(hex(phone.as_bytes())),
                cleanup: true,
            }])
            .unwrap();
        let second = host(&dir);
        assert_eq!(second.grants().len(), 1);
        let removal = Removal::start(second.clone(), &dir);
        assert!(!removal.is_paused());
        assert!(second.grants().is_empty());
        assert!(host(&dir).grants().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A journal that cannot be written changes nothing.
    #[tokio::test]
    async fn a_removal_that_cannot_be_journaled_changes_nothing() {
        let dir = temp_dir("unwritable");
        let host = host(&dir);
        let (grant, _) = host.add_grant(peer(), "laptop".into(), None).unwrap();
        let removal = Removal::start(host.clone(), &dir);
        fs::create_dir_all(dir.join(JOURNAL).join("in-the-way")).unwrap();
        assert!(removal.remove(grant.id).is_err());
        assert_eq!(host.grants().len(), 1);
        assert!(!removal.is_paused());
        fs::remove_dir_all(&dir).unwrap();
    }
}
