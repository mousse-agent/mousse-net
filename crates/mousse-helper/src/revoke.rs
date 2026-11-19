//! Removal of a grant, journaled and fail-closed (Phase 1a §5.4).
//!
//! `grant.remove` takes three steps:
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

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use mousse_net_core::grants::GrantId;
use mousse_net_core::ErrorCode;
use mousse_net_io::store::write_atomic;
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
    pub fn removals(&self) -> watch::Receiver<u64> {
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

    /// Apply every journaled removal, save the table and clear the journal.
    fn settle(&self) -> Result<(), String> {
        let grants = self.journal.load()?;
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
