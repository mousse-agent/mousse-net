//! The last refusal for version, per paired identity (`docs/pair-with-ip-design.md`
//! §1.2 and §5): `version-refusals.json` in the state folder, next to
//! `peers.json` and apart from it. A peer record is an outbound pin the
//! keeper dials, and a device that only uses this computer has none, so the
//! refusal is kept here for both kinds of paired device.
//!
//! A refusal is noted when a connection with a device that holds a grant
//! here, or that this computer pins, closes with `UNSUPPORTED_VERSION`
//! after its `HELLO` was read, whichever side closed it. A connection with
//! that device that agrees a version clears it. Outcomes apply in the
//! order they were seen, so a clear that arrives late never removes a newer
//! refusal. The file also keeps when each device last raised
//! `peer.incompatible`, so neither a restart nor a clear lets it raise
//! again within the gap.
//!
//! Only the app-mode helper writes the file; the copy in memory is the
//! truth while it runs. A failed write is logged and the copy marked
//! unsaved: every later call that may write tries again, also when it
//! changes nothing.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_io::store::{hex, short_id, write_atomic};
use mousse_net_io::HelloSeen;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::time::Instant;

use crate::applog;

/// The file, in the endpoint's state folder.
pub const FILE: &str = "version-refusals.json";

/// One device's last refusal for version.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Refusal {
    /// The device's identity key (hex).
    pub identity: String,
    /// The newest minor version the device's `HELLO` named.
    pub peer_minor: u64,
    /// The newest minor version this side spoke then. Above `peer_minor`:
    /// the device has to update; below it: this computer has to.
    pub local_minor: u64,
    /// When the first refusal of this run of refusals was seen (unix
    /// seconds). Later refusals with the same minors leave it as it is.
    pub since: u64,
}

impl Refusal {
    /// As the app reads it on a peer or grant row.
    pub fn json(&self) -> Value {
        json!({
            "peer_minor": self.peer_minor,
            "local_minor": self.local_minor,
            "since": self.since,
        })
    }
}

/// When a device last raised `peer.incompatible`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Notice {
    identity: String,
    /// Unix seconds.
    at: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct RefusalFile {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    refusals: Vec<Refusal>,
    #[serde(default)]
    notices: Vec<Notice>,
}

/// The copy in memory.
#[derive(Default)]
struct Held {
    file: RefusalFile,
    /// The last write failed: the file is behind this copy.
    unsaved: bool,
    /// Per device, when the outcome applied last was seen.
    seen: HashMap<String, Instant>,
}

/// A change to a device's refusal.
enum Change {
    Note {
        key: String,
        peer_minor: u64,
        local_minor: u64,
        now: u64,
        seen: Instant,
    },
    Clear {
        key: String,
        seen: Instant,
    },
}

/// What applying a [`Change`] did.
struct Applied {
    /// It was not older than the last outcome applied for the device.
    in_order: bool,
    /// The copy changed.
    changed: bool,
}

impl Held {
    fn apply(&mut self, change: Change) -> Applied {
        let (key, seen) = match &change {
            Change::Note { key, seen, .. } | Change::Clear { key, seen } => (key.clone(), *seen),
        };
        // An outcome seen before the one applied last changes nothing.
        if self.seen.get(&key).is_some_and(|last| seen < *last) {
            return Applied {
                in_order: false,
                changed: false,
            };
        }
        self.seen.insert(key, seen);
        let list = &mut self.file.refusals;
        let changed = match change {
            Change::Note {
                key,
                peer_minor,
                local_minor,
                now,
                ..
            } => {
                let same = list.iter().any(|r| {
                    r.identity == key && r.peer_minor == peer_minor && r.local_minor == local_minor
                });
                if !same {
                    list.retain(|r| r.identity != key);
                    list.push(Refusal {
                        identity: key,
                        peer_minor,
                        local_minor,
                        since: now,
                    });
                }
                !same
            }
            Change::Clear { key, .. } => {
                let before = list.len();
                list.retain(|r| r.identity != key);
                list.len() != before
            }
        };
        Applied {
            in_order: true,
            changed,
        }
    }
}

/// The most changes kept while the file cannot be read; the oldest go.
const PENDING_MAX: usize = 256;

#[derive(Default)]
struct State {
    /// Read from the file; `None` until a read succeeds.
    held: Option<Held>,
    /// Changes made while the file could not be read, applied in order
    /// once it can.
    pending: Vec<Change>,
}

/// The store.
pub struct Refusals {
    path: PathBuf,
    state: Mutex<State>,
}

impl Refusals {
    /// `version-refusals.json` in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join(FILE),
            state: Mutex::new(State::default()),
        }
    }

    /// The file as it is: empty when there is none. A file whose contents
    /// cannot be read is moved aside (`.corrupt`), never overwritten. Any
    /// other failure (the file is busy, say) is an error, tried again at
    /// the next call.
    fn load(&self) -> Result<RefusalFile, String> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(RefusalFile::default()),
            Err(e) => return Err(e.to_string()),
        };
        match serde_json::from_slice::<RefusalFile>(&bytes) {
            Ok(file) => Ok(file),
            Err(e) => {
                let aside = self.path.with_extension("json.corrupt");
                std::fs::rename(&self.path, &aside).map_err(|r| r.to_string())?;
                applog::line(format!(
                    "version refusals: unreadable ({e}); kept as {} and started empty",
                    aside.display()
                ));
                Ok(RefusalFile::default())
            }
        }
    }

    /// The copy in memory, read from the file if it has not been yet; the
    /// changes kept meanwhile are applied first. `None`: it cannot be read
    /// now.
    fn loaded<'a>(&self, state: &'a mut State) -> Option<&'a mut Held> {
        if state.held.is_none() {
            match self.load() {
                Ok(file) => {
                    let mut held = Held {
                        file,
                        ..Held::default()
                    };
                    let mut changed = false;
                    for change in state.pending.drain(..) {
                        changed |= held.apply(change).changed;
                    }
                    self.save(&mut held, changed);
                    state.held = Some(held);
                }
                Err(e) => applog::line(format!("version refusals: reading failed: {e}")),
            }
        }
        state.held.as_mut()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Apply `change` and write it; kept for later if the file cannot be
    /// read now (then nothing is applied yet).
    fn change(&self, change: Change) -> Applied {
        let mut state = self.state();
        if self.loaded(&mut state).is_none() {
            if state.pending.len() >= PENDING_MAX {
                state.pending.remove(0);
            }
            state.pending.push(change);
            return Applied {
                in_order: false,
                changed: false,
            };
        }
        let Some(held) = state.held.as_mut() else {
            return Applied {
                in_order: false,
                changed: false,
            };
        };
        let applied = held.apply(change);
        self.save(held, applied.changed);
        applied
    }

    /// Write the copy if `changed` or still unsaved.
    fn save(&self, held: &mut Held, changed: bool) {
        if !changed && !held.unsaved {
            return;
        }
        held.file.version = 1;
        let written = serde_json::to_vec(&held.file)
            .map_err(|e| e.to_string())
            .and_then(|bytes| write_atomic(&self.path, &bytes).map_err(|e| e.to_string()));
        held.unsaved = written.is_err();
        if let Err(e) = written {
            applog::line(format!("version refusals: saving failed: {e}"));
        }
    }

    /// The last refusal of `identity` (hex), if one is kept.
    pub fn get(&self, identity: &str) -> Option<Refusal> {
        let mut state = self.state();
        self.loaded(&mut state)?
            .file
            .refusals
            .iter()
            .find(|r| r.identity == identity)
            .cloned()
    }

    /// Note a refusal of `identity`, seen at `seen`. Kept unless an outcome
    /// seen later was applied already; written when it is new or its minors
    /// changed. Returns whether it was kept now.
    pub fn note(
        &self,
        identity: &IdentityPublicKey,
        peer_minor: u64,
        local_minor: u64,
        now: u64,
        seen: Instant,
    ) -> bool {
        self.change(Change::Note {
            key: hex(identity.as_bytes()),
            peer_minor,
            local_minor,
            now,
            seen,
        })
        .in_order
    }

    /// A connection with `identity` agreed a version, seen at `seen`: its
    /// refusal goes, unless a refusal seen later was noted already.
    /// Returns whether one was removed now.
    pub fn clear(&self, identity: &IdentityPublicKey, seen: Instant) -> bool {
        self.change(Change::Clear {
            key: hex(identity.as_bytes()),
            seen,
        })
        .changed
    }

    /// Record one connection's version decision, ordered by when its
    /// `HELLO` was read: an agreement clears the device's refusal; a
    /// refusal is kept if the device is `paired`. Returns whether a refusal
    /// was kept now.
    pub fn record(&self, seen: &HelloSeen, paired: impl FnOnce() -> bool, now: u64) -> bool {
        match seen.agreed {
            Some(_) => {
                if self.clear(&seen.peer, seen.at) {
                    applog::line(format!(
                        "{} agreed a version: its refusal is cleared",
                        short_id(&seen.peer)
                    ));
                }
                false
            }
            None => {
                paired()
                    && self.note(
                        &seen.peer,
                        seen.peer_minor,
                        mousse_net_io::conn::local_minor(),
                        now,
                        seen.at,
                    )
            }
        }
    }

    /// Whether `identity` may raise `peer.incompatible` now (`now` in unix
    /// seconds): not within `gap` of the last time it did, before a restart
    /// or a clear too, and not while that time is ahead of now (the clock
    /// went back). Taking the turn counts as raising, and is written. No
    /// turn while the file cannot be read.
    pub fn take_turn(&self, identity: &IdentityPublicKey, now: u64, gap: Duration) -> bool {
        let key = hex(identity.as_bytes());
        let gap = gap.as_secs();
        let mut state = self.state();
        let Some(held) = self.loaded(&mut state) else {
            return false;
        };
        let holds = |n: &Notice| now < n.at.saturating_add(gap);
        let notices = &mut held.file.notices;
        if notices.iter().any(|n| n.identity == key && holds(n)) {
            self.save(held, false);
            return false;
        }
        notices.retain(|n| n.identity != key && holds(n));
        notices.push(Notice {
            identity: key,
            at: now,
        });
        self.save(held, true);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mousse_net_core::identity::SoftwareKey;
    use mousse_net_io::rng::{os_rng, random_bytes};

    fn key() -> IdentityPublicKey {
        SoftwareKey::generate(&mut os_rng()).public_key()
    }

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "mousse-refusals-{tag}-{}",
            hex(&random_bytes::<6>())
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_refusal_outlives_a_restart_and_the_next_agreement_clears_it() {
        let d = dir("keep");
        let (a, b) = (key(), key());
        let store = Refusals::in_dir(&d);
        let t0 = Instant::now();
        store.note(&a, 1, 3, 100, t0);
        store.note(&b, 4, 3, 100, t0);
        // The same minors again keep the first time.
        store.note(&a, 1, 3, 200, t0);
        let again = Refusals::in_dir(&d);
        let ka = hex(a.as_bytes());
        assert_eq!(
            again.get(&ka),
            Some(Refusal {
                identity: ka.clone(),
                peer_minor: 1,
                local_minor: 3,
                since: 100
            })
        );
        assert!(again.clear(&a, t0));
        assert!(!again.clear(&a, t0));
        let third = Refusals::in_dir(&d);
        assert_eq!(third.get(&ka), None);
        assert!(third.get(&hex(b.as_bytes())).is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_failed_write_is_tried_again_by_the_next_call_that_changes_nothing() {
        let d = dir("retry");
        let a = key();
        let ka = hex(a.as_bytes());
        // A folder where the file goes: every write fails.
        std::fs::create_dir(d.join(FILE)).unwrap();
        let store = Refusals::in_dir(&d);
        let t0 = Instant::now();
        store.note(&a, 1, 3, 100, t0);
        std::fs::remove_dir(d.join(FILE)).unwrap();
        // The same refusal again: nothing changes, the write happens.
        store.note(&a, 1, 3, 200, t0);
        assert!(Refusals::in_dir(&d).get(&ka).is_some());

        // A clear whose write failed is written by the next call too.
        std::fs::remove_file(d.join(FILE)).unwrap();
        std::fs::create_dir(d.join(FILE)).unwrap();
        assert!(store.clear(&a, t0));
        std::fs::remove_dir(d.join(FILE)).unwrap();
        std::fs::write(
            d.join(FILE),
            serde_json::to_vec(&json!({"version": 1, "refusals": [{
                "identity": ka, "peer_minor": 1, "local_minor": 3, "since": 100
            }]}))
            .unwrap(),
        )
        .unwrap();
        assert!(!store.clear(&a, t0));
        assert_eq!(Refusals::in_dir(&d).get(&ka), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_late_clear_never_removes_a_refusal_seen_after_it() {
        let store = Refusals::in_dir(&dir("order"));
        let a = key();
        let ka = hex(a.as_bytes());
        let agreed = Instant::now();
        let refused = agreed + Duration::from_millis(5);
        store.note(&a, 1, 3, 100, refused);
        // The agreement was seen before the refusal: it changes nothing.
        assert!(!store.clear(&a, agreed));
        assert!(store.get(&ka).is_some());
        // An agreement seen after it clears it.
        assert!(store.clear(&a, refused + Duration::from_millis(5)));
        assert_eq!(store.get(&ka), None);
    }

    #[test]
    fn a_file_that_cannot_be_read_yet_is_never_replaced_and_changes_wait_for_it() {
        let d = dir("busy");
        let (a, b) = (key(), key());
        let (ka, kb) = (hex(a.as_bytes()), hex(b.as_bytes()));
        let t0 = Instant::now();
        Refusals::in_dir(&d).note(&a, 1, 3, 100, t0);
        // The file cannot be read when the helper starts (a folder stands
        // in its place, as a busy file would).
        let aside = d.join("kept.json");
        std::fs::rename(d.join(FILE), &aside).unwrap();
        std::fs::create_dir(d.join(FILE)).unwrap();
        let store = Refusals::in_dir(&d);
        assert!(!store.note(&b, 4, 3, 200, t0));
        assert_eq!(store.get(&ka), None);
        // Readable again: the kept change lands on the file as it was.
        std::fs::remove_dir(d.join(FILE)).unwrap();
        std::fs::rename(&aside, d.join(FILE)).unwrap();
        assert!(store.get(&ka).is_some());
        let again = Refusals::in_dir(&d);
        assert!(again.get(&ka).is_some());
        assert!(again.get(&kb).is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_unreadable_file_is_kept_aside_not_overwritten() {
        let d = dir("corrupt");
        std::fs::write(d.join(FILE), b"{ not json").unwrap();
        let store = Refusals::in_dir(&d);
        store.note(&key(), 1, 3, 100, Instant::now());
        assert_eq!(
            std::fs::read(d.join("version-refusals.json.corrupt")).unwrap(),
            b"{ not json"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_older_refusal_delivered_after_a_newer_agreement_is_dropped() {
        let store = Refusals::in_dir(&dir("late"));
        let a = key();
        let ka = hex(a.as_bytes());
        let seen = |agreed: Option<u64>, at: Instant| HelloSeen {
            peer: a,
            peer_minor: 1,
            agreed,
            at,
            inbound: true,
        };
        let refused_at = Instant::now();
        store.record(
            &seen(None, refused_at - Duration::from_millis(5)),
            || true,
            1,
        );
        assert!(store.get(&ka).is_some());
        // A connection agrees; a refusal whose HELLO was read before that
        // arrives after it, as a slow handler delivers it.
        store.record(
            &seen(Some(3), refused_at + Duration::from_millis(5)),
            || true,
            2,
        );
        assert!(!store.record(&seen(None, refused_at), || true, 3));
        assert_eq!(store.get(&ka), None);
        // An unpaired device's refusal is never kept.
        let b = key();
        let unpaired = HelloSeen {
            peer: b,
            ..seen(None, Instant::now())
        };
        assert!(!store.record(&unpaired, || false, 4));
        assert_eq!(store.get(&hex(b.as_bytes())), None);
    }

    #[test]
    fn a_notice_ahead_of_the_clock_still_holds_the_turn() {
        let d = dir("rollback");
        let a = key();
        let gap = Duration::from_secs(3_600);
        assert!(Refusals::in_dir(&d).take_turn(&a, 10_000, gap));
        // Reopened after the clock went back a second.
        let again = Refusals::in_dir(&d);
        assert!(!again.take_turn(&a, 9_999, gap));
        assert!(!again.take_turn(&a, 13_599, gap));
        assert!(again.take_turn(&a, 13_600, gap));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_device_raises_at_most_once_per_gap_across_a_restart_and_a_clear() {
        let d = dir("turn");
        let (a, b) = (key(), key());
        let gap = Duration::from_secs(3_600);
        let store = Refusals::in_dir(&d);
        assert!(store.take_turn(&a, 1_000, gap));
        assert!(!store.take_turn(&a, 4_599, gap));
        assert!(store.take_turn(&b, 1_000, gap));
        // A clear and a restart keep the turn taken.
        store.note(&a, 1, 3, 1_000, Instant::now());
        store.clear(&a, Instant::now());
        let again = Refusals::in_dir(&d);
        assert!(!again.take_turn(&a, 4_599, gap));
        assert!(again.take_turn(&a, 4_600, gap));
        let _ = std::fs::remove_dir_all(&d);
    }
}
