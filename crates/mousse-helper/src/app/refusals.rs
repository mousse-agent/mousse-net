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
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_io::store::{hex, write_atomic};
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

/// The store.
pub struct Refusals {
    path: PathBuf,
    held: Mutex<Option<Held>>,
}

impl Refusals {
    /// `version-refusals.json` in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join(FILE),
            held: Mutex::new(None),
        }
    }

    /// Run `f` on the copy in memory, read from the file the first time;
    /// an unreadable file counts as empty.
    fn with<R>(&self, f: impl FnOnce(&mut Held) -> R) -> R {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let held = held.get_or_insert_with(|| Held {
            file: std::fs::read(&self.path)
                .ok()
                .and_then(|b| serde_json::from_slice::<RefusalFile>(&b).ok())
                .unwrap_or_default(),
            ..Held::default()
        });
        f(held)
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

    /// Whether an outcome for `key` seen at `seen` is not older than the
    /// one applied last; if so it becomes the last.
    fn in_order(held: &mut Held, key: &str, seen: Instant) -> bool {
        match held.seen.get(key) {
            Some(last) if seen < *last => false,
            _ => {
                held.seen.insert(key.to_owned(), seen);
                true
            }
        }
    }

    /// The last refusal of `identity` (hex), if one is kept.
    pub fn get(&self, identity: &str) -> Option<Refusal> {
        self.with(|held| {
            held.file
                .refusals
                .iter()
                .find(|r| r.identity == identity)
                .cloned()
        })
    }

    /// Note a refusal of `identity`, seen at `seen`. Kept unless an outcome
    /// seen later was applied already; written when it is new or its minors
    /// changed. Returns whether it was kept.
    pub fn note(
        &self,
        identity: &IdentityPublicKey,
        peer_minor: u64,
        local_minor: u64,
        now: u64,
        seen: Instant,
    ) -> bool {
        let key = hex(identity.as_bytes());
        self.with(|held| {
            if !Self::in_order(held, &key, seen) {
                self.save(held, false);
                return false;
            }
            let list = &mut held.file.refusals;
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
            self.save(held, !same);
            true
        })
    }

    /// A connection with `identity` agreed a version, seen at `seen`: its
    /// refusal goes, unless a refusal seen later was noted already.
    /// Returns whether one was removed.
    pub fn clear(&self, identity: &IdentityPublicKey, seen: Instant) -> bool {
        let key = hex(identity.as_bytes());
        self.with(|held| {
            if !Self::in_order(held, &key, seen) {
                self.save(held, false);
                return false;
            }
            let before = held.file.refusals.len();
            held.file.refusals.retain(|r| r.identity != key);
            let removed = held.file.refusals.len() != before;
            self.save(held, removed);
            removed
        })
    }

    /// Whether `identity` may raise `peer.incompatible` now (`now` in unix
    /// seconds): not within `gap` of the last time it did, before a restart
    /// or a clear too. Taking the turn counts as raising, and is written.
    pub fn take_turn(&self, identity: &IdentityPublicKey, now: u64, gap: Duration) -> bool {
        let key = hex(identity.as_bytes());
        let gap = gap.as_secs();
        self.with(|held| {
            // A time ahead of now (the clock went back) does not hold a turn.
            let recent = |n: &Notice| n.at <= now && now - n.at < gap;
            let notices = &mut held.file.notices;
            if notices.iter().any(|n| n.identity == key && recent(n)) {
                self.save(held, false);
                return false;
            }
            notices.retain(|n| n.identity != key && recent(n));
            notices.push(Notice {
                identity: key,
                at: now,
            });
            self.save(held, true);
            true
        })
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
