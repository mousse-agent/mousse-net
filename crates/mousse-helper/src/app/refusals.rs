//! The last refusal for version, per paired identity (`docs/pair-with-ip-design.md`
//! §1.2 and §5): `version-refusals.json` in the state folder, next to
//! `peers.json` and apart from it. A peer record is an outbound pin the
//! keeper dials, and a device that only uses this computer has none, so the
//! refusal is kept here for both kinds of paired device.
//!
//! A refusal is noted when a connection with a device that holds a grant
//! here, or that this computer pins, closes with `UNSUPPORTED_VERSION`
//! after its `HELLO` was read, whichever side closed it. The first
//! connection with that device that agrees a version clears it. Only the
//! app-mode helper writes the file; the copy in memory is the truth while
//! it runs, and a failed write is logged and tried again at the next change.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
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

#[derive(Default, Serialize, Deserialize)]
struct RefusalFile {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    refusals: Vec<Refusal>,
}

/// The store and, in memory only, when each device last raised
/// `peer.incompatible`.
pub struct Refusals {
    path: PathBuf,
    list: Mutex<Option<Vec<Refusal>>>,
    raised: Mutex<HashMap<IdentityPublicKey, Instant>>,
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Refusals {
    /// `version-refusals.json` in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join(FILE),
            list: Mutex::new(None),
            raised: Mutex::new(HashMap::new()),
        }
    }

    /// Read the file once; an unreadable one counts as empty.
    fn loaded<'a>(&self, held: &'a mut Option<Vec<Refusal>>) -> &'a mut Vec<Refusal> {
        held.get_or_insert_with(|| {
            std::fs::read(&self.path)
                .ok()
                .and_then(|b| serde_json::from_slice::<RefusalFile>(&b).ok())
                .map(|f| f.refusals)
                .unwrap_or_default()
        })
    }

    fn save(&self, list: &[Refusal]) {
        let file = RefusalFile {
            version: 1,
            refusals: list.to_vec(),
        };
        let written = serde_json::to_vec(&file)
            .map_err(|e| e.to_string())
            .and_then(|bytes| write_atomic(&self.path, &bytes).map_err(|e| e.to_string()));
        if let Err(e) = written {
            applog::line(format!("version refusals: saving failed: {e}"));
        }
    }

    /// The last refusal of `identity` (hex), if one is kept.
    pub fn get(&self, identity: &str) -> Option<Refusal> {
        let mut held = guard(&self.list);
        self.loaded(&mut held)
            .iter()
            .find(|r| r.identity == identity)
            .cloned()
    }

    /// Whether a refusal of `identity` is kept.
    pub fn holds(&self, identity: &IdentityPublicKey) -> bool {
        let key = hex(identity.as_bytes());
        let mut held = guard(&self.list);
        self.loaded(&mut held).iter().any(|r| r.identity == key)
    }

    /// Note a refusal of `identity`. Written only when it is new or its
    /// minors changed. Returns the refusal as kept.
    pub fn note(
        &self,
        identity: &IdentityPublicKey,
        peer_minor: u64,
        local_minor: u64,
        now: u64,
    ) -> Refusal {
        let key = hex(identity.as_bytes());
        let mut held = guard(&self.list);
        let list = self.loaded(&mut held);
        if let Some(kept) = list.iter().find(|r| {
            r.identity == key && r.peer_minor == peer_minor && r.local_minor == local_minor
        }) {
            return kept.clone();
        }
        list.retain(|r| r.identity != key);
        let refusal = Refusal {
            identity: key,
            peer_minor,
            local_minor,
            since: now,
        };
        list.push(refusal.clone());
        self.save(list);
        refusal
    }

    /// A connection with `identity` agreed a version: its refusal goes.
    /// Returns whether one was kept.
    pub fn clear(&self, identity: &IdentityPublicKey) -> bool {
        let key = hex(identity.as_bytes());
        let mut held = guard(&self.list);
        let list = self.loaded(&mut held);
        let before = list.len();
        list.retain(|r| r.identity != key);
        if list.len() == before {
            return false;
        }
        self.save(list);
        guard(&self.raised).remove(identity);
        true
    }

    /// Whether `identity` may raise `peer.incompatible` now: not within
    /// `gap` of the last time it did. Taking the turn counts as raising.
    pub fn take_turn(&self, identity: &IdentityPublicKey, now: Instant, gap: Duration) -> bool {
        let mut raised = guard(&self.raised);
        match raised.get(identity) {
            Some(last) if now.saturating_duration_since(*last) < gap => false,
            _ => {
                raised.insert(*identity, now);
                true
            }
        }
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
        store.note(&a, 1, 3, 100);
        store.note(&b, 4, 3, 100);
        // The same minors again keep the first time.
        assert_eq!(store.note(&a, 1, 3, 200).since, 100);
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
        assert!(again.clear(&a));
        assert!(!again.clear(&a));
        let third = Refusals::in_dir(&d);
        assert_eq!(third.get(&ka), None);
        assert!(third.get(&hex(b.as_bytes())).is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_device_raises_at_most_once_per_gap() {
        let store = Refusals::in_dir(&dir("turn"));
        let (a, b) = (key(), key());
        let gap = Duration::from_secs(3_600);
        let t0 = Instant::now();
        assert!(store.take_turn(&a, t0, gap));
        assert!(!store.take_turn(&a, t0 + Duration::from_secs(3_599), gap));
        assert!(store.take_turn(&b, t0, gap));
        assert!(store.take_turn(&a, t0 + gap, gap));
    }
}
