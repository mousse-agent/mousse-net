//! The helper's relay state files (Phase 3 §B.4, §B.5, §B.11, §B.12), all
//! in the endpoint's private state folder and written with `write_atomic`.
//! No relay secret is in them in the clear: keys and this host's pair
//! secrets are derived from the relay seed (kept where the identity is
//! kept) with the salts stored here, and the two secrets a caller is given
//! (a host's pair secret, a ticket's invitation tag) are sealed under a key
//! derived from the same seed.
//!
//! - `relays.json`: this computer's own relays (pasted enrollment links):
//!   endpoint, relay id and key, the registration key's salt, old salts
//!   kept through a rotation's overlap, a rotation the relay has not taken
//!   yet, and the manifest sequence.
//! - `relay-grants.json` (host): per grant, the caller key fingerprint and
//!   the pair secret's salt from `mousse-keys`; and the recovery entries of
//!   consumed relay invitations (§B.7).
//! - `relay-peers.json` (caller): per paired host, the caller key's salt,
//!   the pair secret it sent (sealed), its newest manifest, the relay hints
//!   its ticket carried, and the ticket's invitation tag (sealed) until
//!   `mousse-keys` is answered.
//!
//! Relay approvals are Phase 1b's (`approvals.json`, `ApprovalStore`), with
//! `relay://host:port` destinations and the `manifest` source.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use mousse_net_io::store::{unhex, write_atomic};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// An old registration key kept through a rotation's overlap.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OldKey {
    /// Its salt (hex).
    pub salt: String,
    /// When it leaves the manifest and stops registering.
    pub until: u64,
}

/// A rotation the relay has not taken yet (§B.4): journaled before the
/// first `SUCCESSOR` is sent, and kept until the new key registers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingKey {
    /// The new key's salt (hex).
    pub salt: String,
    /// When the rotation started, before any `SUCCESSOR`: the relay's
    /// overlap for the old key starts no earlier.
    pub since: u64,
    /// `relay.rotate {cancel}`: no more `SUCCESSOR`s. The key is dropped
    /// once the relay refuses it, which shows no `SUCCESSOR` was taken; if
    /// one was, the key registers and the rotation completes after all.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cancelled: bool,
}

/// One of this computer's own relays.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnRelay {
    /// `host:port`.
    pub endpoint: String,
    /// The relay id (hex).
    pub relay: String,
    /// The relay's identity key (hex SEC1), from its pinned certificate.
    pub relay_key: Option<String>,
    /// The current registration key's salt (hex).
    pub salt: String,
    /// Keys being rotated out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub old: Vec<OldKey>,
    /// When the link was pasted.
    pub added_at: u64,
    /// When the key last changed, if ever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<u64>,
    /// A rotation under way: the current key stays until the new one
    /// registers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<PendingKey>,
    /// The relay refused the last `SUCCESSOR` as `chain_full`: it holds as
    /// many of this computer's keys as it allows.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub chain_full: bool,
    /// When the relay has dropped every key this computer rotated out, at
    /// the latest; until then a full chain stays full.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_until: Option<u64>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct RelaysFile {
    pub version: u32,
    #[serde(default)]
    pub relays: Vec<OwnRelay>,
    /// The last manifest sequence used.
    #[serde(default)]
    pub manifest_sequence: u64,
}

/// A caller key enrolled with a grant over `mousse-keys`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantKey {
    pub grant: u64,
    /// The grant's identity (hex), so a replaced grant is never matched.
    pub identity: String,
    /// The caller key's fingerprint (hex).
    pub caller: String,
    /// The pair secret's salt (hex).
    pub salt: String,
    pub at: u64,
}

/// A consumed relay invitation's tag, kept listed until the grant it made
/// has its caller key (§B.7).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Recovery {
    pub invitation: String,
    pub tag_hash: String,
    pub grant: u64,
    pub expires_at: u64,
}

#[derive(Default, Serialize, Deserialize)]
pub struct GrantsFile {
    pub version: u32,
    #[serde(default)]
    pub keys: Vec<GrantKey>,
    #[serde(default)]
    pub recovery: Vec<Recovery>,
}

/// What a caller keeps about one paired host for relays.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRelay {
    /// The host (hex SEC1).
    pub identity: String,
    /// The caller key's salt (hex).
    pub salt: String,
    /// The pair secret the host sent on `mousse-keys`, sealed (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_secret: Option<String>,
    /// The newest manifest envelope (hex) and its sequence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    #[serde(default)]
    pub sequence: u64,
    /// `relay://` hints from the ticket this device joined with.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ticket_routes: Vec<String>,
    /// The ticket's invitation tag, sealed (hex), until the host answers
    /// `mousse-keys`: the way back through the relay meanwhile (§B.7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_tag: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct PeersFile {
    pub version: u32,
    #[serde(default)]
    pub peers: Vec<PeerRelay>,
}

/// The three files of one state folder.
#[derive(Clone, Debug)]
pub struct Files {
    dir: PathBuf,
    /// Each read and each write runs alone: on Windows a file opened while
    /// it is being replaced reads as access denied.
    one: std::sync::Arc<std::sync::Mutex<()>>,
}

impl Files {
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            one: Default::default(),
        }
    }

    fn read<T: DeserializeOwned + Default>(&self, name: &str) -> Result<T, String> {
        let _one = self.one.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.dir.join(name);
        match fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(T::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    fn write<T: Serialize>(&self, name: &str, value: &T) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
        let _one = self.one.lock().unwrap_or_else(|e| e.into_inner());
        write_atomic(&self.dir.join(name), &bytes).map_err(|e| e.to_string())
    }

    pub fn relays(&self) -> Result<RelaysFile, String> {
        self.read("relays.json")
    }

    pub fn save_relays(&self, mut file: RelaysFile) -> Result<(), String> {
        file.version = 1;
        self.write("relays.json", &file)
    }

    pub fn grants(&self) -> Result<GrantsFile, String> {
        self.read("relay-grants.json")
    }

    pub fn save_grants(&self, mut file: GrantsFile) -> Result<(), String> {
        file.version = 1;
        self.write("relay-grants.json", &file)
    }

    pub fn peers(&self) -> Result<PeersFile, String> {
        self.read("relay-peers.json")
    }

    pub fn save_peers(&self, mut file: PeersFile) -> Result<(), String> {
        file.version = 1;
        self.write("relay-peers.json", &file)
    }
}

/// `N` bytes from hex, if it is that long.
pub fn fixed<const N: usize>(text: &str) -> Option<[u8; N]> {
    unhex(text).ok()?.try_into().ok()
}
