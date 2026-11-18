//! The device identity key on desktop.
//!
//! The key is a software P-256 key held by the operating system's keystore:
//! Windows Credential Manager (DPAPI), the macOS Keychain, or the Secret
//! Service on Linux. `identity.json` in the state directory records only the
//! public key and where the secret lives.
//!
//! [`KeyStorage::InsecureFile`] keeps the secret in a plain file next to it.
//! It exists for tests and headless runs where no keystore is reachable, and
//! must be asked for explicitly both when the identity is created and every
//! time it is loaded.

use std::fs;
use std::path::{Path, PathBuf};

use mousse_net_core::identity::{
    IdentityPublicKey, IdentitySigner, RawSignature, SignerError, SoftwareKey,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::NetError;
use crate::rng::os_rng;
#[cfg(test)]
use crate::rng::random_bytes;
use crate::store::{hex, identity_from_hex, unhex, write_atomic};

/// Keystore service name for identity entries.
pub const KEYRING_SERVICE: &str = "mousse-net";

const IDENTITY_FILE: &str = "identity.json";
const INSECURE_KEY_FILE: &str = "identity.key";

/// Where the identity secret is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStorage {
    /// The operating system keystore.
    OsKeystore,
    /// A plain file in the state directory. Tests only.
    InsecureFile,
}

impl KeyStorage {
    fn name(self) -> &'static str {
        match self {
            KeyStorage::OsKeystore => "os-keystore",
            KeyStorage::InsecureFile => "insecure-file",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    version: u32,
    public_key: String,
    storage: String,
    keyring_user: Option<String>,
}

/// A loaded identity key.
pub struct StoredIdentity {
    key: SoftwareKey,
    storage: KeyStorage,
}

impl std::fmt::Debug for StoredIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StoredIdentity({:?}, {:?})",
            self.key.public_key(),
            self.storage
        )
    }
}

impl StoredIdentity {
    /// Where the secret is kept.
    pub fn storage(&self) -> KeyStorage {
        self.storage
    }
}

impl IdentitySigner for StoredIdentity {
    fn public_key(&self) -> IdentityPublicKey {
        self.key.public_key()
    }

    fn sign(&self, message: &[u8]) -> Result<RawSignature, SignerError> {
        Ok(self.key.sign_raw(message))
    }
}

/// The identity files of one state directory.
#[derive(Clone, Debug)]
pub struct IdentityStore {
    dir: PathBuf,
}

impl IdentityStore {
    /// The store in `dir`.
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    /// Whether an identity exists here.
    pub fn exists(&self) -> bool {
        self.dir.join(IDENTITY_FILE).exists()
    }

    /// Create a new identity for the endpoint `endpoint_id`. Fails if one
    /// exists. The keystore entry is named after the endpoint, so two
    /// endpoints under one OS user get two separate keys.
    pub fn create(
        &self,
        storage: KeyStorage,
        endpoint_id: &str,
    ) -> Result<StoredIdentity, NetError> {
        if self.exists() {
            return Err(NetError::Store(format!(
                "an identity already exists in {}",
                self.dir.display()
            )));
        }
        fs::create_dir_all(&self.dir)
            .map_err(|e| NetError::Store(format!("{}: {e}", self.dir.display())))?;
        let key = SoftwareKey::generate(&mut os_rng());
        let secret = key.secret_bytes();
        let keyring_user = match storage {
            KeyStorage::OsKeystore => {
                let user = keyring_user(endpoint_id);
                keyring_entry(&user)?
                    .set_secret(secret.as_slice())
                    .map_err(|e| NetError::Store(format!("keystore: {e}")))?;
                Some(user)
            }
            KeyStorage::InsecureFile => {
                let text = Zeroizing::new(hex(secret.as_slice()));
                write_atomic(&self.dir.join(INSECURE_KEY_FILE), text.as_bytes())?;
                None
            }
        };
        let file = IdentityFile {
            version: 1,
            public_key: hex(key.public_key().as_bytes()),
            storage: storage.name().into(),
            keyring_user,
        };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| NetError::Store(e.to_string()))?;
        write_atomic(&self.dir.join(IDENTITY_FILE), &bytes)?;
        Ok(StoredIdentity { key, storage })
    }

    fn read_file(&self) -> Result<IdentityFile, NetError> {
        let path = self.dir.join(IDENTITY_FILE);
        let bytes = fs::read(&path)
            .map_err(|e| NetError::Store(format!("no identity in {} ({e})", self.dir.display())))?;
        let file: IdentityFile = serde_json::from_slice(&bytes)
            .map_err(|e| NetError::Store(format!("{}: {e}", path.display())))?;
        if file.version != 1 {
            return Err(NetError::Store("unsupported identity file version".into()));
        }
        Ok(file)
    }

    /// The public key, without touching the secret.
    pub fn public_key(&self) -> Result<IdentityPublicKey, NetError> {
        identity_from_hex(&self.read_file()?.public_key)
    }

    /// Load the identity. A plain-file identity loads only with
    /// `allow_insecure_file`.
    pub fn load(&self, allow_insecure_file: bool) -> Result<StoredIdentity, NetError> {
        let file = self.read_file()?;
        let expected = identity_from_hex(&file.public_key)?;
        let (secret, storage) = match file.storage.as_str() {
            "os-keystore" => {
                let user = file
                    .keyring_user
                    .as_deref()
                    .ok_or_else(|| NetError::Store("identity file has no keystore entry".into()))?;
                let secret = Zeroizing::new(
                    keyring_entry(user)?
                        .get_secret()
                        .map_err(|e| NetError::Store(format!("keystore: {e}")))?,
                );
                (secret, KeyStorage::OsKeystore)
            }
            "insecure-file" => {
                if !allow_insecure_file {
                    return Err(NetError::Store(
                        "this identity is kept in a plain file; pass the insecure file-key flag to use it"
                            .into(),
                    ));
                }
                let path = self.dir.join(INSECURE_KEY_FILE);
                let text = Zeroizing::new(
                    fs::read_to_string(&path)
                        .map_err(|e| NetError::Store(format!("{}: {e}", path.display())))?,
                );
                (
                    Zeroizing::new(unhex(text.trim())?),
                    KeyStorage::InsecureFile,
                )
            }
            other => return Err(NetError::Store(format!("unknown key storage {other:?}"))),
        };
        let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
            secret
                .as_slice()
                .try_into()
                .map_err(|_| NetError::Store("identity secret has the wrong length".into()))?,
        );
        let key = SoftwareKey::from_secret_bytes(&bytes)
            .map_err(|e| NetError::Store(format!("identity secret: {e}")))?;
        if key.public_key() != expected {
            return Err(NetError::Store(
                "identity secret does not match the recorded public key".into(),
            ));
        }
        Ok(StoredIdentity { key, storage })
    }

    /// Delete the identity: the keystore entry and the files.
    pub fn delete(&self) -> Result<(), NetError> {
        let file = self.read_file()?;
        if let Some(user) = file.keyring_user.as_deref() {
            match keyring_entry(user)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(e) => return Err(NetError::Store(format!("keystore: {e}"))),
            }
        }
        for name in [IDENTITY_FILE, INSECURE_KEY_FILE] {
            let path = self.dir.join(name);
            if path.exists() {
                fs::remove_file(&path)
                    .map_err(|e| NetError::Store(format!("{}: {e}", path.display())))?;
            }
        }
        Ok(())
    }
}

/// The keystore entry name for an endpoint.
pub fn keyring_user(endpoint_id: &str) -> String {
    format!("endpoint-{endpoint_id}")
}

fn keyring_entry(user: &str) -> Result<keyring::Entry, NetError> {
    keyring::Entry::new(KEYRING_SERVICE, user)
        .map_err(|e| NetError::Store(format!("keystore: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("mousse-net-io-{tag}-{}", hex(&random_bytes::<6>())));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn insecure_file_identity_needs_the_flag_every_time() {
        let dir = temp_dir("idfile");
        let store = IdentityStore::new(&dir);
        let created = store.create(KeyStorage::InsecureFile, "ep1").unwrap();
        assert!(store.create(KeyStorage::InsecureFile, "ep1").is_err());
        assert!(store.load(false).is_err());
        let loaded = store.load(true).unwrap();
        assert_eq!(loaded.public_key(), created.public_key());
        assert_eq!(store.public_key().unwrap(), created.public_key());
        let sig = loaded.sign(b"m").unwrap();
        created.public_key().verify(b"m", &sig).unwrap();
        store.delete().unwrap();
        assert!(!store.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_swapped_secret_is_refused() {
        let dir = temp_dir("idswap");
        let store = IdentityStore::new(&dir);
        store.create(KeyStorage::InsecureFile, "ep1").unwrap();
        let other = SoftwareKey::generate(&mut os_rng());
        fs::write(
            dir.join(INSECURE_KEY_FILE),
            hex(other.secret_bytes().as_slice()),
        )
        .unwrap();
        assert!(store.load(true).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn each_endpoint_has_its_own_keystore_entry() {
        assert_eq!(keyring_user("ab12"), "endpoint-ab12");
        assert_ne!(keyring_user("a"), keyring_user("b"));
    }

    /// Writes two endpoints' entries to this machine's real keystore under
    /// one OS user, checks they stay separate, and deletes them. Run by
    /// hand: `cargo test -p mousse-net-io -- --ignored os_keystore`.
    #[test]
    #[ignore]
    fn os_keystore_two_endpoints_round_trip() {
        let a_dir = temp_dir("idos-a");
        let b_dir = temp_dir("idos-b");
        let a = IdentityStore::new(&a_dir);
        let b = IdentityStore::new(&b_dir);
        let a_id = hex(&random_bytes::<16>());
        let b_id = hex(&random_bytes::<16>());
        let created_a = a.create(KeyStorage::OsKeystore, &a_id).unwrap();
        let created_b = b.create(KeyStorage::OsKeystore, &b_id).unwrap();
        assert!(!a_dir.join(INSECURE_KEY_FILE).exists());
        assert_ne!(created_a.public_key(), created_b.public_key());
        let loaded = a.load(false).unwrap();
        assert_eq!(loaded.public_key(), created_a.public_key());
        assert_eq!(loaded.storage(), KeyStorage::OsKeystore);
        a.delete().unwrap();
        assert!(IdentityStore::new(&a_dir).load(false).is_err());
        assert_eq!(b.load(false).unwrap().public_key(), created_b.public_key());
        b.delete().unwrap();
        fs::remove_dir_all(&a_dir).unwrap();
        fs::remove_dir_all(&b_dir).unwrap();
    }
}
