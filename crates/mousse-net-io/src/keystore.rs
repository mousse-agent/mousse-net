//! The device identity key on desktop.
//!
//! The key is a software P-256 key held by the operating system's keystore:
//! Windows Credential Manager (DPAPI), the macOS Keychain, or the Secret
//! Service on Linux. `identity.json` in the state directory records only the
//! public key and where the secret lives.
//!
//! [`KeyStorage::File`] keeps the secret in an owner-only (`0600`) file in the
//! state directory. It is for headless servers with no OS keystore (design
//! §B.13): chosen when the endpoint is created, it loads like a keystore key,
//! and a key file that others can read is refused.
//!
//! [`KeyStorage::InsecureFile`] keeps the secret in a plain file next to it.
//! It exists for tests, and must be asked for explicitly both when the
//! identity is created and every time it is loaded.
//!
//! The same store keeps the endpoint's **Plus key** ([`IdentityStore::plus_key`],
//! Phase 4): a separate P-256 key made when the endpoint first links to
//! Plus, so Plus never learns the identity key. It lives in `plus-key.json`
//! and the keystore entry `endpoint-<id>-plus`, kept like the identity.

use std::fs;
use std::path::{Path, PathBuf};

use mousse_net_core::identity::{
    IdentityPublicKey, IdentityRecord, IdentitySigner, RawSignature, SignerError, SoftwareKey,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::NetError;
use crate::rng::os_rng;
use crate::rng::random_bytes;
use crate::store::{hex, identity_from_hex, unhex, write_atomic};

/// Keystore service name for identity entries.
pub const KEYRING_SERVICE: &str = "mousse-net";

const IDENTITY_FILE: &str = "identity.json";
const INSECURE_KEY_FILE: &str = "identity.key";
const PLUS_FILE: &str = "plus-key.json";
const PLUS_INSECURE_FILE: &str = "plus-key.key";
const FILE_KEY_FILE: &str = "identity.secret";
const PLUS_FILE_KEY_FILE: &str = "plus-key.secret";

/// Where the identity secret is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStorage {
    /// The operating system keystore.
    OsKeystore,
    /// An owner-only file in the state directory, for headless servers
    /// with no OS keystore.
    File,
    /// A plain file in the state directory. Tests only.
    InsecureFile,
    /// When creating only: the OS keystore if it takes the key, otherwise
    /// [`KeyStorage::File`] (a headless server with no keystore). The
    /// identity records which one was used.
    KeystoreOrFile,
}

impl KeyStorage {
    fn name(self) -> &'static str {
        match self {
            KeyStorage::OsKeystore => "os-keystore",
            KeyStorage::File => "file",
            KeyStorage::InsecureFile => "insecure-file",
            KeyStorage::KeystoreOrFile => "keystore-or-file",
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

    /// The key, for a key that is not the identity key (the Plus key signs
    /// its own domain-tagged records).
    pub fn software_key(&self) -> &SoftwareKey {
        &self.key
    }
}

impl IdentitySigner for StoredIdentity {
    fn public_key(&self) -> IdentityPublicKey {
        self.key.public_key()
    }

    fn sign(&self, record: &IdentityRecord) -> Result<RawSignature, SignerError> {
        Ok(self.key.sign_raw(record.as_bytes()))
    }
}

/// The identity files of one state directory.
#[derive(Clone, Debug)]
pub struct IdentityStore {
    dir: PathBuf,
    file: &'static str,
    insecure_file: &'static str,
    file_key_file: &'static str,
    user_suffix: &'static str,
}

impl IdentityStore {
    /// The store in `dir`.
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            file: IDENTITY_FILE,
            insecure_file: INSECURE_KEY_FILE,
            file_key_file: FILE_KEY_FILE,
            user_suffix: "",
        }
    }

    /// The endpoint's Plus key in `dir` (Phase 4).
    pub fn plus_key(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            file: PLUS_FILE,
            insecure_file: PLUS_INSECURE_FILE,
            file_key_file: PLUS_FILE_KEY_FILE,
            user_suffix: "-plus",
        }
    }

    /// Whether an identity exists here.
    pub fn exists(&self) -> bool {
        self.dir.join(self.file).exists()
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
        crate::private::make_private_dir(&self.dir)
            .map_err(|e| NetError::Store(format!("{}: {e}", self.dir.display())))?;
        let key = SoftwareKey::generate(&mut os_rng());
        let secret = key.secret_bytes();
        let in_keystore = |user: &str| -> Result<(), NetError> {
            keyring_entry(user)?
                .set_secret(secret.as_slice())
                .map_err(|e| NetError::Store(format!("keystore: {e}")))
        };
        let in_file = |name: &str| -> Result<(), NetError> {
            // write_atomic makes the file owner-only before any byte.
            let text = Zeroizing::new(hex(secret.as_slice()));
            write_atomic(&self.dir.join(name), text.as_bytes())
        };
        let (storage, keyring_user) = match storage {
            KeyStorage::OsKeystore => {
                let user = format!("{}{}", keyring_user(endpoint_id), self.user_suffix);
                in_keystore(&user)?;
                (KeyStorage::OsKeystore, Some(user))
            }
            KeyStorage::KeystoreOrFile => {
                let user = format!("{}{}", keyring_user(endpoint_id), self.user_suffix);
                match in_keystore(&user) {
                    Ok(()) => (KeyStorage::OsKeystore, Some(user)),
                    Err(_) => {
                        in_file(self.file_key_file)?;
                        (KeyStorage::File, None)
                    }
                }
            }
            KeyStorage::File => {
                in_file(self.file_key_file)?;
                (KeyStorage::File, None)
            }
            KeyStorage::InsecureFile => {
                in_file(self.insecure_file)?;
                (KeyStorage::InsecureFile, None)
            }
        };
        let file = IdentityFile {
            version: 1,
            public_key: hex(key.public_key().as_bytes()),
            storage: storage.name().into(),
            keyring_user,
        };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| NetError::Store(e.to_string()))?;
        write_atomic(&self.dir.join(self.file), &bytes)?;
        Ok(StoredIdentity { key, storage })
    }

    fn read_file(&self) -> Result<IdentityFile, NetError> {
        let path = self.dir.join(self.file);
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
            "file" => {
                let path = self.dir.join(self.file_key_file);
                check_owner_only(&path)?;
                let text = Zeroizing::new(
                    fs::read_to_string(&path)
                        .map_err(|e| NetError::Store(format!("{}: {e}", path.display())))?,
                );
                (Zeroizing::new(unhex(text.trim())?), KeyStorage::File)
            }
            "insecure-file" => {
                if !allow_insecure_file {
                    return Err(NetError::Store(
                        "this identity is kept in a plain file; pass the insecure file-key flag to use it"
                            .into(),
                    ));
                }
                let path = self.dir.join(self.insecure_file);
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
        for name in [self.file, self.insecure_file, self.file_key_file] {
            let path = self.dir.join(name);
            if path.exists() {
                fs::remove_file(&path)
                    .map_err(|e| NetError::Store(format!("{}: {e}", path.display())))?;
            }
        }
        Ok(())
    }
}

/// A key file must be readable by its owner only (`0600` or stricter, as
/// `ssh` asks of a private key). On Windows the state directory's
/// owner-only DACL, inherited by the file, does this.
fn check_owner_only(path: &Path) -> Result<(), NetError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(path)
            .map_err(|e| NetError::Store(format!("{}: {e}", path.display())))?;
        if !meta.file_type().is_file() {
            return Err(NetError::Store(format!(
                "{} is not a plain file",
                path.display()
            )));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(NetError::Store(format!(
                "{} can be read by other users (mode {:o}); make it 0600",
                path.display(),
                meta.mode() & 0o777
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The keystore entry name for an endpoint.
pub fn keyring_user(endpoint_id: &str) -> String {
    format!("endpoint-{endpoint_id}")
}

/// The file of the relay seed, beside a file-kept identity (owner-only,
/// written with `write_atomic`).
const RELAY_SEED_FILE: &str = "relay-seed.key";

/// The keystore entry name of an endpoint's relay seed.
pub fn relay_seed_user(endpoint_id: &str) -> String {
    format!("relay-seed-{endpoint_id}")
}

/// The endpoint's relay seed: 32 random bytes, kept where its identity is
/// kept (`storage`), made on first use. Registration keys, caller keys and
/// pair secrets are derived from it with salts kept in the helper's state
/// files, so no other relay secret is ever written to a plain file.
pub fn relay_seed(
    dir: &Path,
    endpoint_id: &str,
    storage: KeyStorage,
) -> Result<Zeroizing<[u8; 32]>, NetError> {
    let parse = |secret: &[u8]| -> Result<Zeroizing<[u8; 32]>, NetError> {
        let bytes: [u8; 32] = secret
            .try_into()
            .map_err(|_| NetError::Store("the relay seed has the wrong length".into()))?;
        Ok(Zeroizing::new(bytes))
    };
    match storage {
        KeyStorage::OsKeystore | KeyStorage::KeystoreOrFile => {
            let entry = keyring_entry(&relay_seed_user(endpoint_id))?;
            match entry.get_secret() {
                Ok(secret) => parse(&Zeroizing::new(secret)),
                Err(keyring::Error::NoEntry) => {
                    let seed = Zeroizing::new(random_bytes::<32>());
                    entry
                        .set_secret(seed.as_slice())
                        .map_err(|e| NetError::Store(format!("keystore: {e}")))?;
                    Ok(seed)
                }
                Err(e) => Err(NetError::Store(format!("keystore: {e}"))),
            }
        }
        KeyStorage::File | KeyStorage::InsecureFile => {
            let path = dir.join(RELAY_SEED_FILE);
            if storage == KeyStorage::File && path.exists() {
                check_owner_only(&path)?;
            }
            match fs::read_to_string(&path) {
                Ok(text) => {
                    let text = Zeroizing::new(text);
                    parse(&Zeroizing::new(unhex(text.trim())?))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let seed = Zeroizing::new(random_bytes::<32>());
                    let text = Zeroizing::new(hex(seed.as_slice()));
                    write_atomic(&path, text.as_bytes())?;
                    Ok(seed)
                }
                Err(e) => Err(NetError::Store(format!("{}: {e}", path.display()))),
            }
        }
    }
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
        let pending = mousse_net_core::session_cert::PendingCertificate::new(
            mousse_net_core::session_cert::SessionKey::generate(&mut os_rng()),
            mousse_net_core::session_cert::ValidityWindow::starting_at(
                mousse_net_core::time::UnixTime(1_800_000_000),
                3_600,
            )
            .unwrap(),
        );
        let sig = loaded.sign(pending.record()).unwrap();
        created
            .public_key()
            .verify(pending.record().as_bytes(), &sig)
            .unwrap();
        store.delete().unwrap();
        assert!(!store.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_key_loads_without_the_flag_and_only_while_owner_only() {
        let dir = temp_dir("idsoft");
        let store = IdentityStore::new(&dir);
        let created = store.create(KeyStorage::File, "ep1").unwrap();
        let loaded = store.load(false).unwrap();
        assert_eq!(loaded.public_key(), created.public_key());
        assert_eq!(loaded.storage(), KeyStorage::File);
        assert!(!dir.join(INSECURE_KEY_FILE).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let key = dir.join(FILE_KEY_FILE);
            assert_eq!(
                fs::metadata(&key).unwrap().permissions().mode() & 0o777,
                0o600
            );
            fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
            let err = store.load(false).unwrap_err().to_string();
            assert!(err.contains("make it 0600"), "{err}");
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(store.load(false).is_ok());
        }
        store.delete().unwrap();
        assert!(!dir.join(FILE_KEY_FILE).exists());
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
