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
//! On macOS the Keychain trusts a program by its code signature. A build
//! with no stable signature (ad hoc or unsigned, so no Team ID) gets a new
//! one with every build, and the Keychain would ask the user again for every
//! item after each update. Such a build never writes to the Keychain: new
//! secrets go to owner-only files ([`KeyStorage::File`]), and a secret an
//! earlier build kept in the Keychain is read once, the first time it is
//! loaded, written to its owner-only file, and read from there from then on.
//! The identity record then says it was moved, so the relay seed, which has
//! no record of its own, is still looked for in the Keychain by any later
//! build until it has moved too; an endpoint that never used the Keychain
//! never asks it. The Keychain entry is left in place, since removing it can
//! ask the user too. A Developer ID build and other systems use the OS
//! keystore as before.
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
    /// The secret was kept in the OS keystore once and has been moved to
    /// its owner-only file. The endpoint's relay seed may still be there.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    moved_from_keystore: bool,
}

/// A loaded identity key.
pub struct StoredIdentity {
    key: SoftwareKey,
    storage: KeyStorage,
    move_failed: Option<String>,
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

    /// Why moving a keystore-held key to its owner-only file failed on this
    /// load, if it did. The key works; the move is tried again on the next
    /// load.
    pub fn move_failed(&self) -> Option<&str> {
        self.move_failed.as_deref()
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
    keystore: Keystore,
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
            keystore: Keystore::default(),
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
            keystore: Keystore::default(),
        }
    }

    #[cfg(test)]
    fn with_keystore(mut self, keystore: Keystore) -> Self {
        self.keystore = keystore;
        self
    }

    /// Whether an identity exists here.
    pub fn exists(&self) -> bool {
        self.dir.join(self.file).exists()
    }

    /// Create a new identity for the endpoint `endpoint_id`. Fails if one
    /// exists. The keystore entry is named after the endpoint, so two
    /// endpoints under one OS user get two separate keys. Where this process
    /// keeps away from the OS keystore, a keystore `storage` means
    /// [`KeyStorage::File`].
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
        let storage = match storage {
            KeyStorage::OsKeystore | KeyStorage::KeystoreOrFile if !self.keystore.in_use() => {
                KeyStorage::File
            }
            other => other,
        };
        let key = SoftwareKey::generate(&mut os_rng());
        let secret = key.secret_bytes();
        let in_keystore = |user: &str| self.keystore.set(user, secret.as_slice());
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
        self.write_file(&IdentityFile {
            version: 1,
            public_key: hex(key.public_key().as_bytes()),
            storage: storage.name().into(),
            keyring_user,
            moved_from_keystore: false,
        })?;
        Ok(StoredIdentity {
            key,
            storage,
            move_failed: None,
        })
    }

    fn write_file(&self, file: &IdentityFile) -> Result<(), NetError> {
        let bytes = serde_json::to_vec_pretty(file).map_err(|e| NetError::Store(e.to_string()))?;
        write_atomic(&self.dir.join(self.file), &bytes)
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
    ///
    /// Where this process keeps away from the OS keystore, a keystore-held
    /// secret is moved to its owner-only file and the identity then records
    /// [`KeyStorage::File`]; see [`IdentityStore::load_keystore_held`].
    pub fn load(&self, allow_insecure_file: bool) -> Result<StoredIdentity, NetError> {
        let file = self.read_file()?;
        let expected = identity_from_hex(&file.public_key)?;
        let (key, storage, move_failed) = match file.storage.as_str() {
            "os-keystore" => self.load_keystore_held(&file, &expected)?,
            "file" => (self.read_key_file(&expected)?, KeyStorage::File, None),
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
                let secret = Zeroizing::new(unhex(text.trim())?);
                (
                    key_from_secret(&secret, &expected)?,
                    KeyStorage::InsecureFile,
                    None,
                )
            }
            other => return Err(NetError::Store(format!("unknown key storage {other:?}"))),
        };
        Ok(StoredIdentity {
            key,
            storage,
            move_failed,
        })
    }

    /// The owner-only key file's key, if it is the recorded one.
    fn read_key_file(&self, expected: &IdentityPublicKey) -> Result<SoftwareKey, NetError> {
        let path = self.dir.join(self.file_key_file);
        check_owner_only(&path)?;
        let text = Zeroizing::new(
            fs::read_to_string(&path)
                .map_err(|e| NetError::Store(format!("{}: {e}", path.display())))?,
        );
        key_from_secret(&Zeroizing::new(unhex(text.trim())?), expected)
    }

    /// A keystore-held identity. Where this process keeps away from the
    /// keystore, the secret moves to its owner-only file:
    ///
    /// - An owner-only key file that already holds the recorded key (a move
    ///   cut short before the record was switched) is used, and the
    ///   keystore is not asked.
    /// - Otherwise the keystore is read this once. If it refuses, loading
    ///   fails as it always has, and nothing is written.
    /// - The key is written to the file, then the record is switched to
    ///   [`KeyStorage::File`] and marked as moved, so the relay seed is
    ///   looked for in the keystore later ([`relay_seed`]).
    ///
    /// If a write fails the key still loads, the reason is in
    /// [`StoredIdentity::move_failed`], and the move goes on at the next
    /// load.
    fn load_keystore_held(
        &self,
        file: &IdentityFile,
        expected: &IdentityPublicKey,
    ) -> Result<(SoftwareKey, KeyStorage, Option<String>), NetError> {
        let user = file
            .keyring_user
            .as_deref()
            .ok_or_else(|| NetError::Store("identity file has no keystore entry".into()))?;
        if self.keystore.in_use() {
            let key = key_from_secret(&self.keystore.get(user)?, expected)?;
            return Ok((key, KeyStorage::OsKeystore, None));
        }
        let key = match self.read_key_file(expected) {
            Ok(key) => key,
            Err(_) => {
                let key = key_from_secret(&self.keystore.get(user)?, expected)?;
                let text = Zeroizing::new(hex(key.secret_bytes().as_slice()));
                if let Err(e) = write_atomic(&self.dir.join(self.file_key_file), text.as_bytes()) {
                    return Ok((key, KeyStorage::OsKeystore, Some(e.to_string())));
                }
                key
            }
        };
        let switched = self.write_file(&IdentityFile {
            version: 1,
            public_key: file.public_key.clone(),
            storage: KeyStorage::File.name().into(),
            keyring_user: None,
            moved_from_keystore: true,
        });
        Ok((key, KeyStorage::File, switched.err().map(|e| e.to_string())))
    }

    /// Delete the identity: the keystore entry and the files. Where this
    /// process keeps away from the OS keystore, an entry there is left in
    /// place, since removing it can ask the user.
    pub fn delete(&self) -> Result<(), NetError> {
        let file = self.read_file()?;
        if let Some(user) = file.keyring_user.as_deref() {
            if self.keystore.in_use() {
                self.keystore.delete(user)?;
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

/// The key of a stored secret, if it is the recorded one.
fn key_from_secret(secret: &[u8], expected: &IdentityPublicKey) -> Result<SoftwareKey, NetError> {
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
        secret
            .try_into()
            .map_err(|_| NetError::Store("identity secret has the wrong length".into()))?,
    );
    let key = SoftwareKey::from_secret_bytes(&bytes)
        .map_err(|e| NetError::Store(format!("identity secret: {e}")))?;
    if key.public_key() != *expected {
        return Err(NetError::Store(
            "identity secret does not match the recorded public key".into(),
        ));
    }
    Ok(key)
}

/// Whether the endpoint whose identity is in `dir` kept its secrets in the
/// OS keystore at some point: its identity is kept there, or was moved from
/// there. Only then can its relay seed be there.
fn kept_in_keystore(dir: &Path) -> bool {
    IdentityStore::new(dir)
        .read_file()
        .is_ok_and(|file| file.storage == "os-keystore" || file.moved_from_keystore)
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
/// a host's pair secrets are derived from it with salts kept in the
/// helper's state files, and the secrets a caller is given (a host's pair
/// secret, a ticket's invitation tag) are stored sealed under a key derived
/// from it, so no other relay secret is ever written to a plain file.
///
/// Where this process keeps away from the OS keystore, the seed is kept in
/// its owner-only file whatever `storage` says.
///
/// A seed with no file yet, for an endpoint whose identity in `dir` is kept
/// in the keystore or was moved from it, is looked for in the keystore
/// first, on any build: a seed an earlier build kept there is moved to the
/// file, and if the keystore refuses this fails rather than making a new
/// seed. An endpoint that never used the keystore never asks it.
pub fn relay_seed(
    dir: &Path,
    endpoint_id: &str,
    storage: KeyStorage,
) -> Result<Zeroizing<[u8; 32]>, NetError> {
    relay_seed_in(dir, endpoint_id, storage, &Keystore::default())
}

fn relay_seed_in(
    dir: &Path,
    endpoint_id: &str,
    storage: KeyStorage,
    keystore: &Keystore,
) -> Result<Zeroizing<[u8; 32]>, NetError> {
    let parse = |secret: &[u8]| -> Result<Zeroizing<[u8; 32]>, NetError> {
        let bytes: [u8; 32] = secret
            .try_into()
            .map_err(|_| NetError::Store("the relay seed has the wrong length".into()))?;
        Ok(Zeroizing::new(bytes))
    };
    let user = relay_seed_user(endpoint_id);
    match storage {
        KeyStorage::OsKeystore | KeyStorage::KeystoreOrFile if keystore.in_use() => {
            match keystore.get_if_any(&user)? {
                Some(secret) => parse(&secret),
                None => {
                    let seed = Zeroizing::new(random_bytes::<32>());
                    keystore.set(&user, seed.as_slice())?;
                    Ok(seed)
                }
            }
        }
        _ => {
            let insecure = storage == KeyStorage::InsecureFile;
            let path = dir.join(RELAY_SEED_FILE);
            if !insecure && path.exists() {
                check_owner_only(&path)?;
            }
            match fs::read_to_string(&path) {
                Ok(text) => {
                    let text = Zeroizing::new(text);
                    parse(&Zeroizing::new(unhex(text.trim())?))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let earlier = if !insecure && kept_in_keystore(dir) {
                        keystore.get_if_any(&user)?
                    } else {
                        None
                    };
                    let seed = match earlier {
                        Some(secret) => parse(&secret)?,
                        None => Zeroizing::new(random_bytes::<32>()),
                    };
                    let text = Zeroizing::new(hex(seed.as_slice()));
                    write_atomic(&path, text.as_bytes())?;
                    Ok(seed)
                }
                Err(e) => Err(NetError::Store(format!("{}: {e}", path.display()))),
            }
        }
    }
}

/// The OS keystore as the stores reach it, and whether this process uses
/// it. Tests put a stand-in here, or make one the default for their thread.
#[derive(Clone, Debug)]
struct Keystore {
    #[cfg(test)]
    fake: Option<std::sync::Arc<tests::FakeKeystore>>,
}

// Outside tests there is nothing to fill in, but the tests' default isn't empty.
#[cfg_attr(not(test), allow(clippy::derivable_impls))]
impl Default for Keystore {
    fn default() -> Self {
        Self {
            #[cfg(test)]
            fake: tests::THREAD_KEYSTORE.with(|fake| fake.borrow().clone()),
        }
    }
}

impl Keystore {
    /// Whether this process keeps secrets in the OS keystore. False on a
    /// macOS build with no stable signature, which keeps them in owner-only
    /// files instead. A build without the keystore says true, so asking
    /// for it fails as before.
    fn in_use(&self) -> bool {
        #[cfg(test)]
        if let Some(fake) = &self.fake {
            return fake.trusted();
        }
        !(cfg!(feature = "os-keystore") && platform_avoids_keystore())
    }

    fn set(&self, user: &str, secret: &[u8]) -> Result<(), NetError> {
        #[cfg(test)]
        if let Some(fake) = &self.fake {
            return fake.set(user, secret);
        }
        os_keystore::set(user, secret)
    }

    fn get(&self, user: &str) -> Result<Zeroizing<Vec<u8>>, NetError> {
        #[cfg(test)]
        if let Some(fake) = &self.fake {
            return fake.get(user);
        }
        os_keystore::get(user)
    }

    fn get_if_any(&self, user: &str) -> Result<Option<Zeroizing<Vec<u8>>>, NetError> {
        #[cfg(test)]
        if let Some(fake) = &self.fake {
            return fake.get_if_any(user);
        }
        os_keystore::get_if_any(user)
    }

    fn delete(&self, user: &str) -> Result<(), NetError> {
        #[cfg(test)]
        if let Some(fake) = &self.fake {
            return fake.delete(user);
        }
        os_keystore::delete(user)
    }
}

/// Whether the running program keeps away from the OS keystore: on macOS,
/// when it has no stable code signature, checked once per process.
#[cfg(target_os = "macos")]
fn platform_avoids_keystore() -> bool {
    static AVOIDS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVOIDS.get_or_init(|| !signed_with_stable_identity())
}

#[cfg(not(target_os = "macos"))]
fn platform_avoids_keystore() -> bool {
    false
}

/// Whether the running executable has a stable signature, as `codesign`
/// reports it. If `codesign` can't be run or doesn't answer within five
/// seconds, the answer is yes, which keeps the keystore as before.
#[cfg(target_os = "macos")]
fn signed_with_stable_identity() -> bool {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let Ok(exe) = std::env::current_exe() else {
        return true;
    };
    let Ok(mut child) = Command::new("/usr/bin/codesign")
        .args(["--display", "--verbose=2"])
        .arg(&exe)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    else {
        return true;
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return true;
            }
        }
    }
    // The report is a few hundred bytes, well within a pipe's buffer.
    let mut details = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut details);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut details);
    }
    stable_mac_signature(&details)
}

/// Whether `codesign --display --verbose=2` output shows a stable signature:
/// one with a Team ID, or any signature that is neither ad hoc nor missing.
/// An ad hoc signature names the exact binary, so it changes every build.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn stable_mac_signature(details: &str) -> bool {
    let team = details
        .lines()
        .find_map(|line| line.trim().strip_prefix("TeamIdentifier="));
    if team.is_some_and(|team| team != "not set") {
        return true;
    }
    !(details.lines().any(|line| line.trim() == "Signature=adhoc")
        || details.contains("code object is not signed at all"))
}

/// A secret as it is written to the OS keystore: lowercase hex text.
///
/// The keystore client hands every secret to the Linux Secret Service
/// labelled `text/plain`, and KWallet 6.31 and later refuse a `text/plain`
/// secret that is not valid UTF-8, which 32 random bytes almost never are.
/// Hex is valid text everywhere, so the same form is used on every system.
#[cfg_attr(not(feature = "os-keystore"), allow(dead_code))]
fn keystore_text(secret: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(hex(secret))
}

/// A secret read back from the OS keystore: hex text as [`keystore_text`]
/// writes it, or the raw bytes an earlier build wrote. The secrets kept
/// there are 32 bytes, so a raw one is never 64 hex digits.
#[cfg_attr(not(feature = "os-keystore"), allow(dead_code))]
fn keystore_secret(stored: &[u8]) -> Zeroizing<Vec<u8>> {
    let as_text = std::str::from_utf8(stored)
        .ok()
        .filter(|text| text.len() == 64)
        .and_then(|text| unhex(text).ok());
    Zeroizing::new(as_text.unwrap_or_else(|| stored.to_vec()))
}

/// The OS keystore, when this build has one (feature `os-keystore`, on by
/// default). The relay builds without it: it keeps no endpoint identity,
/// and a static Linux build cannot link the Secret Service client.
#[cfg(feature = "os-keystore")]
mod os_keystore {
    use super::{keystore_secret, keystore_text, NetError, KEYRING_SERVICE};
    use zeroize::Zeroizing;

    fn entry(user: &str) -> Result<keyring::Entry, NetError> {
        keyring::Entry::new(KEYRING_SERVICE, user)
            .map_err(|e| NetError::Store(format!("keystore: {e}")))
    }

    pub fn set(user: &str, secret: &[u8]) -> Result<(), NetError> {
        entry(user)?
            .set_secret(keystore_text(secret).as_bytes())
            .map_err(|e| NetError::Store(format!("keystore: {e}")))
    }

    pub fn get(user: &str) -> Result<Zeroizing<Vec<u8>>, NetError> {
        let stored = Zeroizing::new(
            entry(user)?
                .get_secret()
                .map_err(|e| NetError::Store(format!("keystore: {e}")))?,
        );
        Ok(keystore_secret(&stored))
    }

    /// The secret, or `None` when there is no entry.
    pub fn get_if_any(user: &str) -> Result<Option<Zeroizing<Vec<u8>>>, NetError> {
        match entry(user)?.get_secret() {
            Ok(stored) => Ok(Some(keystore_secret(&Zeroizing::new(stored)))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(NetError::Store(format!("keystore: {e}"))),
        }
    }

    pub fn delete(user: &str) -> Result<(), NetError> {
        match entry(user)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(NetError::Store(format!("keystore: {e}"))),
        }
    }
}

#[cfg(not(feature = "os-keystore"))]
mod os_keystore {
    use super::NetError;
    use zeroize::Zeroizing;

    fn none() -> NetError {
        NetError::Store("keystore: this build has no OS keystore".into())
    }

    pub fn set(_user: &str, _secret: &[u8]) -> Result<(), NetError> {
        Err(none())
    }

    pub fn get(_user: &str) -> Result<Zeroizing<Vec<u8>>, NetError> {
        Err(none())
    }

    pub fn get_if_any(_user: &str) -> Result<Option<Zeroizing<Vec<u8>>>, NetError> {
        Err(none())
    }

    pub fn delete(_user: &str) -> Result<(), NetError> {
        Err(none())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    thread_local! {
        /// The keystore `Keystore::default()` gives on this thread, for tests
        /// that go through the public API.
        pub(super) static THREAD_KEYSTORE: RefCell<Option<Arc<FakeKeystore>>> =
            const { RefCell::new(None) };
    }

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

    /// KWallet 6.31 and later refuse a `text/plain` secret that is not
    /// valid UTF-8, and the keystore client labels every secret so.
    #[test]
    fn keystore_secrets_are_written_as_text_and_read_back() {
        let mut not_text = 0;
        for _ in 0..64 {
            let secret = random_bytes::<32>();
            not_text += usize::from(std::str::from_utf8(&secret).is_err());
            let stored = keystore_text(&secret);
            assert!(stored.bytes().all(|b| b.is_ascii_hexdigit()));
            assert_eq!(keystore_secret(stored.as_bytes()).as_slice(), secret);
        }
        // Control: raw secrets are not text, so writing them as they are fails.
        assert!(not_text > 0);
    }

    #[test]
    fn a_raw_secret_from_an_earlier_build_still_reads() {
        let mut secret = random_bytes::<32>();
        assert_eq!(keystore_secret(&secret).as_slice(), secret);
        // Even one that happens to be ASCII hex: it is 32 bytes, not 64.
        secret.copy_from_slice(b"0123456789abcdef0123456789abcdef");
        assert_eq!(keystore_secret(&secret).as_slice(), secret);
    }

    /// A keystore in memory that counts every call, for the builds a test
    /// can't be: one with a stable signature, one without, a keystore that
    /// refuses.
    #[derive(Debug, Default)]
    pub(super) struct FakeKeystore {
        trusted: AtomicBool,
        refuse: AtomicBool,
        calls: AtomicUsize,
        entries: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl FakeKeystore {
        fn new(trusted: bool) -> Arc<Self> {
            let fake = Arc::new(Self::default());
            fake.trusted.store(trusted, Ordering::SeqCst);
            fake
        }

        fn keystore(self: &Arc<Self>) -> Keystore {
            Keystore {
                fake: Some(self.clone()),
            }
        }

        pub(super) fn trusted(&self) -> bool {
            self.trusted.load(Ordering::SeqCst)
        }

        /// The next build: same keystore, other signature.
        fn update_to(&self, trusted: bool) {
            self.trusted.store(trusted, Ordering::SeqCst);
            self.calls.store(0, Ordering::SeqCst);
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn holds(&self, user: &str) -> bool {
            self.entries.lock().unwrap().contains_key(user)
        }

        fn ask(&self) -> Result<(), NetError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.refuse.load(Ordering::SeqCst) {
                return Err(NetError::Store("keystore: the user refused".into()));
            }
            Ok(())
        }

        pub(super) fn set(&self, user: &str, secret: &[u8]) -> Result<(), NetError> {
            self.ask()?;
            self.entries
                .lock()
                .unwrap()
                .insert(user.into(), secret.to_vec());
            Ok(())
        }

        pub(super) fn get(&self, user: &str) -> Result<Zeroizing<Vec<u8>>, NetError> {
            self.get_if_any(user)?
                .ok_or_else(|| NetError::Store("keystore: no entry".into()))
        }

        pub(super) fn get_if_any(
            &self,
            user: &str,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, NetError> {
            self.ask()?;
            Ok(self
                .entries
                .lock()
                .unwrap()
                .get(user)
                .map(|s| Zeroizing::new(s.clone())))
        }

        pub(super) fn delete(&self, user: &str) -> Result<(), NetError> {
            self.ask()?;
            self.entries.lock().unwrap().remove(user);
            Ok(())
        }
    }

    fn mode(path: &Path) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            0o600
        }
    }

    fn record(dir: &Path, name: &str) -> IdentityFile {
        serde_json::from_slice(&fs::read(dir.join(name)).unwrap()).unwrap()
    }

    /// The identity key and the Plus key, which share the store's code.
    fn stores(dir: &Path, keystore: &Keystore) -> [(IdentityStore, &'static str); 2] {
        [
            (
                IdentityStore::new(dir).with_keystore(keystore.clone()),
                "endpoint-ep1",
            ),
            (
                IdentityStore::plus_key(dir).with_keystore(keystore.clone()),
                "endpoint-ep1-plus",
            ),
        ]
    }

    /// `codesign --display --verbose=2` as macOS prints it for each kind of
    /// build.
    #[test]
    fn only_a_signature_that_survives_a_rebuild_counts_as_stable() {
        let rows = [
            // A nightly: linker-signed ad hoc, no Team ID.
            (
                "Executable=/Applications/Mousse.app/Contents/Resources/net-helper/mousse-helper\n\
                 Identifier=mousse-helper-55554944c40c\nFormat=Mach-O thin (arm64)\n\
                 CodeDirectory v=20400 size=1 flags=0x20002(adhoc,linker-signed) hashes=1+0 location=embedded\n\
                 Signature=adhoc\nInfo.plist=not bound\nTeamIdentifier=not set\nSealed Resources=none\n",
                false,
            ),
            // Not signed at all (Intel builds are not linker-signed).
            ("/x/mousse-helper: code object is not signed at all\n", false),
            // Developer ID.
            (
                "Identifier=mousse-helper\nAuthority=Developer ID Application: Example (ABCDE12345)\n\
                 Authority=Developer ID Certification Authority\nAuthority=Apple Root CA\n\
                 TeamIdentifier=ABCDE12345\n",
                true,
            ),
            // A certificate with no Team ID: its identity does not change
            // with the build, as the app decides it too.
            (
                "Identifier=mousse-helper\nAuthority=Local Signing\nTeamIdentifier=not set\n",
                true,
            ),
        ];
        for (details, stable) in rows {
            assert_eq!(stable_mac_signature(details), stable, "{details}");
        }
    }

    /// The real check, on this test binary: cargo leaves it ad hoc signed
    /// (Apple silicon) or unsigned (Intel), as a nightly helper is. Through
    /// the public API, a new key goes to a file.
    #[cfg(all(target_os = "macos", feature = "os-keystore"))]
    #[test]
    fn an_ad_hoc_signed_mac_build_keeps_new_keys_out_of_the_keychain() {
        assert!(!signed_with_stable_identity());
        assert!(!Keystore::default().in_use());
        let dir = temp_dir("idmac");
        let store = IdentityStore::new(&dir);
        let id = hex(&random_bytes::<16>());
        let created = store.create(KeyStorage::OsKeystore, &id).unwrap();
        if created.storage() == KeyStorage::OsKeystore {
            let _ = store.delete();
            panic!("the key went to the keychain");
        }
        assert_eq!(created.storage(), KeyStorage::File);
        assert_eq!(store.load(false).unwrap().storage(), KeyStorage::File);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn without_a_stable_signature_new_keys_go_to_owner_only_files() {
        // Rows: the storage asked for, and whether the build is trusted.
        let rows = [
            (KeyStorage::OsKeystore, false, KeyStorage::File),
            (KeyStorage::KeystoreOrFile, false, KeyStorage::File),
            (KeyStorage::File, false, KeyStorage::File),
            // Control: a Developer ID build still uses the keystore.
            (KeyStorage::OsKeystore, true, KeyStorage::OsKeystore),
            (KeyStorage::KeystoreOrFile, true, KeyStorage::OsKeystore),
        ];
        for (asked, trusted, kept) in rows {
            let fake = FakeKeystore::new(trusted);
            let dir = temp_dir("idnew");
            for (store, user) in stores(&dir, &fake.keystore()) {
                let created = store.create(asked, "ep1").unwrap();
                assert_eq!(created.storage(), kept, "{asked:?} trusted={trusted}");
                let loaded = store.load(false).unwrap();
                assert_eq!(loaded.public_key(), created.public_key());
                assert_eq!(loaded.storage(), kept);
                assert_eq!(fake.holds(user), kept == KeyStorage::OsKeystore);
                if kept == KeyStorage::File {
                    assert_eq!(mode(&dir.join(store.file_key_file)), 0o600);
                }
            }
            if !trusted {
                assert_eq!(fake.calls(), 0, "{asked:?}: the keystore was asked");
            }
            fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn a_keystore_key_moves_to_its_file_once_and_is_never_asked_for_again() {
        let fake = FakeKeystore::new(true);
        let dir = temp_dir("idmove");
        let created: Vec<_> = stores(&dir, &fake.keystore())
            .iter()
            .map(|(store, _)| store.create(KeyStorage::OsKeystore, "ep1").unwrap())
            .collect();
        fake.update_to(false);
        for ((store, user), created) in stores(&dir, &fake.keystore()).iter().zip(&created) {
            let before = fake.calls();
            let loaded = store.load(false).unwrap();
            assert_eq!(loaded.public_key(), created.public_key());
            assert_eq!(loaded.storage(), KeyStorage::File);
            assert_eq!(fake.calls(), before + 1);
            let moved = record(&dir, store.file);
            assert_eq!(moved.storage, "file");
            assert_eq!(moved.keyring_user, None);
            assert!(moved.moved_from_keystore);
            assert_eq!(mode(&dir.join(store.file_key_file)), 0o600);
            // Removing the entry could ask the user, so it stays.
            assert!(fake.holds(user));
            for _ in 0..3 {
                let again = store.load(false).unwrap();
                assert_eq!(again.public_key(), created.public_key());
                assert_eq!(again.storage(), KeyStorage::File);
            }
            assert_eq!(fake.calls(), before + 1, "asked again after the move");
        }
        // A Developer ID build later reads the file and leaves it there.
        fake.update_to(true);
        for (store, _) in stores(&dir, &fake.keystore()) {
            assert_eq!(store.load(false).unwrap().storage(), KeyStorage::File);
        }
        assert_eq!(fake.calls(), 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_keystore_key_that_cant_be_read_fails_the_load_and_changes_nothing() {
        // Rows: the keystore refuses (denied, locked), or the entry is gone.
        for refused in [true, false] {
            let fake = FakeKeystore::new(true);
            let dir = temp_dir("idrefuse");
            let (store, user) = stores(&dir, &fake.keystore())[0].clone();
            let created = store.create(KeyStorage::OsKeystore, "ep1").unwrap();
            let entry = fake.entries.lock().unwrap().get(user).cloned().unwrap();
            let before = fs::read(dir.join(IDENTITY_FILE)).unwrap();
            fake.update_to(false);
            if refused {
                fake.refuse.store(true, Ordering::SeqCst);
            } else {
                fake.entries.lock().unwrap().remove(user);
            }
            assert!(store.load(false).is_err());
            assert_eq!(fs::read(dir.join(IDENTITY_FILE)).unwrap(), before);
            assert!(!dir.join(FILE_KEY_FILE).exists());
            // No new identity was made in its place: once the keystore
            // answers, the same key loads and moves.
            fake.refuse.store(false, Ordering::SeqCst);
            fake.entries.lock().unwrap().insert(user.into(), entry);
            let loaded = store.load(false).unwrap();
            assert_eq!(loaded.public_key(), created.public_key());
            assert_eq!(loaded.storage(), KeyStorage::File);
            fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn without_a_stable_signature_deleting_leaves_the_keystore_alone() {
        let fake = FakeKeystore::new(true);
        let dir = temp_dir("iddelete");
        let store = IdentityStore::new(&dir).with_keystore(fake.keystore());
        store.create(KeyStorage::OsKeystore, "ep1").unwrap();
        fake.update_to(false);
        store.delete().unwrap();
        assert!(!store.exists());
        assert_eq!(fake.calls(), 0);
        assert!(fake.holds("endpoint-ep1"));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// What an earlier build left in `dir` with a keystore it was trusted
    /// by: the identity key and the relay seed of endpoint `ep1` in the
    /// keystore. Returns the seed; the next build is untrusted.
    fn earlier_build_in_keystore(dir: &Path, fake: &Arc<FakeKeystore>) -> Zeroizing<[u8; 32]> {
        fake.update_to(true);
        let store = IdentityStore::new(dir).with_keystore(fake.keystore());
        store.create(KeyStorage::OsKeystore, "ep1").unwrap();
        let seed = relay_seed_in(dir, "ep1", KeyStorage::OsKeystore, &fake.keystore()).unwrap();
        fake.update_to(false);
        seed
    }

    /// Load the identity the way the helper does, and the storage it then
    /// passes for the relay seed.
    fn load_identity(dir: &Path, fake: &Arc<FakeKeystore>) -> KeyStorage {
        IdentityStore::new(dir)
            .with_keystore(fake.keystore())
            .load(false)
            .unwrap()
            .storage()
    }

    #[test]
    fn the_relay_seed_moves_to_its_file_once() {
        let fake = FakeKeystore::new(true);
        let dir = temp_dir("seedmove");
        let earlier = earlier_build_in_keystore(&dir, &fake);
        let storage = load_identity(&dir, &fake);
        assert_eq!(storage, KeyStorage::File);
        let after_identity = fake.calls();
        for _ in 0..3 {
            let seed = relay_seed_in(&dir, "ep1", storage, &fake.keystore()).unwrap();
            assert_eq!(seed.as_slice(), earlier.as_slice());
        }
        assert_eq!(fake.calls(), after_identity + 1);
        assert_eq!(mode(&dir.join(RELAY_SEED_FILE)), 0o600);
        assert!(fake.holds(&relay_seed_user("ep1")));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The identity moved on an unsigned build but the seed did not: the user
    /// refused the seed's prompt, or only a command that never reads the
    /// seed ran. A later build, unsigned or Developer ID, must still find the
    /// seed in the keystore, not make a new one.
    #[test]
    fn a_seed_left_in_the_keystore_after_the_identity_moved_is_never_replaced() {
        // Rows: (the seed's prompt was refused on the unsigned build, the
        // later build is trusted).
        for (refused, later_trusted) in [(true, true), (true, false), (false, true), (false, false)]
        {
            let fake = FakeKeystore::new(true);
            let dir = temp_dir("seedleft");
            let earlier = earlier_build_in_keystore(&dir, &fake);
            assert_eq!(load_identity(&dir, &fake), KeyStorage::File);
            if refused {
                fake.refuse.store(true, Ordering::SeqCst);
                assert!(relay_seed_in(&dir, "ep1", KeyStorage::File, &fake.keystore()).is_err());
                assert!(!dir.join(RELAY_SEED_FILE).exists());
                fake.refuse.store(false, Ordering::SeqCst);
            }
            fake.update_to(later_trusted);
            let storage = load_identity(&dir, &fake);
            assert_eq!(storage, KeyStorage::File);
            let seed = relay_seed_in(&dir, "ep1", storage, &fake.keystore()).unwrap();
            assert_eq!(
                seed.as_slice(),
                earlier.as_slice(),
                "refused={refused} later_trusted={later_trusted}"
            );
            fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn a_relay_seed_is_looked_for_in_the_keystore_only_if_the_endpoint_used_it() {
        // Rows: (the identity record, trusted, storage passed) -> keystore
        // calls for the seed. No seed is in the keystore, so one is made in
        // the file either way. (macOS doesn't ask about an entry that isn't
        // there; a locked keychain would, so an endpoint that never used the
        // keystore must not look.)
        #[derive(Clone, Copy, Debug)]
        enum Record {
            None,
            File,
            Moved,
            InKeystore,
        }
        let rows = [
            (Record::File, false, KeyStorage::File, 0),
            (Record::File, true, KeyStorage::File, 0),
            (Record::None, false, KeyStorage::OsKeystore, 0),
            (Record::None, false, KeyStorage::File, 0),
            (Record::File, false, KeyStorage::InsecureFile, 0),
            (Record::Moved, false, KeyStorage::File, 1),
            (Record::Moved, true, KeyStorage::File, 1),
            // A move whose record write failed still says os-keystore.
            (Record::InKeystore, false, KeyStorage::OsKeystore, 1),
        ];
        for (record, trusted, asked, calls) in rows {
            let fake = FakeKeystore::new(true);
            let dir = temp_dir("seednew");
            let store = IdentityStore::new(&dir).with_keystore(fake.keystore());
            match record {
                Record::None => {}
                Record::File => drop(store.create(KeyStorage::File, "ep1").unwrap()),
                Record::Moved | Record::InKeystore => {
                    store.create(KeyStorage::OsKeystore, "ep1").unwrap();
                }
            }
            if let Record::Moved = record {
                fake.update_to(false);
                store.load(false).unwrap();
            }
            fake.update_to(trusted);
            let made = relay_seed_in(&dir, "ep1", asked, &fake.keystore()).unwrap();
            let again = relay_seed_in(&dir, "ep1", asked, &fake.keystore()).unwrap();
            assert_eq!(made.as_slice(), again.as_slice());
            assert_eq!(
                fake.calls(),
                calls,
                "{record:?} trusted={trusted} {asked:?}"
            );
            assert!(!fake.holds(&relay_seed_user("ep1")));
            assert!(dir.join(RELAY_SEED_FILE).exists());
            fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// A move cut short after the key file was written (a crash, or the
    /// record write failed): the next load uses the file and does not ask the
    /// keystore, so a refusal then can't block a key that is on disk.
    #[test]
    fn a_move_cut_short_finishes_from_the_key_file_without_the_keystore() {
        let fake = FakeKeystore::new(true);
        let dir = temp_dir("idcut");
        let store = IdentityStore::new(&dir).with_keystore(fake.keystore());
        let created = store.create(KeyStorage::OsKeystore, "ep1").unwrap();
        // The key file as the move writes it, the record not yet switched.
        write_atomic(
            &dir.join(FILE_KEY_FILE),
            hex(created.software_key().secret_bytes().as_slice()).as_bytes(),
        )
        .unwrap();
        fake.update_to(false);
        fake.refuse.store(true, Ordering::SeqCst);
        let loaded = store.load(false).unwrap();
        assert_eq!(loaded.public_key(), created.public_key());
        assert_eq!(loaded.storage(), KeyStorage::File);
        assert_eq!(loaded.move_failed(), None);
        assert_eq!(fake.calls(), 0);
        let switched = record(&dir, IDENTITY_FILE);
        assert_eq!(switched.storage, "file");
        assert!(switched.moved_from_keystore);

        // Control: a key file with another key is not used; the keystore is
        // asked, and its refusal fails the load.
        let other = SoftwareKey::generate(&mut os_rng());
        let dir2 = temp_dir("idcut2");
        let store2 = IdentityStore::new(&dir2).with_keystore(fake.keystore());
        fake.update_to(true);
        fake.refuse.store(false, Ordering::SeqCst);
        store2.create(KeyStorage::OsKeystore, "ep2").unwrap();
        write_atomic(
            &dir2.join(FILE_KEY_FILE),
            hex(other.secret_bytes().as_slice()).as_bytes(),
        )
        .unwrap();
        fake.update_to(false);
        fake.refuse.store(true, Ordering::SeqCst);
        assert!(store2.load(false).is_err());
        assert_eq!(fake.calls(), 1);
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&dir2).unwrap();
    }

    /// The record can't be switched (here: the state folder is read-only):
    /// the key still loads and says why the move failed, and the next load
    /// finishes it without asking the keystore again.
    #[cfg(unix)]
    #[test]
    fn a_record_that_cant_be_switched_still_loads_and_finishes_later() {
        use std::os::unix::fs::PermissionsExt;
        let fake = FakeKeystore::new(true);
        let dir = temp_dir("idro");
        let store = IdentityStore::new(&dir).with_keystore(fake.keystore());
        let created = store.create(KeyStorage::OsKeystore, "ep1").unwrap();
        write_atomic(
            &dir.join(FILE_KEY_FILE),
            hex(created.software_key().secret_bytes().as_slice()).as_bytes(),
        )
        .unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        if fs::write(dir.join("probe"), b"").is_ok() {
            // Running as root: permissions don't stop the write.
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            fs::remove_dir_all(&dir).unwrap();
            return;
        }
        fake.update_to(false);
        let loaded = store.load(false).unwrap();
        assert_eq!(loaded.public_key(), created.public_key());
        assert!(loaded.move_failed().is_some());
        assert_eq!(record(&dir, IDENTITY_FILE).storage, "os-keystore");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fake.refuse.store(true, Ordering::SeqCst);
        let again = store.load(false).unwrap();
        assert_eq!(again.storage(), KeyStorage::File);
        assert_eq!(again.move_failed(), None);
        assert_eq!(record(&dir, IDENTITY_FILE).storage, "file");
        assert_eq!(fake.calls(), 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Through the endpoint, as the helper does it: `Endpoint::load_identity`,
    /// then `relay_seed` with the endpoint's folder, id and the key's
    /// storage (what `serve` hands the relay state).
    #[test]
    fn an_endpoint_moved_by_an_unsigned_build_keeps_its_relay_seed() {
        use crate::endpoint::Endpoint;
        let fake = FakeKeystore::new(true);
        THREAD_KEYSTORE.with(|k| *k.borrow_mut() = Some(fake.clone()));
        let dir = temp_dir("epmove");
        let (endpoint, key) = Endpoint::create(&dir, None, KeyStorage::OsKeystore).unwrap();
        let id = endpoint.endpoint_id().to_owned();
        assert_eq!(key.storage(), KeyStorage::OsKeystore);
        let earlier = relay_seed(endpoint.dir(), &id, key.storage()).unwrap();
        drop(endpoint);

        // An unsigned build moves the identity; its seed prompt is refused.
        fake.update_to(false);
        let endpoint = Endpoint::open(&dir).unwrap();
        let key = endpoint.load_identity(false).unwrap();
        assert_eq!(key.storage(), KeyStorage::File);
        fake.refuse.store(true, Ordering::SeqCst);
        assert!(relay_seed(endpoint.dir(), &id, key.storage()).is_err());
        fake.refuse.store(false, Ordering::SeqCst);
        drop(endpoint);

        // A Developer ID build later: same identity, same seed.
        fake.update_to(true);
        let endpoint = Endpoint::open(&dir).unwrap();
        let key = endpoint.load_identity(false).unwrap();
        let seed = relay_seed(endpoint.dir(), &id, key.storage()).unwrap();
        assert_eq!(seed.as_slice(), earlier.as_slice());
        drop(endpoint);
        THREAD_KEYSTORE.with(|k| *k.borrow_mut() = None);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// With this Mac's real Keychain: a key and a relay seed an earlier build
    /// kept there move to their files on first use, and keep working once
    /// the entries are gone. The test binary writes the entries itself, so
    /// the Keychain trusts it and nothing asks the user; it removes them at
    /// the end. Run by hand on a Mac:
    /// `cargo test -p mousse-net-io -- --ignored keychain_secrets_move`.
    #[cfg(all(target_os = "macos", feature = "os-keystore"))]
    #[test]
    #[ignore]
    fn keychain_secrets_move_to_their_files_on_an_ad_hoc_build() {
        struct Entries(Vec<String>);
        impl Drop for Entries {
            fn drop(&mut self) {
                for user in &self.0 {
                    let _ = os_keystore::delete(user);
                }
            }
        }
        assert!(!Keystore::default().in_use());
        let dir = temp_dir("idkeychain");
        let id = hex(&random_bytes::<16>());
        let entries = Entries(vec![keyring_user(&id), relay_seed_user(&id)]);
        // What an earlier build left: both secrets in the Keychain.
        let key = SoftwareKey::generate(&mut os_rng());
        os_keystore::set(&entries.0[0], key.secret_bytes().as_slice()).unwrap();
        let seed = random_bytes::<32>();
        os_keystore::set(&entries.0[1], &seed).unwrap();
        let store = IdentityStore::new(&dir);
        store
            .write_file(&IdentityFile {
                version: 1,
                public_key: hex(key.public_key().as_bytes()),
                storage: KeyStorage::OsKeystore.name().into(),
                keyring_user: Some(entries.0[0].clone()),
                moved_from_keystore: false,
            })
            .unwrap();

        let loaded = store.load(false).unwrap();
        assert_eq!(loaded.public_key(), key.public_key());
        assert_eq!(loaded.storage(), KeyStorage::File);
        assert_eq!(record(&dir, IDENTITY_FILE).storage, "file");
        let moved = relay_seed(&dir, &id, loaded.storage()).unwrap();
        assert_eq!(moved.as_slice(), seed);

        // From now on only the files are used.
        drop(entries);
        assert_eq!(store.load(false).unwrap().public_key(), key.public_key());
        let again = relay_seed(&dir, &id, KeyStorage::File).unwrap();
        assert_eq!(again.as_slice(), seed);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn each_endpoint_has_its_own_keystore_entry() {
        assert_eq!(keyring_user("ab12"), "endpoint-ab12");
        assert_ne!(keyring_user("a"), keyring_user("b"));
    }

    /// Writes two endpoints' entries to this machine's real keystore under
    /// one OS user, checks they stay separate, and deletes them. Run by
    /// hand: `cargo test -p mousse-net-io -- --ignored os_keystore`. A
    /// test binary on macOS has no stable signature, so it never uses the
    /// Keychain and this has nothing to check there.
    #[test]
    #[ignore]
    fn os_keystore_two_endpoints_round_trip() {
        if !Keystore::default().in_use() {
            return;
        }
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
