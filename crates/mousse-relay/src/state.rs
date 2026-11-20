//! The relay's state directory (spec `relay.md` sections 11 and 12).
//!
//! It holds the identity key, the public address, the authorized list and
//! the enrollment code hashes, and two locks: `relay.lock`, held by the
//! running relay so one process runs per identity, and `state.lock`, held
//! briefly by whoever reads or rewrites the lists (the relay and the
//! `enroll`, `list` and `revoke` commands). The directory and every file
//! are owner-only; every rewrite goes to a temporary file, owner-only from
//! its creation, that is synced and renamed over the old one. An identity
//! key other users can read is refused.
//!
//! No user data, payload, address or allow-set is ever written here.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use mousse_net_core::identity::SoftwareKey;
use mousse_net_core::pairing::{Route, RouteHost};
use mousse_net_core::relay::machine::{AuthorizedKey, EnrollCode};
use mousse_net_core::relay::{proof, EnrollmentLink, RelayId};
use mousse_net_core::time::UnixTime;
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const IDENTITY: &str = "identity.key";
const CONFIG: &str = "config.json";
const AUTHORIZED: &str = "authorized.json";
const CODES: &str = "codes.json";
const RELAY_LOCK: &str = "relay.lock";
const STATE_LOCK: &str = "state.lock";

/// A state directory problem.
#[derive(Debug)]
pub enum StateError {
    /// `init` on a directory that already has an identity.
    AlreadyInitialized(PathBuf),
    /// No identity: run `mousse-relay init` first.
    NotInitialized(PathBuf),
    /// Another relay process holds this directory.
    Running(PathBuf),
    /// The public address is not `host:port` as a `tcp` route hint.
    BadAddress(String),
    /// A file could not be read, parsed or written.
    Io(PathBuf, io::Error),
    /// A file's contents are not valid.
    Corrupt(PathBuf, String),
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyInitialized(p) => {
                write!(f, "{} already holds a relay identity", p.display())
            }
            Self::NotInitialized(p) => write!(
                f,
                "{} holds no relay identity; run `mousse-relay init` first",
                p.display()
            ),
            Self::Running(p) => write!(
                f,
                "another mousse-relay is already running with {}",
                p.display()
            ),
            Self::BadAddress(a) => write!(
                f,
                "{a:?} is not <host>:<port> (an IPv6 address in brackets)"
            ),
            Self::Io(p, e) => write!(f, "{}: {e}", p.display()),
            Self::Corrupt(p, why) => write!(f, "{}: {why}", p.display()),
        }
    }
}

impl std::error::Error for StateError {}

#[derive(Serialize, Deserialize)]
struct ConfigFile {
    /// `host:port` clients dial, as printed in enrollment links.
    public: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
struct AuthorizedEntry {
    fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    drop_at: Option<u64>,
    /// The key's `SUCCESSOR` chain, when it is not the key itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chain: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
struct CodeEntry {
    hash: String,
    expires_at: u64,
}

/// What the lists hold.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lists {
    /// The authorized list.
    pub authorized: Vec<AuthorizedKey>,
    /// Enrollment code hashes.
    pub codes: Vec<EnrollCode>,
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 32 bytes from 64 hex digits.
pub fn unhex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Parse `host:port` with the `tcp` route hint grammar (wire.md 10.2.1).
pub fn parse_public(text: &str) -> Result<(RouteHost, u16), StateError> {
    match Route::parse(&format!("tcp://{text}")) {
        Ok(Route::Tcp { host, port }) => Ok((host, port)),
        _ => Err(StateError::BadAddress(text.to_owned())),
    }
}

/// An open state directory.
#[derive(Clone, Debug)]
pub struct StateDir {
    path: PathBuf,
}

/// Held while the relay runs; dropping it releases the directory.
#[derive(Debug)]
pub struct ProcessLock(#[allow(dead_code)] File);

struct ShortLock(File);

impl Drop for ShortLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

impl StateDir {
    /// The directory at `path`, which must hold an identity.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StateError> {
        let dir = Self { path: path.into() };
        if !dir.file(IDENTITY).exists() {
            return Err(StateError::NotInitialized(dir.path));
        }
        Ok(dir)
    }

    /// Create the identity and an empty authorized list in `path`.
    pub fn init<R: CryptoRng + ?Sized>(
        path: impl Into<PathBuf>,
        public: &str,
        rng: &mut R,
    ) -> Result<Self, StateError> {
        let dir = Self { path: path.into() };
        parse_public(public)?;
        mousse_net_io::private::make_private_dir(&dir.path)
            .map_err(|e| StateError::Io(dir.path.clone(), e))?;
        if dir.file(IDENTITY).exists() {
            return Err(StateError::AlreadyInitialized(dir.path));
        }
        let _guard = dir.lock_state()?;
        let key = SoftwareKey::generate(rng);
        let text = Zeroizing::new(format!("{}\n", hex(&key.secret_bytes()[..])));
        dir.write_atomic(IDENTITY, text.as_bytes())?;
        let config = ConfigFile {
            public: public.to_owned(),
        };
        dir.write_atomic(CONFIG, &json(&config))?;
        dir.write_lists(&Lists::default())?;
        Ok(dir)
    }

    /// The directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// The relay identity key. A key file other users can read is refused.
    pub fn identity(&self) -> Result<SoftwareKey, StateError> {
        let path = self.file(IDENTITY);
        check_owner_only(&path)?;
        let text =
            Zeroizing::new(fs::read_to_string(&path).map_err(|e| StateError::Io(path.clone(), e))?);
        let secret = Zeroizing::new(
            unhex32(text.trim())
                .ok_or_else(|| StateError::Corrupt(path.clone(), "not a key".into()))?,
        );
        SoftwareKey::from_secret_bytes(&secret)
            .map_err(|_| StateError::Corrupt(path, "not a P-256 key".into()))
    }

    /// The relay id.
    pub fn relay_id(&self) -> Result<RelayId, StateError> {
        Ok(RelayId::of(&self.identity()?.public_key()))
    }

    /// The public address clients dial.
    pub fn public(&self) -> Result<(RouteHost, u16, String), StateError> {
        let path = self.file(CONFIG);
        let text = fs::read(&path).map_err(|e| StateError::Io(path.clone(), e))?;
        let config: ConfigFile =
            serde_json::from_slice(&text).map_err(|e| StateError::Corrupt(path, e.to_string()))?;
        let (host, port) = parse_public(&config.public)?;
        Ok((host, port, config.public))
    }

    /// Take the process lock, or fail if another relay holds it.
    pub fn lock_process(&self) -> Result<ProcessLock, StateError> {
        let path = self.file(RELAY_LOCK);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| StateError::Io(path.clone(), e))?;
        match file.try_lock() {
            Ok(()) => Ok(ProcessLock(file)),
            Err(fs::TryLockError::WouldBlock) => Err(StateError::Running(self.path.clone())),
            Err(fs::TryLockError::Error(e)) => Err(StateError::Io(path, e)),
        }
    }

    /// Whether a relay process holds this directory now.
    pub fn running(&self) -> bool {
        matches!(self.lock_process(), Err(StateError::Running(_)))
    }

    fn lock_state(&self) -> Result<ShortLock, StateError> {
        let path = self.file(STATE_LOCK);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| StateError::Io(path.clone(), e))?;
        file.lock().map_err(|e| StateError::Io(path, e))?;
        Ok(ShortLock(file))
    }

    /// Read the lists.
    pub fn read(&self) -> Result<Lists, StateError> {
        let _guard = self.lock_state()?;
        self.read_lists()
    }

    /// Read, change and write the lists under the state lock. Expired
    /// enrollment codes are dropped on the way (`now`).
    pub fn update<T>(
        &self,
        now: UnixTime,
        change: impl FnOnce(&mut Lists) -> T,
    ) -> Result<T, StateError> {
        let _guard = self.lock_state()?;
        let mut lists = self.read_lists()?;
        let out = change(&mut lists);
        lists.codes.retain(|c| c.expires_at > now);
        self.write_lists(&lists)?;
        Ok(out)
    }

    /// A new single-use enrollment link, valid for `lifetime_secs`.
    pub fn enroll<R: CryptoRng + ?Sized>(
        &self,
        now: UnixTime,
        lifetime_secs: u64,
        rng: &mut R,
    ) -> Result<EnrollmentLink, StateError> {
        let (host, port, _) = self.public()?;
        let relay = self.relay_id()?;
        let mut code = [0u8; 16];
        rng.fill_bytes(&mut code);
        self.update(now, |l| {
            l.codes.push(EnrollCode {
                hash: proof::code_hash(&code),
                expires_at: now.plus(lifetime_secs),
            })
        })?;
        Ok(EnrollmentLink {
            host,
            port,
            relay,
            code,
        })
    }

    /// Remove a key and every key of its `SUCCESSOR` chain from the
    /// authorized list. Returns how many keys left it.
    pub fn revoke(&self, now: UnixTime, fingerprint: &[u8; 32]) -> Result<usize, StateError> {
        self.update(now, |l| {
            let before = l.authorized.len();
            let chain = l
                .authorized
                .iter()
                .find(|k| &k.fingerprint == fingerprint)
                .map_or(*fingerprint, |k| k.chain);
            l.authorized
                .retain(|k| &k.fingerprint != fingerprint && k.chain != chain);
            before - l.authorized.len()
        })
    }

    fn read_lists(&self) -> Result<Lists, StateError> {
        let path = self.file(AUTHORIZED);
        let authorized: Vec<AuthorizedEntry> = read_json(&path)?;
        let authorized = authorized
            .into_iter()
            .map(|e| {
                let bad = || StateError::Corrupt(path.clone(), "bad fingerprint".into());
                let fingerprint = unhex32(&e.fingerprint).ok_or_else(bad)?;
                let chain = match &e.chain {
                    Some(c) => unhex32(c).ok_or_else(bad)?,
                    None => fingerprint,
                };
                Ok(AuthorizedKey {
                    fingerprint,
                    drop_at: e.drop_at.map(UnixTime),
                    chain,
                })
            })
            .collect::<Result<Vec<_>, StateError>>()?;
        let path = self.file(CODES);
        let codes: Vec<CodeEntry> = read_json(&path)?;
        let codes = codes
            .into_iter()
            .map(|e| {
                Ok(EnrollCode {
                    hash: unhex32(&e.hash)
                        .ok_or_else(|| StateError::Corrupt(path.clone(), "bad code hash".into()))?,
                    expires_at: UnixTime(e.expires_at),
                })
            })
            .collect::<Result<Vec<_>, StateError>>()?;
        Ok(Lists { authorized, codes })
    }

    fn write_lists(&self, lists: &Lists) -> Result<(), StateError> {
        let authorized: Vec<AuthorizedEntry> = lists
            .authorized
            .iter()
            .map(|k| AuthorizedEntry {
                fingerprint: hex(&k.fingerprint),
                drop_at: k.drop_at.map(|t| t.0),
                chain: (k.chain != k.fingerprint).then(|| hex(&k.chain)),
            })
            .collect();
        let codes: Vec<CodeEntry> = lists
            .codes
            .iter()
            .map(|c| CodeEntry {
                hash: hex(&c.hash),
                expires_at: c.expires_at.0,
            })
            .collect();
        self.write_atomic(AUTHORIZED, &json(&authorized))?;
        self.write_atomic(CODES, &json(&codes))
    }

    /// Owner-only from creation, then renamed over `name`.
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), StateError> {
        let path = self.file(name);
        mousse_net_io::store::write_atomic(&path, bytes)
            .map_err(|e| StateError::Io(path.clone(), io::Error::other(e.to_string())))
    }

    /// Under the `relay-persist-allow-set` control only: a file of stale
    /// allow-sets, one per handle (the first ever pushed).
    #[cfg(mousse_control = "relay-persist-allow-set")]
    pub fn control_allow_sets_path(&self) -> PathBuf {
        self.file("allow-sets.control.json")
    }
}

fn json<T: Serialize>(value: &T) -> Vec<u8> {
    let mut v = serde_json::to_vec_pretty(value).expect("serializable");
    v.push(b'\n');
    v
}

fn read_json<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T, StateError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| StateError::Corrupt(path.to_owned(), e.to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(StateError::Io(path.to_owned(), e)),
    }
}

/// A secret file must be a plain file only its owner can read (Unix).
fn check_owner_only(path: &Path) -> Result<(), StateError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(path).map_err(|e| StateError::Io(path.to_owned(), e))?;
        if !meta.file_type().is_file() {
            return Err(StateError::Corrupt(
                path.to_owned(),
                "not a plain file".into(),
            ));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(StateError::Corrupt(
                path.to_owned(),
                format!(
                    "other users can read it (mode {:o}); make it 0600",
                    meta.mode() & 0o777
                ),
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn temp_dir(tag: &str) -> PathBuf {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).unwrap();
        std::env::temp_dir().join(format!("mousse-relay-{tag}-{}", hex(&bytes)))
    }

    #[test]
    fn init_enroll_revoke_and_one_process() {
        let path = temp_dir("state");
        let mut rng = crate::os_rng();
        let dir = StateDir::init(&path, "203.0.113.5:443", &mut rng).unwrap();
        assert!(matches!(
            StateDir::init(&path, "203.0.113.5:443", &mut rng),
            Err(StateError::AlreadyInitialized(_))
        ));
        assert!(StateDir::init(temp_dir("bad"), "203.0.113.5", &mut rng).is_err());
        let now = UnixTime(1_790_000_000);
        let link = dir.enroll(now, 3_600, &mut rng).unwrap();
        assert_eq!(link.relay, dir.relay_id().unwrap());
        assert_eq!(link.authority(), "203.0.113.5:443");
        let lists = dir.read().unwrap();
        assert_eq!(lists.codes.len(), 1);
        assert_eq!(lists.codes[0].hash, proof::code_hash(&link.code));
        // Expired codes go on the next write.
        dir.update(now.plus(3_600), |_| ()).unwrap();
        assert!(dir.read().unwrap().codes.is_empty());
        dir.update(now, |l| l.authorized.push(AuthorizedKey::listed([7; 32])))
            .unwrap();
        assert_eq!(dir.revoke(now, &[7; 32]).unwrap(), 1);
        assert_eq!(dir.revoke(now, &[7; 32]).unwrap(), 0);
        // A revoke takes the key's whole SUCCESSOR chain, from any member.
        dir.update(now, |l| {
            l.authorized.push(AuthorizedKey {
                fingerprint: [1; 32],
                drop_at: Some(now.plus(60)),
                chain: [1; 32],
            });
            l.authorized.push(AuthorizedKey {
                fingerprint: [2; 32],
                drop_at: None,
                chain: [1; 32],
            });
            l.authorized.push(AuthorizedKey::listed([3; 32]));
        })
        .unwrap();
        assert_eq!(dir.read().unwrap().authorized[1].chain, [1; 32]);
        assert_eq!(dir.revoke(now, &[2; 32]).unwrap(), 2);
        assert_eq!(
            dir.read().unwrap().authorized,
            vec![AuthorizedKey::listed([3; 32])]
        );
        let held = dir.lock_process().unwrap();
        assert!(dir.running());
        assert!(matches!(dir.lock_process(), Err(StateError::Running(_))));
        drop(held);
        assert!(!dir.running());
        let _ = fs::remove_dir_all(&path);
    }

    /// The identity key is written owner-only, and a key file other users
    /// can read is refused on load.
    #[cfg(unix)]
    #[test]
    fn identity_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_dir("mode");
        let dir = StateDir::init(&path, "203.0.113.5:443", &mut crate::os_rng()).unwrap();
        let key = path.join(IDENTITY);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&key), 0o600);
        assert_eq!(mode(&path), 0o700);
        for name in [CONFIG, AUTHORIZED, CODES] {
            assert_eq!(mode(&path.join(name)), 0o600, "{name}");
        }
        assert!(dir.identity().is_ok());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(dir.identity(), Err(StateError::Corrupt(..))));
        let _ = fs::remove_dir_all(&path);
    }
}
