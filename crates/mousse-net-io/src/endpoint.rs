//! An endpoint: one Mousse profile's helper on one device.
//!
//! Each endpoint has its own state directory, identity key (its own keystore
//! entry), grant and denial table, peer pins and listener. Two profiles on
//! one computer are two endpoints; nothing here is shared between them.
//!
//! - **Lock:** an endpoint is locked in two places: a file in its state
//!   directory, and one keyed by its identity in the per-user temp
//!   directory, so a copied state directory can't run the same identity
//!   twice either. The process that runs the endpoint (its host) holds
//!   both exclusively: a second one for the same endpoint refuses to
//!   start, while another endpoint on the same machine starts normally.
//!   Short-lived caller commands (join, terminals) share the lock with
//!   each other but not with a running host. The locks go away with the
//!   process.
//! - **Port:** the first start binds a port the OS picks and keeps it in
//!   `endpoint.json`; later starts reuse it. A fixed port (for port
//!   forwarding) can be set per endpoint instead.
//! - **Profile id:** an opaque value recorded at creation. It becomes the
//!   authorizing owner of grants made here.

use std::fs::{self, File, TryLockError};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use mousse_net_core::grants::OwnerRef;
use mousse_net_core::identity::IdentityPublicKey;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::error::NetError;
use crate::keystore::{IdentityStore, KeyStorage, StoredIdentity};
use crate::rng::random_bytes;
use crate::store::{hex, write_atomic};

const ENDPOINT_FILE: &str = "endpoint.json";
const DIR_LOCK_FILE: &str = "endpoint.lock";
const ID_LOCK_DIR: &str = "mousse-net-endpoints";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct EndpointFile {
    version: u32,
    endpoint_id: String,
    profile_id: String,
    port: Option<u16>,
    fixed_port: Option<u16>,
    /// The loopback `ws` listener's kept port (Phase 1b §4.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ws_port: Option<u16>,
}

/// Which port to listen on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortChoice {
    /// The fixed port if one is set, else the kept port (a new one if it is
    /// taken), else a new one.
    Kept,
    /// Use this port from now on. Fails if it is taken.
    Fixed(u16),
    /// Drop any fixed port and let the OS pick a new one to keep.
    Auto,
}

/// A new random profile id (128 bits, hex).
pub fn new_profile_id() -> String {
    hex(&random_bytes::<16>())
}

/// The authorizing owner for grants made by `profile_id`. The one place
/// that turns the stored profile id into the core's owner value.
pub fn owner_for_profile(profile_id: &str) -> Result<OwnerRef, NetError> {
    crate::store::owner_from_hex(profile_id)
        .ok_or_else(|| NetError::Store("a profile id is 32 hex digits".into()))
}

/// The exclusive locks of an open endpoint. Released on drop.
#[derive(Debug)]
pub struct EndpointLock {
    _dir: File,
    _identity: File,
}

fn lock_file(path: &Path, shared: bool) -> Result<File, NetError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| NetError::Store(format!("{}: {e}", parent.display())))?;
    }
    let file = File::options()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|e| NetError::Store(format!("{}: {e}", path.display())))?;
    // The `no-endpoint-lock` control build (tests only) takes no lock, so a
    // second process runs the same endpoint.
    if cfg!(mousse_control = "no-endpoint-lock") {
        return Ok(file);
    }
    let locked = if shared {
        file.try_lock_shared()
    } else {
        file.try_lock()
    };
    match locked {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(NetError::Refused(
            "another process is already running this endpoint".into(),
        )),
        Err(TryLockError::Error(e)) => Err(NetError::Store(format!("{}: {e}", path.display()))),
    }
}

/// Where an endpoint's key and grant table live: its own state directory.
fn lock_file_blocking(path: &Path) -> Result<File, NetError> {
    let err = |e: std::io::Error| NetError::Store(format!("{}: {e}", path.display()));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(err)?;
    }
    let file = File::options()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(err)?;
    file.lock().map_err(err)?;
    Ok(file)
}

/// The `shared-endpoint-state` control build (tests only) puts every
/// endpoint's key and grants in one machine-wide folder instead.
fn private_state_dir(dir: &Path) -> PathBuf {
    if cfg!(mousse_control = "shared-endpoint-state") {
        std::env::temp_dir().join("mousse-net-control-shared-state")
    } else {
        dir.to_path_buf()
    }
}

fn identity_lock_path(dir: &Path, identity: &IdentityPublicKey) -> PathBuf {
    if cfg!(mousse_control = "shared-endpoint-state") {
        return dir.join("control-identity.lock");
    }
    std::env::temp_dir()
        .join(ID_LOCK_DIR)
        .join(format!("{}.lock", hex(&identity.fingerprint())))
}

/// An open endpoint. Holds its locks for as long as it lives.
#[derive(Debug)]
pub struct Endpoint {
    dir: PathBuf,
    file: EndpointFile,
    identity: IdentityPublicKey,
    shared: bool,
    _lock: EndpointLock,
}

impl Endpoint {
    /// Whether `dir` holds an endpoint.
    pub fn exists(dir: &Path) -> bool {
        dir.join(ENDPOINT_FILE).exists()
    }

    /// Create a new endpoint in `dir` with a new identity key. `profile_id`
    /// is the opaque profile id; `None` makes a new random one.
    pub fn create(
        dir: &Path,
        profile_id: Option<&str>,
        storage: KeyStorage,
    ) -> Result<(Self, StoredIdentity), NetError> {
        // Nothing in an existing folder is touched before the lock is held:
        // another process may be writing in it.
        crate::private::ensure_dir_for_lock(dir)
            .map_err(|e| NetError::Store(format!("{}: {e}", dir.display())))?;
        let dir_lock = lock_file(&dir.join(DIR_LOCK_FILE), false)?;
        crate::private::make_private_dir(dir)
            .map_err(|e| NetError::Store(format!("{}: {e}", dir.display())))?;
        if Self::exists(dir) {
            return Err(NetError::Store(format!(
                "an endpoint already exists in {}",
                dir.display()
            )));
        }
        let profile_id = match profile_id {
            Some(p) => p.to_owned(),
            None => new_profile_id(),
        };
        owner_for_profile(&profile_id)?;
        let endpoint_id = hex(&random_bytes::<16>());
        let key_store = IdentityStore::new(&private_state_dir(dir));
        let identity = if cfg!(mousse_control = "shared-endpoint-state") {
            // One process at a time creates or reuses the shared key, so
            // the control breaks separation and nothing else.
            let guard = lock_file_blocking(&private_state_dir(dir).join("create.lock"))?;
            let key = if key_store.exists() {
                key_store.load(true)?
            } else {
                key_store.create(storage, &endpoint_id)?
            };
            drop(guard);
            key
        } else {
            key_store.create(storage, &endpoint_id)?
        };
        let public = mousse_net_core::identity::IdentitySigner::public_key(&identity);
        let id_lock = lock_file(&identity_lock_path(dir, &public), false)?;
        let file = EndpointFile {
            version: 1,
            endpoint_id,
            profile_id,
            port: None,
            fixed_port: None,
            ws_port: None,
        };
        let endpoint = Self {
            dir: dir.to_path_buf(),
            file,
            identity: public,
            shared: false,
            _lock: EndpointLock {
                _dir: dir_lock,
                _identity: id_lock,
            },
        };
        endpoint.save()?;
        Ok((endpoint, identity))
    }

    /// Open the endpoint in `dir` to run it, taking its locks
    /// exclusively. Refuses if another process has it open.
    pub fn open(dir: &Path) -> Result<Self, NetError> {
        Self::open_with(dir, false)
    }

    /// Open the endpoint in `dir` for a short-lived caller command. Several
    /// may run at once, but not while the endpoint's host runs. Such an
    /// endpoint can't bind a listener or change its settings.
    pub fn open_shared(dir: &Path) -> Result<Self, NetError> {
        Self::open_with(dir, true)
    }

    fn open_with(dir: &Path, shared: bool) -> Result<Self, NetError> {
        if !Self::exists(dir) {
            return Err(NetError::Store(format!(
                "no endpoint in {} (run init first)",
                dir.display()
            )));
        }
        // Owner-only, also for a folder made before this was enforced; but
        // only once the lock is held, so a process that is refused never
        // touches files the running one is writing.
        crate::private::ensure_dir_for_lock(dir)
            .map_err(|e| NetError::Store(format!("{}: {e}", dir.display())))?;
        let dir_lock = lock_file(&dir.join(DIR_LOCK_FILE), shared)?;
        crate::private::make_private_dir(dir)
            .map_err(|e| NetError::Store(format!("{}: {e}", dir.display())))?;
        let path = dir.join(ENDPOINT_FILE);
        let bytes =
            fs::read(&path).map_err(|e| NetError::Store(format!("{}: {e}", path.display())))?;
        let file: EndpointFile = serde_json::from_slice(&bytes)
            .map_err(|e| NetError::Store(format!("{}: {e}", path.display())))?;
        if file.version != 1 {
            return Err(NetError::Store("unsupported endpoint file version".into()));
        }
        owner_for_profile(&file.profile_id)?;
        let identity = IdentityStore::new(&private_state_dir(dir)).public_key()?;
        let id_lock = lock_file(&identity_lock_path(dir, &identity), shared)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            file,
            identity,
            shared,
            _lock: EndpointLock {
                _dir: dir_lock,
                _identity: id_lock,
            },
        })
    }

    fn save(&self) -> Result<(), NetError> {
        let bytes =
            serde_json::to_vec_pretty(&self.file).map_err(|e| NetError::Store(e.to_string()))?;
        write_atomic(&self.dir.join(ENDPOINT_FILE), &bytes)
    }

    /// The state directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where this endpoint's grant table lives.
    pub fn grants_dir(&self) -> PathBuf {
        private_state_dir(&self.dir)
    }

    /// Where this endpoint keeps its joiner flow records (owner-only).
    pub fn flow_records(&self) -> crate::store::FlowRecordStore {
        crate::store::FlowRecordStore::in_dir(&private_state_dir(&self.dir))
    }

    /// This endpoint's random id (hex). Names its keystore entry.
    pub fn endpoint_id(&self) -> &str {
        &self.file.endpoint_id
    }

    /// The opaque profile id.
    pub fn profile_id(&self) -> &str {
        &self.file.profile_id
    }

    /// The authorizing owner for grants made here.
    pub fn owner(&self) -> Result<OwnerRef, NetError> {
        owner_for_profile(&self.file.profile_id)
    }

    /// The identity public key.
    pub fn identity(&self) -> IdentityPublicKey {
        self.identity
    }

    /// Load the identity key. A plain-file key loads only with
    /// `allow_insecure_file`.
    pub fn load_identity(&self, allow_insecure_file: bool) -> Result<StoredIdentity, NetError> {
        let key = IdentityStore::new(&private_state_dir(&self.dir)).load(allow_insecure_file)?;
        if mousse_net_core::identity::IdentitySigner::public_key(&key) != self.identity {
            return Err(NetError::Store("identity changed while open".into()));
        }
        Ok(key)
    }

    /// The store of this endpoint's Plus key (Phase 4), next to the
    /// identity key.
    pub fn plus_key_store(&self) -> IdentityStore {
        IdentityStore::plus_key(&private_state_dir(&self.dir))
    }

    /// The kept port, if any.
    pub fn kept_port(&self) -> Option<u16> {
        self.file.port
    }

    /// The fixed port, if one is set.
    pub fn fixed_port(&self) -> Option<u16> {
        self.file.fixed_port
    }

    /// Bind this endpoint's listener on `ip`, and keep the port it got.
    pub async fn bind(&mut self, ip: IpAddr, choice: PortChoice) -> Result<TcpListener, NetError> {
        if self.shared {
            return Err(NetError::Refused(
                "this endpoint is open for a caller command only".into(),
            ));
        }
        let before = self.file.clone();
        let listener = match choice {
            PortChoice::Fixed(port) if port != 0 => {
                self.file.fixed_port = Some(port);
                bind_exact(ip, port).await?
            }
            PortChoice::Fixed(_) | PortChoice::Auto => {
                self.file.fixed_port = None;
                bind_exact(ip, 0).await?
            }
            PortChoice::Kept => match (self.file.fixed_port, self.file.port) {
                (Some(port), _) => bind_exact(ip, port).await?,
                (None, Some(port)) => match bind_exact(ip, port).await {
                    Ok(listener) => listener,
                    Err(NetError::Io(e)) if e.kind() == io::ErrorKind::AddrInUse => {
                        bind_exact(ip, 0).await?
                    }
                    Err(e) => return Err(e),
                },
                (None, None) => bind_exact(ip, 0).await?,
            },
        };
        self.file.port = Some(listener.local_addr()?.port());
        if self.file != before {
            self.save()?;
        }
        Ok(listener)
    }
}

impl Endpoint {
    /// Bind the loopback `ws` listener (Phase 1b §4.1): on `port` if one
    /// is given (0: any), else on the kept ws port (a new one if it is
    /// taken), and keep the port it got.
    pub async fn bind_ws(&mut self, port: Option<u16>) -> Result<TcpListener, NetError> {
        if self.shared {
            return Err(NetError::Refused(
                "this endpoint is open for a caller command only".into(),
            ));
        }
        let loopback = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let listener = match (port, self.file.ws_port) {
            (Some(port), _) if port != 0 => bind_exact(loopback, port).await?,
            (Some(_), _) | (None, None) => bind_exact(loopback, 0).await?,
            (None, Some(kept)) => match bind_exact(loopback, kept).await {
                Ok(listener) => listener,
                Err(NetError::Io(e)) if e.kind() == io::ErrorKind::AddrInUse => {
                    bind_exact(loopback, 0).await?
                }
                Err(e) => return Err(e),
            },
        };
        let got = Some(listener.local_addr()?.port());
        if self.file.ws_port != got {
            self.file.ws_port = got;
            self.save()?;
        }
        Ok(listener)
    }

    /// The kept `ws` port, if any.
    pub fn ws_port(&self) -> Option<u16> {
        self.file.ws_port
    }
}

async fn bind_exact(ip: IpAddr, port: u16) -> Result<TcpListener, NetError> {
    Ok(TcpListener::bind(SocketAddr::new(ip, port)).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("mousse-net-io-{tag}-{}", hex(&random_bytes::<6>())))
    }

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[test]
    fn a_second_open_of_the_same_endpoint_is_refused_and_another_endpoint_opens() {
        let a_dir = temp_dir("ep-a");
        let b_dir = temp_dir("ep-b");
        let (a, _) = Endpoint::create(&a_dir, None, KeyStorage::InsecureFile).unwrap();
        assert!(matches!(Endpoint::open(&a_dir), Err(NetError::Refused(_))));
        let (b, _) = Endpoint::create(&b_dir, None, KeyStorage::InsecureFile).unwrap();
        assert_ne!(a.identity(), b.identity());
        assert_ne!(a.endpoint_id(), b.endpoint_id());
        assert_ne!(a.profile_id(), b.profile_id());
        drop(a);
        let a = Endpoint::open(&a_dir).unwrap();
        a.load_identity(true).unwrap();
        drop((a, b));
        fs::remove_dir_all(&a_dir).unwrap();
        fs::remove_dir_all(&b_dir).unwrap();
    }

    #[tokio::test]
    async fn caller_commands_share_the_lock_but_not_with_a_running_host() {
        let dir = temp_dir("ep-shared");
        let (ep, _) = Endpoint::create(&dir, None, KeyStorage::InsecureFile).unwrap();
        assert!(matches!(
            Endpoint::open_shared(&dir),
            Err(NetError::Refused(_))
        ));
        drop(ep);
        let mut first = Endpoint::open_shared(&dir).unwrap();
        let second = Endpoint::open_shared(&dir).unwrap();
        assert!(matches!(Endpoint::open(&dir), Err(NetError::Refused(_))));
        assert!(first.bind(LOOPBACK, PortChoice::Kept).await.is_err());
        drop((first, second));
        drop(Endpoint::open(&dir).unwrap());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_copied_state_directory_cannot_run_the_same_identity_twice() {
        let a_dir = temp_dir("ep-orig");
        let copy = temp_dir("ep-copy");
        let (a, _) = Endpoint::create(&a_dir, None, KeyStorage::InsecureFile).unwrap();
        fs::create_dir_all(&copy).unwrap();
        for name in ["endpoint.json", "identity.json", "identity.key"] {
            fs::copy(a_dir.join(name), copy.join(name)).unwrap();
        }
        assert!(matches!(Endpoint::open(&copy), Err(NetError::Refused(_))));
        drop(a);
        drop(Endpoint::open(&copy).unwrap());
        fs::remove_dir_all(&a_dir).unwrap();
        fs::remove_dir_all(&copy).unwrap();
    }

    #[test]
    fn the_profile_id_is_kept_opaque() {
        let dir = temp_dir("ep-prof");
        let profile = "0123456789abcdef0123456789abcdef";
        assert!(Endpoint::create(&dir, Some("p-42"), KeyStorage::InsecureFile).is_err());
        let (ep, _) = Endpoint::create(&dir, Some(profile), KeyStorage::InsecureFile).unwrap();
        assert_eq!(hex(ep.owner().unwrap().as_bytes()), profile);
        drop(ep);
        assert_eq!(Endpoint::open(&dir).unwrap().profile_id(), profile);
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(new_profile_id().len(), 32);
    }

    #[tokio::test]
    async fn the_port_is_picked_once_and_kept() {
        let dir = temp_dir("ep-port");
        let (mut ep, _) = Endpoint::create(&dir, None, KeyStorage::InsecureFile).unwrap();
        let first = ep.bind(LOOPBACK, PortChoice::Kept).await.unwrap();
        let port = first.local_addr().unwrap().port();
        assert_ne!(port, 0);
        drop(first);
        drop(ep);
        let mut ep = Endpoint::open(&dir).unwrap();
        assert_eq!(ep.kept_port(), Some(port));
        let again = ep.bind(LOOPBACK, PortChoice::Kept).await.unwrap();
        assert_eq!(again.local_addr().unwrap().port(), port);
        // Taken by someone else: a new port is picked and kept.
        let new = ep.bind(LOOPBACK, PortChoice::Kept).await.unwrap();
        let new_port = new.local_addr().unwrap().port();
        assert_ne!(new_port, port);
        assert_eq!(ep.kept_port(), Some(new_port));
        drop((again, new));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_fixed_port_is_used_and_not_replaced() {
        let dir = temp_dir("ep-fixed");
        let (mut ep, _) = Endpoint::create(&dir, None, KeyStorage::InsecureFile).unwrap();
        let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let fixed = ep.bind(LOOPBACK, PortChoice::Fixed(port)).await.unwrap();
        assert_eq!(fixed.local_addr().unwrap().port(), port);
        assert_eq!(ep.fixed_port(), Some(port));
        // While it is taken, a kept start fails rather than moving.
        assert!(ep.bind(LOOPBACK, PortChoice::Kept).await.is_err());
        drop(fixed);
        let auto = ep.bind(LOOPBACK, PortChoice::Auto).await.unwrap();
        assert_eq!(ep.fixed_port(), None);
        assert_eq!(ep.kept_port(), Some(auto.local_addr().unwrap().port()));
        drop((auto, ep));
        fs::remove_dir_all(&dir).unwrap();
    }
}
