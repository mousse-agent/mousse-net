//! SSH routes on the caller's side (Phase 1b §3.1, §3.2, §7): `ssh.resolve`,
//! `ssh.probe`, `ssh.trust`, `ssh.run` and `ssh.forget`.
//!
//! Each route has a random `route_id` and, in `<state>/ssh/` (owner-only):
//!
//! - `<route_id>.conf`: the constrained config, `Host mousse-<route_id>`
//!   with the hostname, port and user `ssh -G` resolved once, the route's
//!   own `HostKeyAlias`, `UserKnownHostsFile "<state>/ssh/known_hosts"`,
//!   `GlobalKnownHostsFile none`, `StrictHostKeyChecking yes`, and the kept
//!   authentication, algorithm and address-family options. Every later call
//!   reads only this file, so it reaches the same host and port and checks
//!   the same pinned key. A jump host (`ProxyJump`, `ProxyCommand`) is
//!   refused.
//! - `<route_id>.json`: what was resolved, for the reply and the connection
//!   window.
//! - `known_hosts`: one line per pinned route, keyed `mousse-<route_id>`,
//!   written only by `ssh.trust` from the key bytes `ssh.probe` fetched. A
//!   new key for a route replaces its line in one atomic write, so the old
//!   pin and the new one never both hold.
//!
//! `ssh.probe` fetches the key through the route's config with every
//! authentication method off and `-N`, into a temporary `known_hosts`, and
//! keeps the bytes in memory for `SSH_SETUP_TIMEOUT_MS`. `ssh.trust` checks
//! them against the fingerprint the owner confirmed and writes them; it
//! never connects again.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mousse_net_io::pipe::ssh::{
    self as sshpipe, config_path, find_marker, MarkerSearch, SshParams, SshReason, SshTarget,
    SshWindow, MARKER,
};
use mousse_net_io::rng::random_bytes;
use mousse_net_io::store::{hex, write_atomic};
use mousse_net_io::NetError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::time::Instant;

/// The requests this module answers.
pub const OPS: [&str; 5] = [
    "ssh.resolve",
    "ssh.probe",
    "ssh.trust",
    "ssh.run",
    "ssh.forget",
];

/// The folder in the state directory.
const DIR: &str = "ssh";

/// The route's pinned keys.
const KNOWN_HOSTS: &str = "known_hosts";

/// Bytes in a route id (hex in names).
const ROUTE_ID_BYTES: usize = 12;

/// Longest `ssh` user and target the owner may enter (§1.1).
const MAX_USER: usize = 64;
const MAX_TARGET: usize = 253;

/// The `ssh -G` options kept in the constrained config (§3.1), with the
/// name written there. Paths may repeat.
const KEPT: [(&str, &str); 11] = [
    ("identityfile", "IdentityFile"),
    ("identitiesonly", "IdentitiesOnly"),
    ("identityagent", "IdentityAgent"),
    ("certificatefile", "CertificateFile"),
    ("pkcs11provider", "PKCS11Provider"),
    ("hostkeyalgorithms", "HostKeyAlgorithms"),
    ("pubkeyacceptedalgorithms", "PubkeyAcceptedAlgorithms"),
    ("kexalgorithms", "KexAlgorithms"),
    ("ciphers", "Ciphers"),
    ("macs", "MACs"),
    ("addressfamily", "AddressFamily"),
];

/// Options every call runs with, from the helper's limits and (debug
/// builds only) the test hooks.
pub fn params() -> SshParams {
    let l = crate::limits::helper();
    let debug_var = |name: &str| {
        if cfg!(debug_assertions) {
            std::env::var_os(name).filter(|v| !v.is_empty())
        } else {
            None
        }
    };
    SshParams {
        bin: debug_var(sshpipe::SSH_BIN_VAR)
            .map(PathBuf::from)
            .unwrap_or_else(sshpipe::system_ssh),
        connect_timeout_secs: l.ssh_connect_timeout_secs(),
        alive_interval_secs: l.ssh_alive_interval_secs(),
        alive_count: l.ssh_alive_count(),
        stderr_max_bytes: usize::try_from(l.ssh_stderr_max_bytes()).unwrap_or(usize::MAX),
        preamble_max_bytes: usize::try_from(l.ssh_preamble_max_bytes()).unwrap_or(usize::MAX),
        user_config: debug_var(sshpipe::TEST_SSH_CONFIG_VAR).map(PathBuf::from),
    }
}

/// A failed request: the error name the app sees and a line for the
/// tooltip.
#[derive(Debug)]
pub struct Fail {
    pub error: &'static str,
    pub reason: String,
}

fn fail(error: &'static str, reason: impl Into<String>) -> Fail {
    Fail {
        error,
        reason: reason.into(),
    }
}

impl From<NetError> for Fail {
    fn from(e: NetError) -> Self {
        match e {
            NetError::Ssh { reason, detail } => fail(reason.name(), detail),
            other => fail("ssh_failed", other.to_string()),
        }
    }
}

/// What `ssh.resolve` found, kept beside the config.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RouteFile {
    /// What the owner entered.
    target: String,
    user: String,
    hostname: String,
    port: u16,
    /// `ssh -G`'s `userknownhostsfile`, for the `in_user_known_hosts` hint.
    #[serde(default)]
    user_known_hosts: Vec<String>,
}

/// A fetched host key: its type and base64 blob, as in `known_hosts`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HostKey {
    key_type: String,
    blob_b64: String,
}

impl HostKey {
    /// `SHA256:` and the unpadded base64 of the blob's SHA-256, as
    /// `ssh-keygen -l` prints it.
    fn sha256(&self) -> Option<String> {
        let blob = b64_decode(&self.blob_b64)?;
        Some(format!("SHA256:{}", b64_encode(&Sha256::digest(&blob))))
    }
}

/// A probed key, kept for `ssh.trust`.
struct Kept {
    key: HostKey,
    at: Instant,
}

/// The SSH routes of one endpoint.
pub struct Ssh {
    dir: PathBuf,
    params: SshParams,
    window: Arc<SshWindow>,
    kept: Mutex<HashMap<String, Kept>>,
    setup: Duration,
    reply_max: usize,
}

impl Ssh {
    /// The routes in `<state_dir>/ssh`.
    pub fn new(state_dir: &Path) -> Self {
        let l = crate::limits::helper();
        Self {
            dir: state_dir.join(DIR),
            params: params(),
            window: Arc::new(SshWindow::new(
                l.ssh_target_connects(),
                l.ssh_target_window_ms(),
            )),
            kept: Mutex::new(HashMap::new()),
            setup: crate::limits::ms(l.ssh_setup_timeout_ms()),
            reply_max: usize::try_from(l.ssh_reply_max_bytes()).unwrap_or(usize::MAX),
        }
    }

    /// Answer one request in [`OPS`]. `event` hears window waits
    /// (`ssh.waiting`).
    pub async fn handle(
        &self,
        op: &str,
        map: &Map<String, Value>,
        event: impl Fn(Value) + Send + Sync,
    ) -> Result<Value, Fail> {
        let str_field = |k: &str| map.get(k).and_then(Value::as_str);
        match op {
            "ssh.resolve" => {
                let target = str_field("target")
                    .ok_or_else(|| fail("bad_request", "ssh.resolve needs target"))?;
                let again = match str_field("route_id") {
                    Some(id) => Some(route_id(id)?),
                    None => None,
                };
                self.resolve(target, again.as_deref()).await
            }
            "ssh.probe" => {
                let id = route_id(str_field("route_id").unwrap_or(""))?;
                let key = self.fetch_key(&id, &event).await?;
                let sha256 = key
                    .sha256()
                    .ok_or_else(|| fail("remote_failed", "the host key is not valid base64"))?;
                let known = self.in_user_known_hosts(&id, &key).await;
                self.kept_lock().insert(
                    id,
                    Kept {
                        key: key.clone(),
                        at: Instant::now(),
                    },
                );
                Ok(
                    json!({"key_type": key.key_type, "sha256": sha256, "in_user_known_hosts": known}),
                )
            }
            "ssh.trust" => {
                let id = route_id(str_field("route_id").unwrap_or(""))?;
                let sha256 = str_field("sha256")
                    .ok_or_else(|| fail("bad_request", "ssh.trust needs sha256"))?;
                self.trust(&id, sha256, &event).await
            }
            "ssh.run" => {
                let id = route_id(str_field("route_id").unwrap_or(""))?;
                let request = match map.get("request") {
                    Some(Value::Object(r)) => r.clone(),
                    _ => return Err(fail("bad_request", "ssh.run needs request (an object)")),
                };
                let reply = self.run(&id, &Value::Object(request), &event).await?;
                Ok(json!({ "reply": reply }))
            }
            "ssh.forget" => {
                let id = route_id(str_field("route_id").unwrap_or(""))?;
                self.forget(&id)?;
                Ok(json!({}))
            }
            other => Err(fail("unknown_op", format!("unknown op {other:?}"))),
        }
    }

    fn kept_lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Kept>> {
        self.kept.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn conf_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.conf"))
    }

    fn meta_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    fn known_hosts(&self) -> PathBuf {
        self.dir.join(KNOWN_HOSTS)
    }

    fn route(&self, id: &str) -> Result<RouteFile, Fail> {
        let bytes = std::fs::read(self.meta_path(id))
            .map_err(|_| fail("no_route", format!("no SSH route {id}")))?;
        serde_json::from_slice(&bytes).map_err(|e| fail("no_route", format!("SSH route {id}: {e}")))
    }

    fn target(&self, id: &str) -> Result<SshTarget, Fail> {
        let route = self.route(id)?;
        Ok(SshTarget {
            conf: self.conf_path(id),
            alias: alias(id),
            host: route.hostname,
            port: route.port,
            user_target: route.target,
        })
    }

    /// The deadline of one setup call, and the window notice.
    fn setup_deadline(&self) -> Instant {
        Instant::now() + self.setup
    }

    /// `ssh.resolve {target, route_id?}`: `ssh -G` once, then the
    /// constrained config. Given an existing `route_id`, that route is
    /// resolved again and keeps its pinned key only if the hostname and
    /// port are unchanged.
    async fn resolve(&self, text: &str, again: Option<&str>) -> Result<Value, Fail> {
        let (user, target, port) = parse_target(text)?;
        let mut cmd = sshpipe::resolve_command(&self.params, user.as_deref(), port, &target);
        let wait = Duration::from_secs(self.params.connect_timeout_secs);
        let out = tokio::time::timeout(wait, cmd.output())
            .await
            .map_err(|_| fail("timeout", "ssh -G took too long"))?
            .map_err(|e| fail("ssh_failed", format!("ssh -G: {e}")))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(fail("bad_target", err.trim().to_owned()));
        }
        let resolved = parse_dump(&String::from_utf8_lossy(&out.stdout));
        for key in ["proxyjump", "proxycommand"] {
            if resolved
                .get(key)
                .is_some_and(|v| v.iter().any(|v| !v.eq_ignore_ascii_case("none")))
            {
                return Err(fail(
                    "ssh_proxy_unsupported",
                    "Jump hosts aren't supported yet.",
                ));
            }
        }
        let one = |key: &str| resolved.get(key).and_then(|v| v.first()).cloned();
        let hostname =
            one("hostname").ok_or_else(|| fail("bad_target", "ssh -G named no hostname"))?;
        let ssh_user = one("user").ok_or_else(|| fail("bad_target", "ssh -G named no user"))?;
        let ssh_port: u16 = one("port")
            .and_then(|p| p.parse().ok())
            .filter(|p| *p != 0)
            .ok_or_else(|| fail("bad_target", "ssh -G named no port"))?;
        if !hostname_ok(&hostname) {
            return Err(fail(
                "bad_target",
                format!("hostname {hostname:?} cannot be used"),
            ));
        }
        if !value_ok(&ssh_user) || ssh_user.chars().any(char::is_whitespace) {
            return Err(fail("bad_target", "the ssh user cannot be used"));
        }
        let id = match again {
            Some(id) => id.to_owned(),
            None => hex(&random_bytes::<ROUTE_ID_BYTES>()),
        };
        let before = again.and_then(|id| self.route(id).ok());
        mousse_net_io::private::make_private_dir(&self.dir)
            .map_err(|e| fail("store_failed", e.to_string()))?;
        let kh = config_path(&self.known_hosts()).ok_or_else(|| {
            fail(
                "store_failed",
                "the state folder's path cannot go in an ssh config",
            )
        })?;
        let conf = write_conf(&id, &hostname, ssh_port, &ssh_user, &kh, &resolved)?;
        write_atomic(&self.conf_path(&id), conf.as_bytes())
            .map_err(|e| fail("store_failed", e.to_string()))?;
        let route = RouteFile {
            target: text.to_owned(),
            user: ssh_user.clone(),
            hostname: hostname.clone(),
            port: ssh_port,
            user_known_hosts: resolved
                .get("userknownhostsfile")
                .cloned()
                .unwrap_or_default(),
        };
        let meta = serde_json::to_vec(&route).map_err(|e| fail("store_failed", e.to_string()))?;
        write_atomic(&self.meta_path(&id), &meta)
            .map_err(|e| fail("store_failed", e.to_string()))?;
        let same = before.is_some_and(|b| b.hostname == hostname && b.port == ssh_port);
        let pinned = if same {
            self.pinned_key(&id).is_some()
        } else {
            self.write_pin(&id, None)?;
            false
        };
        Ok(json!({
            "route_id": id,
            "user": ssh_user,
            "hostname": hostname,
            "port": ssh_port,
            "pinned": pinned,
        }))
    }

    /// The key pinned for route `id`, if any.
    fn pinned_key(&self, id: &str) -> Option<HostKey> {
        let text = std::fs::read_to_string(self.known_hosts()).ok()?;
        parse_known_hosts(&text)
            .into_iter()
            .find(|(host, _)| *host == alias(id))
            .map(|(_, key)| key)
    }

    /// Replace route `id`'s line in `known_hosts` with `key` (or drop it),
    /// in one atomic write.
    fn write_pin(&self, id: &str, key: Option<&HostKey>) -> Result<(), Fail> {
        let path = self.known_hosts();
        let old = std::fs::read_to_string(&path).unwrap_or_default();
        let name = alias(id);
        let mut out = String::new();
        for line in old.lines() {
            if line.split_whitespace().next() == Some(name.as_str()) || line.trim().is_empty() {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        if let Some(key) = key {
            out.push_str(&format!("{name} {} {}\n", key.key_type, key.blob_b64));
        }
        if old.is_empty() && out.is_empty() {
            return Ok(());
        }
        write_atomic(&path, out.as_bytes()).map_err(|e| fail("store_failed", e.to_string()))
    }

    /// Fetch route `id`'s host key: every authentication method off, `-N`,
    /// into a temporary `known_hosts` that `accept-new` fills.
    async fn fetch_key(
        &self,
        id: &str,
        event: &(impl Fn(Value) + Send + Sync),
    ) -> Result<HostKey, Fail> {
        let target = self.target(id)?;
        let temp = self
            .dir
            .join(format!("probe-{}.known_hosts", hex(&random_bytes::<8>())));
        let temp_value = config_path(&temp).ok_or_else(|| {
            fail(
                "store_failed",
                "the state folder's path cannot go in an ssh config",
            )
        })?;
        let per_call: Vec<String> = [
            format!("UserKnownHostsFile={temp_value}"),
            "StrictHostKeyChecking=accept-new".to_owned(),
            "HashKnownHosts=no".to_owned(),
            "PubkeyAuthentication=no".to_owned(),
            "PasswordAuthentication=no".to_owned(),
            "KbdInteractiveAuthentication=no".to_owned(),
            "HostbasedAuthentication=no".to_owned(),
        ]
        .into_iter()
        .flat_map(|o| ["-o".to_owned(), o])
        .chain(["-N".to_owned()])
        .collect();
        let out = sshpipe::run(
            &self.params,
            &self.window,
            &target,
            &per_call,
            None,
            Vec::new(),
            0,
            self.setup_deadline(),
            waiting(id, &target, event),
        )
        .await;
        let text = std::fs::read_to_string(&temp).unwrap_or_default();
        let _ = std::fs::remove_file(&temp);
        let out = out?;
        parse_known_hosts(&text)
            .into_iter()
            .find(|(host, _)| *host == target.alias)
            .map(|(_, key)| key)
            .ok_or_else(|| {
                let reason = match out.reason() {
                    // The fetch logs in with nothing, so a refused login is
                    // expected; without a key, the server never showed one.
                    SshReason::AuthDenied => SshReason::RemoteFailed,
                    other => other,
                };
                fail(reason.name(), out.stderr.trim().to_owned())
            })
    }

    /// Whether the owner's own `known_hosts` (as `ssh -G` named it) lists
    /// the same key for the hostname: a hint only, checked with
    /// `ssh-keygen -F`, which also reads hashed entries.
    async fn in_user_known_hosts(&self, id: &str, key: &HostKey) -> bool {
        let Ok(route) = self.route(id) else {
            return false;
        };
        let name = if route.port == 22 {
            route.hostname.clone()
        } else {
            format!("[{}]:{}", route.hostname, route.port)
        };
        let keygen = sshpipe::keygen_beside(&self.params.bin);
        let wait = Duration::from_secs(self.params.connect_timeout_secs);
        for file in &route.user_known_hosts {
            let path = expand_home(file);
            if !path.is_file() {
                continue;
            }
            let mut cmd = tokio::process::Command::new(&keygen);
            cmd.arg("-F").arg(&name).arg("-f").arg(&path);
            cmd.stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true);
            #[cfg(windows)]
            cmd.creation_flags(0x0800_0000);
            let Ok(Ok(out)) = tokio::time::timeout(wait, cmd.output()).await else {
                continue;
            };
            let text = String::from_utf8_lossy(&out.stdout);
            if parse_known_hosts(&text).iter().any(|(_, k)| k == key) {
                return true;
            }
        }
        false
    }

    /// `ssh.trust {route_id, sha256}`: write the probed key for the route.
    async fn trust(
        &self,
        id: &str,
        sha256: &str,
        event: &(impl Fn(Value) + Send + Sync),
    ) -> Result<Value, Fail> {
        let kept = {
            let mut kept = self.kept_lock();
            let setup = self.setup;
            kept.retain(|_, k| k.at.elapsed() < setup);
            kept.get(id).map(|k| k.key.clone())
        };
        let key = if cfg!(mousse_control = "trust-unprobed-key") {
            // Control (tests only): trust fetches the key again and writes
            // what it gets, not the bytes the owner confirmed.
            let _ = kept;
            self.fetch_key(id, event).await?
        } else {
            let Some(key) = kept else {
                return Err(fail(
                    "probe_again",
                    "no fetched key is kept for this route; check the key again",
                ));
            };
            if key.sha256().as_deref() != Some(sha256) {
                return Err(fail(
                    "key_mismatch",
                    "that fingerprint is not the key fetched for this route",
                ));
            }
            key
        };
        self.target(id)?;
        self.write_pin(id, Some(&key))?;
        self.kept_lock().remove(id);
        Ok(json!({"sha256": key.sha256(), "pinned": true}))
    }

    /// `ssh.run {route_id, request}`: one setup session running `mousse-cli
    /// net-engine ssh` on the remote, the request on stdin, the reply after
    /// the marker.
    async fn run(
        &self,
        id: &str,
        request: &Value,
        event: &(impl Fn(Value) + Send + Sync),
    ) -> Result<Value, Fail> {
        let target = self.target(id)?;
        let remote = sshpipe::remote_command("mousse-cli", &["net-engine", "ssh"])?;
        let mut input =
            serde_json::to_vec(request).map_err(|e| fail("bad_request", e.to_string()))?;
        input.push(b'\n');
        let preamble = self.params.preamble_max_bytes;
        let cap = preamble
            .saturating_add(MARKER.len())
            .saturating_add(self.reply_max);
        let out = sshpipe::run(
            &self.params,
            &self.window,
            &target,
            &[],
            Some(&remote),
            input,
            cap,
            self.setup_deadline(),
            waiting(id, &target, event),
        )
        .await?;
        let at = match find_marker(&out.stdout, preamble) {
            MarkerSearch::After(at) => at,
            MarkerSearch::TooLong => return Err(fail(
                SshReason::RemoteFailed.name(),
                "the remote printed text before the Mousse marker (past SSH_PREAMBLE_MAX_BYTES)",
            )),
            MarkerSearch::More => {
                let reason = out.reason();
                let detail = if out.stderr.trim().is_empty() {
                    "no Mousse marker in the remote's output".to_owned()
                } else {
                    out.stderr.trim().to_owned()
                };
                return Err(fail(reason.name(), detail));
            }
        };
        let reply = &out.stdout[at..];
        if out.overflow || reply.len() > self.reply_max {
            return Err(fail(
                SshReason::RemoteFailed.name(),
                "the reply is longer than SSH_REPLY_MAX_BYTES",
            ));
        }
        serde_json::from_slice(reply).map_err(|e| {
            fail(
                SshReason::RemoteFailed.name(),
                format!("the reply is not JSON: {e}"),
            )
        })
    }

    /// `ssh.forget {route_id}`: the route's config, record, pin and kept
    /// key go.
    fn forget(&self, id: &str) -> Result<(), Fail> {
        self.kept_lock().remove(id);
        self.write_pin(id, None)?;
        for path in [self.conf_path(id), self.meta_path(id)] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(fail("store_failed", e.to_string())),
            }
        }
        Ok(())
    }

    /// Open the pipe of route `id` to the remote profile `selector`
    /// (§3.3), within `within`. The caller's `ssh` tier calls this
    /// (`SSH_DIAL_TIMEOUT_MS`); TLS and step 1 run on top.
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub async fn dial(
        &self,
        id: &str,
        selector: &str,
        within: Duration,
        on_wait: impl FnMut(Duration),
    ) -> Result<sshpipe::SshPipe, NetError> {
        let target = self.target(id).map_err(|f| NetError::Refused(f.reason))?;
        let remote = sshpipe::remote_command("mousse-helper", &["pipe", "--profile", selector])?;
        sshpipe::dial(
            &self.params,
            &self.window,
            &target,
            &remote,
            within,
            on_wait,
        )
        .await
    }
}

/// The `ssh.waiting` event for a wait in the window.
fn waiting<'a>(
    id: &'a str,
    target: &'a SshTarget,
    event: &'a (impl Fn(Value) + Send + Sync),
) -> impl FnMut(Duration) + 'a {
    move |wait| {
        event(json!({
            "ev": "ssh.waiting",
            "route_id": id,
            "host": target.host,
            "ms": u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
        }))
    }
}

/// `mousse-<route_id>`.
fn alias(id: &str) -> String {
    format!("mousse-{id}")
}

/// A route id: 24 lowercase hex digits.
fn route_id(text: &str) -> Result<String, Fail> {
    if text.len() == ROUTE_ID_BYTES * 2
        && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(text.to_owned())
    } else {
        Err(fail(
            "bad_request",
            "route_id must be 24 lowercase hex digits",
        ))
    }
}

/// `[ssh://][<user>@]<target>[:<port>]` (§1.1): a user of 1 to 64 bytes
/// from `[A-Za-z0-9._-]`, an IP literal (IPv6 in brackets) or a name of 1
/// to 253 bytes from `[A-Za-z0-9._-]`, neither starting with `-`.
fn parse_target(text: &str) -> Result<(Option<String>, String, Option<u16>), Fail> {
    let bad = || fail("bad_target", format!("not an SSH target: {text:?}"));
    let rest = text.strip_prefix("ssh://").unwrap_or(text);
    let (user, rest) = match rest.split_once('@') {
        Some((u, r)) => (Some(u), r),
        None => (None, rest),
    };
    if let Some(u) = user {
        if u.is_empty() || u.len() > MAX_USER || u.starts_with('-') || !u.bytes().all(name_byte) {
            return Err(bad());
        }
    }
    let (target, port) = if let Some(inner) = rest.strip_prefix('[') {
        let (addr, after) = inner.split_once(']').ok_or_else(bad)?;
        let addr: std::net::Ipv6Addr = addr.parse().map_err(|_| bad())?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or_else(bad)?),
        };
        (addr.to_string(), port)
    } else {
        match rest.rsplit_once(':') {
            Some((t, p)) => (t.to_owned(), Some(p)),
            None => (rest.to_owned(), None),
        }
    };
    let port = match port {
        None => None,
        Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(bad)?),
    };
    if !target.contains(':')
        && (target.is_empty()
            || target.len() > MAX_TARGET
            || target.starts_with('-')
            || !target.bytes().all(name_byte))
    {
        return Err(bad());
    }
    Ok((user.map(str::to_owned), target.to_ascii_lowercase(), port))
}

fn name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

/// A hostname `ssh -G` printed that can go in the config unquoted.
fn hostname_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_TARGET + 2
        && !host.starts_with('-')
        && host
            .bytes()
            .all(|b| name_byte(b) || matches!(b, b':' | b'%'))
}

/// A value that can go in the config in double quotes.
fn value_ok(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(|c| c == '"' || c.is_control())
}

/// `ssh -G`'s dump: lowercase keys, each with the values it printed.
fn parse_dump(text: &str) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.trim_end_matches('\r').split_once(' ') else {
            continue;
        };
        let key = key.to_ascii_lowercase();
        let value = value.trim();
        if key == "userknownhostsfile" {
            out.entry(key)
                .or_default()
                .extend(value.split_whitespace().map(str::to_owned));
        } else {
            out.entry(key).or_default().push(value.to_owned());
        }
    }
    out
}

/// The constrained config of route `id` (§3.1).
fn write_conf(
    id: &str,
    hostname: &str,
    port: u16,
    user: &str,
    known_hosts: &str,
    resolved: &HashMap<String, Vec<String>>,
) -> Result<String, Fail> {
    let name = alias(id);
    // Control (tests only): ssh adds unknown keys by itself.
    let strict = if cfg!(mousse_control = "accept-new-host-key") {
        "accept-new"
    } else {
        "yes"
    };
    let mut conf = format!(
        "Host {name}\n  HostName {hostname}\n  Port {port}\n  User \"{user}\"\n  \
         HostKeyAlias {name}\n  UserKnownHostsFile {known_hosts}\n  \
         GlobalKnownHostsFile none\n  StrictHostKeyChecking {strict}\n"
    );
    for (key, written) in KEPT {
        for value in resolved.get(key).into_iter().flatten() {
            if !value_ok(value) {
                return Err(fail(
                    "bad_target",
                    format!("the ssh option {written} cannot be kept"),
                ));
            }
            if value.chars().any(char::is_whitespace) {
                conf.push_str(&format!("  {written} \"{value}\"\n"));
            } else {
                conf.push_str(&format!("  {written} {value}\n"));
            }
        }
    }
    Ok(conf)
}

/// `known_hosts` lines: `(host, key)`, skipping comments, markers and
/// lines that do not parse.
fn parse_known_hosts(text: &str) -> Vec<(String, HostKey)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
                return None;
            }
            let mut parts = line.split_whitespace();
            let host = parts.next()?;
            let key_type = parts.next()?;
            let blob_b64 = parts.next()?;
            b64_decode(blob_b64)?;
            Some((
                host.to_owned(),
                HostKey {
                    key_type: key_type.to_owned(),
                    blob_b64: blob_b64.to_owned(),
                },
            ))
        })
        .collect()
}

/// A path `ssh -G` printed, with a leading `~` in the user's home.
fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" });
        if let Some(home) = home {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 without padding (fingerprints).
fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(B64[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// Standard base64 with or without padding (`known_hosts` blobs); `None`
/// for anything else.
fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let body = text.trim_end_matches('=');
    if text.len() - body.len() > 2 || body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for b in body.bytes() {
        let v = B64.iter().position(|c| *c == b)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be zero.
    (acc == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_and_refuses_junk() {
        for n in 0..40u8 {
            let bytes: Vec<u8> = (0..n).map(|i| i.wrapping_mul(37)).collect();
            let text = b64_encode(&bytes);
            assert_eq!(b64_decode(&text).unwrap(), bytes);
        }
        assert_eq!(b64_encode(b"Man"), "TWFu");
        assert_eq!(b64_decode("TWE=").unwrap(), b"Ma");
        assert!(b64_decode("TW!u").is_none());
        assert!(b64_decode("T").is_none());
        assert!(b64_decode("TWF=").is_none());
    }

    #[test]
    fn the_fingerprint_is_sha256_of_the_blob() {
        // ssh-keygen -l on this test key prints this fingerprint.
        let key = HostKey {
            key_type: "ssh-ed25519".into(),
            blob_b64: "AAAAC3NzaC1lZDI1NTE5AAAAIB52hkRAWi2+fpeCdkkuBVHTbYmRB2MYjEAUrT59HR+t".into(),
        };
        assert_eq!(
            key.sha256().unwrap(),
            "SHA256:mVnrTjhjU8zxOXNfvsChy0nT/AD7DuvYEoOrmqgBsXs"
        );
    }

    #[test]
    fn targets_follow_the_ssh_grammar() {
        assert_eq!(
            parse_target("ana@Box_1.example:2222").unwrap(),
            (Some("ana".into()), "box_1.example".into(), Some(2222))
        );
        assert_eq!(
            parse_target("ssh://box").unwrap(),
            (None, "box".into(), None)
        );
        assert_eq!(
            parse_target("[::1]:22").unwrap(),
            (None, "::1".into(), Some(22))
        );
        for bad in [
            "-oProxyCommand=x",
            "a@-b",
            "@b",
            "b:0",
            "b:x",
            "a b",
            "a;b",
            "[::1",
            "a'b@c",
        ] {
            assert!(parse_target(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_dump_keeps_repeated_options_and_splits_known_hosts_files() {
        let d = parse_dump("user ana\r\nidentityfile ~/.ssh/a\nidentityfile ~/.ssh/b c\nuserknownhostsfile ~/.ssh/known_hosts ~/.ssh/known_hosts2\n");
        assert_eq!(d["identityfile"], ["~/.ssh/a", "~/.ssh/b c"]);
        assert_eq!(d["userknownhostsfile"].len(), 2);
        let conf = write_conf("ab", "h", 22, "ana", "\"/k\"", &d).unwrap();
        assert!(
            conf.contains("  IdentityFile ~/.ssh/a\n  IdentityFile \"~/.ssh/b c\"\n"),
            "{conf}"
        );
        assert!(
            conf.contains("StrictHostKeyChecking yes\n")
                || cfg!(mousse_control = "accept-new-host-key")
        );
        assert!(!conf.contains("UserKnownHostsFile ~"), "{conf}");
    }
}
