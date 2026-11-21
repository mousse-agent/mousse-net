//! The helper's Plus client (design A.3 to A.8, E-L2): linking with a code
//! the user types in the browser, access tokens, account and usage (cached
//! on disk and shown at once), unlinking, relay admission tokens and lease
//! blocks with request ids stored before they are sent.
//!
//! Nothing here starts before the helper is ready, and nothing waits on
//! Plus at start: every call runs in the background with backoff
//! (`MOUSSE_NET_PLUS_RETRY_*`). Plus is never a trust anchor: nothing it
//! serves adds a grant, a pin, a manifest or a removal.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mousse_net_core::cbor::Value;
use mousse_net_core::identity::SoftwareKey;
use mousse_net_io::keystore::{IdentityStore, KeyStorage};
use mousse_net_io::rng::random_bytes;
use mousse_net_io::store::{hex, unhex, write_atomic};
use mousse_net_io::Clock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use tokio::sync::mpsc;

use super::http::{Origin, Transport, TransportError};
use super::proto::{self, map, AdmissionToken, Answer, BadAnswer, Block, Class, PlusError};
use crate::applog;
use crate::limits::{helper, ms};

/// The client's file, in the endpoint's folder.
pub const PLUS_FILE: &str = "plus.json";

/// Why a Plus call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// `MOUSSE_NET_PLUS_URL` is not set.
    NotConfigured,
    /// This endpoint is not linked to an account.
    NotLinked,
    /// No HTTP answer.
    Transport(TransportError),
    /// Plus answered with an error.
    Plus(PlusError),
    /// Plus answered something this build cannot read.
    Bad(String),
    /// A local failure (key store, files).
    Local(String),
}

impl Failure {
    /// The error word the app channel uses.
    pub fn word(&self) -> String {
        match self {
            Failure::NotConfigured => "plus_off".into(),
            Failure::NotLinked => "not_linked".into(),
            Failure::Transport(_) => "unreachable".into(),
            Failure::Plus(e) if e.code.is_empty() => "plus_error".into(),
            Failure::Plus(e) => e.code.clone(),
            Failure::Bad(_) => "bad_answer".into(),
            Failure::Local(_) => "local".into(),
        }
    }

    /// Whether the same request may work later unchanged.
    pub fn is_transient(&self) -> bool {
        match self {
            Failure::Transport(_) => true,
            Failure::Plus(e) => e.is_transient(),
            _ => false,
        }
    }

    /// Plus's own `retry after`, if it gave one.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Failure::Plus(e) => e.retry_after.map(Duration::from_secs),
            _ => None,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::NotConfigured => f.write_str("Plus is not set up on this device"),
            Failure::NotLinked => f.write_str("this device is not signed in to Plus"),
            Failure::Transport(e) => write!(f, "{e}"),
            Failure::Plus(e) => write!(f, "{e}"),
            Failure::Bad(e) => write!(f, "{e}"),
            Failure::Local(e) => f.write_str(e),
        }
    }
}

impl From<BadAnswer> for Failure {
    fn from(e: BadAnswer) -> Self {
        Failure::Bad(e.0)
    }
}

/// A link in progress, as stored.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StoredLink {
    /// Link id (hex, 16 bytes).
    pub id: String,
    /// The code the user types, shown as `XXXX-XXXX`.
    pub user_code: String,
    /// Where the user types it.
    pub verify_url: String,
    /// When Plus said it expires (the helper polls past it anyway).
    pub expires_at: u64,
    /// The poll interval Plus asked for.
    pub poll_ms: u64,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct PlusFile {
    version: u32,
    /// The origin this state belongs to; another origin starts afresh.
    origin: String,
    #[serde(default)]
    endpoint_id: Option<String>,
    #[serde(default)]
    link: Option<StoredLink>,
    /// The last link result the app should see (`approved`, `denied`,
    /// `expired`, `gone`).
    #[serde(default)]
    link_result: Option<String>,
    #[serde(default)]
    account: Option<Json>,
    #[serde(default)]
    usage: Option<Json>,
    #[serde(default)]
    fetched_at: u64,
    /// Lease request ids by `relay|boot|handle|class` (hex), stored before
    /// the request is sent and cleared when its block arrives.
    #[serde(default)]
    lease_requests: BTreeMap<String, String>,
    /// The same for admission tokens, by `relay|registration key`.
    #[serde(default)]
    admission_requests: BTreeMap<String, String>,
}

/// One endpoint's Plus client.
pub struct Plus {
    dir: PathBuf,
    transport: Transport,
    clock: Arc<dyn Clock>,
    /// How the identity key is stored; the Plus key is kept the same way.
    storage: KeyStorage,
    key_store: IdentityStore,
    /// Names the keystore entry.
    endpoint_id: String,
    key: Mutex<Option<SoftwareKey>>,
    token: Mutex<Option<(String, u64)>>,
    file: Mutex<()>,
    events: mpsc::UnboundedSender<Json>,
    polling: Mutex<bool>,
    /// Plus could not be reached since this time (Unix seconds).
    outage: Mutex<Option<u64>>,
}

fn platform() -> String {
    let os = match std::env::consts::OS {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        other => other,
    };
    format!("{os} {arch}")
}

/// A key for the stored request-id maps.
pub fn lease_key(relay: &[u8; 32], boot: &[u8; 16], handle: &[u8; 32], class: Class) -> String {
    format!(
        "{}|{}|{}|{}",
        hex(relay),
        hex(boot),
        hex(handle),
        class.code()
    )
}

impl Plus {
    /// The client for the endpoint in `dir` (its folder), or `None` when
    /// `MOUSSE_NET_PLUS_URL` is unset. Reads nothing from the network.
    pub fn open(
        url: Option<&str>,
        dir: &Path,
        clock: Arc<dyn Clock>,
        storage: KeyStorage,
        key_store: IdentityStore,
        endpoint_id: &str,
        events: mpsc::UnboundedSender<Json>,
    ) -> Result<Option<Arc<Self>>, String> {
        let Some(url) = url else {
            return Ok(None);
        };
        let transport = Transport::new(Origin::parse(url)?)?;
        let plus = Arc::new(Self {
            dir: dir.to_path_buf(),
            transport,
            clock,
            storage,
            key_store,
            endpoint_id: endpoint_id.to_owned(),
            key: Mutex::new(None),
            token: Mutex::new(None),
            file: Mutex::new(()),
            events,
            polling: Mutex::new(false),
            outage: Mutex::new(None),
        });
        Ok(Some(plus))
    }

    /// Start the background work after ready: resume a link in progress
    /// and refresh the account.
    pub fn start(self: &Arc<Self>) {
        let file = self.load();
        if file.link.is_some() {
            self.spawn_poll();
        }
        if file.endpoint_id.is_some() {
            let plus = self.clone();
            tokio::spawn(async move {
                let _ = plus.refresh_with_retry().await;
            });
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.join(PLUS_FILE)
    }

    fn load(&self) -> PlusFile {
        let origin = self.transport.origin().text.clone();
        let file = match fs::read(self.path()) {
            Ok(bytes) => serde_json::from_slice::<PlusFile>(&bytes).unwrap_or_default(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => PlusFile::default(),
            Err(e) => {
                applog::line(format!("plus.json: {e}"));
                PlusFile::default()
            }
        };
        if file.origin != origin {
            // Another Plus: nothing of the old one applies.
            return PlusFile {
                version: 1,
                origin,
                ..PlusFile::default()
            };
        }
        file
    }

    fn update<T>(&self, change: impl FnOnce(&mut PlusFile) -> T) -> Result<T, Failure> {
        let _lock = self.file.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = self.load();
        let out = change(&mut file);
        file.version = 1;
        let bytes = serde_json::to_vec(&file).map_err(|e| Failure::Local(e.to_string()))?;
        write_atomic(&self.path(), &bytes).map_err(|e| Failure::Local(e.to_string()))?;
        Ok(out)
    }

    fn now(&self) -> u64 {
        self.clock.now().secs()
    }

    /// The Plus key, made on first use and kept like the identity key.
    fn key(&self) -> Result<SoftwareKey, Failure> {
        let mut slot = self.key.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(k) = slot.as_ref() {
            return Ok(k.clone());
        }
        let store = &self.key_store;
        let insecure = self.storage == KeyStorage::InsecureFile;
        let stored = if store.exists() {
            store.load(insecure)
        } else {
            store.create(self.storage, &self.endpoint_id)
        }
        .map_err(|e| Failure::Local(format!("Plus key: {e}")))?;
        let key = stored.software_key().clone();
        *slot = Some(key.clone());
        Ok(key)
    }

    fn note_reached(&self, reached: bool) {
        let mut outage = self.outage.lock().unwrap_or_else(|e| e.into_inner());
        match (reached, outage.is_some()) {
            (true, true) => {
                *outage = None;
                drop(outage);
                self.event(json!({"ev": "plus.reach", "reachable": true}));
            }
            (false, false) => {
                let since = self.now();
                *outage = Some(since);
                drop(outage);
                self.event(json!({"ev": "plus.reach", "reachable": false, "since": since}));
            }
            _ => {}
        }
    }

    fn event(&self, value: Json) {
        let _ = self.events.send(value);
    }

    /// One request, no auth or the given one; the body of a 2xx answer.
    async fn call(
        &self,
        path: &str,
        body: Option<&[u8]>,
        auth: Option<&str>,
    ) -> Result<Answer, Failure> {
        let response = self.transport.request(path, body, auth).await;
        self.note_reached(response.is_ok());
        let response = response.map_err(Failure::Transport)?;
        if !(200..300).contains(&response.status) {
            return Err(Failure::Plus(PlusError::from_body(
                response.status,
                &response.body,
            )));
        }
        Ok(Answer::decode(&response.body)?)
    }

    fn linked_id(&self) -> Result<[u8; 16], Failure> {
        let file = self.load();
        let id = file.endpoint_id.ok_or(Failure::NotLinked)?;
        unhex(&id)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Failure::Local("stored endpoint id".into()))
    }

    async fn token(&self, fresh: bool) -> Result<String, Failure> {
        let now = self.now();
        if !fresh {
            if let Some((t, exp)) = self.token.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                if now < exp {
                    return Ok(t);
                }
            }
        }
        let endpoint = self.linked_id()?;
        let key = self.key()?;
        let nonce = random_bytes::<16>();
        let body =
            proto::token_request(&key, &endpoint, &self.transport.origin().text, now, &nonce);
        let answer = self.call("/v1/token", Some(&body), None).await?;
        let token = answer.text(1)?;
        let expires = answer.uint(2)?;
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = Some((token.clone(), expires));
        Ok(token)
    }

    /// A request with a bearer token; a refused token is renewed once.
    async fn bearer(&self, path: &str, body: Option<&[u8]>) -> Result<Answer, Failure> {
        let token = self.token(false).await?;
        match self
            .call(path, body, Some(&format!("Bearer {token}")))
            .await
        {
            Err(Failure::Plus(e)) if e.status == 401 => {
                let token = self.token(true).await?;
                self.call(path, body, Some(&format!("Bearer {token}")))
                    .await
            }
            other => other,
        }
    }

    // ----- Link ------------------------------------------------------------

    /// What the app shows at once: the cached state.
    pub fn status(&self) -> Json {
        let file = self.load();
        let outage = *self.outage.lock().unwrap_or_else(|e| e.into_inner());
        json!({
            "url": self.transport.origin().text,
            "linked": file.endpoint_id.is_some(),
            "link": file.link.as_ref().map(|l| json!({
                "user_code": l.user_code,
                "verify_url": l.verify_url,
                "expires_at": l.expires_at,
            })),
            "link_result": file.link_result,
            "account": file.account,
            "usage": file.usage,
            "fetched_at": file.fetched_at,
            "unreachable_since": outage,
        })
    }

    /// `plus.link.start`: ask Plus for a code. The app shows it and opens
    /// the verify URL; the user types the code there. Polling runs in the
    /// background until Plus answers approved, denied, expired or
    /// `not_found`, never stopping at the helper's own copy of the expiry.
    pub async fn link_start(self: &Arc<Self>) -> Result<StoredLink, Failure> {
        let key = self.key()?;
        let body = map(vec![
            (1, Value::Bytes(key.public_key().as_bytes().to_vec())),
            (2, Value::Text(platform())),
        ]);
        let answer = self.call("/v1/link/start", Some(&body), None).await?;
        let link = StoredLink {
            id: hex(&answer.fixed::<16>(1)?),
            user_code: answer.text(2)?,
            verify_url: answer.text(3)?,
            expires_at: answer.uint(4)?,
            poll_ms: answer.uint(5)?,
        };
        self.update(|f| {
            f.link = Some(link.clone());
            f.link_result = None;
        })?;
        self.spawn_poll();
        Ok(link)
    }

    /// `plus.link.cancel`: stop polling and forget the link.
    pub fn link_cancel(&self) -> Result<(), Failure> {
        self.update(|f| {
            f.link = None;
        })
    }

    fn spawn_poll(self: &Arc<Self>) {
        {
            let mut polling = self.polling.lock().unwrap_or_else(|e| e.into_inner());
            if *polling {
                return;
            }
            *polling = true;
        }
        let plus = self.clone();
        tokio::spawn(async move {
            plus.poll_link().await;
            *plus.polling.lock().unwrap_or_else(|e| e.into_inner()) = false;
        });
    }

    async fn poll_link(self: &Arc<Self>) {
        let mut backoff = Backoff::new();
        loop {
            let Some(link) = self.load().link else {
                return;
            };
            let Ok(id) = unhex(&link.id).map(|b| <[u8; 16]>::try_from(b.as_slice())) else {
                return;
            };
            let Ok(id) = id else {
                return;
            };
            let key = match self.key() {
                Ok(k) => k,
                Err(e) => {
                    applog::line(format!("Plus link: {e}"));
                    return;
                }
            };
            let body = proto::link_poll(&key, &id, self.now());
            let wait = match self.call("/v1/link/poll", Some(&body), None).await {
                Ok(answer) => {
                    backoff.reset();
                    match answer.uint(1).unwrap_or(0) {
                        0 => ms(link.poll_ms.max(1)),
                        1 => {
                            let endpoint = answer.fixed::<16>(2).ok();
                            self.finish_link("approved", endpoint);
                            let plus = self.clone();
                            let _ = plus.refresh().await;
                            return;
                        }
                        2 => return self.finish_link("denied", None),
                        _ => return self.finish_link("expired", None),
                    }
                }
                Err(Failure::Plus(e)) if e.code == "not_found" => {
                    return self.finish_link("gone", None);
                }
                Err(e) if e.is_transient() || matches!(e, Failure::Transport(_)) => e
                    .retry_after()
                    .unwrap_or_else(|| backoff.next())
                    .max(ms(link.poll_ms.max(1))),
                Err(e) => {
                    // A stale or refused poll (clock skew): try again later,
                    // the result stays readable at Plus until it expires.
                    applog::line(format!("Plus link poll: {e}"));
                    backoff.next()
                }
            };
            tokio::time::sleep(wait).await;
        }
    }

    fn finish_link(&self, result: &str, endpoint: Option<[u8; 16]>) {
        let saved = self.update(|f| {
            f.link = None;
            f.link_result = Some(result.to_owned());
            if let Some(id) = endpoint {
                f.endpoint_id = Some(hex(&id));
            }
        });
        if let Err(e) = saved {
            applog::line(format!("Plus link: {e}"));
        }
        applog::line(format!("Plus link: {result}"));
        self.event(json!({"ev": "plus.link", "state": result}));
    }

    // ----- Account ---------------------------------------------------------

    /// `GET /v1/account` and `GET /v1/usage`, cached on disk; then a
    /// `plus.status` event.
    pub async fn refresh(&self) -> Result<Json, Failure> {
        let account = self.bearer("/v1/account", None).await?;
        let usage = self.bearer("/v1/usage", None).await?;
        let account = json!({
            "plan": match account.opt_uint(1) {
                Some(1) => "active",
                Some(2) => "past_due",
                Some(3) => "cancelled",
                _ => "none",
            },
            "plan_id": account.text(2).ok(),
            "period_ends_at": account.opt_uint(3),
            "linked_endpoints": account.opt_uint(5),
        });
        let pool = |a: &Answer, key: u64| -> Result<Json, Failure> {
            let p = a.map(key)?;
            Ok(json!({
                "allowance": p.opt_uint(1),
                "used": p.opt_uint(2),
                "reserved": p.opt_uint(3),
                "available": p.opt_uint(4),
                "debt": p.opt_uint(5),
            }))
        };
        let this = usage.map(5).ok();
        let usage = json!({
            "period_starts_at": usage.opt_uint(1),
            "period_ends_at": usage.opt_uint(2),
            "bulk": pool(&usage, 3)?,
            "interactive": pool(&usage, 4)?,
            "this_device": this.map(|t| json!({
                "bulk_used": t.opt_uint(1),
                "interactive_used": t.opt_uint(2),
            })),
        });
        let now = self.now();
        self.update(|f| {
            f.account = Some(account);
            f.usage = Some(usage);
            f.fetched_at = now;
        })?;
        let status = self.status();
        let mut event = status.clone();
        event["ev"] = json!("plus.status");
        self.event(event);
        Ok(status)
    }

    async fn refresh_with_retry(&self) -> Result<Json, Failure> {
        let mut backoff = Backoff::new();
        loop {
            match self.refresh().await {
                Err(e) if e.is_transient() => {
                    tokio::time::sleep(e.retry_after().unwrap_or_else(|| backoff.next())).await;
                }
                other => return other,
            }
        }
    }

    /// `plus.unlink`: Plus stops serving this endpoint. Its slots and inbox
    /// go at Plus; grants and pins here are untouched.
    pub async fn unlink(&self) -> Result<(), Failure> {
        let body = map(vec![(1, Value::Bytes(random_bytes::<16>().to_vec()))]);
        self.bearer("/v1/endpoint/unlink", Some(&body)).await?;
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.update(|f| {
            f.endpoint_id = None;
            f.account = None;
            f.usage = None;
            f.link_result = None;
            f.lease_requests.clear();
            f.admission_requests.clear();
        })?;
        self.event(json!({"ev": "plus.link", "state": "unlinked"}));
        Ok(())
    }

    // ----- Relay admission and leases (A.7, A.8) ----------------------------

    /// The fleet (`GET /v1/relays`): `(identity key, region, endpoints)`.
    pub async fn relays(&self) -> Result<Vec<(Vec<u8>, String, Vec<String>)>, Failure> {
        let answer = self.bearer("/v1/relays", None).await?;
        let mut out = Vec::new();
        for r in answer.maps(1)? {
            let endpoints = r
                .array(3)?
                .into_iter()
                .filter_map(|v| match v {
                    Value::Text(t) => Some(t),
                    _ => None,
                })
                .collect();
            out.push((r.bytes(1)?, r.text(2).unwrap_or_default(), endpoints));
        }
        Ok(out)
    }

    /// An admission token for `registration`'s handle on `relay_id`. The
    /// request id is stored before sending and reused until a token
    /// arrives, so a retry after a lost answer is the same request.
    pub async fn admission(
        &self,
        relay_id: &[u8; 32],
        registration: &SoftwareKey,
    ) -> Result<AdmissionToken, Failure> {
        let endpoint = self.linked_id()?;
        let key = format!(
            "{}|{}",
            hex(relay_id),
            hex(registration.public_key().as_bytes())
        );
        let request_id = self.stored_request_id(&key, false)?;
        let proof = proto::handle_proof(registration, relay_id, &endpoint);
        let body = map(vec![
            (1, Value::Bytes(request_id.to_vec())),
            (2, Value::Bytes(relay_id.to_vec())),
            (
                3,
                Value::Bytes(registration.public_key().as_bytes().to_vec()),
            ),
            (4, Value::Bytes(proof.as_bytes().to_vec())),
        ]);
        let answer = self.bearer("/v1/relay-admission", Some(&body)).await?;
        let token = AdmissionToken::parse(&answer.bytes(1)?)?;
        if &token.relay_id != relay_id
            || token.handle != proto::handle(relay_id, &registration.public_key())
        {
            return Err(Failure::Bad(
                "admission token for another relay or handle".into(),
            ));
        }
        self.update(|f| {
            f.admission_requests.remove(&key);
        })?;
        Ok(token)
    }

    /// The next block for `handle` and `class` on `relay_id`'s boot
    /// `boot_id`. The request id is stored before sending and reused for
    /// every retry, also after a restart, until a block arrives (A.8).
    pub async fn lease(
        &self,
        relay_id: &[u8; 32],
        boot_id: &[u8; 16],
        handle: &[u8; 32],
        class: Class,
    ) -> Result<Block, Failure> {
        let key = lease_key(relay_id, boot_id, handle, class);
        let request_id = self.stored_request_id(&key, true)?;
        let body = map(vec![
            (1, Value::Bytes(request_id.to_vec())),
            (2, Value::Bytes(relay_id.to_vec())),
            (3, Value::Bytes(boot_id.to_vec())),
            (4, Value::Bytes(handle.to_vec())),
            (5, Value::Uint(class.code())),
        ]);
        let answer = self.bearer("/v1/lease", Some(&body)).await?;
        let block = Block::parse(&answer.bytes(1)?)?;
        if &block.relay_id != relay_id
            || &block.boot_id != boot_id
            || &block.handle != handle
            || block.class != class
        {
            return Err(Failure::Bad(
                "block for another relay, boot, handle or class".into(),
            ));
        }
        self.update(|f| {
            f.lease_requests.remove(&key);
        })?;
        Ok(block)
    }

    /// The stored request id for `key`, made and stored durably first if
    /// there is none.
    fn stored_request_id(&self, key: &str, lease: bool) -> Result<[u8; 16], Failure> {
        self.update(|f| {
            let ids = if lease {
                &mut f.lease_requests
            } else {
                &mut f.admission_requests
            };
            if cfg!(mousse_control = "new-request-id-on-retry") {
                // Must-fail control (tests only): every try is a new
                // request.
                ids.remove(key);
            }
            let id = ids
                .entry(key.to_owned())
                .or_insert_with(|| hex(&random_bytes::<16>()))
                .clone();
            unhex(&id)
                .ok()
                .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
                .unwrap_or_default()
        })
    }

    /// Whether this endpoint is linked.
    pub fn is_linked(&self) -> bool {
        self.load().endpoint_id.is_some()
    }

    /// A bearer `POST` for the directory and mailbox (E-L3).
    pub async fn post_bearer(&self, path: &str, body: &[u8]) -> Result<Answer, Failure> {
        self.bearer(path, Some(body)).await
    }

    /// An anonymous `POST` (directory reads).
    pub async fn post_anonymous(&self, path: &str, body: &[u8]) -> Result<Answer, Failure> {
        self.call(path, Some(body), None).await
    }

    /// A `POST` with a deposit token.
    pub async fn post_deposit(
        &self,
        path: &str,
        body: &[u8],
        token: &[u8; 32],
    ) -> Result<Answer, Failure> {
        let auth = format!("Deposit {}", base64url(token));
        self.call(path, Some(body), Some(&auth)).await
    }
}

/// base64url without padding.
pub fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// Waits that double from `MOUSSE_NET_PLUS_RETRY_FIRST_MS` up to
/// `MOUSSE_NET_PLUS_RETRY_MAX_MS`.
pub struct Backoff {
    next: u64,
}

impl Backoff {
    /// From the first wait.
    pub fn new() -> Self {
        Self {
            next: helper().plus_retry_first_ms(),
        }
    }

    /// The next wait.
    pub fn next(&mut self) -> Duration {
        let wait = self.next;
        self.next = (self.next.saturating_mul(2)).min(helper().plus_retry_max_ms());
        ms(wait)
    }

    /// Back to the first wait.
    pub fn reset(&mut self) {
        self.next = helper().plus_retry_first_ms();
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_known_values() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn backoff_doubles_up_to_the_maximum() {
        let mut b = Backoff::new();
        let first = b.next();
        assert_eq!(first, ms(helper().plus_retry_first_ms()));
        assert_eq!(b.next(), first * 2);
        for _ in 0..40 {
            b.next();
        }
        assert_eq!(b.next(), ms(helper().plus_retry_max_ms()));
    }

    #[test]
    fn the_platform_names_os_and_architecture() {
        let p = platform();
        assert!(!p.is_empty() && p.len() <= 64 && p.contains(' '));
    }
}
