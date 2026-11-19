//! A test stand-in for Plus, built only from the public contract
//! (docs/phase34-design.md, Part A). It is a fixture for the helper's tests
//! and will be replaced by the Plus team's double; it holds no ledger,
//! billing or account model beyond what the contract messages need.
//!
//! Plain HTTP/1.1 on 127.0.0.1, one request per connection, served on its
//! own thread with its own runtime, so synchronous tests can drive it. The
//! plain methods on [`PlusStandIn`] are test hooks: they approve links, set
//! balances, inject failures and play a hostile Plus.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mousse_net_core::cbor::{decode, encode, FieldError, Fields, Value};
use mousse_net_core::identity::{PublicKey, RawSignature, SoftwareKey};
use mousse_net_io::rng::{os_rng, random_bytes};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const REQUEST_MAX: usize = 16_384;
const DIR_ENTRY_MAX: usize = 4096;
const MAIL_ENVELOPE_MAX: usize = 8192;
const DEPOSIT_TOKENS_MAX: usize = 256;
const BLOCK_MAX_LIFETIME: u64 = 172_800;
const BLOCK_MIN: u64 = 65_536;
const SKEW: u64 = 600;
const TOKEN_SECS: u64 = 3600;
const LINK_SECS: u64 = 600;
const BLOCK_SECS: u64 = 86_400;
const RATE_CAP: u64 = 8 << 20;
const PERIOD_SECS: u64 = 30 * 86_400;

const LINK_DOMAIN: &str = "mousse-plus-link-v1";
const TOKEN_DOMAIN: &str = "mousse-plus-token-v1";
const HANDLE_DOMAIN: &str = "mousse-plus-handle-v1";
const ADMIT_DOMAIN: &str = "mousse-relay-admit-v1";
const LEASE_DOMAIN: &str = "mousse-lease-v1";
const CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

// ---------------------------------------------------------------------------
// Public helpers

/// A signed envelope `{1: record, 2: raw signature}` (A.12).
pub fn signed_envelope(record: &[u8], key: &SoftwareKey) -> Vec<u8> {
    let sig = key.sign_raw(record);
    map(vec![(1, bytes(record)), (2, bytes(sig.as_bytes()))])
}

/// Base64url without padding, as deposit tokens travel.
pub fn base64url(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let mut n = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            n |= u32::from(*b) << (16 - 8 * i);
        }
        for i in 0..=chunk.len() {
            out.push(char::from(A[((n >> (18 - 6 * i)) & 0x3f) as usize]));
        }
    }
    out
}

fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut held = 0;
    let mut out = Vec::new();
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(v);
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push((bits >> held) as u8);
            bits &= (1 << held) - 1;
        }
    }
    (held < 6 && bits == 0).then_some(out)
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn map(entries: Vec<(u64, Value)>) -> Vec<u8> {
    encode(&Value::Map(entries))
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Errors (A.2 table)

#[derive(Clone, Debug)]
struct Fail {
    code: String,
    status: u16,
    retry: Option<u64>,
}

fn fail(code: &str) -> Fail {
    let status = match code {
        "invalid" | "version" => 400,
        "unauthorized" => 401,
        "not_plus" | "allowance_used" | "balance_empty" => 402,
        "forbidden" => 403,
        "not_found" => 404,
        "conflict" | "quota" | "cap_reached" | "unknown_boot" | "stale_generation"
        | "handle_taken" => 409,
        "too_large" => 413,
        "rate_limited" => 429,
        "fleet_paused" | "issuer_not_ready" => 503,
        _ => 500,
    };
    Fail {
        code: code.into(),
        status,
        retry: None,
    }
}

impl From<FieldError> for Fail {
    fn from(_: FieldError) -> Self {
        fail("invalid")
    }
}

type Answer = Result<Vec<u8>, Fail>;

// ---------------------------------------------------------------------------
// State

struct Link {
    key: [u8; 65],
    code: String,
    expires_at: u64,
    state: u64,
    endpoint: Option<[u8; 16]>,
    last_poll: Option<Instant>,
}

struct Endpoint {
    key: [u8; 65],
    linked: bool,
}

struct Handle {
    endpoint: [u8; 16],
    relay: [u8; 32],
}

struct Lease {
    endpoint: [u8; 16],
    relay: [u8; 32],
    boot: [u8; 16],
    handle: [u8; 32],
    class: u64,
    done: bool,
}

struct Slot {
    owner: [u8; 16],
    version: u64,
    ciphertext: Vec<u8>,
    /// Earlier (version, ciphertext) pairs, for a restore that loses a write.
    history: Vec<(u64, Vec<u8>)>,
}

struct Message {
    id: [u8; 16],
    seq: u64,
    tag: [u8; 16],
    received_at: u64,
    envelope: Vec<u8>,
}

struct Inbox {
    owner: [u8; 16],
    seq: u64,
    /// (tag, token hash).
    tokens: Vec<([u8; 16], [u8; 32])>,
    next_seq: u64,
    messages: Vec<Message>,
}

struct MessageState {
    inbox: [u8; 32],
    token_hash: [u8; 32],
    state: u64,
}

#[derive(Default)]
struct Pool {
    balance: u64,
    reserved: u64,
}

impl Pool {
    fn available(&self) -> u64 {
        self.balance.saturating_sub(self.reserved)
    }
}

/// (scope, path, request id) → (first body, first answer).
type IdemKey = (Vec<u8>, String, [u8; 16]);

struct State {
    origin: String,
    issuer: SoftwareKey,
    issuer_kid: [u8; 8],
    period_start: u64,

    // Settings.
    plan: u64,
    bulk: Pool,
    interactive: Pool,
    block_bytes: u64,
    admission_secs: u64,
    link_poll_ms: u64,
    tag_quota: usize,
    inbox_quota: usize,
    page: usize,
    slot_quota: usize,
    relays: Vec<([u8; 65], String, Vec<String>)>,

    links: HashMap<[u8; 16], Link>,
    endpoints: HashMap<[u8; 16], Endpoint>,
    tokens: HashMap<String, ([u8; 16], u64)>,
    nonces: HashSet<([u8; 16], [u8; 16])>,
    idem: HashMap<IdemKey, (Vec<u8>, Vec<u8>)>,
    handles: HashMap<[u8; 32], Handle>,
    /// (endpoint, relay) → the newest handle presented.
    newest: HashMap<([u8; 16], [u8; 32]), [u8; 32]>,
    boots: HashSet<([u8; 32], [u8; 16])>,
    leases: HashMap<[u8; 16], Lease>,
    block_seq: HashMap<([u8; 32], u64, [u8; 16]), u64>,
    rate_groups: HashMap<[u8; 32], [u8; 16]>,
    slots: HashMap<[u8; 32], Slot>,
    deleted_slots: HashSet<[u8; 32]>,
    inboxes: HashMap<[u8; 32], Inbox>,
    message_states: HashMap<[u8; 16], MessageState>,

    // Hooks.
    fail_next: HashMap<String, Fail>,
    lose_next: HashSet<String>,
    counts: HashMap<String, usize>,
    lease_ids: Vec<[u8; 16]>,
}

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl State {
    fn new(origin: String) -> Self {
        let issuer = SoftwareKey::generate(&mut os_rng());
        let kid = sha256(&[issuer.public_key().as_bytes()]);
        Self {
            origin,
            issuer,
            issuer_kid: kid[..8].try_into().unwrap(),
            period_start: now(),
            plan: 1,
            bulk: Pool {
                balance: 1 << 30,
                reserved: 0,
            },
            interactive: Pool {
                balance: 1 << 30,
                reserved: 0,
            },
            block_bytes: 8 << 20,
            admission_secs: 3600,
            link_poll_ms: 50,
            tag_quota: 8,
            inbox_quota: 64,
            page: 32,
            slot_quota: 64,
            relays: Vec::new(),
            links: HashMap::new(),
            endpoints: HashMap::new(),
            tokens: HashMap::new(),
            nonces: HashSet::new(),
            idem: HashMap::new(),
            handles: HashMap::new(),
            newest: HashMap::new(),
            boots: HashSet::new(),
            leases: HashMap::new(),
            block_seq: HashMap::new(),
            rate_groups: HashMap::new(),
            slots: HashMap::new(),
            deleted_slots: HashSet::new(),
            inboxes: HashMap::new(),
            message_states: HashMap::new(),
            fail_next: HashMap::new(),
            lose_next: HashSet::new(),
            counts: HashMap::new(),
            lease_ids: Vec::new(),
        }
    }

    /// One request → its answer, and whether the answer is to be lost.
    fn handle(&mut self, req: &Request) -> (Answer, bool) {
        *self.counts.entry(req.path.clone()).or_default() += 1;
        if req.path == "/v1/lease" {
            if let Ok(Value::Map(m)) = decode(&req.body) {
                if let Some((_, Value::Bytes(id))) = m.iter().find(|(k, _)| *k == 1) {
                    if let Ok(id) = <[u8; 16]>::try_from(id.as_slice()) {
                        self.lease_ids.push(id);
                    }
                }
            }
        }
        if let Some(f) = self.fail_next.remove(&req.path) {
            return (Err(f), false);
        }
        let lose = self.lose_next.remove(&req.path);
        (self.route(req), lose)
    }

    fn route(&mut self, req: &Request) -> Answer {
        let version = req.header("mousse-plus-api").unwrap_or("");
        let served = version
            .split_once('.')
            .is_some_and(|(major, minor)| major == "1" && minor == "0");
        if !served {
            return Err(fail("version"));
        }
        if req.body.len() > REQUEST_MAX {
            return Err(fail("too_large"));
        }
        let body = req.body.as_slice();
        match (req.method.as_str(), req.path.as_str()) {
            ("POST", "/v1/link/start") => self.link_start(body),
            ("POST", "/v1/link/poll") => self.link_poll(body),
            ("POST", "/v1/token") => self.token(body),
            ("POST", "/v1/dir/get") => self.dir_get(body),
            ("POST", "/v1/inbox/deposit") => self.deposit(req),
            ("POST", "/v1/message/state") => self.message_state(req),
            ("GET", "/v1/account") => {
                let ep = self.bearer(req)?;
                self.account(ep)
            }
            ("GET", "/v1/usage") => {
                self.bearer(req)?;
                Ok(self.usage())
            }
            ("GET", "/v1/relays") => {
                self.bearer(req)?;
                Ok(self.relays())
            }
            ("POST", path) => {
                let ep = self.bearer(req)?;
                match path {
                    "/v1/endpoint/unlink" => self.unlink(ep, body),
                    "/v1/relay-admission" => self.relay_admission(ep, body),
                    "/v1/lease" => self.lease(ep, body),
                    "/v1/dir/put" => self.dir_put(ep, body),
                    "/v1/dir/delete" => self.dir_delete(ep, body),
                    "/v1/dir/list" => self.dir_list(ep, body),
                    "/v1/inbox/put" => self.inbox_put(ep, body),
                    "/v1/inbox/fetch" => self.inbox_fetch(ep, body),
                    "/v1/inbox/ack" => self.inbox_ack(ep, body),
                    _ => Err(fail("not_found")),
                }
            }
            _ => Err(fail("not_found")),
        }
    }

    /// Idempotency (A.2): the same request id on the same path from the
    /// same credential returns the first answer for the same body and is
    /// `conflict` for another. Only answers that succeeded are kept, so a
    /// retry after an error is served afresh.
    fn once(
        &mut self,
        scope: &[u8],
        path: &str,
        id: [u8; 16],
        body: &[u8],
        work: impl FnOnce(&mut Self) -> Answer,
    ) -> Answer {
        let key = (scope.to_vec(), path.to_string(), id);
        if let Some((first_body, first_answer)) = self.idem.get(&key) {
            return if first_body == body {
                Ok(first_answer.clone())
            } else {
                Err(fail("conflict"))
            };
        }
        let answer = work(self)?;
        self.idem.insert(key, (body.to_vec(), answer.clone()));
        Ok(answer)
    }

    fn bearer(&self, req: &Request) -> Result<[u8; 16], Fail> {
        let token = req
            .header("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| fail("unauthorized"))?;
        match self.tokens.get(token) {
            Some((ep, expires)) if *expires > now() && self.is_linked(ep) => Ok(*ep),
            _ => Err(fail("unauthorized")),
        }
    }

    fn deposit_hash(req: &Request) -> Result<[u8; 32], Fail> {
        req.header("authorization")
            .and_then(|v| v.strip_prefix("Deposit "))
            .and_then(base64url_decode)
            .filter(|t| t.len() == 32)
            .map(|t| sha256(&[&t]))
            .ok_or_else(|| fail("unauthorized"))
    }

    fn is_linked(&self, ep: &[u8; 16]) -> bool {
        self.endpoints.get(ep).is_some_and(|e| e.linked)
    }

    fn sign(&self, record: &[u8]) -> Vec<u8> {
        signed_envelope(record, &self.issuer)
    }

    // --- A.3 link and tokens ------------------------------------------------

    fn link_start(&mut self, body: &[u8]) -> Answer {
        let mut f = Fields::decode(body)?;
        let key: [u8; 65] = f.fixed(1)?;
        let platform = f.text(2)?;
        f.finish()?;
        PublicKey::from_sec1(&key).map_err(|_| fail("invalid"))?;
        if platform.is_empty() || platform.len() > 64 {
            return Err(fail("invalid"));
        }
        let id: [u8; 16] = random_bytes();
        let code: String = random_bytes::<8>()
            .iter()
            .map(|b| char::from(CODE_ALPHABET[usize::from(*b) % CODE_ALPHABET.len()]))
            .collect();
        let expires_at = now() + LINK_SECS;
        self.links.insert(
            id,
            Link {
                key,
                code: code.clone(),
                expires_at,
                state: 0,
                endpoint: None,
                last_poll: None,
            },
        );
        Ok(map(vec![
            (1, bytes(&id)),
            (2, Value::Text(code)),
            (3, Value::Text(format!("{}/link", self.origin))),
            (4, Value::Uint(expires_at)),
            (5, Value::Uint(self.link_poll_ms)),
        ]))
    }

    fn link_poll(&mut self, body: &[u8]) -> Answer {
        let (record, sig, mut f) = open_envelope(body, LINK_DOMAIN)?;
        let id: [u8; 16] = f.fixed(2)?;
        let issued_at = f.uint(3)?;
        f.finish()?;
        let interval = Duration::from_millis(self.link_poll_ms);
        let link = self.links.get_mut(&id).ok_or_else(|| fail("not_found"))?;
        verify(&link.key, &record, &sig)?;
        if issued_at.abs_diff(now()) > SKEW {
            return Err(fail("unauthorized"));
        }
        if link.last_poll.is_some_and(|t| t.elapsed() < interval) {
            let mut f = fail("rate_limited");
            f.retry = Some(interval.as_secs().max(1));
            return Err(f);
        }
        link.last_poll = Some(Instant::now());
        if link.state == 0 && now() >= link.expires_at {
            link.state = 3;
        }
        let mut answer = vec![(1, Value::Uint(link.state))];
        if let Some(ep) = link.endpoint {
            answer.push((2, bytes(&ep)));
        }
        Ok(map(answer))
    }

    fn token(&mut self, body: &[u8]) -> Answer {
        let (record, sig, mut f) = open_envelope(body, TOKEN_DOMAIN)?;
        let ep: [u8; 16] = f.fixed(2)?;
        let audience = f.text(3)?;
        let issued_at = f.uint(4)?;
        let nonce: [u8; 16] = f.fixed(5)?;
        f.finish()?;
        let key = match self.endpoints.get(&ep) {
            Some(e) if e.linked => e.key,
            _ => return Err(fail("unauthorized")),
        };
        verify(&key, &record, &sig)?;
        if audience != self.origin || issued_at.abs_diff(now()) > SKEW {
            return Err(fail("unauthorized"));
        }
        if !self.nonces.insert((ep, nonce)) {
            return Err(fail("unauthorized"));
        }
        let token = base64url(&random_bytes::<32>());
        let expires_at = now() + TOKEN_SECS;
        self.tokens.insert(token.clone(), (ep, expires_at));
        Ok(map(vec![
            (1, Value::Text(token)),
            (2, Value::Uint(expires_at)),
        ]))
    }

    // --- A.4 account ------------------------------------------------------

    fn account(&self, ep: [u8; 16]) -> Answer {
        let linked = self.endpoints.values().filter(|e| e.linked).count() as u64;
        Ok(map(vec![
            (1, Value::Uint(self.plan)),
            (2, Value::Text("standin".into())),
            (3, Value::Uint(self.period_start + PERIOD_SECS)),
            (4, bytes(&ep)),
            (5, Value::Uint(linked)),
        ]))
    }

    fn usage(&self) -> Vec<u8> {
        let pool = |p: &Pool, debt: bool| {
            let mut m = vec![
                (1, Value::Uint(p.balance)),
                (2, Value::Uint(0)),
                (3, Value::Uint(p.reserved)),
                (4, Value::Uint(p.available())),
            ];
            if debt {
                m.push((5, Value::Uint(0)));
            }
            Value::Map(m)
        };
        map(vec![
            (1, Value::Uint(self.period_start)),
            (2, Value::Uint(self.period_start + PERIOD_SECS)),
            (3, pool(&self.bulk, false)),
            (4, pool(&self.interactive, true)),
            (
                5,
                Value::Map(vec![(1, Value::Uint(0)), (2, Value::Uint(0))]),
            ),
        ])
    }

    fn unlink(&mut self, ep: [u8; 16], body: &[u8]) -> Answer {
        let mut f = Fields::decode(body)?;
        let id: [u8; 16] = f.fixed(1)?;
        f.finish()?;
        self.once(&ep, "/v1/endpoint/unlink", id, body, |s| {
            if let Some(e) = s.endpoints.get_mut(&ep) {
                e.linked = false;
            }
            s.tokens.retain(|_, (owner, _)| *owner != ep);
            let owned: Vec<[u8; 32]> = s
                .slots
                .iter()
                .filter(|(_, slot)| slot.owner == ep)
                .map(|(id, _)| *id)
                .collect();
            for id in owned {
                s.slots.remove(&id);
                s.deleted_slots.insert(id);
            }
            s.inboxes.retain(|_, inbox| inbox.owner != ep);
            Ok(map(vec![]))
        })
    }

    // --- A.7 admission and fleet -------------------------------------------

    fn relays(&self) -> Vec<u8> {
        let list = self
            .relays
            .iter()
            .map(|(key, region, endpoints)| {
                Value::Map(vec![
                    (1, bytes(key)),
                    (2, Value::Text(region.clone())),
                    (
                        3,
                        Value::Array(endpoints.iter().cloned().map(Value::Text).collect()),
                    ),
                ])
            })
            .collect();
        map(vec![(1, Value::Array(list))])
    }

    fn relay_admission(&mut self, ep: [u8; 16], body: &[u8]) -> Answer {
        let mut f = Fields::decode(body)?;
        let id: [u8; 16] = f.fixed(1)?;
        let relay: [u8; 32] = f.fixed(2)?;
        let registration: [u8; 65] = f.fixed(3)?;
        let proof = f.bytes(4)?;
        f.finish()?;
        PublicKey::from_sec1(&registration).map_err(|_| fail("invalid"))?;
        let proof = RawSignature::from_slice(&proof).map_err(|_| fail("invalid"))?;
        self.once(&ep, "/v1/relay-admission", id, body, |s| {
            let record = map(vec![
                (1, Value::Text(HANDLE_DOMAIN.into())),
                (2, bytes(&relay)),
                (3, bytes(&ep)),
            ]);
            verify(&registration, &record, &proof).map_err(|_| fail("forbidden"))?;
            let handle = sha256(&[b"mousse-relay-handle-v1", &relay, &registration]);
            if s.handles.get(&handle).is_some_and(|h| h.endpoint != ep) {
                return Err(fail("handle_taken"));
            }
            if s.plan != 1 {
                return Err(fail("not_plus"));
            }
            if let Entry::Vacant(e) = s.handles.entry(handle) {
                e.insert(Handle {
                    endpoint: ep,
                    relay,
                });
                s.newest.insert((ep, relay), handle);
            }
            let not_before = now();
            let record = map(vec![
                (1, Value::Text(ADMIT_DOMAIN.into())),
                (2, bytes(&s.issuer_kid)),
                (3, bytes(&relay)),
                (4, bytes(&handle)),
                (5, Value::Uint(not_before)),
                (6, Value::Uint(not_before + s.admission_secs)),
            ]);
            Ok(map(vec![(1, bytes(&s.sign(&record)))]))
        })
    }

    // --- A.8 leases ---------------------------------------------------------

    fn lease(&mut self, ep: [u8; 16], body: &[u8]) -> Answer {
        let mut f = Fields::decode(body)?;
        let id: [u8; 16] = f.fixed(1)?;
        let relay: [u8; 32] = f.fixed(2)?;
        let boot: [u8; 16] = f.fixed(3)?;
        let handle: [u8; 32] = f.fixed(4)?;
        let class = f.uint(5)?;
        f.finish()?;
        if class > 1 {
            return Err(fail("invalid"));
        }
        self.once(&ep, "/v1/lease", id, body, |s| {
            s.reserve(ep, relay, boot, handle, class)
        })
    }

    fn reserve(
        &mut self,
        ep: [u8; 16],
        relay: [u8; 32],
        boot: [u8; 16],
        handle: [u8; 32],
        class: u64,
    ) -> Answer {
        if !self
            .handles
            .get(&handle)
            .is_some_and(|h| h.endpoint == ep && h.relay == relay)
        {
            return Err(fail("forbidden"));
        }
        if self.plan != 1 {
            return Err(fail("not_plus"));
        }
        if !self.boots.contains(&(relay, boot)) {
            return Err(fail("unknown_boot"));
        }
        let open = self
            .leases
            .values()
            .filter(|l| !l.done && l.handle == handle && l.class == class && l.boot == boot)
            .count();
        let elsewhere = self
            .leases
            .values()
            .any(|l| !l.done && l.endpoint == ep && l.relay != relay);
        let newest = self.newest.get(&(ep, relay)) == Some(&handle);
        if open >= 2 || elsewhere || !newest {
            return Err(fail("cap_reached"));
        }
        let block_bytes = self.block_bytes;
        let pool = if class == 1 {
            &mut self.bulk
        } else {
            &mut self.interactive
        };
        let available = pool.available();
        if available < BLOCK_MIN {
            return Err(fail(if class == 1 {
                "allowance_used"
            } else {
                "balance_empty"
            }));
        }
        let size = block_bytes.min(available);
        pool.reserved += size;

        let seq = self.block_seq.entry((handle, class, boot)).or_insert(0);
        *seq += 1;
        let seq = *seq;
        let group = *self
            .rate_groups
            .entry(handle)
            .or_insert_with(random_bytes::<16>);
        let lease_id: [u8; 16] = random_bytes();
        let not_before = now();
        let record = map(vec![
            (1, Value::Text(LEASE_DOMAIN.into())),
            (2, bytes(&self.issuer_kid)),
            (3, bytes(&lease_id)),
            (4, bytes(&relay)),
            (5, bytes(&boot)),
            (6, bytes(&handle)),
            (7, Value::Uint(class)),
            (8, Value::Uint(seq)),
            (9, Value::Uint(RATE_CAP)),
            (10, Value::Uint(size)),
            (11, Value::Uint(not_before)),
            (
                12,
                Value::Uint(not_before + BLOCK_SECS.min(BLOCK_MAX_LIFETIME)),
            ),
            (13, bytes(&group)),
        ]);
        self.leases.insert(
            lease_id,
            Lease {
                endpoint: ep,
                relay,
                boot,
                handle,
                class,
                done: false,
            },
        );
        Ok(map(vec![(1, bytes(&self.sign(&record)))]))
    }

    // --- A.5 directory ------------------------------------------------------

    fn dir_put(&mut self, ep: [u8; 16], body: &[u8]) -> Answer {
        let mut f = Fields::decode(body)?;
        let id: [u8; 16] = f.fixed(1)?;
        let slot_id: [u8; 32] = f.fixed(2)?;
        let version = f.uint(3)?;
        let ciphertext = f.bytes(4)?;
        f.finish()?;
        if ciphertext.len() > DIR_ENTRY_MAX {
            return Err(fail("too_large"));
        }
        self.once(&ep, "/v1/dir/put", id, body, |s| {
            if s.deleted_slots.contains(&slot_id) {
                return Err(fail("not_found"));
            }
            match s.slots.get_mut(&slot_id) {
                Some(slot) if slot.owner != ep => return Err(fail("not_found")),
                Some(slot) => {
                    if version != slot.version + 1 {
                        return Err(fail("conflict"));
                    }
                    let old = std::mem::replace(&mut slot.ciphertext, ciphertext);
                    slot.history.push((slot.version, old));
                    slot.version = version;
                }
                None => {
                    if version != 1 {
                        return Err(fail("conflict"));
                    }
                    let owned = s.slots.values().filter(|x| x.owner == ep).count();
                    if owned >= s.slot_quota {
                        return Err(fail("quota"));
                    }
                    s.slots.insert(
                        slot_id,
                        Slot {
                            owner: ep,
                            version,
                            ciphertext,
                            history: Vec::new(),
                        },
                    );
                }
            }
            Ok(map(vec![]))
        })
    }

    fn dir_get(&mut self, body: &[u8]) -> Answer {
        let mut f = Fields::decode(body)?;
        let slot_id: [u8; 32] = f.fixed(1)?;
        f.finish()?;
        let slot = self.slots.get(&slot_id).ok_or_else(|| fail("not_found"))?;
        Ok(map(vec![
            (1, Value::Uint(slot.version)),
            (2, bytes(&slot.ciphertext)),
        ]))
    }

    fn dir_delete(&mut self, ep: [u8; 16], body: &[u8]) -> Answer {
        let mut f = Fields::decode(body)?;
        let slot_id: [u8; 32] = f.fixed(1)?;
        f.finish()?;
        match self.slots.get(&slot_id) {
            Some(slot) if slot.owner != ep => Err(fail("not_found")),
            Some(_) => {
                self.slots.remove(&slot_id);
                self.deleted_slots.insert(slot_id);
                Ok(map(vec![]))
            }
            None => Ok(map(vec![])),
        }
    }

    fn dir_list(&mut self, ep: [u8; 16], body: &[u8]) -> Answer {
        Fields::decode(body)?.finish()?;
        let mut mine: Vec<(&[u8; 32], u64)> = self
            .slots
            .iter()
            .filter(|(_, s)| s.owner == ep)
            .map(|(id, s)| (id, s.version))
            .collect();
        mine.sort();
        let list = mine
            .into_iter()
            .map(|(id, v)| Value::Map(vec![(1, bytes(id)), (2, Value::Uint(v))]))
            .collect();
        Ok(map(vec![(1, Value::Array(list))]))
    }

    // --- A.6 mailbox --------------------------------------------------------

    fn inbox_put(&mut self, ep: [u8; 16], body: &[u8]) -> Answer {
        let mut f = Fields::decode(body)?;
        let id: [u8; 16] = f.fixed(1)?;
        let inbox_id: [u8; 32] = f.fixed(2)?;
        let seq = f.uint(3)?;
        let entries = f.array(4)?;
        f.finish()?;
        if entries.len() > DEPOSIT_TOKENS_MAX {
            return Err(fail("too_large"));
        }
        let mut tokens = Vec::with_capacity(entries.len());
        for entry in entries {
            let mut e = Fields::from_value(entry)?;
            let tag: [u8; 16] = e.fixed(1)?;
            let hash: [u8; 32] = e.fixed(2)?;
            e.finish()?;
            tokens.push((tag, hash));
        }
        self.once(&ep, "/v1/inbox/put", id, body, |s| {
            match s.inboxes.get_mut(&inbox_id) {
                Some(inbox) if inbox.owner != ep => return Err(fail("not_found")),
                Some(inbox) => {
                    if seq <= inbox.seq {
                        return Err(fail("conflict"));
                    }
                    inbox.seq = seq;
                    inbox.tokens = tokens;
                    let kept: HashSet<[u8; 16]> = inbox.tokens.iter().map(|(t, _)| *t).collect();
                    inbox.messages.retain(|m| kept.contains(&m.tag));
                }
                None => {
                    if s.inboxes.values().any(|i| i.owner == ep) {
                        return Err(fail("quota"));
                    }
                    s.inboxes.insert(
                        inbox_id,
                        Inbox {
                            owner: ep,
                            seq,
                            tokens,
                            next_seq: 1,
                            messages: Vec::new(),
                        },
                    );
                }
            }
            Ok(map(vec![]))
        })
    }

    fn deposit(&mut self, req: &Request) -> Answer {
        let hash = Self::deposit_hash(req)?;
        let body = req.body.as_slice();
        let mut f = Fields::decode(body)?;
        let id: [u8; 16] = f.fixed(1)?;
        let inbox_id: [u8; 32] = f.fixed(2)?;
        let envelope = f.bytes(3)?;
        f.finish()?;
        if envelope.len() > MAIL_ENVELOPE_MAX {
            return Err(fail("too_large"));
        }
        let tag = self
            .inboxes
            .get(&inbox_id)
            .and_then(|i| i.tokens.iter().find(|(_, h)| *h == hash))
            .map(|(t, _)| *t)
            .ok_or_else(|| fail("unauthorized"))?;
        self.once(&hash, "/v1/inbox/deposit", id, body, |s| {
            let (tag_quota, inbox_quota) = (s.tag_quota, s.inbox_quota);
            let inbox = s.inboxes.get_mut(&inbox_id).expect("checked above");
            let under_tag = inbox.messages.iter().filter(|m| m.tag == tag).count();
            if under_tag >= tag_quota || inbox.messages.len() >= inbox_quota {
                return Err(fail("quota"));
            }
            let message_id = insert_message(inbox, tag, envelope);
            s.message_states.insert(
                message_id,
                MessageState {
                    inbox: inbox_id,
                    token_hash: hash,
                    state: 0,
                },
            );
            Ok(map(vec![(1, bytes(&message_id))]))
        })
    }

    fn inbox_fetch(&mut self, ep: [u8; 16], body: &[u8]) -> Answer {
        let mut f = Fields::decode(body)?;
        let inbox_id: [u8; 32] = f.fixed(1)?;
        let after = match f.optional(2) {
            None => None,
            Some(Value::Uint(n)) => Some(n),
            Some(_) => return Err(fail("invalid")),
        };
        f.finish()?;
        let inbox = self.owned_inbox(ep, &inbox_id)?;
        let mut waiting: Vec<&Message> = inbox
            .messages
            .iter()
            .filter(|m| after.is_none_or(|a| m.seq > a))
            .collect();
        waiting.sort_by_key(|m| m.seq);
        let list = waiting
            .into_iter()
            .take(self.page)
            .map(|m| {
                Value::Map(vec![
                    (1, bytes(&m.id)),
                    (2, Value::Uint(m.seq)),
                    (3, bytes(&m.tag)),
                    (4, Value::Uint(m.received_at)),
                    (5, bytes(&m.envelope)),
                ])
            })
            .collect();
        Ok(map(vec![(1, Value::Array(list))]))
    }

    fn inbox_ack(&mut self, ep: [u8; 16], body: &[u8]) -> Answer {
        let mut f = Fields::decode(body)?;
        let inbox_id: [u8; 32] = f.fixed(1)?;
        let mut ids = HashSet::new();
        for v in f.array(2)? {
            match v {
                Value::Bytes(b) if b.len() == 16 => {
                    ids.insert(<[u8; 16]>::try_from(b.as_slice()).unwrap());
                }
                _ => return Err(fail("invalid")),
            }
        }
        f.finish()?;
        self.owned_inbox(ep, &inbox_id)?;
        let inbox = self.inboxes.get_mut(&inbox_id).unwrap();
        inbox.messages.retain(|m| !ids.contains(&m.id));
        for id in ids {
            if let Some(st) = self.message_states.get_mut(&id) {
                if st.inbox == inbox_id {
                    st.state = 1;
                }
            }
        }
        Ok(map(vec![]))
    }

    fn message_state(&mut self, req: &Request) -> Answer {
        let hash = Self::deposit_hash(req)?;
        let mut f = Fields::decode(&req.body)?;
        let id: [u8; 16] = f.fixed(1)?;
        f.finish()?;
        let st = self
            .message_states
            .get(&id)
            .filter(|st| st.token_hash == hash)
            .ok_or_else(|| fail("not_found"))?;
        let still_valid = self
            .inboxes
            .get(&st.inbox)
            .is_some_and(|i| i.tokens.iter().any(|(_, h)| *h == hash));
        if !still_valid {
            return Err(fail("unauthorized"));
        }
        Ok(map(vec![(1, Value::Uint(st.state))]))
    }

    fn owned_inbox(&self, ep: [u8; 16], inbox_id: &[u8; 32]) -> Result<&Inbox, Fail> {
        self.inboxes
            .get(inbox_id)
            .filter(|i| i.owner == ep)
            .ok_or_else(|| fail("not_found"))
    }
}

fn insert_message(inbox: &mut Inbox, tag: [u8; 16], envelope: Vec<u8>) -> [u8; 16] {
    let id: [u8; 16] = random_bytes();
    inbox.messages.push(Message {
        id,
        seq: inbox.next_seq,
        tag,
        received_at: now(),
        envelope,
    });
    inbox.next_seq += 1;
    id
}

/// Split a signed envelope and check its record's domain. The caller
/// takes the record's other keys and verifies the signature.
fn open_envelope(body: &[u8], domain: &str) -> Result<(Vec<u8>, RawSignature, Fields), Fail> {
    let mut env = Fields::decode(body)?;
    let record = env.bytes(1)?;
    let sig = env.bytes(2)?;
    env.finish()?;
    let sig = RawSignature::from_slice(&sig).map_err(|_| fail("invalid"))?;
    let mut fields = Fields::decode(&record)?;
    if fields.text(1)? != domain {
        return Err(fail("invalid"));
    }
    Ok((record, sig, fields))
}

fn verify(key: &[u8; 65], record: &[u8], sig: &RawSignature) -> Result<(), Fail> {
    PublicKey::from_sec1(key)
        .ok()
        .and_then(|k| k.verify(record, sig).ok())
        .ok_or_else(|| fail("unauthorized"))
}

// ---------------------------------------------------------------------------
// HTTP

async fn serve(mut sock: TcpStream, state: Arc<Mutex<State>>) {
    let request = read_request(&mut sock).await;
    let (answer, lose) = match request {
        Ok(Some(req)) => {
            let mut s = lock(&state);
            s.handle(&req)
        }
        Ok(None) => return,
        Err(f) => (Err(f), false),
    };
    if lose {
        return;
    }
    let (status, body, retry) = match answer {
        Ok(body) => (200, body, None),
        Err(f) => {
            let mut m = vec![(1, Value::Text(f.code.clone()))];
            if let Some(r) = f.retry {
                m.push((2, Value::Uint(r)));
            }
            (f.status, map(m), f.retry)
        }
    };
    let mut head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        if status == 200 { "OK" } else { "Error" },
        body.len()
    );
    if let Some(r) = retry {
        head.push_str(&format!("Retry-After: {r}\r\n"));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(&body);
    let _ = sock.write_all(&out).await;
    let _ = sock.shutdown().await;
}

/// Read one request. `Ok(None)` when the peer went away.
async fn read_request(sock: &mut TcpStream) -> Result<Option<Request>, Fail> {
    const HEAD_MAX: usize = 16_384;
    const READ_MAX: usize = 1 << 20;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > HEAD_MAX {
            return Err(fail("too_large"));
        }
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return Ok(None),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| fail("invalid"))?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_string();
    let path = first.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    for line in lines {
        let (k, v) = line.split_once(':').ok_or_else(|| fail("invalid"))?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    let length = match headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        Some((_, v)) => v.parse::<usize>().map_err(|_| fail("invalid"))?,
        None => 0,
    };
    if length > READ_MAX {
        return Err(fail("too_large"));
    }
    let mut body = buf.split_off(head_end + 4);
    while body.len() < length {
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return Ok(None),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(length);
    Ok(Some(Request {
        method,
        path,
        headers,
        body,
    }))
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// The stand-in and its test hooks

/// A Plus stand-in on loopback. Stops when dropped.
pub struct PlusStandIn {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl PlusStandIn {
    /// Listen on 127.0.0.1 on a free port and serve on a new thread.
    pub fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State::new(format!("http://{addr}"))));
        let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
        let shared = state.clone();
        let thread = std::thread::Builder::new()
            .name("plus-standin".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    loop {
                        tokio::select! {
                            _ = &mut stopped => break,
                            accepted = listener.accept() => {
                                if let Ok((sock, _)) = accepted {
                                    tokio::spawn(serve(sock, shared.clone()));
                                }
                            }
                        }
                    }
                });
            })
            .unwrap();
        Self {
            addr,
            state,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    fn s(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    /// The origin, `http://127.0.0.1:<port>`; also the token audience.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The issuer key that signs admission tokens and blocks (SEC1).
    pub fn issuer_public_key(&self) -> [u8; 65] {
        *self.s().issuer.public_key().as_bytes()
    }

    /// Approve a pending link by its user code (with or without the dash).
    /// A Plus key that is already linked gets its existing endpoint id.
    pub fn approve(&self, user_code: &str) -> Option<[u8; 16]> {
        let code: String = user_code.chars().filter(|c| *c != '-').collect();
        let mut s = self.s();
        let t = now();
        let link_id = *s
            .links
            .iter()
            .find(|(_, l)| l.code == code && l.state == 0 && t < l.expires_at)?
            .0;
        let key = s.links[&link_id].key;
        let existing = s
            .endpoints
            .iter()
            .find(|(_, e)| e.linked && e.key == key)
            .map(|(id, _)| *id);
        let ep = existing.unwrap_or_else(|| {
            let id: [u8; 16] = random_bytes();
            s.endpoints.insert(id, Endpoint { key, linked: true });
            id
        });
        let link = s.links.get_mut(&link_id).unwrap();
        link.state = 1;
        link.endpoint = Some(ep);
        link.expires_at = t + 86_400;
        Some(ep)
    }

    /// Deny a pending link by its user code.
    pub fn deny(&self, user_code: &str) {
        let code: String = user_code.chars().filter(|c| *c != '-').collect();
        for link in self.s().links.values_mut() {
            if link.code == code && link.state == 0 {
                link.state = 2;
            }
        }
    }

    /// User codes of links still waiting for approval.
    pub fn pending_codes(&self) -> Vec<String> {
        let t = now();
        self.s()
            .links
            .values()
            .filter(|l| l.state == 0 && t < l.expires_at)
            .map(|l| l.code.clone())
            .collect()
    }

    /// Plan state: 0 none, 1 active, 2 past due, 3 cancelled.
    pub fn set_plan(&self, state: u64) {
        self.s().plan = state;
    }

    /// Bytes available for new blocks, per class. Clears reservations.
    pub fn set_balance(&self, bulk: u64, interactive: u64) {
        let mut s = self.s();
        s.bulk = Pool {
            balance: bulk,
            reserved: 0,
        };
        s.interactive = Pool {
            balance: interactive,
            reserved: 0,
        };
    }

    /// The default block size (never below 65 536).
    pub fn set_block_bytes(&self, n: u64) {
        self.s().block_bytes = n.max(BLOCK_MIN);
    }

    /// Admission token lifetime in seconds.
    pub fn set_admission_secs(&self, n: u64) {
        self.s().admission_secs = n;
    }

    /// The link poll interval handed out by `link/start`, in ms.
    pub fn set_link_poll_ms(&self, n: u64) {
        self.s().link_poll_ms = n;
    }

    /// Plus heard a boot record for this relay boot.
    pub fn register_boot(&self, relay_id: [u8; 32], boot_id: [u8; 16]) {
        self.s().boots.insert((relay_id, boot_id));
    }

    /// Plus has finished with this lease.
    pub fn finalize_lease(&self, lease_id: [u8; 16]) {
        if let Some(l) = self.s().leases.get_mut(&lease_id) {
            l.done = true;
        }
    }

    /// Plus has finished with every lease on this relay.
    pub fn finalize_relay(&self, relay_id: [u8; 32]) {
        for l in self.s().leases.values_mut() {
            if l.relay == relay_id {
                l.done = true;
            }
        }
    }

    /// The fleet `GET /v1/relays` lists: (identity key, region, endpoints).
    pub fn set_relays(&self, relays: Vec<([u8; 65], String, Vec<String>)>) {
        self.s().relays = relays;
    }

    /// The next request to `path` gets this error instead of an answer.
    pub fn fail_next(&self, path: &str, code: &str, status: u16, retry_after: Option<u64>) {
        let f = Fail {
            code: code.into(),
            status,
            retry: retry_after,
        };
        self.s().fail_next.insert(path.into(), f);
    }

    /// Process the next request to `path` fully, then close the connection
    /// without answering.
    pub fn lose_next_answer(&self, path: &str) {
        self.s().lose_next.insert(path.into());
    }

    /// Requests seen on `path`, failed ones included.
    pub fn request_count(&self, path: &str) -> usize {
        self.s().counts.get(path).copied().unwrap_or(0)
    }

    /// Lease request ids seen, in order, repeats included.
    pub fn lease_request_ids(&self) -> Vec<[u8; 16]> {
        self.s().lease_ids.clone()
    }

    /// Waiting messages: (message id, tag, envelope), by sequence.
    pub fn inbox_messages(&self, inbox_id: [u8; 32]) -> Vec<([u8; 16], [u8; 16], Vec<u8>)> {
        let s = self.s();
        let Some(inbox) = s.inboxes.get(&inbox_id) else {
            return Vec::new();
        };
        let mut list: Vec<&Message> = inbox.messages.iter().collect();
        list.sort_by_key(|m| m.seq);
        list.into_iter()
            .map(|m| (m.id, m.tag, m.envelope.clone()))
            .collect()
    }

    /// Most messages waiting under one tag.
    pub fn set_tag_quota(&self, n: usize) {
        self.s().tag_quota = n;
    }

    /// Most messages waiting in one inbox.
    pub fn set_inbox_quota(&self, n: usize) {
        self.s().inbox_quota = n;
    }

    /// Most messages in one fetch answer.
    pub fn set_page(&self, n: usize) {
        self.s().page = n;
    }

    /// Most directory slots per endpoint.
    pub fn set_slot_quota(&self, n: usize) {
        self.s().slot_quota = n;
    }

    // --- Hostile Plus ----------------------------------------------------

    /// Plus itself inserts a message, without a token, under the inbox's
    /// first tag (or a zero tag when it has none).
    pub fn plus_deposits(&self, inbox_id: [u8; 32], envelope: Vec<u8>) -> Option<[u8; 16]> {
        let tag = {
            let s = self.s();
            let inbox = s.inboxes.get(&inbox_id)?;
            inbox.tokens.first().map(|(t, _)| *t).unwrap_or([0; 16])
        };
        self.plus_deposits_as(inbox_id, tag, envelope)
    }

    /// Plus itself inserts a message under a tag of its choosing.
    pub fn plus_deposits_as(
        &self,
        inbox_id: [u8; 32],
        tag: [u8; 16],
        envelope: Vec<u8>,
    ) -> Option<[u8; 16]> {
        let mut s = self.s();
        let inbox = s.inboxes.get_mut(&inbox_id)?;
        Some(insert_message(inbox, tag, envelope))
    }

    /// Serve slot `a`'s version and ciphertext under `b` and the other way.
    pub fn swap_slots(&self, a: [u8; 32], b: [u8; 32]) {
        let mut s = self.s();
        let (Some(mut x), Some(mut y)) = (s.slots.remove(&a), s.slots.remove(&b)) else {
            return;
        };
        std::mem::swap(&mut x.version, &mut y.version);
        std::mem::swap(&mut x.ciphertext, &mut y.ciphertext);
        s.slots.insert(a, x);
        s.slots.insert(b, y);
    }

    /// Store any version and ciphertext in a slot, bypassing every check.
    pub fn overwrite_slot(&self, slot: [u8; 32], version: u64, ciphertext: Vec<u8>) {
        let mut s = self.s();
        let entry = s.slots.entry(slot).or_insert(Slot {
            owner: [0; 16],
            version: 0,
            ciphertext: Vec::new(),
            history: Vec::new(),
        });
        entry.version = version;
        entry.ciphertext = ciphertext;
    }

    /// Roll a slot back one version, as a restore that lost a write. A slot
    /// at its first version disappears (not as a deletion: it may be
    /// created again).
    pub fn restore_lose_slot_write(&self, slot: [u8; 32]) {
        let mut s = self.s();
        let Some(entry) = s.slots.get_mut(&slot) else {
            return;
        };
        match entry.history.pop() {
            Some((version, ciphertext)) => {
                entry.version = version;
                entry.ciphertext = ciphertext;
            }
            None => {
                s.slots.remove(&slot);
            }
        }
    }

    /// Inbox sequences restart, as after a restore: waiting messages are
    /// numbered again from 1 and new ones follow.
    pub fn restart_sequences(&self) {
        for inbox in self.s().inboxes.values_mut() {
            inbox.messages.sort_by_key(|m| m.seq);
            for (i, m) in inbox.messages.iter_mut().enumerate() {
                m.seq = i as u64 + 1;
            }
            inbox.next_seq = inbox.messages.len() as u64 + 1;
        }
    }

    /// Stop serving and join the server thread.
    pub fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for PlusStandIn {
    fn drop(&mut self) {
        self.stop();
    }
}
