//! TEST FIXTURE ONLY: a stand-in for Plus's issuer, for the hosted relay's
//! tests, until the Plus team's double (P8) exists. Replace it with that
//! double when it lands.
//!
//! It holds a throwaway issuer key and does only what the relay needs, as
//! the contract (`docs/phase34-design.md` Part A) states it:
//!
//! - signs admission tokens and lease blocks (§A.12);
//! - answers `POST /v1/relay/boot` and `POST /v1/relay/report` (§A.9) on
//!   loopback, over plain HTTP, with Plus time in milliseconds;
//! - lists a lease as settled once it has received a final entry for it.
//!
//! It has no accounts, balances, caps or settlement rules: none of Plus's
//! internals. It never listens off loopback.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use mousse_net_core::identity::{PublicKey, SoftwareKey};
use mousse_net_core::relay_hosted::records::{issuer_key_id, REPORT_MAX, REQUEST_MAX};
use mousse_net_core::relay_hosted::{
    AdmissionToken, BootAnswer, BootId, BootRecord, Class, ErrorBody, Handle, IssuerKeys,
    LeaseBlock, LeaseId, RateGroup, RelayId, ReportAnswer, ReportPart, SignedEnvelope,
};

/// One block's fields; [`TestIssuerStandIn::block`] signs it.
#[derive(Clone, Debug)]
pub struct BlockSpec {
    pub lease_id: LeaseId,
    pub relay_id: RelayId,
    pub boot_id: BootId,
    pub handle: Handle,
    pub class: Class,
    pub sequence: u64,
    pub rate_cap: u64,
    pub bytes: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub rate_group: RateGroup,
}

#[derive(Default)]
struct State {
    /// Report keys of the fleet's relays.
    relays: HashMap<RelayId, PublicKey>,
    /// Stored boot records, by relay and boot id.
    boots: HashMap<(RelayId, BootId), Vec<u8>>,
    /// Highest generation per relay, with its boot id.
    highest: HashMap<RelayId, (u64, BootId)>,
    /// Every boot body received, in order (also refused ones).
    boot_bodies: Vec<Vec<u8>>,
    /// Every report part stored, in arrival order.
    parts: Vec<ReportPart>,
    /// Stored report sequences per boot.
    stored: HashMap<(RelayId, BootId), BTreeSet<u64>>,
    /// The first final counters received per lease.
    finals: BTreeMap<LeaseId, (u64, u64)>,
    /// Plus time offset from this machine's clock, ms.
    offset_ms: i64,
    /// Answer this many next requests with 503 `internal`.
    fail_next: usize,
    /// Fail every request.
    down: bool,
    /// Wait this long before answering.
    delay_ms: u64,
}

/// The stand-in. Dropping it stops its listener.
pub struct TestIssuerStandIn {
    issuer: SoftwareKey,
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Drop for TestIssuerStandIn {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn now_ms(offset: i64) -> u64 {
    let sys = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    (sys + offset).max(0) as u64
}

impl TestIssuerStandIn {
    /// Start on 127.0.0.1 with a throwaway issuer key from `seed`.
    pub async fn start(seed: u8) -> Self {
        let issuer = SoftwareKey::generate(&mut ChaCha20Rng::from_seed([seed; 32]));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let s = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((conn, _)) = listener.accept().await else {
                    return;
                };
                let s = s.clone();
                tokio::spawn(async move {
                    let _ = serve(conn, s).await;
                });
            }
        });
        Self {
            issuer,
            addr,
            state,
            task,
        }
    }

    /// The base URL for `MOUSSE_NET_RELAY_PLUS_URL`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The throwaway issuer public key.
    pub fn issuer_public_key(&self) -> PublicKey {
        self.issuer.public_key()
    }

    /// The issuer keys a relay pins for this stand-in.
    pub fn keys(&self) -> IssuerKeys {
        IssuerKeys::new([self.issuer.public_key()])
    }

    /// Add a relay to the fleet with its report key.
    pub fn add_relay(&self, relay_id: RelayId, report_key: PublicKey) {
        self.state
            .lock()
            .unwrap()
            .relays
            .insert(relay_id, report_key);
    }

    /// Plus time now, Unix ms.
    pub fn plus_now_ms(&self) -> u64 {
        now_ms(self.state.lock().unwrap().offset_ms)
    }

    /// Plus time now, Unix seconds.
    pub fn plus_now(&self) -> u64 {
        self.plus_now_ms() / 1_000
    }

    /// Run Plus's clock `ms` ahead of this machine's (negative: behind).
    pub fn set_offset_ms(&self, ms: i64) {
        self.state.lock().unwrap().offset_ms = ms;
    }

    /// Answer the next `n` requests with 503.
    pub fn fail_next(&self, n: usize) {
        self.state.lock().unwrap().fail_next = n;
    }

    /// Fail every request until set back.
    pub fn set_down(&self, down: bool) {
        self.state.lock().unwrap().down = down;
    }

    /// Wait `ms` before each answer.
    pub fn set_delay_ms(&self, ms: u64) {
        self.state.lock().unwrap().delay_ms = ms;
    }

    /// Pretend a boot of `relay_id` with `generation` was already announced
    /// under another boot id.
    pub fn seed_generation(&self, relay_id: RelayId, generation: u64) {
        self.state
            .lock()
            .unwrap()
            .highest
            .insert(relay_id, (generation, [0xee; 16]));
    }

    /// Forget the relay's generations (an operator resolving a rollback).
    pub fn clear_generations(&self, relay_id: RelayId) {
        self.state.lock().unwrap().highest.remove(&relay_id);
    }

    /// Every boot body received.
    pub fn boot_bodies(&self) -> Vec<Vec<u8>> {
        self.state.lock().unwrap().boot_bodies.clone()
    }

    /// Every report part stored.
    pub fn parts(&self) -> Vec<ReportPart> {
        self.state.lock().unwrap().parts.clone()
    }

    /// The first final counters received for `lease`.
    pub fn final_of(&self, lease: LeaseId) -> Option<(u64, u64)> {
        self.state.lock().unwrap().finals.get(&lease).copied()
    }

    /// Sign an admission token.
    pub fn token(
        &self,
        relay_id: RelayId,
        handle: Handle,
        not_before: u64,
        not_after: u64,
    ) -> Vec<u8> {
        let t = AdmissionToken {
            issuer_key_id: issuer_key_id(&self.issuer.public_key()),
            relay_id,
            handle,
            not_before,
            not_after,
        };
        SignedEnvelope::sign(t.encode(), &self.issuer).encode()
    }

    /// Sign a lease block.
    pub fn block(&self, b: &BlockSpec) -> Vec<u8> {
        let block = LeaseBlock {
            issuer_key_id: issuer_key_id(&self.issuer.public_key()),
            lease_id: b.lease_id,
            relay_id: b.relay_id,
            boot_id: b.boot_id,
            handle: b.handle,
            class: b.class,
            sequence: b.sequence,
            rate_cap: b.rate_cap,
            bytes: b.bytes,
            not_before: b.not_before,
            expires_at: b.expires_at,
            rate_group: b.rate_group,
        };
        SignedEnvelope::sign(block.encode(), &self.issuer).encode()
    }
}

fn error(status: u16, code: &str) -> (u16, Vec<u8>) {
    (
        status,
        ErrorBody {
            code: code.into(),
            retry_after_secs: None,
        }
        .encode(),
    )
}

async fn serve(mut conn: TcpStream, state: Arc<Mutex<State>>) -> std::io::Result<()> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 8_192];
    let (path, version, ctype, body) = loop {
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        raw.extend_from_slice(&buf[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        let Ok(httparse::Status::Complete(head)) = req.parse(&raw) else {
            if raw.len() > 16_384 + REPORT_MAX {
                return Ok(());
            }
            continue;
        };
        let header = |name: &str| {
            req.headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(name))
                .map(|h| String::from_utf8_lossy(h.value).into_owned())
        };
        let len: usize = header("content-length")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        if raw.len() >= head + len {
            break (
                req.path.unwrap_or("").to_owned(),
                header("mousse-plus-api"),
                header("content-type"),
                raw[head..head + len].to_vec(),
            );
        }
    };
    let (delay, fail) = {
        let mut s = state.lock().unwrap();
        let fail = s.down || s.fail_next > 0;
        s.fail_next = s.fail_next.saturating_sub(1);
        (s.delay_ms, fail)
    };
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    let (status, answer) = if fail {
        // Record what arrived, then fail.
        if path == "/v1/relay/boot" {
            state.lock().unwrap().boot_bodies.push(body.clone());
        }
        error(503, "internal")
    } else if version.as_deref() != Some("1.0") {
        error(400, "version")
    } else if ctype.as_deref() != Some("application/cbor") {
        error(400, "invalid")
    } else {
        match path.as_str() {
            "/v1/relay/boot" => boot(&state, body),
            "/v1/relay/report" => report(&state, body),
            _ => error(404, "not_found"),
        }
    };
    let head = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        answer.len()
    );
    conn.write_all(head.as_bytes()).await?;
    conn.write_all(&answer).await?;
    conn.shutdown().await
}

fn open(body: &[u8], max: usize) -> Result<SignedEnvelope, (u16, Vec<u8>)> {
    if body.len() > max {
        return Err(error(413, "too_large"));
    }
    SignedEnvelope::decode(body).map_err(|_| error(400, "invalid"))
}

fn boot(state: &Mutex<State>, body: Vec<u8>) -> (u16, Vec<u8>) {
    let mut s = state.lock().unwrap();
    s.boot_bodies.push(body.clone());
    let env = match open(&body, REQUEST_MAX) {
        Ok(e) => e,
        Err(e) => return e,
    };
    let Ok(rec) = BootRecord::decode(&env.record) else {
        return error(400, "invalid");
    };
    let Some(key) = s.relays.get(&rec.relay_id).copied() else {
        return error(401, "unauthorized");
    };
    if env.verify(&key).is_err() {
        return error(401, "unauthorized");
    }
    let id = (rec.relay_id, rec.boot_id);
    if s.boots.get(&id) == Some(&env.record) {
        // A repeat of a stored record is acknowledged (§A.9 duty 2).
    } else {
        if let Some((g, other)) = s.highest.get(&rec.relay_id) {
            if rec.generation <= *g && *other != rec.boot_id {
                return error(409, "stale_generation");
            }
        }
        s.highest
            .insert(rec.relay_id, (rec.generation, rec.boot_id));
        s.boots.insert(id, env.record.clone());
    }
    (
        200,
        BootAnswer {
            plus_time_ms: now_ms(s.offset_ms),
        }
        .encode(),
    )
}

fn report(state: &Mutex<State>, body: Vec<u8>) -> (u16, Vec<u8>) {
    let mut s = state.lock().unwrap();
    let env = match open(&body, REPORT_MAX) {
        Ok(e) => e,
        Err(e) => return e,
    };
    let Ok(part) = ReportPart::decode(&env.record) else {
        return error(400, "invalid");
    };
    let Some(key) = s.relays.get(&part.relay_id).copied() else {
        return error(401, "unauthorized");
    };
    if env.verify(&key).is_err() {
        return error(401, "unauthorized");
    }
    let id = (part.relay_id, part.boot_id);
    if !s.boots.contains_key(&id) {
        return error(409, "unknown_boot");
    }
    for e in &part.entries {
        if e.is_final {
            s.finals
                .entry(e.lease_id)
                .or_insert((e.to_target, e.to_caller));
        }
    }
    let settled: Vec<LeaseId> = part
        .entries
        .iter()
        .filter(|e| s.finals.contains_key(&e.lease_id))
        .map(|e| e.lease_id)
        .collect();
    let stored = s.stored.entry(id).or_default();
    stored.insert(part.sequence);
    let highest = *stored.iter().next_back().unwrap_or(&0);
    s.parts.push(part);
    (
        200,
        ReportAnswer {
            highest_sequence: highest,
            settled,
            stop: vec![],
            plus_time_ms: now_ms(s.offset_ms),
        }
        .encode(),
    )
}
