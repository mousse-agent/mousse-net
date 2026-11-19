//! The relay's hosted mode (`docs/phase34-design.md` §B.10, §A.9), with no
//! I/O: admission tokens and the keep-while-funded rule, leases and their
//! byte-exact counters, rate groups, pause and refill, `RELEASE`,
//! `LEASE_STATUS`, the Plus clock, and the snapshot reports.
//!
//! [`Hosted`] is one relay boot. The relay's connection code calls it on
//! every hosted message (`REGISTER`, `ADMIT`, `LEASE`, `RELEASE`), before
//! every spliced message it forwards ([`Hosted::forward`]), then calls
//! [`Hosted::poll`] (after each call, and at the instant
//! [`Hosted::next_wakeup`] names) and acts on the [`Event`]s it returns.
//! The relay's Plus client feeds Plus's answers back in and sends the
//! parts [`Hosted::next_report_part`] builds.
//!
//! Counters live in memory only; the boot generation is the only
//! lease-related state on disk (§B.10).

pub mod clock;
pub mod records;
mod report;

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use crate::time::Millis;

pub use clock::PlusClock;
pub use records::{
    AdmissionToken, BootAnswer, BootId, BootRecord, BootState, Class, ErrorBody, Handle,
    IssuerKeys, LeaseBlock, LeaseId, RateGroup, RecordError, RelayId, ReportAnswer, ReportEntry,
    ReportPart, SignedEnvelope,
};

use records::{BLOCK_MAX_LIFETIME_SECS, CLASSES, MESSAGE_MAX, RATE_CAP_FLOOR, RELEASE_IDS_MAX};
use report::ReportQueue;

crate::define_limits! {
    /// The hosted relay's limits (§H.1). The relay reads each from
    /// `MOUSSE_NET_<NAME>`; every name starts with `RELAY_`.
    pub struct HostedLimits {
        /// A paused class waits this long for a LEASE before its circuits close with 4001; with the longest peer keepalive (15 s) it stays below the shortest peer idle timeout (30 s), so tighten only.
        refill_wait_ms = "RELAY_REFILL_WAIT_MS": 10_000, [1_000, 10_000];
        /// Snapshot interval; below Plus's boot silence time (120 s by default).
        report_ms = "RELAY_REPORT_MS": 10_000, [1_000, 60_000];
        /// Longest delay from a final to its snapshot, and the shortest gap between snapshots; below REPORT_MS.
        report_min_ms = "RELAY_REPORT_MIN_MS": 1_000, [100, 5_000];
        /// On a graceful stop, how long to wait for the stopping snapshot to be stored.
        final_report_wait_ms = "RELAY_FINAL_REPORT_WAIT_MS": 5_000, [0, 60_000];
        /// One call to Plus.
        plus_timeout_ms = "RELAY_PLUS_TIMEOUT_MS": 10_000, [1_000, 60_000];
        /// Longest round trip whose Plus answer may set the Plus clock; a longer one only ends leases earlier.
        clock_rtt_ms = "RELAY_CLOCK_RTT_MS": 2_000, [100, 10_000];
        /// First wait before sending a boot announcement or report part again after a failed call.
        plus_retry_first_ms = "RELAY_PLUS_RETRY_FIRST_MS": 1_000, [100, 60_000];
        /// Longest such wait; not below the first.
        plus_retry_max_ms = "RELAY_PLUS_RETRY_MAX_MS": 30_000, [1_000, 600_000];
        /// Largest Plus answer read.
        plus_answer_max_bytes = "RELAY_PLUS_ANSWER_MAX_BYTES": 65_536, [16_384, 1_048_576];
    }
    agree(l) {
        if l.report_min_ms >= l.report_ms {
            return Err(crate::limits::LimitError::Conflict(format!(
                "RELAY_REPORT_MIN_MS ({}) is not below RELAY_REPORT_MS ({})",
                l.report_min_ms, l.report_ms
            )));
        }
        if l.plus_retry_max_ms < l.plus_retry_first_ms {
            return Err(crate::limits::LimitError::Conflict(format!(
                "RELAY_PLUS_RETRY_MAX_MS ({}) is below RELAY_PLUS_RETRY_FIRST_MS ({})",
                l.plus_retry_max_ms, l.plus_retry_first_ms
            )));
        }
    }
}

/// WebSocket close code: the class's lease ran out with no refill (§B.2).
pub const CLOSE_LEASE_EXHAUSTED: u16 = 4001;
/// WebSocket close code: past the admission token with no usable block.
pub const CLOSE_ADMISSION_EXPIRED: u16 = 4004;

/// The lowest and highest status threshold a `REGISTER` may give (§B.3).
pub const THRESHOLD_PERCENT: core::ops::RangeInclusive<u64> = 10..=90;

/// Both clocks, read together by the caller: the relay machine's.
pub use crate::relay::machine::Now;

/// Which way a spliced message goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Caller → target.
    ToTarget,
    /// Target → caller.
    ToCaller,
}

/// A lease's state in `LEASE_STATUS` (§B.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseState {
    /// 0: held, waiting for the current one to be spent.
    Pending,
    /// 1: being spent.
    Current,
    /// 2: final; its counters never change again.
    Final,
    /// 3: the `LEASE` was refused.
    Refused,
}

impl LeaseState {
    /// The wire value.
    pub const fn to_u64(self) -> u64 {
        match self {
            LeaseState::Pending => 0,
            LeaseState::Current => 1,
            LeaseState::Final => 2,
            LeaseState::Refused => 3,
        }
    }
}

/// One entry of `LEASE_STATUS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseStatus {
    /// Key 1.
    pub lease_id: LeaseId,
    /// Key 2.
    pub class: Class,
    /// Key 3: bytes forwarded, both directions.
    pub used: u64,
    /// Key 4: the block's bytes.
    pub bytes: u64,
    /// Key 5.
    pub state: LeaseState,
}

impl From<LeaseStatus> for crate::relay::msg::LeaseStatusEntry {
    fn from(s: LeaseStatus) -> Self {
        Self {
            lease: s.lease_id,
            class: s.class,
            used: s.used,
            bytes: s.bytes,
            state: s.state.to_u64() as u8,
        }
    }
}

/// Why a lease became final (§A.9 duty 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalReason {
    /// All its bytes were forwarded.
    Spent,
    /// Its `expires at` passed on the Plus clock, or the clock went stale.
    Expired,
    /// Its target released it.
    Released,
    /// It was current when its class closed with 4001.
    Closed,
    /// The relay is stopping.
    Stopped,
    /// Plus listed it as settled while the relay still held it open.
    Settled,
}

/// Something the relay's connection code must do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Send `LEASE_STATUS` with these entries on the handle's registration
    /// connection, if it has one.
    Status {
        /// The target.
        handle: Handle,
        /// The entries.
        entries: Vec<LeaseStatus>,
    },
    /// A paused class has a new lease: read its legs again.
    Resumed {
        /// The target.
        handle: Handle,
        /// The class.
        class: Class,
    },
    /// Close every circuit of this class of the handle with `code` (4001).
    CloseClass {
        /// The target.
        handle: Handle,
        /// The class.
        class: Class,
        /// The WebSocket close code.
        code: u16,
    },
    /// Close the handle's registration and every circuit of the handle with
    /// `code` (4004).
    CloseHandle {
        /// The target.
        handle: Handle,
        /// The WebSocket close code.
        code: u16,
    },
}

/// What to do with one spliced message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forward {
    /// Forward it now; it has been counted.
    Go,
    /// The rate group's bucket is short: try again at `until`, reading
    /// nothing from this leg meanwhile.
    Wait {
        /// Monotonic instant.
        until: Millis,
    },
    /// The class has no lease that can cover it: stop reading the leg until
    /// [`Event::Resumed`], or until [`Event::CloseClass`].
    Paused,
    /// The relay is stopping and forwards nothing.
    Stopped,
}

/// Why a `REGISTER` or `ADMIT` was refused (`REFUSED(admission)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionRefusal {
    /// The token does not decode or verify under a pinned issuer key.
    Token(RecordError),
    /// The token names another relay.
    WrongRelay,
    /// The token names another handle.
    WrongHandle,
    /// Before the token's `not before`. The helper presents it again later.
    NotBefore,
    /// Past `not after`, and (for `REGISTER`) the handle holds no usable
    /// block.
    Expired,
    /// A hosted `REGISTER` without a status threshold in 10 to 90.
    Threshold,
    /// `ADMIT` on a connection that is not a live registration.
    NotRegistered,
    /// The relay is stopping.
    Stopping,
}

impl fmt::Display for AdmissionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdmissionRefusal::Token(e) => write!(f, "admission token rejected: {e}"),
            AdmissionRefusal::WrongRelay => f.write_str("admission token names another relay"),
            AdmissionRefusal::WrongHandle => f.write_str("admission token names another handle"),
            AdmissionRefusal::NotBefore => f.write_str("admission token is not valid yet"),
            AdmissionRefusal::Expired => f.write_str("admission token has expired"),
            AdmissionRefusal::Threshold => f.write_str("status threshold missing or out of range"),
            AdmissionRefusal::NotRegistered => f.write_str("no live registration"),
            AdmissionRefusal::Stopping => f.write_str("relay is stopping"),
        }
    }
}

/// Why a `LEASE` was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseRefusal {
    /// The relay is stopping.
    Stopping,
    /// No live registration for the handle.
    NotRegistered,
    /// Past the admission token's `not after` (§A.9 duty 10).
    AdmissionExpired,
    /// The block does not decode or verify under a pinned issuer key.
    Record(RecordError),
    /// The block names another relay.
    WrongRelay,
    /// The block names another boot.
    WrongBoot,
    /// The block names another handle.
    WrongHandle,
    /// Rate cap below 65 536 bytes per second.
    RateCapTooLow,
    /// Fewer bytes than the largest message.
    TooSmall,
    /// `expires at` not after `not before`, or more than
    /// `BLOCK_MAX_LIFETIME` after it.
    BadWindow,
    /// No fresh Plus clock yet (§A.9 duty 12). The helper presents it again.
    NoPlusClock,
    /// Before `not before` on the Plus clock. The helper presents it again.
    NotBefore,
    /// At or past `expires at` on the Plus clock.
    Expired,
    /// The block sequence is not above the last accepted for this handle
    /// and class in this boot (§A.9 duty 6).
    SequenceNotAbove,
    /// A lease with this id is already held in this boot.
    DuplicateLease,
    /// A current and a pending lease of this class are already held.
    Full,
}

impl LeaseRefusal {
    /// Stable snake_case name.
    pub fn code(self) -> &'static str {
        match self {
            LeaseRefusal::Stopping => "stopping",
            LeaseRefusal::NotRegistered => "not_registered",
            LeaseRefusal::AdmissionExpired => "admission_expired",
            LeaseRefusal::Record(e) => e.code(),
            LeaseRefusal::WrongRelay => "wrong_relay",
            LeaseRefusal::WrongBoot => "wrong_boot",
            LeaseRefusal::WrongHandle => "wrong_handle",
            LeaseRefusal::RateCapTooLow => "rate_cap_too_low",
            LeaseRefusal::TooSmall => "too_small",
            LeaseRefusal::BadWindow => "bad_window",
            LeaseRefusal::NoPlusClock => "no_plus_clock",
            LeaseRefusal::NotBefore => "not_before",
            LeaseRefusal::Expired => "expired",
            LeaseRefusal::SequenceNotAbove => "sequence_not_above",
            LeaseRefusal::DuplicateLease => "duplicate_lease",
            LeaseRefusal::Full => "full",
        }
    }
}

/// A refused `LEASE`: the reason, and the `LEASE_STATUS` entry (state 3)
/// to send when the block named a lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseRefused {
    /// Why.
    pub reason: LeaseRefusal,
    /// The entry to send, when the block could be read.
    pub status: Option<LeaseStatus>,
}

/// Why a `RELEASE` was refused. Nothing changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseRefusal {
    /// More than four lease ids.
    TooMany,
    /// A lease id that another handle holds.
    OtherHandle,
}

#[derive(Clone, Debug)]
struct Lease {
    handle: Handle,
    class: Class,
    rate_group: RateGroup,
    bytes: u64,
    not_before_ms: u64,
    expires_ms: u64,
    to_target: u64,
    to_caller: u64,
    final_reason: Option<FinalReason>,
    threshold_sent: bool,
}

impl Lease {
    fn used(&self) -> u64 {
        self.to_target.saturating_add(self.to_caller)
    }

    fn remaining(&self) -> u64 {
        self.bytes.saturating_sub(self.used())
    }

    fn status(&self, id: LeaseId, state: LeaseState) -> LeaseStatus {
        LeaseStatus {
            lease_id: id,
            class: self.class,
            used: self.used(),
            bytes: self.bytes,
            state,
        }
    }

    fn entry(&self, id: LeaseId) -> ReportEntry {
        ReportEntry {
            lease_id: id,
            to_target: self.to_target,
            to_caller: self.to_caller,
            is_final: self.final_reason.is_some(),
        }
    }
}

/// The leases one handle holds for one class.
#[derive(Clone, Debug, Default)]
struct Slot {
    current: Option<LeaseId>,
    pending: Option<LeaseId>,
    /// The highest block sequence accepted for this handle and class in
    /// this boot. Never goes down, and is kept for the whole boot.
    last_sequence: u64,
    /// When the class paused for want of a lease.
    paused_since: Option<Millis>,
}

#[derive(Clone, Copy, Debug)]
struct Admission {
    /// The latest `not after` of a valid token presented, Unix seconds.
    not_after: u64,
    /// Status threshold percent from `REGISTER`.
    threshold: u64,
    /// Whether a registration connection is live.
    registered: bool,
}

/// A token bucket in thousandths of a byte, so refill is exact in
/// milliseconds.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    cap: u64,
    milli: u128,
    at: Millis,
}

impl Bucket {
    fn full(cap: u64, at: Millis) -> Self {
        Self {
            cap,
            milli: u128::from(cap) * 1_000,
            at,
        }
    }

    fn capacity(&self) -> u128 {
        u128::from(self.cap) * 1_000
    }

    fn refill(&mut self, now: Millis) {
        if now > self.at {
            let add = u128::from(self.cap) * u128::from(now.since(self.at));
            self.milli = (self.milli + add).min(self.capacity());
            self.at = now;
        }
    }

    /// When `bytes` will be available, if not now.
    fn short_until(&self, bytes: u64, now: Millis) -> Option<Millis> {
        let need = u128::from(bytes) * 1_000;
        if self.milli >= need {
            return None;
        }
        let cap = u128::from(self.cap.max(1));
        let ms = (need - self.milli).div_ceil(cap);
        Some(now.plus(u64::try_from(ms).unwrap_or(u64::MAX)))
    }
}

/// Bucket key: `{rate group, class}` (§A.9 duty 8). The third part is
/// always 0, except in the `per-socket-rate` control build, where it is the
/// circuit: the planted bug that lets parallel sockets multiply the rate.
type BucketKey = (RateGroup, Class, u64);

/// One hosted relay boot.
pub struct Hosted {
    relay_id: RelayId,
    boot_id: BootId,
    limits: HostedLimits,
    keys: IssuerKeys,
    clock: PlusClock,
    leases: BTreeMap<LeaseId, Lease>,
    slots: BTreeMap<(Handle, Class), Slot>,
    admissions: BTreeMap<Handle, Admission>,
    buckets: BTreeMap<BucketKey, Bucket>,
    /// The cap of the block most recently accepted per group and class.
    group_caps: BTreeMap<(RateGroup, Class), u64>,
    events: VecDeque<Event>,
    stopping: bool,
    reports: ReportQueue,
    /// A lease became final since the reporter last looked.
    report_wake: bool,
}

impl fmt::Debug for Hosted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hosted")
            .field("leases", &self.leases.len())
            .field("registrations", &self.admissions.len())
            .field("stopping", &self.stopping)
            .finish_non_exhaustive()
    }
}

impl Hosted {
    /// A new boot of the relay `relay_id`, pinning `keys`.
    pub fn new(relay_id: RelayId, boot_id: BootId, keys: IssuerKeys, limits: HostedLimits) -> Self {
        Self {
            relay_id,
            boot_id,
            limits,
            keys,
            clock: PlusClock::new(),
            leases: BTreeMap::new(),
            slots: BTreeMap::new(),
            admissions: BTreeMap::new(),
            buckets: BTreeMap::new(),
            group_caps: BTreeMap::new(),
            events: VecDeque::new(),
            stopping: false,
            reports: ReportQueue::new(),
            report_wake: false,
        }
    }

    /// This boot's id, announced in `RELAY_HELLO` and the boot record.
    pub fn boot_id(&self) -> BootId {
        self.boot_id
    }

    /// The relay id.
    pub fn relay_id(&self) -> RelayId {
        self.relay_id
    }

    /// The limits in force.
    pub fn limits(&self) -> &HostedLimits {
        &self.limits
    }

    /// Replace the pinned issuer keys (`mousse-relay reload`). Leases and
    /// registrations already accepted are kept.
    pub fn set_issuer_keys(&mut self, keys: IssuerKeys) {
        self.keys = keys;
    }

    /// The Plus clock.
    pub fn clock(&self) -> &PlusClock {
        &self.clock
    }

    /// Whether the relay is stopping.
    pub fn is_stopping(&self) -> bool {
        self.stopping
    }

    fn admission_now_ms(&self, now: Now) -> u64 {
        self.clock.now_or_wall_ms(now.mono, now.wall)
    }

    /// Plus time for lease windows; `None` while no fresh clock exists.
    fn lease_now_ms(&self, now: Now) -> Option<u64> {
        #[cfg(mousse_control = "expiry-on-relay-wall-clock")]
        {
            return Some(now.wall.secs().saturating_mul(1_000));
        }
        #[allow(unreachable_code)]
        if !self.clock.is_fresh(now.mono) {
            return None;
        }
        self.clock.now_ms(now.mono)
    }

    fn usable(&self, lease: &Lease, now: Now) -> bool {
        if lease.final_reason.is_some() || lease.remaining() == 0 {
            return false;
        }
        match self.lease_now_ms(now) {
            Some(t) => t >= lease.not_before_ms && t < lease.expires_ms,
            None => false,
        }
    }

    fn token_window(&self, token: &AdmissionToken, now: Now) -> Result<bool, AdmissionRefusal> {
        let t = self.admission_now_ms(now);
        if t < token.not_before.saturating_mul(1_000) {
            return Err(AdmissionRefusal::NotBefore);
        }
        let expired = t > token.not_after.saturating_mul(1_000);
        #[cfg(mousse_control = "ignore-admission-expiry")]
        let expired = {
            let _ = expired;
            false
        };
        Ok(expired)
    }

    fn open_token(
        &self,
        handle: &Handle,
        envelope: &[u8],
    ) -> Result<AdmissionToken, AdmissionRefusal> {
        let token = AdmissionToken::open(envelope, &self.keys).map_err(AdmissionRefusal::Token)?;
        if token.relay_id != self.relay_id {
            return Err(AdmissionRefusal::WrongRelay);
        }
        if token.handle != *handle {
            return Err(AdmissionRefusal::WrongHandle);
        }
        Ok(token)
    }

    /// A hosted `REGISTER` of `handle` (which the relay derived from the
    /// registration key that proved itself) with an admission token and a
    /// status threshold. A token past `not after` but otherwise valid is
    /// accepted only while the handle holds a usable block in this boot
    /// (§A.9 duty 10).
    pub fn register(
        &mut self,
        handle: Handle,
        token: &[u8],
        threshold_percent: Option<u64>,
        now: Now,
    ) -> Result<(), AdmissionRefusal> {
        if self.stopping {
            return Err(AdmissionRefusal::Stopping);
        }
        let threshold = threshold_percent
            .filter(|t| THRESHOLD_PERCENT.contains(t))
            .ok_or(AdmissionRefusal::Threshold)?;
        let token = self.open_token(&handle, token)?;
        let expired = self.token_window(&token, now)?;
        #[cfg(mousse_control = "refuse-expired-reregister")]
        if expired {
            return Err(AdmissionRefusal::Expired);
        }
        if expired && !self.funded(&handle, now) {
            return Err(AdmissionRefusal::Expired);
        }
        let not_after = self
            .admissions
            .get(&handle)
            .map_or(token.not_after, |a| a.not_after.max(token.not_after));
        self.admissions.insert(
            handle,
            Admission {
                not_after,
                threshold,
                registered: true,
            },
        );
        Ok(())
    }

    /// The handle's registration connection closed, and no other live
    /// registration of the handle replaced it (a replacement is a new
    /// [`Hosted::register`] and needs no call here). Its circuits and
    /// leases stay (§B.4).
    pub fn unregister(&mut self, handle: &Handle) {
        if let Some(a) = self.admissions.get_mut(handle) {
            a.registered = false;
        }
    }

    /// `ADMIT` on the live registration of `handle`: a renewed token, which
    /// must be valid now.
    pub fn admit(
        &mut self,
        handle: Handle,
        token: &[u8],
        now: Now,
    ) -> Result<(), AdmissionRefusal> {
        if self.stopping {
            return Err(AdmissionRefusal::Stopping);
        }
        if !self.admissions.get(&handle).is_some_and(|a| a.registered) {
            return Err(AdmissionRefusal::NotRegistered);
        }
        let token = self.open_token(&handle, token)?;
        if self.token_window(&token, now)? {
            return Err(AdmissionRefusal::Expired);
        }
        if let Some(a) = self.admissions.get_mut(&handle) {
            a.not_after = a.not_after.max(token.not_after);
        }
        Ok(())
    }

    fn admission_expired(&self, a: &Admission, now: Now) -> bool {
        if cfg!(mousse_control = "ignore-admission-expiry") {
            return false;
        }
        self.admission_now_ms(now) > a.not_after.saturating_mul(1_000)
    }

    /// Whether the handle holds a usable block in this boot: a current or
    /// pending lease of either class, not spent, not expired.
    pub fn funded(&self, handle: &Handle, now: Now) -> bool {
        CLASSES.iter().any(|c| {
            self.slots.get(&(*handle, *c)).is_some_and(|s| {
                [s.current, s.pending]
                    .into_iter()
                    .flatten()
                    .any(|id| self.leases.get(&id).is_some_and(|l| self.usable(l, now)))
            })
        })
    }

    /// `LEASE` on the registration of `handle`.
    pub fn lease(
        &mut self,
        handle: Handle,
        envelope: &[u8],
        now: Now,
    ) -> Result<LeaseState, LeaseRefused> {
        let peek = LeaseBlock::peek(envelope);
        let refuse = |reason| {
            let status = peek.as_ref().map(|b| LeaseStatus {
                lease_id: b.lease_id,
                class: b.class,
                used: 0,
                bytes: b.bytes,
                state: LeaseState::Refused,
            });
            LeaseRefused { reason, status }
        };
        if self.stopping {
            return Err(refuse(LeaseRefusal::Stopping));
        }
        let Some(adm) = self.admissions.get(&handle).copied() else {
            return Err(refuse(LeaseRefusal::NotRegistered));
        };
        if self.admission_expired(&adm, now) {
            return Err(refuse(LeaseRefusal::AdmissionExpired));
        }
        let block =
            LeaseBlock::open(envelope, &self.keys).map_err(|e| refuse(LeaseRefusal::Record(e)))?;
        if block.relay_id != self.relay_id {
            return Err(refuse(LeaseRefusal::WrongRelay));
        }
        if block.boot_id != self.boot_id {
            return Err(refuse(LeaseRefusal::WrongBoot));
        }
        if block.handle != handle {
            return Err(refuse(LeaseRefusal::WrongHandle));
        }
        if block.rate_cap < RATE_CAP_FLOOR {
            return Err(refuse(LeaseRefusal::RateCapTooLow));
        }
        if block.bytes < MESSAGE_MAX {
            return Err(refuse(LeaseRefusal::TooSmall));
        }
        if block.expires_at <= block.not_before
            || block.expires_at - block.not_before > BLOCK_MAX_LIFETIME_SECS
        {
            return Err(refuse(LeaseRefusal::BadWindow));
        }
        let Some(t) = self.lease_now_ms(now) else {
            return Err(refuse(LeaseRefusal::NoPlusClock));
        };
        if t < block.not_before.saturating_mul(1_000) {
            return Err(refuse(LeaseRefusal::NotBefore));
        }
        if t >= block.expires_at.saturating_mul(1_000) {
            return Err(refuse(LeaseRefusal::Expired));
        }
        let key = (handle, block.class);
        let slot = self.slots.get(&key).cloned().unwrap_or_default();
        if !cfg!(mousse_control = "accept-replayed-lease") && block.sequence <= slot.last_sequence {
            return Err(refuse(LeaseRefusal::SequenceNotAbove));
        }
        if self.leases.contains_key(&block.lease_id) {
            return Err(refuse(LeaseRefusal::DuplicateLease));
        }
        // Make room: a spent or expired current or pending is final first.
        self.expire(now);
        let slot = self.slots.entry(key).or_default();
        if slot.current.is_none() {
            slot.current = slot.pending.take();
        }
        if slot.current.is_some() && slot.pending.is_some() {
            return Err(refuse(LeaseRefusal::Full));
        }
        slot.last_sequence = slot.last_sequence.max(block.sequence);
        let state = if slot.current.is_none() {
            slot.current = Some(block.lease_id);
            LeaseState::Current
        } else {
            slot.pending = Some(block.lease_id);
            LeaseState::Pending
        };
        if slot.paused_since.take().is_some() {
            self.events.push_back(Event::Resumed {
                handle,
                class: block.class,
            });
        }
        self.leases.insert(
            block.lease_id,
            Lease {
                handle,
                class: block.class,
                rate_group: block.rate_group,
                bytes: block.bytes,
                not_before_ms: block.not_before.saturating_mul(1_000),
                expires_ms: block.expires_at.saturating_mul(1_000),
                to_target: 0,
                to_caller: 0,
                final_reason: None,
                threshold_sent: false,
            },
        );
        // The cap of the block most recently accepted for the group and
        // class applies to the whole group (§A.9 duty 8).
        self.group_caps
            .insert((block.rate_group, block.class), block.rate_cap);
        for (k, b) in self.buckets.iter_mut() {
            if k.0 == block.rate_group && k.1 == block.class {
                b.refill(now.mono);
                b.cap = block.rate_cap;
                b.milli = b.milli.min(b.capacity());
            }
        }
        Ok(state)
    }

    /// `RELEASE` from `handle`: those leases are final at once with their
    /// counters (§B.10). Ids this boot does not hold are ignored; an id
    /// another handle holds refuses the whole message.
    pub fn release(
        &mut self,
        handle: Handle,
        ids: &[LeaseId],
        now: Now,
    ) -> Result<(), ReleaseRefusal> {
        if ids.len() > RELEASE_IDS_MAX {
            return Err(ReleaseRefusal::TooMany);
        }
        if ids
            .iter()
            .any(|id| self.leases.get(id).is_some_and(|l| l.handle != handle))
        {
            return Err(ReleaseRefusal::OtherHandle);
        }
        for id in ids {
            self.finalize(*id, FinalReason::Released, now);
        }
        Ok(())
    }

    /// Whether a `CALL` or `JOIN` of `class` to `handle` may be put
    /// through: the class has a usable lease (§B.6). Part of the relay's
    /// single refusal path; the answer is the same whichever check fails.
    pub fn can_call(&mut self, handle: &Handle, class: Class, now: Now) -> bool {
        if self.stopping {
            return false;
        }
        self.expire(now);
        let key = (*handle, class);
        let Some(slot) = self.slots.get_mut(&key) else {
            return false;
        };
        if slot.current.is_none() {
            slot.current = slot.pending.take();
        }
        let current = slot.current;
        current
            .and_then(|id| self.leases.get(&id))
            .is_some_and(|l| self.usable(l, now))
    }

    /// Count one spliced message of `len` bytes on a circuit of `handle`
    /// and `class`, going `direction`. `circuit` names the circuit; the
    /// relay uses it only to tell sockets apart.
    ///
    /// The current lease takes the bytes it has left and is then spent; the
    /// pending lease becomes current and takes the rest (§A.9 duty 7). A
    /// message the leases cannot cover pauses the class; a short rate
    /// bucket asks the caller to wait.
    pub fn forward(
        &mut self,
        handle: Handle,
        class: Class,
        circuit: u64,
        direction: Direction,
        len: u64,
        now: Now,
    ) -> Forward {
        #[cfg(not(mousse_control = "per-socket-rate"))]
        let _ = circuit;
        if self.stopping {
            return Forward::Stopped;
        }
        if len == 0 {
            return Forward::Go;
        }
        self.expire(now);
        let key = (handle, class);
        let slot = self.slots.entry(key).or_default();
        if slot.current.is_none() {
            slot.current = slot.pending.take();
        }
        let (cur, pend) = (slot.current, slot.pending);
        let remaining = |id: Option<LeaseId>| {
            id.and_then(|id| self.leases.get(&id))
                .map_or(0, |l| l.remaining())
        };
        let (cur_left, pend_left) = (remaining(cur), remaining(pend));
        if cur_left.saturating_add(pend_left) < len {
            let slot = self.slots.entry(key).or_default();
            slot.paused_since.get_or_insert(now.mono);
            return Forward::Paused;
        }
        let first = len.min(cur_left);
        let mut portions: Vec<(LeaseId, u64)> = Vec::with_capacity(2);
        if let Some(id) = cur.filter(|_| first > 0) {
            portions.push((id, first));
        }
        if len > first {
            if let Some(id) = pend {
                portions.push((id, len - first));
            }
        }

        // Rate: every portion against its group's bucket, all or nothing.
        let mut need: BTreeMap<BucketKey, u64> = BTreeMap::new();
        for (id, n) in &portions {
            if let Some(l) = self.leases.get(id) {
                #[cfg(mousse_control = "per-socket-rate")]
                let scope = circuit;
                #[cfg(not(mousse_control = "per-socket-rate"))]
                let scope = 0;
                *need.entry((l.rate_group, class, scope)).or_default() += n;
            }
        }
        let mut wait: Option<Millis> = None;
        for (k, n) in &need {
            let cap = self.group_cap(k.0, k.1);
            let b = self
                .buckets
                .entry(*k)
                .or_insert_with(|| Bucket::full(cap, now.mono));
            b.refill(now.mono);
            if let Some(until) = b.short_until(*n, now.mono) {
                wait = Some(wait.map_or(until, |w: Millis| w.max(until)));
            }
        }
        if let Some(until) = wait {
            return Forward::Wait { until };
        }
        for (k, n) in &need {
            if let Some(b) = self.buckets.get_mut(k) {
                b.milli -= u128::from(*n) * 1_000;
            }
        }

        // Count.
        let threshold = self.admissions.get(&handle).map(|a| a.threshold);
        for (id, n) in portions {
            let Some(l) = self.leases.get_mut(&id) else {
                continue;
            };
            match direction {
                Direction::ToTarget => l.to_target += n,
                Direction::ToCaller => l.to_caller += n,
            }
            if l.remaining() == 0 {
                self.finalize(id, FinalReason::Spent, now);
            } else if let Some(t) = threshold {
                if !l.threshold_sent
                    && u128::from(l.used()) * 100 >= u128::from(l.bytes) * u128::from(t)
                {
                    l.threshold_sent = true;
                    let status = l.status(id, LeaseState::Current);
                    self.events.push_back(Event::Status {
                        handle,
                        entries: vec![status],
                    });
                }
            }
        }
        if let Some(slot) = self.slots.get_mut(&key) {
            slot.paused_since = None;
        }
        Forward::Go
    }

    /// The cap of the block most recently accepted for the group and class.
    fn group_cap(&self, group: RateGroup, class: Class) -> u64 {
        self.group_caps
            .get(&(group, class))
            .copied()
            .unwrap_or(RATE_CAP_FLOOR)
    }

    /// Make a lease final, tell its target, and take it out of its slot.
    fn finalize(&mut self, id: LeaseId, reason: FinalReason, now: Now) {
        let Some(l) = self.leases.get_mut(&id) else {
            return;
        };
        if l.final_reason.is_some() {
            return;
        }
        l.final_reason = Some(reason);
        let (handle, class) = (l.handle, l.class);
        let status = l.status(id, LeaseState::Final);
        if let Some(slot) = self.slots.get_mut(&(handle, class)) {
            if slot.current == Some(id) {
                slot.current = slot.pending.take();
            } else if slot.pending == Some(id) {
                slot.pending = None;
            }
        }
        self.events.push_back(Event::Status {
            handle,
            entries: vec![status],
        });
        self.reports.note_final(now.mono);
        self.report_wake = true;
    }

    /// Whether a lease became final since the last call: a snapshot may be
    /// due sooner, so the reporter should look again.
    pub fn take_report_wake(&mut self) -> bool {
        std::mem::take(&mut self.report_wake)
    }

    /// Whether [`Hosted::poll`] has events waiting.
    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    /// Make every lease that stopped being usable by time final.
    fn expire(&mut self, now: Now) {
        let t = self.lease_now_ms(now);
        let ended: Vec<LeaseId> = self
            .leases
            .iter()
            .filter(|(_, l)| l.final_reason.is_none())
            .filter(|(_, l)| t.is_none_or(|t| t >= l.expires_ms))
            .map(|(id, _)| *id)
            .collect();
        for id in ended {
            self.finalize(id, FinalReason::Expired, now);
        }
    }

    /// Run the timers due at `now` and return what the connection code
    /// must do: statuses, resumed and closed classes, closed handles.
    pub fn poll(&mut self, now: Now) -> Vec<Event> {
        self.expire(now);
        // Paused classes past the refill wait close with 4001; the current
        // lease is final with what it forwarded.
        let refill = self.limits.refill_wait_ms();
        let timed_out: Vec<(Handle, Class)> = self
            .slots
            .iter()
            .filter(|(_, s)| s.paused_since.is_some_and(|p| now.mono.since(p) >= refill))
            .map(|(k, _)| *k)
            .collect();
        for (handle, class) in timed_out {
            let current = self.slots.get_mut(&(handle, class)).and_then(|s| {
                s.paused_since = None;
                s.current
            });
            if let Some(id) = current {
                self.finalize(id, FinalReason::Closed, now);
            }
            self.events.push_back(Event::CloseClass {
                handle,
                class,
                code: CLOSE_LEASE_EXHAUSTED,
            });
        }
        // Past the admission token: kept only while funded (§A.9 duty 10).
        let expired: Vec<Handle> = self
            .admissions
            .iter()
            .filter(|(_, a)| self.admission_expired(a, now))
            .map(|(h, _)| *h)
            .collect();
        for handle in expired {
            let close =
                cfg!(mousse_control = "close-funded-at-expiry") || !self.funded(&handle, now);
            if close {
                self.admissions.remove(&handle);
                self.events.push_back(Event::CloseHandle {
                    handle,
                    code: CLOSE_ADMISSION_EXPIRED,
                });
            }
        }
        self.drop_idle_buckets(now);
        self.events.drain(..).collect()
    }

    /// Buckets of groups with no open lease, once full again. Dropping one
    /// earlier would let a new block of the group start a fresh bucket and
    /// burst past `cap × (T + 1)`.
    fn drop_idle_buckets(&mut self, now: Now) {
        let live: Vec<(RateGroup, Class)> = self
            .leases
            .values()
            .filter(|l| l.final_reason.is_none())
            .map(|l| (l.rate_group, l.class))
            .collect();
        self.buckets.retain(|k, b| {
            if live.contains(&(k.0, k.1)) {
                return true;
            }
            b.refill(now.mono);
            b.milli < b.capacity()
        });
        let buckets = &self.buckets;
        self.group_caps
            .retain(|g, _| live.contains(g) || buckets.keys().any(|k| (k.0, k.1) == *g));
    }

    /// The next monotonic instant [`Hosted::poll`] has work, if any.
    pub fn next_wakeup(&self, now: Now) -> Option<Millis> {
        let mut next: Option<Millis> = None;
        let mut at = |t: Millis| next = Some(next.map_or(t, |n: Millis| n.min(t)));
        let refill = self.limits.refill_wait_ms();
        for s in self.slots.values() {
            if let Some(p) = s.paused_since {
                at(p.plus(refill));
            }
        }
        let open = self.leases.values().any(|l| l.final_reason.is_none());
        if open {
            if let Some(stale) = self.clock.stale_at() {
                at(stale);
            }
        }
        for l in self.leases.values().filter(|l| l.final_reason.is_none()) {
            if let Some(t) = self.clock.when(l.expires_ms, now.mono) {
                at(t);
            }
        }
        // Tokens not yet past `not after`. One already past is kept only
        // while funded, and its block ending is a lease event or a lease
        // expiry, both covered above.
        let t = self.admission_now_ms(now);
        for a in self.admissions.values() {
            let end = a.not_after.saturating_mul(1_000).saturating_add(1);
            if end > t {
                at(now.mono.plus(end - t));
            }
        }
        next
    }

    /// The `LEASE_STATUS` entries of every lease `handle` holds open.
    pub fn statuses(&self, handle: &Handle) -> Vec<LeaseStatus> {
        let mut out = Vec::new();
        for c in CLASSES {
            if let Some(s) = self.slots.get(&(*handle, c)) {
                for (id, state) in [
                    (s.current, LeaseState::Current),
                    (s.pending, LeaseState::Pending),
                ] {
                    if let Some(l) = id.and_then(|id| self.leases.get(&id).map(|l| (id, l))) {
                        out.push(l.1.status(l.0, state));
                    }
                }
            }
        }
        out
    }

    /// A graceful stop: forward nothing more, accept no `LEASE`, make every
    /// lease final, and take the stopping snapshot (§A.9 duty 11). Send its
    /// parts and wait up to `FINAL_REPORT_WAIT_MS` for them to be stored.
    pub fn stop(&mut self, now: Now) {
        if self.stopping {
            return;
        }
        self.stopping = true;
        let open: Vec<LeaseId> = self
            .leases
            .iter()
            .filter(|(_, l)| l.final_reason.is_none())
            .map(|(id, _)| *id)
            .collect();
        for id in open {
            self.finalize(id, FinalReason::Stopped, now);
        }
        let entries = self.snapshot_entries();
        self.reports.take(entries, BootState::Stopping, now.mono);
    }

    fn snapshot_entries(&self) -> Vec<ReportEntry> {
        self.leases.iter().map(|(id, l)| l.entry(*id)).collect()
    }

    /// Plus answered this boot's announcement: the boot is known, and the
    /// answer may set the Plus clock. `sent` is when the request was sent.
    pub fn boot_answered(&mut self, answer: &BootAnswer, sent: Millis, now: Now) {
        self.clock.answer(
            answer.plus_time_ms,
            sent,
            now.mono,
            self.limits.clock_rtt_ms(),
        );
        self.reports.booted();
    }

    /// Take a snapshot if one is due.
    pub fn report_tick(&mut self, now: Now) {
        if self.reports.take_due(&self.limits, now.mono) {
            let entries = self.snapshot_entries();
            self.reports.take(entries, BootState::Running, now.mono);
        }
    }

    /// The next report part to send, if any. The same part is returned
    /// until Plus has stored it.
    pub fn next_report_part(&mut self, now: Now) -> Option<ReportPart> {
        self.report_tick(now);
        let sent_at = self.clock.now_or_wall_ms(now.mono, now.wall) / 1_000;
        self.reports.next_part(self.relay_id, self.boot_id, sent_at)
    }

    /// When the next snapshot is to be taken, whatever is being delivered.
    /// A reporter backing off after a failed call still wakes for it.
    pub fn snapshot_due(&self, now: Now) -> Option<Millis> {
        self.reports.take_at(&self.limits, now.mono)
    }

    /// When [`Hosted::report_tick`] next has work (a snapshot to take or a
    /// part to send), if ever.
    pub fn report_due(&self, now: Now) -> Option<Millis> {
        self.reports.due(&self.limits, now.mono)
    }

    /// Plus answered the part with sequence `sequence`, sent at `sent`.
    /// Settled leases are forgotten (and made final first if still open).
    pub fn report_answered(
        &mut self,
        sequence: u64,
        answer: &ReportAnswer,
        sent: Millis,
        now: Now,
    ) {
        self.clock.answer(
            answer.plus_time_ms,
            sent,
            now.mono,
            self.limits.clock_rtt_ms(),
        );
        self.reports.answered(sequence, answer.highest_sequence);
        for id in &answer.settled {
            self.finalize(*id, FinalReason::Settled, now);
            self.leases.remove(id);
        }
    }

    /// Whether the stopping snapshot has been stored in full.
    pub fn stop_reported(&self) -> bool {
        self.reports.stop_reported()
    }

    /// How many leases this boot still reports.
    pub fn lease_count(&self) -> usize {
        self.leases.len()
    }
}

#[cfg(test)]
mod tests;
