//! Lease blocks on a hosted relay, per registration handle (design A.8,
//! B.10): prefetch at the threshold, one current and one pending per
//! class, re-presenting a block refused for `not before`, bulk paused on
//! a failed refill, and the remaining time per class.
//!
//! [`Book`] is the decision logic with no I/O; [`run`] drives it against a
//! relay registration (through channels) and Plus.

use std::sync::Arc;

use serde_json::{json, Value as Json};
use tokio::sync::mpsc;

use super::client::{Backoff, Failure, Plus};
use super::proto::{Block, Class};
use crate::limits::{helper, ms};

/// A `LEASE_STATUS` entry from the relay (B.3 type 15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusEntry {
    /// The lease.
    pub lease_id: [u8; 16],
    /// Its class.
    pub class: Class,
    /// Bytes forwarded so far.
    pub used: u64,
    /// Its bytes.
    pub bytes: u64,
    /// 0 pending, 1 current, 2 final, 3 refused.
    pub state: u8,
}

/// A held block and what the relay last said about it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Held {
    block: Block,
    used: u64,
}

/// One class's blocks on one handle.
#[derive(Clone, Debug, Default)]
struct ClassBook {
    current: Option<Held>,
    pending: Option<Held>,
    /// A block the relay refused, to present again at this monotonic time.
    retry: Option<(Block, u64)>,
    /// A request to Plus runs since this monotonic time.
    requesting_since: Option<u64>,
    /// The last refill failed with this error word.
    refill_error: Option<String>,
    /// Shown paused (bulk only).
    paused: bool,
    /// Bytes used, sampled for the rate: `(mono ms, total used)`.
    samples: Vec<(u64, u64)>,
    /// Total used on blocks that are final.
    used_before: u64,
}

/// What the driver must do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Send `LEASE` with this block.
    Present(Block),
    /// Ask Plus for the next block of this class.
    Request(Class),
    /// Show this class paused (`true`) or running again.
    Paused(Class, bool),
}

/// The blocks of one handle on one relay boot.
#[derive(Clone, Debug)]
pub struct Book {
    percent: u64,
    refill_deadline_ms: u64,
    not_before_retry_ms: u64,
    classes: [ClassBook; 2],
}

fn idx(class: Class) -> usize {
    match class {
        Class::Interactive => 0,
        Class::Bulk => 1,
    }
}

impl Book {
    /// A book with the helper's limits.
    pub fn new() -> Self {
        let h = helper();
        Self::with(
            h.plus_prefetch_percent(),
            h.plus_refill_deadline_ms(),
            h.plus_not_before_retry_ms(),
        )
    }

    /// A book with explicit numbers.
    pub fn with(percent: u64, refill_deadline_ms: u64, not_before_retry_ms: u64) -> Self {
        Self {
            percent,
            refill_deadline_ms,
            not_before_retry_ms,
            classes: Default::default(),
        }
    }

    fn class(&mut self, class: Class) -> &mut ClassBook {
        &mut self.classes[idx(class)]
    }

    /// Whether `class` needs another block from Plus now: none is current,
    /// or the current one passed the threshold and none is pending.
    pub fn wants(&self, class: Class) -> bool {
        let c = &self.classes[idx(class)];
        if c.requesting_since.is_some() || c.retry.is_some() {
            return false;
        }
        match (&c.current, &c.pending) {
            (None, None) => true,
            (Some(cur), None) => {
                cfg!(not(mousse_control = "no-prefetch"))
                    && cur.used.saturating_mul(100) >= cur.block.bytes.saturating_mul(self.percent)
            }
            // A pending block becomes current when the current one ends.
            _ => false,
        }
    }

    /// A request to Plus for `class` started.
    pub fn requested(&mut self, class: Class, now_ms: u64) {
        let c = self.class(class);
        c.requesting_since.get_or_insert(now_ms);
    }

    /// The request for `class` failed with `word` (`allowance_used`,
    /// `balance_empty`, `cap_reached`, ...). The driver retries.
    pub fn request_failed(&mut self, class: Class, word: &str) {
        let c = self.class(class);
        c.refill_error = Some(word.to_owned());
    }

    /// A block arrived from Plus: present it to the relay.
    pub fn on_block(&mut self, block: Block, now_ms: u64) -> Vec<Action> {
        let class = block.class;
        let c = self.class(class);
        c.requesting_since = None;
        c.refill_error = None;
        let held = Held {
            block: block.clone(),
            used: 0,
        };
        if c.current.is_none() {
            c.current = Some(held);
        } else {
            c.pending = Some(held);
        }
        let mut out = vec![Action::Present(block)];
        if c.paused {
            c.paused = false;
            out.push(Action::Paused(class, false));
        }
        c.samples.push((now_ms, c.used_before));
        out
    }

    /// A `LEASE_STATUS` from the relay.
    pub fn on_status(&mut self, entries: &[StatusEntry], now_ms: u64) -> Vec<Action> {
        let mut out = Vec::new();
        for e in entries {
            let retry_ms = self.not_before_retry_ms;
            let c = self.class(e.class);
            let is = |h: &Option<Held>| h.as_ref().is_some_and(|h| h.block.lease_id == e.lease_id);
            match e.state {
                // Pending or current: note its use.
                0 | 1 => {
                    for h in [&mut c.current, &mut c.pending].into_iter().flatten() {
                        if h.block.lease_id == e.lease_id {
                            h.used = e.used;
                        }
                    }
                    if e.state == 1 && is(&c.pending) {
                        // The relay moved on to the pending block.
                        if let Some(cur) = c.current.take() {
                            c.used_before += cur.used;
                        }
                        c.current = c.pending.take();
                    }
                }
                // Final: the pending block (if any) is current now.
                2 => {
                    if is(&c.current) {
                        if let Some(cur) = c.current.take() {
                            c.used_before += e.used.max(cur.used);
                        }
                        c.current = c.pending.take();
                    } else if is(&c.pending) {
                        c.pending = None;
                    }
                }
                // Refused: present it again after the retry wait (a block
                // refused for `not before`, or before the relay's first Plus
                // answer, is fine a moment later).
                _ => {
                    let block = if is(&c.current) {
                        c.current.take().map(|h| h.block)
                    } else if is(&c.pending) {
                        c.pending.take().map(|h| h.block)
                    } else {
                        None
                    };
                    if let Some(block) = block {
                        c.retry = Some((block, now_ms + retry_ms));
                    }
                }
            }
            let total = c.used_before + c.current.as_ref().map_or(0, |h| h.used);
            c.samples.push((now_ms, total));
            if c.samples.len() > 32 {
                c.samples.remove(0);
            }
        }
        for class in [Class::Interactive, Class::Bulk] {
            if self.wants(class) {
                out.push(Action::Request(class));
            }
        }
        out
    }

    /// Timers: re-present refused blocks; show bulk paused when its refill
    /// is late (`MOUSSE_NET_PLUS_REFILL_DEADLINE_MS`) and it has nothing
    /// left. Interactive is never paused by this: it has its own blocks.
    pub fn tick(&mut self, now_ms: u64, now_secs: u64) -> Vec<Action> {
        let mut out = Vec::new();
        let deadline = self.refill_deadline_ms;
        for class in [Class::Interactive, Class::Bulk] {
            let c = self.class(class);
            if let Some((block, at)) = c.retry.clone() {
                if block.expires_at <= now_secs {
                    c.retry = None;
                } else if now_ms >= at {
                    c.retry = None;
                    if c.current.is_none() {
                        c.current = Some(Held {
                            block: block.clone(),
                            used: 0,
                        });
                    } else {
                        c.pending = Some(Held {
                            block: block.clone(),
                            used: 0,
                        });
                    }
                    out.push(Action::Present(block));
                }
            }
            let empty = c
                .current
                .as_ref()
                .is_none_or(|h| h.used >= h.block.bytes || h.block.expires_at <= now_secs)
                && c.pending.is_none();
            let late = c
                .requesting_since
                .is_some_and(|since| now_ms.saturating_sub(since) >= deadline)
                || c.refill_error.is_some();
            let pause_this = if cfg!(mousse_control = "pause-all-classes") {
                true
            } else {
                class == Class::Bulk
            };
            if pause_this && empty && late && !c.paused {
                c.paused = true;
                out.push(Action::Paused(class, true));
            }
        }
        if cfg!(mousse_control = "pause-all-classes")
            && out
                .iter()
                .any(|a| matches!(a, Action::Paused(Class::Bulk, true)))
            && !self.classes[0].paused
        {
            self.classes[0].paused = true;
            out.push(Action::Paused(Class::Interactive, true));
        }
        out
    }

    /// Whether `class` shows paused.
    pub fn is_paused(&self, class: Class) -> bool {
        self.classes[idx(class)].paused
    }

    /// Lease ids held for `class` (current and pending): what `RELEASE`
    /// names when the helper stops using this handle.
    pub fn held_ids(&self) -> Vec<[u8; 16]> {
        self.classes
            .iter()
            .flat_map(|c| [&c.current, &c.pending])
            .flatten()
            .map(|h| h.block.lease_id)
            .collect()
    }

    /// Forget every block (after `RELEASE`).
    pub fn released(&mut self) {
        for c in &mut self.classes {
            c.current = None;
            c.pending = None;
            c.retry = None;
        }
    }

    /// What the app shows for `class`: bytes left, when the blocks expire,
    /// and how long they last at the recent rate (the outage display:
    /// a host stays reachable through a Plus outage this long).
    pub fn view(&self, class: Class, now_secs: u64) -> Json {
        let c = &self.classes[idx(class)];
        let live = |h: &&Held| h.block.expires_at > now_secs;
        let left: u64 = [&c.current, &c.pending]
            .into_iter()
            .flatten()
            .filter(live)
            .map(|h| h.block.bytes.saturating_sub(h.used))
            .sum();
        let expires = [&c.current, &c.pending]
            .into_iter()
            .flatten()
            .filter(live)
            .map(|h| h.block.expires_at)
            .max();
        let rate = rate(&c.samples);
        let by_bytes = (rate > 0).then(|| left / rate);
        let by_time = expires.map(|e| e.saturating_sub(now_secs));
        let lasts = match (by_bytes, by_time) {
            (Some(b), Some(t)) => Some(b.min(t)),
            (None, t) => t,
            (b, None) => b.filter(|_| left > 0),
        };
        let state = if c.paused {
            "paused"
        } else if left == 0 {
            "unfunded"
        } else {
            "funded"
        };
        json!({
            "class": class.name(),
            "state": state,
            "bytes_left": left,
            "expires_at": expires,
            "lasts_secs": lasts,
            "refill_error": c.refill_error,
        })
    }
}

impl Default for Book {
    fn default() -> Self {
        Self::new()
    }
}

/// Bytes per second, from samples `(mono ms, total used)`.
fn rate(samples: &[(u64, u64)]) -> u64 {
    let (Some(first), Some(last)) = (samples.first(), samples.last()) else {
        return 0;
    };
    let dt = last.0.saturating_sub(first.0);
    if dt == 0 {
        return 0;
    }
    last.1.saturating_sub(first.1).saturating_mul(1000) / dt
}

/// What the relay registration reports to the driver.
#[derive(Clone, Debug)]
pub enum RelayEvent {
    /// A `LEASE_STATUS`.
    Status(Vec<StatusEntry>),
    /// The registration ended.
    Closed,
}

/// What the driver sends on the registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayCommand {
    /// `LEASE {block}`.
    Lease(Vec<u8>),
    /// `RELEASE {lease ids}`.
    Release(Vec<[u8; 16]>),
}

/// The relay registration a driver funds.
#[derive(Clone, Copy, Debug)]
pub struct Registration {
    /// Relay id.
    pub relay_id: [u8; 32],
    /// The relay boot (`RELAY_HELLO` key 3).
    pub boot_id: [u8; 16],
    /// The handle.
    pub handle: [u8; 32],
}

/// Keep `registration` funded from Plus until the relay says it closed or
/// `commands` closes. App events (`plus.relay`) go to `events`.
pub async fn run(
    plus: Arc<Plus>,
    reg: Registration,
    mut relay: mpsc::UnboundedReceiver<RelayEvent>,
    commands: mpsc::UnboundedSender<RelayCommand>,
    events: mpsc::UnboundedSender<Json>,
    clock: Arc<dyn mousse_net_io::Clock>,
) {
    let mut book = Book::new();
    let (got, mut blocks) = mpsc::unbounded_channel::<(Class, Result<Block, Failure>)>();
    let mut tick = tokio::time::interval(ms(helper().plus_not_before_retry_ms()));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut backoff = [Backoff::new(), Backoff::new()];
    let mut actions: Vec<Action> = [Class::Interactive, Class::Bulk]
        .into_iter()
        .filter(|c| book.wants(*c))
        .map(Action::Request)
        .collect();
    loop {
        for action in std::mem::take(&mut actions) {
            match action {
                Action::Present(block) => {
                    let _ = commands.send(RelayCommand::Lease(block.envelope));
                }
                Action::Request(class) => {
                    book.requested(class, clock.mono().ms());
                    let plus = plus.clone();
                    let got = got.clone();
                    tokio::spawn(async move {
                        let r = plus
                            .lease(&reg.relay_id, &reg.boot_id, &reg.handle, class)
                            .await;
                        let _ = got.send((class, r));
                    });
                }
                Action::Paused(class, paused) => {
                    let _ = events.send(json!({
                        "ev": "plus.relay.paused",
                        "class": class.name(),
                        "paused": paused,
                    }));
                }
            }
        }
        let now_ms = clock.mono().ms();
        tokio::select! {
            ev = relay.recv() => match ev {
                Some(RelayEvent::Status(entries)) => actions = book.on_status(&entries, now_ms),
                Some(RelayEvent::Closed) | None => return,
            },
            Some((class, result)) = blocks.recv() => match result {
                Ok(block) => {
                    backoff[idx(class)].reset();
                    actions = book.on_block(block, now_ms);
                }
                Err(e) => {
                    book.request_failed(class, &e.word());
                    let wait = e.retry_after().unwrap_or_else(|| backoff[idx(class)].next());
                    // Retried with the same stored request id.
                    let got = got.clone();
                    let plus = plus.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(wait).await;
                        let r = plus.lease(&reg.relay_id, &reg.boot_id, &reg.handle, class).await;
                        let _ = got.send((class, r));
                    });
                }
            },
            _ = tick.tick() => {
                actions = book.tick(clock.mono().ms(), clock.now().secs());
                let _ = events.send(json!({
                    "ev": "plus.relay",
                    "relay": mousse_net_io::store::hex(&reg.relay_id),
                    "interactive": book.view(Class::Interactive, clock.now().secs()),
                    "bulk": book.view(Class::Bulk, clock.now().secs()),
                }));
            }
            () = commands.closed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(class: Class, id: u8, bytes: u64, expires_at: u64) -> Block {
        Block {
            envelope: vec![id],
            lease_id: [id; 16],
            relay_id: [1; 32],
            boot_id: [2; 16],
            handle: [3; 32],
            class,
            sequence: u64::from(id),
            rate_cap: 65_536,
            bytes,
            not_before: 0,
            expires_at,
        }
    }

    fn status(class: Class, id: u8, used: u64, bytes: u64, state: u8) -> StatusEntry {
        StatusEntry {
            lease_id: [id; 16],
            class,
            used,
            bytes,
            state,
        }
    }

    #[test]
    fn the_next_block_is_asked_for_at_the_threshold_and_one_is_pending() {
        let mut b = Book::with(50, 5_000, 1_000);
        assert!(b.wants(Class::Bulk));
        b.requested(Class::Bulk, 0);
        assert!(!b.wants(Class::Bulk), "one request at a time");
        let out = b.on_block(block(Class::Bulk, 1, 1000, 10_000), 0);
        assert_eq!(
            out,
            vec![Action::Present(block(Class::Bulk, 1, 1000, 10_000))]
        );
        assert!(!b.wants(Class::Bulk));
        // Below the threshold: nothing.
        let out = b.on_status(&[status(Class::Bulk, 1, 499, 1000, 1)], 10);
        assert!(!out.contains(&Action::Request(Class::Bulk)));
        // At it: the next block.
        let out = b.on_status(&[status(Class::Bulk, 1, 500, 1000, 1)], 20);
        assert!(out.contains(&Action::Request(Class::Bulk)));
        b.requested(Class::Bulk, 20);
        b.on_block(block(Class::Bulk, 2, 1000, 10_000), 30);
        // Current and pending held: no third.
        let out = b.on_status(&[status(Class::Bulk, 1, 900, 1000, 1)], 40);
        assert!(!out.contains(&Action::Request(Class::Bulk)));
        // The current one is final: the pending one is current, and at its
        // threshold the next is asked for.
        b.on_status(&[status(Class::Bulk, 1, 1000, 1000, 2)], 50);
        let out = b.on_status(&[status(Class::Bulk, 2, 600, 1000, 1)], 60);
        assert!(out.contains(&Action::Request(Class::Bulk)));
        assert_eq!(b.held_ids(), vec![[2; 16]]);
    }

    #[test]
    fn bulk_pauses_alone_when_its_refill_is_late() {
        let mut b = Book::with(50, 5_000, 1_000);
        b.on_block(block(Class::Interactive, 1, 1000, 10_000), 0);
        b.on_block(block(Class::Bulk, 2, 1000, 10_000), 0);
        b.on_status(&[status(Class::Bulk, 2, 1000, 1000, 2)], 10);
        b.requested(Class::Bulk, 10);
        // The refill is slow: paused only once the deadline passes.
        assert!(b.tick(4_000, 100).is_empty());
        let out = b.tick(5_100, 100);
        assert!(out.contains(&Action::Paused(Class::Bulk, true)));
        assert!(!b.is_paused(Class::Interactive));
        // Interactive running out with its refill late does not pause it.
        b.on_status(&[status(Class::Interactive, 1, 1000, 1000, 2)], 5_200);
        b.requested(Class::Interactive, 5_200);
        b.tick(20_000, 100);
        assert!(!b.is_paused(Class::Interactive));
        // A block arrives: running again.
        let out = b.on_block(block(Class::Bulk, 3, 1000, 10_000), 6_000);
        assert!(out.contains(&Action::Paused(Class::Bulk, false)));
        // A refill Plus refuses (the allowance is spent) pauses at once.
        b.on_status(&[status(Class::Bulk, 3, 1000, 1000, 2)], 6_100);
        b.requested(Class::Bulk, 6_100);
        b.request_failed(Class::Bulk, "allowance_used");
        assert!(b
            .tick(6_200, 100)
            .contains(&Action::Paused(Class::Bulk, true)));
    }

    #[test]
    fn a_refused_block_is_presented_again_after_the_retry_wait() {
        let mut b = Book::with(50, 5_000, 1_000);
        b.on_block(block(Class::Interactive, 1, 1000, 10_000), 0);
        b.on_status(&[status(Class::Interactive, 1, 0, 1000, 3)], 100);
        assert!(!b.wants(Class::Interactive), "the refused block comes back");
        assert!(b.tick(900, 50).is_empty());
        let out = b.tick(1_100, 50);
        assert_eq!(
            out,
            vec![Action::Present(block(Class::Interactive, 1, 1000, 10_000))]
        );
        // An expired one is not presented again.
        b.on_status(&[status(Class::Interactive, 1, 0, 1000, 3)], 1_200);
        assert!(b.tick(5_000, 10_001).is_empty());
    }

    #[test]
    fn remaining_time_is_the_sooner_of_bytes_at_the_rate_and_expiry() {
        let mut b = Book::with(50, 5_000, 1_000);
        b.on_block(block(Class::Bulk, 1, 100_000, 1_000), 0);
        b.on_status(&[status(Class::Bulk, 1, 10_000, 100_000, 1)], 10_000);
        // 1000 bytes/s, 90 000 left: 90 s; expiry is 900 s away.
        let v = b.view(Class::Bulk, 100);
        assert_eq!(v["bytes_left"], 90_000);
        assert_eq!(v["lasts_secs"], 90);
        assert_eq!(v["state"], "funded");
        // Idle: until expiry.
        let mut idle = Book::with(50, 5_000, 1_000);
        idle.on_block(block(Class::Bulk, 1, 100_000, 1_000), 0);
        assert_eq!(idle.view(Class::Bulk, 100)["lasts_secs"], 900);
    }
}
