//! The hosted relay's link to Plus (`docs/phase34-design.md` §A.9): the boot
//! announcement, the snapshot reports and the stopping snapshot.
//!
//! [`HostedRuntime`] holds the boot's [`Hosted`] state for every task of
//! the relay. [`run`] announces the boot in the background, retrying the
//! same record until Plus answers, then sends report parts one at a time
//! as the state builds them. On a stop it makes every lease final and waits
//! up to `MOUSSE_NET_RELAY_FINAL_REPORT_WAIT_MS` for the stopping snapshot
//! to be stored.
//!
//! Log lines carry aggregate facts only: no handle, lease id or address.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::{watch, Notify};

use mousse_net_core::identity::SoftwareKey;
use mousse_net_core::relay_hosted::{
    BootAnswer, BootRecord, Event, Hosted, IssuerKeys, Now, ReportAnswer, SignedEnvelope,
};
use mousse_net_core::Millis;
use mousse_net_io::Clock;

use crate::http::{CallError, PlusHttp};

/// Where log lines go.
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

/// API path of the boot announcement.
pub const BOOT_PATH: &str = "/v1/relay/boot";
/// API path of a report part.
pub const REPORT_PATH: &str = "/v1/relay/report";

/// One hosted boot's state, shared by the relay's tasks.
pub struct HostedRuntime {
    hosted: Mutex<Hosted>,
    wake: Notify,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for HostedRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedRuntime").finish_non_exhaustive()
    }
}

impl HostedRuntime {
    /// Share `hosted`, reading time from `clock`. The clock's monotonic
    /// time must count while the machine sleeps (the Plus clock rests on
    /// it, §A.9 duty 12); [`mousse_net_io::SystemClock`] does.
    pub fn new(hosted: Hosted, clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            hosted: Mutex::new(hosted),
            wake: Notify::new(),
            clock,
        })
    }

    /// Both clocks now.
    pub fn now(&self) -> Now {
        Now {
            mono: self.clock.mono(),
            wall: self.clock.now(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Hosted> {
        // A panic while holding the lock leaves counters that may be half
        // updated; the relay cannot vouch for them, so it stops.
        self.hosted.lock().expect("hosted state lock poisoned")
    }

    /// Run `f` on the state at the current time, then let the reporter
    /// look again (a final may have made a snapshot due).
    pub fn with<R>(&self, f: impl FnOnce(&mut Hosted, Now) -> R) -> R {
        let now = self.now();
        let r = f(&mut self.lock(), now);
        self.wake.notify_one();
        r
    }

    /// [`HostedRuntime::with`] for the reporter itself: it must not wake
    /// itself, or its wait would end at once and spin.
    fn quiet<R>(&self, f: impl FnOnce(&mut Hosted, Now) -> R) -> R {
        let now = self.now();
        f(&mut self.lock(), now)
    }

    /// Run the timers and return the events for the connection code.
    pub fn poll(&self) -> Vec<Event> {
        self.with(|h, now| h.poll(now))
    }

    /// When [`HostedRuntime::poll`] next has work.
    pub fn next_wakeup(&self) -> Option<Millis> {
        let now = self.now();
        self.lock().next_wakeup(now)
    }

    /// Replace the pinned issuer keys (`mousse-relay reload`).
    pub fn reload(&self, keys: IssuerKeys) {
        self.with(|h, _| h.set_issuer_keys(keys));
    }
}

/// What the reporter needs besides the state.
pub struct PlusLink {
    /// Calls to Plus.
    pub http: PlusHttp,
    /// The relay's report key.
    pub report_key: SoftwareKey,
    /// This boot's record, signed once and sent until Plus answers.
    pub boot: BootRecord,
    /// Log sink.
    pub log: Log,
}

struct Backoff {
    first: u64,
    max: u64,
    next: u64,
}

impl Backoff {
    fn new(first: u64, max: u64) -> Self {
        Self {
            first,
            max,
            next: first,
        }
    }

    fn reset(&mut self) {
        self.next = self.first;
    }

    /// The wait after a failure; `retry_after` from Plus lengthens it, up to
    /// the longest wait.
    fn after(&mut self, e: &CallError) -> u64 {
        let mut wait = self.next;
        if let CallError::Plus {
            retry_after_secs: Some(s),
            ..
        } = e
        {
            wait = wait.max(s.saturating_mul(1_000));
        }
        self.next = self.next.saturating_mul(2).min(self.max);
        wait.min(self.max)
    }
}

/// A stop was asked for, or whoever could ask is gone.
fn stop_asked(stop: &watch::Receiver<bool>) -> bool {
    *stop.borrow() || stop.has_changed().is_err()
}

fn ms_until(now: Millis, at: Millis) -> Duration {
    Duration::from_millis(at.since(now))
}

/// Announce the boot, then report until stopped. Returns once the
/// stopping snapshot is stored or the final report wait has passed (or at
/// once on a stop before Plus has answered the boot, since no lease can
/// have been accepted).
pub async fn run(rt: Arc<HostedRuntime>, link: PlusLink, mut stop: watch::Receiver<bool>) {
    let limits = *rt.lock().limits();
    let mut backoff = Backoff::new(limits.plus_retry_first_ms(), limits.plus_retry_max_ms());
    let boot = SignedEnvelope::sign(link.boot.encode(), &link.report_key).encode();

    // Announce (§A.9 duty 2): the same bytes every time.
    loop {
        if stop_asked(&stop) {
            rt.quiet(|h, now| h.stop(now));
            return;
        }
        let sent = rt.now().mono;
        match link.http.post(BOOT_PATH, &boot).await {
            Ok(body) => match BootAnswer::decode(&body) {
                Ok(a) => {
                    rt.quiet(|h, now| h.boot_answered(&a, sent, now));
                    (link.log)("plus: boot acknowledged");
                    backoff.reset();
                    break;
                }
                Err(_) => (link.log)("plus: boot answer unreadable; retrying"),
            },
            Err(e) => {
                if e.code() == Some("stale_generation") {
                    (link.log)("plus: boot refused as stale_generation; an operator must resolve it at Plus; retrying");
                } else {
                    (link.log)(&format!("plus: boot announcement failed ({e}); retrying"));
                }
                let wait = Duration::from_millis(backoff.after(&e));
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = stop.changed() => {}
                }
            }
        }
    }

    // Report (§A.9 duty 4) until a stop, then the stopping snapshot.
    let mut deadline: Option<Millis> = None;
    loop {
        if deadline.is_none() && stop_asked(&stop) {
            rt.quiet(|h, now| h.stop(now));
            deadline = Some(rt.now().mono.plus(limits.final_report_wait_ms()));
        }
        if let Some(d) = deadline {
            if rt.lock().stop_reported() {
                (link.log)("plus: stopping snapshot stored");
                return;
            }
            if rt.now().mono >= d {
                (link.log)("plus: stopping snapshot not stored in time");
                return;
            }
        }
        let part = rt.quiet(|h, now| h.next_report_part(now));
        let Some(part) = part else {
            let now = rt.now();
            let due = rt.lock().report_due(now);
            let wake = match (due, deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            let sleep = wake.map(|w| ms_until(now.mono, w));
            tokio::select! {
                _ = async { match sleep { Some(s) => tokio::time::sleep(s).await, None => std::future::pending().await } } => {}
                _ = rt.wake.notified() => {}
                _ = stop.changed(), if deadline.is_none() => {}
            }
            continue;
        };
        let env = SignedEnvelope::sign(part.encode(), &link.report_key).encode();
        let sent = rt.now().mono;
        let failed = match link.http.post(REPORT_PATH, &env).await {
            Ok(body) => match ReportAnswer::decode(&body) {
                Ok(a) => {
                    rt.quiet(|h, now| h.report_answered(part.sequence, &a, sent, now));
                    backoff.reset();
                    None
                }
                Err(_) => Some(CallError::BadAnswer("report answer unreadable")),
            },
            Err(e) => Some(e),
        };
        if let Some(e) = failed {
            (link.log)(&format!("plus: report part failed ({e}); retrying"));
            let wait = backoff.after(&e);
            let now = rt.now();
            // Wake early to take a snapshot on time, or at the stop deadline.
            let mut until = now.mono.plus(wait);
            if let Some(t) = rt.lock().snapshot_due(now) {
                until = until.min(t.max(now.mono));
            }
            if let Some(d) = deadline {
                until = until.min(d);
            }
            tokio::select! {
                _ = tokio::time::sleep(ms_until(now.mono, until)) => {}
                _ = stop.changed(), if deadline.is_none() => {}
            }
        }
    }
}
