//! Wall-clock and monotonic time for the I/O layer.
//!
//! Core takes time as explicit values. This module is where those values come
//! from, behind a trait so tests can move the wall clock.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use mousse_net_core::{Millis, UnixTime};

/// A source of wall-clock and monotonic time.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Wall-clock time, whole seconds since the Unix epoch.
    fn now(&self) -> UnixTime;
    /// Monotonic milliseconds from an arbitrary origin.
    fn mono(&self) -> Millis;
}

fn system_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The system clock.
#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// A clock whose monotonic origin is now.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> UnixTime {
        UnixTime(system_secs())
    }

    fn mono(&self) -> Millis {
        Millis(self.origin.elapsed().as_millis() as u64)
    }
}

/// The system clock with adjustable offsets, for tests that need a device
/// whose clock is ahead or behind, or that skip a wait.
#[derive(Debug)]
pub struct ManualClock {
    origin: Instant,
    offset_secs: AtomicI64,
    mono_offset_ms: AtomicU64,
    /// A stopped wall clock, or -1.
    frozen: AtomicI64,
    /// The monotonic time it stopped at, or `u64::MAX` while it runs.
    mono_frozen: AtomicU64,
}

impl ManualClock {
    /// A clock that starts at the system time.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
            offset_secs: AtomicI64::new(0),
            mono_offset_ms: AtomicU64::new(0),
            frozen: AtomicI64::new(-1),
            mono_frozen: AtomicU64::new(u64::MAX),
        }
    }

    /// Stop the monotonic clock where it is, so it moves only by
    /// [`ManualClock::advance_mono`]: a check at an exact millisecond.
    pub fn freeze_mono(&self) {
        let at = self.origin.elapsed().as_millis() as u64;
        let _ = self
            .mono_frozen
            .compare_exchange(u64::MAX, at, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// Move the monotonic clock forward by `ms` (the wall clock stays).
    pub fn advance_mono(&self, ms: u64) {
        self.mono_offset_ms.fetch_add(ms, Ordering::SeqCst);
    }

    /// Move the wall clock by `secs` (may be negative).
    pub fn advance(&self, secs: i64) {
        self.offset_secs.fetch_add(secs, Ordering::SeqCst);
    }

    /// Stop the wall clock at `at`, for checks at an exact second. Until
    /// [`ManualClock::thaw`], `advance` has no effect.
    pub fn freeze_at(&self, at: UnixTime) {
        self.frozen
            .store(i64::try_from(at.0).unwrap_or(i64::MAX), Ordering::SeqCst);
    }

    /// Let the wall clock run again.
    pub fn thaw(&self) {
        self.frozen.store(-1, Ordering::SeqCst);
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> UnixTime {
        let frozen = self.frozen.load(Ordering::SeqCst);
        if frozen >= 0 {
            return UnixTime(frozen as u64);
        }
        let base = system_secs() as i64;
        let shifted = base.saturating_add(self.offset_secs.load(Ordering::SeqCst));
        UnixTime(shifted.max(0) as u64)
    }

    fn mono(&self) -> Millis {
        let base = match self.mono_frozen.load(Ordering::SeqCst) {
            u64::MAX => self.origin.elapsed().as_millis() as u64,
            frozen => frozen,
        };
        Millis(base + self.mono_offset_ms.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_moves_wall_time_only() {
        let clock = ManualClock::new();
        let before = clock.now();
        clock.advance(3_600);
        let after = clock.now();
        assert!(after.secs() >= before.secs() + 3_600);
        assert!(after.secs() <= before.secs() + 3_602);
    }
}
