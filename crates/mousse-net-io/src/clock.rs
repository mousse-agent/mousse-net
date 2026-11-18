//! Wall-clock and monotonic time for the I/O layer.
//!
//! Core takes time as explicit values. This module is where those values come
//! from, behind a trait so tests can move the wall clock.
//!
//! The monotonic clock keeps counting while the device sleeps, so a session
//! cap measured on it cannot be stretched by a suspend followed by setting
//! the wall clock back: `CLOCK_BOOTTIME` on Linux and Android,
//! `mach_continuous_time` on Apple systems, `QueryInterruptTime` on Windows.
//! (`std::time::Instant` pauses during sleep on Linux and Apple systems.)

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// Milliseconds on the platform's monotonic clock that counts sleep,
/// from an arbitrary origin.
fn awake_or_asleep_ms() -> u64 {
    imp::now_ms()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unsafe_code)]
mod imp {
    pub fn now_ms() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid place for the result.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
        // CLOCK_BOOTTIME is in every kernel since 2.6.39.
        assert_eq!(rc, 0, "clock_gettime(CLOCK_BOOTTIME) failed");
        (ts.tv_sec as u64)
            .saturating_mul(1_000)
            .saturating_add(ts.tv_nsec as u64 / 1_000_000)
    }
}

#[cfg(target_vendor = "apple")]
#[allow(unsafe_code)]
mod imp {
    use std::sync::OnceLock;

    unsafe extern "C" {
        /// Like `mach_absolute_time`, but it keeps counting while the
        /// system sleeps (macOS 10.12, iOS 10).
        fn mach_continuous_time() -> u64;
    }

    pub fn now_ms() -> u64 {
        static TIMEBASE: OnceLock<(u64, u64)> = OnceLock::new();
        let (numer, denom) = *TIMEBASE.get_or_init(|| {
            let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
            // SAFETY: `info` is a valid place for the result.
            let rc = unsafe { libc::mach_timebase_info(&mut info) };
            assert!(rc == 0 && info.denom != 0, "mach_timebase_info failed");
            (u64::from(info.numer), u64::from(info.denom))
        });
        // SAFETY: takes no arguments and only reads the clock.
        let ticks = unsafe { mach_continuous_time() };
        let ns = u128::from(ticks) * u128::from(numer) / u128::from(denom);
        u64::try_from(ns / 1_000_000).unwrap_or(u64::MAX)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use windows_sys::Win32::System::WindowsProgramming::QueryInterruptTime;

    pub fn now_ms() -> u64 {
        let mut t = 0u64;
        // SAFETY: `t` is a valid place for the result. The interrupt time
        // counts sleep and hibernation (the unbiased variant would not).
        unsafe { QueryInterruptTime(&mut t) };
        // 100 ns units.
        t / 10_000
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
)))]
mod imp {
    use std::sync::OnceLock;
    use std::time::Instant;

    /// Elsewhere: `Instant`, whatever it does during sleep.
    pub fn now_ms() -> u64 {
        static ORIGIN: OnceLock<Instant> = OnceLock::new();
        ORIGIN.get_or_init(Instant::now).elapsed().as_millis() as u64
    }
}

/// The system clock.
#[derive(Debug)]
pub struct SystemClock {
    origin: u64,
}

impl SystemClock {
    /// A clock whose monotonic origin is now.
    pub fn new() -> Self {
        Self {
            origin: awake_or_asleep_ms(),
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
        Millis(awake_or_asleep_ms().saturating_sub(self.origin))
    }
}

/// The system clock with adjustable offsets, for tests that need a device
/// whose clock is ahead or behind, or that skip a wait.
#[derive(Debug)]
pub struct ManualClock {
    origin: u64,
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
            origin: awake_or_asleep_ms(),
            offset_secs: AtomicI64::new(0),
            mono_offset_ms: AtomicU64::new(0),
            frozen: AtomicI64::new(-1),
            mono_frozen: AtomicU64::new(u64::MAX),
        }
    }

    /// Stop the monotonic clock where it is, so it moves only by
    /// [`ManualClock::advance_mono`]: a check at an exact millisecond.
    pub fn freeze_mono(&self) {
        let at = awake_or_asleep_ms().saturating_sub(self.origin);
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
            u64::MAX => awake_or_asleep_ms().saturating_sub(self.origin),
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

    /// The monotonic clock moves with real time and never back.
    #[test]
    fn the_system_monotonic_clock_moves_with_real_time() {
        let clock = SystemClock::new();
        let real = std::time::Instant::now();
        let first = clock.mono();
        std::thread::sleep(std::time::Duration::from_millis(60));
        let second = clock.mono();
        let elapsed = real.elapsed().as_millis() as u64;
        assert!(second.0 >= first.0 + 50, "{first:?} {second:?}");
        assert!(
            second.0 <= first.0 + elapsed + 50,
            "{first:?} {second:?} {elapsed}"
        );
    }
}
