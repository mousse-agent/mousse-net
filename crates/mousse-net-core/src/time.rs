//! Explicit time values. Core never reads a clock.

/// Allowed clock difference between two devices, in seconds (±10 minutes).
///
/// The same rule applies everywhere a signed time is checked: certificate
/// windows, live-session deadlines and ticket expiry on the joiner.
pub const CLOCK_SKEW_SECS: u64 = 600;

/// Wall-clock time in whole seconds since the Unix epoch (UTC).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct UnixTime(pub u64);

impl UnixTime {
    /// Seconds since the Unix epoch.
    pub const fn secs(self) -> u64 {
        self.0
    }

    /// This time plus `secs`, saturating at the maximum.
    pub const fn plus(self, secs: u64) -> Self {
        Self(self.0.saturating_add(secs))
    }

    /// This time minus `secs`, saturating at zero.
    pub const fn minus(self, secs: u64) -> Self {
        Self(self.0.saturating_sub(secs))
    }
}

/// Monotonic time in milliseconds from an arbitrary origin. Used for timers
/// (keepalive, idle timeout, proof wait) that must not jump with the wall
/// clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Millis(pub u64);

impl Millis {
    /// Milliseconds since the origin.
    pub const fn ms(self) -> u64 {
        self.0
    }

    /// This instant plus `ms`, saturating at the maximum.
    pub const fn plus(self, ms: u64) -> Self {
        Self(self.0.saturating_add(ms))
    }

    /// Milliseconds elapsed from `earlier` to `self`, zero if `earlier` is later.
    pub const fn since(self, earlier: Millis) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}
