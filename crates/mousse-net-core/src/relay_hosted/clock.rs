//! The relay's estimate of Plus's clock (`docs/phase34-design.md` §A.9
//! duty 12).
//!
//! The relay notes its monotonic clock when it sends each boot or report
//! request. From an answer whose round trip took at most
//! `MOUSSE_NET_RELAY_CLOCK_RTT_MS` it sets
//! `Plus clock = answer's Plus time + (monotonic now − monotonic send time)`.
//! Plus built the answer after the request was sent, so the estimate is
//! never behind Plus's real clock except by monotonic drift. Leases are
//! judged on it, never on the relay's wall clock.

use crate::time::{Millis, UnixTime};

use super::records::BLOCK_MAX_LIFETIME_SECS;

/// One answer the clock was set from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Anchor {
    /// Plus time in the answer, Unix milliseconds.
    plus_ms: u64,
    /// The relay's monotonic clock when it sent the request.
    sent: Millis,
}

/// The Plus clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlusClock {
    anchor: Option<Anchor>,
}

impl PlusClock {
    /// A clock with no answer yet.
    pub const fn new() -> Self {
        Self { anchor: None }
    }

    /// Take an answer built at `plus_ms` (Unix milliseconds) to a request
    /// sent at `sent` and answered at `now`. An answer whose round trip took
    /// longer than `rtt_max_ms` is ignored. So is an answer to a request
    /// sent before the one the clock already follows, since answers can
    /// arrive out of order. Returns whether the clock was set.
    pub fn answer(&mut self, plus_ms: u64, sent: Millis, now: Millis, rtt_max_ms: u64) -> bool {
        if now < sent || now.since(sent) > rtt_max_ms {
            return false;
        }
        if let Some(a) = self.anchor {
            if sent < a.sent {
                return false;
            }
        }
        self.anchor = Some(Anchor { plus_ms, sent });
        true
    }

    /// Whether any answer has set the clock in this boot.
    pub fn is_set(&self) -> bool {
        self.anchor.is_some()
    }

    /// Plus time now, Unix milliseconds, if the clock is set.
    pub fn now_ms(&self, now: Millis) -> Option<u64> {
        self.anchor
            .map(|a| a.plus_ms.saturating_add(now.since(a.sent)))
    }

    /// Whether leases may still be used at `now`: the clock is set, and the
    /// request behind it was sent less than `BLOCK_MAX_LIFETIME` ago.
    pub fn is_fresh(&self, now: Millis) -> bool {
        self.anchor
            .is_some_and(|a| now.since(a.sent) < BLOCK_MAX_LIFETIME_SECS * 1_000)
    }

    /// The monotonic instant when the clock stops being fresh.
    pub fn stale_at(&self) -> Option<Millis> {
        self.anchor
            .map(|a| a.sent.plus(BLOCK_MAX_LIFETIME_SECS * 1_000))
    }

    /// The monotonic instant when Plus time reaches `plus_ms`, if the clock
    /// is set (`now` if it already has).
    pub fn when(&self, plus_ms: u64, now: Millis) -> Option<Millis> {
        let a = self.anchor?;
        let at = a.sent.plus(plus_ms.saturating_sub(a.plus_ms));
        Some(if at < now { now } else { at })
    }

    /// Time for admission windows and report `sent at`: Plus time once the
    /// clock is set, the wall clock before (§A.9 duty 12, §A.12 key 5).
    pub fn now_or_wall_ms(&self, now: Millis, wall: UnixTime) -> u64 {
        self.now_ms(now)
            .unwrap_or_else(|| wall.secs().saturating_mul(1_000))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn the_estimate_counts_from_the_send_time() {
        let mut c = PlusClock::new();
        assert!(!c.is_set());
        assert_eq!(c.now_ms(Millis(0)), None);
        // Sent at 1000, answered at 1300, Plus said 50_000.
        assert!(c.answer(50_000, Millis(1_000), Millis(1_300), 2_000));
        // So now (1300) is at least 50_300 on Plus's clock: never behind.
        assert_eq!(c.now_ms(Millis(1_300)), Some(50_300));
        assert_eq!(c.now_ms(Millis(2_000)), Some(51_000));
        assert_eq!(c.when(60_000, Millis(1_300)), Some(Millis(11_000)));
    }

    #[test]
    fn a_slow_answer_does_not_set_the_clock() {
        let mut c = PlusClock::new();
        assert!(!c.answer(50_000, Millis(0), Millis(2_001), 2_000));
        assert!(!c.is_set());
        assert!(c.answer(50_000, Millis(0), Millis(2_000), 2_000));
    }

    #[test]
    fn an_older_request_does_not_replace_a_newer_one() {
        let mut c = PlusClock::new();
        assert!(c.answer(90_000, Millis(5_000), Millis(5_100), 2_000));
        assert!(!c.answer(80_000, Millis(4_000), Millis(5_200), 2_000));
        assert_eq!(c.now_ms(Millis(5_100)), Some(90_100));
    }

    #[test]
    fn the_clock_goes_stale_a_block_lifetime_after_its_request() {
        let mut c = PlusClock::new();
        assert!(c.answer(0, Millis(10), Millis(20), 2_000));
        let limit = BLOCK_MAX_LIFETIME_SECS * 1_000;
        assert!(c.is_fresh(Millis(10 + limit - 1)));
        assert!(!c.is_fresh(Millis(10 + limit)));
        assert_eq!(c.stale_at(), Some(Millis(10 + limit)));
    }

    #[test]
    fn before_any_answer_admission_uses_the_wall_clock() {
        let c = PlusClock::new();
        assert_eq!(c.now_or_wall_ms(Millis(5), UnixTime(7)), 7_000);
    }
}
