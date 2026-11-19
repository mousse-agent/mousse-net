//! The credit the helper grants the app for data going to the engine
//! (Phase 1a §2.2): one budget for every stream (`APP_CREDIT_BUDGET_BYTES`),
//! at most `APP_STREAM_CREDIT_BYTES` held by one stream, and
//! `APP_CREDIT_INTERACTIVE_RESERVE_BYTES` of it only interactive streams
//! may use. Credit returns to the budget once the engine has taken the
//! bytes, or when the stream ends.

use mousse_net_core::mux::PriorityClass;

/// The budget.
#[derive(Debug)]
pub struct Budget {
    total: u64,
    reserve: u64,
    used: u64,
    used_bulk: u64,
}

impl Budget {
    /// A budget of `total` bytes with `reserve` kept for interactive
    /// streams.
    pub fn new(total: u64, reserve: u64) -> Self {
        Self {
            total,
            reserve: reserve.min(total),
            used: 0,
            used_bulk: 0,
        }
    }

    /// Credit out now, all streams.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Up to `want` bytes for a stream of `class`.
    pub fn take(&mut self, class: PriorityClass, want: u64) -> u64 {
        let free = self.total - self.used;
        let room = match class {
            PriorityClass::Interactive => free,
            PriorityClass::Bulk => {
                free.min((self.total - self.reserve).saturating_sub(self.used_bulk))
            }
        };
        let n = want.min(room);
        self.used += n;
        if class == PriorityClass::Bulk {
            self.used_bulk += n;
        }
        n
    }

    /// `n` bytes back from a stream of `class`.
    pub fn give_back(&mut self, class: PriorityClass, n: u64) {
        self.used = self.used.saturating_sub(n);
        if class == PriorityClass::Bulk {
            self.used_bulk = self.used_bulk.saturating_sub(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_leaves_the_reserve_to_interactive() {
        let mut b = Budget::new(1_000, 300);
        assert_eq!(b.take(PriorityClass::Bulk, 500), 500);
        assert_eq!(b.take(PriorityClass::Bulk, 500), 200);
        assert_eq!(b.take(PriorityClass::Bulk, 1), 0);
        assert_eq!(b.take(PriorityClass::Interactive, 500), 300);
        assert_eq!(b.take(PriorityClass::Interactive, 1), 0);
        b.give_back(PriorityClass::Interactive, 100);
        // Freed interactive credit is still kept from bulk streams.
        assert_eq!(b.take(PriorityClass::Bulk, 100), 0);
        b.give_back(PriorityClass::Bulk, 50);
        assert_eq!(b.take(PriorityClass::Bulk, 100), 50);
        assert_eq!(b.used(), 900);
    }

    #[test]
    fn interactive_may_use_all_of_it() {
        let mut b = Budget::new(1_000, 300);
        assert_eq!(b.take(PriorityClass::Interactive, 2_000), 1_000);
        assert_eq!(b.take(PriorityClass::Bulk, 1), 0);
    }
}
