//! The credit the helper grants the app for data going to the engine
//! (Phase 1a §2.2): one budget for thread and other app streams
//! (`APP_CREDIT_BUDGET_BYTES`), at most `APP_STREAM_CREDIT_BYTES` held by
//! one stream, and `APP_CREDIT_INTERACTIVE_RESERVE_BYTES` of it only
//! interactive streams may use.
//!
//! A bot's chat and calls (`mousse.botsub`, `mousse.botrpc`) draw on a
//! pool of their own, `APP_CREDIT_BOT_RESERVE_BYTES`, and never on the
//! budget: thread streams can't take bot credit, and bot streams can't
//! take the threads' (nor the interactive reserve). One bot stream holds
//! at most a [`BOT_RESERVE_SHARES`]th of the pool, so a bot stream whose
//! reader stalls leaves the rest to the others. A bot's live browser view
//! (`mousse.botview`) counts as bulk, whatever class it was opened with,
//! so pictures never take the interactive reserve or bot credit.
//!
//! Credit returns once the engine has taken the bytes, or when the stream
//! ends.

use mousse_net_core::mux::PriorityClass;

/// One bot stream holds at most this fraction of the bot pool.
pub const BOT_RESERVE_SHARES: u64 = 4;

/// Which part of the budget a stream draws on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credit {
    /// A bot's chat or calls: the bot pool only.
    Bot,
    /// The interactive reserve, then the shared part.
    Interactive,
    /// The shared part only.
    Bulk,
}

impl Credit {
    /// The credit kind of a stream labelled `label`, opened as `class`.
    pub fn of(label: &str, class: PriorityClass) -> Self {
        match label {
            "mousse.botsub" | "mousse.botrpc" => Self::Bot,
            "mousse.botview" => Self::Bulk,
            _ => match class {
                PriorityClass::Interactive => Self::Interactive,
                PriorityClass::Bulk => Self::Bulk,
            },
        }
    }
}

/// The budget.
#[derive(Debug)]
pub struct Budget {
    total: u64,
    reserve: u64,
    used: u64,
    used_bulk: u64,
    bot_total: u64,
    bot_used: u64,
}

impl Budget {
    /// A budget of `total` bytes with `reserve` of it kept for interactive
    /// streams, and a pool of `bot_total` bytes for bot chat and calls.
    pub fn new(total: u64, reserve: u64, bot_total: u64) -> Self {
        Self {
            total,
            reserve: reserve.min(total),
            used: 0,
            used_bulk: 0,
            bot_total,
            bot_used: 0,
        }
    }

    /// Credit out now, all streams.
    pub fn used(&self) -> u64 {
        self.used + self.bot_used
    }

    /// Most credit one stream drawing on `credit` holds, given the most any
    /// stream holds (`APP_STREAM_CREDIT_BYTES`).
    pub fn stream_max(&self, credit: Credit, max: u64) -> u64 {
        match credit {
            Credit::Bot => max.min(self.bot_total / BOT_RESERVE_SHARES),
            Credit::Interactive | Credit::Bulk => max,
        }
    }

    /// Up to `want` bytes for a stream drawing on `credit`.
    pub fn take(&mut self, credit: Credit, want: u64) -> u64 {
        let free = self.total - self.used;
        let n = want.min(match credit {
            Credit::Bot => self.bot_total - self.bot_used,
            Credit::Interactive => free,
            Credit::Bulk => free.min((self.total - self.reserve).saturating_sub(self.used_bulk)),
        });
        match credit {
            Credit::Bot => self.bot_used += n,
            Credit::Interactive => self.used += n,
            Credit::Bulk => {
                self.used += n;
                self.used_bulk += n;
            }
        }
        n
    }

    /// `n` bytes back from a stream drawing on `credit`.
    pub fn give_back(&mut self, credit: Credit, n: u64) {
        match credit {
            Credit::Bot => self.bot_used = self.bot_used.saturating_sub(n),
            Credit::Interactive => self.used = self.used.saturating_sub(n),
            Credit::Bulk => {
                self.used = self.used.saturating_sub(n);
                self.used_bulk = self.used_bulk.saturating_sub(n);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_leaves_the_reserve_to_interactive() {
        let mut b = Budget::new(1_000, 300, 0);
        assert_eq!(b.take(Credit::Bulk, 500), 500);
        assert_eq!(b.take(Credit::Bulk, 500), 200);
        assert_eq!(b.take(Credit::Bulk, 1), 0);
        assert_eq!(b.take(Credit::Interactive, 500), 300);
        assert_eq!(b.take(Credit::Interactive, 1), 0);
        b.give_back(Credit::Interactive, 100);
        // Freed interactive credit is still kept from bulk streams.
        assert_eq!(b.take(Credit::Bulk, 100), 0);
        b.give_back(Credit::Bulk, 50);
        assert_eq!(b.take(Credit::Bulk, 100), 50);
        assert_eq!(b.used(), 900);
    }

    #[test]
    fn interactive_may_use_all_of_the_shared_budget() {
        let mut b = Budget::new(1_000, 300, 0);
        assert_eq!(b.take(Credit::Interactive, 2_000), 1_000);
        assert_eq!(b.take(Credit::Bulk, 1), 0);
    }

    #[test]
    fn threads_and_bots_never_take_each_others_credit() {
        let mut b = Budget::new(1_000, 300, 200);
        assert_eq!(b.take(Credit::Bulk, 2_000), 700);
        assert_eq!(b.take(Credit::Interactive, 2_000), 300);
        assert_eq!(b.take(Credit::Interactive, 1), 0);
        // Bot chat still gets its whole pool, and no more.
        assert_eq!(b.take(Credit::Bot, 500), 200);
        assert_eq!(b.take(Credit::Bot, 1), 0);
        assert_eq!(b.used(), 1_200);
        // Bot credit freed stays bots'; thread credit freed stays threads'.
        b.give_back(Credit::Bot, 200);
        assert_eq!(b.take(Credit::Interactive, 1), 0);
        b.give_back(Credit::Interactive, 100);
        assert_eq!(b.take(Credit::Bot, 1_000), 200);
        assert_eq!(b.take(Credit::Interactive, 1_000), 100);
    }

    #[test]
    fn bots_at_their_cap_leave_the_interactive_reserve_to_a_thread_call() {
        let mut b = Budget::new(1_000, 300, 200);
        assert_eq!(b.take(Credit::Bulk, 2_000), 700);
        // Bot streams opened bulk or interactive draw on the bot pool only.
        for class in [PriorityClass::Bulk, PriorityClass::Interactive] {
            let bot = Credit::of("mousse.botsub", class);
            while b.take(bot, 50) > 0 {}
        }
        assert_eq!(b.take(Credit::Interactive, 2_000), 300);
    }

    #[test]
    fn one_bot_stream_holds_at_most_a_share_of_the_pool() {
        let b = Budget::new(1_000, 300, 1 << 20);
        assert_eq!(b.stream_max(Credit::Bot, 4 << 20), 256 << 10);
        assert_eq!(b.stream_max(Credit::Bot, 64 << 10), 64 << 10);
        assert_eq!(b.stream_max(Credit::Interactive, 4 << 20), 4 << 20);
    }

    #[test]
    fn the_browser_view_counts_as_bulk_and_never_takes_a_reserve() {
        for class in [PriorityClass::Interactive, PriorityClass::Bulk] {
            assert_eq!(Credit::of("mousse.botview", class), Credit::Bulk);
            assert_eq!(Credit::of("mousse.botsub", class), Credit::Bot);
            assert_eq!(Credit::of("mousse.botrpc", class), Credit::Bot);
        }
        assert_eq!(
            Credit::of("mousse.sub", PriorityClass::Interactive),
            Credit::Interactive
        );
        let mut b = Budget::new(1_000, 300, 200);
        let view = Credit::of("mousse.botview", PriorityClass::Interactive);
        assert_eq!(b.take(view, 2_000), 700);
        assert_eq!(b.take(Credit::Interactive, 2_000), 300);
        assert_eq!(b.take(Credit::Bot, 2_000), 200);
    }
}
