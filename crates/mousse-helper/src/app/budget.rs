//! The credit the helper grants the app for data going to the engine
//! (Phase 1a §2.2): one budget for every stream (`APP_CREDIT_BUDGET_BYTES`),
//! at most `APP_STREAM_CREDIT_BYTES` held by one stream, and
//! `APP_CREDIT_INTERACTIVE_RESERVE_BYTES` of it only interactive streams
//! may use. On top of it, `APP_CREDIT_BOT_RESERVE_BYTES` only a bot's chat
//! and calls (`mousse.botsub`, `mousse.botrpc`) may use, so they never wait
//! behind thread traffic; they may use the rest of the budget too when it
//! is free. A bot's live browser view (`mousse.botview`) counts as bulk,
//! whatever class it was opened with, so pictures never take the
//! interactive reserve or the bot reserve. Credit returns to the budget
//! once the engine has taken the bytes, or when the stream ends.

use mousse_net_core::mux::PriorityClass;

/// Which part of the budget a stream draws on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credit {
    /// A bot's chat or calls: the bot reserve, then anything free.
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
    /// The shared budget plus the bot reserve.
    total: u64,
    bot_reserve: u64,
    reserve: u64,
    used: u64,
    /// Out to streams other than bot chat and calls.
    used_others: u64,
    used_bulk: u64,
}

impl Budget {
    /// A budget of `shared` bytes with `reserve` of it kept for interactive
    /// streams, plus `bot_reserve` bytes only bot chat and calls may use.
    pub fn new(shared: u64, reserve: u64, bot_reserve: u64) -> Self {
        Self {
            total: shared.saturating_add(bot_reserve),
            bot_reserve,
            reserve: reserve.min(shared),
            used: 0,
            used_others: 0,
            used_bulk: 0,
        }
    }

    /// Credit out now, all streams.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Up to `want` bytes for a stream drawing on `credit`.
    pub fn take(&mut self, credit: Credit, want: u64) -> u64 {
        let free = self.total - self.used;
        let shared = self.total - self.bot_reserve;
        let others = shared.saturating_sub(self.used_others);
        let room = match credit {
            Credit::Bot => free,
            Credit::Interactive => free.min(others),
            Credit::Bulk => free
                .min(others)
                .min((shared - self.reserve).saturating_sub(self.used_bulk)),
        };
        let n = want.min(room);
        self.used += n;
        if credit != Credit::Bot {
            self.used_others += n;
        }
        if credit == Credit::Bulk {
            self.used_bulk += n;
        }
        n
    }

    /// `n` bytes back from a stream drawing on `credit`.
    pub fn give_back(&mut self, credit: Credit, n: u64) {
        self.used = self.used.saturating_sub(n);
        if credit != Credit::Bot {
            self.used_others = self.used_others.saturating_sub(n);
        }
        if credit == Credit::Bulk {
            self.used_bulk = self.used_bulk.saturating_sub(n);
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
    fn threads_filling_the_budget_leave_the_bot_reserve() {
        let mut b = Budget::new(1_000, 300, 200);
        assert_eq!(b.take(Credit::Bulk, 2_000), 700);
        assert_eq!(b.take(Credit::Interactive, 2_000), 300);
        assert_eq!(b.take(Credit::Interactive, 1), 0);
        assert_eq!(b.take(Credit::Bulk, 1), 0);
        // Bot chat still gets the whole reserve.
        assert_eq!(b.take(Credit::Bot, 500), 200);
        assert_eq!(b.used(), 1_200);
        // Freed thread credit is shared again; bot credit freed stays bots'.
        b.give_back(Credit::Bot, 200);
        assert_eq!(b.take(Credit::Interactive, 1), 0);
        b.give_back(Credit::Interactive, 100);
        assert_eq!(
            b.take(Credit::Bot, 1_000),
            300,
            "the reserve and the free part"
        );
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
