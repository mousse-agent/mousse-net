//! A move to another hosted relay (design B.11): a staged cutover with a
//! short, stated interruption, because Plus funds one relay per endpoint
//! (A.8).
//!
//! 1. **Stage:** register on the new relay (admission token, no blocks),
//!    push the allow-set and add the route to the manifest. The old route
//!    keeps serving while callers approve the new destination.
//! 2. **Cut over** after `MOUSSE_NET_VIA_RELAY_MOVE_STAGE_SECS`, or at once
//!    if the old relay is gone: `RELEASE` every old block, then ask Plus for
//!    blocks on the new relay. Until the first new block, relayed calls are
//!    refused; the app shows "Moving to a new relay".
//! 3. The old route leaves the manifest at cutover.

/// Where a move stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoveState {
    /// No move.
    Idle,
    /// The new relay is registered and in the manifest; the old one funds.
    Staged {
        /// The new relay.
        to: [u8; 32],
        /// When staging began (Unix seconds).
        since: u64,
    },
    /// The old blocks are released; the new relay is not funded yet.
    CuttingOver {
        /// The new relay.
        to: [u8; 32],
        /// When the cutover began (Unix seconds).
        at: u64,
    },
}

/// What the driver must do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoveAction {
    /// The old relay's registrations send `RELEASE` for every block they
    /// hold, and end.
    ReleaseOld,
    /// Start asking Plus for blocks on the new relay.
    FundNew([u8; 32]),
    /// Drop the old route from the manifest.
    DropOldRoute,
    /// Tell the app: relayed calls pause until the new relay is funded.
    Interrupted,
    /// Tell the app: the move is done. (The hosted client says so itself
    /// once no other relay holds blocks.)
    #[cfg(test)]
    Done([u8; 32]),
}

/// One endpoint's relay move.
#[derive(Clone, Debug)]
pub struct RelayMove {
    stage_secs: u64,
    state: MoveState,
}

impl RelayMove {
    /// With `MOUSSE_NET_VIA_RELAY_MOVE_STAGE_SECS`.
    pub fn new(stage_secs: u64) -> Self {
        Self {
            stage_secs,
            state: MoveState::Idle,
        }
    }

    /// A move staged before a restart, from what was kept on disk.
    pub fn resume(stage_secs: u64, to: [u8; 32], since: u64) -> Self {
        Self {
            stage_secs,
            state: MoveState::Staged { to, since },
        }
    }

    /// The state.
    #[cfg(test)]
    pub fn state(&self) -> &MoveState {
        &self.state
    }

    /// The new relay is registered and its route staged.
    pub fn staged(&mut self, to: [u8; 32], now: u64) -> Vec<MoveAction> {
        self.state = MoveState::Staged { to, since: now };
        if cfg!(mousse_control = "fund-two-relays") {
            // Must-fail control (tests only): fund the new relay while the
            // old one still holds blocks.
            return vec![MoveAction::FundNew(to)];
        }
        Vec::new()
    }

    /// Time passed, or the old relay is gone (`old_gone`: no live
    /// registration there to send `RELEASE`).
    pub fn tick(&mut self, now: u64, old_gone: bool) -> Vec<MoveAction> {
        let MoveState::Staged { to, since } = self.state else {
            return Vec::new();
        };
        if !old_gone && now < since.saturating_add(self.stage_secs) {
            return Vec::new();
        }
        self.state = MoveState::CuttingOver { to, at: now };
        let mut out = Vec::new();
        if !old_gone {
            out.push(MoveAction::ReleaseOld);
        }
        out.extend([
            MoveAction::DropOldRoute,
            MoveAction::Interrupted,
            MoveAction::FundNew(to),
        ]);
        out
    }

    /// The first block on the new relay arrived.
    #[cfg(test)]
    pub fn funded(&mut self) -> Vec<MoveAction> {
        match self.state {
            MoveState::CuttingOver { to, .. } => {
                self.state = MoveState::Idle;
                vec![MoveAction::Done(to)]
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEW: [u8; 32] = [7; 32];

    #[test]
    fn a_move_stages_then_releases_before_funding_the_new_relay() {
        let mut m = RelayMove::new(86_400);
        assert!(
            m.staged(NEW, 1_000).is_empty(),
            "nothing funds the new relay while staged"
        );
        assert!(m.tick(1_000 + 86_399, false).is_empty());
        let out = m.tick(1_000 + 86_400, false);
        let release = out
            .iter()
            .position(|a| *a == MoveAction::ReleaseOld)
            .expect("old blocks released");
        let fund = out
            .iter()
            .position(|a| *a == MoveAction::FundNew(NEW))
            .expect("new relay funded");
        assert!(release < fund);
        assert!(out.contains(&MoveAction::Interrupted));
        assert_eq!(m.funded(), vec![MoveAction::Done(NEW)]);
        assert_eq!(m.state(), &MoveState::Idle);
    }

    #[test]
    fn a_gone_old_relay_cuts_over_at_once() {
        let mut m = RelayMove::new(86_400);
        m.staged(NEW, 1_000);
        let out = m.tick(1_001, true);
        assert!(!out.contains(&MoveAction::ReleaseOld));
        assert!(out.contains(&MoveAction::FundNew(NEW)));
    }
}
