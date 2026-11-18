//! Watching for network changes a caller must react to (Phase 1a §6 and
//! §8).
//!
//! - **Interfaces.** Every [`IoLimits::iface_poll_ms`] the watcher lists
//!   the interfaces through an [`InterfaceSource`]. A list that differs
//!   from the last one is a [`NetChange::Interfaces`].
//! - **Wake.** The monotonic clock counts time asleep (see
//!   [`Clock::mono`]); the timer that paces the polls need not. When the
//!   clock ran more than [`IoLimits::wake_jump_ms`] past one poll
//!   interval, the computer slept: [`NetChange::Wake`].
//!
//! Neither change says which connections still work. The caller pings
//! them ([`Connection::ping`](crate::Connection::ping)) and redials.

use std::sync::Arc;

use mousse_net_core::Millis;
use tokio::sync::mpsc;

use crate::clock::Clock;
use crate::limits::{ms, IoLimits};

/// A change the watcher saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetChange {
    /// The interfaces or their addresses changed.
    Interfaces,
    /// The computer slept for about `slept_ms` and woke.
    Wake {
        /// How much longer than one poll interval the monotonic clock ran.
        slept_ms: u64,
    },
}

/// Lists the interfaces.
pub trait InterfaceSource: Send + Sync {
    /// The interfaces now, in a form that is equal when nothing changed.
    fn snapshot(&self) -> Vec<String>;
}

/// The computer's interfaces other than loopback: name, address and
/// whether each is up.
pub struct SystemInterfaces;

impl InterfaceSource for SystemInterfaces {
    fn snapshot(&self) -> Vec<String> {
        let mut list: Vec<String> = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .filter(|i| !i.is_loopback())
            .map(|i| {
                let up = if i.is_oper_up() { "up" } else { "down" };
                format!("{} {} {up}", i.name, i.ip())
            })
            .collect();
        list.sort();
        list.dedup();
        list
    }
}

/// Tells a sleep from an ordinary poll by how far the monotonic clock ran.
#[derive(Clone, Copy, Debug)]
pub struct WakeDetector {
    last: Millis,
    poll_ms: u64,
    jump_ms: u64,
}

impl WakeDetector {
    /// A detector whose last poll was at `now`.
    pub fn new(now: Millis, limits: &IoLimits) -> Self {
        Self {
            last: now,
            poll_ms: limits.iface_poll_ms(),
            jump_ms: limits.wake_jump_ms(),
        }
    }

    /// A poll ran at `now`. Returns how long the computer slept when the
    /// clock ran more than the jump past one poll interval.
    pub fn poll(&mut self, now: Millis) -> Option<u64> {
        let ran = now.since(self.last);
        self.last = now;
        (ran > self.poll_ms.saturating_add(self.jump_ms)).then(|| ran - self.poll_ms)
    }
}

/// Watch the network until the receiver is dropped. Must be called inside
/// a tokio runtime.
pub fn watch(
    clock: Arc<dyn Clock>,
    source: Arc<dyn InterfaceSource>,
    limits: &IoLimits,
) -> mpsc::UnboundedReceiver<NetChange> {
    let (tx, rx) = mpsc::unbounded_channel();
    let poll = ms(limits.iface_poll_ms());
    let mut wake = WakeDetector::new(clock.mono(), limits);
    tokio::spawn(async move {
        let mut seen = source.snapshot();
        loop {
            tokio::time::sleep(poll).await;
            if tx.is_closed() {
                return;
            }
            if let Some(slept_ms) = wake.poll(clock.mono()) {
                let _ = tx.send(NetChange::Wake { slept_ms });
            }
            let now = source.snapshot();
            if now != seen {
                seen = now;
                let _ = tx.send(NetChange::Interfaces);
            }
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;
    use crate::clock::ManualClock;

    struct Listed(Mutex<Vec<String>>);

    impl InterfaceSource for Listed {
        fn snapshot(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    /// Nothing within three polls.
    async fn quiet(changes: &mut mpsc::UnboundedReceiver<NetChange>) -> bool {
        let three = Duration::from_millis(IoLimits::DEFAULT.iface_poll_ms() * 3);
        tokio::time::timeout(three, changes.recv()).await.is_err()
    }

    #[tokio::test(start_paused = true)]
    async fn a_monotonic_jump_is_a_wake_and_a_new_interface_list_a_change() {
        let clock = Arc::new(ManualClock::new());
        clock.freeze_mono();
        let wifi = "wlan0 192.168.1.20 up".to_owned();
        let source = Arc::new(Listed(Mutex::new(vec![wifi.clone()])));
        let mut changes = watch(clock.clone(), source.clone(), &IoLimits::DEFAULT);
        assert!(quiet(&mut changes).await);

        // Up to the jump past one interval is no sleep.
        let interval = IoLimits::DEFAULT.iface_poll_ms();
        let jump = IoLimits::DEFAULT.wake_jump_ms();
        clock.advance_mono(interval + jump);
        assert!(quiet(&mut changes).await);
        clock.advance_mono(interval + jump + 1);
        assert_eq!(
            changes.recv().await,
            Some(NetChange::Wake { slept_ms: jump + 1 })
        );
        assert!(quiet(&mut changes).await);

        // Another address, then the old one back: two changes.
        *source.0.lock().unwrap() = vec!["wlan0 10.0.0.7 up".to_owned()];
        assert_eq!(changes.recv().await, Some(NetChange::Interfaces));
        assert!(quiet(&mut changes).await);
        *source.0.lock().unwrap() = vec![wifi];
        assert_eq!(changes.recv().await, Some(NetChange::Interfaces));
        assert!(quiet(&mut changes).await);
    }

    #[test]
    fn the_system_list_leaves_out_loopback_and_is_stable() {
        let first = SystemInterfaces.snapshot();
        assert!(
            first
                .iter()
                .all(|i| !i.contains(" 127.0.0.1 ") && !i.contains(" ::1 ")),
            "{first:?}"
        );
        assert_eq!(SystemInterfaces.snapshot(), first);
    }

    #[test]
    fn the_jump_is_measured_from_the_last_poll() {
        let limits = IoLimits::DEFAULT;
        let mut wake = WakeDetector::new(Millis(1_000), &limits);
        let late = limits.iface_poll_ms() + limits.wake_jump_ms();
        // Slow polls that each stay within the jump add up to no sleep.
        assert_eq!(wake.poll(Millis(1_000 + late)), None);
        assert_eq!(wake.poll(Millis(1_000 + 2 * late)), None);
        assert_eq!(
            wake.poll(Millis(1_000 + 3 * late + 60_000)),
            Some(limits.wake_jump_ms() + 60_000)
        );
        // A clock that did not move is no sleep either.
        assert_eq!(wake.poll(Millis(1_000 + 3 * late + 60_000)), None);
    }
}
