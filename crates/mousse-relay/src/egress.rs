//! The shared egress ceiling (`RELAY_EGRESS_BPS`) with interactive
//! circuits first (spec `relay.md` 13): a token bucket holding one second
//! of traffic. A bulk write waits while any interactive write is waiting.

use std::sync::Mutex;
use std::time::Duration;

use mousse_net_core::relay::Class;
use tokio::sync::Notify;
use tokio::time::Instant;

/// The egress scheduler.
#[derive(Debug)]
pub struct Egress {
    rate: f64,
    state: Mutex<State>,
    turn: Notify,
}

#[derive(Debug)]
struct State {
    tokens: f64,
    last: Instant,
    interactive_waiting: usize,
}

impl Egress {
    /// A scheduler for `bytes_per_sec`, starting full.
    pub fn new(bytes_per_sec: u64) -> Self {
        let rate = bytes_per_sec as f64;
        Self {
            rate,
            state: Mutex::new(State {
                tokens: rate,
                last: Instant::now(),
                interactive_waiting: 0,
            }),
            turn: Notify::new(),
        }
    }

    /// Wait until `bytes` may be written for a circuit of `class`.
    pub async fn take(&self, bytes: usize, class: Class) {
        let interactive = class == Class::Interactive;
        if interactive {
            self.state.lock().expect("egress").interactive_waiting += 1;
        }
        loop {
            let wait = {
                let mut s = self.state.lock().expect("egress");
                let now = Instant::now();
                let elapsed = now.duration_since(s.last).as_secs_f64();
                s.tokens = (s.tokens + elapsed * self.rate).min(self.rate);
                s.last = now;
                // Must-fail control (phase4.relay-leases `fifo-egress`):
                // bulk does not wait for interactive writes.
                if !interactive
                    && s.interactive_waiting > 0
                    && !cfg!(mousse_control = "fifo-egress")
                {
                    None
                } else if s.tokens > 0.0 {
                    // A message may take the bucket below zero; the next
                    // writer waits for it to refill.
                    s.tokens -= bytes as f64;
                    if interactive {
                        s.interactive_waiting -= 1;
                    }
                    break;
                } else {
                    Some(Duration::from_secs_f64(-s.tokens / self.rate + 0.000_1))
                }
            };
            match wait {
                Some(d) => tokio::time::sleep(d).await,
                None => {
                    let notified = self.turn.notified();
                    tokio::select! {
                        _ = notified => {}
                        _ = tokio::time::sleep(Duration::from_millis(5)) => {}
                    }
                }
            }
        }
        if interactive {
            self.turn.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test(start_paused = true)]
    async fn the_ceiling_holds_and_interactive_goes_first() {
        let egress = Arc::new(Egress::new(100_000));
        let start = Instant::now();
        for _ in 0..3 {
            egress.take(100_000, Class::Bulk).await;
        }
        // A write may take the bucket below zero; the next one waits until
        // it is back above. A full bucket, then 100 000 bytes a second.
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(990), "{took:?}");
        assert!(took < Duration::from_millis(1_100), "{took:?}");

        // The bucket is empty: a bulk and an interactive write both wait,
        // and the interactive one goes first.
        let order = Arc::new(Mutex::new(Vec::new()));
        let bulk = {
            let (e, o) = (egress.clone(), order.clone());
            tokio::spawn(async move {
                e.take(10, Class::Bulk).await;
                o.lock().unwrap().push("bulk");
            })
        };
        tokio::task::yield_now().await;
        let inter = {
            let (e, o) = (egress.clone(), order.clone());
            tokio::spawn(async move {
                e.take(10, Class::Interactive).await;
                o.lock().unwrap().push("interactive");
            })
        };
        bulk.await.unwrap();
        inter.await.unwrap();
        assert_eq!(*order.lock().unwrap(), ["interactive", "bulk"]);
    }
}
