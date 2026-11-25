//! What the helper writes to the app, in order (Phase 1a §2.2): control
//! first (JSON, then CREDIT), then interactive DATA, then bulk DATA,
//! streams taking turns within a class. Each stream's DATA stays in its own
//! queue, so a FIN (a flag on a DATA frame) follows every byte queued
//! before it.
//!
//! `conn.*` events are coalesced per connection: a newer one replaces one
//! still waiting. CREDIT is coalesced per stream.

use std::collections::{BTreeMap, HashMap, VecDeque};

use mousse_net_core::mux::PriorityClass;

use super::frame;

/// What a written frame was, for the accounting after it is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Meta {
    /// JSON.
    Json,
    /// CREDIT.
    Credit,
    /// DATA of `len` bytes, maybe with FIN.
    Data { handle: u32, len: u64, fin: bool },
}

struct Item {
    bytes: Vec<u8>,
    meta: Meta,
    /// The connection a `conn.*` event is about (coalesced per connection).
    conn_event: Option<u64>,
    /// The stream a `stream.incoming` event announces: dropped with the
    /// stream if it is reset before the event is written.
    announces: Option<u32>,
}

/// The queues.
#[derive(Default)]
pub struct Out {
    control: VecDeque<Item>,
    control_bytes: usize,
    credits: BTreeMap<u32, u64>,
    data: HashMap<u32, VecDeque<Item>>,
    /// Streams with DATA waiting, per class, in turn order.
    turns: [VecDeque<u32>; 2],
    /// The `fifo-writer` control: one queue for everything.
    #[cfg(mousse_control = "fifo-writer")]
    fifo: VecDeque<Item>,
}

#[cfg_attr(mousse_control = "fifo-writer", allow(dead_code))]
fn slot(class: PriorityClass) -> usize {
    match class {
        PriorityClass::Interactive => 0,
        PriorityClass::Bulk => 1,
    }
}

impl Out {
    /// JSON and CREDIT bytes waiting.
    pub fn control_bytes(&self) -> usize {
        self.control_bytes
    }

    /// Queue a JSON reply or event.
    pub fn json(&mut self, value: &serde_json::Value) {
        self.push_control(Item {
            bytes: frame::json(value),
            meta: Meta::Json,
            conn_event: None,
            announces: None,
        });
    }

    /// Queue the event that announces stream `handle` to the app
    /// (`stream.incoming`). [`Out::unannounce`] takes it back while it
    /// waits.
    pub fn announce(&mut self, handle: u32, value: &serde_json::Value) {
        self.push_control(Item {
            bytes: frame::json(value),
            meta: Meta::Json,
            conn_event: None,
            announces: Some(handle),
        });
    }

    /// Drop the announcement of `handle` if it was not written yet: `true`
    /// if it was dropped (the app never hears of the stream).
    pub fn unannounce(&mut self, handle: u32) -> bool {
        let announced = |i: &Item| i.announces == Some(handle);
        let mut dropped = 0;
        let mut bytes = 0;
        self.control.retain(|i| {
            let hit = announced(i);
            if hit {
                dropped += 1;
                bytes += i.bytes.len();
            }
            !hit
        });
        #[cfg(mousse_control = "fifo-writer")]
        self.fifo.retain(|i| {
            let hit = announced(i);
            if hit {
                dropped += 1;
                bytes += i.bytes.len();
            }
            !hit
        });
        self.control_bytes = self.control_bytes.saturating_sub(bytes);
        dropped > 0
    }

    /// Queue a `conn.*` event; it replaces one about the same connection
    /// that is still waiting.
    pub fn conn_event(&mut self, conn: u64, value: &serde_json::Value) {
        let item = Item {
            bytes: frame::json(value),
            meta: Meta::Json,
            conn_event: Some(conn),
            announces: None,
        };
        #[cfg(mousse_control = "fifo-writer")]
        {
            self.control_bytes += item.bytes.len();
            self.fifo.push_back(item);
        }
        #[cfg(not(mousse_control = "fifo-writer"))]
        {
            if let Some(old) = self.control.iter_mut().find(|i| i.conn_event == Some(conn)) {
                self.control_bytes = self.control_bytes - old.bytes.len() + item.bytes.len();
                *old = item;
                return;
            }
            self.push_control(item);
        }
    }

    fn push_control(&mut self, item: Item) {
        self.control_bytes += item.bytes.len();
        #[cfg(mousse_control = "fifo-writer")]
        self.fifo.push_back(item);
        #[cfg(not(mousse_control = "fifo-writer"))]
        self.control.push_back(item);
    }

    /// More credit for the app on `handle`.
    pub fn credit(&mut self, handle: u32, bytes: u64) {
        if bytes == 0 {
            return;
        }
        #[cfg(mousse_control = "fifo-writer")]
        {
            let mut left = bytes;
            while left > 0 {
                let n = left.min(u64::from(u32::MAX));
                left -= n;
                self.push_control(Item {
                    bytes: frame::credit(handle, n as u32),
                    meta: Meta::Credit,
                    conn_event: None,
                    announces: None,
                });
            }
        }
        #[cfg(not(mousse_control = "fifo-writer"))]
        {
            *self.credits.entry(handle).or_default() += bytes;
        }
    }

    /// Credit for `handle` not yet written, taken back.
    pub fn take_credit(&mut self, handle: u32) -> u64 {
        self.credits.remove(&handle).unwrap_or(0)
    }

    /// Queue DATA (and FIN) on `handle`, behind the stream's earlier DATA.
    pub fn data(&mut self, handle: u32, class: PriorityClass, fin: bool, bytes: &[u8]) {
        let item = Item {
            bytes: frame::data(handle, fin, bytes),
            meta: Meta::Data {
                handle,
                len: bytes.len() as u64,
                fin,
            },
            conn_event: None,
            announces: None,
        };
        #[cfg(mousse_control = "fifo-writer")]
        {
            let _ = class;
            self.fifo.push_back(item);
        }
        #[cfg(not(mousse_control = "fifo-writer"))]
        {
            let queue = self.data.entry(handle).or_default();
            if queue.is_empty() {
                self.turns[slot(class)].push_back(handle);
            }
            queue.push_back(item);
        }
    }

    /// The `fin-overtakes` control: FIN as a control frame, ahead of the
    /// stream's queued DATA.
    #[cfg(mousse_control = "fin-overtakes")]
    pub fn fin_as_control(&mut self, handle: u32) {
        self.push_control(Item {
            bytes: frame::data(handle, true, &[]),
            meta: Meta::Data {
                handle,
                len: 0,
                fin: true,
            },
            conn_event: None,
            announces: None,
        });
    }

    /// Drop everything waiting for `handle` (it was reset). Returns the
    /// DATA bytes dropped.
    pub fn discard(&mut self, handle: u32) -> u64 {
        self.credits.remove(&handle);
        let mut dropped = 0;
        if let Some(queue) = self.data.remove(&handle) {
            dropped += queue.iter().map(len_of).sum::<u64>();
        }
        let before: u64 = self
            .control
            .iter()
            .filter(|i| of(i, handle))
            .map(len_of)
            .sum();
        self.control.retain(|i| !of(i, handle));
        dropped += before;
        #[cfg(mousse_control = "fifo-writer")]
        {
            dropped += self
                .fifo
                .iter()
                .filter(|i| of(i, handle))
                .map(len_of)
                .sum::<u64>();
            self.fifo.retain(|i| !of(i, handle));
        }
        dropped
    }

    /// The next frame to write.
    pub fn next(&mut self) -> Option<(Vec<u8>, Meta)> {
        #[cfg(mousse_control = "fifo-writer")]
        {
            let item = self.fifo.pop_front()?;
            if !matches!(item.meta, Meta::Data { .. }) {
                self.control_bytes = self.control_bytes.saturating_sub(item.bytes.len());
            }
            Some((item.bytes, item.meta))
        }
        #[cfg(not(mousse_control = "fifo-writer"))]
        {
            if let Some(item) = self.control.pop_front() {
                self.control_bytes -= item.bytes.len();
                return Some((item.bytes, item.meta));
            }
            if let Some((&handle, &bytes)) = self.credits.iter().next() {
                let n = bytes.min(u64::from(u32::MAX));
                if bytes > n {
                    self.credits.insert(handle, bytes - n);
                } else {
                    self.credits.remove(&handle);
                }
                return Some((frame::credit(handle, n as u32), Meta::Credit));
            }
            for turn in 0..2 {
                while let Some(handle) = self.turns[turn].pop_front() {
                    let Some(queue) = self.data.get_mut(&handle) else {
                        continue;
                    };
                    let Some(item) = queue.pop_front() else {
                        self.data.remove(&handle);
                        continue;
                    };
                    if queue.is_empty() {
                        self.data.remove(&handle);
                    } else {
                        self.turns[turn].push_back(handle);
                    }
                    return Some((item.bytes, item.meta));
                }
            }
            None
        }
    }
}

fn of(item: &Item, handle: u32) -> bool {
    matches!(item.meta, Meta::Data { handle: h, .. } if h == handle)
}

fn len_of(item: &Item) -> u64 {
    match item.meta {
        Meta::Data { len, .. } => len,
        _ => 0,
    }
}

#[cfg(all(test, not(mousse_control = "fifo-writer")))]
mod tests {
    use super::*;
    use serde_json::json;

    fn kinds(out: &mut Out) -> Vec<String> {
        let mut seen = Vec::new();
        while let Some((_, meta)) = out.next() {
            seen.push(match meta {
                Meta::Json => "json".to_owned(),
                Meta::Credit => "credit".to_owned(),
                Meta::Data { handle, fin, .. } => format!("{handle}{}", if fin { "!" } else { "" }),
            });
        }
        seen
    }

    #[test]
    fn control_then_interactive_then_bulk_streams_taking_turns() {
        let mut out = Out::default();
        out.data(1, PriorityClass::Bulk, false, b"a");
        out.data(1, PriorityClass::Bulk, true, b"b");
        out.data(2, PriorityClass::Bulk, false, b"c");
        out.data(3, PriorityClass::Interactive, false, b"d");
        out.credit(5, 10);
        out.json(&json!({"ev": "x"}));
        assert_eq!(kinds(&mut out), ["json", "credit", "3", "1", "2", "1!"]);
    }

    #[test]
    fn conn_events_coalesce_and_reset_streams_lose_their_queue() {
        let mut out = Out::default();
        out.conn_event(1, &json!({"ev": "conn.up", "conn": 1}));
        out.conn_event(2, &json!({"ev": "conn.up", "conn": 2}));
        out.conn_event(1, &json!({"ev": "conn.down", "conn": 1}));
        let (first, _) = out.next().unwrap();
        assert!(String::from_utf8_lossy(&first).contains("conn.down"));
        out.next().unwrap();
        assert_eq!(out.control_bytes(), 0);
        out.data(4, PriorityClass::Bulk, false, b"abc");
        out.credit(4, 9);
        assert_eq!(out.discard(4), 3);
        assert!(out.next().is_none());
    }

    /// A stream's announcement waiting to be written is taken back with
    /// the stream; other events stay.
    #[test]
    fn a_waiting_announcement_is_taken_back() {
        let mut out = Out::default();
        out.announce(7, &json!({"ev": "stream.incoming", "handle": 7}));
        out.announce(8, &json!({"ev": "stream.incoming", "handle": 8}));
        out.json(&json!({"ev": "x"}));
        assert!(out.unannounce(7));
        assert!(!out.unannounce(7));
        let mut left = Vec::new();
        while let Some((bytes, _)) = out.next() {
            left.push(String::from_utf8_lossy(&bytes).into_owned());
        }
        assert_eq!(left.len(), 2, "{left:?}");
        assert!(left[0].contains("\"handle\":8"), "{left:?}");
        assert_eq!(out.control_bytes(), 0);
        // Once written, it cannot be taken back.
        out.announce(9, &json!({"ev": "stream.incoming", "handle": 9}));
        out.next().unwrap();
        assert!(!out.unannounce(9));
    }
}
