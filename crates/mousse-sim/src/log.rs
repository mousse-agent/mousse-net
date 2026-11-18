//! The event log: one line per notable event, hashed as it is written.
//!
//! The log never contains secrets: pairing codes, ticket secrets and exporter
//! values are described ("typed the right code"), never printed.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

pub(crate) struct EventLog {
    keep: bool,
    lines: Vec<String>,
    hasher: Sha256,
    count: u64,
    buf: String,
}

impl EventLog {
    pub(crate) fn new(keep: bool) -> Self {
        Self {
            keep,
            lines: Vec::new(),
            hasher: Sha256::new(),
            count: 0,
            buf: String::new(),
        }
    }

    pub(crate) fn push(&mut self, now_ms: u64, actor: &str, args: std::fmt::Arguments<'_>) {
        self.buf.clear();
        let _ = write!(
            self.buf,
            "{:>6}.{:03} {:<8} {}",
            now_ms / 1000,
            now_ms % 1000,
            actor,
            args
        );
        self.hasher.update(self.buf.as_bytes());
        self.hasher.update(b"\n");
        self.count += 1;
        if self.keep {
            self.lines.push(self.buf.clone());
        }
    }

    pub(crate) fn finish(self) -> ([u8; 32], u64, Vec<String>) {
        (self.hasher.finalize().into(), self.count, self.lines)
    }
}
