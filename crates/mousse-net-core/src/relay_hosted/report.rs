//! Snapshot reports (`docs/phase34-design.md` §A.9 duty 4, §A.12).
//!
//! A snapshot is the counters of every lease the boot still reports, all
//! taken at one instant. One is taken every `REPORT_MS`, and after a final
//! as soon as `REPORT_MIN_MS` has passed since the last one, so finals that
//! come close together share a snapshot and every final is in a snapshot
//! taken within `REPORT_MIN_MS` of it.
//!
//! Parts are sent one at a time, each until Plus has stored it. A snapshot
//! gets its report sequences only when its first part is about to be sent,
//! so a snapshot taken while another is still being delivered can be
//! replaced by a newer one without leaving a gap in the sequences.

use std::collections::VecDeque;

use crate::time::Millis;

use super::records::{BootId, BootState, RelayId, ReportEntry, ReportPart, REPORT_ENTRIES_MAX};
use super::HostedLimits;

/// A snapshot that has no sequences yet.
#[derive(Clone, Debug)]
struct Taken {
    entries: Vec<ReportEntry>,
    state: BootState,
}

#[derive(Clone, Debug)]
pub(super) struct ReportQueue {
    /// The sequence the next part gets; from 1.
    next_sequence: u64,
    /// Parts of the snapshot being delivered, first unstored part first.
    in_flight: VecDeque<ReportPart>,
    /// The newest snapshot taken while another was being delivered.
    waiting: Option<Taken>,
    /// When the last snapshot was taken.
    last_taken: Option<Millis>,
    /// The earliest final not yet in a taken snapshot.
    final_since: Option<Millis>,
    /// Plus has acknowledged this boot; reports may start.
    booted: bool,
    /// The stopping snapshot has been taken; no other follows it.
    stopping: bool,
    /// The stopping snapshot has been stored in full.
    stop_reported: bool,
}

impl ReportQueue {
    pub(super) fn new() -> Self {
        Self {
            next_sequence: 1,
            in_flight: VecDeque::new(),
            waiting: None,
            last_taken: None,
            final_since: None,
            booted: false,
            stopping: false,
            stop_reported: false,
        }
    }

    pub(super) fn booted(&mut self) {
        self.booted = true;
    }

    pub(super) fn note_final(&mut self, now: Millis) {
        self.final_since.get_or_insert(now);
    }

    /// When the next snapshot should be taken.
    pub(super) fn take_at(&self, limits: &HostedLimits, now: Millis) -> Option<Millis> {
        if !self.booted || self.stopping {
            return None;
        }
        let Some(last) = self.last_taken else {
            return Some(now);
        };
        let periodic = last.plus(limits.report_ms());
        Some(match self.final_since {
            Some(f) => periodic.min(f.max(last.plus(limits.report_min_ms()))),
            None => periodic,
        })
    }

    pub(super) fn take_due(&self, limits: &HostedLimits, now: Millis) -> bool {
        self.take_at(limits, now).is_some_and(|t| t <= now)
    }

    /// Take a snapshot of `entries` (already in lease-id order).
    pub(super) fn take(&mut self, entries: Vec<ReportEntry>, state: BootState, now: Millis) {
        if self.stopping {
            return;
        }
        if state == BootState::Stopping {
            self.stopping = true;
        }
        self.last_taken = Some(now);
        self.final_since = None;
        self.waiting = Some(Taken { entries, state });
    }

    /// The part to send now. A waiting snapshot gets its sequences once the
    /// one being delivered is stored.
    pub(super) fn next_part(
        &mut self,
        relay_id: RelayId,
        boot_id: BootId,
        sent_at: u64,
    ) -> Option<ReportPart> {
        if !self.booted {
            return None;
        }
        if self.in_flight.is_empty() {
            if let Some(t) = self.waiting.take() {
                let chunks: Vec<Vec<ReportEntry>> = if t.entries.is_empty() {
                    vec![Vec::new()]
                } else {
                    t.entries
                        .chunks(REPORT_ENTRIES_MAX)
                        .map(<[ReportEntry]>::to_vec)
                        .collect()
                };
                let snapshot = self.next_sequence;
                let part_count = chunks.len() as u64;
                for (i, entries) in chunks.into_iter().enumerate() {
                    self.in_flight.push_back(ReportPart {
                        relay_id,
                        boot_id,
                        sequence: snapshot + i as u64,
                        sent_at,
                        boot_state: t.state,
                        snapshot,
                        part_count,
                        entries,
                    });
                }
                self.next_sequence = snapshot + part_count;
            }
        }
        self.in_flight.front().cloned()
    }

    /// Plus answered part `sequence`, saying it has stored every part up to
    /// `highest`.
    pub(super) fn answered(&mut self, sequence: u64, highest: u64) {
        if highest < sequence {
            return;
        }
        while self
            .in_flight
            .front()
            .is_some_and(|p| p.sequence <= highest)
        {
            let p = self.in_flight.pop_front();
            if let Some(p) = p {
                if p.boot_state == BootState::Stopping && self.in_flight.is_empty() {
                    self.stop_reported = true;
                }
            }
        }
    }

    /// When there is next something to do: a part to send now, or a
    /// snapshot to take.
    pub(super) fn due(&self, limits: &HostedLimits, now: Millis) -> Option<Millis> {
        if !self.booted {
            return None;
        }
        if !self.in_flight.is_empty() || self.waiting.is_some() {
            return Some(now);
        }
        self.take_at(limits, now)
    }

    pub(super) fn stop_reported(&self) -> bool {
        self.stop_reported
    }
}
