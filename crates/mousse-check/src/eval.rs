//! Turning manifests, local run records and device evidence into one status
//! per check × target cell, and a phase verdict.
//!
//! Rules, in order:
//! 1. A deferred check is DEFERRED only if the phase's `[defer]` table lists
//!    it; otherwise FAIL.
//! 2. A manual check is ATTESTED if someone attested it for this build;
//!    otherwise INCOMPLETE. It never becomes PASS.
//! 3. An automated check with no control, or with a control marked missing,
//!    is FAIL.
//! 4. A placeholder is INCOMPLETE.
//! 5. Evidence (a local run record, else signed device results) must be for
//!    the build under test; anything else is INCOMPLETE. Any FAIL, any
//!    control that did not fail, or a control that printed no FAIL line is
//!    FAIL. Missing parts are INCOMPLETE.
//! 6. On a dirty tree, PASS becomes INCOMPLETE unless `--allow-dirty`.
//! 7. An attestation on an automated check shows as ATTESTED but blocks the
//!    verdict like INCOMPLETE.
//!
//! The phase passes only if every cell is PASS, an allowed DEFERRED, or an
//! ATTESTED manual step, and no result file shows signs of tampering.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;

use crate::build::{check_build, BuildState, Commits};
use crate::evidence::{Attestation, Evidence, ResultPayload};
use crate::manifest::{Check, Judge, Manifest};
use crate::runner::{RunRecord, RunVerdict};

/// One cell's status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Pass,
    Fail,
    Incomplete,
    Deferred,
    Attested,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Incomplete => "INCOMPLETE",
            Status::Deferred => "DEFERRED",
            Status::Attested => "ATTESTED",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Cell {
    pub check: String,
    pub target: String,
    pub status: Status,
    pub details: String,
    pub title: String,
    pub plan: String,
    pub manual: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RejectedFile {
    pub path: String,
    pub reason: String,
    pub tampering: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Verdict {
    pub passed: bool,
    pub summary: String,
    pub blocking: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub phase: String,
    pub title: String,
    pub build: String,
    pub dirty: bool,
    pub dirty_paths: Vec<String>,
    pub allow_dirty: bool,
    pub cells: Vec<Cell>,
    pub rejected: Vec<RejectedFile>,
    pub counts: BTreeMap<Status, usize>,
    pub verdict: Verdict,
}

/// Everything the evaluation reads.
pub struct Inputs<'a> {
    pub manifest: &'a Manifest,
    pub build: &'a BuildState,
    pub commits: &'a dyn Commits,
    pub allow_dirty: bool,
    pub records: &'a [RunRecord],
    pub evidence: &'a Evidence,
    pub rejected_paths: &'a [(PathBuf, String, bool)],
    /// Notes about old unsigned results, keyed by (check, target).
    pub legacy: &'a BTreeMap<(String, String), String>,
}

struct Outcome {
    status: Status,
    details: String,
}

fn out(status: Status, details: impl Into<String>) -> Outcome {
    Outcome {
        status,
        details: details.into(),
    }
}

pub fn evaluate(inp: &Inputs<'_>) -> Report {
    let m = inp.manifest;
    let mut cells = Vec::new();
    for check in &m.checks {
        for target in &check.targets {
            let o = eval_cell(inp, check, target);
            cells.push(Cell {
                check: check.id.clone(),
                target: target.clone(),
                status: o.status,
                details: o.details,
                title: check.title.clone(),
                plan: check.plan.clone(),
                manual: check.manual,
            });
        }
    }
    let rejected: Vec<RejectedFile> = inp
        .rejected_paths
        .iter()
        .map(|(p, r, t)| RejectedFile {
            path: p.display().to_string(),
            reason: r.clone(),
            tampering: *t,
        })
        .collect();
    let mut counts = BTreeMap::new();
    for c in &cells {
        *counts.entry(c.status).or_insert(0) += 1;
    }
    let mut blocking: Vec<String> = cells
        .iter()
        .filter(|c| !cell_ok(c))
        .map(|c| {
            let why = if c.status == Status::Attested {
                "ATTESTED, but needs an automated result".to_string()
            } else {
                c.status.label().to_string()
            };
            format!("{} @ {}: {why}", c.check, c.target)
        })
        .collect();
    for r in rejected.iter().filter(|r| r.tampering) {
        blocking.push(format!("result file {}: {}", r.path, r.reason));
    }
    let passed = blocking.is_empty() && !cells.is_empty();
    let summary = if passed {
        let mut s = format!("{} PASS", m.phase);
        let attested = counts.get(&Status::Attested).copied().unwrap_or(0);
        let deferred = counts.get(&Status::Deferred).copied().unwrap_or(0);
        if deferred > 0 {
            s.push_str(&format!(", {deferred} allowed DEFERRED"));
        }
        if attested > 0 {
            s.push_str(&format!(", {attested} manual steps ATTESTED"));
        }
        if inp.build.dirty {
            s.push_str(" (dirty tree allowed)");
        }
        s
    } else {
        format!("{} NOT PASSED: {} blocking", m.phase, blocking.len())
    };
    Report {
        phase: m.phase.clone(),
        title: m.title.clone(),
        build: inp.build.short(),
        dirty: inp.build.dirty,
        dirty_paths: inp.build.dirty_paths.clone(),
        allow_dirty: inp.allow_dirty,
        cells,
        rejected,
        counts,
        verdict: Verdict {
            passed,
            summary,
            blocking,
        },
    }
}

fn cell_ok(c: &Cell) -> bool {
    match c.status {
        Status::Pass | Status::Deferred => true,
        Status::Attested => c.manual,
        Status::Fail | Status::Incomplete => false,
    }
}

fn eval_cell(inp: &Inputs<'_>, check: &Check, target: &str) -> Outcome {
    if check.deferred {
        return match inp.manifest.defer.get(&check.id) {
            Some(reason) => out(Status::Deferred, reason.clone()),
            None => out(
                Status::Fail,
                "marked deferred, but this phase's [defer] list does not allow deferring it",
            ),
        };
    }
    if check.manual {
        return eval_manual(inp, check, target);
    }
    let mut o = eval_automated(inp, check, target);
    if o.status == Status::Pass && inp.build.dirty {
        if inp.allow_dirty {
            o.details.push_str(" (dirty tree allowed)");
        } else {
            o = out(
                Status::Incomplete,
                format!(
                    "would pass, but the tree is dirty ({}); commit, or pass --allow-dirty",
                    inp.build.dirty_paths.join(", ")
                ),
            );
        }
    }
    if o.status == Status::Incomplete {
        if let Some(a) = latest_attestation(inp, check, target) {
            o = out(
                Status::Attested,
                format!(
                    "attested by {} at {}: {} (does not count: this check needs an automated result; {})",
                    a.by, a.time, a.note, o.details
                ),
            );
        }
    }
    o
}

fn latest_attestation<'a>(
    inp: &'a Inputs<'_>,
    check: &Check,
    target: &str,
) -> Option<&'a Attestation> {
    inp.evidence
        .attestations
        .iter()
        .filter(|a| a.check == check.id && a.target == target)
        .filter(|a| check_build(inp.commits, inp.build, &a.build, None, inp.allow_dirty).is_ok())
        .max_by(|a, b| a.time.cmp(&b.time))
}

fn eval_manual(inp: &Inputs<'_>, check: &Check, target: &str) -> Outcome {
    if let Some(a) = latest_attestation(inp, check, target) {
        return out(
            Status::Attested,
            format!("by {} at {}: {}", a.by, a.time, a.note),
        );
    }
    let stale = inp
        .evidence
        .attestations
        .iter()
        .filter(|a| a.check == check.id && a.target == target)
        .filter_map(|a| check_build(inp.commits, inp.build, &a.build, None, inp.allow_dirty).err())
        .next();
    let steps = check.steps.clone().unwrap_or_default();
    match stale {
        Some(why) => out(
            Status::Incomplete,
            format!("attested for another build ({why}); redo: {steps}"),
        ),
        None => out(
            Status::Incomplete,
            format!("manual step not attested yet: {steps}"),
        ),
    }
}

fn eval_automated(inp: &Inputs<'_>, check: &Check, target: &str) -> Outcome {
    if check.control.is_empty() {
        return out(Status::Fail, "no must-fail control: this check cannot pass");
    }
    let missing: Vec<String> = check
        .control
        .iter()
        .filter_map(|k| k.missing.as_ref().map(|why| format!("{}: {why}", k.name)))
        .collect();
    if !missing.is_empty() {
        return out(
            Status::Fail,
            format!("control missing: {}", missing.join("; ")),
        );
    }
    if let Some(why) = &check.placeholder {
        return out(Status::Incomplete, format!("not wired yet: {why}"));
    }
    let local = check.local_for(target);
    if let Some(why) = local.and_then(|l| l.placeholder.as_ref()) {
        return out(
            Status::Incomplete,
            format!("not wired yet on {target}: {why}"),
        );
    }
    let has_records = inp
        .records
        .iter()
        .any(|r| r.check == check.id && r.target == target);
    let has_results = inp
        .evidence
        .results
        .iter()
        .any(|r| r.check == check.id && r.target == target);
    if let (Some(l), false, false) = (local, has_records, has_results) {
        return out(
            Status::Incomplete,
            format!(
                "not run for this build: `mousse-check run {}` on {} (another machine adds --sign-with <key>){}",
                check.id,
                l.host,
                legacy_note(inp, check, target)
            ),
        );
    }
    if has_records {
        let o = eval_local(inp, check, target);
        if o.status != Status::Incomplete || !has_results {
            return o;
        }
    }
    eval_device(inp, check, target)
}

fn record<'a>(
    inp: &'a Inputs<'_>,
    check: &Check,
    target: &str,
    part: &str,
) -> Option<&'a RunRecord> {
    inp.records
        .iter()
        .filter(|r| r.check == check.id && r.target == target && r.part == part)
        .max_by(|a, b| a.time.cmp(&b.time))
}

fn eval_local(inp: &Inputs<'_>, check: &Check, target: &str) -> Outcome {
    let mut fails = Vec::new();
    let mut gaps = Vec::new();
    let usable =
        |r: &RunRecord| check_build(inp.commits, inp.build, &r.build, None, inp.allow_dirty);
    let normal = record(inp, check, target, "normal");
    let mut normal_total = None;
    let mut normal_summary = String::new();
    match normal {
        None => gaps.push("not run for this build".to_string()),
        Some(r) => match usable(r) {
            Err(why) => gaps.push(format!("last run does not count: {why}")),
            Ok(_) => match r.verdict {
                RunVerdict::Pass => {
                    normal_total = r.tests_total;
                    normal_summary = r.summary.clone();
                }
                _ => fails.push(format!("run failed: {}", r.summary)),
            },
        },
    }
    for k in &check.control {
        match record(inp, check, target, &k.name) {
            None => gaps.push(format!("control {} not run", k.name)),
            Some(r) => match usable(r) {
                Err(why) => gaps.push(format!("control {} does not count: {why}", k.name)),
                Ok(_) => match r.verdict {
                    RunVerdict::FailedAsRequired => {
                        if check.judge == Judge::CargoTest {
                            if let (Some(a), Some(b)) = (normal_total, r.tests_total) {
                                if a != b {
                                    fails.push(format!(
                                        "control {} ran {b} tests, the check ran {a}; a control must run the same tests (use --no-fail-fast)",
                                        k.name
                                    ));
                                }
                            }
                        }
                    }
                    RunVerdict::DidNotFail => fails.push(format!(
                        "control did not fail: {} ({}): {}",
                        k.name, k.breaks, r.summary
                    )),
                    _ => fails.push(format!(
                        "control {} did not print FAIL: {}",
                        k.name, r.summary
                    )),
                },
            },
        }
    }
    if !fails.is_empty() {
        return out(Status::Fail, fails.join("; "));
    }
    if !gaps.is_empty() {
        return out(Status::Incomplete, gaps.join("; "));
    }
    out(
        Status::Pass,
        format!(
            "{normal_summary}; {} control(s) failed as required",
            check.control.len()
        ),
    )
}

fn legacy_note(inp: &Inputs<'_>, check: &Check, target: &str) -> String {
    inp.legacy
        .get(&(check.id.clone(), target.to_string()))
        .map(|n| format!("; {n}"))
        .unwrap_or_default()
}

fn eval_device(inp: &Inputs<'_>, check: &Check, target: &str) -> Outcome {
    let profile = check.profile.as_deref().or(inp.manifest.profile.as_deref());
    let all: Vec<&ResultPayload> = inp
        .evidence
        .results
        .iter()
        .filter(|r| r.check == check.id && r.target == target)
        .collect();
    let legacy = legacy_note(inp, check, target);
    let hint = check
        .device_steps
        .as_ref()
        .map(|s| format!(" ({s})"))
        .unwrap_or_default();
    if all.is_empty() {
        return out(
            Status::Incomplete,
            format!("no signed result yet{hint}{legacy}"),
        );
    }
    let mut stale = Vec::new();
    let mut ok = Vec::new();
    for r in all {
        match check_build(inp.commits, inp.build, &r.build, profile, inp.allow_dirty) {
            Ok(_) => ok.push(r),
            Err(why) => stale.push(why),
        }
    }
    if ok.is_empty() {
        return out(
            Status::Incomplete,
            format!(
                "{} signed result(s), none for this build: {}{legacy}",
                stale.len(),
                stale.first().cloned().unwrap_or_default()
            ),
        );
    }
    let mut fails = Vec::new();
    let mut gaps = Vec::new();
    let normal: Vec<&&ResultPayload> = ok.iter().filter(|r| r.control.is_none()).collect();
    for r in normal.iter().filter(|r| r.outcome == "FAIL") {
        fails.push(format!(
            "{} reported FAIL{} at {}: {}",
            r.device,
            r.case
                .as_ref()
                .map(|c| format!(" for {c}"))
                .unwrap_or_default(),
            r.time,
            r.details
        ));
    }
    let expected = check.cases(target);
    let missing: Vec<String> = expected
        .iter()
        .filter(|case| {
            !normal
                .iter()
                .any(|r| &r.case == *case && r.outcome == "PASS")
        })
        .map(|c| c.clone().unwrap_or_else(|| "result".into()))
        .collect();
    if !missing.is_empty() {
        gaps.push(if expected.len() == 1 {
            "no PASS result for this build".to_string()
        } else {
            format!(
                "{} of {} cases missing ({})",
                missing.len(),
                expected.len(),
                missing
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        });
    }
    for k in &check.control {
        let rs: Vec<&&ResultPayload> = ok
            .iter()
            .filter(|r| r.control.as_deref() == Some(k.name.as_str()))
            .collect();
        if rs.is_empty() {
            gaps.push(format!("no result for control {}", k.name));
        }
        for r in rs.iter().filter(|r| r.outcome != "FAIL") {
            fails.push(format!(
                "control did not fail: {} reported {} for {} ({})",
                r.device, r.outcome, k.name, k.breaks
            ));
        }
    }
    if !fails.is_empty() {
        return out(Status::Fail, fails.join("; "));
    }
    if !gaps.is_empty() {
        return out(Status::Incomplete, format!("{}{hint}", gaps.join("; ")));
    }
    let mut devices: Vec<&str> = normal.iter().map(|r| r.device.as_str()).collect();
    devices.sort_unstable();
    devices.dedup();
    let latest = normal.iter().map(|r| r.time.as_str()).max().unwrap_or("");
    out(
        Status::Pass,
        format!(
            "signed by {} (latest {latest}): {} case(s) PASS; {} control(s) failed as required",
            devices.join(", "),
            expected.len(),
            check.control.len()
        ),
    )
}

#[cfg(test)]
#[path = "eval_tests.rs"]
mod tests;
