//! The owner's table.

use std::fmt::Write as _;

use crate::eval::{Report, Status};

const DETAILS_WIDTH: usize = 110;

fn cut(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_string()
    } else {
        let mut s: String = text.chars().take(width.saturating_sub(1)).collect();
        s.push('…');
        s
    }
}

/// The table as text. `full` prints details without cutting them.
pub fn table(r: &Report, full: bool) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "mousse-check {}: {}", r.phase, r.title);
    let tree = match (r.dirty, r.allow_dirty) {
        (false, _) => "clean tree".to_string(),
        (true, false) => format!(
            "DIRTY tree ({}): no PASS without --allow-dirty",
            r.dirty_paths.join(", ")
        ),
        (true, true) => format!(
            "DIRTY tree, --allow-dirty given ({})",
            r.dirty_paths.join(", ")
        ),
    };
    let _ = writeln!(s, "build under test: {}  ({tree})", r.build);
    let _ = writeln!(s);
    let w_check = r
        .cells
        .iter()
        .map(|c| c.check.len())
        .max()
        .unwrap_or(5)
        .max(5);
    let w_target = r
        .cells
        .iter()
        .map(|c| c.target.len())
        .max()
        .unwrap_or(6)
        .max(6);
    let _ = writeln!(
        s,
        "{:<w_check$}  {:<w_target$}  {:<10}  DETAILS",
        "CHECK", "TARGET", "STATUS"
    );
    let mut last_check = "";
    for c in &r.cells {
        let name = if c.check == last_check {
            ""
        } else {
            c.check.as_str()
        };
        last_check = &c.check;
        let details = if full {
            c.details.clone()
        } else {
            cut(&c.details, DETAILS_WIDTH)
        };
        let _ = writeln!(
            s,
            "{:<w_check$}  {:<w_target$}  {:<10}  {}",
            name,
            c.target,
            c.status.label(),
            details
        );
    }
    if !r.rejected.is_empty() {
        let _ = writeln!(s);
        let _ = writeln!(s, "Rejected result files:");
        for f in &r.rejected {
            let _ = writeln!(
                s,
                "  {}{}: {}",
                if f.tampering { "[TAMPERED] " } else { "" },
                f.path,
                f.reason
            );
        }
    }
    let _ = writeln!(s);
    let totals: Vec<String> = [
        Status::Pass,
        Status::Fail,
        Status::Incomplete,
        Status::Deferred,
        Status::Attested,
    ]
    .iter()
    .filter_map(|st| r.counts.get(st).map(|n| format!("{n} {}", st.label())))
    .collect();
    let _ = writeln!(s, "cells: {}", totals.join(", "));
    let _ = writeln!(s, "VERDICT: {}", r.verdict.summary);
    if !r.verdict.passed && !full {
        let _ = writeln!(
            s,
            "(--full prints every detail; report --json prints everything)"
        );
    }
    s
}
