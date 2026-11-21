//! `mousse-check`: the owner test kit for `mousse-net`.
//!
//! The owner runs `mousse-check phase0` and gets one row per check × target
//! cell, each PASS, FAIL, INCOMPLETE, DEFERRED or ATTESTED, and one verdict.
//! The kit is built to be hard to fool:
//!
//! - every automated check has must-fail controls (a deliberately broken
//!   build); a control that does not print FAIL makes the check FAIL, and a
//!   check without a control can never PASS;
//! - results from other machines are signed with a per-device P-256 key and
//!   checked against `checks/devices.toml` and the build under test;
//! - manual steps are ATTESTED, never PASS; DEFERRED only where the phase
//!   allows it; a dirty tree never passes without `--allow-dirty`;
//! - app checks (`app = true`) run only against a clean app checkout at the
//!   revision pinned in `app/MOUSSE_REVISION`, and count only with that app
//!   build.
#![forbid(unsafe_code)]

pub mod app;
pub mod build;
pub mod eval;
pub mod evidence;
pub mod hosted;
pub mod inspect;
pub mod kit;
pub mod manifest;
pub mod probe;
pub mod report;
pub mod runner;
pub mod util;
