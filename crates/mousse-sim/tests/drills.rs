//! Determinism, drill smoke runs, must-fail controls and the known core
//! findings.

use std::collections::BTreeSet;
use std::ops::Range;

use mousse_sim::{run, Bug, Drill, Invariant, RunConfig, RunOutcome};

/// Violations the drills report against the current core. Each has a pinned
/// seed below. A smoke run may hit these and nothing else.
const KNOWN_CORE_FINDINGS: &[(Drill, Invariant)] = &[
    (Drill::PairingLimits, Invariant::PairingAgreement),
    (Drill::Handshake, Invariant::GrantIdsUnique),
];

fn config(drill: Drill, seed: u64, bug: Option<Bug>) -> RunConfig {
    RunConfig {
        bug,
        ..RunConfig::new(drill, seed)
    }
}

/// Run the configs on all cores (each run is single-threaded).
fn run_all(configs: &[RunConfig]) -> Vec<RunOutcome> {
    let jobs = std::thread::available_parallelism().map_or(1, |n| n.get());
    let chunk = configs.len().div_ceil(jobs).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = configs
            .chunks(chunk)
            .map(|part| scope.spawn(move || part.iter().map(run).collect::<Vec<_>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("simulation thread"))
            .collect()
    })
}

fn seeds(drill: Drill, range: Range<u64>, bug: Option<Bug>) -> Vec<RunOutcome> {
    let configs: Vec<RunConfig> = range.map(|s| config(drill, s, bug)).collect();
    run_all(&configs)
}

#[test]
fn the_same_seed_gives_the_same_log() {
    for drill in Drill::ALL {
        for seed in 0..6 {
            let a = run(&config(drill, seed, None));
            let b = run(&RunConfig {
                keep_log: true,
                ..config(drill, seed, None)
            });
            assert_eq!(a.log_hash, b.log_hash, "{drill} seed {seed}");
            assert_eq!(a.log_lines, b.log_lines, "{drill} seed {seed}");
            assert_eq!(a.events, b.events, "{drill} seed {seed}");
            assert_eq!(b.log.len() as u64, b.log_lines);
        }
    }
}

#[test]
fn different_seeds_give_different_logs() {
    for drill in Drill::ALL {
        let hashes: BTreeSet<[u8; 32]> = seeds(drill, 0..10, None)
            .into_iter()
            .map(|o| o.log_hash)
            .collect();
        assert_eq!(hashes.len(), 10, "{drill}");
    }
}

#[test]
fn cached_and_full_verification_give_the_same_log() {
    for drill in Drill::ALL {
        for seed in 0..2 {
            let cached = run(&config(drill, seed, None));
            let full = run(&RunConfig {
                full_verify: true,
                ..config(drill, seed, None)
            });
            assert_eq!(cached.log_hash, full.log_hash, "{drill} seed {seed}");
        }
    }
}

fn smoke(drill: Drill, range: Range<u64>) {
    let outcomes = seeds(drill, range, None);
    let mut variants = BTreeSet::new();
    for o in &outcomes {
        variants.insert(o.variant);
        if let Some(v) = &o.violation {
            assert!(
                KNOWN_CORE_FINDINGS.contains(&(drill, v.invariant)),
                "{drill} seed {}: {v}\n  replay: {}",
                o.config.seed,
                o.config.replay_command()
            );
        }
    }
    let all: BTreeSet<&str> = drill.variants().iter().copied().collect();
    assert_eq!(variants, all, "{drill}: every variant runs");
}

#[test]
fn pairing_limits_smoke() {
    smoke(Drill::PairingLimits, 0..400);
}

#[test]
fn handshake_smoke() {
    smoke(Drill::Handshake, 0..200);
}

#[test]
fn shared_endpoints_smoke() {
    smoke(Drill::SharedEndpoints, 0..200);
}

/// Each planted bug is reported as its invariant within 100 seeds, and the
/// same seed without the bug does not report it.
#[test]
fn every_planted_bug_is_caught() {
    for bug in Bug::ALL {
        let caught = seeds(bug.drill(), 0..100, Some(bug))
            .into_iter()
            .find(|o| o.violation.as_ref().map(|v| v.invariant) == Some(bug.expected()));
        let Some(caught) = caught else {
            panic!(
                "{bug} was not reported as {} in seeds 0..100",
                bug.expected()
            );
        };
        let clean = run(&config(bug.drill(), caught.config.seed, None));
        assert_ne!(
            clean.violation.map(|v| v.invariant),
            Some(bug.expected()),
            "{bug}: seed {} reports {} even without the bug",
            caught.config.seed,
            bug.expected()
        );
    }
}

#[test]
fn a_planted_bug_is_named_in_the_replay_command() {
    let cfg = config(Drill::SharedEndpoints, 7, Some(Bug::SharedGrantTable));
    assert_eq!(
        cfg.replay_command(),
        "mousse-sim replay --drill shared-endpoints --seed 7 --bug shared-grant-table"
    );
    assert_eq!(
        "shared-endpoints".parse::<Drill>(),
        Ok(Drill::SharedEndpoints)
    );
    assert!("shared".parse::<Drill>().is_err());
    assert_eq!(
        "no-pin-on-reconnect".parse::<Bug>(),
        Ok(Bug::NoPinOnReconnect)
    );
}

/// Core finding: a joiner whose third attempt succeeded but whose `PAIRED`
/// was lost with the connection ends as `AttemptsExhausted`, while the host
/// keeps the grant. When core fixes this, this seed passes and the entry in
/// `KNOWN_CORE_FINDINGS` should go.
#[test]
fn known_core_finding_joiner_fails_after_a_lost_paired() {
    let o = run(&config(Drill::PairingLimits, 2352, None));
    let v = o.violation.expect("the finding still reproduces");
    assert_eq!(v.invariant, Invariant::PairingAgreement, "{v}");
}

/// Core finding: `GrantTable::restore` sets the next id from the stored
/// grants only, so after removing the newest grant and restarting, the next
/// grant reuses its id.
#[test]
fn known_core_finding_grant_id_reused_after_restore() {
    let o = run(&config(Drill::Handshake, 21, None));
    let v = o.violation.expect("the finding still reproduces");
    assert_eq!(v.invariant, Invariant::GrantIdsUnique, "{v}");
}
