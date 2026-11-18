//! Determinism, drill smoke runs, must-fail controls and the known core
//! findings.

use std::collections::BTreeSet;
use std::ops::Range;

use mousse_sim::{run, Bug, Drill, Invariant, RunConfig, RunOutcome};

/// A violation the drills report against the current core: the drill, the
/// invariant, a seed that shows it, and what is wrong. Smoke runs may hit
/// these and nothing else.
///
/// When core fixes one, its seed passes and
/// `known_core_findings_still_reproduce` fails: delete the entry. The list
/// should end empty.
#[cfg_attr(feature = "insecure-exchange", allow(dead_code))]
struct Finding {
    drill: Drill,
    invariant: Invariant,
    seed: u64,
    what: &'static str,
}

const KNOWN_CORE_FINDINGS: &[Finding] = &[];

fn is_known(drill: Drill, invariant: Invariant) -> bool {
    KNOWN_CORE_FINDINGS
        .iter()
        .any(|f| f.drill == drill && f.invariant == invariant)
}

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
                is_known(drill, v.invariant),
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

/// The seeds are for the default exchange (CPace); the insecure stand-in
/// draws different randomness, so its runs differ.
#[cfg(not(feature = "insecure-exchange"))]
#[test]
fn known_core_findings_still_reproduce() {
    for f in KNOWN_CORE_FINDINGS {
        let o = run(&config(f.drill, f.seed, None));
        let got = o.violation.as_ref().map(|v| v.invariant);
        assert_eq!(
            got,
            Some(f.invariant),
            "{} seed {} no longer reports {} ({}): if core fixed it, delete this entry",
            f.drill,
            f.seed,
            f.invariant,
            f.what
        );
    }
}

/// Seed 19126 ends the laptop's grant in the same millisecond as another
/// event. The checks must wait until the host has run its due timers, or
/// they see a channel on a grant that is about to close.
#[cfg(not(feature = "insecure-exchange"))]
#[test]
fn a_grant_that_ends_with_another_event_is_closed_before_the_checks() {
    let o = run(&RunConfig {
        keep_log: true,
        ..RunConfig::new(Drill::Handshake, 19_126)
    });
    assert!(o.violation.is_none(), "{:?}", o.violation);
    assert!(
        o.log.iter().any(|l| l.contains("grant 0 ends")),
        "the seed no longer ends a grant mid-run"
    );
}
