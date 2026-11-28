//! Command line for the simulator.
//!
//! ```text
//! mousse-sim run pairing-limits --seeds 5000 [--bug NAME] [--full-verify] [--jobs N]
//! mousse-sim run --drill all --seeds 1000..2000
//! mousse-sim run pairing-direct
//! mousse-sim replay --drill handshake --seed 42 [--bug NAME] [--full-verify]
//! mousse-sim must-fail [--drill pairing-direct] [--seeds 0..500]
//! mousse-sim list
//! ```
//!
//! `run` and `must-fail` spread seeds over worker threads. Each run is
//! still single-threaded and deterministic; threads only run different
//! seeds side by side.
//!
//! `--seeds N` means seeds `0..N`; `--seeds A..B` a range; `--seed N` one
//! seed. `run` without seeds runs `0..1000`, `must-fail` `0..500`. The drill
//! is the first plain argument or `--drill`; `must-fail` with a drill plants
//! only that drill's bugs.
//!
//! `run` ends each drill with `PASS sim <drill>` or `FAIL sim <drill>`. With
//! `--bug`, the verdict counts only the invariant that bug must break, so a
//! must-fail control prints `FAIL` exactly when its bug was caught.
//!
//! Exit status: 0 when every drill passes (for `must-fail`: when every
//! planted bug is caught), 1 otherwise, 2 for a usage error.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ops::Range;
use std::process::ExitCode;
use std::time::Instant;

use mousse_sim::{run, Bug, Drill, Invariant, RunConfig, RunOutcome};

const USAGE: &str = "usage:
  mousse-sim run <drill|all> [--seeds <N|A..B>] [--bug <name>] [--full-verify] [--jobs <N>]
  mousse-sim replay --drill <name> --seed <N> [--bug <name>] [--full-verify]
  mousse-sim must-fail [--drill <name>] [--seeds <A..B>] [--jobs <N>]
  mousse-sim list";

/// How many failures `run` prints in full.
const SHOWN_FAILURES: usize = 20;

/// The seeds `run` uses when none are given.
const RUN_SEEDS: Range<u64> = 0..1_000;

/// The seeds `must-fail` uses when none are given.
const MUST_FAIL_SEEDS: Range<u64> = 0..500;

struct Args {
    drills: Vec<Drill>,
    seeds: Option<Range<u64>>,
    bug: Option<Bug>,
    full_verify: bool,
    jobs: usize,
}

/// Run every config, spread over `jobs` threads, and return the outcomes in
/// input order.
fn run_all(configs: &[RunConfig], jobs: usize) -> Vec<RunOutcome> {
    let jobs = jobs.clamp(1, configs.len().max(1));
    let chunk = configs.len().div_ceil(jobs).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = configs
            .chunks(chunk)
            .map(|part| scope.spawn(move || part.iter().map(run).collect::<Vec<_>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("a simulation thread panicked"))
            .collect()
    })
}

/// `A..B`, or `N` meaning `0..N` (`--seeds`) or the one seed `N` (`--seed`).
fn parse_seeds(s: &str, single: bool) -> Result<Range<u64>, String> {
    let bad = || format!("bad seeds {s:?}; use A..B or N");
    match s.split_once("..") {
        Some((a, b)) => {
            let a: u64 = a.parse().map_err(|_| bad())?;
            let b: u64 = b.parse().map_err(|_| bad())?;
            if b <= a {
                return Err(bad());
            }
            Ok(a..b)
        }
        None => {
            let n: u64 = s.parse().map_err(|_| bad())?;
            match (single, n) {
                (true, _) => Ok(n..n.saturating_add(1)),
                (false, 0) => Err(bad()),
                (false, _) => Ok(0..n),
            }
        }
    }
}

fn parse_args(rest: &[String]) -> Result<Args, String> {
    let mut args = Args {
        drills: Vec::new(),
        seeds: None,
        bug: None,
        full_verify: false,
        jobs: std::thread::available_parallelism().map_or(1, |n| n.get()),
    };
    let set_drill = |args: &mut Args, v: &str| -> Result<(), String> {
        args.drills = if v == "all" {
            Drill::ALL.to_vec()
        } else {
            vec![v.parse()?]
        };
        Ok(())
    };
    let mut it = rest.iter();
    while let Some(flag) = it.next() {
        if !flag.starts_with("--") {
            if !args.drills.is_empty() {
                return Err(format!("unexpected argument {flag:?}"));
            }
            set_drill(&mut args, flag)?;
            continue;
        }
        let mut value = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match flag.as_str() {
            "--drill" => {
                let v = value()?;
                set_drill(&mut args, &v)?;
            }
            "--seeds" => args.seeds = Some(parse_seeds(&value()?, false)?),
            "--seed" => args.seeds = Some(parse_seeds(&value()?, true)?),
            "--bug" => args.bug = Some(value()?.parse()?),
            "--full-verify" => args.full_verify = true,
            "--jobs" => {
                args.jobs = value()?
                    .parse()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or("--jobs needs a positive number")?
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(args)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = argv.first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let args = match parse_args(&argv[1..]) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match command.as_str() {
        "run" => cmd_run(&args),
        "replay" => cmd_replay(&args),
        "must-fail" => cmd_must_fail(&args),
        "list" => cmd_list(),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown command {other:?}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn cmd_run(args: &Args) -> ExitCode {
    if args.drills.is_empty() {
        eprintln!("run needs a drill\n{USAGE}");
        return ExitCode::from(2);
    }
    let seeds = args.seeds.clone().unwrap_or(RUN_SEEDS);
    let mut failed = false;
    for &drill in &args.drills {
        let started = Instant::now();
        let mut runs = 0u64;
        let mut events = 0u64;
        let mut failures = Vec::new();
        let mut by_variant: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
        let configs: Vec<RunConfig> = seeds
            .clone()
            .map(|seed| RunConfig {
                bug: args.bug,
                full_verify: args.full_verify,
                ..RunConfig::new(drill, seed)
            })
            .collect();
        for outcome in run_all(&configs, args.jobs) {
            runs += 1;
            events += outcome.events;
            let entry = by_variant.entry(outcome.variant).or_default();
            entry.0 += 1;
            let counts = match (&outcome.violation, args.bug) {
                (None, _) => false,
                (Some(_), None) => true,
                (Some(v), Some(bug)) => v.invariant == bug.expected(),
            };
            if counts {
                entry.1 += 1;
                failures.push(outcome);
            }
        }
        let secs = started.elapsed().as_secs_f64();
        for f in failures.iter().take(SHOWN_FAILURES) {
            if let Some(v) = &f.violation {
                println!(
                    "FAIL {} seed {} ({}): {v}\n  replay: {}",
                    drill,
                    f.config.seed,
                    f.variant,
                    f.config.replay_command()
                );
            }
        }
        if failures.len() > SHOWN_FAILURES {
            println!("... and {} more failures", failures.len() - SHOWN_FAILURES);
        }
        let variants: Vec<String> = by_variant
            .iter()
            .map(|(v, (n, f))| {
                format!(
                    "{v} {n}{}",
                    if *f > 0 {
                        format!(" ({f} failed)")
                    } else {
                        String::new()
                    }
                )
            })
            .collect();
        println!(
            "{drill}: {runs} seeds, {} failed, {events} events, {secs:.2} s on {} threads ({:.0} seeds/s)\n  variants: {}",
            failures.len(),
            args.jobs,
            runs as f64 / secs.max(1e-9),
            variants.join(", ")
        );
        if let Some(bug) = args.bug {
            println!(
                "planted bug {bug}: {}",
                if failures.is_empty() {
                    format!("not caught (no seed reported {})", bug.expected())
                } else {
                    format!("caught as {} in {} seeds", bug.expected(), failures.len())
                }
            );
        }
        let verdict = if failures.is_empty() { "PASS" } else { "FAIL" };
        println!("{verdict} sim {drill}");
        failed |= !failures.is_empty();
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn cmd_replay(args: &Args) -> ExitCode {
    let (Some(seeds), [drill]) = (args.seeds.clone(), args.drills.as_slice()) else {
        eprintln!("replay needs one --drill and --seed\n{USAGE}");
        return ExitCode::from(2);
    };
    let config = RunConfig {
        bug: args.bug,
        full_verify: args.full_verify,
        keep_log: true,
        ..RunConfig::new(*drill, seeds.start)
    };
    let outcome = run(&config);
    for line in &outcome.log {
        println!("{line}");
    }
    println!(
        "-- {} seed {} variant {}: {} lines, {} events, ended at {} ms, log sha256 {}",
        drill,
        config.seed,
        outcome.variant,
        outcome.log_lines,
        outcome.events,
        outcome.end_ms,
        outcome.log_hash_hex()
    );
    match &outcome.violation {
        Some(v) => {
            println!("-- FAIL: {v}");
            ExitCode::from(1)
        }
        None => {
            println!("-- every invariant held");
            ExitCode::SUCCESS
        }
    }
}

/// Plant each bug (of the named drills, or every bug) and confirm its drill
/// reports the expected invariant.
fn cmd_must_fail(args: &Args) -> ExitCode {
    let seeds = args.seeds.clone().unwrap_or(MUST_FAIL_SEEDS);
    let mut missed = false;
    let bugs = Bug::ALL
        .into_iter()
        .filter(|b| args.drills.is_empty() || args.drills.contains(&b.drill()));
    for bug in bugs {
        let started = Instant::now();
        let configs: Vec<RunConfig> = seeds
            .clone()
            .map(|seed| RunConfig {
                bug: Some(bug),
                ..RunConfig::new(bug.drill(), seed)
            })
            .collect();
        let caught = run_all(&configs, args.jobs)
            .into_iter()
            .find(|o| o.violation.as_ref().map(|v| v.invariant) == Some(bug.expected()))
            .map(|o| o.config);
        let secs = started.elapsed().as_secs_f64();
        match caught {
            Some(config) => println!(
                "caught {bug} as {} at seed {} ({secs:.2} s)\n  replay: {}",
                bug.expected(),
                config.seed,
                config.replay_command()
            ),
            None => {
                missed = true;
                println!(
                    "MISSED {bug}: no seed in {}..{} reported {}",
                    seeds.start,
                    seeds.end,
                    bug.expected()
                );
            }
        }
    }
    if missed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn cmd_list() -> ExitCode {
    println!("drills:");
    for d in Drill::ALL {
        println!("  {d}: {}", d.variants().join(", "));
    }
    println!("invariants:");
    for i in Invariant::ALL {
        println!("  {i}");
    }
    println!("planted bugs (--bug):");
    for b in Bug::ALL {
        println!("  {b} (drill {}, expects {})", b.drill(), b.expected());
    }
    ExitCode::SUCCESS
}
