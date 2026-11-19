//! Command line for the owner test kit. Run `mousse-check help`.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mousse_check::evidence::file_part;
use mousse_check::evidence::{
    device_key_text, generate_device_key, load_device_key, parse_public_key, Attestation, Device,
    DeviceList, ATTEST_FORMAT,
};
use mousse_check::kit::{
    host, payload_from, public_hex, read_unsigned, write_signed, Kit, Only, Parts, SignArgs, Signer,
};
use mousse_check::report::table;
use mousse_check::util::now_rfc3339;

const HELP: &str = "\
mousse-check: the owner test kit for mousse-net

USAGE
  mousse-check <phase> [--allow-dirty] [--no-run] [--only <check-id>]... [--full] [--json]
      Run this machine's local checks and their must-fail controls, collect
      signed device results and attestations, print the table. Exit 0 only if
      the phase passes. Example: mousse-check phase0
  mousse-check run <check-id> [--control] [--target <cell>] [--case <name>]
                   [--sign-with <key file> [--device <name>] [--platform <text>] [--out <dir>]]
      Run one check here (or, with --control, its controls). A check with
      named cases runs once per case, or only --case. With --sign-with,
      also write signed results, for a machine whose results another machine
      evaluates.
  mousse-check sign --device-key <key file> [--device <name>] [--check <id>] [--target <cell>]
                    [--control <name>] [--platform <text>] [--profile <p>] [--out <dir>]
                    [--config <digest>] <file>...
      Sign result files a device produced (result JSON, crypto matrix files,
      or logs of MATRIX_RESULT lines). Each result needs the configuration
      digest recorded before the run: a `config` field, or --config.
      Writes into checks/results/<device>/.
  mousse-check config-digest <check-id> [--target <cell>] [--control <name>]
      Print the configuration digest of one run of a check, from this
      checkout's manifest. A device that produces results outside
      `mousse-check run` runs this before the run and passes the digest to
      `sign --config`.
  mousse-check control-env <check-id> --control <name>
      Print, as one JSON object, the environment a control adds to a run.
      tools/app-check/run.mjs reads it for --control on a device run.
  mousse-check attest <check-id> --note <text> [--target <cell>] [--by <name>]
      Record a manual step. Shown as ATTESTED, never PASS.
  mousse-check device keygen --out <key file>
  mousse-check device add --name <name> --key <hex or file> --targets <a,b,...> [--platform <text>]
  mousse-check device list
  mousse-check report [<phase>] [--allow-dirty] [--full] [--json]
      Print the table from stored runs and results without running anything.

Global: --root <dir> (default: the git checkout containing the current folder).
App checks (app = true) run only with MOUSSE_APP_DIR set to a clean checkout of
the app at the revision in app/MOUSSE_REVISION.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match real_main(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("mousse-check: {e}");
            ExitCode::from(2)
        }
    }
}

/// Parsed flags: `--name value`, `--flag`, and positionals.
struct Args {
    positional: Vec<String>,
    flags: Vec<(String, Option<String>)>,
}

const VALUE_FLAGS: &[&str] = &[
    "--root",
    "--only",
    "--target",
    "--sign-with",
    "--device",
    "--device-key",
    "--platform",
    "--out",
    "--check",
    "--profile",
    "--note",
    "--by",
    "--name",
    "--key",
    "--targets",
    "--config",
    "--case",
];

impl Args {
    fn parse(raw: Vec<String>, control_takes_value: bool) -> Result<Self, String> {
        let mut positional = Vec::new();
        let mut flags = Vec::new();
        let mut it = raw.into_iter();
        while let Some(a) = it.next() {
            if let Some(name) = a.strip_prefix("--") {
                let takes =
                    VALUE_FLAGS.contains(&a.as_str()) || (control_takes_value && name == "control");
                if takes {
                    let v = it.next().ok_or_else(|| format!("{a} needs a value"))?;
                    flags.push((a, Some(v)));
                } else {
                    flags.push((a, None));
                }
            } else {
                positional.push(a);
            }
        }
        Ok(Self { positional, flags })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.as_deref())
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.flags
            .iter()
            .filter(|(n, _)| n == name)
            .filter_map(|(_, v)| v.as_deref())
            .collect()
    }

    fn has(&self, name: &str) -> bool {
        self.flags.iter().any(|(n, _)| n == name)
    }

    fn only_known(&self, known: &[&str]) -> Result<(), String> {
        for (n, _) in &self.flags {
            if !known.contains(&n.as_str()) && n != "--root" {
                return Err(format!("unknown option {n} (see mousse-check help)"));
            }
        }
        Ok(())
    }
}

fn real_main(raw: Vec<String>) -> Result<ExitCode, String> {
    let Some(cmd) = raw.first().cloned() else {
        print!("{HELP}");
        return Ok(ExitCode::from(2));
    };
    let rest = raw[1..].to_vec();
    let a = Args::parse(
        rest,
        matches!(cmd.as_str(), "sign" | "config-digest" | "control-env"),
    )?;
    if matches!(cmd.as_str(), "help" | "--help" | "-h") {
        print!("{HELP}");
        return Ok(ExitCode::SUCCESS);
    }
    let kit = Kit::open(a.get("--root").map(Path::new))?;
    match cmd.as_str() {
        "run" => cmd_run(&kit, &a),
        "sign" => cmd_sign(&kit, &a),
        "attest" => cmd_attest(&kit, &a),
        "config-digest" => cmd_config_digest(&kit, &a),
        "control-env" => cmd_control_env(&kit, &a),
        "device" => cmd_device(&kit, &a),
        "report" => cmd_report(&kit, &a, None),
        phase if kit.has_phase(phase) => cmd_report(&kit, &a, Some(phase)),
        other => Err(format!(
            "unknown command or phase {other:?}; phases here: {}",
            kit.phases().join(", ")
        )),
    }
}

fn cmd_report(kit: &Kit, a: &Args, run_phase: Option<&str>) -> Result<ExitCode, String> {
    a.only_known(&["--allow-dirty", "--no-run", "--only", "--full", "--json"])?;
    let phase = match (run_phase, a.positional.first()) {
        (Some(p), _) => p.to_string(),
        (None, Some(p)) => p.clone(),
        (None, None) => match kit.phases().as_slice() {
            [only] => only.clone(),
            many => return Err(format!("which phase? ({})", many.join(", "))),
        },
    };
    let m = kit.load_manifest(&phase)?;
    let only = a.all("--only");
    for id in &only {
        if m.check(id).is_none() {
            return Err(format!("no check {id} in {phase}"));
        }
    }
    if run_phase.is_some() && !a.has("--no-run") {
        if std::env::var_os("CARGO_TARGET_DIR").is_none() {
            eprintln!("note: CARGO_TARGET_DIR is not set; builds inside the checkout can make the tree dirty");
        }
        eprintln!("running local checks for {phase} on {}:", host());
        for c in &m.checks {
            if c.deferred || c.manual || c.placeholder.is_some() {
                continue;
            }
            if !only.is_empty() && !only.contains(&c.id.as_str()) {
                continue;
            }
            kit.run_local(&m, c, Only::default(), Parts::Both, false, None)?;
        }
        eprintln!();
    }
    let mut report = kit.report(&m, a.has("--allow-dirty"))?;
    if !only.is_empty() {
        report.cells.retain(|c| only.contains(&c.check.as_str()));
        report.verdict.passed = false;
        report.verdict.summary = format!(
            "{} (only some checks shown: no phase verdict)",
            report.verdict.summary
        );
    }
    if a.has("--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        print!("{}", table(&report, a.has("--full")));
    }
    Ok(if report.verdict.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn cmd_run(kit: &Kit, a: &Args) -> Result<ExitCode, String> {
    a.only_known(&[
        "--control",
        "--target",
        "--case",
        "--sign-with",
        "--device",
        "--platform",
        "--out",
    ])?;
    let id = a.positional.first().ok_or("run needs a check id")?;
    let (m, c) = kit.find_check(id)?;
    if c.manual {
        return Err(format!(
            "{id} is a manual step; record it with `mousse-check attest`"
        ));
    }
    if c.local.is_empty() {
        return Err(format!(
            "{id} has no local command; its cells come from device results"
        ));
    }
    let signer = match a.get("--sign-with") {
        None => None,
        Some(path) => {
            let key = load_device_key(Path::new(path))?;
            let device = resolve_device(kit, &key, a.get("--device"))?;
            let out_dir = a
                .get("--out")
                .map(PathBuf::from)
                .unwrap_or_else(|| kit.results_dir().join(file_part(&device)));
            Some(Signer {
                key,
                platform: a.get("--platform").map(str::to_string).unwrap_or_else(host),
                device,
                out_dir,
            })
        }
    };
    let parts = if a.has("--control") {
        Parts::Controls
    } else {
        Parts::Normal
    };
    if let Some(case) = a.get("--case") {
        if !c.cases.iter().any(|k| k == case) {
            return Err(format!(
                "{id} has no case {case} (cases: {})",
                if c.cases.is_empty() {
                    "none".to_string()
                } else {
                    c.cases.join(", ")
                }
            ));
        }
    }
    let ok = kit.run_local(
        &m,
        &c,
        Only {
            target: a.get("--target"),
            case: a.get("--case"),
        },
        parts,
        true,
        signer.as_ref(),
    )?;
    Ok(if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// The device name for a key: from devices.toml, or `--device`.
fn resolve_device(
    kit: &Kit,
    key: &mousse_net_core::identity::SoftwareKey,
    given: Option<&str>,
) -> Result<String, String> {
    let devices = kit.devices()?;
    match (devices.by_key(&key.public_key()), given) {
        (Some(d), Some(g)) if d.name != g => Err(format!(
            "this key belongs to device {} in devices.toml, not {g}",
            d.name
        )),
        (Some(d), _) => Ok(d.name.clone()),
        (None, Some(g)) => {
            eprintln!(
                "note: this key is not in {} here; results count only once the evaluating checkout trusts it",
                kit.devices_path().display()
            );
            Ok(g.to_string())
        }
        (None, None) => Err(format!(
            "key {} is not in devices.toml; give --device <name>",
            public_hex(key)
        )),
    }
}

fn cmd_sign(kit: &Kit, a: &Args) -> Result<ExitCode, String> {
    a.only_known(&[
        "--device-key",
        "--device",
        "--check",
        "--target",
        "--control",
        "--platform",
        "--profile",
        "--out",
        "--config",
    ])?;
    if let Some(d) = a.get("--config") {
        if d.len() != 64
            || !d
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(format!(
                "--config {d:?} is not a digest from `mousse-check config-digest`"
            ));
        }
    }
    let key_path = a.get("--device-key").ok_or("sign needs --device-key")?;
    if a.positional.is_empty() {
        return Err("sign needs at least one result file".into());
    }
    let key = load_device_key(Path::new(key_path))?;
    let device = resolve_device(kit, &key, a.get("--device"))?;
    let default_build = match a.get("--profile") {
        Some(p) => Some(kit.state()?.id(p).to_string()),
        None => None,
    };
    let out_dir = a
        .get("--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| kit.results_dir().join(file_part(&device)));
    let sa = SignArgs {
        check: a.get("--check"),
        target: a.get("--target"),
        control: a.get("--control"),
        platform: a.get("--platform"),
        default_build,
        config: a.get("--config"),
        device: &device,
    };
    let mut payloads = Vec::new();
    let mut given = std::collections::BTreeSet::new();
    for file in &a.positional {
        for v in read_unsigned(Path::new(file))? {
            let p = payload_from(&v, &sa).map_err(|e| format!("{file}: {e}"))?;
            let id = format!(
                "{} @ {} [{}]",
                p.check,
                p.target,
                p.control.as_deref().unwrap_or("normal")
            );
            match (&p.config, v.get("config")) {
                (None, _) => {
                    return Err(format!(
                        "{file}: {id} has no configuration digest. Before producing a result outside `mousse-check run`, run `mousse-check config-digest {} --target {}{}` and pass its output to sign --config",
                        p.check,
                        p.target,
                        p.control.as_ref().map(|c| format!(" --control {c}")).unwrap_or_default()
                    ))
                }
                (Some(_), None) => {
                    given.insert(id.clone());
                }
                (Some(_), Some(_)) => {}
            }
            payloads.push((id, p));
        }
    }
    if given.len() > 1 {
        return Err(format!(
            "--config is the digest of one run, but these results are from {} runs ({}); sign each run separately",
            given.len(),
            given.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    let app_revision = mousse_check::app::read_revision(kit.root()).ok();
    for (id, p) in &payloads {
        let now = config_for(kit, &p.check, &p.target, p.control.as_deref())?;
        let (_, c) = kit.find_check(&p.check)?;
        if c.app {
            let mut claims = vec![("", p.extra_str("app_build"))];
            if c.cross_machine {
                claims.push(("host: ", p.extra_str("host_app_build")));
            }
            for (side, claimed) in claims {
                if let Err(why) =
                    mousse_check::app::app_build_counts(claimed, app_revision.as_deref())
                {
                    eprintln!("note: {id} is an app check; {side}{why}, so it will not count");
                }
            }
        }
        if p.config.as_deref() != Some(now.as_str()) {
            eprintln!(
                "note: {id} was produced under another configuration than this checkout's manifest; it will count only for that configuration"
            );
        }
    }
    for (_, p) in &payloads {
        let path = write_signed(&out_dir, p, &key)?;
        println!("signed {}", path.display());
    }
    eprintln!("{} result(s) signed as {device}", payloads.len());
    Ok(ExitCode::SUCCESS)
}

/// `config-digest`: the digest a device records before producing a result.
fn cmd_config_digest(kit: &Kit, a: &Args) -> Result<ExitCode, String> {
    a.only_known(&["--target", "--control"])?;
    let id = a
        .positional
        .first()
        .ok_or("config-digest needs a check id")?;
    let (_, c) = kit.find_check(id)?;
    let target = match (a.get("--target"), c.targets.as_slice()) {
        (Some(t), _) => t.to_string(),
        (None, [only]) => only.clone(),
        (None, many) => return Err(format!("which target? ({})", many.join(", "))),
    };
    println!("{}", config_for(kit, id, &target, a.get("--control"))?);
    Ok(ExitCode::SUCCESS)
}

/// The configuration digest of one run, from this checkout's manifest.
fn config_for(
    kit: &Kit,
    check: &str,
    target: &str,
    control: Option<&str>,
) -> Result<String, String> {
    let (m, c) = kit.find_check(check)?;
    if !c.targets.iter().any(|t| t == target) {
        return Err(format!("{check} has no target {target}"));
    }
    let control = match control {
        None => None,
        Some(name) => Some(
            c.control_named(name)
                .ok_or_else(|| format!("{check} has no control {name}"))?,
        ),
    };
    Ok(m.config_digest(&c, target, control))
}

/// `control-env`: what a control adds to the environment, for runs made
/// outside `mousse-check run`.
fn cmd_control_env(kit: &Kit, a: &Args) -> Result<ExitCode, String> {
    a.only_known(&["--control"])?;
    let id = a.positional.first().ok_or("control-env needs a check id")?;
    let name = a
        .get("--control")
        .ok_or("control-env needs --control <name>")?;
    let (_, c) = kit.find_check(id)?;
    let k = c
        .control_named(name)
        .ok_or_else(|| format!("{id} has no control {name}"))?;
    if let Some(why) = &k.missing {
        return Err(format!("control {name} does not exist yet: {why}"));
    }
    if k.command.is_some() || !k.args.is_empty() {
        return Err(format!(
            "control {name} changes the command, not only the environment; run it with `mousse-check run {id} --control`"
        ));
    }
    println!(
        "{}",
        serde_json::to_string(&k.env).map_err(|e| e.to_string())?
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_attest(kit: &Kit, a: &Args) -> Result<ExitCode, String> {
    a.only_known(&["--note", "--target", "--by"])?;
    let id = a.positional.first().ok_or("attest needs a check id")?;
    let note = a.get("--note").ok_or("attest needs --note")?;
    if note.trim().is_empty() {
        return Err("the note must say what was done and seen".into());
    }
    let (_, c) = kit.find_check(id)?;
    let target = match (a.get("--target"), c.targets.as_slice()) {
        (Some(t), _) => {
            if !c.targets.iter().any(|x| x == t) {
                return Err(format!("{id} has no target {t} ({})", c.targets.join(", ")));
            }
            t.to_string()
        }
        (None, [only]) => only.clone(),
        (None, many) => return Err(format!("which target? ({})", many.join(", "))),
    };
    let by = a
        .get("--by")
        .map(str::to_string)
        .or_else(|| kit.git.user_name())
        .ok_or("who? give --by <name>")?;
    let state = kit.state()?;
    let att = Attestation {
        format: ATTEST_FORMAT.into(),
        check: id.clone(),
        target: target.clone(),
        build: state.id("manual").to_string(),
        by,
        time: now_rfc3339(),
        note: note.to_string(),
    };
    let dir = kit.results_dir().join("attest");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!(
        "{}__{}__{}.json",
        file_part(id),
        file_part(&target),
        file_part(&att.time.replace(':', ""))
    ));
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&att).map_err(|e| e.to_string())? + "\n",
    )
    .map_err(|e| e.to_string())?;
    println!("attested {}", path.display());
    if !c.manual {
        eprintln!("note: {id} needs an automated result; this attestation shows as ATTESTED but does not let the phase pass");
    }
    if state.dirty {
        eprintln!("note: the tree is dirty; this attestation counts only with --allow-dirty");
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_device(kit: &Kit, a: &Args) -> Result<ExitCode, String> {
    match a.positional.first().map(String::as_str) {
        Some("keygen") => {
            a.only_known(&["--out"])?;
            let out = a
                .get("--out")
                .ok_or("device keygen needs --out <key file>")?;
            let path = Path::new(out);
            if path.exists() {
                return Err(format!("{out} exists; not overwriting a key"));
            }
            let key = generate_device_key()?;
            write_secret(path, device_key_text(&key).as_bytes())?;
            println!("{}", public_hex(&key));
            eprintln!("secret key written to {out}; keep it on this device and never commit it");
            eprintln!(
                "trust it on the evaluating checkout with:\n  mousse-check device add --name <name> --key {} --targets <cells>",
                public_hex(&key)
            );
            Ok(ExitCode::SUCCESS)
        }
        Some("add") => {
            a.only_known(&["--name", "--key", "--targets", "--platform"])?;
            let name = a.get("--name").ok_or("device add needs --name")?;
            let key_arg = a.get("--key").ok_or("device add needs --key")?;
            let targets: Vec<String> = a
                .get("--targets")
                .ok_or("device add needs --targets (the cells this device may report)")?
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();
            if targets.is_empty() {
                return Err("--targets is empty".into());
            }
            let key_hex = if Path::new(key_arg).is_file() {
                std::fs::read_to_string(key_arg).map_err(|e| e.to_string())?
            } else {
                key_arg.to_string()
            };
            let key_hex = key_hex.trim().to_ascii_lowercase();
            if key_hex.len() == 64 {
                return Err(
                    "that looks like a secret key; give the public key (130 hex digits)".into(),
                );
            }
            parse_public_key(&key_hex)?;
            let dev = Device {
                name: name.to_string(),
                key: key_hex,
                platform: a.get("--platform").unwrap_or("").to_string(),
                targets,
                added: now_rfc3339(),
            };
            let path = kit.devices_path();
            let old = std::fs::read_to_string(&path).unwrap_or_default();
            let new = format!("{old}{}", DeviceList::entry_text(&dev));
            DeviceList::parse(&new)?;
            std::fs::write(&path, new).map_err(|e| e.to_string())?;
            println!("added {name} to {}", path.display());
            eprintln!("commit checks/devices.toml: an uncommitted trust list makes the tree dirty");
            Ok(ExitCode::SUCCESS)
        }
        Some("list") => {
            for d in kit.devices()?.devices {
                println!(
                    "{}  {}  [{}]  key {}…",
                    d.name,
                    d.platform,
                    d.targets.join(", "),
                    &d.key[..d.key.len().min(20)]
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        _ => Err("device keygen | add | list".into()),
    }
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        f.write_all(bytes).map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        f.write_all(bytes).map_err(|e| e.to_string())
    }
}
