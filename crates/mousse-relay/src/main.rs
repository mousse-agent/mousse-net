//! `mousse-relay`: run a self-hosted relay and manage who may register.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::SystemTime;

use clap::{Parser, Subcommand};
use mousse_net_core::time::UnixTime;
use mousse_relay::server::{self, ServerConfig};
use mousse_relay::state::{hex, unhex32, StateDir};
use mousse_relay::{limits, os_rng};

#[derive(Parser)]
#[command(name = "mousse-relay", version, about = "Mousse relay")]
struct Cli {
    /// State directory (identity key, authorized list, enrollment codes).
    #[arg(long, global = true, env = "MOUSSE_RELAY_STATE", default_value = default_state())]
    state: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the relay identity and print the first enrollment link.
    Init {
        /// `host:port` that clients dial (an IPv6 address in brackets).
        #[arg(long)]
        public: String,
    },
    /// Run the relay.
    Run {
        /// Address to listen on; by default every address on the public port.
        #[arg(long)]
        listen: Option<SocketAddr>,
        /// Hosted mode: admission tokens and leases from Plus
        /// (`MOUSSE_NET_RELAY_PLUS_URL`, the `issuer-keys` file in the state
        /// directory) instead of the authorized list.
        #[arg(long)]
        hosted: bool,
    },
    /// Check the `issuer-keys` file; a running hosted relay reads it again
    /// within `MOUSSE_NET_RELAY_STATE_POLL_MS`, or at once on `SIGHUP`.
    Reload,
    /// Print a new single-use enrollment link.
    Enroll,
    /// Print the authorized registration keys.
    List,
    /// Remove a registration key; its registration and circuits close.
    Revoke {
        /// The key's fingerprint, 64 hex digits (`list` prints them).
        fingerprint: String,
    },
    /// Print the relay id, address, and whether it is running.
    Status {
        /// Machine-readable, with this binary's SHA-256 (to compare with a
        /// reproducible build of the release, docs/release.md), where the
        /// log goes and the state directory's file list.
        #[arg(long)]
        json: bool,
    },
}

fn default_state() -> &'static str {
    if cfg!(unix) {
        "/var/lib/mousse-relay"
    } else {
        "mousse-relay-state"
    }
}

fn now() -> UnixTime {
    UnixTime(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

fn main() -> ExitCode {
    no_core_dumps();
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mousse-relay: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let limits = limits::from_env()?;
    let s = |e: mousse_relay::state::StateError| e.to_string();
    match cli.command {
        Command::Init { public } => {
            let dir = StateDir::init(&cli.state, &public, &mut os_rng()).map_err(s)?;
            let link = dir
                .enroll(now(), limits.enroll_secs(), &mut os_rng())
                .map_err(s)?;
            println!("relay id {}", hex(&link.relay.0));
            println!("enrollment link (single use, {} s):", limits.enroll_secs());
            println!("{}", link.to_text());
        }
        Command::Enroll => {
            let dir = StateDir::open(&cli.state).map_err(s)?;
            let link = dir
                .enroll(now(), limits.enroll_secs(), &mut os_rng())
                .map_err(s)?;
            println!("{}", link.to_text());
        }
        Command::List => {
            let dir = StateDir::open(&cli.state).map_err(s)?;
            for k in dir.read().map_err(s)?.authorized {
                match k.drop_at {
                    Some(t) => println!("{} superseded, dropped at {}", hex(&k.fingerprint), t.0),
                    None => println!("{}", hex(&k.fingerprint)),
                }
            }
        }
        Command::Revoke { fingerprint } => {
            let dir = StateDir::open(&cli.state).map_err(s)?;
            let fp = unhex32(&fingerprint.to_ascii_lowercase())
                .ok_or("a fingerprint is 64 hex digits")?;
            if !dir.revoke(now(), &fp).map_err(s)? {
                return Err("no such key in the authorized list".into());
            }
            println!("revoked");
        }
        Command::Status { json } => {
            let dir = StateDir::open(&cli.state).map_err(s)?;
            let (_, _, public) = dir.public().map_err(s)?;
            let lists = dir.read().map_err(s)?;
            if json {
                let status = serde_json::json!({
                    "relay_id": hex(&dir.relay_id().map_err(s)?.0),
                    "public": public,
                    "authorized": lists.authorized.len(),
                    "codes": lists.codes.len(),
                    "running": dir.running(),
                    "build": {
                        "version": env!("CARGO_PKG_VERSION"),
                        "sha256": executable_sha256()?,
                    },
                    "log": { "destination": "stderr" },
                    "process": process_hardening(),
                    "state": state_listing(dir.path())?,
                });
                println!("{status:#}");
                return Ok(());
            }
            println!("relay id   {}", hex(&dir.relay_id().map_err(s)?.0));
            println!("public     {public}");
            println!("authorized {}", lists.authorized.len());
            println!("codes      {}", lists.codes.len());
            println!("running    {}", if dir.running() { "yes" } else { "no" });
        }
        Command::Reload => {
            let dir = StateDir::open(&cli.state).map_err(s)?;
            let path = dir.path().join(server::ISSUER_KEYS_FILE);
            let keys = mousse_relay_plus::issuers::load(&path).map_err(|e| e.to_string())?;
            println!(
                "{} issuer keys; a running relay takes them within {} ms (at once on SIGHUP)",
                keys.len(),
                limits.state_poll_ms()
            );
        }
        Command::Run { listen, hosted } => {
            let hosted = if hosted {
                Some(server::HostedConfig {
                    settings: mousse_relay_plus::settings::from_vars(|k: &str| {
                        std::env::var_os(k)
                    })?,
                    build_id: format!("mousse-relay {}", env!("CARGO_PKG_VERSION")),
                })
            } else {
                None
            };
            let dir = StateDir::open(&cli.state).map_err(s)?;
            let (_, port, _) = dir.public().map_err(s)?;
            let listen = listen.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], port)));
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            rt.block_on(async move {
                let running = server::start(ServerConfig {
                    state: dir,
                    listen,
                    limits,
                    hosted,
                })
                .await?;
                eprintln!(
                    "mousse-relay: relay {} listening on {}",
                    hex(&running.relay_id.0),
                    running.local_addr
                );
                shutdown_signal().await;
                eprintln!("mousse-relay: stopping");
                running.stop().await
            })?;
        }
    }
    Ok(())
}

/// Core dumps off before anything else runs (design §B.15, §B.16): a crash
/// must not write the identity key or spliced bytes to disk, wherever the
/// relay runs (the image has no shell to set `ulimit -c 0`). The hard limit
/// goes to 0 too, so nothing in the process can raise it again. The process
/// is also made non-dumpable (`PR_SET_DUMPABLE` 0), so other processes of
/// the same user cannot attach to it or read its memory through `/proc`.
///
/// Debug builds only: `MOUSSE_NET_RELAY_TEST_KEEP_DUMPABLE=1` keeps the
/// process dumpable, so `phase3.marker` can sample the relay's memory.
/// Release builds ignore it.
fn no_core_dumps() {
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{
            set_dumpable_behavior, setrlimit, DumpableBehavior, Resource, Rlimit,
        };
        let none = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        if let Err(e) = setrlimit(Resource::Core, none) {
            eprintln!("mousse-relay: cannot turn core dumps off: {e}");
        }
        let keep = cfg!(debug_assertions)
            && std::env::var_os(limits::TEST_KEEP_DUMPABLE).is_some_and(|v| v == "1");
        // The `relay-dumpable` control build (tests only) leaves it dumpable.
        if !keep && !cfg!(mousse_control = "relay-dumpable") {
            if let Err(e) = set_dumpable_behavior(DumpableBehavior::NotDumpable) {
                eprintln!("mousse-relay: cannot make the process non-dumpable: {e}");
            }
        }
    }
}

/// This process's core-dump limit and whether it is dumpable (Linux), for
/// `status --json`.
fn process_hardening() -> serde_json::Value {
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{dumpable_behavior, getrlimit, DumpableBehavior, Resource};
        let core = getrlimit(Resource::Core);
        serde_json::json!({
            "dumpable": dumpable_behavior().ok().map(|d| d != DumpableBehavior::NotDumpable),
            "core_limit": core.current,
            "core_limit_max": core.maximum,
        })
    }
    #[cfg(not(target_os = "linux"))]
    serde_json::json!({})
}

/// SHA-256 of the running executable, as `SHA256SUMS` lists it.
fn executable_sha256() -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let exe = std::env::current_exe().map_err(|e| format!("own executable: {e}"))?;
    let mut file = std::fs::File::open(&exe).map_err(|e| format!("{}: {e}", exe.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf)
            .map_err(|e| format!("{}: {e}", exe.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// The state directory's files: names and sizes, never contents.
fn state_listing(dir: &std::path::Path) -> Result<Vec<serde_json::Value>, String> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let meta = entry
            .metadata()
            .map_err(|e| format!("{}: {e}", entry.path().display()))?;
        files.push(serde_json::json!({
            "name": entry.file_name().to_string_lossy(),
            "bytes": meta.len(),
            "dir": meta.is_dir(),
        }));
    }
    files.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(files)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("signal handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
