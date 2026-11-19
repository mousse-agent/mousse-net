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
#[command(name = "mousse-relay", version, about = "Self-hosted Mousse relay")]
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
    },
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
    Status,
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
        Command::Status => {
            let dir = StateDir::open(&cli.state).map_err(s)?;
            let (_, _, public) = dir.public().map_err(s)?;
            let lists = dir.read().map_err(s)?;
            println!("relay id   {}", hex(&dir.relay_id().map_err(s)?.0));
            println!("public     {public}");
            println!("authorized {}", lists.authorized.len());
            println!("codes      {}", lists.codes.len());
            println!("running    {}", if dir.running() { "yes" } else { "no" });
        }
        Command::Run { listen } => {
            let dir = StateDir::open(&cli.state).map_err(s)?;
            let (_, port, _) = dir.public().map_err(s)?;
            let listen = listen.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], port)));
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            rt.block_on(async move {
                let running = server::start(ServerConfig {
                    state: dir,
                    listen,
                    limits,
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
