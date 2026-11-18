//! `mousse-helper`: one Mousse endpoint (one profile on one device) on the
//! command line. Pair in person, list and remove grants, and open terminals.
#![forbid(unsafe_code)]

#[cfg(all(
    not(debug_assertions),
    any(
        mousse_control = "skip-pin-check",
        mousse_control = "keep-removed-grant",
        mousse_control = "shared-endpoint-state",
        mousse_control = "allow-break-env"
    )
))]
compile_error!("a mousse_control build has a deliberate defect and is for tests only; build it without --release");

mod ipc;
mod peer;
mod serve;
mod term;

use std::io::{BufRead, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};
use mousse_net_core::grants::GrantId;
use mousse_net_io::keystore::KeyStorage;
use mousse_net_io::store::{short_id, GrantStore};
use mousse_net_io::Endpoint;
use serde_json::{json, Value};

/// One Mousse endpoint: pairing, grants and terminal channels.
#[derive(Parser)]
#[command(name = "mousse-helper", version)]
struct Cli {
    /// The endpoint's state directory (one per profile).
    #[arg(long, global = true, env = "MOUSSE_HELPER_STATE")]
    state: Option<PathBuf>,
    /// Keep the identity key in a plain file instead of the OS keystore.
    /// For tests and headless runs only; needed on every command.
    #[arg(long, global = true)]
    insecure_file_key: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create this endpoint: a new identity key and state directory.
    Init {
        /// An opaque profile id (default: a new random one).
        #[arg(long)]
        profile: Option<String>,
    },
    /// Show this endpoint's device id and port.
    Id,
    /// Run the host: listen, pair, and serve terminals until stopped.
    Serve {
        /// Address to listen on. Use 0.0.0.0 to listen on the LAN.
        #[arg(long, default_value = "127.0.0.1")]
        listen_ip: IpAddr,
        /// A fixed port from now on (0: go back to a port the OS picks).
        /// Without it, the port picked at the first start is kept.
        #[arg(long)]
        port: Option<u16>,
        /// Approve the next in-person join without asking.
        #[arg(long)]
        approve_next: bool,
        /// Don't advertise on mDNS (it is off anyway on loopback).
        #[arg(long)]
        no_mdns: bool,
        /// The name paired devices see (default: this computer's name).
        #[arg(long)]
        name: Option<String>,
    },
    /// Make an in-person invitation on the running host, print the ticket
    /// and a QR code, and answer "Is the device next to you?".
    Invite {
        /// Answer yes without asking.
        #[arg(long)]
        approve_next: bool,
        /// Print only the ticket line, no QR code.
        #[arg(long)]
        no_qr: bool,
    },
    /// Pair with a host using its ticket.
    Join {
        /// The ticket (the fragment, or a link containing `#`).
        ticket: String,
        /// The name the host sees (default: this computer's name).
        #[arg(long)]
        name: Option<String>,
        /// Address to use instead of the ticket's, as tcp://host:port.
        #[arg(long = "route")]
        routes: Vec<String>,
    },
    /// List the hosts this endpoint paired with.
    Peers,
    /// List the devices this endpoint has granted.
    Grants,
    /// Remove a grant. Its channels close at once.
    Remove {
        /// The grant id (see `grants`).
        grant: u64,
        /// Also deny the device on this endpoint.
        #[arg(long)]
        deny: bool,
    },
    /// Stop the running host.
    Stop,
    /// Open a terminal on a paired host.
    Term {
        /// The host's name or the start of its device id.
        peer: String,
        /// Address to use instead of the stored ones, as tcp://host:port.
        #[arg(long = "route")]
        routes: Vec<String>,
        /// Command to run instead of the shell.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Cross-machine slice check, run on the dialling side: pair, run a
    /// command, wait for the host to remove this device, check a new
    /// connection is refused, and write a result file.
    SliceCheck {
        /// The host's ticket.
        #[arg(long)]
        ticket: String,
        /// The name the host sees.
        #[arg(long)]
        name: Option<String>,
        /// Address to use instead of the ticket's.
        #[arg(long = "route")]
        routes: Vec<String>,
        /// Seconds to wait for the removal.
        #[arg(long, default_value_t = 300)]
        removal_timeout: u64,
        /// Where to write the result JSON.
        #[arg(long)]
        out: Option<PathBuf>,
        /// The target cell named in the result.
        #[arg(long, default_value = "pc-to-mac-lan")]
        target: String,
        /// The control this run exercises, recorded in the result.
        #[arg(long)]
        control: Option<String>,
        /// The build id recorded in the result (default: from git).
        #[arg(long)]
        build: Option<String>,
        /// Command to run on the host.
        #[arg(last = true)]
        command: Vec<String>,
    },
}

fn computer_name() -> String {
    let name = gethostname::gethostname().to_string_lossy().into_owned();
    let mut out: String = name.chars().filter(|c| !c.is_control()).collect();
    while out.len() > 64 {
        out.pop();
    }
    if out.is_empty() {
        "computer".into()
    } else {
        out
    }
}

fn storage(insecure: bool) -> KeyStorage {
    if insecure {
        KeyStorage::InsecureFile
    } else {
        KeyStorage::OsKeystore
    }
}

/// Open the endpoint in `dir` (`shared` for caller commands). A process
/// that just exited may hold its
/// lock for a moment (Windows releases it asynchronously), so a held lock
/// is retried for up to two seconds before giving up.
pub fn open_endpoint(dir: &Path, shared: bool) -> Result<Endpoint, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let opened = if shared {
            Endpoint::open_shared(dir)
        } else {
            Endpoint::open(dir)
        };
        match opened {
            Ok(endpoint) => return Ok(endpoint),
            Err(mousse_net_io::NetError::Refused(_)) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn print_grants(reply: &Value) {
    let list = reply
        .get("grants")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if list.is_empty() {
        println!("no grants");
    }
    for g in list {
        println!(
            "{}  {}  {}  {}  connections {}",
            g["id"],
            g["device"].as_str().unwrap_or(""),
            g["name"].as_str().unwrap_or(""),
            g["role"].as_str().unwrap_or(""),
            g["connections"]
        );
    }
}

/// Grants straight from the file, when no host is running.
fn offline_grants(dir: &Path) -> Result<Value, String> {
    let endpoint = open_endpoint(dir, true)?;
    let table = GrantStore::in_dir(&endpoint.grants_dir())
        .load()
        .map_err(|e| e.to_string())?;
    let list: Vec<Value> = table
        .grants()
        .map(|g| {
            json!({
                "id": g.id.0,
                "name": g.name,
                "device": short_id(&g.identity),
                "role": format!("{:?}", g.role),
                "connections": 0,
            })
        })
        .collect();
    Ok(json!({ "grants": list }))
}

fn offline_remove(dir: &Path, grant: u64, deny: bool) -> Result<(), String> {
    let endpoint = open_endpoint(dir, false)?;
    let store = GrantStore::in_dir(&endpoint.grants_dir());
    let mut table = store.load().map_err(|e| e.to_string())?;
    let Some(identity) = table.get(GrantId(grant)).map(|g| g.identity) else {
        return Err(format!("no grant {grant}"));
    };
    if deny {
        let now = mousse_net_core::UnixTime(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        table.deny(identity, now);
    } else {
        table.remove(GrantId(grant));
    }
    store.save(&table).map_err(|e| e.to_string())
}

fn ask_yes_no(question: &str) -> bool {
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "Yes")
}

async fn invite(dir: &Path, approve_next: bool, no_qr: bool) -> Result<(), String> {
    let mut ch = ipc::request(dir, json!({"cmd": "invite"}))
        .await?
        .ok_or("no host is running for this endpoint (start `serve` first)")?;
    let first = ch
        .recv()
        .await?
        .ok_or("the host closed the control channel")?;
    if let Some(e) = first.get("error").and_then(Value::as_str) {
        return Err(e.to_owned());
    }
    let ticket = first["ticket"].as_str().unwrap_or("").to_owned();
    println!("TICKET {ticket}");
    if !no_qr {
        if let Ok(code) = qrcode::QrCode::new(ticket.as_bytes()) {
            let art = code
                .render::<qrcode::render::unicode::Dense1x2>()
                .quiet_zone(true)
                .build();
            println!("{art}");
        }
    }
    let routes: Vec<String> = first["routes"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    println!("routes: {}", routes.join(" "));
    println!("waiting for the device to join (the ticket is valid for 10 minutes)");
    let _ = std::io::stdout().flush();
    loop {
        let Some(event) = ch.recv().await? else {
            return Err("the host closed the control channel".into());
        };
        match event.get("event").and_then(Value::as_str) {
            Some("approval") => {
                let question = format!(
                    "\"{}\" ({}) wants to pair. Is the device next to you?",
                    event["name"].as_str().unwrap_or(""),
                    event["device"].as_str().unwrap_or("")
                );
                let yes = if approve_next {
                    println!("{question} [y/N] y (--approve-next)");
                    true
                } else {
                    tokio::task::spawn_blocking(move || ask_yes_no(&question))
                        .await
                        .unwrap_or(false)
                };
                ch.send(&json!({"answer": yes})).await?;
            }
            Some("enrolled") => {
                println!(
                    "paired: grant {} for {}",
                    event["grant"],
                    event["device"].as_str().unwrap_or("")
                );
                return Ok(());
            }
            Some("ended") => {
                return Err(format!(
                    "the invitation ended: {}",
                    event["reason"].as_str().unwrap_or("")
                ))
            }
            _ => {
                if let Some(e) = event.get("error").and_then(Value::as_str) {
                    return Err(e.to_owned());
                }
            }
        }
    }
}

async fn run(cli: Cli) -> Result<i32, String> {
    let dir = cli.state.unwrap_or_else(serve::default_state_dir);
    let insecure = cli.insecure_file_key;
    match cli.command {
        Command::Init { profile } => {
            let (endpoint, _) = Endpoint::create(&dir, profile.as_deref(), storage(insecure))
                .map_err(|e| e.to_string())?;
            println!(
                "created endpoint {} in {}",
                short_id(&endpoint.identity()),
                dir.display()
            );
        }
        Command::Id => {
            if let Some(reply) = ipc::call(&dir, json!({"cmd": "status"})).await? {
                println!(
                    "{} serving at {}",
                    reply["device"].as_str().unwrap_or(""),
                    reply["routes"]
                );
            } else {
                let endpoint = open_endpoint(&dir, true)?;
                println!(
                    "{} port {} profile {}",
                    short_id(&endpoint.identity()),
                    endpoint
                        .fixed_port()
                        .or(endpoint.kept_port())
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "not yet picked".into()),
                    endpoint.profile_id()
                );
            }
        }
        Command::Serve {
            listen_ip,
            port,
            approve_next,
            no_mdns,
            name,
        } => {
            let opts = serve::ServeOptions {
                name: name.unwrap_or_else(computer_name),
                listen_ip,
                port,
                approve_next,
                mdns: !no_mdns,
            };
            serve::run(&dir, insecure, opts).await?;
        }
        Command::Invite {
            approve_next,
            no_qr,
        } => invite(&dir, approve_next, no_qr).await?,
        Command::Join {
            ticket,
            name,
            routes,
        } => {
            let ticket = peer::parse_ticket(&ticket)?;
            let side = peer::CallerSide::open(&dir, insecure)?;
            println!("joining; the host owner is asked to confirm");
            let (_conn, record) =
                peer::join(&side, &ticket, &name.unwrap_or_else(computer_name), &routes).await?;
            println!(
                "paired with {} ({})",
                record.name,
                short_id(&ticket.host_identity)
            );
        }
        Command::Peers => peer::print_peers(&dir)?,
        Command::Grants => match ipc::call(&dir, json!({"cmd": "grants"})).await? {
            Some(reply) => print_grants(&reply),
            None => print_grants(&offline_grants(&dir)?),
        },
        Command::Remove { grant, deny } => {
            match ipc::call(&dir, json!({"cmd": "remove", "grant": grant, "deny": deny})).await? {
                Some(_) => println!("removed grant {grant}"),
                None => {
                    offline_remove(&dir, grant, deny)?;
                    println!("removed grant {grant} (host not running)");
                }
            }
        }
        Command::Stop => match ipc::call(&dir, json!({"cmd": "stop"})).await? {
            Some(_) => println!("stopping"),
            None => println!("no host is running for this endpoint"),
        },
        Command::Term {
            peer,
            routes,
            command,
        } => {
            let side = peer::CallerSide::open(&dir, insecure)?;
            return Ok(peer::term(&side, &peer, &routes, command).await);
        }
        Command::SliceCheck {
            ticket,
            name,
            routes,
            removal_timeout,
            out,
            target,
            control,
            build,
            command,
        } => {
            let side = peer::CallerSide::open(&dir, insecure)?;
            let command = if command.is_empty() {
                vec!["uname".into(), "-a".into()]
            } else {
                command
            };
            let opts = peer::SliceCheck {
                ticket,
                name: name.unwrap_or_else(computer_name),
                routes,
                command,
                removal_timeout: Duration::from_secs(removal_timeout),
                out,
                control,
                build,
                target,
            };
            return Ok(peer::slice_check(&side, opts).await);
        }
    }
    Ok(0)
}

fn main() {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cannot start: {e}");
            std::process::exit(2);
        }
    };
    let code = match runtime.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            2
        }
    };
    let _ = std::io::stdout().flush();
    // Exit now: a pending stdin read must not keep the process alive.
    std::process::exit(code)
}
