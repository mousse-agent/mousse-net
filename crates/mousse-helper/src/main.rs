//! `mousse-helper`: one Mousse endpoint (one profile on one device) on the
//! command line. Pair in person, list and remove grants, and open terminals.
#![forbid(unsafe_code)]

#[cfg(all(
    not(debug_assertions),
    any(
        mousse_control = "skip-pin-check",
        mousse_control = "keep-removed-grant",
        mousse_control = "shared-endpoint-state",
        mousse_control = "allow-break-env",
        mousse_control = "read-without-credit",
        mousse_control = "fifo-writer",
        mousse_control = "fin-overtakes",
        mousse_control = "no-revoke-journal",
        mousse_control = "stop-on-mismatch",
        mousse_control = "public-routes",
        mousse_control = "no-rediscovery",
        mousse_control = "auto-send-unknown",
        mousse_control = "new-request-id-on-retry",
        mousse_control = "no-prefetch",
        mousse_control = "pause-all-classes",
        mousse_control = "fund-two-relays",
        mousse_control = "keep-removed-slot",
        mousse_control = "unpinned-manifest",
        mousse_control = "trust-from-plus",
        mousse_control = "no-tag-quota",
        mousse_control = "no-preauth-budget",
        mousse_control = "shared-preauth-pool",
        mousse_control = "ws-slot-after-headers",
        mousse_control = "ipc-unbounded-line",
        mousse_control = "ipc-handoff-drops-buffer",
        mousse_control = "join-only-frees-slot",
        mousse_control = "join-only-outlives-invitation",
        mousse_control = "fence-at-accept-only",
        mousse_control = "fence-tcp-only",
        mousse_control = "enroll-while-paused",
        mousse_control = "repair-skips-slot",
        mousse_control = "repair-skips-fence",
        mousse_control = "limits-raise",
        mousse_control = "no-endpoint-lock",
        mousse_control = "ws-allow-origin",
        mousse_control = "plain-ws-off-loopback",
        mousse_control = "release-test-root",
        mousse_control = "accept-new-host-key",
        mousse_control = "user-config-in-pipe",
        mousse_control = "trust-unprobed-key",
        mousse_control = "pipe-no-token",
        mousse_control = "no-preamble-skip",
        mousse_control = "pipe-outlives-helper",
        mousse_control = "window-per-route",
        mousse_control = "peer-ssh-routes",
        mousse_control = "loopback-routes",
        mousse_control = "plain-ws-from-ticket",
        mousse_control = "unapproved-public",
        mousse_control = "unapproved-last-route",
        mousse_control = "upgrade-trusts-routes",
        mousse_control = "resolve-again",
        mousse_control = "unlisted-allowed",
        mousse_control = "stale-renewal-routes",
        mousse_control = "unbounded-candidates",
        mousse_control = "ssh-races-lan",
        mousse_control = "bind-all-lan-off",
        mousse_control = "inbound-before-live",
        mousse_control = "journal-pins-link",
        mousse_control = "fabricate-pending-kind2",
        mousse_control = "joiner-records-in-memory",
        mousse_control = "link-accepts-kind1",
        mousse_control = "no-completion-record",
        mousse_control = "done-pin-only",
        mousse_control = "replay-after-removal",
        mousse_control = "join-ignores-removal",
        mousse_control = "removal-leaves-pending",
        mousse_control = "role-edit-keeps-reverse-path",
        mousse_control = "restricted-grant-served-to-legacy-app",
        mousse_control = "restricted-grant-opens-standalone-terminal",
        mousse_control = "demoted-owner-keeps-grants",
        mousse_control = "role-edit-keeps-queued-announcement",
        mousse_control = "role-edit-delivers-on-closing-path",
        mousse_control = "suspended-reads-as-revoked",
        mousse_control = "select-after-route-cap",
        mousse_control = "selector-adds-address",
        mousse_control = "relay-reservation-overbooks",
        mousse_control = "invite-all-ways",
        mousse_control = "check-dials-destination",
        mousse_control = "check-auto-approves-public",
        mousse_control = "probe-accepts-outer-tls",
        mousse_control = "probe-sends-join-proof",
        mousse_control = "probe-dials-unapproved",
        mousse_control = "probe-opens-relay-circuit",
        mousse_control = "probe-restarts-deadline",
        mousse_control = "probe-cancel-keeps-slot",
        mousse_control = "way-invite-drops-role",
        mousse_control = "local-revoke-forgets-peer",
        mousse_control = "local-revoke-keeps-inbound-access",
        mousse_control = "completion-omits-relay-admission",
        mousse_control = "completion-replays-retired-tag",
        mousse_control = "completion-stores-clear-tag",
        mousse_control = "relay-replay-after-forget"
    )
))]
compile_error!("a mousse_control build has a deliberate defect and is for tests only; build it without --release");

#[cfg(all(not(debug_assertions), feature = "test-in-person"))]
compile_error!("test-in-person lets a typed ticket count as scanned from the host's screen; it is for test builds only, build it without --release");

// The same controls (and `test-in-person`) in a release-profile build, even
// with debug assertions on. `build.rs` passes the profile in
// `MOUSSE_BUILD_PROFILE`.
#[cfg(any(
    mousse_control = "skip-pin-check",
    mousse_control = "keep-removed-grant",
    mousse_control = "shared-endpoint-state",
    mousse_control = "allow-break-env",
    mousse_control = "read-without-credit",
    mousse_control = "fifo-writer",
    mousse_control = "fin-overtakes",
    mousse_control = "no-revoke-journal",
    mousse_control = "stop-on-mismatch",
    mousse_control = "public-routes",
    mousse_control = "no-rediscovery",
    mousse_control = "auto-send-unknown",
    mousse_control = "new-request-id-on-retry",
    mousse_control = "no-prefetch",
    mousse_control = "pause-all-classes",
    mousse_control = "fund-two-relays",
    mousse_control = "keep-removed-slot",
    mousse_control = "unpinned-manifest",
    mousse_control = "trust-from-plus",
    mousse_control = "no-tag-quota",
    mousse_control = "no-preauth-budget",
    mousse_control = "shared-preauth-pool",
    mousse_control = "ws-slot-after-headers",
    mousse_control = "ipc-unbounded-line",
    mousse_control = "ipc-handoff-drops-buffer",
    mousse_control = "join-only-frees-slot",
    mousse_control = "join-only-outlives-invitation",
    mousse_control = "fence-at-accept-only",
    mousse_control = "fence-tcp-only",
    mousse_control = "enroll-while-paused",
    mousse_control = "repair-skips-slot",
    mousse_control = "repair-skips-fence",
    mousse_control = "limits-raise",
    mousse_control = "no-endpoint-lock",
    mousse_control = "ws-allow-origin",
    mousse_control = "plain-ws-off-loopback",
    mousse_control = "release-test-root",
    mousse_control = "accept-new-host-key",
    mousse_control = "user-config-in-pipe",
    mousse_control = "trust-unprobed-key",
    mousse_control = "pipe-no-token",
    mousse_control = "no-preamble-skip",
    mousse_control = "pipe-outlives-helper",
    mousse_control = "window-per-route",
    mousse_control = "peer-ssh-routes",
    mousse_control = "loopback-routes",
    mousse_control = "plain-ws-from-ticket",
    mousse_control = "unapproved-public",
    mousse_control = "unapproved-last-route",
    mousse_control = "upgrade-trusts-routes",
    mousse_control = "resolve-again",
    mousse_control = "unlisted-allowed",
    mousse_control = "stale-renewal-routes",
    mousse_control = "unbounded-candidates",
    mousse_control = "ssh-races-lan",
    mousse_control = "bind-all-lan-off",
    mousse_control = "inbound-before-live",
    mousse_control = "journal-pins-link",
    mousse_control = "fabricate-pending-kind2",
    mousse_control = "joiner-records-in-memory",
    mousse_control = "link-accepts-kind1",
    mousse_control = "no-completion-record",
    mousse_control = "done-pin-only",
    mousse_control = "replay-after-removal",
    mousse_control = "join-ignores-removal",
    mousse_control = "removal-leaves-pending",
    mousse_control = "role-edit-keeps-reverse-path",
    mousse_control = "restricted-grant-served-to-legacy-app",
    mousse_control = "restricted-grant-opens-standalone-terminal",
    mousse_control = "demoted-owner-keeps-grants",
    mousse_control = "role-edit-keeps-queued-announcement",
    mousse_control = "role-edit-delivers-on-closing-path",
    mousse_control = "suspended-reads-as-revoked",
    mousse_control = "select-after-route-cap",
    mousse_control = "selector-adds-address",
    mousse_control = "relay-reservation-overbooks",
    mousse_control = "invite-all-ways",
    mousse_control = "check-dials-destination",
    mousse_control = "check-auto-approves-public",
    mousse_control = "probe-accepts-outer-tls",
    mousse_control = "probe-sends-join-proof",
    mousse_control = "probe-dials-unapproved",
    mousse_control = "probe-opens-relay-circuit",
    mousse_control = "probe-restarts-deadline",
    mousse_control = "probe-cancel-keeps-slot",
    mousse_control = "way-invite-drops-role",
    mousse_control = "local-revoke-forgets-peer",
    mousse_control = "local-revoke-keeps-inbound-access",
    mousse_control = "completion-omits-relay-admission",
    mousse_control = "completion-replays-retired-tag",
    mousse_control = "completion-stores-clear-tag",
    mousse_control = "relay-replay-after-forget",
    feature = "test-in-person"
))]
const _: () = {
    let profile = env!("MOUSSE_BUILD_PROFILE").as_bytes();
    let release = b"release";
    let mut same = profile.len() == release.len();
    let mut i = 0;
    while same && i < profile.len() {
        same = profile[i] == release[i];
        i += 1;
    }
    assert!(
        !same,
        "a mousse_control or test-in-person build is for tests only; build it without --release"
    );
};

mod app;
mod applog;
mod engine;
mod ipc;
mod limits;
mod peer;
mod pipe;
mod plus;
mod revoke;
mod ssh;

/// This build: `<commit>[-dirty]+<profile>`, fixed at compile time (see
/// `build.rs`; `MOUSSE_BUILD_ID` overrides it).
pub const BUILD: &str = env!("MOUSSE_HELPER_BUILD");

/// `--version`: the package version, the build and the must-fail control
/// compiled in (`none` normally).
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " build ",
    env!("MOUSSE_HELPER_BUILD"),
    " control ",
    env!("MOUSSE_HELPER_CONTROL")
);
mod serve;
mod term;

use std::collections::VecDeque;
use std::io::{BufRead, Read, Write};
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
#[command(name = "mousse-helper", version = VERSION)]
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
        /// Run for the Mousse app: exit at once when stdin closes (the app
        /// is gone), so an app killed during a first start leaves no
        /// `init` behind.
        #[arg(long)]
        app: bool,
        #[command(flatten)]
        headless: Headless,
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
        /// Don't advertise on mDNS (it is off anyway on loopback).
        #[arg(long)]
        no_mdns: bool,
        /// Run the loopback ws listener for a tunnel client on this port
        /// (0: any). Without it the listener runs, on its kept port, only
        /// with --tunnel.
        #[arg(long)]
        ws_port: Option<u16>,
        /// The public wss URL of a tunnel to the ws listener, advertised in
        /// tickets (repeatable).
        #[arg(long = "tunnel")]
        tunnels: Vec<String>,
        /// The name paired devices see (default: this computer's name).
        #[arg(long)]
        name: Option<String>,
        /// Talk to the Mousse app on stdin and stdout (framed; see
        /// docs/phase1a-design.md §2). The helper's own lines go to
        /// `helper.log` in the state directory, and it exits when stdin
        /// closes.
        #[arg(long, conflicts_with = "headless")]
        app: bool,
        #[command(flatten)]
        headless: Headless,
    },
    /// Make an invitation on the running host and print the ticket and a QR
    /// code. In person (the default), answer "Is the device next to you?";
    /// with --link, show the code to type on the joining device. Every
    /// in-person request is put to the owner; none is approved unseen.
    Invite {
        /// A send link: the joining device types a 6-digit code shown here,
        /// a fresh one for each attempt.
        #[arg(long)]
        link: bool,
        /// Show the ticket as a QR code in the terminal, for the phone's
        /// in-app scanner (the default in person).
        #[arg(long, conflicts_with_all = ["link", "no_qr"])]
        qr: bool,
        /// Print only the ticket line, no QR code.
        #[arg(long)]
        no_qr: bool,
    },
    /// Pair with a host using its ticket.
    Join {
        /// The ticket (the fragment, or a link containing `#`).
        ticket: String,
        #[command(flatten)]
        arrival: TicketArrival,
        /// The name the host sees in person (default: this computer's
        /// name). A send link sends the computer name only.
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
    /// The remote end of an SSH route (run by SSH, not by hand): pass
    /// stdin and stdout to the running helper of the profile with this
    /// selector, after the `mousse-ssh/1` marker. Exits 2 (not running),
    /// 3 (no such profile, or networking off) or 4 (refused).
    Pipe {
        /// The profile's selector, from `$MOUSSE_HOME/net-engine/endpoints.json`.
        #[arg(long)]
        profile: String,
    },
    /// Cross-machine slice check, run on the dialling side: pair, run a
    /// command, wait for the host to remove this device, check a new
    /// connection is refused, and write a result file.
    SliceCheck {
        /// The host's ticket.
        #[arg(long)]
        ticket: String,
        #[command(flatten)]
        arrival: TicketArrival,
        /// The name the host sees in person. A send link sends the
        /// computer name only.
        #[arg(long)]
        name: Option<String>,
        /// Address to use instead of the ticket's.
        #[arg(long = "route")]
        routes: Vec<String>,
        /// Seconds to wait for the removal (default:
        /// MOUSSE_NET_REMOVAL_WAIT_SECS, 300).
        #[arg(long)]
        removal_timeout: Option<u64>,
        /// Where to write the result JSON.
        #[arg(long)]
        out: Option<PathBuf>,
        /// The target cell named in the result.
        #[arg(long, default_value = "pc-to-mac-lan")]
        target: String,
        /// The control this run exercises, recorded in the result.
        #[arg(long)]
        control: Option<String>,
        /// The host's build, from the `ready` line its `serve` printed. Used
        /// when the run never gets to ask the host (a control that fails
        /// before pairing); otherwise the host's own answer must match it.
        #[arg(long)]
        host_build: Option<String>,
        /// Command to run on the host.
        #[arg(last = true)]
        command: Vec<String>,
    },
}

/// A headless endpoint (design §B.13): one endpoint on a server, no app,
/// driven by this CLI. Its key goes in the OS keystore when one takes it,
/// otherwise in an owner-only file in the state directory.
#[derive(clap::Args, Debug, Clone, Copy)]
struct Headless {
    /// No app: create the endpoint on first start if the state directory
    /// has none, with its key in the OS keystore or, where there is none,
    /// in an owner-only file (0600) in the state directory.
    #[arg(long)]
    headless: bool,
    /// With --headless: keep the key in the owner-only file even if an OS
    /// keystore is available.
    #[arg(long, requires = "headless")]
    key_file: bool,
}

impl Headless {
    fn storage(self) -> KeyStorage {
        if self.key_file {
            KeyStorage::File
        } else {
            KeyStorage::KeystoreOrFile
        }
    }
}

/// Create the endpoint in `dir` for a headless run and say where its key
/// went.
fn create_headless(
    dir: &Path,
    profile: Option<&str>,
    headless: Headless,
) -> Result<Endpoint, String> {
    let (endpoint, key) =
        Endpoint::create(dir, profile, headless.storage()).map_err(|e| e.to_string())?;
    println!(
        "created endpoint {} in {}",
        short_id(&endpoint.identity()),
        dir.display()
    );
    match key.storage() {
        KeyStorage::OsKeystore => println!("identity key: in the OS keystore"),
        _ => println!(
            "identity key: in an owner-only file in {} (no OS keystore used)",
            dir.display()
        ),
    }
    Ok(endpoint)
}

/// How a ticket reached this device. A ticket given on the command line
/// counts as sent (pasted or opened as a link): only the app's own scanner
/// can say it was scanned from the host's screen, so an in-person ticket
/// does not pair here. Test builds (feature `test-in-person`, refused in
/// release builds) take `--in-person` to stand in for the scanner.
#[derive(clap::Args, Debug)]
struct TicketArrival {
    /// Test builds only: the ticket counts as scanned from the host's
    /// screen, as the app's scanner would say.
    #[cfg(feature = "test-in-person")]
    #[arg(long)]
    in_person: bool,
}

impl TicketArrival {
    fn arrival(&self) -> mousse_net_core::pairing::Arrival {
        #[cfg(feature = "test-in-person")]
        if self.in_person {
            return mousse_net_core::pairing::Arrival::InAppScan;
        }
        mousse_net_core::pairing::Arrival::Link
    }
}

fn computer_name() -> String {
    let name = gethostname::gethostname().to_string_lossy().into_owned();
    let mut out: String = name.chars().filter(|c| !c.is_control()).collect();
    let max = usize::try_from(limits::helper().computer_name_max_bytes()).unwrap_or(usize::MAX);
    while out.len() > max {
        out.pop();
    }
    if out.is_empty() {
        "computer".into()
    } else {
        out
    }
}

/// A name another device chose, made safe to print on one line: control
/// characters (newlines, escape sequences), bidirectional and invisible
/// formatting characters and backslashes are written as escapes, so the
/// name can neither start a fake log line nor drive the terminal.
pub fn printable(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control()
                || matches!(
                    c,
                    '\u{200B}'..='\u{200F}'
                        | '\u{2028}'..='\u{202E}'
                        | '\u{2060}'..='\u{2069}'
                        | '\u{FEFF}'
                ) =>
            {
                out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out
}

fn storage(insecure: bool) -> KeyStorage {
    if insecure {
        KeyStorage::InsecureFile
    } else {
        KeyStorage::OsKeystore
    }
}

/// Open the endpoint in `dir` (`shared` for caller commands). A process
/// that just exited may hold its lock for a moment (Windows releases it
/// asynchronously), so a held lock is retried for up to
/// `ENDPOINT_LOCK_WAIT_MS` before giving up.
pub fn open_endpoint(dir: &Path, shared: bool) -> Result<Endpoint, String> {
    let limits = limits::helper();
    let deadline = std::time::Instant::now() + limits::ms(limits.endpoint_lock_wait_ms());
    loop {
        let opened = if shared {
            Endpoint::open_shared(dir)
        } else {
            Endpoint::open(dir)
        };
        match opened {
            Ok(endpoint) => return Ok(endpoint),
            Err(mousse_net_io::NetError::Refused(_)) if std::time::Instant::now() < deadline => {
                std::thread::sleep(limits::ms(limits.endpoint_lock_retry_ms()));
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
            printable(g["name"].as_str().unwrap_or("")),
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

/// Ends the process when stdin closes or fails: the app that started this
/// helper is gone, whether it stopped or was killed outright.
fn exit_when_stdin_closes() {
    std::thread::spawn(|| {
        let mut buf = [0u8; 256];
        let mut stdin = std::io::stdin();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => {
                    // Not `eprintln!`: it panics when stderr is a pipe
                    // to the app that is gone, and the process would stay.
                    let _ = writeln!(std::io::stderr(), "error: the app is gone");
                    std::process::exit(3);
                }
                Ok(_) => {}
            }
        }
    });
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

async fn invite(dir: &Path, link: bool, no_qr: bool) -> Result<(), String> {
    let mut ch = ipc::request(dir, json!({"cmd": "invite", "link": link}))
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
    let valid = peer::parse_ticket(&ticket)
        .map(|t| t.expires_at.secs().saturating_sub(peer::now_secs()))
        .unwrap_or(0);
    println!(
        "waiting for the device to join (the ticket is valid for {})",
        validity(valid)
    );
    let _ = std::io::stdout().flush();
    // One question on screen at a time, in the order asked. Events keep
    // arriving meanwhile: the invitation may pair or end while one is open.
    let mut queued: VecDeque<(String, String)> = VecDeque::new();
    let mut asking: Option<(String, tokio::task::JoinHandle<bool>)> = None;
    loop {
        if asking.is_none() {
            if let Some((request, question)) = queued.pop_front() {
                let ask = tokio::task::spawn_blocking(move || ask_yes_no(&question));
                asking = Some((request, ask));
            }
        }
        let answered = async {
            match asking.as_mut() {
                Some((_, ask)) => ask.await.unwrap_or(false),
                None => std::future::pending().await,
            }
        };
        let event = tokio::select! {
            yes = answered => {
                // The answer names its request: it never applies to
                // another device or a newer request.
                if let Some((request, _)) = asking.take() {
                    ch.send(&json!({"answer": yes, "request": request})).await?;
                }
                continue;
            }
            event = ch.recv() => event?,
        };
        let Some(event) = event else {
            return Err("the host closed the control channel".into());
        };
        match event.get("event").and_then(Value::as_str) {
            Some("code") => {
                println!(
                    "CODE {} (type it on the joining device)",
                    event["code"].as_str().unwrap_or("")
                );
                let _ = std::io::stdout().flush();
            }
            Some("approval") => {
                let request = event["request"].as_str().unwrap_or("").to_owned();
                let question = format!(
                    "\"{}\" ({}) wants to pair. Is the device next to you?",
                    printable(event["name"].as_str().unwrap_or("")),
                    event["device"].as_str().unwrap_or("")
                );
                queued.push_back((request, question));
            }
            Some("stale") => {
                println!(
                    "that request is no longer waiting: {}",
                    event["error"].as_str().unwrap_or("")
                );
                let _ = std::io::stdout().flush();
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

/// How long a ticket stays valid, for people: whole minutes from a minute
/// up, else seconds.
fn validity(secs: u64) -> String {
    if secs < 60 {
        return format!("{secs} s");
    }
    let minutes = (secs + 30) / 60;
    let unit = if minutes == 1 { "minute" } else { "minutes" };
    if secs.is_multiple_of(60) {
        format!("{minutes} {unit}")
    } else {
        format!("about {minutes} {unit}")
    }
}

async fn run(cli: Cli) -> Result<i32, String> {
    let dir = cli.state.unwrap_or_else(serve::default_state_dir);
    // Absolute from here on: the control socket of a long state path is
    // reached after changing to the state directory (Phase 1b §3.3).
    let dir = std::path::absolute(&dir).unwrap_or(dir);
    let insecure = cli.insecure_file_key;
    match cli.command {
        Command::Init {
            profile,
            app,
            headless,
        } => {
            if app {
                exit_when_stdin_closes();
            }
            let hold = crate::limits::helper().init_hold_ms();
            if hold > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(hold)).await;
            }
            if headless.headless {
                create_headless(&dir, profile.as_deref(), headless)?;
                return Ok(0);
            }
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
            no_mdns,
            ws_port,
            tunnels,
            name,
            app,
            headless,
        } => {
            // A headless first start keeps the endpoint it created, and
            // with it the endpoint's locks, straight into serving: no other
            // process can open it in between. Another first start that lost
            // the race finds the endpoint made and refuses like any second
            // process.
            let mut created = None;
            if headless.headless && !Endpoint::exists(&dir) {
                match create_headless(&dir, None, headless) {
                    Ok(endpoint) => created = Some(endpoint),
                    Err(_) if Endpoint::exists(&dir) => {}
                    Err(e) => return Err(e),
                }
            }
            let opts = serve::ServeOptions {
                name: name.unwrap_or_else(computer_name),
                listen_ip,
                port,
                mdns: !no_mdns,
                app,
                ws_port,
                tunnels,
            };
            serve::run(&dir, insecure, opts, created).await?;
        }
        Command::Invite { link, qr: _, no_qr } => invite(&dir, link, no_qr).await?,
        Command::Join {
            ticket,
            arrival,
            name,
            routes,
        } => {
            let ticket = peer::parse_ticket(&ticket)?;
            let side = peer::CallerSide::open(&dir, insecure)?;
            let name = peer::join_name(&ticket, name, computer_name());
            let joined = peer::join(&side, &ticket, arrival.arrival(), &name, &routes).await?;
            println!("{}", peer::joined_line(&joined, &ticket.host_identity));
        }
        Command::Peers => peer::print_peers(&dir)?,
        Command::Pipe { profile } => return Ok(pipe::run(&profile).await),
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
            arrival,
            name,
            routes,
            removal_timeout,
            out,
            target,
            control,
            host_build,
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
                arrival: arrival.arrival(),
                name,
                routes,
                command,
                removal_timeout: Duration::from_secs(
                    removal_timeout.unwrap_or(limits::helper().removal_wait_secs()),
                ),
                out,
                control,
                host_build,
                target,
            };
            return Ok(peer::slice_check(&side, opts).await);
        }
    }
    Ok(0)
}

fn main() {
    let cli = Cli::parse();
    // Limits come from MOUSSE_NET_* once, before anything runs.
    if let Err(e) = limits::init_from_env() {
        eprintln!("error: {e}");
        std::process::exit(2);
    }
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
    // In app mode stdout carries the channel. Its writer may be blocked on a
    // full pipe the app stopped reading, holding stdout's lock: a final flush
    // would wait for it forever. What it had not written is lost either way.
    let app_mode = matches!(cli.command, Command::Serve { app: true, .. });
    let code = match runtime.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            2
        }
    };
    if !app_mode {
        let _ = std::io::stdout().flush();
    }
    // Exit now: a pending stdin read must not keep the process alive.
    std::process::exit(code)
}

#[cfg(test)]
mod tests {
    use super::{printable, validity};

    #[test]
    fn the_ticket_validity_reads_in_minutes() {
        assert_eq!(validity(600), "10 minutes");
        assert_eq!(validity(599), "about 10 minutes");
        assert_eq!(validity(60), "1 minute");
        assert_eq!(validity(100), "about 2 minutes");
        assert_eq!(validity(20), "20 s");
    }

    #[test]
    fn a_peer_name_prints_on_one_line_without_terminal_controls() {
        assert_eq!(printable("Ana's laptop"), "Ana's laptop");
        assert_eq!(
            printable("x\nconnected 1234 from 10.0.0.1\r\x1b[2J\t\u{7}"),
            r"x\nconnected 1234 from 10.0.0.1\r\u{1b}[2J\t\u{7}"
        );
        // Bidirectional overrides and invisible characters, and C1 controls.
        assert_eq!(
            printable("a\u{202E}b\u{200B}c\u{2066}d\u{feff}\u{9b}"),
            r"a\u{202e}b\u{200b}c\u{2066}d\u{feff}\u{9b}"
        );
        // A backslash cannot fake an escape.
        assert_eq!(printable(r"a\nb"), r"a\\nb");
        assert!(!printable("\u{85}\u{2028}").chars().any(char::is_control));
    }
}
