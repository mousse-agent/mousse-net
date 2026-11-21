//! `test-sshd`: the SSH test server of `tests/common/sshd.rs` as a program,
//! for app checks that need a real SSH route on loopback (Phase 1b §3.7).
//! Test use only; it is an example, so release packages never carry it.
//!
//!     cargo run -p mousse-helper --example test-sshd -- --port 0 --keys <dir> [--home <dir>]
//!         [--mousse-home <dir>] [--launcher <name>=<path>]... [--preamble <text>]
//!
//! - Listens on `127.0.0.1:<port>` only (0 picks one).
//! - `--keys <dir>` holds throwaway keys, made on the first run and reused
//!   after: `host_ed25519` (the server's host key) and `client_ed25519`
//!   (`.pub` beside it), the only client key the server accepts. It also
//!   writes `ssh_config` there: a `Host mousse-test-sshd` entry for this
//!   server with that identity, no agent, and `known_hosts` in the same
//!   folder (left empty: the app probes and pins the host key itself).
//!   Point `MOUSSE_NET_TEST_SSH_CONFIG` (debug builds) at that file.
//! - Commands run as the current user, with `HOME` (and `USERPROFILE` on
//!   Windows) set to `--home` and `MOUSSE_HOME` to `--mousse-home`
//!   (default `<home>/.mousse`), in that folder. On Unix they run through
//!   `/bin/sh -c`, so `<home>/.mousse/bin` must hold real launchers. On
//!   Windows each `--launcher <name>=<program>` stands in for
//!   `~/.mousse/bin/<name>`; `--launcher mousse-cli=echo` gives the
//!   built-in stand-in that writes the marker and echoes stdin.
//! - Prints one line, `ready port <port> host_key <SHA256:...> config
//!   <path>`, then serves until stdin closes or it is stopped.

#[path = "../tests/common/sshd.rs"]
mod sshd;

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use russh::keys::ssh_key::LineEnding;
use russh::keys::PrivateKey;
use sshd::{Config, Launcher, Shell, TestSshd};

struct Args {
    port: u16,
    keys: PathBuf,
    home: Option<PathBuf>,
    mousse_home: Option<PathBuf>,
    launchers: Vec<(String, String)>,
    preamble: Vec<u8>,
}

fn usage() -> String {
    "usage: test-sshd --port <n> --keys <dir> [--home <dir>] [--mousse-home <dir>] \
     [--launcher <name>=<path>]... [--preamble <text>]"
        .into()
}

fn parse() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let (mut port, mut keys, mut home, mut mousse_home) = (None, None, None, None);
    let mut launchers = Vec::new();
    let mut preamble = Vec::new();
    while let Some(flag) = args.next() {
        let mut value = || {
            args.next()
                .ok_or_else(|| format!("{flag} needs a value\n{}", usage()))
        };
        match flag.as_str() {
            "--port" => {
                port = Some(
                    value()?
                        .parse::<u16>()
                        .map_err(|e| format!("--port: {e}"))?,
                )
            }
            "--keys" => keys = Some(PathBuf::from(value()?)),
            "--home" => home = Some(PathBuf::from(value()?)),
            "--mousse-home" => mousse_home = Some(PathBuf::from(value()?)),
            "--launcher" => {
                let text = value()?;
                let (name, path) = text
                    .split_once('=')
                    .ok_or_else(|| format!("--launcher {text}: expected <name>=<path>"))?;
                launchers.push((name.to_owned(), path.to_owned()));
            }
            "--preamble" => preamble = value()?.into_bytes(),
            other => return Err(format!("unknown argument {other}\n{}", usage())),
        }
    }
    Ok(Args {
        port: port.ok_or_else(usage)?,
        keys: keys.ok_or_else(usage)?,
        home,
        mousse_home,
        launchers,
        preamble,
    })
}

/// The key at `path`, made and saved owner-only if it is not there.
fn key_at(path: &Path) -> Result<PrivateKey, String> {
    if let Ok(text) = std::fs::read_to_string(path) {
        return PrivateKey::from_openssh(&text).map_err(|e| format!("{}: {e}", path.display()));
    }
    let key = sshd::generate_key();
    let text = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| format!("encode a key: {e}"))?;
    std::fs::write(path, text.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
    mousse_net_io::private::restrict_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(key)
}

/// A path as an ssh_config value: double quotes, `%` doubled.
fn quoted(path: &Path) -> String {
    format!("\"{}\"", path.display().to_string().replace('%', "%%"))
}

fn run() -> Result<(), String> {
    let args = parse()?;
    mousse_net_io::private::make_private_dir(&args.keys)
        .map_err(|e| format!("{}: {e}", args.keys.display()))?;
    let host_key = key_at(&args.keys.join("host_ed25519"))?;
    let client_path = args.keys.join("client_ed25519");
    let client_key = key_at(&client_path)?;
    let client_pub = client_key
        .public_key()
        .to_openssh()
        .map_err(|e| format!("encode a key: {e}"))?;
    std::fs::write(
        args.keys.join("client_ed25519.pub"),
        format!("{client_pub}\n"),
    )
    .map_err(|e| format!("client_ed25519.pub: {e}"))?;

    let mut env: Vec<(OsString, OsString)> = Vec::new();
    let mut cwd = None;
    if let Some(home) = &args.home {
        let mousse_home = args
            .mousse_home
            .clone()
            .unwrap_or_else(|| home.join(".mousse"));
        env.push(("HOME".into(), home.clone().into_os_string()));
        if cfg!(windows) {
            env.push(("USERPROFILE".into(), home.clone().into_os_string()));
        }
        env.push(("MOUSSE_HOME".into(), mousse_home.into_os_string()));
        cwd = Some(home.clone());
    } else if let Some(mousse_home) = &args.mousse_home {
        env.push(("MOUSSE_HOME".into(), mousse_home.clone().into_os_string()));
    }
    let launchers: HashMap<String, Launcher> = args
        .launchers
        .iter()
        .map(|(name, path)| {
            let launcher = if path == "echo" {
                Launcher::Echo
            } else {
                Launcher::Program {
                    path: PathBuf::from(path),
                    env: env.clone(),
                }
            };
            (name.clone(), launcher)
        })
        .collect();

    // Bind before the config is written, so it names the real port.
    let server = TestSshd::start_on(
        Config {
            host_key,
            client_key: client_key.public_key().clone(),
            shell: Shell::Default,
            env,
            cwd,
            preamble: args.preamble,
            launchers,
        },
        args.port,
    );
    let known_hosts = args.keys.join("known_hosts");
    if !known_hosts.exists() {
        std::fs::write(&known_hosts, b"").map_err(|e| format!("known_hosts: {e}"))?;
    }
    let config = args.keys.join("ssh_config");
    let text = format!(
        "Host mousse-test-sshd\n  HostName 127.0.0.1\n  Port {port}\n  User tester\n  \
         IdentityFile {key}\n  IdentitiesOnly yes\n  IdentityAgent none\n  \
         UserKnownHostsFile {kh}\n",
        port = server.port(),
        key = quoted(&client_path),
        kh = quoted(&known_hosts),
    );
    std::fs::write(&config, text).map_err(|e| format!("ssh_config: {e}"))?;
    println!(
        "ready port {} host_key {} config {}",
        server.port(),
        server.host_key_sha256(),
        config.display()
    );
    // Until stdin closes (the kit that started it is gone) or a kill.
    let mut sink = [0u8; 256];
    let mut stdin = std::io::stdin();
    while matches!(stdin.read(&mut sink), Ok(n) if n > 0) {}
    drop(server);
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("test-sshd: {e}");
            ExitCode::from(2)
        }
    }
}
