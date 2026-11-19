//! The client side: the system OpenSSH client through §3.1's constrained
//! config, against the test server.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rand::RngExt;
use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};

use crate::remote::MARKER;
use crate::Args;

const PREAMBLE_MAX: usize = 65536;

pub fn keygen(args: &Args) -> i32 {
    let keygen = args.need("--keygen");
    let dir = PathBuf::from(args.need("--dir"));
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["id_test", "id_other"] {
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("pub"));
        let st = Command::new(&keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "mousse-spike", "-f"])
            .arg(&path)
            .status()
            .expect("ssh-keygen");
        if !st.success() {
            eprintln!("ssh-keygen failed for {name}");
            return 1;
        }
        println!("{}", path.with_extension("pub").display());
    }
    0
}

/// How a path is written in the config file.
#[derive(Clone, Copy, Debug)]
pub enum Quote {
    /// `"C:\a b\x"`
    Double,
    /// `"C:/a b/x"`
    DoubleForward,
    /// `C:\a b\x`
    Bare,
    /// `"C:\\a b\\x"`
    DoubleEscaped,
    /// `'C:\a b\x'`
    Single,
}

fn qpath(p: &Path, q: Quote, escape_percent: bool) -> String {
    let mut s = p.to_string_lossy().into_owned();
    if escape_percent {
        s = s.replace('%', "%%");
    }
    match q {
        Quote::Double => format!("\"{s}\""),
        Quote::DoubleForward => format!("\"{}\"", s.replace('\\', "/")),
        Quote::Bare => s,
        Quote::DoubleEscaped => format!("\"{}\"", s.replace('\\', "\\\\")),
        Quote::Single => format!("'{s}'"),
    }
}

struct Route {
    host: String,
    port: u16,
    user: String,
    alias: String,
}

#[allow(clippy::too_many_arguments)]
fn write_conf(
    path: &Path,
    r: &Route,
    port: u16,
    known_hosts: &Path,
    key: &Path,
    q: Quote,
    escape_percent: bool,
) {
    let text = format!(
        "Host {alias}\n  HostName {host}\n  Port {port}\n  User {user}\n  HostKeyAlias {alias}\n  \
         UserKnownHostsFile {kh}\n  GlobalKnownHostsFile none\n  StrictHostKeyChecking yes\n  \
         IdentityFile {key}\n  IdentitiesOnly yes\n  IdentityAgent none\n",
        alias = r.alias,
        host = r.host,
        user = r.user,
        kh = qpath(known_hosts, q, escape_percent),
        key = qpath(key, q, escape_percent),
    );
    std::fs::write(path, text).unwrap();
}

fn fixed(connect_timeout: u32) -> Vec<String> {
    let mut v = vec!["-T".to_string()];
    for o in [
        "BatchMode=yes",
        "RemoteCommand=none",
        "RequestTTY=no",
        "UpdateHostKeys=no",
        "CheckHostIP=no",
        &format!("ConnectTimeout={connect_timeout}"),
        "ServerAliveInterval=15",
        "ServerAliveCountMax=3",
        "ControlMaster=no",
        "ControlPath=none",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "LogLevel=ERROR",
    ] {
        v.push("-o".into());
        v.push(o.to_string());
    }
    v
}

fn ssh_command(
    ssh: &str,
    conf: &Path,
    extra: &[String],
    alias: &str,
    remote: Option<&str>,
) -> Command {
    let mut cmd = Command::new(ssh);
    // OpenSSH keeps the first value it sees for an option, so per-call
    // options go before the fixed ones.
    cmd.arg("-F")
        .arg(conf)
        .args(extra)
        .args(fixed(10))
        .arg("--")
        .arg(alias);
    if let Some(r) = remote {
        cmd.arg(r);
    }
    for v in [
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "SSH_AUTH_SOCK",
        "DISPLAY",
    ] {
        cmd.env_remove(v);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

struct Out {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
    ms: u128,
    timed_out: bool,
}

/// Run to completion with `input` on stdin, killed after `limit`.
fn run(mut cmd: Command, input: Vec<u8>, limit: Duration) -> Out {
    let start = Instant::now();
    let mut child = cmd.spawn().expect("spawn ssh");
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        for chunk in input.chunks(16 * 1024) {
            if stdin.write_all(chunk).is_err() {
                return;
            }
        }
        drop(stdin);
    });
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let r1 = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = so.read_to_end(&mut v);
        v
    });
    let r2 = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = se.read_to_end(&mut v);
        v
    });
    let mut timed_out = false;
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break Some(st);
        }
        if start.elapsed() > limit {
            timed_out = true;
            let _ = child.kill();
            break child.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let ms = start.elapsed().as_millis();
    let _ = writer.join();
    let stdout = r1.join().unwrap();
    let stderr = String::from_utf8_lossy(&r2.join().unwrap()).into_owned();
    Out {
        code: status.and_then(|s| s.code()),
        stdout,
        stderr,
        ms,
        timed_out,
    }
}

/// The offset just past the first marker (`mousse-ssh/1` and a newline),
/// which must come
/// within `PREAMBLE_MAX` bytes. It need not start a line: an rc file that
/// prints text without a final newline puts the marker mid-line.
fn after_marker(buf: &[u8]) -> Option<usize> {
    let end = buf.len().min(PREAMBLE_MAX + MARKER.len());
    buf[..end]
        .windows(MARKER.len())
        .position(|w| w == MARKER)
        .map(|i| i + MARKER.len())
}

fn show(name: &str, ok: bool, detail: &str) {
    println!("== {name}: {} | {detail}", if ok { "PASS" } else { "FAIL" });
}

fn show_stderr(out: &Out) {
    for line in out.stderr.lines() {
        println!("   stderr| {line}");
    }
}

fn random_hex(n: usize) -> String {
    let mut rng = rand::rng();
    (0..n)
        .map(|_| format!("{:02x}", rng.random::<u8>()))
        .collect()
}

/// Parse a `known_hosts` file the probe wrote: `(host, key)`.
fn parse_known_hosts(text: &str) -> Vec<(String, PublicKey)> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut parts = l.splitn(2, ' ');
            let host = parts.next()?.to_string();
            let key = PublicKey::from_openssh(parts.next()?.trim()).ok()?;
            Some((host, key))
        })
        .collect()
}

pub fn drive(args: &Args) -> i32 {
    let ssh = args.need("--ssh");
    let state = PathBuf::from(args.need("--state"));
    let sshdir = state.join("ssh");
    std::fs::create_dir_all(&sshdir).unwrap();
    let keys = state.join("keys");
    let key = keys.join("id_test");
    let other_key = keys.join("id_other");
    let remote = args.need("--remote");
    let expect_fp = args.need("--expect-fp");
    let route = Route {
        host: args.need("--host"),
        port: args.need("--port").parse().unwrap(),
        user: args.need("--user"),
        alias: format!("mousse-{}", random_hex(8)),
    };
    let quote = match args.get("--quote").as_deref() {
        Some("forward") => Quote::DoubleForward,
        Some("escaped") => Quote::DoubleEscaped,
        _ => Quote::Double,
    };
    let escape_percent = args.flag("--escape-percent");
    let limit = Duration::from_secs(30);
    println!("state={}", state.display());
    println!("alias={} host={}:{}", route.alias, route.host, route.port);
    let version = Command::new(&ssh).arg("-V").output().unwrap();
    println!("client={}", String::from_utf8_lossy(&version.stderr).trim());

    let known_hosts = sshdir.join("known_hosts");
    let _ = std::fs::remove_file(&known_hosts);
    let conf = sshdir.join(format!("{}.conf", route.alias));
    write_conf(
        &conf,
        &route,
        route.port,
        &known_hosts,
        &key,
        quote,
        escape_percent,
    );

    // 3. Probe: every auth method off, -N, into a temporary known_hosts.
    let probe_kh = sshdir.join(format!("probe-{}.known_hosts", random_hex(4)));
    let probe_opts: Vec<String> = [
        format!(
            "UserKnownHostsFile={}",
            qpath(&probe_kh, quote, escape_percent)
        ),
        "StrictHostKeyChecking=accept-new".into(),
        "HashKnownHosts=no".into(),
        "PubkeyAuthentication=no".into(),
        "PasswordAuthentication=no".into(),
        "KbdInteractiveAuthentication=no".into(),
        "HostbasedAuthentication=no".into(),
    ]
    .into_iter()
    .flat_map(|o| ["-o".to_string(), o])
    .chain(["-N".to_string()])
    .collect();
    let out = run(
        ssh_command(&ssh, &conf, &probe_opts, &route.alias, None),
        vec![],
        limit,
    );
    let probe_text = std::fs::read_to_string(&probe_kh).unwrap_or_default();
    let _ = std::fs::remove_file(&probe_kh);
    let parsed = parse_known_hosts(&probe_text);
    let fetched = parsed.first().cloned();
    let fp = fetched
        .as_ref()
        .map(|(_, k)| k.fingerprint(HashAlg::Sha256).to_string())
        .unwrap_or_default();
    show(
        "probe",
        fp == expect_fp
            && fetched
                .as_ref()
                .map(|(h, _)| h == &route.alias)
                .unwrap_or(false),
        &format!(
            "exit={:?} {}ms lines={} host={:?} sha256={fp} expected={expect_fp}",
            out.code,
            out.ms,
            parsed.len(),
            fetched.as_ref().map(|(h, _)| h.clone())
        ),
    );
    show_stderr(&out);
    let Some((_, host_key)) = fetched else {
        println!("probe wrote no key; stopping");
        return 1;
    };
    // `ssh.trust`: write the line for the alias.
    std::fs::write(
        &known_hosts,
        format!("{} {}\n", route.alias, host_key.to_openssh().unwrap()),
    )
    .unwrap();

    // 1 + 4. Strict connect, preamble skipped up to the marker, 1 MiB of
    // random bytes echoed both ways.
    let mut data = vec![0u8; 1 << 20];
    rand::rng().fill(&mut data[..]);
    let echo_cmd = args.get("--echo-cmd").unwrap_or(format!("{remote} echo"));
    let out = run(
        ssh_command(&ssh, &conf, &[], &route.alias, Some(&echo_cmd)),
        data.clone(),
        limit,
    );
    let start = after_marker(&out.stdout);
    let ok = out.code == Some(0) && start.map(|s| out.stdout[s..] == data[..]).unwrap_or(false);
    show(
        "strict-connect+echo",
        ok,
        &format!(
            "exit={:?} {}ms preamble_bytes={:?} echoed={} of {}",
            out.code,
            out.ms,
            start.map(|s| s - MARKER.len()),
            start.map(|s| out.stdout.len() - s).unwrap_or(0),
            data.len()
        ),
    );
    if let Some(s) = start {
        let pre = String::from_utf8_lossy(&out.stdout[..s - MARKER.len()]);
        for line in pre.lines() {
            println!("   preamble| {line}");
        }
    }
    show_stderr(&out);

    // A trivial session (login, marker, nothing else), timed, for the dial
    // budget.
    let mut times = Vec::new();
    for _ in 0..5 {
        let out = run(
            ssh_command(&ssh, &conf, &[], &route.alias, Some(&echo_cmd)),
            vec![],
            limit,
        );
        times.push((out.ms, out.code));
    }
    show("session-setup-ms", true, &format!("{times:?}"));

    if args.flag("--variants") {
        variants(&ssh, &route, &state, &key, &host_key, &remote);
    }

    // 7. Stderr texts.
    if !args.flag("--skip-cases") {
        cases(
            &ssh,
            &route,
            &sshdir,
            &key,
            &other_key,
            &known_hosts,
            &remote,
            quote,
            escape_percent,
            args,
        );
    }

    // 6. Killing the client ends the remote child.
    let sleeper = args
        .get("--sleeper-cmd")
        .unwrap_or(format!("{remote} sleeper"));
    kill_check(&ssh, &conf, &route, &remote, &sleeper);
    0
}

#[allow(clippy::too_many_arguments)]
fn cases(
    ssh: &str,
    route: &Route,
    sshdir: &Path,
    key: &Path,
    other_key: &Path,
    known_hosts: &Path,
    remote: &str,
    quote: Quote,
    pct: bool,
    args: &Args,
) {
    let limit = Duration::from_secs(30);
    let report = |name: &str, out: &Out| {
        println!(
            "== stderr {name}: exit={:?} {}ms timed_out={}",
            out.code, out.ms, out.timed_out
        );
        show_stderr(out);
    };
    let cmd = format!("{remote} echo");

    // auth denied: another key.
    let conf = sshdir.join("case-denied.conf");
    write_conf(&conf, route, route.port, known_hosts, other_key, quote, pct);
    report(
        "auth_denied",
        &run(
            ssh_command(ssh, &conf, &[], &route.alias, Some(&cmd)),
            vec![],
            limit,
        ),
    );

    // host key changed: another key for the alias.
    let changed_kh = sshdir.join("case-changed.known_hosts");
    let other = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    std::fs::write(
        &changed_kh,
        format!(
            "{} {}\n",
            route.alias,
            other.public_key().to_openssh().unwrap()
        ),
    )
    .unwrap();
    let conf = sshdir.join("case-changed.conf");
    write_conf(&conf, route, route.port, &changed_kh, key, quote, pct);
    report(
        "host_key_changed",
        &run(
            ssh_command(ssh, &conf, &[], &route.alias, Some(&cmd)),
            vec![],
            limit,
        ),
    );

    // unknown host key: empty file.
    let empty_kh = sshdir.join("case-empty.known_hosts");
    std::fs::write(&empty_kh, "").unwrap();
    let conf = sshdir.join("case-unknown.conf");
    write_conf(&conf, route, route.port, &empty_kh, key, quote, pct);
    report(
        "host_key_unknown",
        &run(
            ssh_command(ssh, &conf, &[], &route.alias, Some(&cmd)),
            vec![],
            limit,
        ),
    );
    // unknown host key, known_hosts file missing.
    let conf = sshdir.join("case-missing.conf");
    write_conf(
        &conf,
        route,
        route.port,
        &sshdir.join("case-missing.known_hosts"),
        key,
        quote,
        pct,
    );
    report(
        "host_key_unknown_nofile",
        &run(
            ssh_command(ssh, &conf, &[], &route.alias, Some(&cmd)),
            vec![],
            limit,
        ),
    );

    // connection refused.
    let refused_port: u16 = match args.get("--refused-port") {
        Some(p) => p.parse().unwrap(),
        None => {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        }
    };
    let conf = sshdir.join("case-refused.conf");
    write_conf(&conf, route, refused_port, known_hosts, key, quote, pct);
    report(
        "connection_refused",
        &run(
            ssh_command(ssh, &conf, &[], &route.alias, Some(&cmd)),
            vec![],
            limit,
        ),
    );
    let info = vec!["-o".to_string(), "LogLevel=INFO".to_string()];
    report(
        "connection_refused_loglevel_info",
        &run(
            ssh_command(ssh, &conf, &info, &route.alias, Some(&cmd)),
            vec![],
            limit,
        ),
    );

    // timeout: a listener that accepts and never speaks (banner exchange).
    let quiet_port: u16 = match args.get("--quiet-port") {
        Some(p) => p.parse().unwrap(),
        None => {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            std::thread::spawn(move || {
                let mut held = Vec::new();
                for s in l.incoming().flatten() {
                    held.push(s);
                }
            });
            port
        }
    };
    let conf = sshdir.join("case-timeout.conf");
    write_conf(&conf, route, quiet_port, known_hosts, key, quote, pct);
    let extra = vec!["-o".to_string(), "ConnectTimeout=3".to_string()];
    report(
        "timeout_banner",
        &run(
            ssh_command(ssh, &conf, &extra, &route.alias, Some(&cmd)),
            vec![],
            limit,
        ),
    );

    // remote command not found.
    let conf = sshdir.join(format!("{}.conf", route.alias));
    report(
        "remote_not_found",
        &run(
            ssh_command(
                ssh,
                &conf,
                &[],
                &route.alias,
                Some("mousse-spike-no-such-command pipe"),
            ),
            vec![],
            limit,
        ),
    );
}

fn kill_check(ssh: &str, conf: &Path, route: &Route, remote: &str, sleeper: &str) {
    let mut child = ssh_command(ssh, conf, &[], &route.alias, Some(sleeper))
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut pid = None;
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if let Some(p) = line.trim().strip_prefix("pid=") {
            pid = p.parse::<u32>().ok();
            break;
        }
        line.clear();
    }
    let Some(pid) = pid else {
        show("kill-client", false, "no pid from the sleeper");
        let _ = child.kill();
        return;
    };
    let alive_before = remote_alive(ssh, conf, route, remote, pid);
    let killed_at = Instant::now();
    child.kill().unwrap();
    let _ = child.wait();
    let mut gone_after = None;
    for _ in 0..20 {
        if remote_alive(ssh, conf, route, remote, pid) == Some(false) {
            gone_after = Some(killed_at.elapsed().as_millis());
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    show(
        "kill-client",
        alive_before == Some(true) && gone_after.is_some(),
        &format!("remote pid {pid} alive_before={alive_before:?} gone_after_ms={gone_after:?}"),
    );
}

fn remote_alive(ssh: &str, conf: &Path, route: &Route, remote: &str, pid: u32) -> Option<bool> {
    let out = run(
        ssh_command(
            ssh,
            conf,
            &[],
            &route.alias,
            Some(&format!("{remote} alive {pid}")),
        ),
        vec![],
        Duration::from_secs(30),
    );
    let text = String::from_utf8_lossy(&out.stdout);
    if text.contains("gone") {
        Some(false)
    } else if text.contains("alive") {
        Some(true)
    } else {
        None
    }
}

/// 2. Quoting of paths with spaces, an apostrophe and `%` in the config.
fn variants(
    ssh: &str,
    route: &Route,
    state: &Path,
    key: &Path,
    host_key: &PublicKey,
    remote: &str,
) {
    let dirs = [
        state.join("var space O'Brien"),
        state.join("var pct 100%"),
        state.join("var pct %d"),
    ];
    let cmd = format!("{remote} echo");
    for dir in &dirs {
        std::fs::create_dir_all(dir).unwrap();
        let kh = dir.join("known_hosts");
        std::fs::write(
            &kh,
            format!("{} {}\n", route.alias, host_key.to_openssh().unwrap()),
        )
        .unwrap();
        let k = dir.join("id_test");
        std::fs::copy(key, &k).unwrap();
        restrict(&k);
        for q in [
            Quote::Double,
            Quote::DoubleForward,
            Quote::DoubleEscaped,
            Quote::Single,
            Quote::Bare,
        ] {
            for pct in [false, true] {
                if pct && !dir.to_string_lossy().contains('%') {
                    continue;
                }
                let conf = dir.join(format!("v-{q:?}-{pct}.conf"));
                write_conf(&conf, route, route.port, &kh, &k, q, pct);
                let out = run(
                    ssh_command(ssh, &conf, &[], &route.alias, Some(&cmd)),
                    vec![],
                    Duration::from_secs(30),
                );
                let ok = out.code == Some(0);
                show(
                    &format!(
                        "quote dir={:?} style={q:?} escape_percent={pct}",
                        dir.file_name().unwrap()
                    ),
                    ok,
                    &format!(
                        "exit={:?} stderr={}",
                        out.code,
                        out.stderr.lines().next().unwrap_or("")
                    ),
                );
            }
        }
        // The same path as a command-line `-o` value, quoted and not.
        for (label, value) in [
            ("cli-bare", format!("UserKnownHostsFile={}", kh.display())),
            (
                "cli-quoted",
                format!("UserKnownHostsFile=\"{}\"", kh.display()),
            ),
        ] {
            let conf = dir.join("v-Double-false.conf");
            let extra = vec!["-o".to_string(), value];
            let out = run(
                ssh_command(ssh, &conf, &extra, &route.alias, Some(&cmd)),
                vec![],
                Duration::from_secs(30),
            );
            let ok = out.code == Some(0);
            show(
                &format!("quote dir={:?} {label}", dir.file_name().unwrap()),
                ok,
                &format!(
                    "exit={:?} stderr={}",
                    out.code,
                    out.stderr.lines().next().unwrap_or("")
                ),
            );
        }
    }
}

/// Owner-only private key, as ssh requires.
fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(windows)]
    {
        let user = std::env::var("USERNAME").unwrap();
        let _ = Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r", &format!("{user}:F")])
            .stdout(Stdio::null())
            .status();
    }
}
