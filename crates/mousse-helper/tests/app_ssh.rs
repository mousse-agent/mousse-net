//! E9: the `ssh-stdio` route (Phase 1b §3). The system `ssh` client runs
//! through each route's constrained config against the `russh` test server
//! on loopback (`common/sshd.rs`); the remote end is `mousse-helper pipe`
//! reaching a running helper's IPC. The check cell `phase1b.ssh` runs this
//! file.
//!
//! No test reads the owner's own ssh config, keys, agent or `known_hosts`:
//! `ssh -G` reads a test config (`MOUSSE_NET_TEST_SSH_CONFIG`, debug
//! builds), whose host entries name a throwaway key with
//! `IdentitiesOnly yes` and `IdentityAgent none`, and every later call
//! reads only the route's own config.

mod common;
#[path = "common/sshd.rs"]
mod sshd;

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{PrivateKey, PublicKey};
use serde_json::{json, Value};
use sshd::{Config, Launcher, Shell, TestSshd};

// ---------------------------------------------------------------------
// The fixture: a throwaway client key, the "user's" ssh config, and
// remotes (a test home with Mousse's launchers, served by a test sshd).
// ---------------------------------------------------------------------

struct Fx {
    root: PathBuf,
    key_path: PathBuf,
    client: PublicKey,
    /// The config `ssh -G` reads in place of `~/.ssh/config`.
    user_config: PathBuf,
    /// The `known_hosts` that config names (the `in_user_known_hosts`
    /// hint).
    user_known_hosts: PathBuf,
}

impl Fx {
    fn new(tag: &str) -> Self {
        let root = temp_dir(&format!("ssh{tag}"));
        mousse_net_io::private::make_private_dir(&root).unwrap();
        let key = sshd::generate_key();
        let key_path = root.join("id_test");
        let text = key.to_openssh(LineEnding::LF).unwrap();
        std::fs::write(&key_path, text.as_bytes()).unwrap();
        mousse_net_io::private::restrict_file(&key_path).unwrap();
        let fx = Self {
            client: key.public_key().clone(),
            key_path,
            user_config: root.join("user_config"),
            user_known_hosts: root.join("user_known_hosts"),
            root,
        };
        fx.hosts(&[]);
        fx
    }

    /// A config value for a path (double quotes, `%` doubled).
    fn quoted(path: &Path) -> String {
        format!("\"{}\"", path.display().to_string().replace('%', "%%"))
    }

    /// Write the user config: one entry per `(alias, port)` on loopback,
    /// plus `extra` text.
    fn hosts_with(&self, hosts: &[(&str, u16)], extra: &str) {
        let mut text = String::new();
        for (alias, port) in hosts {
            text.push_str(&format!(
                "Host {alias}\n  HostName 127.0.0.1\n  Port {port}\n  User tester\n  \
                 IdentityFile {key}\n  IdentitiesOnly yes\n  IdentityAgent none\n  \
                 UserKnownHostsFile {kh}\n",
                key = Self::quoted(&self.key_path),
                kh = Self::quoted(&self.user_known_hosts),
            ));
        }
        text.push_str(extra);
        std::fs::write(&self.user_config, text).unwrap();
    }

    fn hosts(&self, hosts: &[(&str, u16)]) {
        self.hosts_with(hosts, "");
    }

    /// A helper in app mode whose `ssh -G` reads the test config.
    fn caller(&self, tag: &str, env: &[(&str, &str)]) -> (Endpoint, App) {
        let end = Endpoint::init(tag);
        let mut app = end.app_raw(
            tag,
            env,
            0,
            &[("MOUSSE_NET_TEST_SSH_CONFIG", self.user_config.as_path())],
        );
        app.hello();
        (end, app)
    }

    /// A remote: a home with Mousse's launchers, served by a test sshd.
    fn remote(&self, tag: &str, opts: RemoteOpts) -> Remote {
        let home = self.root.join(format!("home-{tag}"));
        let bin_dir = home.join(".mousse").join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(home.join(".mousse").join("net-engine")).unwrap();
        let mousse_home = home.join(".mousse");
        let mut launchers = HashMap::new();
        if opts.launchers {
            write_launchers(&bin_dir, &mousse_home);
            launchers.insert(
                "mousse-helper".to_owned(),
                Launcher::Program {
                    path: bin().to_path_buf(),
                    env: vec![("MOUSSE_HOME".into(), mousse_home.clone().into_os_string())],
                },
            );
            launchers.insert("mousse-cli".to_owned(), Launcher::Echo);
        }
        let mut env: Vec<(OsString, OsString)> = vec![
            ("HOME".into(), home.clone().into_os_string()),
            ("MOUSSE_HOME".into(), mousse_home.clone().into_os_string()),
        ];
        if cfg!(windows) {
            env.push(("USERPROFILE".into(), home.clone().into_os_string()));
        }
        for (k, v) in &opts.env {
            env.push(((*k).into(), (*v).into()));
        }
        let sshd = TestSshd::start(Config {
            host_key: opts.host_key.unwrap_or_else(sshd::generate_key),
            client_key: opts.client.unwrap_or_else(|| self.client.clone()),
            shell: opts.shell,
            env,
            cwd: Some(home.clone()),
            preamble: opts.preamble,
            launchers,
        });
        Remote { home, sshd }
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Unix: real launcher scripts, run by the test sshd's `/bin/sh`.
fn write_launchers(bin_dir: &Path, mousse_home: &Path) {
    if !cfg!(unix) {
        return;
    }
    let helper = format!(
        "#!/bin/sh\nMOUSSE_HOME='{}'\nexport MOUSSE_HOME\nexec '{}' \"$@\"\n",
        mousse_home.display(),
        bin().display()
    );
    let cli = "#!/bin/sh\nprintf 'mousse-ssh/1\\n'\nexec cat\n";
    for (name, text) in [("mousse-helper", helper.as_str()), ("mousse-cli", cli)] {
        let path = bin_dir.join(name);
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}

struct RemoteOpts {
    preamble: Vec<u8>,
    shell: Shell,
    launchers: bool,
    host_key: Option<PrivateKey>,
    /// The only client key the server takes (default: the fixture's).
    client: Option<PublicKey>,
    env: Vec<(&'static str, &'static str)>,
}

impl Default for RemoteOpts {
    fn default() -> Self {
        Self {
            preamble: Vec::new(),
            shell: Shell::Default,
            launchers: true,
            host_key: None,
            client: None,
            env: Vec::new(),
        }
    }
}

struct Remote {
    home: PathBuf,
    sshd: TestSshd,
}

impl Remote {
    fn port(&self) -> u16 {
        self.sshd.port()
    }

    /// `endpoints.json`: `selector` names `state`.
    fn publish(&self, entries: &[(&str, &Path, bool)]) {
        let mut profiles = serde_json::Map::new();
        for (selector, state, networking) in entries {
            profiles.insert(
                (*selector).to_owned(),
                json!({"state": state, "networking": networking}),
            );
        }
        std::fs::write(
            self.home
                .join(".mousse")
                .join("net-engine")
                .join("endpoints.json"),
            json!({ "profiles": profiles }).to_string(),
        )
        .unwrap();
    }
}

/// A selector: 26 characters of `[a-z2-7]`.
const SEL: &str = "abcdefghijklmnopqrstuvwx23";

/// `ssh.resolve` that must work: its route id.
fn resolve(app: &mut App, target: &str) -> String {
    let reply = app.call("ssh.resolve", json!({"target": target}));
    reply["route_id"].as_str().unwrap().to_owned()
}

/// Probe and trust the key a route's server shows; its fingerprint.
fn pin(app: &mut App, route: &str) -> String {
    let probe = app.call("ssh.probe", json!({"route_id": route}));
    let sha = probe["sha256"].as_str().unwrap().to_owned();
    app.call("ssh.trust", json!({"route_id": route, "sha256": sha}));
    sha
}

/// The error a request failed with (`""` if it worked).
fn error_of(reply: &Value) -> String {
    reply["error"].as_str().unwrap_or("").to_owned()
}

fn known_hosts(end: &Endpoint) -> String {
    std::fs::read_to_string(end.dir.join("ssh").join("known_hosts")).unwrap_or_default()
}

/// The lines `known_hosts` holds for a route.
fn pins_of(end: &Endpoint, route: &str) -> Vec<String> {
    let alias = format!("mousse-{route}");
    known_hosts(end)
        .lines()
        .filter(|l| l.split_whitespace().next() == Some(alias.as_str()))
        .map(str::to_owned)
        .collect()
}

/// A host helper (the remote's running Mousse) paired with `caller`: the
/// caller holds its pin and it grants the caller.
/// Also returns the pairing connection's number on the host.
fn host_for(caller: &mut App, tag: &str) -> (Endpoint, App, u64) {
    let end = Endpoint::init(tag);
    let mut host = end.app(tag, &[]);
    host.hello();
    let joined = pair_apps(&mut host, caller);
    (end, host, joined.a_conn)
}

/// `test.ssh_dial`: open a path to `identity` over the SSH route alone.
fn ssh_dial(app: &mut App, route: &str, selector: &str, identity: &str) -> Value {
    app.request(
        "test.ssh_dial",
        json!({"route_id": route, "selector": selector, "identity": identity}),
    )
}

/// Bytes pass over the connection `conn` (caller side) to the host, which
/// takes them on an inbound connection other than `not` (the pairing one).
fn exchange(caller: &mut App, conn: u64, host: &mut App, not: u64, size: usize) {
    let handle = caller.open(conn, "mousse.rpc", "bulk");
    let payload = pattern(size, 7);
    caller.send(handle, &payload, true);
    let (host_conn, host_handle) = host.wait("the stream on the host", WAIT, |st| {
        st.messages
            .iter()
            .find(|m| m["ev"] == "stream.incoming")
            .map(|m| {
                (
                    m["conn"].as_u64().unwrap(),
                    m["handle"].as_u64().unwrap() as u32,
                )
            })
    });
    assert_ne!(
        host_conn, not,
        "the stream came over the pairing connection"
    );
    let up = host.event("conn.up", |m| m["conn"] == host_conn);
    assert_eq!(up["dir"], "in", "{up}");
    assert_eq!(up["identity"], caller.identity.as_str(), "{up}");
    host.accept(host_handle);
    // Credit past the payload plus the helper's read-ahead.
    host.credit(host_handle, 8 << 20);
    let got = host.until_fin(host_handle, WAIT);
    assert_eq!(got.len(), payload.len());
    assert!(got == payload, "the bytes changed on the way");
}

// ---------------------------------------------------------------------
// A loopback forwarder whose target can change: one SSH "server" whose
// host key changes, for probe, trust and rotation.
// ---------------------------------------------------------------------

struct Forward {
    port: u16,
    target: Arc<AtomicU16>,
    stop: Arc<AtomicBool>,
}

impl Forward {
    fn to(port: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let me = listener.local_addr().unwrap().port();
        let target = Arc::new(AtomicU16::new(port));
        let stop = Arc::new(AtomicBool::new(false));
        let (t, s) = (target.clone(), stop.clone());
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                if s.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(inbound) = conn else { continue };
                let Ok(outbound) = TcpStream::connect(("127.0.0.1", t.load(Ordering::SeqCst)))
                else {
                    continue;
                };
                splice(inbound, outbound);
            }
        });
        Self {
            port: me,
            target,
            stop,
        }
    }

    fn switch(&self, port: u16) {
        self.target.store(port, Ordering::SeqCst);
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn splice(a: TcpStream, b: TcpStream) {
    for (mut from, mut to) in [(a.try_clone().unwrap(), b.try_clone().unwrap()), (b, a)] {
        std::thread::spawn(move || {
            let mut buf = [0u8; 16384];
            loop {
                match from.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if to.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = to.shutdown(std::net::Shutdown::Write);
        });
    }
}

// ---------------------------------------------------------------------
// ssh.resolve: one constrained config per route.
// ---------------------------------------------------------------------

/// `ssh -G` runs once; the route's config pins the host, port, user and
/// key checking, and keeps the authentication, algorithm and
/// address-family options. It is owner-only.
#[test]
fn resolve_writes_one_constrained_config_with_the_kept_options() {
    let fx = Fx::new("resolve");
    fx.hosts_with(
        &[("box", 2222)],
        "Host box\n  KexAlgorithms curve25519-sha256\n  Ciphers aes256-gcm@openssh.com\n",
    );
    let (end, mut a) = fx.caller("resolve", &[]);
    let reply = a.call("ssh.resolve", json!({"target": "box"}));
    assert_eq!(reply["user"], "tester");
    assert_eq!(reply["hostname"], "127.0.0.1");
    assert_eq!(reply["port"], 2222);
    assert_eq!(reply["pinned"], false);
    let id = reply["route_id"].as_str().unwrap();
    assert_eq!(id.len(), 24, "{reply}");
    let conf_path = end.dir.join("ssh").join(format!("{id}.conf"));
    let conf = std::fs::read_to_string(&conf_path).unwrap();
    for line in [
        format!("Host mousse-{id}"),
        "HostName 127.0.0.1".into(),
        "Port 2222".into(),
        "User \"tester\"".into(),
        format!("HostKeyAlias mousse-{id}"),
        "GlobalKnownHostsFile none".into(),
        "StrictHostKeyChecking yes".into(),
        "IdentitiesOnly yes".into(),
        "IdentityAgent none".into(),
        "KexAlgorithms curve25519-sha256".into(),
        "Ciphers aes256-gcm@openssh.com".into(),
    ] {
        assert!(
            conf.lines().any(|l| l.trim() == line),
            "{line:?} missing:\n{conf}"
        );
    }
    let kh = end.dir.join("ssh").join("known_hosts");
    assert!(
        conf.contains(&format!("UserKnownHostsFile {}", Fx::quoted(&kh))),
        "{conf}"
    );
    assert!(conf.contains("IdentityFile"), "{conf}");
    assert!(
        mousse_net_io::private::is_owner_only(&conf_path).unwrap(),
        "the route's config is not owner-only"
    );
    // Same input, another route: a new id, a new file.
    let again = resolve(&mut a, "box");
    assert_ne!(again, id);
    // Bad targets never reach `ssh`.
    for bad in ["-oProxyCommand=x", "a b", "box;id", "x@"] {
        let reply = a.request("ssh.resolve", json!({"target": bad}));
        assert_eq!(error_of(&reply), "bad_target", "{bad}: {reply}");
    }
}

/// A jump host is refused, and no config is written.
#[test]
fn a_jump_host_is_refused() {
    let fx = Fx::new("jump");
    fx.hosts_with(
        &[("box", 2222)],
        "Host viajump\n  ProxyJump box\nHost viacmd\n  ProxyCommand nc %h %p\n",
    );
    let (end, mut a) = fx.caller("jump", &[]);
    for target in ["viajump", "viacmd"] {
        let reply = a.request("ssh.resolve", json!({"target": target}));
        assert_eq!(error_of(&reply), "ssh_proxy_unsupported", "{reply}");
    }
    let confs = std::fs::read_dir(end.dir.join("ssh"))
        .map(|d| d.flatten().count())
        .unwrap_or(0);
    assert_eq!(confs, 0, "a config was written for a jump host");
}

// ---------------------------------------------------------------------
// Host keys: probe, trust, strict checking, rotation.
// ---------------------------------------------------------------------

/// The probe fetches the server's key; trust writes exactly that key for
/// the route; a strict session then runs.
#[test]
fn probe_fetches_the_key_and_trust_pins_exactly_it() {
    let fx = Fx::new("probe");
    let r = fx.remote("b", RemoteOpts::default());
    fx.hosts(&[("box", r.port())]);
    let (end, mut a) = fx.caller("probe", &[]);
    let route = resolve(&mut a, "box");
    let probe = a.call("ssh.probe", json!({"route_id": route}));
    assert_eq!(probe["key_type"], "ssh-ed25519");
    assert_eq!(probe["sha256"], r.sshd.host_key_sha256().as_str());
    assert_eq!(probe["in_user_known_hosts"], false);
    assert!(pins_of(&end, &route).is_empty(), "the probe pinned a key");
    a.call(
        "ssh.trust",
        json!({"route_id": route, "sha256": probe["sha256"]}),
    );
    assert_eq!(
        pins_of(&end, &route),
        [format!("mousse-{route} {}", r.sshd.host_key_line())]
    );
    let request = json!({"op": "profiles", "n": 1});
    let reply = a.call("ssh.run", json!({"route_id": route, "request": request}));
    assert_eq!(reply["reply"], request);
}

/// The owner's own `known_hosts` (as `ssh -G` names it) listing the same
/// key is reported as a hint.
#[test]
fn in_user_known_hosts_is_a_hint_from_the_users_own_file() {
    let fx = Fx::new("hint");
    let r = fx.remote("b", RemoteOpts::default());
    fx.hosts(&[("box", r.port())]);
    std::fs::write(
        &fx.user_known_hosts,
        format!("[127.0.0.1]:{} {}\n", r.port(), r.sshd.host_key_line()),
    )
    .unwrap();
    let (_end, mut a) = fx.caller("hint", &[]);
    let route = resolve(&mut a, "box");
    let probe = a.call("ssh.probe", json!({"route_id": route}));
    assert_eq!(probe["in_user_known_hosts"], true, "{probe}");
}

/// With no pinned key, ssh refuses the host and adds nothing: never
/// `accept-new`.
#[test]
fn an_unpinned_route_is_refused_and_nothing_is_added() {
    let fx = Fx::new("unpinned");
    let r = fx.remote("b", RemoteOpts::default());
    fx.hosts(&[("box", r.port())]);
    let (end, mut a) = fx.caller("unpinned", &[]);
    let route = resolve(&mut a, "box");
    let reply = a.request(
        "ssh.run",
        json!({"route_id": route, "request": {"op": "profiles"}}),
    );
    assert_eq!(error_of(&reply), "host_key_unknown", "{reply}");
    assert!(pins_of(&end, &route).is_empty(), "{}", known_hosts(&end));
    // And again: still refused.
    let reply = a.request(
        "ssh.run",
        json!({"route_id": route, "request": {"op": "profiles"}}),
    );
    assert_eq!(error_of(&reply), "host_key_unknown", "{reply}");
}

/// Trust needs the fetched key, kept for SSH_SETUP_TIMEOUT_MS, and its
/// exact fingerprint.
#[test]
fn trust_needs_the_fetched_key_and_its_fingerprint() {
    let fx = Fx::new("trust");
    let r = fx.remote("b", RemoteOpts::default());
    fx.hosts(&[("box", r.port())]);
    let (end, mut a) = fx.caller("trust", &[("SSH_SETUP_TIMEOUT_MS", "4000")]);
    let route = resolve(&mut a, "box");
    let sha = r.sshd.host_key_sha256();
    let reply = a.request("ssh.trust", json!({"route_id": route, "sha256": sha}));
    assert_eq!(error_of(&reply), "probe_again", "{reply}");
    a.call("ssh.probe", json!({"route_id": route}));
    let other = sshd::sha256(sshd::generate_key().public_key());
    let reply = a.request("ssh.trust", json!({"route_id": route, "sha256": other}));
    assert_eq!(error_of(&reply), "key_mismatch", "{reply}");
    assert!(pins_of(&end, &route).is_empty());
    // Past SSH_SETUP_TIMEOUT_MS the kept key is gone.
    std::thread::sleep(Duration::from_millis(4300));
    let reply = a.request("ssh.trust", json!({"route_id": route, "sha256": sha}));
    assert_eq!(error_of(&reply), "probe_again", "{reply}");
    assert!(pins_of(&end, &route).is_empty());
}

/// Trust writes the bytes the probe fetched, not whatever the server shows
/// now: a key that changed between probe and trust is caught at the next
/// session.
#[test]
fn trust_writes_the_probed_bytes_without_connecting_again() {
    let fx = Fx::new("trustbytes");
    let first = fx.remote("one", RemoteOpts::default());
    let second = fx.remote("two", RemoteOpts::default());
    let fwd = Forward::to(first.port());
    fx.hosts(&[("box", fwd.port)]);
    let (end, mut a) = fx.caller("trustbytes", &[]);
    let route = resolve(&mut a, "box");
    let probe = a.call("ssh.probe", json!({"route_id": route}));
    assert_eq!(probe["sha256"], first.sshd.host_key_sha256().as_str());
    fwd.switch(second.port());
    a.call(
        "ssh.trust",
        json!({"route_id": route, "sha256": probe["sha256"]}),
    );
    assert_eq!(
        pins_of(&end, &route),
        [format!("mousse-{route} {}", first.sshd.host_key_line())]
    );
    let reply = a.request(
        "ssh.run",
        json!({"route_id": route, "request": {"op": "profiles"}}),
    );
    assert_eq!(error_of(&reply), "host_key_changed", "{reply}");
}

/// A changed key fails with `host_key_changed`; checking and trusting
/// again replaces the route's one line, so the old key no longer holds.
#[test]
fn a_changed_key_fails_and_trusting_again_replaces_the_pin() {
    let fx = Fx::new("rotate");
    let first = fx.remote("one", RemoteOpts::default());
    let second = fx.remote("two", RemoteOpts::default());
    let fwd = Forward::to(first.port());
    fx.hosts(&[("box", fwd.port)]);
    let (end, mut a) = fx.caller("rotate", &[]);
    let route = resolve(&mut a, "box");
    let other = resolve(&mut a, "box");
    // Another route to the same server keeps no pin of its own.
    pin(&mut a, &route);
    let request = json!({"op": "profiles"});
    a.call("ssh.run", json!({"route_id": route, "request": request}));
    fwd.switch(second.port());
    let reply = a.request("ssh.run", json!({"route_id": route, "request": request}));
    assert_eq!(error_of(&reply), "host_key_changed", "{reply}");
    let sha = pin(&mut a, &route);
    assert_eq!(sha, second.sshd.host_key_sha256());
    assert_eq!(
        pins_of(&end, &route),
        [format!("mousse-{route} {}", second.sshd.host_key_line())]
    );
    a.call("ssh.run", json!({"route_id": route, "request": request}));
    assert!(pins_of(&end, &other).is_empty());
    // Forget drops the route's pin and files.
    a.call("ssh.forget", json!({"route_id": route}));
    assert!(pins_of(&end, &route).is_empty());
    assert!(!end.dir.join("ssh").join(format!("{route}.conf")).exists());
    let reply = a.request("ssh.probe", json!({"route_id": route}));
    assert_eq!(error_of(&reply), "no_route", "{reply}");
}

// ---------------------------------------------------------------------
// ssh.run: marker, preamble and the reply cap.
// ---------------------------------------------------------------------

/// A login shell's output before the marker is skipped, even when the
/// marker lands mid-line.
#[test]
fn the_reply_follows_the_marker_after_a_preamble() {
    let fx = Fx::new("preamble");
    let r = fx.remote(
        "b",
        RemoteOpts {
            preamble: b"Welcome\r\n\x1b[1mbanner\x1b[0m\nmousse-ssh/1 is not alone on this line\nno newline at end".to_vec(),
            ..RemoteOpts::default()
        },
    );
    fx.hosts(&[("box", r.port())]);
    let (_end, mut a) = fx.caller("preamble", &[]);
    let route = resolve(&mut a, "box");
    pin(&mut a, &route);
    let request = json!({"op": "profiles", "pad": "x".repeat(500)});
    let reply = a.call("ssh.run", json!({"route_id": route, "request": request}));
    assert_eq!(reply["reply"], request);
}

/// Output past SSH_PREAMBLE_MAX_BYTES before the marker, or a reply past
/// SSH_REPLY_MAX_BYTES, fails with `remote_failed`.
#[test]
fn a_long_preamble_or_reply_is_remote_failed() {
    let fx = Fx::new("caps");
    let r = fx.remote(
        "b",
        RemoteOpts {
            preamble: vec![b'.'; 300],
            ..RemoteOpts::default()
        },
    );
    fx.hosts(&[("box", r.port())]);
    let (_end, mut a) = fx.caller(
        "caps",
        &[
            ("SSH_PREAMBLE_MAX_BYTES", "200"),
            ("SSH_REPLY_MAX_BYTES", "1024"),
        ],
    );
    let route = resolve(&mut a, "box");
    pin(&mut a, &route);
    let reply = a.request(
        "ssh.run",
        json!({"route_id": route, "request": {"op": "x"}}),
    );
    assert_eq!(error_of(&reply), "remote_failed", "{reply}");
    assert!(
        reply["reason"]
            .as_str()
            .unwrap()
            .contains("SSH_PREAMBLE_MAX_BYTES"),
        "{reply}"
    );

    let r2 = fx.remote("c", RemoteOpts::default());
    fx.hosts(&[("box", r.port()), ("box2", r2.port())]);
    let route = resolve(&mut a, "box2");
    pin(&mut a, &route);
    let ok = json!({"op": "x", "pad": "y".repeat(900)});
    a.call("ssh.run", json!({"route_id": route, "request": ok}));
    let big = json!({"op": "x", "pad": "y".repeat(1100)});
    let reply = a.request("ssh.run", json!({"route_id": route, "request": big}));
    assert_eq!(error_of(&reply), "remote_failed", "{reply}");
    assert!(
        reply["reason"]
            .as_str()
            .unwrap()
            .contains("SSH_REPLY_MAX_BYTES"),
        "{reply}"
    );
}

/// What the client and the remote say maps to a named reason: a missing
/// launcher, a Windows remote, a refused login, nothing listening.
#[test]
fn failures_are_named() {
    let fx = Fx::new("reasons");
    let bare = fx.remote(
        "bare",
        RemoteOpts {
            launchers: false,
            ..RemoteOpts::default()
        },
    );
    let windows = fx.remote(
        "win",
        RemoteOpts {
            shell: Shell::WindowsCmd,
            ..RemoteOpts::default()
        },
    );
    let stranger = fx.remote(
        "stranger",
        RemoteOpts {
            client: Some(sshd::generate_key().public_key().clone()),
            ..RemoteOpts::default()
        },
    );
    // A port nothing listens on.
    let dead = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    fx.hosts(&[
        ("bare", bare.port()),
        ("win", windows.port()),
        ("stranger", stranger.port()),
        ("dead", dead),
    ]);
    let (_end, mut a) = fx.caller("reasons", &[]);
    let request = json!({"op": "profiles"});
    for (target, want) in [
        ("bare", "remote_not_installed"),
        ("win", "windows_remote_unsupported"),
        ("stranger", "auth_denied"),
    ] {
        let route = resolve(&mut a, target);
        pin(&mut a, &route);
        let reply = a.request("ssh.run", json!({"route_id": route, "request": request}));
        assert_eq!(error_of(&reply), want, "{target}: {reply}");
    }
    let route = resolve(&mut a, "dead");
    let reply = a.request("ssh.probe", json!({"route_id": route}));
    assert_eq!(error_of(&reply), "unreachable", "{reply}");
}

// ---------------------------------------------------------------------
// The pipe: SshPipe, the remote `pipe --profile` and the helper's IPC.
// ---------------------------------------------------------------------

/// The route's pipe reaches the remote's running helper and carries the
/// session: step 1 and step 2 pass and stream bytes go both ways, after a
/// preamble whose marker lands mid-line.
#[test]
fn the_pipe_reaches_the_running_helper_and_carries_the_session() {
    let fx = Fx::new("pipe");
    let r = fx.remote(
        "b",
        RemoteOpts {
            preamble: b"motd\nno newline at end".to_vec(),
            ..RemoteOpts::default()
        },
    );
    fx.hosts(&[("box", r.port())]);
    let (_a_end, mut a) = fx.caller("pipea", &[]);
    let (b_end, mut b, pairing) = host_for(&mut a, "pipeb");
    r.publish(&[(SEL, &b_end.dir, true)]);
    let route = resolve(&mut a, "box");
    pin(&mut a, &route);
    let reply = ssh_dial(&mut a, &route, SEL, &b.identity);
    let conn = reply["conn"].as_u64().unwrap_or_else(|| panic!("{reply}"));
    let up = a.event("conn.up", |m| m["conn"] == conn);
    assert_eq!(up["route"]["kind"], "ssh", "{up}");
    assert_eq!(up["identity"], b.identity.as_str());
    exchange(&mut a, conn, &mut b, pairing, 200_000);
}

/// The pipe dial reads only the route's config: after the user's config
/// changes, the route still reaches the host and key it was set up with.
#[test]
fn the_pipe_dial_uses_the_routes_config_not_the_users() {
    let fx = Fx::new("ownconf");
    let r = fx.remote("b", RemoteOpts::default());
    fx.hosts(&[("box", r.port())]);
    let (_a_end, mut a) = fx.caller("ownconfa", &[]);
    let (b_end, b, _) = host_for(&mut a, "ownconfb");
    r.publish(&[(SEL, &b_end.dir, true)]);
    let route = resolve(&mut a, "box");
    pin(&mut a, &route);
    // The user's `box` now names a port nothing listens on.
    let dead = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    fx.hosts(&[("box", dead)]);
    let reply = ssh_dial(&mut a, &route, SEL, &b.identity);
    assert!(reply["conn"].is_u64(), "{reply}");
}

/// When the helper goes, the remote `pipe` exits at once though SSH still
/// holds its stdin, so the session ends and the caller sees the path
/// close well before any keepalive would notice.
#[test]
fn the_pipe_ends_when_the_helper_closes() {
    let fx = Fx::new("ending");
    let r = fx.remote("b", RemoteOpts::default());
    fx.hosts(&[("box", r.port())]);
    let (_a_end, mut a) = fx.caller("endinga", &[]);
    let (b_end, mut b, _) = host_for(&mut a, "endingb");
    r.publish(&[(SEL, &b_end.dir, true)]);
    let route = resolve(&mut a, "box");
    pin(&mut a, &route);
    let reply = ssh_dial(&mut a, &route, SEL, &b.identity);
    let conn = reply["conn"].as_u64().unwrap_or_else(|| panic!("{reply}"));
    // A hard stop: no GOAWAY, the IPC stream just closes.
    b.kill();
    let start = Instant::now();
    a.wait("the SSH path to close", Duration::from_secs(8), |st| {
        st.messages
            .iter()
            .find(|m| m["ev"] == "conn.down" && m["conn"] == conn)
            .cloned()
    });
    assert!(
        start.elapsed() < Duration::from_secs(6),
        "the path closed only after {:?}",
        start.elapsed()
    );
}

/// The remote `pipe` names why it cannot connect: no helper running for
/// the profile, or no such profile.
#[test]
fn the_pipe_names_the_remote_state() {
    let fx = Fx::new("pipestate");
    let r = fx.remote("b", RemoteOpts::default());
    fx.hosts(&[("box", r.port())]);
    let (_a_end, mut a) = fx.caller("pipestatea", &[]);
    let (b_end, mut b, _) = host_for(&mut a, "pipestateb");
    let off = "bbcdefghijklmnopqrstuvwx23";
    r.publish(&[(SEL, &b_end.dir, true), (off, &b_end.dir, false)]);
    let route = resolve(&mut a, "box");
    pin(&mut a, &route);
    let identity = b.identity.clone();
    let reply = ssh_dial(&mut a, &route, off, &identity);
    assert_eq!(error_of(&reply), "remote_no_endpoint", "{reply}");
    let reply = ssh_dial(&mut a, &route, "zzcdefghijklmnopqrstuvwx23", &identity);
    assert_eq!(error_of(&reply), "remote_no_endpoint", "{reply}");
    b.kill();
    // A hard stop leaves its control file behind; nothing answers there.
    let reply = ssh_dial(&mut a, &route, SEL, &identity);
    assert_eq!(error_of(&reply), "remote_not_running", "{reply}");
}

/// The helper's IPC hands over a pipe only with the token; in app mode it
/// answers only `pipe` and `status`.
#[test]
fn a_pipe_needs_the_token_and_app_mode_ipc_answers_only_pipe_and_status() {
    let end = Endpoint::init("pipetoken");
    let mut b = end.app("hostB", &[]);
    b.hello();
    let (mut conn, token) = ipc_raw(&end.dir);
    conn.write_all(b"{\"cmd\":\"pipe\",\"token\":\"00\"}\n")
        .unwrap();
    let got = read_line_within(conn, Duration::from_secs(5)).expect("no answer");
    let reply: Value = serde_json::from_slice(&got).unwrap();
    assert_eq!(reply["error"], "refused", "{reply}");

    let (mut conn, _) = ipc_raw(&end.dir);
    conn.write_all(format!("{{\"cmd\":\"grants\",\"token\":\"{token}\"}}\n").as_bytes())
        .unwrap();
    let got = read_line_within(conn, Duration::from_secs(5)).expect("no answer");
    let reply: Value = serde_json::from_slice(&got).unwrap();
    assert!(
        reply["error"].as_str().unwrap().contains("run by Mousse"),
        "{reply}"
    );

    let (mut conn, _) = ipc_raw(&end.dir);
    conn.write_all(format!("{{\"cmd\":\"status\",\"token\":\"{token}\"}}\n").as_bytes())
        .unwrap();
    let got = read_line_within(conn, Duration::from_secs(5)).expect("no answer");
    let reply: Value = serde_json::from_slice(&got).unwrap();
    assert_eq!(reply["identity"], b.identity.as_str(), "{reply}");
    // Nothing waits for authorization on the pipe pool afterwards.
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(b.stats()["preauth_open"]["pipe"], 0);
}

/// The connection window is kept per resolved host and port: two routes
/// to one server share it, another server has its own. A connection over
/// it waits, and fails at once if the wait would pass its deadline.
#[test]
fn the_window_is_shared_by_routes_to_one_server() {
    let fx = Fx::new("window");
    let r = fx.remote("b", RemoteOpts::default());
    let other = fx.remote("c", RemoteOpts::default());
    fx.hosts(&[
        ("box", r.port()),
        ("alias", r.port()),
        ("other", other.port()),
    ]);
    let (_end, mut a) = fx.caller(
        "window",
        &[
            ("SSH_TARGET_CONNECTS", "1"),
            ("SSH_SETUP_TIMEOUT_MS", "4000"),
        ],
    );
    let first = resolve(&mut a, "box");
    let second = resolve(&mut a, "alias");
    let third = resolve(&mut a, "other");
    a.call("ssh.probe", json!({"route_id": first}));
    let started = Instant::now();
    let reply = a.request("ssh.probe", json!({"route_id": second}));
    assert_eq!(error_of(&reply), "timeout", "{reply}");
    assert!(
        reply["reason"]
            .as_str()
            .unwrap()
            .contains("SSH_TARGET_CONNECTS"),
        "{reply}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the probe waited"
    );
    a.call("ssh.probe", json!({"route_id": third}));
}

/// A wait in the window is announced, so the dialog can say why.
#[test]
fn a_wait_in_the_window_is_announced() {
    let fx = Fx::new("waiting");
    let r = fx.remote("b", RemoteOpts::default());
    fx.hosts(&[("box", r.port())]);
    // A window place frees 30 s after it was taken: allow the wait.
    let (_end, mut a) = fx.caller(
        "waiting",
        &[
            ("SSH_TARGET_CONNECTS", "1"),
            ("SSH_SETUP_TIMEOUT_MS", "40000"),
        ],
    );
    let route = resolve(&mut a, "box");
    a.call("ssh.probe", json!({"route_id": route}));
    a.start("ssh.probe", json!({"route_id": route}));
    let ev = a.event("ssh.waiting", |m| m["route_id"] == route.as_str());
    let ms = ev["ms"].as_u64().unwrap();
    assert!(ms > 20_000 && ms <= 30_000, "{ev}");
    assert_eq!(ev["host"], "127.0.0.1");
}

/// A state directory too long for a Unix socket path: the helper binds and
/// `pipe` connects by the name relative to it (Phase 1b §3.3, S1).
#[test]
fn a_long_state_path_is_reached_by_its_relative_socket_name() {
    let fx = Fx::new("longpath");
    let r = fx.remote("b", RemoteOpts::default());
    fx.hosts(&[("box", r.port())]);
    let (_a_end, mut a) = fx.caller("longa", &[]);
    let base = temp_dir("longb");
    let mut dir = base.clone();
    while dir.as_os_str().len() < 150 {
        dir = dir.join("a-long-folder-name");
    }
    std::fs::create_dir_all(dir.parent().unwrap()).unwrap();
    let b_end = Endpoint { dir: dir.clone() };
    let mut init = b_end.cli(&["init"], false);
    assert_eq!(init.exit_within(WAIT), Some(0), "init: {}", init.err());
    let mut b = b_end.app("longb", &[]);
    b.hello();
    pair_apps(&mut b, &mut a);
    assert!(dir.join("control.json").exists());
    r.publish(&[(SEL, &dir, true)]);
    let route = resolve(&mut a, "box");
    pin(&mut a, &route);
    let reply = ssh_dial(&mut a, &route, SEL, &b.identity);
    assert!(reply["conn"].is_u64(), "{reply}");
    drop(b);
    drop(b_end);
    let _ = std::fs::remove_dir_all(&base);
}

/// Tighten-only SSH limits cannot be raised (the window only lengthened).
#[test]
fn ssh_limits_can_only_be_tightened() {
    let dir = temp_dir("sshtighten");
    for (name, value, range) in [
        ("MOUSSE_NET_SSH_TARGET_CONNECTS", "6", "1 to 5"),
        (
            "MOUSSE_NET_SSH_TARGET_WINDOW_MS",
            "29999",
            "30000 to 600000",
        ),
        ("MOUSSE_NET_SSH_PREAMBLE_MAX_BYTES", "65537", "0 to 65536"),
        (
            "MOUSSE_NET_SSH_REPLY_MAX_BYTES",
            "1048577",
            "1024 to 1048576",
        ),
    ] {
        let out = std::process::Command::new(bin())
            .arg("--state")
            .arg(&dir)
            .arg("id")
            .env(name, value)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{name}={value}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "{name}={value} is out of range; allowed range is {range}"
            )),
            "{name}={value}: {stderr}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
