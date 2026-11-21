//! The SSH test server (Phase 1b §3.7), built on `russh` (a dev-dependency
//! only). Tests drive it with the system `ssh` client.
//!
//! - Listens on `127.0.0.1` (port 0 picks one); never off loopback.
//! - One generated Ed25519 host key; accepts exactly one client public key.
//! - Exec requests only. No shell, pty, subsystem, forwarding or agent.
//! - Runs the command as the current user, with the configured environment
//!   (`HOME`, `MOUSSE_HOME`, ...) and the home as working directory:
//!   - Unix: through `/bin/sh -c <command>`, as OpenSSH does with a POSIX
//!     login shell, so the remote command form of §3.3 runs as written;
//!   - Windows (Windows remotes are not supported in 1b, so this only
//!     stands in for a Unix remote on the PC): the one command form Mousse
//!     sends, `exec /bin/sh -c '"$HOME"/.mousse/bin/<launcher> <args>'`, is
//!     read here and the launcher named in [`Config::launchers`] runs with
//!     those arguments. A launcher that is not there fails as `sh` does
//!     (`not found`, exit 127).
//! - Launchers may be the built-in echo stand-in for `mousse-cli net-engine
//!   ssh`: the marker, then stdin echoed back.
//! - [`Shell::WindowsCmd`] answers every command as a Windows `cmd` remote
//!   does to `exec` (exit 1, "'exec' is not recognized ...").
//! - Wires stdin, stdout, stderr (extended data 1) and the exit status.
//! - Can print a login-shell preamble on stdout before the command's output.
//! - Kills the child's whole tree when the channel or session ends (a Unix
//!   process group, or `taskkill /T /F` on Windows).
//!
//! It runs on its own tokio runtime, so plain `#[test]` functions can use
//! it.
#![allow(dead_code)]

use std::collections::HashMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, ChannelMsg, MethodKind, MethodSet};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::oneshot;

/// The marker `pipe` and `mousse-cli net-engine ssh` write first.
pub const MARKER: &[u8] = b"mousse-ssh/1\n";

/// How the server runs a command.
#[derive(Clone, Debug)]
pub enum Shell {
    /// Unix: `/bin/sh -c <command>`. Windows: the §3.3 command form, read
    /// here (see the module docs).
    Default,
    /// A Windows `cmd` remote: `exec` is not a command there.
    WindowsCmd,
}

/// What a launcher in `~/.mousse/bin` runs (Windows only; on Unix the
/// tests write real launcher scripts).
#[derive(Clone, Debug)]
pub enum Launcher {
    /// A program, with these variables added.
    Program {
        path: PathBuf,
        env: Vec<(OsString, OsString)>,
    },
    /// The marker, then stdin echoed back until it ends.
    Echo,
}

/// Server settings.
pub struct Config {
    pub host_key: PrivateKey,
    /// The only client key accepted.
    pub client_key: PublicKey,
    pub shell: Shell,
    /// Environment for the command, added to the server's own.
    pub env: Vec<(OsString, OsString)>,
    /// Working directory for the command (the user's home).
    pub cwd: Option<PathBuf>,
    /// Printed on stdout before the command's output, as a login shell's
    /// rc files would.
    pub preamble: Vec<u8>,
    /// Windows only: the launchers by name.
    pub launchers: HashMap<String, Launcher>,
}

/// A fresh Ed25519 key.
pub fn generate_key() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("ed25519 key")
}

/// A key's `SHA256:` fingerprint, as `ssh-keygen -l` prints it.
pub fn sha256(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// A running server. Dropping it stops the listener; sessions in flight
/// end and their children are killed.
pub struct TestSshd {
    pub addr: SocketAddr,
    pub host_key: PublicKey,
    stop: Option<server::RunningServerHandle>,
    rt: Option<tokio::runtime::Runtime>,
}

impl TestSshd {
    pub fn start(config: Config) -> Self {
        Self::start_on(config, 0)
    }

    /// [`TestSshd::start`] on `127.0.0.1:<port>` (0 picks one).
    pub fn start_on(config: Config, port: u16) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("sshd runtime");
        let (addr, host_key, stop) = rt
            .block_on(serve(config, port))
            .expect("start the test sshd");
        Self {
            addr,
            host_key,
            stop: Some(stop),
            rt: Some(rt),
        }
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// `SHA256:<base64>`, as `ssh-keygen -l` prints it.
    pub fn host_key_sha256(&self) -> String {
        sha256(&self.host_key)
    }

    /// The host key as a `known_hosts` key part: `<type> <base64>`.
    pub fn host_key_line(&self) -> String {
        self.host_key.to_openssh().expect("openssh encoding")
    }
}

impl Drop for TestSshd {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.shutdown("stopping".into());
        }
        if let Some(rt) = self.rt.take() {
            rt.shutdown_timeout(Duration::from_secs(2));
        }
    }
}

async fn serve(
    config: Config,
    port: u16,
) -> std::io::Result<(SocketAddr, PublicKey, server::RunningServerHandle)> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = listener.local_addr()?;
    let host_key = config.host_key.public_key().clone();
    let russh_config = Arc::new(server::Config {
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        keys: vec![config.host_key],
        auth_rejection_time: Duration::from_millis(100),
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: Some(Duration::from_secs(600)),
        nodelay: true,
        ..Default::default()
    });
    let shared = Arc::new(Shared {
        client_key: config.client_key,
        shell: config.shell,
        env: config.env,
        cwd: config.cwd,
        preamble: config.preamble,
        launchers: config.launchers,
    });
    let mut server = Factory { shared };
    let (handle_tx, handle_rx) = oneshot::channel();
    tokio::spawn(async move {
        let running = server.run_on_socket(russh_config, &listener);
        let _ = handle_tx.send(running.handle());
        let _ = running.await;
    });
    let stop = handle_rx
        .await
        .map_err(|_| std::io::Error::other("the server task ended"))?;
    Ok((addr, host_key, stop))
}

struct Shared {
    client_key: PublicKey,
    shell: Shell,
    env: Vec<(OsString, OsString)>,
    cwd: Option<PathBuf>,
    preamble: Vec<u8>,
    launchers: HashMap<String, Launcher>,
}

struct Factory {
    shared: Arc<Shared>,
}

impl server::Server for Factory {
    type Handler = Conn;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Conn {
        Conn {
            shared: self.shared.clone(),
            channels: HashMap::new(),
            kills: Vec::new(),
        }
    }
}

/// One client connection.
pub struct Conn {
    shared: Arc<Shared>,
    channels: HashMap<ChannelId, Channel<Msg>>,
    /// Dropped with the connection, which kills every child it started.
    kills: Vec<oneshot::Sender<()>>,
}

impl Conn {
    fn accepted(&self, key: &PublicKey) -> Auth {
        if key.key_data() == self.shared.client_key.key_data() {
            Auth::Accept
        } else {
            Auth::reject()
        }
    }
}

/// What one exec request runs.
enum Plan {
    Child(Command),
    Echo,
    Fail { stderr: Vec<u8>, code: u32 },
}

impl server::Handler for Conn {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        offer: server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(self.accepted(offer.public_key))
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(self.accepted(key.public_key))
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(channel) = self.channels.remove(&id) else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let command = String::from_utf8_lossy(command).into_owned();
        let preamble = self.shared.preamble.clone();
        match plan(&self.shared, &command) {
            Plan::Child(cmd) => {
                let child = match spawn(&self.shared, cmd) {
                    Ok(child) => child,
                    Err(_) => {
                        session.channel_failure(id)?;
                        return Ok(());
                    }
                };
                session.channel_success(id)?;
                let (kill_tx, kill_rx) = oneshot::channel();
                self.kills.push(kill_tx);
                tokio::spawn(run(channel, child, preamble, kill_rx));
            }
            Plan::Echo => {
                session.channel_success(id)?;
                tokio::spawn(echo(channel, preamble));
            }
            Plan::Fail { stderr, code } => {
                session.channel_success(id)?;
                tokio::spawn(fail(channel, preamble, stderr, code));
            }
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        id: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)?;
        Ok(())
    }
}

fn plan(shared: &Shared, command: &str) -> Plan {
    if let Shell::WindowsCmd = shared.shell {
        let word = command.split_whitespace().next().unwrap_or("");
        return Plan::Fail {
            stderr: format!(
                "'{word}' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n"
            )
            .into_bytes(),
            code: 1,
        };
    }
    if cfg!(unix) {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(command);
        return Plan::Child(cmd);
    }
    // Windows: read the one command form Mousse sends.
    let not_found = |what: &str| Plan::Fail {
        stderr: format!("/bin/sh: 1: {what}: not found\n").into_bytes(),
        code: 127,
    };
    let Some(inner) = command
        .strip_prefix("exec /bin/sh -c '")
        .and_then(|c| c.strip_suffix('\''))
    else {
        return not_found(command);
    };
    let Some(rest) = inner.strip_prefix("\"$HOME\"/.mousse/bin/") else {
        return not_found(inner);
    };
    let mut words = rest.split(' ');
    let name = words.next().unwrap_or("");
    let args: Vec<&str> = words.collect();
    match shared.launchers.get(name) {
        None => not_found(&format!("~/.mousse/bin/{name}")),
        Some(Launcher::Echo) => Plan::Echo,
        Some(Launcher::Program { path, env }) => {
            let mut cmd = Command::new(path);
            cmd.args(&args).envs(env.iter().map(|(k, v)| (k, v)));
            Plan::Child(cmd)
        }
    }
}

fn spawn(shared: &Shared, mut cmd: Command) -> std::io::Result<tokio::process::Child> {
    cmd.envs(shared.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(cwd) = &shared.cwd {
        cmd.current_dir(cwd);
    }
    #[cfg(unix)]
    cmd.process_group(0);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    cmd.spawn()
}

/// Kill the child and everything it started.
async fn kill_tree(child: &mut tokio::process::Child) {
    if let Some(pid) = child.id() {
        #[cfg(unix)]
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{pid}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        #[cfg(windows)]
        let _ = Command::new("taskkill")
            .args(["/T", "/F", "/PID", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
            .status()
            .await;
    }
    let _ = child.kill().await;
}

async fn run(
    channel: Channel<Msg>,
    mut child: tokio::process::Child,
    preamble: Vec<u8>,
    kill_rx: oneshot::Receiver<()>,
) {
    let (mut read, write) = channel.split();
    let mut stdin = child.stdin.take();
    let (Some(mut stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return;
    };

    let mut out = write.make_writer();
    let mut err = write.make_writer_ext(Some(1));
    let out_task = tokio::spawn(async move {
        if !preamble.is_empty() {
            out.write_all(&preamble).await?;
        }
        tokio::io::copy(&mut stdout, &mut out).await?;
        out.flush().await
    });
    let err_task = tokio::spawn(async move {
        tokio::io::copy(&mut stderr, &mut err).await?;
        err.flush().await
    });

    // Client to child. Signals `gone` when the channel or the session ends,
    // which kills the child.
    let (gone_tx, gone_rx) = oneshot::channel::<()>();
    let in_task = tokio::spawn(async move {
        loop {
            match read.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    if let Some(w) = stdin.as_mut() {
                        if w.write_all(&data).await.is_err() {
                            stdin = None;
                        }
                    }
                }
                Some(ChannelMsg::Eof) => {
                    if let Some(mut w) = stdin.take() {
                        let _ = w.shutdown().await;
                    }
                }
                Some(ChannelMsg::Close) | None => {
                    let _ = gone_tx.send(());
                    return;
                }
                Some(_) => {}
            }
        }
    });

    let status = tokio::select! {
        status = child.wait() => status.ok(),
        _ = gone_rx => { kill_tree(&mut child).await; None }
        _ = kill_rx => { kill_tree(&mut child).await; None }
    };
    let _ = out_task.await;
    let _ = err_task.await;
    if let Some(status) = status {
        let code = status.code().map(|c| c as u32).unwrap_or(255);
        let _ = write.exit_status(code).await;
        let _ = write.eof().await;
        let _ = write.close().await;
    }
    in_task.abort();
}

/// The `mousse-cli net-engine ssh` stand-in: the marker, then stdin back.
async fn echo(channel: Channel<Msg>, preamble: Vec<u8>) {
    let (mut read, write) = channel.split();
    let mut out = write.make_writer();
    if out.write_all(&preamble).await.is_err() || out.write_all(MARKER).await.is_err() {
        return;
    }
    let _ = out.flush().await;
    loop {
        match read.wait().await {
            Some(ChannelMsg::Data { data }) => {
                if out.write_all(&data).await.is_err() {
                    return;
                }
                let _ = out.flush().await;
            }
            Some(ChannelMsg::Eof) => break,
            Some(ChannelMsg::Close) | None => return,
            Some(_) => {}
        }
    }
    let _ = write.exit_status(0).await;
    let _ = write.eof().await;
    let _ = write.close().await;
}

/// A command that fails at once with `stderr` and `code`.
async fn fail(channel: Channel<Msg>, preamble: Vec<u8>, stderr: Vec<u8>, code: u32) {
    let (_read, write) = channel.split();
    let mut out = write.make_writer();
    let mut err = write.make_writer_ext(Some(1));
    let _ = out.write_all(&preamble).await;
    let _ = out.flush().await;
    let _ = err.write_all(&stderr).await;
    let _ = err.flush().await;
    let _ = write.exit_status(code).await;
    let _ = write.eof().await;
    let _ = write.close().await;
}
