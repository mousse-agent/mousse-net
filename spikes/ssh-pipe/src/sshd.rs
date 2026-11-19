//! A small SSH server for tests, built on `russh`.
//!
//! Written to be lifted into `crates/mousse-helper/tests/common/sshd.rs`:
//! it depends only on `russh`, `tokio` and `rand`, and has no `unsafe`.
//!
//! - Listens on the address it is given (`127.0.0.1:0` in tests).
//! - One generated host key; accepts exactly one client public key.
//! - Exec requests only. No shell, pty, subsystem, forwarding or agent.
//! - Runs the requested command through a shell as the current user
//!   (`/bin/sh -c <command>` on Unix; `cmd.exe /c <command>` on Windows,
//!   which is what Windows OpenSSH does with `cmd` as the default shell),
//!   with the configured environment (`HOME`, `MOUSSE_HOME`, ...) and the
//!   home as working directory.
//! - Wires stdin, stdout, stderr (extended data 1) and the exit status.
//! - Can print a login-shell preamble on stdout before the command's output.
//! - Kills the child's whole tree when the channel or session ends: a Unix
//!   process group (`kill -KILL -<pgid>`), or `taskkill /T /F` on Windows.

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

/// How the server runs a command.
#[derive(Clone, Debug)]
pub enum Shell {
    /// `<path> -c <command>`, as OpenSSH does with a POSIX login shell.
    Posix(PathBuf),
    /// `cmd.exe /c <command>`, the command passed through unquoted, as
    /// Windows OpenSSH does with `cmd` as the default shell.
    Cmd,
}

impl Default for Shell {
    fn default() -> Self {
        if cfg!(windows) {
            Shell::Cmd
        } else {
            Shell::Posix(PathBuf::from("/bin/sh"))
        }
    }
}

/// Server settings.
pub struct Config {
    pub listen: SocketAddr,
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
}

impl Config {
    /// A fresh Ed25519 host key.
    pub fn generate_host_key() -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("ed25519 key")
    }
}

/// A running server. Dropping it stops the listener; sessions in flight
/// end and their children are killed.
pub struct TestSshd {
    pub addr: SocketAddr,
    pub host_key: PublicKey,
    stop: server::RunningServerHandle,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl TestSshd {
    pub async fn start(config: Config) -> std::io::Result<Self> {
        let listener = TcpListener::bind(config.listen).await?;
        let addr = listener.local_addr()?;
        let host_key = config.host_key.public_key().clone();
        let russh_config = Arc::new(server::Config {
            methods: MethodSet::from(&[MethodKind::PublicKey][..]),
            keys: vec![config.host_key],
            auth_rejection_time: Duration::from_millis(100),
            auth_rejection_time_initial: Some(Duration::ZERO),
            inactivity_timeout: Some(Duration::from_secs(3600)),
            nodelay: true,
            ..Default::default()
        });
        let shared = Arc::new(Shared {
            client_key: config.client_key,
            shell: config.shell,
            env: config.env,
            cwd: config.cwd,
            preamble: config.preamble,
        });
        let mut server = Factory { shared };
        let (handle_tx, handle_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let running = server.run_on_socket(russh_config, &listener);
            let _ = handle_tx.send(running.handle());
            running.await
        });
        let stop = handle_rx
            .await
            .map_err(|_| std::io::Error::other("the server task ended"))?;
        Ok(Self {
            addr,
            host_key,
            stop,
            task,
        })
    }

    /// The host key as a `known_hosts` key part: `<type> <base64>`.
    pub fn host_key_line(&self) -> String {
        self.host_key.to_openssh().expect("openssh encoding")
    }

    /// `SHA256:<base64>`, as `ssh-keygen -l` prints it.
    pub fn host_key_sha256(&self) -> String {
        self.host_key.fingerprint(HashAlg::Sha256).to_string()
    }

    pub async fn stop(self) {
        self.stop.shutdown("stopping".into());
        let _ = self.task.await;
    }
}

struct Shared {
    client_key: PublicKey,
    shell: Shell,
    env: Vec<(OsString, OsString)>,
    cwd: Option<PathBuf>,
    preamble: Vec<u8>,
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
        let child = match spawn(&self.shared, &command) {
            Ok(child) => child,
            Err(_) => {
                session.channel_failure(id)?;
                return Ok(());
            }
        };
        session.channel_success(id)?;
        let (kill_tx, kill_rx) = oneshot::channel();
        self.kills.push(kill_tx);
        tokio::spawn(run(channel, child, self.shared.preamble.clone(), kill_rx));
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

fn spawn(shared: &Shared, command: &str) -> std::io::Result<tokio::process::Child> {
    let mut cmd = match &shared.shell {
        Shell::Posix(sh) => {
            let mut cmd = Command::new(sh);
            cmd.arg("-c").arg(command);
            cmd
        }
        Shell::Cmd => cmd_command(command),
    };
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
    cmd.spawn()
}

#[cfg(windows)]
fn cmd_command(command: &str) -> Command {
    let system = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let mut cmd = Command::new(PathBuf::from(system).join("System32").join("cmd.exe"));
    cmd.raw_arg("/c").raw_arg(command);
    // CREATE_NO_WINDOW
    cmd.creation_flags(0x0800_0000);
    cmd
}

#[cfg(not(windows))]
fn cmd_command(_command: &str) -> Command {
    unreachable!("cmd is Windows only")
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
    let mut stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");

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
