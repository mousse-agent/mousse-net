//! Phase 1b spike S1. See README.md.

mod drive;
mod remote;
mod sshd;
#[cfg(windows)]
mod winpipe;

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use russh::keys::PublicKey;

fn usage() -> ! {
    eprintln!(
        "usage:
  ssh-pipe sshd --listen ADDR --client-key FILE --out DIR [--host-key FILE] [--shell sh|cmd|PATH]
                [--preamble-file FILE] [--home DIR] [--env K=V]... [--seconds N]
  ssh-pipe keygen --keygen SSH_KEYGEN --dir DIR
  ssh-pipe drive --ssh SSH --host H --port P --user U --state DIR --expect-fp FP --remote CMD
                 [--refused-port P] [--variants] [--quiet-port P]
  ssh-pipe echo | sleeper | alive PID | sock-test DIR | sock-connect DIR | quiet-listen ADDR SECS
  ssh-pipe winpipe-server NAME [--seconds N] | winpipe-client NAME"
    );
    std::process::exit(64)
}

/// `--name value` pairs and bare flags.
pub struct Args(Vec<String>);

impl Args {
    pub fn get(&self, name: &str) -> Option<String> {
        let pos = self.0.iter().position(|a| a == name)?;
        self.0.get(pos + 1).cloned()
    }
    pub fn all(&self, name: &str) -> Vec<String> {
        self.0
            .windows(2)
            .filter(|w| w[0] == name)
            .map(|w| w[1].clone())
            .collect()
    }
    pub fn need(&self, name: &str) -> String {
        self.get(name).unwrap_or_else(|| {
            eprintln!("missing {name}");
            usage()
        })
    }
    pub fn flag(&self, name: &str) -> bool {
        self.0.iter().any(|a| a == name)
    }
}

fn main() {
    let mut argv = std::env::args().skip(1);
    let Some(cmd) = argv.next() else { usage() };
    let args = Args(argv.collect());
    let code = match cmd.as_str() {
        "sshd" => run_sshd(&args),
        "keygen" => drive::keygen(&args),
        "drive" => drive::drive(&args),
        "echo" => remote::echo(),
        "sleeper" => remote::sleeper(),
        "alive" => remote::alive(&args.0),
        "sock-test" => remote::sock_test(&args.0),
        "sock-connect" => remote::sock_connect(&args.0),
        "quiet-listen" => remote::quiet_listen(&args.0),
        #[cfg(windows)]
        "winpipe-server" => winpipe::server(&args),
        #[cfg(windows)]
        "winpipe-client" => winpipe::client(&args),
        _ => usage(),
    };
    std::process::exit(code)
}

fn run_sshd(args: &Args) -> i32 {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let listen = args.need("--listen").parse().expect("--listen ADDR");
        let client_line = std::fs::read_to_string(args.need("--client-key")).expect("client key");
        let client_key = PublicKey::from_openssh(client_line.trim()).expect("client key format");
        let out = PathBuf::from(args.need("--out"));
        std::fs::create_dir_all(&out).expect("out dir");
        let host_key = match args.get("--host-key") {
            Some(path) if std::path::Path::new(&path).exists() => {
                russh::keys::PrivateKey::from_openssh(std::fs::read_to_string(&path).unwrap())
                    .expect("host key")
            }
            other => {
                let key = sshd::Config::generate_host_key();
                if let Some(path) = other {
                    let text = key
                        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                        .unwrap();
                    std::fs::write(path, text.as_bytes()).unwrap();
                }
                key
            }
        };
        let shell = match args.get("--shell").as_deref() {
            None => sshd::Shell::default(),
            Some("cmd") => sshd::Shell::Cmd,
            Some("sh") => sshd::Shell::Posix("/bin/sh".into()),
            Some(path) => sshd::Shell::Posix(path.into()),
        };
        let mut env: Vec<(OsString, OsString)> = Vec::new();
        let home = args.get("--home").map(PathBuf::from);
        if let Some(home) = &home {
            std::fs::create_dir_all(home).expect("home");
            env.push(("HOME".into(), home.clone().into()));
            env.push(("MOUSSE_HOME".into(), home.join(".mousse").into()));
            if cfg!(windows) {
                env.push(("USERPROFILE".into(), home.clone().into()));
            }
        }
        for kv in args.all("--env") {
            if let Some((k, v)) = kv.split_once('=') {
                env.push((k.into(), v.into()));
            }
        }
        let preamble = args
            .get("--preamble-file")
            .map(|p| std::fs::read(p).expect("preamble"))
            .unwrap_or_default();
        let server = sshd::TestSshd::start(sshd::Config {
            listen,
            host_key,
            client_key,
            shell,
            env,
            cwd: home,
            preamble,
        })
        .await
        .expect("start");
        let fp = server.host_key_sha256();
        std::fs::write(out.join("sshd-port"), server.addr.port().to_string()).unwrap();
        std::fs::write(out.join("sshd-fp"), &fp).unwrap();
        std::fs::write(out.join("sshd-hostkey.pub"), server.host_key_line()).unwrap();
        println!("ready {} {fp}", server.addr);
        let secs: u64 = args
            .get("--seconds")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1800);
        tokio::time::sleep(Duration::from_secs(secs)).await;
        server.stop().await;
        0
    })
}
