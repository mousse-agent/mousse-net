//! `phase3.marker` (Linux): a caller sends a random marker to a host through
//! a relay, inside the peer TLS session of `mousse-net-io` pinned to the
//! host's identity. The marker must appear 0 times in:
//!
//! - a capture of every byte of both legs between the clients and the relay
//!   (a TCP proxy the clients dial);
//! - the relay's decrypted view of both legs (the debug relay tap,
//!   `MOUSSE_RELAY_TAP`);
//! - a sample of the relay process's memory (`/proc/<pid>/mem`).
//!
//! It prints `PASS phase3.marker`, or `FAIL phase3.marker reason=<packet|
//! memory|delivery>` and fails. Positive controls: `marker-in-splice` (the
//! caller also sends the marker in the clear inside the splice, and the
//! relay runs without outer TLS: the capture and tap must find it) and
//! `marker-in-relay-memory` (the relay copies the marker into its heap: the
//! memory sample must find it). Run with `--nocapture`. The memory sample
//! needs Linux: elsewhere the test is ignored, and with `--ignored` it ends
//! `FAIL phase3.marker reason=platform` after the other two checks.

mod common;

use std::io::{BufRead, BufReader};
#[cfg(target_os = "linux")]
use std::io::{Read, Seek, SeekFrom};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use mousse_net_core::identity::SoftwareKey;
use mousse_net_core::relay::{Class, RelayMessage};
use mousse_net_io::certs::CertManager;
use mousse_net_io::{Clock, SharedSigner, SystemClock, TlsPolicy};
use mousse_relay::client::RelayConn;
use mousse_relay::state::{hex, StateDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const ID: &str = "phase3.marker";

/// A TCP proxy in front of the relay that records every byte both ways.
async fn capture_proxy(relay: SocketAddr, seen: Arc<Mutex<Vec<u8>>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let Ok(server) = TcpStream::connect(relay).await else {
                    return;
                };
                let (mut cr, mut cw) = client.into_split();
                let (mut sr, mut sw) = server.into_split();
                let s1 = seen.clone();
                let up = async move {
                    let mut b = vec![0u8; 64 * 1024];
                    while let Ok(n) = cr.read(&mut b).await {
                        if n == 0 || sw.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                        s1.lock().unwrap().extend_from_slice(&b[..n]);
                    }
                };
                let down = async move {
                    let mut b = vec![0u8; 64 * 1024];
                    while let Ok(n) = sr.read(&mut b).await {
                        if n == 0 || cw.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                        seen.lock().unwrap().extend_from_slice(&b[..n]);
                    }
                };
                tokio::join!(up, down);
            });
        }
    });
    addr
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

/// How many times `needle` is in the readable memory of process `pid`.
#[cfg(not(target_os = "linux"))]
fn memory_count(_pid: u32, _needle: &[u8]) -> std::io::Result<usize> {
    Err(std::io::Error::other(
        "the memory sample reads /proc and needs Linux",
    ))
}

/// How many times `needle` is in the readable memory of process `pid`.
#[cfg(target_os = "linux")]
fn memory_count(pid: u32, needle: &[u8]) -> std::io::Result<usize> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mut mem = std::fs::File::open(format!("/proc/{pid}/mem"))?;
    let mut found = 0;
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !perms.starts_with('r') || line.ends_with("[vvar]") || line.ends_with("[vsyscall]") {
            continue;
        }
        let Some((a, b)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16)) else {
            continue;
        };
        let mut pos = start;
        let chunk = 1 << 20;
        let mut carry: Vec<u8> = Vec::new();
        while pos < end {
            let len = (end - pos).min(chunk) as usize;
            let mut buf = vec![0u8; len];
            if mem.seek(SeekFrom::Start(pos)).is_err() || mem.read_exact(&mut buf).is_err() {
                break;
            }
            let mut joined = std::mem::take(&mut carry);
            joined.extend_from_slice(&buf);
            found += count(&joined, needle);
            let keep = needle.len().saturating_sub(1).min(joined.len());
            carry = joined[joined.len() - keep..].to_vec();
            pos += len as u64;
        }
    }
    Ok(found)
}

struct Relay(Child);

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn fail(reason: &str, detail: String) -> ! {
    println!("FAIL {ID} reason={reason}");
    panic!("{detail}");
}

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "the memory sample needs Linux; run with --ignored to check the rest"
)]
async fn the_marker_never_shows_at_the_relay() {
    let mut rnd = [0u8; 16];
    getrandom::fill(&mut rnd).unwrap();
    let marker = format!("MOUSSE-MARKER-{}", hex(&rnd)).into_bytes();

    // The relay, as its own process, with a tap.
    let path = temp_dir("marker");
    let dir = StateDir::init(&path, "127.0.0.1:443", &mut mousse_relay::os_rng()).unwrap();
    let (target, caller) = (key(0x61), key(0x71));
    dir.update(now(), |l| {
        l.authorized
            .push(mousse_net_core::relay::machine::AuthorizedKey::listed(
                target.fingerprint(),
            ))
    })
    .unwrap();
    let tap = path.join("tap.bin");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mousse-relay"));
    cmd.arg("--state")
        .arg(&path)
        .args(["run", "--listen", "127.0.0.1:0"])
        .env("MOUSSE_RELAY_TAP", &tap)
        // Debug builds only: stay dumpable so this test can read the
        // relay's memory (a release relay is never dumpable).
        .env("MOUSSE_NET_RELAY_TEST_KEEP_DUMPABLE", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if cfg!(mousse_control = "marker-in-relay-memory") {
        let f = path.join("control-marker");
        std::fs::write(&f, &marker).unwrap();
        cmd.env("MOUSSE_RELAY_CONTROL_MARKER_FILE", f);
    }
    let mut child = cmd.spawn().unwrap();
    let stderr = child.stderr.take().unwrap();
    let relay_proc = Relay(child);
    let mut first = String::new();
    BufReader::new(stderr).read_line(&mut first).unwrap();
    let relay_addr: SocketAddr = first
        .rsplit(' ')
        .next()
        .and_then(|a| a.trim().parse().ok())
        .unwrap_or_else(|| panic!("relay did not start: {first}"));
    let id = dir.relay_id().unwrap();

    // Both clients dial through the capture proxy.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let proxy = capture_proxy(relay_addr, seen.clone()).await;
    let dial = || RelayConn::dial(proxy, "127.0.0.1", id);
    let h = target.handle(&id);
    let mut reg = dial().await.unwrap();
    reg.send(&RelayMessage::Register {
        key: target.public_key(),
        proof: target.register_proof(&id, &reg.binding),
        hosted: None,
    })
    .await
    .unwrap();
    assert!(matches!(
        relay(&mut reg).await,
        RelayMessage::Registered { .. }
    ));
    allow(&mut reg, 1, &[&caller]).await;
    let mut leg = dial().await.unwrap();
    leg.send(&RelayMessage::Call {
        handle: h,
        key: caller.public_key(),
        proof: caller.call_proof(&id, &h, &leg.binding, Class::Interactive),
        class: Class::Interactive,
    })
    .await
    .unwrap();
    let circuit = incoming(&mut reg).await;
    let mut acc = dial().await.unwrap();
    acc.send(&RelayMessage::Accept {
        handle: h,
        circuit,
        proof: target.accept_proof(&id, &circuit, &acc.binding),
    })
    .await
    .unwrap();
    assert_eq!(relay(&mut leg).await, RelayMessage::Spliced);
    assert_eq!(relay(&mut acc).await, RelayMessage::Spliced);

    // The peer session inside, pinned to the host's identity.
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let host_key = Arc::new(SoftwareKey::generate(&mut mousse_relay::os_rng()));
    let host_pin = host_key.public_key();
    let host_signer: SharedSigner = host_key;
    let caller_signer: SharedSigner = Arc::new(SoftwareKey::generate(&mut mousse_relay::os_rng()));
    let host_cert = CertManager::new(host_signer, clock.clone())
        .current()
        .unwrap();
    let caller_cert = CertManager::new(caller_signer, clock.clone())
        .current()
        .unwrap();
    let policy = TlsPolicy::default();
    let (host_pipe, _) = bridge(acc);
    let (caller_pipe, inject) = bridge(leg);
    let host = {
        let clock = clock.clone();
        let marker = marker.clone();
        tokio::spawn(async move {
            let (mut tls, _) = mousse_net_io::tls::accept(host_pipe, &host_cert, clock, policy)
                .await
                .expect("host side of the peer TLS");
            let mut got = vec![0u8; marker.len() * 200];
            tls.read_exact(&mut got).await.expect("the marker arrives");
            tls.write_all(&marker.repeat(200)).await.unwrap();
            tls.flush().await.unwrap();
            // Keep the session (so the circuit) open until the samples.
            (count(&got, &marker), tls)
        })
    };
    let (mut tls, _) =
        mousse_net_io::tls::connect(caller_pipe, &caller_cert, host_pin, clock, policy)
            .await
            .expect("caller side of the peer TLS, pinned to the host");
    tls.write_all(&marker.repeat(200)).await.unwrap();
    tls.flush().await.unwrap();
    let mut back = vec![0u8; marker.len() * 200];
    tls.read_exact(&mut back).await.unwrap();
    let (delivered, _host_tls) = tokio::time::timeout(WAIT, host).await.unwrap().unwrap();
    if delivered != 200 || count(&back, &marker) != 200 {
        fail(
            "delivery",
            format!(
                "the marker did not cross the relay: {delivered} and {}",
                count(&back, &marker)
            ),
        );
    }
    if cfg!(mousse_control = "marker-in-splice") {
        for _ in 0..50 {
            inject.send(marker.clone()).unwrap();
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The capture and the tap, then the relay's memory while the circuit is
    // still open.
    let in_capture = count(&seen.lock().unwrap(), &marker);
    let tapped = std::fs::read(&tap).unwrap_or_default();
    let in_tap = count(&tapped, &marker);
    println!(
        "captured {} bytes, tapped {} bytes; marker found: capture {in_capture}, tap {in_tap}",
        seen.lock().unwrap().len(),
        tapped.len()
    );
    if tapped.is_empty() {
        fail("delivery", "the relay tap saw no spliced bytes".into());
    }
    if in_capture > 0 || in_tap > 0 {
        fail(
            "packet",
            format!("marker in the capture {in_capture} times, in the tap {in_tap} times"),
        );
    }
    let in_memory = match memory_count(relay_proc.0.id(), &marker) {
        Ok(n) => n,
        Err(e) if cfg!(target_os = "linux") => {
            fail("memory", format!("cannot read the relay's memory: {e}"))
        }
        Err(e) => fail("platform", e.to_string()),
    };
    println!("marker found in the relay's memory {in_memory} times");
    drop(relay_proc);
    let _ = std::fs::remove_dir_all(&path);
    if in_memory > 0 {
        fail(
            "memory",
            format!("marker in the relay's memory {in_memory} times"),
        );
    }
    println!("PASS {ID}");
}
