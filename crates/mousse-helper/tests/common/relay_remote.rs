//! A `mousse-relay` running on another machine, for the cross-machine relay
//! checks (`phase3.relay-routes-cross`, `phase3.relay-rotation-cross`). It
//! has the API of the loopback fixture (`common/relay.rs`), so the same
//! cases run against it. Test files include it with `#[path]` as
//! `relay_fixture`.
//!
//! The relay is named by its enrollment links, in `MOUSSE_RELAY_TEST_LINKS`
//! (docs/limits.md, "Relay tests"): whitespace- or comma-separated, each
//! used once, of one relay or several. Links of one relay share its id;
//! each relay must be at an IP address outside loopback. A case that wants
//! a second relay (an approval per destination) needs links of two.
//!
//! As in the loopback fixture, every connection a helper makes to the relay
//! goes through a forwarder in the test process, which counts them and can
//! cut them: each link handed to a helper names that forwarder on loopback,
//! and the forwarder dials the relay on the other machine. The outer TLS,
//! pinned to the relay id in the link, runs end to end through it.
//!
//! Without links, or with too few, a case fails with `NOT_CONFIGURED` in its
//! message; it never passes without the relay.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use mousse_net_core::pairing::RouteHost;
use mousse_net_core::relay::{Class, EnrollmentLink, RelayClientKey, RelayId};
use mousse_net_io::relay::{dial_call, RelayAddr};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{AbortHandle, JoinHandle};

#[path = "relay.rs"]
mod local;
pub use local::caller_key_of;

/// The variable that names the remote relay's enrollment links.
pub const LINKS_VAR: &str = "MOUSSE_RELAY_TEST_LINKS";

/// In the message of every failure caused by missing or too few links.
pub const NOT_CONFIGURED: &str = "remote relay not configured";

const WAIT: Duration = Duration::from_secs(20);

/// One relay on the other machine and its unused links.
struct Remote {
    relay: RelayId,
    addr: SocketAddr,
    links: VecDeque<EnrollmentLink>,
    in_use: bool,
}

static POOL: Mutex<Option<Result<Vec<Remote>, String>>> = Mutex::new(None);

fn lock() -> MutexGuard<'static, Option<Result<Vec<Remote>, String>>> {
    POOL.lock().unwrap_or_else(|e| e.into_inner())
}

/// The relays in `text`, grouped by relay id, or why they cannot be used.
fn parse(text: &str) -> Result<Vec<Remote>, String> {
    let mut remotes: Vec<Remote> = Vec::new();
    for word in text
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|w| !w.is_empty())
    {
        let link = EnrollmentLink::parse(word).map_err(|e| format!("{LINKS_VAR}: a link: {e}"))?;
        let ip: IpAddr = match &link.host {
            RouteHost::Ipv4(ip) => (*ip).into(),
            RouteHost::Ipv6(ip) => (*ip).into(),
            RouteHost::Dns(_) => {
                return Err(format!(
                    "{LINKS_VAR}: {} names a host, not an IP address",
                    link.authority()
                ))
            }
        };
        if ip.is_loopback() || ip.is_unspecified() {
            return Err(format!(
                "{LINKS_VAR}: {} is not another machine; these checks need the relay there",
                link.authority()
            ));
        }
        let addr = SocketAddr::new(ip, link.port);
        match remotes.iter_mut().find(|r| r.relay == link.relay) {
            Some(r) if r.addr != addr => {
                return Err(format!(
                    "{LINKS_VAR}: one relay id at {} and {addr}",
                    r.addr
                ))
            }
            Some(r) => r.links.push_back(link),
            None => remotes.push(Remote {
                relay: link.relay,
                addr,
                links: VecDeque::from([link]),
                in_use: false,
            }),
        }
    }
    if remotes.is_empty() {
        return Err(format!("{LINKS_VAR} is not set or holds no link"));
    }
    Ok(remotes)
}

fn pool() -> MutexGuard<'static, Option<Result<Vec<Remote>, String>>> {
    let mut guard = lock();
    if guard.is_none() {
        let text = std::env::var(LINKS_VAR).unwrap_or_default();
        *guard = Some(parse(&text));
    }
    guard
}

/// What the configured relays are (`<n> link(s) for <address>` each), or
/// why there are none.
pub fn configured() -> Result<String, String> {
    let guard = pool();
    match guard.as_ref().unwrap() {
        Err(why) => Err(why.clone()),
        Ok(remotes) => Ok(remotes
            .iter()
            .map(|r| format!("{} link(s) for {}", r.links.len(), r.addr))
            .collect::<Vec<_>>()
            .join(", ")),
    }
}

/// Counts a forwarded connection as live until both directions end.
struct Live(Arc<AtomicUsize>);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct TestRelay {
    rt: tokio::runtime::Runtime,
    index: usize,
    relay_id: RelayId,
    front: SocketAddr,
    connections: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
    carried: Arc<Mutex<Vec<AbortHandle>>>,
    forwarder: JoinHandle<()>,
}

impl TestRelay {
    /// The next configured relay not in use by another fixture, behind a
    /// new loopback forwarder.
    pub fn start() -> Self {
        let (index, relay_id, target) = {
            let mut guard = pool();
            let remotes = match guard.as_mut().unwrap() {
                Ok(r) => r,
                Err(why) => panic!("{NOT_CONFIGURED}: {why}"),
            };
            let Some((index, r)) = remotes
                .iter_mut()
                .enumerate()
                .find(|(_, r)| !r.in_use && !r.links.is_empty())
            else {
                panic!(
                    "{NOT_CONFIGURED}: no relay with an unused link left in {LINKS_VAR}; \
                     this case needs one more relay or more links"
                );
            };
            r.in_use = true;
            (index, r.relay, r.addr)
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(AtomicUsize::new(0));
        let carried: Arc<Mutex<Vec<AbortHandle>>> = Arc::default();
        let listener = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        let front = listener.local_addr().unwrap();
        let forwarder = rt.spawn({
            let connections = connections.clone();
            let live = live.clone();
            let carried = carried.clone();
            async move {
                while let Ok((mut inbound, _)) = listener.accept().await {
                    connections.fetch_add(1, Ordering::SeqCst);
                    live.fetch_add(1, Ordering::SeqCst);
                    let held = Live(live.clone());
                    let task = tokio::spawn(async move {
                        let _held = held;
                        let dial = tokio::time::timeout(WAIT, TcpStream::connect(target)).await;
                        if let Ok(Ok(mut out)) = dial {
                            let _ = out.set_nodelay(true);
                            let _ = inbound.set_nodelay(true);
                            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut out).await;
                        }
                    });
                    carried.lock().unwrap().push(task.abort_handle());
                }
            }
        });
        Self {
            rt,
            index,
            relay_id,
            front,
            connections,
            live,
            carried,
            forwarder,
        }
    }

    /// The next unused enrollment link of this relay, naming the forwarder.
    pub fn link(&self) -> String {
        let mut guard = pool();
        let remote = &mut guard.as_mut().unwrap().as_mut().unwrap()[self.index];
        let Some(mut link) = remote.links.pop_front() else {
            panic!(
                "{NOT_CONFIGURED}: no unused link left for the relay at {} in {LINKS_VAR}",
                remote.addr
            );
        };
        link.host = RouteHost::Ipv4(std::net::Ipv4Addr::LOCALHOST);
        link.port = self.front.port();
        link.to_text()
    }

    /// The destination helpers approve: `relay://127.0.0.1:<forwarder>`.
    pub fn destination(&self) -> String {
        format!("relay://{}", self.front)
    }

    /// Connections made to this relay so far.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Wait until exactly `n` connections to this relay are open. With no
    /// circuits up, that is the number of live registrations.
    pub fn wait_live(&self, n: usize) {
        let start = Instant::now();
        while self.live.load(Ordering::SeqCst) != n {
            assert!(
                start.elapsed() < WAIT,
                "{} connections open, not {n}",
                self.live.load(Ordering::SeqCst)
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// `CALL` `handle` with `key` and wait for the answer: `Ok` once
    /// spliced, else the error's word (`relay_refused` when the relay
    /// does not list the key for the handle).
    pub fn call(&self, handle: [u8; 32], key: &RelayClientKey) -> Result<(), &'static str> {
        let addr = RelayAddr {
            addr: self.front,
            name: None,
        };
        self.rt
            .block_on(dial_call(
                &addr,
                self.relay_id,
                handle,
                key,
                Class::Interactive,
                WAIT,
            ))
            .map(drop)
            .map_err(|e| e.word())
    }

    /// Cut this relay off: the forwarder stops accepting and every
    /// connection through it closes, so dials to it are refused. The relay
    /// on the other machine keeps running.
    pub fn stop(&mut self) {
        self.forwarder.abort();
        for task in self.carried.lock().unwrap().drain(..) {
            task.abort();
        }
    }

    /// The handle of `host_dir`'s current registration key on this relay,
    /// from its relay seed and stored salt.
    pub fn handle_of(&self, host_dir: &Path) -> [u8; 32] {
        local::handle_in(host_dir, &self.relay_id)
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        self.stop();
        if let Some(Ok(remotes)) = lock().as_mut() {
            remotes[self.index].in_use = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
    const OTHER: &str = "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg";
    const CODE: &str = "CQkJCQkJCQkJCQkJCQkJCQ";

    fn link(authority: &str, id: &str) -> String {
        format!("mousse-relay://{authority}/#{id}.{CODE}")
    }

    #[test]
    fn links_group_by_relay_and_must_name_another_machine() {
        let text = format!(
            "{} {},\n{}",
            link("192.0.2.5:7443", ID),
            link("192.0.2.5:7443", ID),
            link("192.0.2.5:7444", OTHER)
        );
        let remotes = parse(&text).unwrap();
        assert_eq!(remotes.len(), 2);
        assert_eq!(remotes[0].links.len(), 2);
        assert_eq!(remotes[1].addr, "192.0.2.5:7444".parse().unwrap());
        for bad in [
            String::new(),
            " , ".into(),
            link("127.0.0.1:7443", ID),
            link("[::1]:7443", ID),
            link("relay.example:7443", ID),
            format!(
                "{} {}",
                link("192.0.2.5:7443", ID),
                link("192.0.2.6:7443", ID)
            ),
            "mousse-relay://192.0.2.5:7443/#nope".into(),
        ] {
            assert!(parse(&bad).is_err(), "{bad:?} was accepted");
        }
    }
}
