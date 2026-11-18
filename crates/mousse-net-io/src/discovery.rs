//! LAN discovery: mDNS with a rotating random instance name, plus manual
//! addresses as the fallback.
//!
//! The advertised record says only "a Mousse host is listening here": the
//! instance name and the mDNS host name are random, change on every start
//! and every [`ROTATE_EVERY_MS`], and the TXT record carries just the
//! protocol version. Nothing in it names the device or its identity. A
//! caller that is looking for a paired host tries each address it finds;
//! TLS with the stored pin tells the right host from the others.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use mousse_net_core::Millis;
use rand_core::CryptoRng;

use crate::clock::Clock;
use crate::error::NetError;
use crate::rng::os_rng;

/// The DNS-SD service type.
pub const SERVICE_TYPE: &str = "_mousse._tcp.local.";

/// How often the instance name changes while running (15 minutes).
pub const ROTATE_EVERY_MS: u64 = 15 * 60 * 1000;

/// Prefix of every instance name.
pub const NAME_PREFIX: &str = "mousse-";

/// Random characters after the prefix (base32, 5 bits each: 60 bits).
pub const NAME_RANDOM_CHARS: usize = 12;

const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// A fresh random instance name, `mousse-` and 12 base32 characters.
pub fn random_instance_name<R: CryptoRng + ?Sized>(rng: &mut R) -> String {
    let mut bytes = [0u8; NAME_RANDOM_CHARS];
    rng.fill_bytes(&mut bytes);
    let mut name = String::with_capacity(NAME_PREFIX.len() + NAME_RANDOM_CHARS);
    name.push_str(NAME_PREFIX);
    for b in bytes {
        name.push(BASE32[usize::from(b & 31)] as char);
    }
    name
}

/// The current instance name and when it changes next. Pure: time and
/// randomness are passed in.
#[derive(Clone, Debug)]
pub struct RotatingName {
    current: String,
    since: Millis,
    period_ms: u64,
}

impl RotatingName {
    /// A new name at `now` (so every start gets a new one).
    pub fn new<R: CryptoRng + ?Sized>(rng: &mut R, now: Millis, period_ms: u64) -> Self {
        Self {
            current: random_instance_name(rng),
            since: now,
            period_ms: period_ms.max(1),
        }
    }

    /// The name to advertise now.
    pub fn current(&self) -> &str {
        &self.current
    }

    /// When the name changes next.
    pub fn next_rotation(&self) -> Millis {
        self.since.plus(self.period_ms)
    }

    /// Rotate if the period is over. Returns the old name when it changed.
    pub fn poll<R: CryptoRng + ?Sized>(&mut self, rng: &mut R, now: Millis) -> Option<String> {
        if now < self.next_rotation() {
            return None;
        }
        let mut next = random_instance_name(rng);
        while next == self.current {
            next = random_instance_name(rng);
        }
        self.since = now;
        Some(std::mem::replace(&mut self.current, next))
    }
}

fn mdns_err(e: mdns_sd::Error) -> NetError {
    NetError::Io(std::io::Error::other(e.to_string()))
}

fn service(name: &str, port: u16) -> Result<ServiceInfo, NetError> {
    let host = format!("{name}.local.");
    ServiceInfo::new(SERVICE_TYPE, name, &host, "", port, &[("v", "1")][..])
        .map(ServiceInfo::enable_addr_auto)
        .map_err(mdns_err)
}

/// Advertises this host while it runs, rotating the name.
pub struct Advertiser {
    daemon: ServiceDaemon,
    name: Arc<Mutex<RotatingName>>,
    task: tokio::task::JoinHandle<()>,
}

impl Advertiser {
    /// Start advertising `port`. Opens multicast sockets.
    pub fn start(port: u16, clock: Arc<dyn Clock>) -> Result<Self, NetError> {
        let daemon = ServiceDaemon::new().map_err(mdns_err)?;
        let rotating = RotatingName::new(&mut os_rng(), clock.mono(), ROTATE_EVERY_MS);
        daemon
            .register(service(rotating.current(), port)?)
            .map_err(mdns_err)?;
        let name = Arc::new(Mutex::new(rotating));
        let task_daemon = daemon.clone();
        let task_name = name.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let mut guard = match task_name.lock() {
                    Ok(guard) => guard,
                    Err(_) => return,
                };
                if let Some(old) = guard.poll(&mut os_rng(), clock.mono()) {
                    let _ = task_daemon.unregister(&format!("{old}.{SERVICE_TYPE}"));
                    if let Ok(info) = service(guard.current(), port) {
                        let _ = task_daemon.register(info);
                    }
                }
            }
        });
        Ok(Self { daemon, name, task })
    }

    /// The name advertised right now.
    pub fn current_name(&self) -> String {
        self.name
            .lock()
            .map(|n| n.current().to_owned())
            .unwrap_or_default()
    }

    /// Stop advertising.
    pub fn stop(self) {
        self.task.abort();
        let _ = self.daemon.shutdown();
    }
}

/// Look for Mousse hosts on the LAN for `wait`. Opens multicast sockets.
pub async fn browse(wait: Duration) -> Result<Vec<SocketAddr>, NetError> {
    let daemon = ServiceDaemon::new().map_err(mdns_err)?;
    let events = daemon.browse(SERVICE_TYPE).map_err(mdns_err)?;
    let mut found = BTreeSet::new();
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Ok(event)) = tokio::time::timeout_at(deadline, events.recv_async()).await {
        if let ServiceEvent::ServiceResolved(resolved) = event {
            for ip in &resolved.addresses {
                found.insert(SocketAddr::new(ip.to_ip_addr(), resolved.port));
            }
        }
    }
    let _ = daemon.shutdown();
    Ok(found.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    #[test]
    fn names_have_the_prefix_and_only_base32() {
        let mut r = os_rng();
        for _ in 0..50 {
            let name = random_instance_name(&mut r);
            assert!(name.starts_with(NAME_PREFIX));
            let tail = &name[NAME_PREFIX.len()..];
            assert_eq!(tail.len(), NAME_RANDOM_CHARS);
            assert!(tail.bytes().all(|b| BASE32.contains(&b)), "{name}");
        }
    }

    #[test]
    fn every_start_gets_a_different_name() {
        let mut r = os_rng();
        let names: BTreeSet<String> = (0..64)
            .map(|_| {
                RotatingName::new(&mut r, Millis(0), ROTATE_EVERY_MS)
                    .current()
                    .to_owned()
            })
            .collect();
        assert_eq!(names.len(), 64);
    }

    #[test]
    fn the_name_rotates_at_the_period_and_not_before() {
        let mut r = rng(7);
        let mut name = RotatingName::new(&mut r, Millis(1_000), 60_000);
        let first = name.current().to_owned();
        assert_eq!(name.next_rotation(), Millis(61_000));
        assert_eq!(name.poll(&mut r, Millis(60_999)), None);
        assert_eq!(name.current(), first);
        assert_eq!(name.poll(&mut r, Millis(61_000)), Some(first.clone()));
        let second = name.current().to_owned();
        assert_ne!(second, first);
        // The period restarts from the rotation.
        assert_eq!(name.next_rotation(), Millis(121_000));
        assert_eq!(name.poll(&mut r, Millis(120_999)), None);
        assert_eq!(name.poll(&mut r, Millis(500_000)), Some(second));
    }

    #[test]
    fn names_do_not_depend_on_the_device() {
        // Two devices with the same random stream would get the same name;
        // nothing else (host name, identity) goes into it.
        let a = RotatingName::new(&mut rng(3), Millis(0), 1);
        let b = RotatingName::new(&mut rng(3), Millis(99), 1);
        assert_eq!(a.current(), b.current());
    }
}
