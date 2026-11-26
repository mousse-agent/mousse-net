//! LAN discovery: mDNS with a rotating random instance name, plus manual
//! addresses as the fallback.
//!
//! The advertised record says only "a Mousse host is listening here": the
//! instance name and the mDNS host name are random, change on every start
//! and every [`IoLimits::mdns_rotate_ms`], and the TXT record carries just the
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
use crate::limits::{ms, IoLimits};
use crate::rng::os_rng;

/// The DNS-SD service type.
pub const SERVICE_TYPE: &str = "_mousse._tcp.local.";

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

/// The record advertised for instance `name` on `port`: the instance and
/// the mDNS host name are both `name` (random, see [`RotatingName`]), the
/// addresses are this machine's, and the TXT record holds only `v=1`.
pub fn record(name: &str, port: u16) -> Result<ServiceInfo, NetError> {
    let host = format!("{name}.local.");
    ServiceInfo::new(SERVICE_TYPE, name, &host, "", port, &[("v", "1")][..])
        .map(ServiceInfo::enable_addr_auto)
        .map_err(mdns_err)
}

/// Advertises this host while it runs, rotating the name.
pub struct Advertiser {
    daemon: ServiceDaemon,
    name: Arc<Mutex<RotatingName>>,
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl Advertiser {
    /// Start advertising `port`, rotating the name as `limits` say. Opens
    /// multicast sockets.
    pub fn start(port: u16, clock: Arc<dyn Clock>, limits: &IoLimits) -> Result<Self, NetError> {
        let daemon = ServiceDaemon::new().map_err(mdns_err)?;
        let rotating = RotatingName::new(&mut os_rng(), clock.mono(), limits.mdns_rotate_ms());
        let check = ms(limits.mdns_rotate_check_ms());
        daemon
            .register(record(rotating.current(), port)?)
            .map_err(mdns_err)?;
        let name = Arc::new(Mutex::new(rotating));
        let task_daemon = daemon.clone();
        let task_name = name.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(check).await;
                let mut guard = match task_name.lock() {
                    Ok(guard) => guard,
                    Err(_) => return,
                };
                if let Some(old) = guard.poll(&mut os_rng(), clock.mono()) {
                    let _ = task_daemon.unregister(&format!("{old}.{SERVICE_TYPE}"));
                    if let Ok(info) = record(guard.current(), port) {
                        let _ = task_daemon.register(info);
                    }
                }
            }
        });
        Ok(Self {
            daemon,
            name,
            port,
            task,
        })
    }

    /// The name advertised right now.
    pub fn current_name(&self) -> String {
        self.name
            .lock()
            .map(|n| n.current().to_owned())
            .unwrap_or_default()
    }

    /// Announce the record again with this computer's addresses now, say
    /// after a wake or an interface change. The daemon also notices new
    /// addresses by itself, every few seconds.
    pub fn refresh(&self) {
        let Ok(name) = self.name.lock() else {
            return;
        };
        if let Ok(info) = record(name.current(), self.port) {
            let _ = self.daemon.register(info);
        }
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

/// What a browse found: addresses where some Mousse host may listen. TLS
/// with the stored pin tells which host each one is.
pub type BrowseFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Vec<SocketAddr>, NetError>> + Send + 'a>,
>;

/// Where a caller looks for hosts on the LAN (Phase 1a §6): mDNS
/// ([`MdnsBrowse`]), or in tests a source that needs no multicast.
pub trait BrowseSource: Send + Sync {
    /// Look for hosts, listening up to `wait`.
    fn browse(&self, wait: Duration) -> BrowseFuture<'_>;
}

/// Browse with mDNS. Opens multicast sockets on every browse.
#[derive(Clone, Copy, Debug, Default)]
pub struct MdnsBrowse;

impl BrowseSource for MdnsBrowse {
    fn browse(&self, wait: Duration) -> BrowseFuture<'_> {
        Box::pin(browse(wait))
    }
}

/// A browse source whose results are reused for
/// [`IoLimits::browse_cache_ms`], so dials to several hosts, or one host
/// retried, browse once. A failed browse is not kept.
pub struct CachedBrowse {
    source: Arc<dyn BrowseSource>,
    clock: Arc<dyn Clock>,
    wait: Duration,
    keep_ms: u64,
    cache: tokio::sync::Mutex<Option<(Millis, Vec<SocketAddr>)>>,
}

impl CachedBrowse {
    /// Cache `source`, timed by `clock`'s monotonic reading.
    pub fn new(source: Arc<dyn BrowseSource>, clock: Arc<dyn Clock>, limits: &IoLimits) -> Self {
        Self {
            source,
            clock,
            wait: ms(limits.browse_wait_ms()),
            keep_ms: limits.browse_cache_ms(),
            cache: tokio::sync::Mutex::new(None),
        }
    }

    /// The cached results while they are fresh, else a new browse.
    /// Concurrent callers share one browse.
    pub async fn addresses(&self) -> Result<Vec<SocketAddr>, NetError> {
        let mut cache = self.cache.lock().await;
        if let Some((at, found)) = cache.as_ref() {
            if self.clock.mono() < at.plus(self.keep_ms) {
                return Ok(found.clone());
            }
        }
        let found = self.source.browse(self.wait).await?;
        *cache = Some((self.clock.mono(), found.clone()));
        Ok(found)
    }

    /// The cached results while they are fresh, without browsing: `None`
    /// when there are none or a browse is running.
    pub fn cached(&self) -> Option<Vec<SocketAddr>> {
        let cache = self.cache.try_lock().ok()?;
        let (at, found) = cache.as_ref()?;
        (self.clock.mono() < at.plus(self.keep_ms)).then(|| found.clone())
    }

    /// Forget the cached results (the network changed).
    pub async fn forget(&self) {
        *self.cache.lock().await = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    struct Counting(std::sync::atomic::AtomicUsize);

    impl BrowseSource for Counting {
        fn browse(&self, _wait: Duration) -> BrowseFuture<'_> {
            let n = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { Ok(vec![SocketAddr::from(([10, 0, 0, n as u8], 7443))]) })
        }
    }

    #[tokio::test]
    async fn browse_results_are_reused_until_they_are_stale() {
        let clock = Arc::new(crate::clock::ManualClock::new());
        clock.freeze_mono();
        let source = Arc::new(Counting(Default::default()));
        let cache = CachedBrowse::new(source.clone(), clock.clone(), &IoLimits::DEFAULT);
        let first = cache.addresses().await.unwrap();
        clock.advance_mono(IoLimits::DEFAULT.browse_cache_ms() - 1);
        assert_eq!(cache.addresses().await.unwrap(), first);
        clock.advance_mono(1);
        let second = cache.addresses().await.unwrap();
        assert_ne!(second, first);
        cache.forget().await;
        assert_ne!(cache.addresses().await.unwrap(), second);
        assert_eq!(source.0.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn the_record_holds_the_random_name_and_the_version_only() {
        let name = random_instance_name(&mut os_rng());
        let info = record(&name, 7443).unwrap();
        assert_eq!(info.get_fullname(), format!("{name}.{SERVICE_TYPE}"));
        assert_eq!(info.get_hostname(), format!("{name}.local."));
        let props: Vec<(String, String)> = info
            .get_properties()
            .iter()
            .map(|p| (p.key().to_owned(), p.val_str().to_owned()))
            .collect();
        assert_eq!(props, vec![("v".to_owned(), "1".to_owned())]);
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
                RotatingName::new(&mut r, Millis(0), IoLimits::DEFAULT.mdns_rotate_ms())
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
