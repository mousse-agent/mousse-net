//! Which addresses may be dialled, and resolving a route to them (Phase 1b
//! §1.2).
//!
//! - [`AddrPolicy::class_of`] is [`classify`] for a socket address, plus
//!   the build's loopback rule: release builds never dial loopback, debug
//!   builds may (1a E5a.1). In debug builds `MOUSSE_NET_TEST_CLASS_MAP`
//!   relabels a loopback port as another class, so a check can stand a
//!   loopback listener in for a tailnet or internet address.
//! - [`resolve`]: a name is resolved once per try, every address it gives
//!   is classified, `forbidden` ones are dropped, and the caller dials
//!   exactly the addresses returned. No lower layer resolves the name again.
//! - The automatic rule ([`AddrPolicy::automatic`]): a `tcp` route to an
//!   IP literal of class `lan`. Everything else needs the owner's approval.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use super::{classify, AddrClass, LocalRoute};
use crate::error::NetError;

/// The environment variable a debug build reads its class map from:
/// `<port>=<class>` entries (`lan`, `tailnet` or `public`) separated by
/// commas, for loopback addresses only. A `*=<class>` entry gives the class
/// of every loopback port the map does not name (default `lan`).
pub const TEST_CLASS_MAP_VAR: &str = "MOUSSE_NET_TEST_CLASS_MAP";

/// How this build classifies the addresses it dials.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddrPolicy {
    /// Loopback may be dialled (debug builds).
    loopback: bool,
    /// Loopback ports relabelled as another class.
    map: Vec<(u16, AddrClass)>,
    /// The class of a loopback port the map does not name (`*=<class>`).
    unmapped: Option<AddrClass>,
}

impl AddrPolicy {
    /// A release build's policy: loopback is `forbidden`.
    pub fn release() -> Self {
        Self::default()
    }

    /// A debug build's policy with no class map: loopback counts as `lan`.
    pub fn debug() -> Self {
        Self {
            loopback: true,
            map: Vec::new(),
            unmapped: None,
        }
    }

    /// This build's policy: [`AddrPolicy::release`] in release builds;
    /// [`AddrPolicy::debug`] with the class map from
    /// [`TEST_CLASS_MAP_VAR`] in debug builds.
    pub fn for_build() -> Result<Self, NetError> {
        if !cfg!(debug_assertions) {
            return Ok(Self::release());
        }
        match std::env::var(TEST_CLASS_MAP_VAR) {
            Ok(text) => Self::debug().with_class_map(&text),
            Err(_) => Ok(Self::debug()),
        }
    }

    /// This policy with loopback ports relabelled as `text` says. Only a
    /// policy that dials loopback can use a map.
    pub fn with_class_map(mut self, text: &str) -> Result<Self, NetError> {
        let bad = |why: &str| NetError::Refused(format!("{TEST_CLASS_MAP_VAR}: {why}"));
        if !self.loopback {
            return Err(bad("only debug builds read a class map"));
        }
        for entry in text.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let (port, class) = entry
                .split_once('=')
                .ok_or_else(|| bad("entries are <port>=<class>"))?;
            let class = match class.trim() {
                "lan" => AddrClass::Lan,
                "tailnet" => AddrClass::Tailnet,
                "public" => AddrClass::Public,
                _ => return Err(bad("a class is lan, tailnet or public")),
            };
            if port.trim() == "*" {
                self.unmapped = Some(class);
                continue;
            }
            let port: u16 = port.trim().parse().map_err(|_| bad("bad port"))?;
            self.map.retain(|(p, _)| *p != port);
            self.map.push((port, class));
        }
        Ok(self)
    }

    /// Whether this policy dials loopback.
    pub fn dials_loopback(&self) -> bool {
        self.loopback
    }

    /// The class of `addr` under this policy.
    pub fn class_of(&self, addr: SocketAddr) -> AddrClass {
        let ip = canonical(addr.ip());
        if ip.is_loopback() {
            // The control build dials loopback under the release policy.
            if !self.loopback && !cfg!(mousse_control = "loopback-routes") {
                return AddrClass::Forbidden;
            }
            return self
                .map
                .iter()
                .find(|(port, _)| *port == addr.port())
                .map(|(_, class)| *class)
                .or(self.unmapped)
                .unwrap_or(AddrClass::Lan);
        }
        classify(ip)
    }

    /// The class of an inbound connection from `from` to this host's
    /// listener at `local`. A loopback connection takes the class the map
    /// gives the listener's port (a check's stand-in for a tailnet or
    /// internet listener), else the one it gives `from`'s port; otherwise
    /// `from`'s class.
    pub fn class_of_inbound(&self, from: SocketAddr, local: Option<SocketAddr>) -> AddrClass {
        let mapped = local.and_then(|local| {
            self.map
                .iter()
                .find(|(port, _)| *port == local.port())
                .map(|(_, class)| *class)
        });
        match mapped {
            Some(class) if canonical(from.ip()).is_loopback() && self.loopback => class,
            _ => self.class_of(from),
        }
    }

    /// 1a's automatic rule (§1.3): a `tcp` route to an IP literal of class
    /// `lan`. Such a route needs no approval.
    pub fn automatic(&self, route: &LocalRoute) -> bool {
        match (route, route.ip(), route.port()) {
            (LocalRoute::Tcp { .. }, Some(ip), Some(port)) => {
                self.class_of(SocketAddr::new(ip, port)) == AddrClass::Lan
            }
            _ => false,
        }
    }

    /// Whether the route names an IP literal of class `forbidden`. A plain
    /// `ws` route is the owner's local tunnel hop: loopback is its only
    /// allowed address, in release builds too (§1.1, Decision 2).
    pub fn names_forbidden(&self, route: &LocalRoute) -> bool {
        if let LocalRoute::Ws { host, .. } = route {
            return !host.is_loopback();
        }
        match (route.ip(), route.port()) {
            (Some(ip), Some(port)) => {
                self.class_of(SocketAddr::new(ip, port)) == AddrClass::Forbidden
            }
            _ => false,
        }
    }
}

/// An IPv4-mapped IPv6 address as its IPv4 address.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// What a [`Resolver`] returns.
pub type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, NetError>> + Send + 'a>>;

/// Turns a name into addresses. The system's is [`SystemResolver`]; tests
/// may pass their own to the caller.
pub trait Resolver: Send + Sync {
    /// The addresses of `name` with `port`.
    fn resolve<'a>(&'a self, name: &'a str, port: u16) -> ResolveFuture<'a>;
}

/// The system resolver.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, name: &'a str, port: u16) -> ResolveFuture<'a> {
        Box::pin(async move { Ok(tokio::net::lookup_host((name, port)).await?.collect()) })
    }
}

/// The addresses to dial for `route`, each with its class: a literal as
/// is, a name resolved once. `forbidden` addresses are dropped; none left
/// is [`NetError::Forbidden`]. An `ssh` route has no address here.
pub async fn resolve(
    route: &LocalRoute,
    policy: &AddrPolicy,
    resolver: &Arc<dyn Resolver>,
) -> Result<Vec<(SocketAddr, AddrClass)>, NetError> {
    let (host, port) = match route {
        LocalRoute::Tcp { host, port } | LocalRoute::Wss { host, port, .. } => (host, *port),
        // The owner's local tunnel hop: loopback only, in every build. Its
        // class is the tunnel's, whatever loopback counts as for `tcp`.
        LocalRoute::Ws { host, port, .. } if !policy.names_forbidden(route) => {
            return Ok(vec![(SocketAddr::new(*host, *port), AddrClass::Lan)]);
        }
        LocalRoute::Ws { .. } => {
            return Err(NetError::Forbidden(format!(
                "{} is not a loopback address",
                route.uri()
            )));
        }
        LocalRoute::Ssh { .. } => {
            return Err(NetError::Refused("an ssh route is resolved by ssh".into()));
        }
    };
    let found = match host {
        mousse_net_core::pairing::RouteHost::Dns(name) => {
            // A check's egress fence resolves no name (debug builds only).
            super::test_egress::check_name(name, port)?;
            resolver.resolve(name, port).await?
        }
        _ => route
            .ip()
            .map(|ip| vec![SocketAddr::new(ip, port)])
            .unwrap_or_default(),
    };
    keep_allowed(route, policy, found)
}

fn keep_allowed(
    route: &LocalRoute,
    policy: &AddrPolicy,
    found: Vec<SocketAddr>,
) -> Result<Vec<(SocketAddr, AddrClass)>, NetError> {
    let mut out: Vec<(SocketAddr, AddrClass)> = Vec::new();
    for addr in found {
        let class = policy.class_of(addr);
        if class != AddrClass::Forbidden && !out.iter().any(|(a, _)| *a == addr) {
            out.push((addr, class));
        }
    }
    if out.is_empty() {
        return Err(NetError::Forbidden(format!(
            "{} has no address that may be dialled",
            route.uri()
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_lan_in_debug_and_forbidden_in_release() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert_eq!(AddrPolicy::debug().class_of(addr), AddrClass::Lan);
        if !cfg!(mousse_control = "loopback-routes") {
            assert_eq!(AddrPolicy::release().class_of(addr), AddrClass::Forbidden);
        }
        let mapped = AddrPolicy::debug()
            .with_class_map("9=public, 10=tailnet")
            .unwrap();
        assert_eq!(mapped.class_of(addr), AddrClass::Public);
        assert_eq!(
            mapped.class_of("[::1]:10".parse().unwrap()),
            AddrClass::Tailnet
        );
        assert!(AddrPolicy::release().with_class_map("9=public").is_err());
        assert!(AddrPolicy::debug().with_class_map("9=forbidden").is_err());
    }
}
