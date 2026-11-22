//! This computer's own routes (Phase 1b §1.5): `<state>/routes.json`, which
//! addresses the listener binds, and which it advertises.
//!
//! - **Bound:** `lan` binds `0.0.0.0`, which also serves every other
//!   interface. Without `lan`: each tailnet (`100.64.0.0/10`) address of the
//!   interfaces when `tailnet` is on, the forwarded-to LAN address when
//!   `public` is set, and `127.0.0.1` only when nothing is selected. IPv4
//!   only, one socket per address, all on the kept port.
//! - **Advertised** in tickets and pairback routes: only what is served.
//!   `lan`: the interfaces' private IPv4 addresses; `tailnet`: their tailnet
//!   addresses, when bound; `public` and `tunnels` as given.
//! - **Restart:** a change to `lan`, `tailnet`, `port` or the forwarded-to
//!   address, `public` becoming empty or not, and the first tunnel added or
//!   the last removed need a restart ([`RoutesConfig::restart_needed`]).
//!   Other list changes reach the next ticket.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::NetError;
use crate::pipe::{classify, AddrClass, AddrPolicy, LocalRoute, RouteKind};
use crate::store::write_atomic;

/// Most route hints a ticket carries (wire 10.2).
const MAX_ADVERTISED: usize = mousse_net_core::pairing::MAX_ROUTES;

/// Where a route this computer offers comes from: the way a joiner reaches
/// it (`docs/pairing-flow-design.md` §2). Relays are the helper's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Way {
    /// A served private IPv4 address of an interface.
    Lan,
    /// A served `100.64.0.0/10` address of an interface.
    Tailnet,
    /// An entry of the `public` list (a port forward).
    Public,
    /// An entry of the `tunnels` list.
    Tunnel,
}

impl Way {
    /// The name in the app protocol.
    pub fn name(self) -> &'static str {
        match self {
            Self::Lan => "lan",
            Self::Tailnet => "tailnet",
            Self::Public => "public",
            Self::Tunnel => "tunnel",
        }
    }
}

/// One route this computer offers, and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The way it came from.
    pub way: Way,
    /// The route in its canonical form.
    pub route: String,
}

/// `<state>/routes.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutesConfig {
    /// Listen on every interface and advertise the LAN addresses.
    #[serde(default)]
    pub lan: bool,
    /// Listen on, and advertise, the tailnet addresses.
    #[serde(default)]
    pub tailnet: bool,
    /// Port-forward routes (`tcp://`), advertised as given.
    #[serde(default)]
    pub public: Vec<String>,
    /// The LAN address the router forwards to; bound when `public` is set
    /// without `lan`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_to: Option<Ipv4Addr>,
    /// Tunnel routes (`wss://`), advertised as given.
    #[serde(default)]
    pub tunnels: Vec<String>,
    /// The fixed port; `None` keeps the port picked at the first start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl RoutesConfig {
    /// Check the routes and the forwarded-to address against `policy`
    /// and `interfaces` (this computer's addresses): `public` entries are
    /// `tcp` routes naming no forbidden address, `tunnels` are `wss`
    /// routes, and the forwarded-to address is one of this computer's.
    /// Routes come back in their canonical form.
    pub fn checked(mut self, policy: &AddrPolicy, interfaces: &[IpAddr]) -> Result<Self, String> {
        let canonical = |list: &[String], kind: &str| -> Result<Vec<String>, String> {
            let mut out: Vec<String> = Vec::new();
            for text in list {
                let route = LocalRoute::parse(text).map_err(|e| e.to_string())?;
                let ok = matches!(
                    (kind, &route),
                    ("tcp", LocalRoute::Tcp { .. }) | ("wss", LocalRoute::Wss { .. })
                );
                if !ok {
                    return Err(format!("{text} is not a {kind}:// route"));
                }
                if policy.names_forbidden(&route) {
                    return Err(format!("{text} names an address that is never dialled"));
                }
                if !out.contains(&route.uri()) {
                    out.push(route.uri());
                }
            }
            Ok(out)
        };
        self.public = canonical(&self.public, "tcp")?;
        self.tunnels = canonical(&self.tunnels, "wss")?;
        if let Some(addr) = self.forward_to {
            if !interfaces.contains(&IpAddr::V4(addr)) {
                return Err(format!("{addr} is not an address of this computer"));
            }
        }
        if !self.public.is_empty() && !self.lan && self.forward_to.is_none() {
            return Err("a port forward needs the LAN address the router forwards to".into());
        }
        if self.port == Some(0) {
            return Err("the port is 1 to 65535".into());
        }
        Ok(self)
    }

    /// Whether changing from `self` to `next` needs the helper restarted.
    pub fn restart_needed(&self, next: &Self) -> bool {
        self.lan != next.lan
            || self.tailnet != next.tailnet
            || self.port != next.port
            || self.public.is_empty() != next.public.is_empty()
            || (!next.public.is_empty() && self.forward_to != next.forward_to)
            || self.tunnels.is_empty() != next.tunnels.is_empty()
    }

    /// The addresses to bind, given this computer's `interfaces`.
    pub fn bind_plan(&self, interfaces: &[IpAddr]) -> Vec<IpAddr> {
        let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        if self.lan {
            return vec![any];
        }
        let selected = self.tailnet || !self.public.is_empty();
        // The control build listens everywhere whenever anything is on.
        if cfg!(mousse_control = "bind-all-lan-off") && selected {
            return vec![any];
        }
        let mut out: Vec<IpAddr> = Vec::new();
        if self.tailnet {
            for ip in interfaces {
                if ip.is_ipv4() && classify(*ip) == AddrClass::Tailnet && !out.contains(ip) {
                    out.push(*ip);
                }
            }
        }
        if !self.public.is_empty() {
            if let Some(addr) = self.forward_to.map(IpAddr::V4) {
                if !out.contains(&addr) {
                    out.push(addr);
                }
            }
        }
        if !selected {
            out.push(IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
        out
    }

    /// The routes to advertise when the listener serves `bound` on `port`,
    /// with this computer's `interfaces`: at most 8. The first distinct
    /// [`RoutesConfig::candidates`], in their order.
    pub fn advertised(&self, interfaces: &[IpAddr], bound: &[IpAddr], port: u16) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for candidate in self.candidates(interfaces, bound, port) {
            if !out.contains(&candidate.route) && out.len() < MAX_ADVERTISED {
                out.push(candidate.route);
            }
        }
        out
    }

    /// Every route this config offers when the listener serves `bound` on
    /// `port`, with this computer's `interfaces`, before any cap and with
    /// repeats kept (`docs/pairing-flow-design.md` §2): the served LAN and
    /// tailnet addresses in interface order, then `public`, then
    /// `tunnels`. Each route is in its canonical form and carries the way
    /// it came from, never one read back from its text: a `public` entry
    /// naming a private address is still `public`.
    pub fn candidates(&self, interfaces: &[IpAddr], bound: &[IpAddr], port: u16) -> Vec<Candidate> {
        let all = bound.iter().any(IpAddr::is_unspecified);
        let served = |ip: &IpAddr| all || bound.contains(ip);
        let mut out: Vec<Candidate> = Vec::new();
        for ip in interfaces.iter().filter(|ip| ip.is_ipv4()) {
            let class = classify(*ip);
            let way = if self.lan && class == AddrClass::Lan && !is_link_local(ip) {
                Way::Lan
            } else if self.tailnet && class == AddrClass::Tailnet {
                Way::Tailnet
            } else {
                continue;
            };
            if served(ip) {
                out.push(Candidate {
                    way,
                    route: LocalRoute::tcp(std::net::SocketAddr::new(*ip, port)).uri(),
                });
            }
        }
        let listed = self
            .public
            .iter()
            .map(|t| (Way::Public, t))
            .chain(self.tunnels.iter().map(|t| (Way::Tunnel, t)));
        for (way, text) in listed {
            if let Ok(route) = LocalRoute::parse(text) {
                out.push(Candidate {
                    way,
                    route: route.uri(),
                });
            }
        }
        out
    }

    /// Whether the ws listener runs (§4.1): while a tunnel is set.
    pub fn ws_listener(&self) -> bool {
        !self.tunnels.is_empty()
    }
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(_) => false,
    }
}

/// Where `routes.json` lives.
#[derive(Clone, Debug)]
pub struct RoutesStore {
    path: PathBuf,
}

impl RoutesStore {
    /// `routes.json` in `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            path: dir.join("routes.json"),
        }
    }

    /// The config, or `None` when there is no file yet (the helper then
    /// listens as its command line says).
    pub fn load(&self) -> Result<Option<RoutesConfig>, NetError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(NetError::Store(format!("{}: {e}", self.path.display()))),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| NetError::Store(format!("{}: {e}", self.path.display())))
    }

    /// Write the config atomically.
    pub fn save(&self, config: &RoutesConfig) -> Result<(), NetError> {
        let bytes = serde_json::to_vec_pretty(config)
            .map_err(|e| NetError::Store(format!("{}: {e}", self.path.display())))?;
        write_atomic(&self.path, &bytes)
    }
}

/// Whether `route` is one this computer may serve itself on (a `tcp`
/// route); `routes.test` dials only those and `wss` tunnels.
pub fn testable(route: &LocalRoute) -> bool {
    matches!(route.kind(), RouteKind::Tcp | RouteKind::Ws)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn any() -> Vec<IpAddr> {
        vec![ip("0.0.0.0")]
    }

    /// Ten LAN addresses fill a ticket: the tunnel after them is cut from
    /// what is advertised, yet stays a candidate, of its own way.
    #[test]
    fn a_later_way_survives_the_cap_among_the_candidates() {
        let interfaces: Vec<IpAddr> = (1..=10).map(|n| ip(&format!("192.168.1.{n}"))).collect();
        let config = RoutesConfig {
            lan: true,
            tunnels: vec!["wss://t.example/mousse-net/1".into()],
            ..RoutesConfig::default()
        };
        let advertised = config.advertised(&interfaces, &any(), 7000);
        assert_eq!(advertised.len(), MAX_ADVERTISED);
        assert!(advertised.iter().all(|r| r.starts_with("tcp://192.168.1.")));
        let candidates = config.candidates(&interfaces, &any(), 7000);
        assert_eq!(candidates.len(), 11);
        assert_eq!(
            candidates.last(),
            Some(&Candidate {
                way: Way::Tunnel,
                route: "wss://t.example:443/mousse-net/1".into(),
            })
        );
    }

    /// The way comes from the list an entry is in: a port forward naming a
    /// private address is `public`, and with LAN off no interface address
    /// is offered for it.
    #[test]
    fn a_public_entry_keeps_its_way_whatever_its_address() {
        let config = RoutesConfig {
            tailnet: true,
            public: vec!["tcp://192.168.1.9:7000".into()],
            forward_to: Some("192.168.1.9".parse().unwrap()),
            ..RoutesConfig::default()
        };
        let interfaces = [ip("192.168.1.9"), ip("100.100.1.2")];
        let bound = [ip("192.168.1.9"), ip("100.100.1.2")];
        let candidates = config.candidates(&interfaces, &bound, 7000);
        assert_eq!(
            candidates,
            vec![
                Candidate {
                    way: Way::Tailnet,
                    route: "tcp://100.100.1.2:7000".into(),
                },
                Candidate {
                    way: Way::Public,
                    route: "tcp://192.168.1.9:7000".into(),
                },
            ]
        );
    }

    /// Only served addresses are offered: a tailnet address whose socket is
    /// not bound is no candidate, and neither are link-local addresses.
    #[test]
    fn unserved_and_link_local_addresses_are_not_candidates() {
        let config = RoutesConfig {
            lan: false,
            tailnet: true,
            ..RoutesConfig::default()
        };
        let interfaces = [ip("100.100.1.2"), ip("100.100.1.3")];
        let candidates = config.candidates(&interfaces, &[ip("100.100.1.3")], 7000);
        assert_eq!(
            candidates
                .iter()
                .map(|c| c.route.as_str())
                .collect::<Vec<_>>(),
            vec!["tcp://100.100.1.3:7000"]
        );
        let lan = RoutesConfig {
            lan: true,
            ..RoutesConfig::default()
        };
        assert!(lan
            .candidates(&[ip("169.254.3.4")], &any(), 7000)
            .is_empty());
    }

    /// A route listed twice stays twice among the candidates, each with its
    /// way, and is advertised once, where it first appears.
    #[test]
    fn repeats_are_kept_as_candidates_and_advertised_once() {
        let config = RoutesConfig {
            lan: true,
            public: vec![
                "tcp://192.168.1.9:7000".into(),
                "tcp://far.example:7000".into(),
            ],
            ..RoutesConfig::default()
        };
        let interfaces = [ip("192.168.1.9")];
        let candidates = config.candidates(&interfaces, &any(), 7000);
        let ways: Vec<(Way, &str)> = candidates
            .iter()
            .map(|c| (c.way, c.route.as_str()))
            .collect();
        assert_eq!(
            ways,
            vec![
                (Way::Lan, "tcp://192.168.1.9:7000"),
                (Way::Public, "tcp://192.168.1.9:7000"),
                (Way::Public, "tcp://far.example:7000"),
            ]
        );
        assert_eq!(
            config.advertised(&interfaces, &any(), 7000),
            vec!["tcp://192.168.1.9:7000", "tcp://far.example:7000"]
        );
    }
}
