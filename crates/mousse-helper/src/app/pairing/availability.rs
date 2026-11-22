//! The ways this computer can offer, and `routes.available`
//! (`docs/pairing-flow-design.md` §2 and §3).
//!
//! **Inventory.** Every candidate, before any cap, with the way it came
//! from: `lan` and `tailnet` from the addresses the listener serves now,
//! `public` and `tunnel` from their lists, `relay` from this computer's
//! registered relays. Without `routes.json` the listener serves what
//! `--listen-ip` gives, and those addresses take the way of their class.
//! Candidates are deduplicated by canonical text, first way first. A
//! selected ticket is built from the inventory: select by way (and exact
//! route), then cap at `MAX_ROUTES`. The 1.1 invitation path does not use
//! it.
//!
//! **Readiness.** `routes.available {}` → `{ways: [{way, state, reason,
//! routes}]}`, all five ways in order. `routes` is what a selection of that
//! way alone puts in a ticket now, and is empty unless the way is `ready`.
//! It sends nothing on the network.

use std::net::{IpAddr, SocketAddr};

use mousse_net_core::pairing::MAX_ROUTES;
use mousse_net_io::pipe::{classify, AddrClass, LocalRoute};
use mousse_net_io::routes::{RoutesConfig, RoutesStore, Way};
use serde_json::{json, Map, Value};

use super::super::{error, Shared};
use crate::serve::ListenState;

/// The ways, in the order `routes.available` lists them.
pub const WAYS: [&str; 5] = ["lan", "tailnet", "public", "tunnel", "relay"];

/// One route this computer can put in a ticket now.
#[derive(Clone, Debug)]
pub struct Offer {
    pub way: &'static str,
    pub route: String,
}

/// What this computer can offer now.
pub struct Inventory {
    /// Every candidate, deduplicated by canonical text, in way order.
    pub offers: Vec<Offer>,
    /// The listener state the offers were read from.
    listen: ListenState,
    /// This computer's interface addresses, or why they could not be
    /// listed.
    interfaces: Result<Vec<IpAddr>, String>,
    /// Own relays: how many are set, or why `relays.json` could not be
    /// read.
    relays: Result<usize, String>,
}

impl Inventory {
    /// Why the relay inventory could not be read, if it could not.
    pub fn relay_store_failed(&self) -> Option<&str> {
        self.relays.as_ref().err().map(String::as_str)
    }
}

/// The tunnel origins this computer serves now: the configured and
/// command-line tunnels, while the WebSocket listener runs. The managed
/// tunnel of pull request #10 is added here once it merges.
fn tunnel_origins(shared: &Shared, listen: &ListenState) -> Vec<String> {
    if shared.info.ws_port.is_none() {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    for text in listen.config.tunnels.iter().chain(&listen.extra) {
        if let Ok(route) = LocalRoute::parse(text) {
            out.push(route.uri());
        }
    }
    out
}

/// The way of an address the listener serves without `routes.json`:
/// IPv4 literals of class `lan` or `tailnet` under this build's policy.
fn served_way(shared: &Shared, route: &LocalRoute) -> Option<Way> {
    let (Some(ip), Some(port)) = (route.ip(), route.port()) else {
        return None;
    };
    if !ip.is_ipv4() || !matches!(route, LocalRoute::Tcp { .. }) {
        return None;
    }
    match shared
        .caller
        .addr_policy()
        .class_of(SocketAddr::new(ip, port))
    {
        AddrClass::Lan => Some(Way::Lan),
        AddrClass::Tailnet => Some(Way::Tailnet),
        _ => None,
    }
}

/// Whether a port forward is served: by the 0.0.0.0 socket, or by the
/// socket on the forwarded-to address.
fn public_served(listen: &ListenState) -> bool {
    let any = listen.bound.iter().any(IpAddr::is_unspecified);
    let forwarded = listen
        .config
        .forward_to
        .is_some_and(|a| listen.bound.contains(&IpAddr::V4(a)));
    any || forwarded
}

/// The routes the 1.1 invitation path carries: what the listener
/// advertises, then the relay hints while there is room.
pub fn legacy_routes(shared: &Shared) -> Vec<String> {
    let mut routes = shared
        .info
        .listen
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .routes
        .clone();
    for hint in super::super::relay::ticket_hints(shared) {
        if routes.len() < MAX_ROUTES {
            routes.push(hint);
        }
    }
    routes
}

/// Everything this computer can offer now, before any cap.
pub fn inventory(shared: &Shared) -> Inventory {
    let listen = shared
        .info
        .listen
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let interfaces = super::super::changes::listed_interface_ips();
    let mut all: Vec<(Way, String)> = Vec::new();
    match listen.listen_ip {
        // No `routes.json`: what `--listen-ip` serves, whatever the
        // synthesized config says.
        Some(ip) => {
            for hint in crate::serve::route_hints(ip, listen.port) {
                if let Ok(route) = LocalRoute::parse(&hint) {
                    if let Some(way) = served_way(shared, &route) {
                        all.push((way, route.uri()));
                    }
                }
            }
        }
        None => {
            let ips = interfaces.as_deref().unwrap_or_default();
            for c in listen.config.candidates(ips, &listen.bound, listen.port) {
                if matches!(c.way, Way::Lan | Way::Tailnet) {
                    all.push((c.way, c.route));
                }
            }
        }
    }
    if public_served(&listen) {
        for c in listen.config.candidates(&[], &listen.bound, listen.port) {
            if c.way == Way::Public {
                all.push((c.way, c.route));
            }
        }
    }
    let mut offers: Vec<Offer> = Vec::new();
    let mut push = |way: &'static str, route: String| {
        if !offers.iter().any(|o| o.route == route) {
            offers.push(Offer { way, route });
        }
    };
    for way in [Way::Lan, Way::Tailnet, Way::Public] {
        for (w, route) in &all {
            if *w == way {
                push(way.name(), route.clone());
            }
        }
    }
    for route in tunnel_origins(shared, &listen) {
        push(Way::Tunnel.name(), route);
    }
    let relays = match super::super::relay::own_relay_hints(shared) {
        Ok(own) => {
            for hint in own.hints {
                push("relay", hint);
            }
            Ok(own.configured)
        }
        Err(e) => Err(e),
    };
    // Must-fail control: the way is selected from the capped 1.1 list.
    if cfg!(mousse_control = "select-after-route-cap") {
        let legacy = legacy_routes(shared);
        offers.retain(|o| legacy.contains(&o.route));
    }
    Inventory {
        offers,
        listen,
        interfaces,
        relays,
    }
}

/// The routes a ticket of `way` carries, `route` alone if given: at most
/// `MAX_ROUTES`. Empty when the inventory has nothing for it.
pub fn select(inventory: &Inventory, way: &str, route: Option<&str>) -> Vec<String> {
    // Must-fail control: a selected ticket carries every way's hints.
    let all_ways = cfg!(mousse_control = "invite-all-ways");
    let mut picked: Vec<String> = inventory
        .offers
        .iter()
        .filter(|o| all_ways || o.way == way)
        .map(|o| o.route.clone())
        .collect();
    if let Some(route) = route {
        picked.retain(|r| r == route);
        // Must-fail control: a route outside the inventory is carried.
        if picked.is_empty() && cfg!(mousse_control = "selector-adds-address") {
            picked.push(route.to_owned());
        }
    }
    picked.truncate(MAX_ROUTES);
    picked
}

/// The ways of `routes`, distinct, in order. A route the inventory does
/// not hold has no way.
pub fn ways_of(inventory: &Inventory, routes: &[String]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for route in routes {
        if let Some(offer) = inventory.offers.iter().find(|o| &o.route == route) {
            if !out.contains(&offer.way) {
                out.push(offer.way);
            }
        }
    }
    out
}

/// Whether this computer has an interface address of `class` (IPv4; LAN
/// without link-local), or `None` when the interfaces could not be listed.
fn has_interface(inventory: &Inventory, class: AddrClass) -> Option<bool> {
    let list = inventory.interfaces.as_ref().ok()?;
    Some(list.iter().any(|ip| match ip {
        IpAddr::V4(v4) => classify(*ip) == class && !v4.is_link_local(),
        IpAddr::V6(_) => false,
    }))
}

/// Whether the listener running now serves addresses of `class`.
fn running_on(shared: &Shared, inventory: &Inventory, class: AddrClass) -> bool {
    let listen = &inventory.listen;
    match listen.listen_ip {
        Some(ip) if ip.is_unspecified() => true,
        Some(ip) => {
            let route = LocalRoute::tcp(SocketAddr::new(ip, listen.port));
            let way = served_way(shared, &route);
            matches!(
                (class, way),
                (AddrClass::Lan, Some(Way::Lan)) | (AddrClass::Tailnet, Some(Way::Tailnet))
            )
        }
        None => match class {
            AddrClass::Lan => listen.config.lan,
            AddrClass::Tailnet => listen.config.tailnet,
            _ => false,
        },
    }
}

/// Whether the saved setting for `way` differs from the one running, so
/// it takes effect at the next start ([`RoutesConfig::restart_needed`],
/// per way).
fn restart_pending(running: &RoutesConfig, saved: Option<&RoutesConfig>, way: &str) -> bool {
    let Some(saved) = saved else {
        return false;
    };
    match way {
        "lan" => saved.lan != running.lan,
        "tailnet" => saved.tailnet != running.tailnet,
        "public" => {
            saved.public.is_empty() != running.public.is_empty()
                || (!saved.public.is_empty() && saved.forward_to != running.forward_to)
        }
        "tunnel" => saved.tunnels.is_empty() != running.tunnels.is_empty(),
        _ => false,
    }
}

/// Why `way` has nothing to offer: `(state, reason)` as `routes.available`
/// says it. `saved` is `routes.json` as stored.
fn why_not(
    shared: &Shared,
    inventory: &Inventory,
    saved: Option<&RoutesConfig>,
    way: &str,
) -> (&'static str, &'static str) {
    const NA: &str = "unavailable";
    let running = &inventory.listen.config;
    if restart_pending(running, saved, way) {
        return (NA, "restart_required");
    }
    match way {
        "lan" | "tailnet" => {
            let class = if way == "lan" {
                AddrClass::Lan
            } else {
                AddrClass::Tailnet
            };
            match (
                running_on(shared, inventory, class),
                has_interface(inventory, class),
            ) {
                (_, None) => (NA, "interface_unknown"),
                (_, Some(false)) => (NA, "no_interface"),
                (false, Some(true)) => ("off", "disabled"),
                (true, Some(true)) => (NA, "not_bound"),
            }
        }
        "public" if !running.public.is_empty() => (NA, "not_bound"),
        "tunnel" if !running.tunnels.is_empty() || !inventory.listen.extra.is_empty() => {
            (NA, "origin_unavailable")
        }
        "relay" => match inventory.relays {
            Ok(0) | Err(_) => (NA, "not_configured"),
            Ok(_) => (NA, "relay_not_registered"),
        },
        _ => (NA, "not_configured"),
    }
}

/// How one way stands: `(state, reason, routes)`. `Err` when the relay
/// state could not be read.
pub fn readiness(
    shared: &Shared,
    inventory: &Inventory,
    saved: Option<&RoutesConfig>,
    way: &str,
) -> Result<(&'static str, Option<&'static str>, Vec<String>), String> {
    if shared.removal.is_paused() {
        return Ok(("unavailable", Some("paused"), Vec::new()));
    }
    if way == "relay" {
        if let Some(e) = inventory.relay_store_failed() {
            return Err(e.to_owned());
        }
    }
    let routes = select(inventory, way, None);
    if routes.is_empty() {
        let (state, reason) = why_not(shared, inventory, saved, way);
        return Ok((state, Some(reason), Vec::new()));
    }
    if way == "relay" && !super::super::relay::slot_free(shared)? {
        return Ok(("unavailable", Some("relay_capacity"), Vec::new()));
    }
    Ok(("ready", None, routes))
}

/// Why a selection of `way` has nothing to offer, for its
/// `way_unavailable` error. The stored routes config is read as well as it
/// can be.
pub fn unavailable_reason(shared: &Shared, inventory: &Inventory, way: &str) -> &'static str {
    let saved = RoutesStore::in_dir(&shared.info.state_dir)
        .load()
        .ok()
        .flatten();
    why_not(shared, inventory, saved.as_ref(), way).1
}

/// `routes.available {}`.
pub fn available(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    if let Some(field) = map.keys().find(|k| !matches!(k.as_str(), "id" | "op")) {
        return error(
            id,
            "bad_request",
            format!("routes.available has no field {field:?}"),
        );
    }
    let saved = match RoutesStore::in_dir(&shared.info.state_dir).load() {
        Ok(saved) => saved,
        Err(e) => return error(id, "store_failed", e.to_string()),
    };
    let inventory = inventory(shared);
    let mut ways = Vec::new();
    for way in WAYS {
        match readiness(shared, &inventory, saved.as_ref(), way) {
            Ok((state, reason, routes)) => ways.push(json!({
                "way": way,
                "state": state,
                "reason": reason,
                "routes": routes,
            })),
            Err(e) => return error(id, "store_failed", e),
        }
    }
    json!({"re": id, "ways": ways})
}
