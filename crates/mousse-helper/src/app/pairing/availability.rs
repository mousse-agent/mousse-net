//! The ways this computer can offer, and `routes.available`
//! (`docs/pairing-flow-design.md` §2 and §3).
//!
//! **Inventory.** Every candidate, before any cap, with the way it came
//! from: `lan` and `tailnet` from the addresses the listener serves now,
//! `public` and `tunnel` from their lists, `relay` from this computer's
//! registered relays. Without `routes.json` the listener serves what
//! `--listen-ip` gives (every address, uncapped), and those addresses take
//! the way of their class. Candidates are deduplicated by canonical text
//! within each way, so a route served two ways is an offer of each, and a
//! candidate longer than `MAX_ROUTE_LEN` is left out. A selected ticket is
//! built from the inventory: select by way (and exact route), then cap at
//! `MAX_ROUTES`. The 1.1 invitation path does not use it.
//!
//! **Readiness.** `routes.available {}` → `{ways: [{way, state, reason,
//! routes}]}`, all five ways in order. `routes` is what a selection of that
//! way alone puts in a ticket now, and is empty unless the way is `ready`.
//! It sends nothing on the network.

use std::net::{IpAddr, SocketAddr};

use mousse_net_core::pairing::{MAX_ROUTES, MAX_ROUTE_LEN};
use mousse_net_io::pipe::{classify, AddrClass, AddrPolicy, LocalRoute};
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
    /// Every candidate that fits a ticket, deduplicated by canonical text
    /// within its way, in way order.
    pub offers: Vec<Offer>,
    /// The ways that had a candidate longer than `MAX_ROUTE_LEN`, left out.
    too_long: Vec<&'static str>,
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
/// command-line tunnels, then the app's managed tunnel
/// (`routes.managed_tunnel`), while the WebSocket listener runs.
fn tunnel_origins(shared: &Shared, listen: &ListenState) -> Vec<String> {
    if shared.info.ws_port.is_none() {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    let configured = listen.config.tunnels.iter().chain(&listen.extra);
    for text in configured.chain(&listen.managed_tunnel) {
        if let Ok(route) = LocalRoute::parse(text) {
            out.push(route.uri());
        }
    }
    out
}

/// The way of an address the listener serves without `routes.json`:
/// IPv4 literals of class `lan` or `tailnet` under `policy`.
fn served_way(policy: &AddrPolicy, route: &LocalRoute) -> Option<Way> {
    let (Some(ip), Some(port)) = (route.ip(), route.port()) else {
        return None;
    };
    if !ip.is_ipv4() || !matches!(route, LocalRoute::Tcp { .. }) {
        return None;
    }
    match policy.class_of(SocketAddr::new(ip, port)) {
        AddrClass::Lan => Some(Way::Lan),
        AddrClass::Tailnet => Some(Way::Tailnet),
        _ => None,
    }
}

/// The `lan` and `tailnet` candidates of a listener on `ip`:`port` without
/// `routes.json`: every address it serves (for `0.0.0.0`, each usable one
/// of `addrs`), uncapped, with the way of its class. The 1.1 advertisement
/// ([`crate::serve::route_hints`]) is the same list cut to eight before it
/// is classed; selection must not inherit that cut.
fn listener_candidates(
    policy: &AddrPolicy,
    ip: IpAddr,
    port: u16,
    addrs: &[IpAddr],
) -> Vec<(Way, String)> {
    crate::serve::served_hints(ip, port, addrs)
        .iter()
        .filter_map(|hint| {
            let route = LocalRoute::parse(hint).ok()?;
            Some((served_way(policy, &route)?, route.uri()))
        })
        .collect()
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
            let addrs = interfaces.as_deref().unwrap_or_default();
            all.extend(listener_candidates(
                shared.caller.addr_policy(),
                ip,
                listen.port,
                addrs,
            ));
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
    let mut listed: Vec<(&'static str, String)> = Vec::new();
    for way in [Way::Lan, Way::Tailnet, Way::Public] {
        for (w, route) in &all {
            if *w == way {
                listed.push((way.name(), route.clone()));
            }
        }
    }
    for route in tunnel_origins(shared, &listen) {
        listed.push((Way::Tunnel.name(), route));
    }
    let relays = match super::super::relay::own_relay_hints(shared) {
        Ok(own) => {
            for hint in own.hints {
                listed.push(("relay", hint));
            }
            Ok(own.configured)
        }
        Err(e) => Err(e),
    };
    let (mut offers, too_long) = offers_of(listed);
    // Must-fail control: the way is selected from the capped 1.1 list.
    if cfg!(mousse_control = "select-after-route-cap") {
        let legacy = legacy_routes(shared);
        offers.retain(|o| legacy.contains(&o.route));
    }
    Inventory {
        offers,
        too_long,
        listen,
        interfaces,
        relays,
    }
}

/// The offers of `listed` candidates (in way order), and the ways that had
/// one too long for a ticket. Deduplicated within each way: a route served
/// two ways (a LAN address also listed as a port forward) is an offer of
/// each. A candidate longer than `MAX_ROUTE_LEN` can never be offered, so
/// it is left out before readiness and before the cap.
fn offers_of(listed: Vec<(&'static str, String)>) -> (Vec<Offer>, Vec<&'static str>) {
    let mut offers: Vec<Offer> = Vec::new();
    let mut too_long: Vec<&'static str> = Vec::new();
    for (way, route) in listed {
        if route.len() > MAX_ROUTE_LEN {
            if !too_long.contains(&way) {
                too_long.push(way);
            }
        } else if !offers.iter().any(|o| o.way == way && o.route == route) {
            offers.push(Offer { way, route });
        }
    }
    (offers, too_long)
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

/// The ways of a selection of `way` that gave `routes`, distinct, in order:
/// a route offered as `way` counts as `way`, any other as the first way
/// that offers it. A route the inventory does not hold has no way.
pub fn ways_of(inventory: &Inventory, way: &str, routes: &[String]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for route in routes {
        let of_route = || inventory.offers.iter().filter(move |o| &o.route == route);
        if let Some(offer) = of_route()
            .find(|o| o.way == way)
            .or_else(|| of_route().next())
        {
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
    running_on_with(shared.caller.addr_policy(), &inventory.listen, class)
}

fn running_on_with(policy: &AddrPolicy, listen: &ListenState, class: AddrClass) -> bool {
    match listen.listen_ip {
        Some(ip) if ip.is_unspecified() => true,
        Some(ip) => {
            let route = LocalRoute::tcp(SocketAddr::new(ip, listen.port));
            let way = served_way(policy, &route);
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

/// Whether the saved setting for `way` differs from what is running, so
/// what this way offers changes at the next start. `routes.config` applies
/// a change that needs no restart to the running config at once
/// ([`RoutesConfig::restart_needed`]), so any difference left is one that
/// waits for a restart. For `lan` and `tailnet`, the running side is what
/// the listener actually serves (including when started without
/// `routes.json`), not only the synthesized config. The port counts for
/// every way the listener serves.
fn restart_pending(
    policy: &AddrPolicy,
    listen: &ListenState,
    saved: Option<&RoutesConfig>,
    way: &str,
) -> bool {
    let Some(saved) = saved else {
        return false;
    };
    let running = &listen.config;
    let port = saved.port != running.port;
    match way {
        "lan" => {
            let served = running_on_with(policy, listen, AddrClass::Lan);
            saved.lan != served || (port && served)
        }
        "tailnet" => {
            let served = running_on_with(policy, listen, AddrClass::Tailnet);
            saved.tailnet != served || (port && served)
        }
        "public" => {
            canonical(&saved.public) != canonical(&running.public)
                || (!saved.public.is_empty() && saved.forward_to != running.forward_to)
                || (port && !running.public.is_empty())
        }
        "tunnel" => canonical(&saved.tunnels) != canonical(&running.tunnels),
        _ => false,
    }
}

/// A route list as canonical text, deduplicated in first-occurrence order:
/// `routes.config` stores it that way via `RoutesConfig::checked`, while
/// the running copy keeps what `routes.json` had at start.
fn canonical(list: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for text in list {
        let uri = LocalRoute::parse(text).map_or_else(|_| text.clone(), |r| r.uri());
        if !out.contains(&uri) {
            out.push(uri);
        }
    }
    out
}

/// Whether `way` waits for a restart: its saved setting differs from what
/// is running ([`restart_pending`]).
pub fn restart_required(
    shared: &Shared,
    inventory: &Inventory,
    saved: Option<&RoutesConfig>,
    way: &str,
) -> bool {
    restart_pending(shared.caller.addr_policy(), &inventory.listen, saved, way)
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
    if restart_required(shared, inventory, saved, way) {
        return (NA, "restart_required");
    }
    if inventory.too_long.contains(&way) {
        return (NA, "route_too_long");
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
        "tunnel"
            if !running.tunnels.is_empty()
                || !inventory.listen.extra.is_empty()
                || inventory.listen.managed_tunnel.is_some() =>
        {
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
    // What the listener offers now is about to be replaced.
    if restart_required(shared, inventory, saved, way) {
        return Ok(("unavailable", Some("restart_required"), Vec::new()));
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
/// `way_unavailable` error. `saved` is `routes.json` as stored.
pub fn unavailable_reason(
    shared: &Shared,
    inventory: &Inventory,
    saved: Option<&RoutesConfig>,
    way: &str,
) -> &'static str {
    why_not(shared, inventory, saved, way).1
}

/// `routes.json` as stored: `None` when there is none, `Err` when it cannot
/// be read.
pub fn saved_config(shared: &Shared) -> Result<Option<RoutesConfig>, String> {
    RoutesStore::in_dir(&shared.info.state_dir)
        .load()
        .map_err(|e| e.to_string())
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
    let saved = match saved_config(shared) {
        Ok(saved) => saved,
        Err(e) => return error(id, "store_failed", e),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A `0.0.0.0` listener with eight LAN addresses that sort before a
    /// tailnet one still offers the tailnet address: selection sees every
    /// address, while the 1.1 list is cut to eight before it is classed.
    #[test]
    fn a_wildcard_listener_offers_every_address_uncapped() {
        let policy = AddrPolicy::release();
        let mut addrs: Vec<IpAddr> = (1..=8).map(|n| IpAddr::from([10, 0, 0, n])).collect();
        addrs.push(IpAddr::from([100, 100, 9, 9]));
        addrs.push(IpAddr::from([127, 0, 0, 1]));
        let any = IpAddr::from([0, 0, 0, 0]);
        let tailnet = "tcp://100.100.9.9:7443".to_owned();

        let all = listener_candidates(&policy, any, 7443, &addrs);
        let of = |way: Way| -> Vec<String> {
            all.iter()
                .filter(|(w, _)| *w == way)
                .map(|(_, r)| r.clone())
                .collect()
        };
        assert_eq!(of(Way::Tailnet), std::slice::from_ref(&tailnet));
        assert_eq!(of(Way::Lan).len(), 8, "{all:?}");
        assert!(!all.iter().any(|(_, r)| r.contains("127.0.0.1")));

        let mut legacy = crate::serve::served_hints(any, 7443, &addrs);
        legacy.truncate(8);
        assert!(!legacy.contains(&tailnet), "{legacy:?}");
    }

    /// A listener on one address offers that address alone.
    #[test]
    fn a_listener_on_one_address_offers_it_alone() {
        let policy = AddrPolicy::release();
        let ip = IpAddr::from([100, 100, 9, 9]);
        let addrs = [IpAddr::from([10, 0, 0, 1]), ip];
        assert_eq!(
            listener_candidates(&policy, ip, 7443, &addrs),
            [(Way::Tailnet, "tcp://100.100.9.9:7443".to_owned())]
        );
    }

    fn pairs(offers: &[Offer]) -> Vec<(&'static str, &str)> {
        offers.iter().map(|o| (o.way, o.route.as_str())).collect()
    }

    /// A LAN address also listed as a port forward is an offer of each
    /// way; a route listed twice within one way is one offer.
    #[test]
    fn duplicates_are_dropped_within_a_way_not_across_ways() {
        let lan = "tcp://192.168.1.5:7443";
        let (offers, too_long) = offers_of(vec![
            ("lan", lan.to_owned()),
            ("lan", lan.to_owned()),
            ("public", lan.to_owned()),
            ("public", "tcp://p1.example:7443".to_owned()),
            ("public", lan.to_owned()),
        ]);
        assert_eq!(
            pairs(&offers),
            [
                ("lan", lan),
                ("public", lan),
                ("public", "tcp://p1.example:7443"),
            ]
        );
        assert!(too_long.is_empty());
    }

    /// A candidate longer than `MAX_ROUTE_LEN` is left out before the cap,
    /// so it never takes the place of one that fits; its way is recorded.
    #[test]
    fn a_route_too_long_is_left_out_before_the_cap() {
        let long = format!("tcp://{}.example:7443", "a".repeat(MAX_ROUTE_LEN));
        let fits: Vec<String> = (1..=MAX_ROUTES)
            .map(|n| format!("tcp://p{n}.example:7443"))
            .collect();
        let mut listed = vec![("public", long.clone())];
        listed.extend(fits.iter().map(|r| ("public", r.clone())));
        listed.push((
            "tunnel",
            format!("wss://{}.example/mousse-net/1", "b".repeat(MAX_ROUTE_LEN)),
        ));
        let (offers, too_long) = offers_of(listed);
        assert_eq!(too_long, ["public", "tunnel"]);
        let inventory = Inventory {
            offers,
            too_long,
            listen: ListenState::default(),
            interfaces: Ok(Vec::new()),
            relays: Ok(0),
        };
        assert_eq!(select(&inventory, "public", None), fits);
        assert!(select(&inventory, "public", Some(&long)).is_empty());
        assert!(select(&inventory, "tunnel", None).is_empty());
    }

    /// Without `routes.json`, a `0.0.0.0` listener serves both LAN and
    /// tailnet even though the synthesized config says `tailnet: false`: a
    /// save that turns tailnet off or changes the port marks it pending.
    #[test]
    fn restart_pending_uses_served_ways_when_started_without_routes_json() {
        let policy = AddrPolicy::release();
        let listen = ListenState {
            config: RoutesConfig {
                lan: true,
                tailnet: false,
                ..RoutesConfig::default()
            },
            port: 7000,
            listen_ip: Some(IpAddr::from([0, 0, 0, 0])),
            ..ListenState::default()
        };
        let saved_tailnet_off = RoutesConfig {
            lan: true,
            tailnet: false,
            ..RoutesConfig::default()
        };
        assert!(!restart_pending(
            &policy,
            &listen,
            Some(&saved_tailnet_off),
            "lan"
        ));
        assert!(restart_pending(
            &policy,
            &listen,
            Some(&saved_tailnet_off),
            "tailnet"
        ));

        let saved_port_change = RoutesConfig {
            lan: true,
            tailnet: true,
            port: Some(7443),
            ..RoutesConfig::default()
        };
        assert!(restart_pending(
            &policy,
            &listen,
            Some(&saved_port_change),
            "lan"
        ));
        assert!(restart_pending(
            &policy,
            &listen,
            Some(&saved_port_change),
            "tailnet"
        ));
    }

    /// `canonical` removes duplicates after canonicalization, keeping
    /// first-occurrence order as `RoutesConfig::checked` does.
    #[test]
    fn canonical_deduplicates_in_first_occurrence_order() {
        let list = vec![
            "wss://t.example/mousse-net/1".to_owned(),
            "wss://other.example:443/mousse-net/1".to_owned(),
            "wss://t.example:443/mousse-net/1".to_owned(),
            "wss://T.EXAMPLE/mousse-net/1".to_owned(),
        ];
        assert_eq!(
            canonical(&list),
            [
                "wss://t.example:443/mousse-net/1",
                "wss://other.example:443/mousse-net/1",
            ]
        );
    }
}
