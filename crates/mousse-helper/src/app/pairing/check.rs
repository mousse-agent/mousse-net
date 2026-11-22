//! `join.check {ticket, arrival}`: what a join of a link would do, with no
//! network traffic (`docs/pairing-flow-design.md` §4).
//!
//! The decisions are the ones `join` makes, not a copy: the arrival rule
//! for an in-person ticket and the pause ([`super::admit`]), the refusals
//! before dialling ([`mousse_net_io::Caller::check_join`]: this computer's
//! own ticket, expiry, stored attempts) and the hint filter
//! ([`super::super::paths::hint_decision`]). It reads the stored flow
//! record only: no join hold, no completion replay, no approval, no event,
//! and nothing is written. No name is looked up, no interface is browsed
//! and no socket is opened.
//!
//! The reply has one entry per ticket hint, in ticket order:
//! `{route, way, eligibility, destination, reason, local}`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use mousse_net_core::pairing::{Arrival, InvitationKind};
use mousse_net_io::pipe::{classify, AddrClass, AddrPolicy, LocalRoute};
use serde_json::{json, Map, Value};

use super::super::paths::{hint_decision, HintDecision};
use super::super::{error, Shared};

/// The way a receiver can infer from a route: the class of a `tcp`
/// literal, `tunnel` for `wss`; `None` for a DNS-named `tcp` hint.
fn way_of(policy: &AddrPolicy, route: &LocalRoute) -> Option<&'static str> {
    match route {
        LocalRoute::Tcp { port, .. } => {
            let ip = route.ip()?;
            match policy.class_of(SocketAddr::new(ip, *port)) {
                AddrClass::Lan => Some("lan"),
                AddrClass::Tailnet => Some("tailnet"),
                AddrClass::Public => Some("public"),
                AddrClass::Forbidden => None,
            }
        }
        LocalRoute::Wss { .. } | LocalRoute::Ws { .. } => Some("tunnel"),
        LocalRoute::Ssh { .. } => None,
    }
}

/// Whether this computer has an address that could reach `route` directly:
/// one of the same class, or the address itself. Advice only.
fn local_of(
    interfaces: &Result<Vec<IpAddr>, String>,
    way: Option<&str>,
    route: &LocalRoute,
) -> &'static str {
    let class = match way {
        Some("lan") => AddrClass::Lan,
        Some("tailnet") => AddrClass::Tailnet,
        _ => return "unknown",
    };
    let Ok(list) = interfaces else {
        return "unknown";
    };
    let target = route.ip();
    let present = list.iter().any(|ip| {
        Some(*ip) == target
            || match ip {
                IpAddr::V4(v4) => classify(*ip) == class && !v4.is_link_local(),
                IpAddr::V6(_) => false,
            }
    });
    if present {
        "interface_present"
    } else {
        "no_matching_interface"
    }
}

/// One hint as `join.check` reports it, with the route the owner would
/// approve when it needs approval.
fn hint_entry(
    policy: &AddrPolicy,
    interfaces: &Result<Vec<IpAddr>, String>,
    hint: &str,
) -> (Value, Option<LocalRoute>) {
    let (way, eligibility, destination, reason, local, approve) = match hint_decision(policy, hint)
    {
        HintDecision::Automatic(route) => {
            let way = way_of(policy, &route);
            let local = local_of(interfaces, way, &route);
            (way, "automatic", None, None, local, None)
        }
        HintDecision::Approval(route) => {
            let way = way_of(policy, &route);
            let local = local_of(interfaces, way, &route);
            // Must-fail control: a public hint is reported as automatic.
            if cfg!(mousse_control = "check-auto-approves-public") && way == Some("public") {
                (way, "automatic", None, None, local, None)
            } else {
                let destination = route.uri();
                (
                    way,
                    "approval_required",
                    Some(destination),
                    None,
                    local,
                    Some(route),
                )
            }
        }
        HintDecision::Relay(route) => (
            Some("relay"),
            "approval_required",
            Some(route.endpoint.destination()),
            None,
            "unknown",
            None,
        ),
        HintDecision::Skip(reason) => (None, "skip", None, Some(reason), "unknown", None),
    };
    let entry = json!({
        "route": hint,
        "way": way,
        "eligibility": eligibility,
        "destination": destination,
        "reason": reason,
        "local": local,
    });
    (entry, approve)
}

/// `join.check`; `None` when the reply is sent later (the control build
/// that dials).
pub fn check(shared: &Arc<Shared>, id: &Value, map: &Map<String, Value>) -> Option<Value> {
    if let Some(field) = map
        .keys()
        .find(|k| !matches!(k.as_str(), "id" | "op" | "ticket" | "arrival"))
    {
        return Some(error(
            id,
            "bad_request",
            format!("join.check has no field {field:?}"),
        ));
    }
    let Some(text) = map.get("ticket").and_then(Value::as_str) else {
        return Some(error(id, "bad_request", "join.check needs ticket"));
    };
    let arrival = match map.get("arrival").and_then(Value::as_str) {
        Some("scan") => Arrival::InAppScan,
        Some("link") => Arrival::Link,
        _ => return Some(error(id, "bad_request", "arrival is scan or link")),
    };
    let ticket = match crate::peer::parse_ticket(text) {
        Ok(t) => t,
        Err(e) => return Some(error(id, "bad_ticket", e)),
    };
    let arrival = match super::admit(shared, id, &ticket, arrival) {
        Ok(arrival) => arrival,
        Err(reply) => return Some(reply),
    };
    let name = super::state(shared).name.clone();
    if let Err(e) = shared.caller.check_join(&ticket, arrival, &name, false) {
        return Some(match crate::peer::reason_of(&e).as_str() {
            "store" => error(id, "store_failed", e.to_string()),
            reason => error(id, reason, crate::peer::describe(&e)),
        });
    }
    let policy = shared.caller.addr_policy().clone();
    let interfaces = super::super::changes::listed_interface_ips();
    let mut hints = Vec::new();
    let mut to_approve = Vec::new();
    for hint in &ticket.routes {
        let (entry, approve) = hint_entry(&policy, &interfaces, hint);
        hints.push(entry);
        to_approve.extend(approve);
    }
    let reply = json!({
        "re": id,
        "kind": match ticket.kind {
            InvitationKind::InPerson => "in_person",
            InvitationKind::SendLink => "link",
        },
        "invitation": super::invitation_hex(&ticket.invitation),
        "hints": hints,
    });
    // Must-fail control: inspection dials each destination to approve.
    if cfg!(mousse_control = "check-dials-destination") {
        let shared = shared.clone();
        tokio::spawn(async move {
            for route in &to_approve {
                let _ = shared.caller.open_route(route).await;
            }
            shared.event(reply);
        });
        return None;
    }
    Some(reply)
}
