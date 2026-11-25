//! This computer's own routes on the app channel (Phase 1b §1.5 and §7).
//!
//! - `routes.config {lan?, tailnet?, public?, forward_to?, tunnels?,
//!   port?}` → `{routes, restart_needed, config}`: changes `routes.json`
//!   (each field given replaces the stored one; `null` clears
//!   `forward_to` and `port`). `restart_needed` says whether the change
//!   takes a restart of this helper ([`RoutesConfig::restart_needed`]);
//!   other changes reach the next ticket. `routes` is what the new config
//!   advertises with the interfaces now.
//! - `routes.managed_tunnel {route}` → `{routes}` adds a running app
//!   tunnel to new invitations. `null` withdraws it. This route is kept in
//!   memory and does not affect the saved owner routes. It is a candidate
//!   of the `tunnel` way for `routes.available` and `invite.create {way}`
//!   (feature `managed-tunnel`; `docs/pairing-flow-design.md` §1 to §3).
//! - `routes.test {route}` → `{ok, ms}` or `{ok: false, reason, why}`:
//!   dials this helper's own `tcp`, `ws` or `wss` route pinned to its own
//!   identity, and closes once step 1 passed, before step 2. A failure
//!   reads "Couldn't confirm from this network": many routers do not loop a
//!   port forward back to the inside. Saving never depends on it.

use std::net::Ipv4Addr;
use std::sync::Arc;

use mousse_net_core::pairing::MAX_ROUTE_LEN;
use mousse_net_io::pipe::LocalRoute;
use mousse_net_io::routes::{testable, RoutesConfig, RoutesStore};
use serde_json::{json, Map, Value};

use super::{error, Shared};

/// The line a failed `routes.test` shows.
pub const TEST_FAILED: &str = "Couldn't confirm from this network";

fn strings(value: &Value, field: &str) -> Result<Vec<String>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("{field} is a list of routes"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} is a list of routes"))
        })
        .collect()
}

/// Apply the fields of a `routes.config` request to `config`.
fn apply(mut config: RoutesConfig, map: &Map<String, Value>) -> Result<RoutesConfig, String> {
    for (field, value) in map {
        match field.as_str() {
            "id" | "op" => {}
            "lan" | "tailnet" => {
                let on = value
                    .as_bool()
                    .ok_or_else(|| format!("{field} is true or false"))?;
                if field == "lan" {
                    config.lan = on;
                } else {
                    config.tailnet = on;
                }
            }
            "public" => config.public = strings(value, field)?,
            "tunnels" => config.tunnels = strings(value, field)?,
            "forward_to" => {
                config.forward_to = match value {
                    Value::Null => None,
                    v => Some(
                        v.as_str()
                            .and_then(|t| t.parse::<Ipv4Addr>().ok())
                            .ok_or("forward_to is an IPv4 address of this computer")?,
                    ),
                }
            }
            "port" => {
                config.port = match value {
                    Value::Null => None,
                    v => Some(
                        v.as_u64()
                            .and_then(|p| u16::try_from(p).ok())
                            .filter(|p| *p != 0)
                            .ok_or("port is 1 to 65535")?,
                    ),
                }
            }
            other => return Err(format!("routes.config has no field {other:?}")),
        }
    }
    Ok(config)
}

/// `routes.config`.
pub fn config(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let (running, port) = {
        let st = shared.info.listen.lock().unwrap_or_else(|e| e.into_inner());
        (st.config.clone(), st.port)
    };
    let store = RoutesStore::in_dir(&shared.info.state_dir);
    let base = match store.load() {
        Ok(stored) => stored.unwrap_or_else(|| running.clone()),
        Err(e) => return error(id, "store_failed", e.to_string()),
    };
    let interfaces = crate::app::interface_ips();
    let next =
        match apply(base, map).and_then(|c| c.checked(shared.caller.addr_policy(), &interfaces)) {
            Ok(next) => next,
            Err(e) => return error(id, "bad_route", e),
        };
    if let Err(e) = store.save(&next) {
        return error(id, "store_failed", e.to_string());
    }
    let restart_needed = running.restart_needed(&next);
    let routes = if restart_needed {
        next.advertised(
            &interfaces,
            &next.bind_plan(&interfaces),
            next.port.unwrap_or(port),
        )
    } else {
        // Nothing to rebind: the next ticket carries the new lists.
        let mut st = shared.info.listen.lock().unwrap_or_else(|e| e.into_inner());
        if st.config.public != next.public || st.config.tunnels != next.tunnels {
            st.config = next.clone();
            st.readvertise(&interfaces);
        }
        st.routes.clone()
    };
    json!({
        "re": id,
        "routes": routes,
        "restart_needed": restart_needed,
        "config": next,
    })
}

/// An app-owned route that was verified by the app through `routes.test`.
pub fn managed_tunnel(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    // A 1.2 operation: a field it does not know is refused, not ignored.
    if let Some(unknown) = map
        .keys()
        .find(|k| !["op", "id", "route"].contains(&k.as_str()))
    {
        return error(id, "bad_request", format!("unknown field {unknown:?}"));
    }
    let route = match map.get("route") {
        Some(Value::Null) => None,
        Some(Value::String(text)) => {
            let Ok(route @ LocalRoute::Wss { .. }) = LocalRoute::parse(text) else {
                return error(id, "bad_route", "the managed tunnel needs a wss route");
            };
            let uri = route.uri();
            if uri.len() > MAX_ROUTE_LEN || shared.caller.addr_policy().names_forbidden(&route) {
                return error(id, "bad_route", "the managed tunnel route is not diallable");
            }
            if shared.info.ws_port.is_none() {
                return error(id, "bad_route", "the local tunnel origin is unavailable");
            }
            Some(uri)
        }
        _ => return error(id, "bad_route", "the managed tunnel needs a route or null"),
    };
    let interfaces = crate::app::interface_ips();
    let mut listen = shared.info.listen.lock().unwrap_or_else(|e| e.into_inner());
    listen.managed_tunnel = route;
    listen.readvertise(&interfaces);
    json!({"re": id, "routes": listen.routes})
}

/// `routes.test {route}`: answered when the try ends.
pub async fn test(shared: Arc<Shared>, id: Value, route: Option<String>) {
    let reply = match route.as_deref().map(LocalRoute::parse) {
        None => error(&id, "bad_request", "routes.test needs route"),
        Some(Err(e)) => error(&id, "bad_route", e.to_string()),
        Some(Ok(route)) if !testable(&route) => error(
            &id,
            "bad_route",
            "routes.test dials this computer's tcp, ws and wss routes",
        ),
        Some(Ok(route)) => match shared
            .caller
            .probe_route(&route, shared.info.identity)
            .await
        {
            Ok(took) => json!({
                "re": id,
                "ok": true,
                "ms": u64::try_from(took.as_millis()).unwrap_or(u64::MAX),
            }),
            Err(e) => json!({
                "re": id,
                "ok": false,
                "reason": TEST_FAILED,
                "why": crate::peer::reason_of(&e),
                "detail": crate::peer::describe(&e),
            }),
        },
    };
    shared.event(reply);
}
