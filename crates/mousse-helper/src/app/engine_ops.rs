//! App-channel requests for engine-owned features: `removal.*` ("Remove on
//! all my hosts", Phase 4 Part D) and `plus.*` (the Plus client).
//!
//! - `removal.plan {identity}` → `{hosts: [{host, name, grant, list_at}]}`:
//!   for each host where this device is an owner, the grant id its last
//!   grant list named for the device (`null`: "Not known on <host>").
//! - `removal.confirm {identity, name, hosts: [{host, grant}]}` →
//!   `{removals: [...], unknown: [host]}`: one signed removal per host and
//!   grant id the user saw and confirmed.
//! - `removal.ask.answer {identity, host, grant, yes}`: the answer to
//!   `removal.ask` ("<X> is also on <host>. Remove it there?").
//! - `removal.list` → `{removals: [...], asks: [...]}`.
//! - Events: `removal.state {id, host, removed, name, grant, state,
//!   result?}` and `removal.ask {identity, name, host, grant}`.

use std::sync::Arc;

use mousse_net_core::grants::GrantId;
use mousse_net_io::store::identity_from_hex;
use serde_json::{Map, Value};

use super::{error, Shared};

/// The ops handled here.
pub const OPS: [&str; 4] = [
    "removal.plan",
    "removal.confirm",
    "removal.ask.answer",
    "removal.list",
];

fn reply(id: &Value, result: Result<Value, String>) -> Value {
    match result {
        Ok(mut v) => {
            v["re"] = id.clone();
            v
        }
        Err(why) => error(id, "failed", why),
    }
}

/// Handle one request.
pub fn on_request(shared: &Arc<Shared>, id: Value, op: &str, map: &Map<String, Value>) {
    let engine = shared.engine.clone();
    let identity = map
        .get("identity")
        .and_then(Value::as_str)
        .map(identity_from_hex);
    let out = match op {
        "removal.plan" => match identity {
            Some(Ok(removed)) => reply(&id, engine.removal_plan(&removed)),
            _ => error(&id, "bad_request", "removal.plan needs identity (hex)"),
        },
        "removal.list" => reply(&id, engine.removal_list()),
        "removal.confirm" => {
            let name = map.get("name").and_then(Value::as_str).unwrap_or("");
            let hosts: Option<Vec<_>> = map
                .get("hosts")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .map(|h| {
                            let host = identity_from_hex(h.get("host")?.as_str()?).ok()?;
                            let grant = GrantId(h.get("grant")?.as_u64()?);
                            Some((host, grant))
                        })
                        .collect()
                })
                .and_then(|v: Vec<Option<_>>| v.into_iter().collect());
            match (identity, hosts) {
                (Some(Ok(removed)), Some(hosts)) if !name.is_empty() => {
                    reply(&id, engine.removal_confirm(&removed, name, &hosts))
                }
                _ => error(
                    &id,
                    "bad_request",
                    "removal.confirm needs identity, name and hosts [{host, grant}]",
                ),
            }
        }
        "removal.ask.answer" => {
            let host = map
                .get("host")
                .and_then(Value::as_str)
                .and_then(|h| identity_from_hex(h).ok());
            let grant = map.get("grant").and_then(Value::as_u64).map(GrantId);
            let yes = map.get("yes").and_then(Value::as_bool);
            match (identity, host, grant, yes) {
                (Some(Ok(removed)), Some(host), Some(grant), Some(yes)) => {
                    reply(&id, engine.removal_ask_answer(&removed, &host, grant, yes))
                }
                _ => error(
                    &id,
                    "bad_request",
                    "removal.ask.answer needs identity, host, grant and yes",
                ),
            }
        }
        other => error(&id, "unknown_op", format!("unknown op {other:?}")),
    };
    shared.event(out);
}

/// Whether a stored role is `owner`.
pub fn is_owner(stored: &str) -> bool {
    super::pairing::role_text(stored) == mousse_net_core::grants::Role::OWNER
}
