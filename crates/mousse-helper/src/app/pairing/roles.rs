//! Grant roles on the app channel (`grant-roles`,
//! `docs/pairing-flow-design.md` §8): the role field of `invite.create`,
//! `approval.answer` and `grant.add`, and `grant.set_role`.

use std::sync::Arc;

use mousse_net_core::grants::{Grant, GrantId, Role};
use mousse_net_io::RoleEditError;
use serde_json::{json, Map, Value};

use super::super::{cut_role, error, Shared};

/// The fields `grant.set_role` takes.
const SET_ROLE_FIELDS: [&str; 5] = ["op", "id", "grant", "expected_revision", "role"];

/// The optional `role` field of a request: `Ok(None)` when absent, an
/// error text when it is not a valid role name.
pub(super) fn optional_role(map: &Map<String, Value>) -> Result<Option<Role>, String> {
    match map.get("role") {
        None => Ok(None),
        Some(Value::String(name)) => Role::new(name)
            .map(Some)
            .map_err(|_| format!("bad role {name:?}")),
        Some(_) => Err("role is a string".into()),
    }
}

/// `grant.set_role {grant, expected_revision, role}` → `{grant, role,
/// revision, changed}`. `None`: the reply comes later, once every
/// connection the edit closed has dropped what was queued on it under the
/// old role.
pub(super) fn set_role(
    shared: &Arc<Shared>,
    id: &Value,
    map: &Map<String, Value>,
) -> Option<Value> {
    if let Some(unknown) = map.keys().find(|k| !SET_ROLE_FIELDS.contains(&k.as_str())) {
        return Some(error(
            id,
            "bad_request",
            format!("unknown field {unknown:?}"),
        ));
    }
    let (Some(grant), Some(expected)) = (
        map.get("grant").and_then(Value::as_u64),
        map.get("expected_revision").and_then(Value::as_u64),
    ) else {
        return Some(error(
            id,
            "bad_request",
            "grant.set_role needs grant and expected_revision",
        ));
    };
    let role = match optional_role(map) {
        Ok(Some(role)) => role,
        Ok(None) => return Some(error(id, "bad_request", "grant.set_role needs role")),
        Err(e) => return Some(error(id, "bad_request", e)),
    };
    if shared.removal.is_paused() {
        return Some(super::paused(shared, id));
    }
    let identity = shared
        .host
        .grants()
        .into_iter()
        .find(|g| g.id == GrantId(grant))
        .map(|g| g.identity);
    // The host commits and closes its connections under the old role;
    // this channel cuts its own at once, before any of them is waited on.
    let editing = shared.host.edit_role(GrantId(grant), expected, role);
    let cut = match editing.outcome() {
        Ok((now, true)) => cut_role(shared, grant, now.revision, &now.identity),
        Err(RoleEditError::Unsettled(_)) => match &identity {
            // The grant is served under neither role now: cut what this
            // channel serves under it too.
            Some(identity) => cut_role(shared, grant, 0, identity),
            None => Vec::new(),
        },
        _ => Vec::new(),
    };
    let (shared, id) = (shared.clone(), id.clone());
    tokio::spawn(async move {
        let result = editing.finish().await;
        for conn in cut {
            conn.fence().await;
        }
        let reply = edit_reply(&shared, &id, grant, result);
        shared.event(reply);
    });
    None
}

/// The reply to `grant.set_role` once the edit is finished.
fn edit_reply(
    shared: &Shared,
    id: &Value,
    grant: u64,
    result: Result<(Grant, bool), RoleEditError>,
) -> Value {
    match result {
        Ok((now, changed)) => {
            json!({
                "re": id,
                "grant": grant,
                "role": now.role.as_str(),
                "revision": now.revision,
                "changed": changed,
            })
        }
        Err(RoleEditError::NoGrant) => error(id, "no_grant", "no such grant"),
        Err(RoleEditError::RevisionConflict) => error(
            id,
            "revision_conflict",
            "the grant changed since that revision; read grants.list again",
        ),
        Err(e @ RoleEditError::Refused(_)) => error(id, "bad_request", e.to_string()),
        Err(RoleEditError::Paused) => super::paused(shared, id),
        Err(
            e @ (RoleEditError::Unsettled(_)
            | RoleEditError::NotSaved(_)
            | RoleEditError::NotServing),
        ) => error(id, "store_failed", e.to_string()),
    }
}
