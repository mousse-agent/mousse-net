//! Grant roles on the app channel (`grant-roles`,
//! `docs/pairing-flow-design.md` §8): the role field of `invite.create`,
//! `approval.answer` and `grant.add`, and `grant.set_role`.

use mousse_net_core::grants::{GrantId, Role};
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
/// revision, changed}`.
pub(super) fn set_role(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    if let Some(unknown) = map.keys().find(|k| !SET_ROLE_FIELDS.contains(&k.as_str())) {
        return error(id, "bad_request", format!("unknown field {unknown:?}"));
    }
    let (Some(grant), Some(expected)) = (
        map.get("grant").and_then(Value::as_u64),
        map.get("expected_revision").and_then(Value::as_u64),
    ) else {
        return error(
            id,
            "bad_request",
            "grant.set_role needs grant and expected_revision",
        );
    };
    let role = match optional_role(map) {
        Ok(Some(role)) => role,
        Ok(None) => return error(id, "bad_request", "grant.set_role needs role"),
        Err(e) => return error(id, "bad_request", e),
    };
    if shared.removal.is_paused() {
        return super::paused(shared, id);
    }
    let identity = shared
        .host
        .grants()
        .into_iter()
        .find(|g| g.id == GrantId(grant))
        .map(|g| g.identity);
    match shared.host.set_role(GrantId(grant), expected, role) {
        Ok((now, changed)) => {
            if changed {
                cut_role(shared, grant, now.revision, &now.identity);
            }
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
        Err(e @ RoleEditError::Unsettled(_)) => {
            // The grant is served under neither role now: cut what this
            // channel serves under it too.
            if let Some(identity) = identity {
                cut_role(shared, grant, 0, &identity);
            }
            error(id, "store_failed", e.to_string())
        }
        Err(e @ (RoleEditError::NotSaved(_) | RoleEditError::NotServing)) => {
            error(id, "store_failed", e.to_string())
        }
    }
}
