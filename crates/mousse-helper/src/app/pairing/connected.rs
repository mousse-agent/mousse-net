//! `grant.add_connected {conn, name, role}` → `{grant, role, already}`
//! (`grant-add-connected`, `docs/pairing-flow-design.md` §7): grant access
//! to this computer to the peer at the other end of one of this channel's
//! connections, after the owner allowed the peer's request for it.
//!
//! - The identity is the authenticated peer of connection `conn`. The
//!   request names none, and a request that does is refused.
//! - The connection must be published and live when the grant is
//!   committed. The channel's entry is looked up under the core lock (a
//!   connection this channel forgot, or one closing, is refused there);
//!   the commit runs under the host's lock and a live permit of the
//!   connection, which closing it waits for, so a grant never lands on a
//!   connection that started to close, whoever closes it (`peer.forget`,
//!   an edit or removal, the peer's `GOAWAY`, the certificate's deadline).
//!   The pause, revocation and denial are decided under the host's lock
//!   too. The core lock is not held while the table is saved.
//! - An inbound connection is live only under a grant of this computer: that
//!   grant is the answer. A grant that existed is returned as it is, with
//!   its own role, never widened.
//! - The grant is saved before the reply, also when it existed and an
//!   earlier save failed.

use mousse_net_core::grants::{validate_name, Grant, Role, MAX_NAME_LEN};
use mousse_net_io::store::identity_from_hex;
use mousse_net_io::ConnectedGrantError;
use serde_json::{json, Map, Value};

use super::super::{error, lock, Shared};
use super::roles::optional_role;

/// The fields `grant.add_connected` takes; all but `op` and `id` are
/// required.
const FIELDS: [&str; 5] = ["op", "id", "conn", "name", "role"];

/// `grant.add_connected`.
pub(super) fn add_connected(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    // Must-fail control (tests only): the identity is taken from the
    // request when it names one.
    let trusts_request = cfg!(mousse_control = "connected-grant-trusts-request-identity");
    let known = |k: &str| FIELDS.contains(&k) || (trusts_request && k == "identity");
    if let Some(unknown) = map.keys().find(|k| !known(k.as_str())) {
        return error(id, "bad_request", format!("unknown field {unknown:?}"));
    }
    let Some(no) = map.get("conn").and_then(Value::as_u64) else {
        return error(id, "bad_request", "grant.add_connected needs conn");
    };
    let name = match map.get("name").and_then(Value::as_str) {
        Some(name) if validate_name(name).is_ok() => name.to_owned(),
        Some(_) => {
            return error(
                id,
                "bad_request",
                format!("name must be 1 to {MAX_NAME_LEN} bytes"),
            )
        }
        None => return error(id, "bad_request", "grant.add_connected needs name"),
    };
    let role = match optional_role(map) {
        Ok(Some(role)) => role,
        Ok(None) => return error(id, "bad_request", "grant.add_connected needs role"),
        Err(e) => return error(id, "bad_request", e),
    };
    // Must-fail control (tests only): a connection that is closing, or
    // one this channel forgot, is taken as live.
    let stale = !cfg!(mousse_control = "grant-from-stale-connection");
    let (conn, inbound, mut identity) = {
        let core = lock(&shared.core);
        if shared.removal.is_paused() {
            drop(core);
            return super::paused(shared, id);
        }
        let Some(entry) = core.conns.get(&no) else {
            return error(id, "no_conn", format!("no connection {no} on this channel"));
        };
        let forgotten =
            !entry.inbound && core.peer_gen.get(&entry.identity).copied().unwrap_or(0) != entry.gen;
        if stale && (entry.conn.is_closing() || forgotten) {
            return error(id, "no_conn", format!("connection {no} is closing"));
        }
        (entry.conn.clone(), entry.inbound, entry.identity)
    };
    if trusts_request {
        if let Some(Ok(named)) = map
            .get("identity")
            .and_then(Value::as_str)
            .map(identity_from_hex)
        {
            identity = named;
        }
    }
    let added = shared
        .host
        .add_grant_connected(&conn, inbound, identity, name, role.clone());
    match added {
        Ok((grant, already)) => reply(shared, id, grant, role, already),
        Err(ConnectedGrantError::Paused) => super::paused(shared, id),
        Err(ConnectedGrantError::Closing) => {
            error(id, "no_conn", format!("connection {no} is closing"))
        }
        Err(e @ ConnectedGrantError::NotSaved(_)) => error(
            id,
            "store_failed",
            format!("{e}; repeat grant.add_connected"),
        ),
        Err(e @ ConnectedGrantError::Refused(_)) => error(id, "refused", e.to_string()),
    }
}

/// The reply for `grant`, which held its own role. `asked` is the role the
/// request named; an existing grant keeps its own.
fn reply(shared: &Shared, id: &Value, mut grant: Grant, asked: Role, already: bool) -> Value {
    // Must-fail control (tests only): an existing grant is widened to the
    // role the request named.
    if cfg!(mousse_control = "connected-grant-upgrades-existing") && already && grant.role != asked
    {
        let editing = shared.host.edit_role(grant.id, grant.revision, asked);
        if let Ok((edited, _)) = editing.outcome() {
            grant = edited.clone();
        }
        tokio::spawn(async move {
            let _ = editing.finish().await;
        });
    }
    json!({
        "re": id,
        "grant": grant.id.0,
        "role": grant.role.as_str(),
        "already": already,
    })
}
