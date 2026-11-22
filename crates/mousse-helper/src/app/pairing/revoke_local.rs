//! `grant.revoke_local {grant}` (`docs/pairing-flow-design.md` §6.1): end
//! this computer's grant for a peer, and nothing of the other direction.
//!
//! The grant goes through the same journal as `grant.remove`
//! ([`crate::revoke::Removal::remove`]): its connections close with
//! `GRANT_REVOKED`, streams the peer opened on this computer's own
//! connections to it are reset and refused from then on, and relay
//! cleanup drops the grant's caller key and recovery entries. A save that
//! fails pauses networking until a retry saves it, and a start replays the
//! journal before anything is accepted.
//!
//! Unlike `grant.remove`, it leaves alone what belongs to this computer
//! calling the peer: the peer record, its approvals, the relay material
//! this computer keeps as that peer's caller, any link completion record
//! and the routes the caller remembers. So this computer can still call
//! the peer afterwards.
//!
//! Replies: `{removed: false}` when the grant is gone already,
//! `{removed: true}` once saved, `{removed: true, paused: true}` when the
//! save failed. Errors: `bad_request` (also for a field it does not take),
//! `journal_failed`.

use mousse_net_core::grants::GrantId;
use serde_json::{json, Map, Value};

use super::super::{error, Shared};
use crate::applog;
use crate::revoke::Removed;

/// The fields `grant.revoke_local` takes; any other is `bad_request`.
const FIELDS: [&str; 3] = ["id", "op", "grant"];

/// Answer `grant.revoke_local`.
pub(super) fn revoke_local(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    if let Some(unknown) = map.keys().find(|k| !FIELDS.contains(&k.as_str())) {
        return error(
            id,
            "bad_request",
            format!("grant.revoke_local does not take {unknown:?}"),
        );
    }
    let Some(grant) = map.get("grant").and_then(Value::as_u64) else {
        return error(
            id,
            "bad_request",
            "grant.revoke_local needs grant (a number)",
        );
    };
    let grant = GrantId(grant);
    // Must-fail control: the reply says removed and the grant stays.
    if cfg!(mousse_control = "local-revoke-keeps-inbound-access") {
        return json!({"re": id, "removed": true});
    }
    // Must-fail control: the outbound peer goes with the grant, as a
    // `peer.forget` would take it.
    let forget = cfg!(mousse_control = "local-revoke-forgets-peer")
        .then(|| {
            shared
                .host
                .grants()
                .iter()
                .find(|g| g.id == grant)
                .map(|g| g.identity)
        })
        .flatten();
    let removed = shared.removal.remove(grant);
    if let (Ok(Removed::Saved | Removed::Paused), Some(identity)) = (&removed, forget) {
        let mut fields = Map::new();
        fields.insert(
            "identity".into(),
            json!(mousse_net_io::store::hex(identity.as_bytes())),
        );
        super::forget_peer(shared, id, &fields);
    }
    match removed {
        Ok(Removed::Gone) => json!({"re": id, "removed": false}),
        Ok(Removed::Saved) => json!({"re": id, "removed": true}),
        Ok(Removed::Paused) => json!({"re": id, "removed": true, "paused": true}),
        Err(e) => {
            applog::line(format!("journaling a removal failed: {}", e.0));
            error(id, "journal_failed", "Couldn't remove; try again")
        }
    }
}
