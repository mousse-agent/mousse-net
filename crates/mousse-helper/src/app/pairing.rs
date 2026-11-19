//! Pairing both ways, grants and peers on the app channel (Phase 1a §2.3,
//! §5.1 and §5.4).
//!
//! - **Host:** `invite.create` (in person only), `invite.cancel`,
//!   `approval.answer`; events `approval`, `enrolled`, `invite.ended`.
//! - **Joiner:** `join {ticket, pinned}`, `join.cancel`; event
//!   `join.progress`. A `pinned` join is one the app recorded before it
//!   started: the ticket's host counts as pinned, and repeated past the
//!   ticket's expiry it learns whether a lost `PAIRED` enrolled it.
//! - **Grants:** `grants.list`, `grant.add` (idempotent), `grant.remove`
//!   (journaled, see [`crate::revoke`]); events `grant.closed`,
//!   `store.failed`, `net.paused` and `net.resumed`.
//! - **Peers:** `peers.list`, `peer.add` (idempotent), `peer.forget`,
//!   `peer.addresses.set`, and `dial`, whose `conn.up` carries the role the
//!   peer gave this device (see [`super::paths`]).
//! - **Session:** `config.set {name}`.

use std::collections::HashMap;
use std::sync::{Arc, MutexGuard};

use mousse_net_core::grants::{Grant, GrantId};
use mousse_net_core::pairing::{Arrival, InvitationId, InvitationKind, Route, Ticket};
use mousse_net_core::ErrorCode;
use mousse_net_io::store::{hex, identity_from_hex, short_id, unhex, PeerRecord, PeerStore};
use mousse_net_io::{ApprovalRequest, HostEvent, NetError, NoCode};
use serde_json::{json, Map, Value};
use tokio::task::AbortHandle;

use super::{error, Shared};
use crate::applog;
use crate::revoke::Removed;

/// The requests this module answers.
pub const OPS: [&str; 14] = [
    "config.set",
    "invite.create",
    "invite.cancel",
    "approval.answer",
    "join",
    "join.cancel",
    "grants.list",
    "grant.add",
    "grant.remove",
    "peers.list",
    "peer.add",
    "peer.forget",
    "peer.addresses.set",
    "dial",
];

/// Pairing state of one channel.
pub struct State {
    /// The device name sent in `PAIRED` and in joins.
    name: String,
    /// Invitations this channel made and has not seen end.
    invitations: Vec<InvitationId>,
    /// Approval questions waiting for an answer, by request id.
    approvals: HashMap<String, ApprovalRequest>,
    /// Joins running, by invitation (hex): the request to answer and the
    /// task.
    joins: HashMap<String, (Value, AbortHandle)>,
}

impl State {
    pub fn new(name: String) -> Self {
        Self {
            name,
            invitations: Vec::new(),
            approvals: HashMap::new(),
            joins: HashMap::new(),
        }
    }
}

fn state(shared: &Shared) -> MutexGuard<'_, State> {
    shared.pairing.lock().unwrap_or_else(|e| e.into_inner())
}

/// Set the device name: what `PAIRED` sends from now on, and what joins
/// send.
pub fn set_name(shared: &Shared, name: &str) -> Result<(), String> {
    shared.host.set_name(name).map_err(|e| e.to_string())?;
    state(shared).name = name.to_owned();
    Ok(())
}

/// A role as stored: older records hold its debug form (`Role("owner")`).
pub(super) fn role_text(stored: &str) -> String {
    stored
        .strip_prefix("Role(\"")
        .and_then(|r| r.strip_suffix("\")"))
        .unwrap_or(stored)
        .to_owned()
}

fn invitation_hex(id: &InvitationId) -> String {
    hex(&id.0)
}

fn parse_invitation(text: Option<&str>) -> Option<InvitationId> {
    let bytes = unhex(text?).ok()?;
    Some(InvitationId(bytes.try_into().ok()?))
}

/// The id of one approval question: the joining connection and the full
/// fingerprint of the device shown, so an answer never applies to another
/// device or a newer request.
fn request_id(req: &ApprovalRequest) -> String {
    format!("{}-{}", req.conn.0, hex(&req.joiner.fingerprint()))
}

fn grant_json(shared: &Shared, g: &Grant) -> Value {
    json!({
        "grant": g.id.0,
        "identity": hex(g.identity.as_bytes()),
        "name": g.name,
        "role": g.role.as_str(),
        "granted_at": g.granted_at.secs(),
        "expires_at": g.expires_at.map(|t| t.secs()),
        "receipt": g.enrolled_by.as_ref().map(invitation_hex),
        "connections": shared.host.connections_for(g.id),
    })
}

fn peer_json(p: &PeerRecord) -> Value {
    json!({
        "identity": p.identity,
        "name": p.name,
        "role": role_text(&p.role),
        "routes": p.routes,
        "addresses": p.addresses,
        "last_route": p.last_route,
        "paired_at": p.paired_at,
    })
}

fn peers(shared: &Shared) -> PeerStore {
    PeerStore::in_dir(&shared.info.state_dir)
}

fn str_field<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

/// Answer one request in [`OPS`].
pub fn on_request(shared: &Arc<Shared>, id: Value, op: &str, map: &Map<String, Value>) {
    let reply = match op {
        "config.set" => match str_field(map, "name") {
            Some(name) => match set_name(shared, name) {
                Ok(()) => json!({"re": id}),
                Err(e) => error(&id, "bad_name", e),
            },
            None => error(&id, "bad_request", "config.set needs name"),
        },
        "invite.create" => invite(shared, &id),
        "invite.cancel" => match parse_invitation(str_field(map, "invitation")) {
            Some(invitation) => {
                shared.host.cancel(&invitation);
                json!({"re": id})
            }
            None => error(&id, "bad_request", "invite.cancel needs invitation"),
        },
        "approval.answer" => answer(shared, &id, map),
        "join" => match start_join(shared, &id, map) {
            Some(reply) => reply,
            None => return,
        },
        "join.cancel" => cancel_join(shared, &id, map),
        "grants.list" => {
            let grants: Vec<Value> = shared
                .host
                .grants()
                .iter()
                .map(|g| grant_json(shared, g))
                .collect();
            json!({"re": id, "grants": grants})
        }
        "grant.add" => add_grant(shared, &id, map),
        "grant.remove" => remove_grant(shared, &id, map),
        "peers.list" => match peers(shared).load() {
            Ok(list) => json!({"re": id, "peers": list.iter().map(peer_json).collect::<Vec<_>>()}),
            Err(e) => error(&id, "store_failed", e.to_string()),
        },
        "peer.add" => add_peer(shared, &id, map),
        "peer.forget" => forget_peer(shared, &id, map),
        "peer.addresses.set" => super::paths::set_addresses(shared, &id, map),
        "dial" => match str_field(map, "identity") {
            Some(_) if shared.removal.is_paused() => paused(shared, &id),
            Some(identity) => {
                tokio::spawn(super::paths::dial_op(
                    shared.clone(),
                    id,
                    identity.to_lowercase(),
                ));
                return;
            }
            None => error(&id, "bad_request", "dial needs identity"),
        },
        other => error(&id, "unknown_op", format!("unknown op {other:?}")),
    };
    shared.event(reply);
}

pub(super) fn paused(shared: &Shared, id: &Value) -> Value {
    let why = shared.removal.paused_reason().unwrap_or_default();
    error(
        id,
        "paused",
        format!("networking is paused until a removal is saved ({why})"),
    )
}

fn invite(shared: &Shared, id: &Value) -> Value {
    let routes = shared.info.routes.clone();
    match shared.host.invite(InvitationKind::InPerson, routes.clone()) {
        Ok(created) => {
            let invitation = created.ticket.invitation;
            state(shared).invitations.push(invitation);
            json!({
                "re": id,
                "invitation": invitation_hex(&invitation),
                "uri": created.fragment,
                "routes": routes,
                "expires_at": created.ticket.expires_at.secs(),
            })
        }
        Err(e) => error(id, "refused", e.to_string()),
    }
}

fn answer(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let Some(request) = str_field(map, "request") else {
        return error(id, "bad_request", "approval.answer needs request");
    };
    let yes = map.get("yes").and_then(Value::as_bool).unwrap_or(false);
    let Some(req) = state(shared).approvals.remove(request) else {
        return error(id, "no_request", "no such approval request is waiting");
    };
    if !yes {
        shared.host.decline(&req.invitation);
        return json!({"re": id});
    }
    match shared.host.approve(&req) {
        Ok(()) => json!({"re": id}),
        Err(e) => error(id, "stale", e.to_string()),
    }
}

/// Start a join; `None` when the reply comes from the join itself.
fn start_join(shared: &Arc<Shared>, id: &Value, map: &Map<String, Value>) -> Option<Value> {
    let Some(text) = str_field(map, "ticket") else {
        return Some(error(id, "bad_request", "join needs ticket"));
    };
    let ticket = match crate::peer::parse_ticket(text) {
        Ok(t) => t,
        Err(e) => return Some(error(id, "bad_ticket", e)),
    };
    if ticket.kind != InvitationKind::InPerson {
        return Some(error(
            id,
            "not_supported",
            "only in-person tickets pair in this version",
        ));
    }
    if shared.removal.is_paused() {
        return Some(paused(shared, id));
    }
    let pinned = map.get("pinned").and_then(Value::as_bool).unwrap_or(false);
    let key = invitation_hex(&ticket.invitation);
    let mut st = state(shared);
    if st.joins.contains_key(&key) {
        return Some(error(id, "busy", "a join with this ticket is running"));
    }
    let task = tokio::spawn(join(
        shared.clone(),
        id.clone(),
        ticket,
        key.clone(),
        pinned,
        st.name.clone(),
    ));
    st.joins.insert(key, (id.clone(), task.abort_handle()));
    None
}

async fn join(
    shared: Arc<Shared>,
    id: Value,
    ticket: Ticket,
    key: String,
    pinned: bool,
    name: String,
) {
    // Only private-range hints are dialled (§5.3).
    let candidates: Vec<Route> = super::paths::ticket_routes(&ticket.routes);
    let result = if candidates.is_empty() {
        Err(crate::peer::Failure {
            text: "the ticket has no usable private-range address".into(),
            reason: "no_route".into(),
        })
    } else {
        let progress = |route: &str| {
            shared.event(json!({
                "ev": "join.progress",
                "invitation": key,
                "step": "connecting",
                "route": route,
            }));
        };
        crate::peer::join_routes(
            &shared.caller,
            &peers(&shared),
            &ticket,
            Arrival::InAppScan,
            &name,
            &candidates,
            pinned,
            &mut NoCode,
            progress,
        )
        .await
    };
    // A cancel that came first has answered already.
    if state(&shared).joins.remove(&key).is_none() {
        if let Ok((conn, _, _)) = result {
            conn.close(ErrorCode::Cancelled);
        }
        return;
    }
    let reply = match result {
        Ok((conn, record, already)) => {
            let role = (record.role != "unknown").then(|| role_text(&record.role));
            applog::line(format!(
                "joined {} ({})",
                short_id(&ticket.host_identity),
                if already { "already paired" } else { "paired" }
            ));
            let no = shared.add_conn(conn, false, json!({"dir": "out", "role": role}));
            json!({
                "re": id,
                "identity": hex(ticket.host_identity.as_bytes()),
                "name": record.name,
                "role": role,
                "already": already,
                "conn": no,
            })
        }
        Err(f) => error(&id, &f.reason, f.text),
    };
    shared.event(reply);
}

fn cancel_join(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let Some(key) = str_field(map, "invitation").map(str::to_lowercase) else {
        return error(id, "bad_request", "join.cancel needs invitation");
    };
    let Some((join_id, task)) = state(shared).joins.remove(&key) else {
        return error(id, "no_join", "no join with that invitation is running");
    };
    task.abort();
    shared.event(error(&join_id, "cancelled", "the join was cancelled"));
    json!({"re": id})
}

fn add_grant(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let identity = match str_field(map, "identity").map(identity_from_hex) {
        Some(Ok(identity)) => identity,
        _ => return error(id, "bad_request", "grant.add needs identity (hex)"),
    };
    let Some(name) = str_field(map, "name") else {
        return error(id, "bad_request", "grant.add needs name");
    };
    let receipt = match map.get("receipt") {
        None | Some(Value::Null) => None,
        Some(v) => match parse_invitation(v.as_str()) {
            Some(r) => Some(r),
            None => return error(id, "bad_request", "receipt is an invitation id (hex)"),
        },
    };
    match shared.host.add_grant(identity, name.to_owned(), receipt) {
        Ok((grant, already)) => json!({"re": id, "grant": grant.id.0, "already": already}),
        Err(e @ NetError::Store(_)) => error(
            id,
            "store_failed",
            format!("the grant is in effect but saving it failed ({e}); repeat grant.add"),
        ),
        Err(e) => error(id, "refused", e.to_string()),
    }
}

fn remove_grant(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let Some(grant) = map.get("grant").and_then(Value::as_u64) else {
        return error(id, "bad_request", "grant.remove needs grant");
    };
    match shared.removal.remove(GrantId(grant)) {
        Ok(Removed::Gone) => json!({"re": id, "removed": false}),
        Ok(Removed::Saved) => json!({"re": id, "removed": true}),
        Ok(Removed::Paused) => json!({"re": id, "removed": true, "paused": true}),
        Err(e) => {
            applog::line(format!("journaling a removal failed: {}", e.0));
            error(id, "journal_failed", "Couldn't remove; try again")
        }
    }
}

fn add_peer(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let identity = match str_field(map, "identity").map(identity_from_hex) {
        Some(Ok(identity)) => identity,
        _ => return error(id, "bad_request", "peer.add needs identity (hex)"),
    };
    let Some(name) = str_field(map, "name") else {
        return error(id, "bad_request", "peer.add needs name");
    };
    // The routes a host sends when it pairs back: private ranges only.
    let routes = match super::paths::parse_routes(map.get("routes")) {
        Ok(routes) => routes,
        Err(e) => return error(id, "bad_route", e),
    };
    // 1a grants are owner grants (`grant.add` makes no other).
    let role = str_field(map, "role").unwrap_or("owner").to_owned();
    let mut already = false;
    let updated = peers(shared).update(|list| {
        let key = hex(identity.as_bytes());
        match list.iter_mut().find(|p| p.identity == key) {
            Some(p) => {
                already = true;
                p.name = name.to_owned();
                p.role = role.clone();
                for r in &routes {
                    if !p.routes.contains(r) {
                        p.routes.push(r.clone());
                    }
                }
            }
            None => list.push(PeerRecord {
                name: name.to_owned(),
                identity: key,
                role: role.clone(),
                routes: routes.clone(),
                last_route: None,
                addresses: Vec::new(),
                paired_at: crate::peer::now_secs(),
            }),
        }
    });
    match updated {
        Ok(()) => {
            shared.keep.kick(super::paths::Kick::Reset(Some(identity)));
            json!({"re": id, "already": already})
        }
        Err(e) => error(id, "store_failed", e.to_string()),
    }
}

fn forget_peer(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let identity = match str_field(map, "identity").map(identity_from_hex) {
        Some(Ok(identity)) => identity,
        _ => return error(id, "bad_request", "peer.forget needs identity (hex)"),
    };
    let key = hex(identity.as_bytes());
    let mut forgotten = false;
    let updated = peers(shared).update(|list| {
        let before = list.len();
        list.retain(|p| p.identity != key);
        forgotten = list.len() != before;
    });
    if let Err(e) = updated {
        return error(id, "store_failed", e.to_string());
    }
    // Its outbound connections go with it, and so do those still opening:
    // a dial or renewal that started before publishes nothing.
    let mut core = super::lock(&shared.core);
    *core.peer_gen.entry(identity).or_default() += 1;
    for entry in core.conns.values() {
        if !entry.inbound && entry.identity == identity {
            entry.conn.close(ErrorCode::Cancelled);
        }
    }
    json!({"re": id, "forgotten": forgotten})
}

/// A host event, as app events.
pub fn host_event(shared: &Shared, event: HostEvent) {
    let value = match event {
        HostEvent::ApprovalRequested(req) => {
            let mut st = state(shared);
            if !st.invitations.contains(&req.invitation) {
                drop(st);
                // Not an invitation of this channel: nobody can answer.
                shared.host.decline(&req.invitation);
                return;
            }
            let request = request_id(&req);
            let value = json!({
                "ev": "approval",
                "request": request,
                "invitation": invitation_hex(&req.invitation),
                "identity": hex(req.joiner.as_bytes()),
                "device": short_id(&req.joiner),
                "name": req.name,
            });
            st.approvals.insert(request, req);
            value
        }
        // Send links are not in 1.0: no code is ever shown.
        HostEvent::ShowCode { .. } => return,
        HostEvent::Enrolled {
            invitation,
            grant,
            identity,
        } => {
            applog::line(format!(
                "enrolled grant {} {}",
                grant.0,
                short_id(&identity)
            ));
            let mut st = state(shared);
            st.invitations.retain(|i| *i != invitation);
            st.approvals.retain(|_, r| r.invitation != invitation);
            json!({
                "ev": "enrolled",
                "invitation": invitation_hex(&invitation),
                "grant": grant.0,
                "identity": hex(identity.as_bytes()),
            })
        }
        HostEvent::InvitationEnded { invitation, reason } => {
            let mut st = state(shared);
            st.invitations.retain(|i| *i != invitation);
            st.approvals.retain(|_, r| r.invitation != invitation);
            json!({
                "ev": "invite.ended",
                "invitation": invitation_hex(&invitation),
                "reason": reason.name(),
            })
        }
        HostEvent::ChannelsClosed { grant, connections } => json!({
            "ev": "grant.closed",
            "grant": grant.0,
            "connections": connections,
        }),
        HostEvent::StoreFailed(reason) => {
            applog::line(format!("saving grants failed: {reason}"));
            json!({"ev": "store.failed", "reason": reason})
        }
    };
    shared.event(value);
}

/// Tell the app when networking pauses and resumes; a pause closes the
/// connections this channel opened (the host closes its own).
pub async fn watch_pause(shared: Arc<Shared>) {
    let mut changes = shared.removal.watch();
    while changes.changed().await.is_ok() {
        let now = changes.borrow_and_update().clone();
        match now {
            Some(reason) => {
                {
                    let core = super::lock(&shared.core);
                    for entry in core.conns.values() {
                        entry.conn.close(ErrorCode::InternalError);
                    }
                }
                shared.event(json!({"ev": "net.paused", "reason": reason}));
            }
            None => {
                shared.event(json!({"ev": "net.resumed"}));
                shared.keep.kick(super::paths::Kick::Reset(None));
            }
        }
    }
}
