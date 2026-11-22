//! Pairing both ways, grants and peers on the app channel (Phase 1a §2.3,
//! §5.1 and §5.4; "Send link", Phase 1b §5 and §7).
//!
//! - **Host:** `invite.create {kind: in_person|link}`, `invite.cancel`,
//!   `approval.answer`; events `approval`, `invite.code` (a link's code,
//!   each time a new one shows), `enrolled`, `invite.ended`.
//! - **Choosing the way** (protocol 1.2, features `invite-way` and
//!   `route-readiness`; `docs/pairing-flow-design.md` §2 and §3):
//!   `invite.create {kind?, way, route?}` puts only the chosen way's hints
//!   in the ticket, or the one exact `route` of this computer's inventory
//!   (see [`availability`]), and its reply lists the `ways` carried.
//!   Without `way` or `route` it is the 1.1 path, unchanged, reply
//!   included. With either, unknown fields, `way: null`, an unknown way
//!   or a selector of the wrong type are `bad_request`, and a selection
//!   with nothing to offer now is `way_unavailable` with its `reason`
//!   (`restart_required` first when the way's saved setting waits for a
//!   restart; `route_not_offered` when the way offers routes but not the
//!   exact `route`); it leaves no invitation, code or relay allow-set
//!   entry. A relay ticket takes a free allow-set slot under one lock with
//!   its creation, never one held by an open invitation or a recovery
//!   entry. `routes.available {}` reports each way's state, reason and
//!   routes.
//! - **Joiner:** `join {ticket, arrival: scan|link, approved, pinned}`,
//!   `join.code`, `join.cancel`, `join.status`, `join.ack`; events
//!   `join.progress`, `join.code_needed`, `join.attempt_failed`.
//!   `join.check {ticket, arrival}` reports what a join would refuse and
//!   what it would do with each hint, with no network traffic (see
//!   [`check`]); it shares its decisions with `join` ([`admit`],
//!   [`mousse_net_io::Caller::check_join`] and
//!   [`super::paths::hint_decision`]). `join.probe {ticket, arrival,
//!   approved?}` and `join.probe.cancel {probe}` (feature `join-probe`)
//!   report whether the ticket's host answers on a route a join would
//!   dial, pairing nothing (see [`probe`]). An
//!   in-person ticket needs `arrival: scan`. A `pinned` in-person join is
//!   one the app recorded before it started: the ticket's host counts as
//!   pinned, and repeated past the ticket's expiry it learns whether a
//!   lost `PAIRED` enrolled it. A link join ignores `pinned` (see
//!   [`crate::peer::join_routes`]); a `PAIRED` for its ticket leaves a
//!   completion record that `join.status` replays and `join.ack` drops.
//!   `approved` lists the ticket's hints beyond the automatic rule that the
//!   owner approved at Connect (Phase 1b §1.3): only those and private
//!   literals are dialled, and a join that pairs stores them as `ticket`
//!   approvals (a link join through its completion record).
//! - **Grants:** `grants.list`, `grant.add` (idempotent), `grant.remove`
//!   (journaled, see [`crate::revoke`]); events `grant.closed`,
//!   `store.failed`, `net.paused` and `net.resumed`.
//! - **Peers:** `peers.list`, `peer.add` (idempotent), `peer.forget`,
//!   `peer.addresses.set`, `approvals.list`, and `dial`, whose `conn.up`
//!   carries the role the peer gave this device and the route it came up on
//!   (see [`super::paths`]). `peer.add {offered}` keeps the routes a host
//!   offered beyond the automatic rule as suggestions.
//! - **Session:** `config.set {name}`.

use std::collections::HashMap;
use std::sync::{Arc, MutexGuard};

use mousse_net_core::grants::{Grant, GrantId};
use mousse_net_core::pairing::{Arrival, InvitationId, InvitationKind, PairingCode, Ticket};
use mousse_net_core::ErrorCode;
use mousse_net_io::store::{
    hex, identity_from_hex, short_id, unhex, Approval, ApprovalStore, CompletionStore, PeerRecord,
    PeerStore, APPROVAL_SOURCE_TICKET,
};
use mousse_net_io::{ApprovalRequest, CodeEntry, HostEvent, NetError, NoCode};
use serde_json::{json, Map, Value};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::{error, Shared};
use crate::applog;
use crate::peer::{JoinRoute, JoinedVia};
use crate::revoke::Removed;

mod availability;
mod check;
mod probe;

/// The requests this module answers.
pub const OPS: [&str; 22] = [
    "config.set",
    "invite.create",
    "routes.available",
    "join.check",
    "join.probe",
    "join.probe.cancel",
    "invite.cancel",
    "approval.answer",
    "join",
    "join.code",
    "join.cancel",
    "join.status",
    "join.ack",
    "grants.list",
    "grant.add",
    "grant.remove",
    "peers.list",
    "peer.add",
    "peer.forget",
    "peer.addresses.set",
    "dial",
    "approvals.list",
];

/// Pairing state of one channel.
pub struct State {
    /// The device name sent in `PAIRED` and in joins.
    name: String,
    /// Invitations this channel made and has not seen end.
    invitations: Vec<InvitationId>,
    /// Approval questions waiting for an answer, by request id.
    approvals: HashMap<String, ApprovalRequest>,
    /// Joins running, by invitation (hex).
    joins: HashMap<String, Join>,
    /// Probes running (see [`probe`]).
    probes: Vec<probe::Probe>,
}

/// A join running.
struct Join {
    /// The `join` request, answered when it ends.
    id: Value,
    task: JoinHandle<()>,
    /// Where `join.code` sends a link's code.
    codes: Option<mpsc::UnboundedSender<String>>,
}

impl State {
    pub fn new(name: String) -> Self {
        Self {
            name,
            invitations: Vec::new(),
            approvals: HashMap::new(),
            joins: HashMap::new(),
            probes: Vec::new(),
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
        "relay": super::relay::grant_status(shared, g.id.0),
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

fn peer_json(shared: &Shared, p: &PeerRecord) -> Value {
    json!({
        "relay": p.pin().map(|pin| super::relay::peer_json(shared, &pin)).unwrap_or(Value::Null),
        "identity": p.identity,
        "name": p.name,
        "role": role_text(&p.role),
        "routes": p.routes,
        "addresses": p.addresses,
        "offered": p.offered,
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
        "invite.create" => invite(shared, &id, map),
        "routes.available" => availability::available(shared, &id, map),
        "join.check" => match check::check(shared, &id, map) {
            Some(reply) => reply,
            None => return,
        },
        "join.probe" => match probe::start(shared, &id, map) {
            Some(reply) => reply,
            None => return,
        },
        "join.probe.cancel" => match probe::cancel(shared, &id, map) {
            Some(reply) => reply,
            None => return,
        },
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
        "join.code" => submit_code(shared, &id, map),
        "join.cancel" => match cancel_join(shared, &id, map) {
            Some(reply) => reply,
            None => return,
        },
        "join.status" => join_status(shared, &id, map),
        "join.ack" => join_ack(shared, &id, map),
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
        "approvals.list" => super::paths::list_approvals(shared, &id, map),
        "peers.list" => match peers(shared).load() {
            Ok(list) => {
                json!({"re": id, "peers": list.iter().map(|p| peer_json(shared, p)).collect::<Vec<_>>()})
            }
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

fn invite(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    // A selector asks for the 1.2 path; without one, 1.1 unchanged.
    if map.contains_key("way") || map.contains_key("route") {
        return invite_way(shared, id, map);
    }
    let kind = match str_field(map, "kind") {
        None | Some("in_person") => InvitationKind::InPerson,
        Some("link") => InvitationKind::SendLink,
        Some(_) => return error(id, "bad_request", "kind is in_person or link"),
    };
    // What the listener serves now (Phase 1b §1.5), then this computer's
    // registered relays as `relay` hints (Phase 3 B.11).
    let routes = availability::legacy_routes(shared);
    match shared.host.invite(kind, routes.clone()) {
        Ok(created) => {
            super::relay::on_invite(shared, &created.ticket);
            invite_reply(shared, id, &created, &routes, None)
        }
        Err(e) => error(id, "refused", e.to_string()),
    }
}

/// The reply to an `invite.create` that made `created` with `routes`. Only
/// a selected ticket's reply lists its `ways`: the 1.1 reply stays as it
/// was.
fn invite_reply(
    shared: &Shared,
    id: &Value,
    created: &mousse_net_core::pairing::CreatedInvitation,
    routes: &[String],
    ways: Option<&[&str]>,
) -> Value {
    let invitation = created.ticket.invitation;
    state(shared).invitations.push(invitation);
    let mut reply = json!({
        "re": id,
        "invitation": invitation_hex(&invitation),
        "uri": created.fragment,
        "routes": routes,
        "expires_at": created.ticket.expires_at.secs(),
    });
    if let Some(ways) = ways {
        reply["ways"] = json!(ways);
    }
    // A link's first code. It is shown only to the owner, never logged, and
    // is not part of the link.
    if let Some((code, left)) = shared.host.invitation_code(&invitation) {
        reply["code"] = json!(code.as_str());
        reply["attempts_left"] = json!(left);
    }
    reply
}

/// `way_unavailable`, and why (a reason of `routes.available`).
fn way_unavailable(id: &Value, way: &str, reason: &str) -> Value {
    let mut reply = error(
        id,
        "way_unavailable",
        format!("this computer has nothing to offer for {way} now ({reason})"),
    );
    reply["reason"] = json!(reason);
    reply
}

/// `invite.create {kind?, way, route?}`: a ticket that carries only the
/// chosen way's hints, or the one exact `route`. Every check comes before
/// the invitation exists, so a refusal leaves nothing behind.
fn invite_way(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    if let Some(field) = map
        .keys()
        .find(|k| !matches!(k.as_str(), "id" | "op" | "kind" | "way" | "route"))
    {
        return error(
            id,
            "bad_request",
            format!("invite.create has no field {field:?}"),
        );
    }
    let kind = match map.get("kind") {
        None => InvitationKind::InPerson,
        Some(Value::String(k)) if k == "in_person" => InvitationKind::InPerson,
        Some(Value::String(k)) if k == "link" => InvitationKind::SendLink,
        Some(_) => return error(id, "bad_request", "kind is in_person or link"),
    };
    let way = match map.get("way").and_then(Value::as_str) {
        Some(way) if availability::WAYS.contains(&way) => way,
        _ => {
            return error(
                id,
                "bad_request",
                "way is lan, tailnet, public, tunnel or relay",
            )
        }
    };
    let route = match map.get("route") {
        None => None,
        Some(Value::String(route)) => Some(route.as_str()),
        Some(_) => return error(id, "bad_request", "route is a hint text"),
    };
    if shared.removal.is_paused() {
        return way_unavailable(id, way, "paused");
    }
    let saved = match availability::saved_config(shared) {
        Ok(saved) => saved,
        Err(e) => return error(id, "store_failed", e),
    };
    let inventory = availability::inventory(shared);
    if way == "relay" {
        if let Some(e) = inventory.relay_store_failed() {
            return error(id, "store_failed", e.to_owned());
        }
    }
    // What the listener offers now is about to be replaced.
    if availability::restart_required(shared, &inventory, saved.as_ref(), way) {
        return way_unavailable(id, way, "restart_required");
    }
    let routes = availability::select(&inventory, way, route);
    if routes.is_empty() {
        let reason = if route.is_some() && !availability::select(&inventory, way, None).is_empty() {
            // The way offers routes, just not this one. For relay, capacity
            // and the grants store come before `route_not_offered`.
            if way == "relay" {
                match super::relay::slot_free(shared) {
                    Ok(true) => "route_not_offered",
                    Ok(false) => "relay_capacity",
                    Err(e) => return error(id, "store_failed", e),
                }
            } else {
                "route_not_offered"
            }
        } else {
            availability::unavailable_reason(shared, &inventory, saved.as_ref(), way)
        };
        return way_unavailable(id, way, reason);
    }
    let ways = availability::ways_of(&inventory, way, &routes);
    let carries_relay = routes
        .iter()
        .any(|r| mousse_net_core::relay_endpoint::RelayRoute::parse_hint(r).is_some());
    let made = if carries_relay {
        // The allow-set slot is checked and taken with the creation.
        super::relay::invite_with_slot(shared, || shared.host.invite(kind, routes.clone()))
    } else {
        shared
            .host
            .invite(kind, routes.clone())
            .map_err(super::relay::SlotRefused::Create)
    };
    match made {
        Ok(created) => invite_reply(shared, id, &created, &routes, Some(&ways)),
        Err(super::relay::SlotRefused::Full) => way_unavailable(id, way, "relay_capacity"),
        Err(super::relay::SlotRefused::Store(e)) => error(id, "store_failed", e),
        Err(super::relay::SlotRefused::Create(e)) => error(id, "refused", e.to_string()),
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
    // 1.0 apps send no arrival: their tickets came from the in-app scanner.
    let arrival = match str_field(map, "arrival") {
        None | Some("scan") => Arrival::InAppScan,
        Some("link") => Arrival::Link,
        Some(_) => return Some(error(id, "bad_request", "arrival is scan or link")),
    };
    let approved: Vec<String> = match map.get("approved") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(list)) => {
            match list.iter().map(Value::as_str).collect::<Option<Vec<_>>>() {
                Some(list) => list.into_iter().map(str::to_owned).collect(),
                None => return Some(error(id, "bad_request", "approved is a list of routes")),
            }
        }
        Some(_) => return Some(error(id, "bad_request", "approved is a list of routes")),
    };
    let arrival = match admit(shared, id, &ticket, arrival) {
        Ok(arrival) => arrival,
        Err(reply) => return Some(reply),
    };
    let pinned = map.get("pinned").and_then(Value::as_bool).unwrap_or(false);
    let key = invitation_hex(&ticket.invitation);
    let mut st = state(shared);
    if st.joins.contains_key(&key) {
        return Some(error(id, "busy", "a join with this ticket is running"));
    }
    let (codes, typed) = match ticket.kind {
        InvitationKind::SendLink => {
            let (tx, rx) = mpsc::unbounded_channel();
            (Some(tx), Some(rx))
        }
        InvitationKind::InPerson => (None, None),
    };
    let task = tokio::spawn(join(
        shared.clone(),
        id.clone(),
        ticket,
        key.clone(),
        JoinAsk {
            arrival,
            pinned,
            approved,
            typed,
        },
        st.name.clone(),
    ));
    st.joins.insert(
        key,
        Join {
            id: id.clone(),
            task,
            codes,
        },
    );
    None
}

/// The refusals `join`, `join.check` and `join.probe` share before the
/// ticket's flow record is read: the arrival an in-person ticket needs,
/// and the pause. The arrival to join with, or the error reply.
fn admit(shared: &Shared, id: &Value, ticket: &Ticket, arrival: Arrival) -> Result<Arrival, Value> {
    let mut arrival = arrival;
    // An in-person ticket skips the code, so it pairs only from a scan of
    // the host's screen: one that came as a link may have been swapped.
    if ticket.kind == InvitationKind::InPerson && arrival == Arrival::Link {
        // Must-fail control: the link is taken as a scan.
        if cfg!(mousse_control = "link-accepts-kind1") {
            arrival = Arrival::InAppScan;
        } else {
            return Err(error(
                id,
                "pairing_failed",
                "an in-person ticket pairs only when scanned from the host's screen \
                 (PAIRING_FAILED)",
            ));
        }
    }
    if shared.removal.is_paused() {
        return Err(paused(shared, id));
    }
    Ok(arrival)
}

/// What a join of `ticket` dials, in order: the ticket's private-range
/// hints and the ones the owner approved (§1.3), then its relay routes the
/// owner approved (Phase 3 B.7).
struct JoinPlan {
    /// `approved`, in canonical form.
    approved_routes: Vec<String>,
    /// The relay routes, with the invitation's tag.
    relays: Vec<(mousse_net_core::relay_endpoint::RelayRoute, [u8; 32])>,
    candidates: Vec<JoinRoute>,
}

fn join_plan(shared: &Shared, ticket: &Ticket, approved: &[String]) -> JoinPlan {
    let policy = shared.caller.addr_policy().clone();
    let approved_routes = super::paths::canonical_list(Some(&json!(approved)));
    let relays = super::relay::join_candidates(ticket, approved);
    let candidates: Vec<JoinRoute> =
        super::paths::ticket_candidates(&policy, &ticket.routes, &approved_routes)
            .into_iter()
            .map(JoinRoute::Local)
            .chain(relays.iter().map(|(route, tag)| JoinRoute::Relay {
                route: route.clone(),
                tag: *tag,
            }))
            .collect();
    JoinPlan {
        approved_routes,
        relays,
        candidates,
    }
}

/// What a `join` asked for.
struct JoinAsk {
    arrival: Arrival,
    pinned: bool,
    /// The ticket hints the owner approved at Connect.
    approved: Vec<String>,
    /// A link's codes, from `join.code`.
    typed: Option<mpsc::UnboundedReceiver<String>>,
}

/// Where a link join asks for its code: the app, through
/// `join.code_needed` (or `join.attempt_failed` after a wrong code), and
/// `join.code`.
struct ChannelCode {
    shared: Arc<Shared>,
    invitation: String,
    typed: mpsc::UnboundedReceiver<String>,
}

impl CodeEntry for ChannelCode {
    async fn code(&mut self, retry: Option<u8>) -> Option<String> {
        self.ask(retry.unwrap_or(0), retry.is_some()).await
    }

    async fn ask(&mut self, attempts_left: u8, retry: bool) -> Option<String> {
        // Every `join.code` is a code the owner submitted, so one sent
        // early is kept for this ask rather than dropped.
        let ev = if retry {
            "join.attempt_failed"
        } else {
            "join.code_needed"
        };
        self.shared.event(json!({
            "ev": ev,
            "invitation": self.invitation,
            "attempts_left": attempts_left,
        }));
        self.typed.recv().await
    }
}

async fn join(
    shared: Arc<Shared>,
    id: Value,
    ticket: Ticket,
    key: String,
    ask: JoinAsk,
    name: String,
) {
    let JoinAsk {
        arrival,
        pinned,
        approved,
        typed,
    } = ask;
    let JoinPlan {
        approved_routes,
        relays,
        candidates,
    } = join_plan(&shared, &ticket, &approved);
    // A removal of the host while the join runs (`peer.forget`) wins: the
    // join stores nothing, or what it stored goes with the removal.
    let pin = ticket.host_identity;
    let gen = shared.peer_gen(&pin);
    let wanted = || shared.peer_gen(&pin) == gen;
    let result = if candidates.is_empty() {
        Err(crate::peer::Failure {
            text: "the ticket has no private-range address and none it lists was approved".into(),
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
        let link = (ticket.kind == InvitationKind::SendLink).then_some(approved.as_slice());
        match typed {
            Some(typed) => {
                let mut codes = ChannelCode {
                    shared: shared.clone(),
                    invitation: key.clone(),
                    typed,
                };
                crate::peer::join_routes(
                    &shared.caller,
                    &peers(&shared),
                    &ticket,
                    arrival,
                    &name,
                    &candidates,
                    pinned,
                    link,
                    &mut codes,
                    progress,
                    wanted,
                )
                .await
            }
            None => {
                crate::peer::join_routes(
                    &shared.caller,
                    &peers(&shared),
                    &ticket,
                    arrival,
                    &name,
                    &candidates,
                    pinned,
                    link,
                    &mut NoCode,
                    progress,
                    wanted,
                )
                .await
            }
        }
    };
    // A cancel that came first has answered already.
    if state(&shared).joins.remove(&key).is_none() {
        if let Ok((conn, _, _, _)) = result {
            conn.close(ErrorCode::Cancelled);
        }
        return;
    }
    let reply = match result {
        Ok((conn, record, already, reached)) => {
            let role = (record.role != "unknown").then(|| role_text(&record.role));
            applog::line(format!(
                "joined {} ({})",
                short_id(&ticket.host_identity),
                if already { "already paired" } else { "paired" }
            ));
            // A link join stored its approvals with its completion record.
            if ticket.kind == InvitationKind::InPerson && !already {
                store_ticket_approvals(&shared, &ticket, &approved_routes);
            }
            shared.caller.forget_routes(Some(&ticket.host_identity));
            super::relay::approve_ticket_routes(&shared, &ticket, &approved);
            let (route, via) = match reached {
                JoinedVia::Local(reached) => (super::paths::route_json(&reached), None),
                JoinedVia::Relay(route) => {
                    if let Some((_, tag)) = relays.iter().find(|(r, _)| *r == route) {
                        super::relay::after_join(&shared, &ticket, &route, *tag);
                    }
                    (super::relay::route_json(&route, false), Some(route))
                }
            };
            let fields = json!({"dir": "out", "role": role, "route": route});
            match shared.add_outbound(conn, gen, fields) {
                Ok(no) => {
                    if let Some(route) = via {
                        shared.set_via(no, route);
                    }
                    json!({
                        "re": id,
                        "identity": hex(ticket.host_identity.as_bytes()),
                        "name": record.name,
                        "role": role,
                        "already": already,
                        "conn": no,
                        "ticket_hash": hex(&ticket.hash()),
                    })
                }
                Err(super::Stale::Paused) => paused(&shared, &id),
                Err(super::Stale::Forgotten) => error(
                    &id,
                    "forgotten",
                    "the host was removed while this device was joining it",
                ),
            }
        }
        Err(f) => error(&id, &f.reason, f.text),
    };
    shared.event(reply);
}

/// Stop a join; `None` when the reply comes once it has stopped. The
/// replies wait until the join has let go of its ticket, so a join of the
/// same ticket started after them is not refused as one in progress.
fn cancel_join(shared: &Arc<Shared>, id: &Value, map: &Map<String, Value>) -> Option<Value> {
    let Some(key) = str_field(map, "invitation").map(str::to_lowercase) else {
        return Some(error(id, "bad_request", "join.cancel needs invitation"));
    };
    let Some(join) = state(shared).joins.remove(&key) else {
        return Some(error(
            id,
            "no_join",
            "no join with that invitation is running",
        ));
    };
    join.task.abort();
    let (shared, id) = (shared.clone(), id.clone());
    tokio::spawn(async move {
        let _ = join.task.await;
        shared.event(error(&join.id, "cancelled", "the join was cancelled"));
        shared.event(json!({"re": id}));
    });
    None
}

/// `join.code {invitation, code}`: the code typed for a link join. A code
/// that is not six digits is `bad_code` and spends no attempt.
fn submit_code(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let Some(key) = str_field(map, "invitation").map(str::to_lowercase) else {
        return error(id, "bad_request", "join.code needs invitation");
    };
    let Some(text) = str_field(map, "code") else {
        return error(id, "bad_request", "join.code needs code");
    };
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if PairingCode::parse(&digits).is_none() {
        return error(id, "bad_code", "the code is six digits");
    }
    let st = state(shared);
    match st.joins.get(&key).and_then(|j| j.codes.as_ref()) {
        Some(codes) if codes.send(digits).is_ok() => json!({"re": id}),
        _ => error(
            id,
            "no_join",
            "no link join with that invitation is running",
        ),
    }
}

fn ticket_hash(map: &Map<String, Value>) -> Option<[u8; 32]> {
    unhex(str_field(map, "ticket_hash")?).ok()?.try_into().ok()
}

/// `join.status {ticket_hash}`: how a link join of that ticket stands. A
/// completion record is replayed first (Phase 1b §5.4): the host's row,
/// its approvals and the settled pending mark, so `done` is only answered
/// once all three are stored.
fn join_status(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let Some(hash) = ticket_hash(map) else {
        return error(id, "bad_request", "join.status needs ticket_hash (hex)");
    };
    let stale = Some((
        shared.caller.now().secs(),
        shared.limits.join_done_keep_secs(),
    ));
    // Must-fail control: recovery saves the pin alone.
    let full = !cfg!(mousse_control = "done-pin-only");
    let done = match crate::peer::replay_completion(&shared.info.state_dir, &hash, full, stale) {
        Ok(done) => done,
        Err(e) => return error(id, "store_failed", e.to_string()),
    };
    if let Some(done) = &done {
        if let Err(e) = shared.caller.settle_stored(&hash) {
            return error(id, "store_failed", e.to_string());
        }
        if let Ok(identity) = identity_from_hex(&done.host_identity) {
            shared.keep.kick(super::paths::Kick::Reset(Some(identity)));
        }
    }
    let record = match shared.caller.flow_record(&hash) {
        Ok(record) => record,
        Err(e) => return error(id, "store_failed", e.to_string()),
    };
    json!({
        "re": id,
        "done": done.map(|d| json!({
            "identity": d.host_identity,
            "name": d.peer.name,
            "role": role_text(&d.peer.role),
        })),
        "pending": record.is_some_and(|r| r.outcome_pending),
        "attempts_left": record.map_or(shared.caller.attempts_per_flow(), |r| r.attempts_left),
    })
}

/// `join.ack {ticket_hash}`: the app stored the outcome; drop the
/// completion record.
fn join_ack(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let Some(hash) = ticket_hash(map) else {
        return error(id, "bad_request", "join.ack needs ticket_hash (hex)");
    };
    match CompletionStore::in_dir(&shared.info.state_dir).remove(&hash) {
        Ok(removed) => json!({"re": id, "removed": removed}),
        Err(e) => error(id, "store_failed", e.to_string()),
    }
}

/// Drop the completion records whose ticket expired more than
/// `JOIN_DONE_KEEP_SECS` ago. Runs once at start, after the channel is up.
pub async fn prune_completions(shared: Arc<Shared>) {
    let dir = shared.info.state_dir.clone();
    let now = shared.caller.now().secs();
    let keep = shared.limits.join_done_keep_secs();
    let pruned =
        tokio::task::spawn_blocking(move || CompletionStore::in_dir(&dir).prune(now, keep)).await;
    if let Ok(Err(e)) = pruned {
        applog::line(format!("dropping old link completion records failed: {e}"));
    }
}

/// An in-person join paired: the ticket's hints the owner approved become
/// `ticket` approvals for its host (§1.3). Private literals need none.
fn store_ticket_approvals(shared: &Shared, ticket: &Ticket, approved: &[String]) {
    let policy = shared.caller.addr_policy().clone();
    let key = hex(ticket.host_identity.as_bytes());
    let at = crate::peer::now_secs();
    let entries: Vec<Approval> = super::paths::ticket_candidates(&policy, &ticket.routes, approved)
        .into_iter()
        .filter(|r| !policy.automatic(r) && approved.contains(&r.uri()))
        .map(|r| Approval {
            identity: key.clone(),
            destination: r.uri(),
            source: APPROVAL_SOURCE_TICKET.into(),
            at,
        })
        .collect();
    if entries.is_empty() {
        return;
    }
    let peers = peers(shared);
    let stored = peers
        .lock()
        .and_then(|held| ApprovalStore::in_dir(&shared.info.state_dir).add(&held, &entries));
    if let Err(e) = stored {
        applog::line(format!("saving approvals failed: {e}"));
    }
}

/// The host `identity` was removed: no completion record may bring it
/// back (Phase 1b §5.4).
fn forget_completions(shared: &Shared, identity: &str) -> Result<(), NetError> {
    let peers = peers(shared);
    let held = peers.lock()?;
    let removed = crate::peer::drop_completions(&shared.info.state_dir, &held, identity)?;
    drop(held);
    settle(shared, &removed);
    Ok(())
}

/// Clear the pending marks of `tickets`, whose completion records a
/// removal dropped, so repeating their joins cannot pair again.
fn settle(shared: &Shared, tickets: &[[u8; 32]]) {
    for hash in tickets {
        if let Err(e) = shared.caller.settle_stored(hash) {
            applog::line(format!("clearing a pending pairing mark failed: {e}"));
        }
    }
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
    let identity = shared
        .host
        .grants()
        .iter()
        .find(|g| g.id == GrantId(grant))
        .map(|g| hex(g.identity.as_bytes()));
    let removed = shared.removal.remove(GrantId(grant));
    if let (Ok(Removed::Saved | Removed::Paused), Some(identity)) = (&removed, &identity) {
        // Its approvals go too (§1.3), with any completion record.
        if let Err(e) = forget_completions(shared, identity) {
            applog::line(format!("dropping link completion records failed: {e}"));
        }
        if let Ok(pin) = identity_from_hex(identity) {
            shared.caller.forget_routes(Some(&pin));
        }
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

fn add_peer(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let identity = match str_field(map, "identity").map(identity_from_hex) {
        Some(Ok(identity)) => identity,
        _ => return error(id, "bad_request", "peer.add needs identity (hex)"),
    };
    let Some(name) = str_field(map, "name") else {
        return error(id, "bad_request", "peer.add needs name");
    };
    // The routes a host sends when it pairs back: private ranges only;
    // the others it offered are suggestions, never dialled (§1.3).
    let policy = shared.caller.addr_policy().clone();
    let routes = match super::paths::parse_routes(&policy, map.get("routes")) {
        Ok(routes) => routes,
        Err(e) => return error(id, "bad_route", e),
    };
    let offered = match super::paths::parse_offered(&policy, map.get("offered")) {
        Ok(offered) => offered,
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
                for r in &offered {
                    if !p.offered.contains(r) {
                        p.offered.push(r.clone());
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
                offered: offered.clone(),
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
    // The row, its approvals and any completion record naming it go
    // together, under the peers lock.
    let store = peers(shared);
    let updated = store.lock().and_then(|held| {
        held.update(|list| {
            let before = list.len();
            list.retain(|p| p.identity != key);
            forgotten = list.len() != before;
        })?;
        // Under the peers lock, which a join checks the generation under
        // before it stores the host: it stores before this or not at all.
        *super::lock(&shared.core)
            .peer_gen
            .entry(identity)
            .or_default() += 1;
        crate::peer::drop_completions(&shared.info.state_dir, &held, &key)
    });
    match updated {
        Ok(tickets) => settle(shared, &tickets),
        Err(e) => return error(id, "store_failed", e.to_string()),
    }
    shared.caller.forget_routes(Some(&identity));
    super::relay::forget_peer(shared, &identity);
    // Its outbound connections go with it, and so do those still opening:
    // a dial or renewal that started before publishes nothing.
    let core = super::lock(&shared.core);
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
        // A link's code, each time a new one shows (never logged).
        HostEvent::ShowCode {
            invitation,
            code,
            attempts_left,
        } => {
            if !state(shared).invitations.contains(&invitation) {
                return;
            }
            json!({
                "ev": "invite.code",
                "invitation": invitation_hex(&invitation),
                "code": code.as_str(),
                "attempts_left": attempts_left,
            })
        }
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
            super::relay::on_enrolled(shared, &invitation, grant.0);
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
            super::relay::on_invitation_ended(shared, &invitation);
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
                // Joins still running stop; each is answered `paused`.
                let joins: Vec<Join> = state(&shared).joins.drain().map(|(_, join)| join).collect();
                for join in joins {
                    join.task.abort();
                    shared.event(paused(&shared, &join.id));
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
