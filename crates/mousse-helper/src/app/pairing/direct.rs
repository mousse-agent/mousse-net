//! Pair with IP on the app channel (`docs/pair-with-ip-design.md` §4,
//! `docs/pairing-flow-design.md` §1.1). Every operation here answers
//! `unsupported` unless this helper speaks wire minor 4
//! ([`crate::direct::enabled`]).
//!
//! **Host.**
//! - `invite.create {kind: "direct", way: "lan"|"tailnet", route?, role?}`
//!   → `{invitation, kind, address, addresses, code, attempts_left,
//!   expires_at, ways}`, no `uri`. `address` is the way's first IPv4
//!   candidate (or the exact `route`), `addresses` the others. Other ways,
//!   unknown fields and a `route` the way does not offer are refused before
//!   the invitation exists.
//! - `invite.code {invitation, code, attempts_left}` after every attempt
//!   (the same code), `invite.cancel`, `enrolled` (with `kind: "direct"` and
//!   `provisional: true`: the grant commits on the device's first stream,
//!   `grant.committed`, or goes on a cancel, `enrollment.undone`) and
//!   `invite.ended`.
//! - `approval {kind: "direct", request, invitation, identity, device,
//!   name, role, state: connected|away, decision: pending|allowed,
//!   answer_by}`: one request per (invitation, identity), sent again with
//!   the same id whenever `state` or `decision` changes.
//!   `approval.answer {request, yes, role?}` allows (an `away` request is
//!   marked allowed and enrolled when the device is back) or declines.
//!   `approval.ended {request, invitation, reason}` takes the prompt away
//!   (`enrolled`, `cancelled`, `declined`, `dismissed`, `window_ended`).
//!
//! **Joiner.**
//! - `join.direct {address, code}` → `join.progress {flow, step:
//!   connecting|checking_code|awaiting_approval|reconnecting, short_id}`
//!   (`short_id`: this device's), then `{identity, name, role, invitation,
//!   conn, flow}` or an error. A flow already running for the same typed
//!   lookup and address (a recovery started at startup) takes the request
//!   instead of a new one.
//! - `join.direct.cancel {flow}` answers the flow's request `cancelled` at
//!   once; a flow that is away keeps running to deliver the cancel.
//! - A flow with no request (started at startup, or cancelled) ends with
//!   `join.direct.ended {flow, ...}`, the reply's fields or its error.
//! - `join.status {}` lists the completions by invitation and how many kept
//!   records did not read; `join.ack {invitation}` drops one.
//!
//! Neither the code nor its lookup is ever logged or put in a reply: store
//! errors of the joiner's records name files after the lookup, so they are
//! reported in fixed words.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use mousse_net_core::grants::Role;
use mousse_net_core::pairing::{
    ApprovalEnd, DirectCode, DirectEnd, DirectJoinerState, DirectPaired, DirectRequestId,
    InvitationId, RequestDecision, RequestPresence,
};
use mousse_net_core::ErrorCode;
use mousse_net_io::pipe::LocalRoute;
use mousse_net_io::store::{hex, short_id};
use mousse_net_io::{
    DirectCancelFailed, DirectDialFailure, DirectEvent, DirectJoin, DirectJoinEvent, Reached,
    RouteClass,
};
use serde_json::{json, Map, Value};
use tokio::sync::{mpsc, oneshot};

use super::super::{error, Shared};
use super::{availability, invitation_hex, paused, roles, state, way_unavailable};
use crate::applog;

/// Pair with IP state of one channel.
#[derive(Default)]
pub struct State {
    /// Kind 3 invitations this channel made and has not seen end.
    invitations: Vec<InvitationId>,
    /// Approval prompts that may still be answered, by request id.
    requests: HashMap<String, DirectRequestId>,
    /// Joiner flows running, by flow id.
    flows: HashMap<String, Flow>,
    next_flow: u64,
    /// Kept pending records whose names or contents did not read at the
    /// last start.
    unreadable: usize,
    /// Flows (by typed lookup and address) whose cancel could not be
    /// stored: never started again in this process, so a crossing Allow
    /// cannot pair them.
    blocked: HashSet<String>,
}

/// A joiner flow running.
struct Flow {
    /// The `join.direct` request it answers, if any.
    request: Option<Value>,
    /// The typed lookup and address, to match a later `join.direct` (kept
    /// in memory only: the lookup is part of the code).
    key: String,
    /// The last progress step shown.
    step: Option<&'static str>,
    cmds: mpsc::UnboundedSender<Cmd>,
    /// Where the flow stores the pairing; says whether a removal of the
    /// host refused it.
    store: Arc<crate::direct::DirectStore>,
    /// Cancelled: it runs on only to deliver the cancel, and no request
    /// takes it.
    cancelled: bool,
}

/// What a cancel came to.
enum Cancelled {
    /// The cancel is stored (or nothing of the flow is left to cancel).
    Safe,
    /// It could not be stored: the flow stopped.
    NotRecorded,
    /// The flow paired first.
    Paired,
    /// The flow can no longer be cancelled.
    WrongState,
}

enum Cmd {
    Cancel(oneshot::Sender<Cancelled>),
    Stop,
}

fn unsupported(id: &Value) -> Value {
    error(id, "unsupported", crate::direct::UNSUPPORTED)
}

/// Whether `invitation` is a kind 3 invitation of this channel.
pub fn owns_invitation(shared: &Shared, invitation: &InvitationId) -> bool {
    state(shared).direct.invitations.contains(invitation)
}

/// The id of a request: its invitation and the full fingerprint of the
/// device, so it stays the same while that device comes and goes.
fn request_id(request: &DirectRequestId, presence: RequestPresence) -> String {
    let id = format!(
        "direct-{}-{}",
        hex(&request.invitation.0),
        hex(&request.identity.fingerprint())
    );
    // Must-fail control (tests only): a new id each time the device comes
    // back, as a per-connection id would be.
    if cfg!(mousse_control = "direct-approval-per-connection") && presence == RequestPresence::Away
    {
        return format!("{id}-away");
    }
    id
}

/// `invite.create {kind: "direct", way, route?, role?}`.
pub fn invite(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    if !crate::direct::enabled() {
        return unsupported(id);
    }
    if let Some(field) = map
        .keys()
        .find(|k| !matches!(k.as_str(), "id" | "op" | "kind" | "way" | "route" | "role"))
    {
        return error(
            id,
            "bad_request",
            format!("invite.create has no field {field:?}"),
        );
    }
    let role = match roles::optional_role(map) {
        Ok(role) => role.unwrap_or_else(Role::owner),
        Err(e) => return error(id, "bad_request", e),
    };
    let way = match map.get("way").and_then(Value::as_str) {
        Some(way @ ("lan" | "tailnet")) => way,
        _ => {
            return error(
                id,
                "bad_request",
                "a direct invitation's way is lan or tailnet",
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
    if availability::restart_required(shared, &inventory, saved.as_ref(), way) {
        return way_unavailable(id, way, "restart_required");
    }
    // The way's IPv4 candidates in their order; virtual adapters are not
    // ranked after physical ones yet (that waits for a check by hand on
    // Windows).
    let shown = |route: Option<&str>| -> Vec<SocketAddr> {
        let selected = availability::select(&inventory, way, route);
        crate::serve::direct_addresses(selected.iter().map(String::as_str))
    };
    let addresses = shown(route);
    let Some(&address) = addresses.first() else {
        let reason = if route.is_some() && !shown(None).is_empty() {
            "route_not_offered"
        } else {
            availability::unavailable_reason(shared, &inventory, saved.as_ref(), way)
        };
        return way_unavailable(id, way, reason);
    };
    let created = match shared.host.invite_direct(address, role) {
        Ok(created) => created,
        Err(e) => return error(id, "refused", e.to_string()),
    };
    state(shared).direct.invitations.push(created.invitation);
    // Shown only to the owner, never logged.
    let code = created.code.to_display();
    json!({
        "re": id,
        "invitation": invitation_hex(&created.invitation),
        "kind": "direct",
        "address": address.to_string(),
        "addresses": addresses[1..].iter().map(ToString::to_string).collect::<Vec<_>>(),
        "code": code.as_str(),
        "attempts_left": created.attempts_left,
        "expires_at": created.expires_at.secs(),
        "ways": [way],
    })
}

/// `invite.cancel` of a kind 3 invitation.
pub fn cancel_invitation(shared: &Shared, invitation: &InvitationId) {
    shared.host.cancel_direct(invitation);
}

/// `approval.answer` for a kind 3 request; `None` when `request` is not
/// one.
pub fn answer(
    shared: &Shared,
    id: &Value,
    request: &str,
    yes: bool,
    role: Option<Role>,
) -> Option<Value> {
    let req = state(shared).direct.requests.get(request).cloned()?;
    if !yes {
        return Some(match shared.host.decline_direct(&req) {
            Ok(()) => json!({"re": id}),
            Err(e) => error(id, "stale", e.to_string()),
        });
    }
    if shared.removal.is_paused() {
        return Some(paused(shared, id));
    }
    Some(match shared.host.allow_direct(&req, role) {
        Ok(()) => json!({"re": id}),
        Err(e @ mousse_net_io::NetError::Store(_)) => error(id, "store_failed", e.to_string()),
        Err(e) => error(id, "stale", e.to_string()),
    })
}

fn presence_name(p: RequestPresence) -> &'static str {
    match p {
        RequestPresence::Connected => "connected",
        RequestPresence::Away => "away",
    }
}

fn decision_name(d: RequestDecision) -> &'static str {
    match d {
        RequestDecision::Pending => "pending",
        RequestDecision::Allowed => "allowed",
    }
}

fn end_name(end: ApprovalEnd) -> &'static str {
    match end {
        ApprovalEnd::Enrolled => "enrolled",
        ApprovalEnd::Cancelled => "cancelled",
        ApprovalEnd::Declined => "declined",
        ApprovalEnd::Dismissed => "dismissed",
        ApprovalEnd::WindowEnded => "window_ended",
    }
}

/// A Pair with IP host event, as app events; `None` for nothing to send.
pub fn host_event(shared: &Shared, event: DirectEvent) -> Option<Value> {
    match event {
        DirectEvent::Code {
            invitation,
            attempts_left,
        } => {
            if !owns_invitation(shared, &invitation) {
                return None;
            }
            // The same code, fewer attempts (never logged).
            let (code, _) = shared.host.direct_code(&invitation)?;
            let code = code.to_display();
            Some(json!({
                "ev": "invite.code",
                "invitation": invitation_hex(&invitation),
                "code": code.as_str(),
                "attempts_left": attempts_left,
            }))
        }
        DirectEvent::Approval(a) => {
            if !owns_invitation(shared, &a.request.invitation) {
                // Not an invitation of this channel: nobody can answer.
                let _ = shared.host.decline_direct(&a.request);
                return None;
            }
            let request = request_id(&a.request, a.presence);
            let value = json!({
                "ev": "approval",
                "kind": "direct",
                "request": request,
                "invitation": invitation_hex(&a.request.invitation),
                "identity": hex(a.request.identity.as_bytes()),
                "device": short_id(&a.request.identity),
                "name": a.name,
                "role": a.role.as_str(),
                "state": presence_name(a.presence),
                "decision": decision_name(a.decision),
                "answer_by": a.answer_by.secs(),
            });
            state(shared).direct.requests.insert(request, a.request);
            Some(value)
        }
        DirectEvent::ApprovalEnded { request, reason } => {
            let mut st = state(shared);
            let ids: Vec<String> = st
                .direct
                .requests
                .iter()
                .filter(|(_, r)| **r == request)
                .map(|(id, _)| id.clone())
                .collect();
            for id in &ids {
                st.direct.requests.remove(id);
            }
            drop(st);
            let id = ids
                .into_iter()
                .next()
                .unwrap_or_else(|| request_id(&request, RequestPresence::Connected));
            Some(json!({
                "ev": "approval.ended",
                "request": id,
                "invitation": invitation_hex(&request.invitation),
                "reason": end_name(reason),
            }))
        }
        DirectEvent::Enrolled {
            invitation,
            grant,
            identity,
            role,
        } => {
            applog::line(format!(
                "enrolled grant {} {} by Pair with IP (provisional)",
                grant.0,
                short_id(&identity)
            ));
            state(shared)
                .direct
                .invitations
                .retain(|i| *i != invitation);
            Some(json!({
                "ev": "enrolled",
                "kind": "direct",
                "provisional": true,
                "invitation": invitation_hex(&invitation),
                "grant": grant.0,
                "identity": hex(identity.as_bytes()),
                "role": role.as_str(),
            }))
        }
        DirectEvent::Committed { grant, identity } => {
            applog::line(format!(
                "grant {} {} committed",
                grant.0,
                short_id(&identity)
            ));
            Some(json!({
                "ev": "grant.committed",
                "grant": grant.0,
                "identity": hex(identity.as_bytes()),
            }))
        }
        DirectEvent::EnrollmentUndone {
            invitation,
            grant,
            identity,
        } => {
            applog::line(format!(
                "provisional grant {} {} removed",
                grant.0,
                short_id(&identity)
            ));
            Some(json!({
                "ev": "enrollment.undone",
                "invitation": invitation_hex(&invitation),
                "grant": grant.0,
                "identity": hex(identity.as_bytes()),
            }))
        }
        DirectEvent::Ended { invitation, reason } => {
            let mut st = state(shared);
            st.direct.invitations.retain(|i| *i != invitation);
            st.direct.requests.retain(|_, r| r.invitation != invitation);
            drop(st);
            Some(json!({
                "ev": "invite.ended",
                "invitation": invitation_hex(&invitation),
                "reason": reason.name(),
            }))
        }
    }
}

/// The flow key of a typed lookup and address.
fn flow_key(lookup: &str, address: &str) -> String {
    format!("{lookup}@{address}")
}

/// `join.direct {address, code}`; `None` when the flow answers later.
pub fn join(shared: &Arc<Shared>, id: &Value, map: &Map<String, Value>) -> Option<Value> {
    if !crate::direct::enabled() {
        return Some(unsupported(id));
    }
    if let Some(field) = map
        .keys()
        .find(|k| !matches!(k.as_str(), "id" | "op" | "address" | "code"))
    {
        return Some(error(
            id,
            "bad_request",
            format!("join.direct has no field {field:?}"),
        ));
    }
    let (Some(address), Some(code)) = (
        map.get("address").and_then(Value::as_str),
        map.get("code").and_then(Value::as_str),
    ) else {
        return Some(error(
            id,
            "bad_request",
            "join.direct needs address and code",
        ));
    };
    if shared.removal.is_paused() {
        return Some(paused(shared, id));
    }
    let address = match crate::direct::typed_address(shared.caller.addr_policy(), address) {
        Ok(address) => address,
        Err(why) => return Some(error(id, "bad_address", why)),
    };
    // Checked here too so a bad code spends nothing and finds no flow.
    let lookup = match DirectCode::parse(code) {
        Ok(code) => code.lookup(),
        Err(e) => return Some(error(id, "bad_code", e.to_string())),
    };
    let key = flow_key(lookup.as_str(), &address.to_string());
    // Under the gate a pause stops flows under: this join starts before
    // the pause, which then stops it, or sees it and is refused.
    let _gate = shared.direct_gate.lock().unwrap_or_else(|e| e.into_inner());
    if shared.removal.is_paused() {
        return Some(paused(shared, id));
    }
    let name = {
        let mut st = state(shared);
        let attached = st.direct.flows.iter_mut().find(|(_, f)| f.key == key);
        if let Some((flow, entry)) = attached {
            if entry.request.is_some() || entry.cancelled {
                return Some(error(
                    id,
                    "busy",
                    "a join to that address with that code is running",
                ));
            }
            // A recovery started at startup: this request takes it.
            entry.request = Some(id.clone());
            let step = entry.step;
            let flow = flow.clone();
            drop(st);
            if let Some(step) = step {
                progress(shared, &flow, step, Some(id));
            }
            return None;
        }
        st.name.clone()
    };
    let (setup, store) = flow_setup(shared);
    let join = match shared
        .caller
        .join_direct(&setup, &address.to_string(), code, &name)
    {
        Ok(join) => join,
        Err(e) => {
            let code = match e.name() {
                "invalid_name" => "bad_name",
                other => other,
            };
            return Some(error(id, code, e.to_string()));
        }
    };
    start(shared, join, Some(id.clone()), false, store);
    None
}

/// What a flow starting now uses: the records, the denied identities, and
/// a store fenced against a removal of the host from now on (and against
/// a pause).
fn flow_setup(
    shared: &Arc<Shared>,
) -> (mousse_net_io::DirectSetup, Arc<crate::direct::DirectStore>) {
    let fence = shared.direct_fence();
    let paused_by = Arc::downgrade(shared);
    let fence: crate::direct::JoinFence = Arc::new(move |identity| {
        // Networking paused: nothing is stored until it resumes.
        if paused_by.upgrade().is_none_or(|s| s.removal.is_paused()) {
            return None;
        }
        fence(identity)
    });
    crate::direct::setup(
        &shared.info.state_dir,
        shared.caller.addr_policy().clone(),
        shared.direct_denied.clone(),
        Some(fence),
    )
}

/// Register a running flow and drive it. `recovery`: it recovers a kept
/// pending record (its code passed before).
fn start(
    shared: &Arc<Shared>,
    join: DirectJoin,
    request: Option<Value>,
    recovery: bool,
    store: Arc<crate::direct::DirectStore>,
) -> String {
    let key = flow_key(join.lookup().as_str(), &join.address().to_string());
    let (cmds, rx) = mpsc::unbounded_channel();
    let flow = {
        let mut st = state(shared);
        st.direct.next_flow += 1;
        let flow = format!("f{}", st.direct.next_flow);
        st.direct.flows.insert(
            flow.clone(),
            Flow {
                request,
                key,
                step: None,
                cmds,
                store,
                cancelled: false,
            },
        );
        flow
    };
    tokio::spawn(drive(shared.clone(), flow.clone(), join, rx, recovery));
    flow
}

/// A progress event; `request` is the `join.direct` the flow answers, if
/// any, so the app can tell its own join from another or a recovery.
fn progress(shared: &Shared, flow: &str, step: &str, request: Option<&Value>) {
    let mut event = json!({
        "ev": "join.progress",
        "flow": flow,
        "step": step,
        "short_id": short_id(&shared.caller.identity()),
    });
    if let Some(request) = request {
        event["request"] = request.clone();
    }
    shared.event(event);
}

/// The progress step of `state`; `passed`: the code passed on this flow
/// (or it recovers a pending record).
fn step_of(state: DirectJoinerState, passed: bool) -> Option<&'static str> {
    match state {
        DirectJoinerState::Holding
        | DirectJoinerState::Connecting
        | DirectJoinerState::AwaitingHello
        | DirectJoinerState::AwaitingAnswer => {
            Some(if passed { "reconnecting" } else { "connecting" })
        }
        DirectJoinerState::Exchanging => Some("checking_code"),
        DirectJoinerState::AwaitingAllow => Some("awaiting_approval"),
        DirectJoinerState::Away => Some("reconnecting"),
        DirectJoinerState::Paired | DirectJoinerState::Ended(_) => None,
    }
}

/// Show `step` for `flow` if it is new.
fn show(shared: &Shared, flow: &str, step: Option<&'static str>) {
    let Some(step) = step else { return };
    let request = {
        let mut st = state(shared);
        let Some(entry) = st.direct.flows.get_mut(flow) else {
            return;
        };
        if entry.step == Some(step) {
            return;
        }
        entry.step = Some(step);
        entry.request.clone()
    };
    progress(shared, flow, step, request.as_ref());
}

async fn drive(
    shared: Arc<Shared>,
    flow: String,
    mut join: DirectJoin,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
    recovery: bool,
) {
    let mut watch = join.state();
    // A recovery starts with its code already passed.
    let mut passed = recovery;
    let mut paired: Option<DirectPaired> = None;
    let mut watching = true;
    show(&shared, &flow, step_of(*watch.borrow_and_update(), passed));
    loop {
        tokio::select! {
            event = join.event() => match event {
                Some(DirectJoinEvent::CodePassed) => {
                    passed = true;
                    show(&shared, &flow, Some("awaiting_approval"));
                }
                Some(DirectJoinEvent::Paired(p)) => paired = Some(p),
                Some(DirectJoinEvent::Away) => {
                    passed = true;
                    show(&shared, &flow, Some("reconnecting"));
                }
                Some(DirectJoinEvent::Ended(_)) => {}
                None => break,
            },
            changed = watch.changed(), if watching => match changed {
                Ok(()) => {
                    let now = *watch.borrow_and_update();
                    if now == DirectJoinerState::AwaitingAllow {
                        passed = true;
                    }
                    show(&shared, &flow, step_of(now, passed));
                }
                Err(_) => watching = false,
            },
            cmd = cmds.recv() => match cmd {
                Some(Cmd::Cancel(done)) => match join.cancel() {
                    // Answered once the cancel is safe, never before.
                    Ok(pending) => {
                        tokio::spawn(async move {
                            let _ = done.send(match pending.confirmed().await {
                                Ok(()) => Cancelled::Safe,
                                Err(DirectCancelFailed::NotRecorded) => Cancelled::NotRecorded,
                                Err(DirectCancelFailed::Paired) => Cancelled::Paired,
                            });
                        });
                    }
                    Err(_) => {
                        let _ = done.send(Cancelled::WrongState);
                    }
                },
                Some(Cmd::Stop) | None => {
                    join.stop();
                    state(&shared).direct.flows.remove(&flow);
                    return;
                }
            },
        }
    }
    let result = join.finish().await;
    let (request, store) = match state(&shared).direct.flows.remove(&flow) {
        Some(entry) => (entry.request, entry.store),
        // Stopped meanwhile (a pause answered it).
        None => return,
    };
    let body = match result {
        Ok(joined) if joined.end == DirectEnd::Paired => match paired {
            Some(p) => paired_body(&shared, &flow, &p, joined.connection, &store),
            None => failure(&flow, "store_failed", "the pairing was not stored", None),
        },
        Ok(_) if store.was_fenced() => failure(
            &flow,
            "removed",
            "the host was removed, or networking paused, while the join ran; nothing was stored",
            None,
        ),
        Ok(joined) => end_body(&flow, joined.end, joined.dial),
        Err(_) => {
            applog::line("a Pair with IP join stopped: its records could not be read or stored");
            failure(
                &flow,
                "store_failed",
                "a Pair with IP record could not be read or stored",
                None,
            )
        }
    };
    let mut body = body;
    match request {
        Some(id) => body["re"] = id,
        None => body["ev"] = json!("join.direct.ended"),
    }
    shared.event(body);
}

fn failure(flow: &str, code: &str, reason: &str, attempts_left: Option<u8>) -> Value {
    let mut v = json!({"flow": flow, "error": code, "reason": reason});
    if let Some(left) = attempts_left {
        v["attempts_left"] = json!(left);
    }
    v
}

/// The error a flow that ended otherwise than paired gives.
fn end_body(flow: &str, end: DirectEnd, dial: Option<DirectDialFailure>) -> Value {
    match end {
        DirectEnd::Paired => failure(flow, "store_failed", "the pairing was not stored", None),
        DirectEnd::NeedsUpdate => failure(
            flow,
            "needs_update",
            "that computer runs an older Mousse",
            None,
        ),
        DirectEnd::OwnDevice => failure(flow, "own_device", "that address is this device", None),
        DirectEnd::CodeFailed { attempts_left } => failure(
            flow,
            "pairing_failed",
            "the code didn't work",
            Some(attempts_left),
        ),
        DirectEnd::AttemptsExhausted => failure(
            flow,
            "attempts_exhausted",
            "no tries left for this code",
            None,
        ),
        DirectEnd::NotReceived { attempts_left } => failure(
            flow,
            "not_received",
            "the connection dropped before the code arrived; connect again",
            Some(attempts_left),
        ),
        DirectEnd::Cancelled => failure(flow, "cancelled", "the join was cancelled", None),
        DirectEnd::Busy => failure(
            flow,
            "busy",
            "another join with this code is running on this device",
            None,
        ),
        DirectEnd::BadRecord => failure(
            flow,
            "store_failed",
            "a Pair with IP record could not be read",
            None,
        ),
        DirectEnd::Settled => failure(
            flow,
            "settled",
            "another join on this device settled this one",
            None,
        ),
        DirectEnd::Closed(code) => match code {
            Some(ErrorCode::InvitationInvalid) => failure(
                flow,
                "invitation_invalid",
                "no open invitation at that address",
                None,
            ),
            Some(ErrorCode::PairingDeclined) => {
                failure(flow, "declined", "the host owner declined", None)
            }
            Some(ErrorCode::Cancelled) => {
                failure(flow, "cancelled", "the join was cancelled", None)
            }
            Some(ErrorCode::AttemptsExhausted) => failure(
                flow,
                "attempts_exhausted",
                "no tries left for this code",
                None,
            ),
            Some(ErrorCode::InternalError) => {
                failure(flow, "busy", "that computer is busy; try again", None)
            }
            Some(ErrorCode::UnsupportedVersion) => failure(
                flow,
                "needs_update",
                "that computer runs an older Mousse",
                None,
            ),
            Some(ErrorCode::PairingFailed) => {
                failure(flow, "pairing_failed", "pairing failed", None)
            }
            Some(other) => failure(
                flow,
                "unreachable",
                &format!("the connection closed ({})", other.name()),
                None,
            ),
            None => match dial {
                Some(DirectDialFailure::Forbidden) => {
                    failure(flow, "bad_address", "that address is never dialled", None)
                }
                Some(DirectDialFailure::NotMousse) => failure(
                    flow,
                    "not_mousse",
                    "can't reach Mousse at that address",
                    None,
                ),
                _ => failure(flow, "unreachable", "can't reach that address", None),
            },
        },
    }
}

/// The reply of a flow that paired: the pin, owner route and completion
/// record are stored; the live connection, if it is still up, is published.
fn paired_body(
    shared: &Arc<Shared>,
    flow: &str,
    p: &DirectPaired,
    connection: Option<mousse_net_io::Connection>,
    store: &crate::direct::DirectStore,
) -> Value {
    applog::line(format!("joined {} by Pair with IP", short_id(&p.identity)));
    shared.forget_routes(&p.identity);
    shared
        .keep
        .kick(super::super::paths::Kick::Reset(Some(p.identity)));
    let role = p.role.as_str().to_owned();
    let conn = connection.and_then(|conn| {
        let policy = shared.caller.addr_policy();
        let addr = SocketAddr::new(p.address.ip, p.address.port);
        let route = LocalRoute::parse(&format!("tcp://{}", p.address)).ok()?;
        let reached = Reached {
            route,
            class: RouteClass::of_tcp(policy.class_of(addr)),
        };
        let fields = json!({
            "dir": "out",
            "role": role,
            "route": super::super::paths::route_json(&reached),
        });
        // The generation the host had when it was stored, under the peers
        // lock: a `peer.forget` since closes this path instead. Must-fail
        // control (tests only): read now.
        let gen = if cfg!(mousse_control = "direct-pin-after-removal") {
            shared.peer_gen(&p.identity)
        } else {
            store.stored_gen(&p.identity)?
        };
        shared.add_outbound(conn, gen, fields).ok()
    });
    json!({
        "flow": flow,
        "identity": hex(p.identity.as_bytes()),
        "name": p.name,
        "role": role,
        "invitation": invitation_hex(&p.invitation),
        "already": false,
        "conn": conn,
    })
}

/// `join.direct.cancel {flow}`; `None` when the reply comes later.
pub fn cancel(shared: &Arc<Shared>, id: &Value, map: &Map<String, Value>) -> Option<Value> {
    if !crate::direct::enabled() {
        return Some(unsupported(id));
    }
    if let Some(field) = map
        .keys()
        .find(|k| !matches!(k.as_str(), "id" | "op" | "flow"))
    {
        return Some(error(
            id,
            "bad_request",
            format!("join.direct.cancel has no field {field:?}"),
        ));
    }
    let Some(flow) = map.get("flow").and_then(Value::as_str) else {
        return Some(error(id, "bad_request", "join.direct.cancel needs flow"));
    };
    let Some(cmds) = state(shared).direct.flows.get(flow).map(|f| f.cmds.clone()) else {
        return Some(error(
            id,
            "no_join",
            "no Pair with IP join with that flow is running",
        ));
    };
    let (done, taken) = oneshot::channel();
    if cmds.send(Cmd::Cancel(done)).is_err() {
        return Some(error(
            id,
            "no_join",
            "no Pair with IP join with that flow is running",
        ));
    }
    let (shared, id, flow) = (shared.clone(), id.clone(), flow.to_owned());
    tokio::spawn(async move {
        match taken.await.unwrap_or(Cancelled::NotRecorded) {
            Cancelled::Safe => {}
            Cancelled::WrongState => {
                shared.event(error(
                    &id,
                    "no_join",
                    "that join can no longer be cancelled",
                ));
                return;
            }
            Cancelled::Paired => {
                shared.event(error(&id, "no_join", "that join paired before the cancel"));
                return;
            }
            // Not stored: the flow stops, is never started again here, and
            // its request is answered with the store failure.
            Cancelled::NotRecorded => {
                let entry = {
                    let mut st = state(&shared);
                    let entry = st.direct.flows.remove(&flow);
                    if let Some(entry) = &entry {
                        st.direct.blocked.insert(entry.key.clone());
                    }
                    entry
                };
                let reason = "the cancel could not be stored; the join is stopped";
                if let Some(entry) = entry {
                    let _ = entry.cmds.send(Cmd::Stop);
                    if let Some(request) = entry.request {
                        let mut reply = failure(&flow, "store_failed", reason, None);
                        reply["re"] = request;
                        shared.event(reply);
                    }
                }
                applog::line("a Pair with IP cancel could not be stored; the join is stopped");
                shared.event(error(&id, "store_failed", reason));
                return;
            }
        }
        // The cancel is stored: the request is answered now; a flow that
        // is away keeps running to deliver it, and ends with
        // `join.direct.ended`.
        let request = state(&shared).direct.flows.get_mut(&flow).and_then(|f| {
            f.cancelled = true;
            f.request.take()
        });
        if let Some(request) = request {
            let mut reply = failure(&flow, "cancelled", "the join was cancelled", None);
            reply["re"] = request;
            shared.event(reply);
        }
        shared.event(json!({"re": id}));
    });
    None
}

/// `join.status {}` (no `ticket_hash`): the Pair with IP completions by
/// invitation, and how many kept records did not read at the last start.
pub fn status(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    if !crate::direct::enabled() {
        return unsupported(id);
    }
    if let Some(field) = map.keys().find(|k| !matches!(k.as_str(), "id" | "op")) {
        return error(
            id,
            "bad_request",
            format!("join.status has no field {field:?}"),
        );
    }
    match crate::direct::Completions::in_dir(&shared.info.state_dir).list() {
        Ok(list) => json!({
            "re": id,
            "direct": list.iter().map(crate::direct::DirectCompletion::json).collect::<Vec<_>>(),
            "direct_unreadable": state(shared).direct.unreadable,
        }),
        Err(e) => error(id, "store_failed", e.to_string()),
    }
}

/// `join.ack {invitation}`: the app stored a Pair with IP completion.
pub fn ack(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    if !crate::direct::enabled() {
        return unsupported(id);
    }
    if let Some(field) = map
        .keys()
        .find(|k| !matches!(k.as_str(), "id" | "op" | "invitation"))
    {
        return error(
            id,
            "bad_request",
            format!("join.ack has no field {field:?}"),
        );
    }
    let Some(invitation) = map
        .get("invitation")
        .and_then(Value::as_str)
        .and_then(crate::direct::parse_invitation)
    else {
        return error(id, "bad_request", "join.ack needs invitation (hex)");
    };
    match crate::direct::Completions::in_dir(&shared.info.state_dir).remove(&invitation) {
        Ok(removed) => json!({"re": id, "removed": removed}),
        Err(e) => error(id, "store_failed", e.to_string()),
    }
}

/// Recover every kept pending record (at start, and when networking
/// resumes). Records whose names do not read are counted for `join.status`
/// and logged by number only.
pub fn resume(shared: &Arc<Shared>) {
    if !crate::direct::enabled() {
        return;
    }
    // Under the gate a pause stops flows under, and never while paused:
    // the pause's end starts them. Must-fail control (tests only): the
    // pause is not checked.
    let _gate = shared.direct_gate.lock().unwrap_or_else(|e| e.into_inner());
    if shared.removal.is_paused() && !cfg!(mousse_control = "direct-resume-while-paused") {
        return;
    }
    let name = state(shared).name.clone();
    let (setup, store) = flow_setup(shared);
    match shared.caller.resume_direct(&setup, &name) {
        Ok(resumed) => {
            // Bad names and bad contents alike; never their file names.
            // Must-fail control (tests only): bad contents not counted.
            let damaged = if cfg!(mousse_control = "direct-unreadable-names-only") {
                0
            } else {
                resumed.damaged
            };
            let unreadable = resumed.unreadable.len() + damaged;
            state(shared).direct.unreadable = unreadable;
            if unreadable > 0 {
                applog::line(format!(
                    "{unreadable} kept Pair with IP record(s) could not be read; they are kept"
                ));
            }
            for join in resumed.joins {
                let key = flow_key(join.lookup().as_str(), &join.address().to_string());
                // A flow whose cancel could not be stored stays stopped.
                if state(shared).direct.blocked.contains(&key) {
                    join.stop();
                    continue;
                }
                start(shared, join, None, true, store.clone());
            }
        }
        Err(_) => applog::line("listing the kept Pair with IP records failed"),
    }
}

/// Networking paused: every flow stops where it is (its records stay for
/// the next start or resume), and each waiting request is answered
/// `paused`.
pub fn pause(shared: &Shared) {
    let _gate = shared.direct_gate.lock().unwrap_or_else(|e| e.into_inner());
    let flows: Vec<Flow> = state(shared).direct.flows.drain().map(|(_, f)| f).collect();
    for flow in flows {
        let _ = flow.cmds.send(Cmd::Stop);
        if let Some(id) = flow.request {
            shared.event(paused(shared, &id));
        }
    }
}

/// Whether no flow runs (a resume starts them again only then).
pub fn idle(shared: &Shared) -> bool {
    state(shared).direct.flows.is_empty()
}
