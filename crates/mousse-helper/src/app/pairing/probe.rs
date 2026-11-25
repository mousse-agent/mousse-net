//! `join.probe {ticket, arrival, approved?}` and `join.probe.cancel
//! {probe}`: whether the host a link names answers on a route a join would
//! dial (`docs/pairing-flow-design.md` §5).
//!
//! - It dials what `join` would dial ([`super::join_plan`]): private
//!   literals, and hints in both the ticket and `approved` (at most
//!   `MAX_ROUTES`), in the join's order ([`crate::peer::in_join_order`]).
//!   Nothing given here is stored.
//! - Each route is opened as a join opens it
//!   ([`mousse_net_io::Caller::open_route`]: a name is resolved once, and
//!   the first address that takes the connection is the one used), then
//!   the inner TLS handshake pinned to the ticket's host runs on that pipe
//!   ([`mousse_net_io::Caller::probe_pipe`]) and the pipe is dropped. No
//!   `HELLO`, `JOIN_PROOF`, code or stream; nothing is stored and no
//!   connection is announced.
//! - Relay hints are never probed: a relay join opens a circuit and uses
//!   the host's pre-accept quota. With one left and no direct route that
//!   answered, the reply is `reachable: null, reason: "relay_unprobed"`.
//! - One route at a time, under one monotonic deadline for the whole probe
//!   (`MOUSSE_NET_JOIN_PROBE_MS`). No route starts after the deadline, a
//!   cancel, a networking pause or the channel's close: each is checked
//!   before the first route and before each next one, and dropping the
//!   attempt cancels its dial.
//! - The request id is a string or a number, and is the cancel handle; an
//!   id of a probe still running is `busy`. One probe per ticket hash, and
//!   at most `MOUSSE_NET_JOIN_PROBES_MAX` at once (the helper has one app
//!   channel); another is `busy`.
//! - It ends on `join.probe.cancel` (the error `cancelled`, once), on a
//!   networking pause (`paused`) and when the channel closes. A probe's
//!   slot stays counted until its task has exited, however it exits (a
//!   panic too), and is freed before its answer or its cancel's reply.
//!
//! Replies: `{reachable: true, route, ms}`; `{reachable: null, reason}`
//! (`approval_required`, `relay_unprobed`); `{reachable: false, reason}`
//! (`no_route`, `timeout`, `unreachable`, `forbidden_address`,
//! `pin_mismatch`, `peer_certificate`, `tls`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::pairing::{Arrival, Ticket, MAX_ROUTES};
use mousse_net_io::pipe::LocalRoute;
use serde_json::{json, Map, Value};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::super::paths::{hint_decision, HintDecision};
use super::super::{error, End, Shared};
use crate::peer::JoinRoute;

/// A probe whose task has not exited yet.
pub struct Probe {
    /// The `join.probe` request id: its cancel handle.
    id: Value,
    /// The ticket's hash: one probe per ticket.
    hash: [u8; 32],
    /// This probe alone: an id can be used again once its probe ended.
    token: u64,
    /// The task, until a cancel takes it to stop it.
    task: Option<JoinHandle<()>>,
    /// A cancel took this probe: the cancel answers its request.
    cancelled: bool,
}

/// The next probe's token.
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(0);

/// A probe's hold on its slot, owned by its task: dropped when the task
/// exits, however it exits (its answer, a cancel's abort, a panic, the
/// runtime ending). It frees the slot, then sends the answer, so no answer
/// comes before the slot is free.
struct Slot {
    shared: Arc<Shared>,
    id: Value,
    token: u64,
    /// What the probe answers; `None` with `done` when nobody is left to
    /// answer.
    reply: Option<Value>,
    /// The probe ran to its end. Without it (a panic), the request is
    /// answered with an error, unless a cancel took it.
    done: bool,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let cancelled = {
            let mut st = super::state(&self.shared);
            match st.probes.iter().position(|p| p.token == self.token) {
                // Must-fail control: a cancelled probe keeps its slot.
                Some(i)
                    if st.probes[i].cancelled
                        && cfg!(mousse_control = "probe-cancel-keeps-slot") =>
                {
                    true
                }
                Some(i) => st.probes.remove(i).cancelled,
                None => false,
            }
        };
        if cancelled {
            return;
        }
        if let Some(reply) = self.reply.take() {
            self.shared.event(reply);
        } else if !self.done {
            self.shared
                .event(error(&self.id, "error", "the probe stopped"));
        }
    }
}

/// The reasons a probe that found nothing gives; any other failure reads
/// as `unreachable`.
const FAILURES: [&str; 6] = [
    "timeout",
    "unreachable",
    "forbidden_address",
    "pin_mismatch",
    "peer_certificate",
    "tls",
];

fn failure_of(e: &mousse_net_io::NetError) -> String {
    let reason = crate::peer::reason_of(e);
    if FAILURES.contains(&reason.as_str()) {
        reason
    } else {
        "unreachable".into()
    }
}

/// What one probe tries, and what it leaves untried.
struct Plan {
    pin: IdentityPublicKey,
    /// The direct routes a join would dial, in its order.
    routes: Vec<LocalRoute>,
    /// The ticket carries a relay hint (never probed).
    relay_left: bool,
    /// The ticket carries a hint a join would dial once approved, not
    /// approved here.
    approval_left: bool,
    /// For the control builds that break the probe.
    ticket: Ticket,
    arrival: Arrival,
    name: String,
    relays: Vec<(mousse_net_core::relay_endpoint::RelayRoute, [u8; 32])>,
}

/// `join.probe`; `None` when the probe answers later.
pub fn start(shared: &Arc<Shared>, id: &Value, map: &Map<String, Value>) -> Option<Value> {
    // The id is the cancel handle: it must be one a cancel can name.
    if !(id.is_string() || id.is_number()) {
        return Some(error(
            id,
            "bad_request",
            "join.probe needs a string or number id",
        ));
    }
    if let Some(field) = map
        .keys()
        .find(|k| !matches!(k.as_str(), "id" | "op" | "ticket" | "arrival" | "approved"))
    {
        return Some(error(
            id,
            "bad_request",
            format!("join.probe has no field {field:?}"),
        ));
    }
    let Some(text) = map.get("ticket").and_then(Value::as_str) else {
        return Some(error(id, "bad_request", "join.probe needs ticket"));
    };
    let arrival = match map.get("arrival").and_then(Value::as_str) {
        Some("scan") => Arrival::InAppScan,
        Some("link") => Arrival::Link,
        _ => return Some(error(id, "bad_request", "arrival is scan or link")),
    };
    let approved: Vec<String> = match map.get("approved") {
        None => Vec::new(),
        Some(Value::Array(list)) if list.len() <= MAX_ROUTES => {
            match list.iter().map(Value::as_str).collect::<Option<Vec<_>>>() {
                Some(list) => list.into_iter().map(str::to_owned).collect(),
                None => return Some(error(id, "bad_request", "approved is a list of routes")),
            }
        }
        Some(_) => {
            return Some(error(
                id,
                "bad_request",
                format!("approved is a list of at most {MAX_ROUTES} routes"),
            ))
        }
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
    let plan = super::join_plan(shared, &ticket, &approved);
    let mut routes: Vec<LocalRoute> = crate::peer::in_join_order(&plan.candidates)
        .into_iter()
        .filter_map(|c| match c {
            JoinRoute::Local(route) => Some(route.clone()),
            JoinRoute::Relay { .. } => None,
        })
        .collect();
    let mut relay_left = false;
    let mut approval_left = false;
    for hint in &ticket.routes {
        match hint_decision(&policy, hint) {
            HintDecision::Relay(_) => relay_left = true,
            HintDecision::Approval(route) if !plan.approved_routes.contains(&route.uri()) => {
                approval_left = true;
                // Must-fail control: an unapproved destination is dialled.
                if cfg!(mousse_control = "probe-dials-unapproved") && !routes.contains(&route) {
                    routes.push(route);
                }
            }
            _ => {}
        }
    }
    let hash = ticket.hash();
    let max = usize::try_from(shared.limits.join_probes_max()).unwrap_or(1);
    let mut st = super::state(shared);
    if st.probes.iter().any(|p| p.id == *id) {
        return Some(error(id, "busy", "a probe with this id is running"));
    }
    if st.probes.iter().any(|p| p.hash == hash) {
        return Some(error(id, "busy", "a probe of this ticket is running"));
    }
    if st.probes.len() >= max {
        return Some(error(id, "busy", "as many probes as allowed are running"));
    }
    let plan = Plan {
        pin: ticket.host_identity,
        routes,
        relay_left,
        approval_left,
        ticket,
        arrival,
        name,
        relays: plan.relays,
    };
    let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
    // The slot goes into the task's future now, so even a task aborted
    // before it first runs frees it.
    let slot = Slot {
        shared: shared.clone(),
        id: id.clone(),
        token,
        reply: None,
        done: false,
    };
    let task = tokio::spawn(run(slot, plan));
    st.probes.push(Probe {
        id: id.clone(),
        hash,
        token,
        task: Some(task),
        cancelled: false,
    });
    None
}

/// How a probe that stopped early answers: `paused`, or nothing once the
/// channel has closed.
enum Stop {
    Paused,
    Closed,
}

/// Whether the probe must stop before its next route: networking paused
/// or the channel closed.
fn stop(shared: &Shared, closed: &watch::Receiver<Option<End>>) -> Option<Stop> {
    if shared.removal.is_paused() {
        Some(Stop::Paused)
    } else if closed.borrow().is_some() {
        Some(Stop::Closed)
    } else {
        None
    }
}

/// Run one probe to its answer, unless it is cancelled, networking pauses
/// or the channel closes first. The answer goes out when `slot` drops.
async fn run(mut slot: Slot, plan: Plan) {
    let shared = slot.shared.clone();
    let id = slot.id.clone();
    let mut pause = shared.removal.watch();
    let mut ended = shared.ended.subscribe();
    let closed = shared.ended.subscribe();
    // A pause or close already there wins over the search.
    let outcome = tokio::select! {
        biased;
        _ = pause.wait_for(Option::is_some) => Err(Stop::Paused),
        _ = ended.wait_for(Option::is_some) => Err(Stop::Closed),
        reply = search(&shared, &id, plan, &closed) => reply,
    };
    slot.reply = match outcome {
        Ok(reply) => Some(reply),
        Err(Stop::Paused) => Some(super::paused(&shared, &id)),
        // Nobody is left to answer.
        Err(Stop::Closed) => None,
    };
    slot.done = true;
}

/// Try the plan's routes one at a time until one answers as the ticket's
/// host or the deadline passes; `Err` when a pause or the channel's close
/// came before a route.
async fn search(
    shared: &Shared,
    id: &Value,
    plan: Plan,
    closed: &watch::Receiver<Option<End>>,
) -> Result<Value, Stop> {
    let total = crate::limits::ms(shared.limits.join_probe_ms());
    let deadline = Instant::now() + total;
    // Must-fail control: each route gets a deadline of its own.
    let restart = cfg!(mousse_control = "probe-restarts-deadline");
    // Must-fail control: the probe opens a circuit through each relay.
    if cfg!(mousse_control = "probe-opens-relay-circuit") {
        let policy = shared.caller.addr_policy().clone();
        for (route, tag) in &plan.relays {
            let _ = super::super::relay::dial_join_route(&policy, route, *tag).await;
        }
    }
    let mut last: Option<String> = None;
    for route in &plan.routes {
        if let Some(stopped) = stop(shared, closed) {
            return Err(stopped);
        }
        if Instant::now() >= deadline && !restart {
            last = Some("timeout".into());
            break;
        }
        let attempt = probe_one(shared, &plan, route);
        let result = if restart {
            tokio::time::timeout(total, attempt).await
        } else {
            tokio::time::timeout_at(deadline, attempt).await
        };
        match result {
            Ok(Ok(took)) => {
                return Ok(json!({
                    "re": id,
                    "reachable": true,
                    "route": route.uri(),
                    "ms": u64::try_from(took.as_millis()).unwrap_or(u64::MAX),
                }));
            }
            Ok(Err(e)) => last = Some(failure_of(&e)),
            Err(_) => {
                last = Some("timeout".into());
                if !restart {
                    break;
                }
            }
        }
    }
    if plan.relay_left {
        return Ok(json!({"re": id, "reachable": null, "reason": "relay_unprobed"}));
    }
    if plan.approval_left {
        return Ok(json!({"re": id, "reachable": null, "reason": "approval_required"}));
    }
    Ok(json!({
        "re": id,
        "reachable": false,
        "reason": last.unwrap_or_else(|| "no_route".into()),
    }))
}

/// One route, as a join takes it: the pipe opened on the first address
/// that takes it, the pinned inner handshake on that pipe, then the pipe is
/// dropped. Another address of the same name is never tried after a
/// failed handshake, as a join never tries one.
async fn probe_one(
    shared: &Shared,
    plan: &Plan,
    route: &LocalRoute,
) -> Result<Duration, mousse_net_io::NetError> {
    let started = std::time::Instant::now();
    let (pipe, _) = shared.caller.open_route(route).await?;
    // Must-fail control: an open pipe counts, whoever answers inside it.
    if cfg!(mousse_control = "probe-accepts-outer-tls") {
        return Ok(started.elapsed());
    }
    shared
        .caller
        .probe_pipe(pipe, route.kind(), plan.pin)
        .await?;
    let took = started.elapsed();
    // Must-fail control: the probe goes on to pair, which reaches the
    // invitation.
    if cfg!(mousse_control = "probe-sends-join-proof") {
        if let Ok((pipe, _)) = shared.caller.open_route(route).await {
            let joining = shared
                .caller
                .join(pipe, &plan.ticket, plan.arrival, &plan.name);
            let _ = tokio::time::timeout(Duration::from_secs(2), joining).await;
        }
    }
    Ok(took)
}

/// `join.probe.cancel {probe}` → `{cancelled}`; `None` when the reply
/// comes once the probe has stopped. The probe's request is answered
/// `cancelled` once, and its slot is free before either reply.
pub fn cancel(shared: &Arc<Shared>, id: &Value, map: &Map<String, Value>) -> Option<Value> {
    if let Some(field) = map
        .keys()
        .find(|k| !matches!(k.as_str(), "id" | "op" | "probe"))
    {
        return Some(error(
            id,
            "bad_request",
            format!("join.probe.cancel has no field {field:?}"),
        ));
    }
    let Some(probe) = map.get("probe").filter(|p| p.is_string() || p.is_number()) else {
        return Some(error(id, "bad_request", "join.probe.cancel needs probe"));
    };
    // A probe that answered, ended or was cancelled already is not taken
    // again. The entry stays: the slot is the task's until it exits.
    let found = super::state(shared)
        .probes
        .iter_mut()
        .find(|p| p.id == *probe && !p.cancelled)
        .map(|p| {
            p.cancelled = true;
            (p.id.clone(), p.task.take())
        });
    let Some((probe_id, task)) = found else {
        return Some(json!({"re": id, "cancelled": false}));
    };
    // Stopped at once: no route starts after the cancel.
    if let Some(task) = &task {
        task.abort();
    }
    let (shared, id) = (shared.clone(), id.clone());
    tokio::spawn(async move {
        // The task has exited, so its slot is free, before either reply.
        if let Some(task) = task {
            let _ = task.await;
        }
        shared.event(error(&probe_id, "cancelled", "the probe was cancelled"));
        shared.event(json!({"re": id, "cancelled": true}));
    });
    None
}
