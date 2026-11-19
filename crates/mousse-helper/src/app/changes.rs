//! Path renewals and network changes (Phase 1a §2, §6 and §8).
//!
//! - **Renewals.** The caller renews each outbound path before its
//!   deadline. The new path is announced as `conn.up`, then
//!   `path.reopen {identity, from, conn}`: the app reopens its channels on
//!   `conn` and sends `path.reopened {conn}`, and only then does the old
//!   path close with `PATH_REPLACED`. A renewal try that fails is
//!   `path.renew_failed {identity, why, reason}`; the caller tries again
//!   later, until the old path's deadline.
//! - **Network changes.** The watcher reports interface changes and wakes
//!   (a jump of the monotonic clock). Either way every connection must
//!   answer a `PING` within `WAKE_PING_MS` or it is closed as dead, the
//!   browse cache is dropped, and every paired host without a path is
//!   dialled again at once, its backoff reset. (`serve` also announces the
//!   mDNS record again.)
//! - **Test hooks**, debug builds only: `MOUSSE_HELPER_INTERFACES_FILE`
//!   names a file whose lines are the interface list, read at every poll;
//!   `MOUSSE_HELPER_MANUAL_CLOCK=1` runs the helper on a clock the app moves
//!   with `test.clock {advance_secs, advance_mono_ms}`.

use std::sync::Arc;

use mousse_net_core::ErrorCode;
use mousse_net_io::store::{hex, short_id};
use mousse_net_io::watch::{InterfaceSource, NetChange};
use mousse_net_io::{Clock, ManualClock, PathEvent, SystemClock};
use serde_json::{json, Map, Value};

use super::{error, paths, Core, Shared};
use crate::applog;

/// Take the caller's renewals for as long as the channel runs.
pub async fn forward_renewals(shared: Arc<Shared>) {
    let mut events = shared.caller.start_renewals();
    while let Some(event) = events.recv().await {
        match event {
            PathEvent::Reopen { pin, from, conn } => {
                let identity = hex(pin.as_bytes());
                if shared.removal.is_paused() {
                    // Nothing new while networking is paused; the caller
                    // asks again later.
                    conn.close(ErrorCode::NoError);
                    shared.event(json!({
                        "ev": "path.renew_failed",
                        "identity": identity,
                        "why": "paused",
                        "reason": "networking is paused",
                    }));
                    continue;
                }
                // The caller numbers its paths apart from the host, so an
                // inbound connection can carry the same id: only this
                // peer's outbound ones are candidates.
                let from = super::lock(&shared.core)
                    .conns
                    .iter()
                    .find(|(_, e)| !e.inbound && e.identity == pin && e.conn.id() == from)
                    .map(|(no, _)| *no);
                let role = paths::stored_role(&shared, &pin);
                let no = shared.add_conn(conn, false, json!({"dir": "out", "role": role}));
                applog::line(format!("renewed path to {} (conn {no})", short_id(&pin)));
                shared.event(json!({
                    "ev": "path.reopen",
                    "identity": identity,
                    "from": from,
                    "conn": no,
                }));
            }
            PathEvent::RenewFailed { pin, error } => {
                applog::line(format!("renewing {} failed: {error}", short_id(&pin)));
                shared.event(json!({
                    "ev": "path.renew_failed",
                    "identity": hex(pin.as_bytes()),
                    "why": crate::peer::reason_of(&error),
                    "reason": crate::peer::describe(&error),
                }));
            }
        }
    }
}

/// `path.reopened {conn}`: the app reopened its channels on the renewed
/// path `conn`. It becomes current; the old path closes with
/// `PATH_REPLACED`.
pub fn reopened(shared: &Shared, core: &Core, id: &Value, map: &Map<String, Value>) -> Value {
    let Some(no) = map.get("conn").and_then(Value::as_u64) else {
        return error(id, "bad_request", "path.reopened needs conn");
    };
    let Some(entry) = core.conns.get(&no) else {
        return error(id, "no_conn", "no such connection");
    };
    match shared.caller.reopened(&entry.conn) {
        Ok(()) => json!({"re": id}),
        Err(e) => error(id, "not_renewed", e.to_string()),
    }
}

/// React to an interface change or a wake.
pub async fn on_change(shared: Arc<Shared>, change: NetChange) {
    applog::line(format!("network change: {change:?}"));
    if let Some(browse) = &shared.info.browse {
        browse.forget().await;
    }
    let conns: Vec<_> = super::lock(&shared.core)
        .conns
        .values()
        .map(|e| e.conn.clone())
        .collect();
    let within = crate::limits::ms(crate::limits::get().net.io().wake_ping_ms());
    let mut pings = tokio::task::JoinSet::new();
    for conn in conns {
        pings.spawn(async move {
            if !conn.ping(within).await {
                applog::line(format!(
                    "closing the path to {}: no answer after the change",
                    short_id(conn.peer())
                ));
                conn.close(ErrorCode::IdleTimeout);
            }
        });
    }
    while pings.join_next().await.is_some() {}
    shared.keep.kick(paths::Kick::Reset(None));
}

#[cfg(debug_assertions)]
struct FileInterfaces(std::path::PathBuf);

#[cfg(debug_assertions)]
impl InterfaceSource for FileInterfaces {
    fn snapshot(&self) -> Vec<String> {
        std::fs::read_to_string(&self.0)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// Where the watcher lists interfaces: the computer's, or in debug builds
/// the file named by `MOUSSE_HELPER_INTERFACES_FILE` if set.
pub fn interface_source() -> Arc<dyn InterfaceSource> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("MOUSSE_HELPER_INTERFACES_FILE") {
        return Arc::new(FileInterfaces(path.into()));
    }
    Arc::new(mousse_net_io::watch::SystemInterfaces)
}

/// The helper's clock, and in debug builds with
/// `MOUSSE_HELPER_MANUAL_CLOCK=1` the handle `test.clock` moves it by.
pub fn clock() -> (Arc<dyn Clock>, Option<Arc<ManualClock>>) {
    #[cfg(debug_assertions)]
    if std::env::var("MOUSSE_HELPER_MANUAL_CLOCK").as_deref() == Ok("1") {
        let manual = Arc::new(ManualClock::new());
        return (manual.clone(), Some(manual));
    }
    (Arc::new(SystemClock::new()), None)
}

/// `test.clock {advance_secs, advance_mono_ms}` (debug builds with a manual
/// clock): move the wall clock and the monotonic clock forward.
#[cfg(debug_assertions)]
pub fn test_clock(shared: &Shared, id: &Value, map: &Map<String, Value>) -> Value {
    let Some(clock) = &shared.info.manual_clock else {
        return error(id, "unknown_op", "no manual clock");
    };
    let secs = map.get("advance_secs").and_then(Value::as_i64).unwrap_or(0);
    let mono = map
        .get("advance_mono_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    clock.advance(secs);
    clock.advance_mono(mono);
    json!({"re": id, "now": clock.now().secs()})
}
