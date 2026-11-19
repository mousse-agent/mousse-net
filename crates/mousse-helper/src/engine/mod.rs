//! Engine-owned work: streams whose labels start `mousse-` (handled here,
//! never passed to the app), "remove on all my hosts" (Phase 4 Part D),
//! and the Plus client.
//!
//! Engine streams are opened only when the connection's agreed wire minor
//! allows them; anything else with a `mousse-` label is refused.

pub mod removals;
pub mod stream;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use mousse_net_core::grants::Role;
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::removal::{GRANTS_LABEL, REMOVAL_LABEL, REMOVAL_MIN_MINOR};
use mousse_net_core::ErrorCode;
use mousse_net_io::{Clock, Connection, Host, MuxStream, SharedSigner};
use serde_json::Value;
use tokio::sync::{mpsc, watch, Notify};

use crate::revoke::Removal;

/// The prefix of engine-owned stream labels.
pub const ENGINE_PREFIX: &str = "mousse-";

/// One endpoint's engine-owned work.
pub struct Engine {
    pub host: Host,
    pub removal: Arc<Removal>,
    pub signer: SharedSigner,
    pub clock: Arc<dyn Clock>,
    /// The endpoint's folder (peers, flow records, the admin store).
    pub state_dir: PathBuf,
    events: mpsc::UnboundedSender<Value>,
    /// Serializes changes to the admin store.
    admin_lock: Mutex<()>,
    /// Hosts a removal delivery runs for now.
    delivering: Mutex<HashSet<IdentityPublicKey>>,
    /// Live outbound connections, by a local number.
    outbound: Mutex<HashMap<u64, Arc<Connection>>>,
    next_outbound: Mutex<u64>,
    /// Wakes the mailbox task early (a new removal to deposit).
    mail_wake: Notify,
}

/// Ends a host's delivery turn when dropped.
pub struct DeliveryTurn<'a> {
    engine: &'a Engine,
    host: IdentityPublicKey,
}

impl Drop for DeliveryTurn<'_> {
    fn drop(&mut self) {
        self.engine
            .delivering
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.host);
    }
}

impl Engine {
    /// The engine of one endpoint. Events for the app (`removal.*`,
    /// `plus.*`) go to the returned receiver.
    pub fn new(
        host: Host,
        removal: Arc<Removal>,
        signer: SharedSigner,
        clock: Arc<dyn Clock>,
        state_dir: PathBuf,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<Value>) {
        let (events, rx) = mpsc::unbounded_channel();
        let engine = Arc::new(Self {
            host,
            removal,
            signer,
            clock,
            state_dir,
            events,
            admin_lock: Mutex::new(()),
            delivering: Mutex::new(HashSet::new()),
            outbound: Mutex::new(HashMap::new()),
            next_outbound: Mutex::new(1),
            mail_wake: Notify::new(),
        });
        (engine, rx)
    }

    /// Send an event to the app.
    pub fn event(&self, value: Value) {
        let _ = self.events.send(value);
    }

    /// Whether the inbound connection `conn` is live under an owner grant.
    pub fn is_owner_conn(&self, conn: &Connection) -> bool {
        self.host
            .grant_of(conn.id())
            .is_some_and(|g| g.role.as_str() == Role::OWNER)
    }

    /// Take the delivery turn for `host`, if no delivery runs for it.
    pub fn delivery_turn(&self, host: IdentityPublicKey) -> Option<DeliveryTurn<'_>> {
        let mut busy = self.delivering.lock().unwrap_or_else(|e| e.into_inner());
        if !busy.insert(host) {
            return None;
        }
        Some(DeliveryTurn { engine: self, host })
    }

    /// Live outbound connections to `host`.
    pub fn outbound_conns(&self, host: &IdentityPublicKey) -> Vec<Arc<Connection>> {
        self.outbound
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|c| c.peer() == host)
            .cloned()
            .collect()
    }

    /// Wake the mailbox task.
    pub fn mail_kick(&self) {
        self.mail_wake.notify_one();
    }

    /// Wait for [`Engine::mail_kick`].
    pub async fn mail_woken(&self) {
        self.mail_wake.notified().await;
    }

    /// An inbound connection is live. `opened` turns true once the caller
    /// has opened a stream (a host opens none before that).
    pub fn on_inbound(self: &Arc<Self>, conn: Arc<Connection>, opened: watch::Receiver<bool>) {
        tokio::spawn(removals::publish_grants(self.clone(), conn, opened));
    }

    /// An outbound connection is live: deliver what waits for its host.
    pub fn on_outbound(self: &Arc<Self>, conn: Arc<Connection>) {
        let no = {
            let mut next = self.next_outbound.lock().unwrap_or_else(|e| e.into_inner());
            let no = *next;
            *next += 1;
            no
        };
        self.outbound
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(no, conn.clone());
        let engine = self.clone();
        tokio::spawn(async move {
            tokio::spawn(removals::deliver(engine.clone(), conn.clone()));
            conn.closed().await;
            engine
                .outbound
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&no);
        });
    }

    /// A stream with a `mousse-` label. Handled here or refused.
    pub fn on_stream(self: &Arc<Self>, conn: Arc<Connection>, inbound: bool, stream: MuxStream) {
        let minor = conn.minor().unwrap_or(0);
        let label = stream.label().to_owned();
        if inbound && label == REMOVAL_LABEL && minor >= REMOVAL_MIN_MINOR {
            tokio::spawn(removals::serve_removal(self.clone(), stream));
        } else if !inbound && label == GRANTS_LABEL && minor >= REMOVAL_MIN_MINOR {
            tokio::spawn(removals::receive_grants(self.clone(), conn, stream));
        } else {
            stream.writer.reset(ErrorCode::RefusedStream);
        }
    }
}
