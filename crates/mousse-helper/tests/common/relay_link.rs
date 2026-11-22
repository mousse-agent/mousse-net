//! A "Send link" join that can only go through a relay (pairing-flow
//! design §9): host B is enrolled on a relay, and its own route is
//! relabelled `public` for joiner A (`TEST_CLASS_MAP`), which approves only
//! the relay's destination. Test files include it with `#[path]`, beside
//! the relay fixture named `relay_fixture`.
#![allow(dead_code)]

use std::path::Path;
use std::time::{Duration, Instant};

use crate::common::*;
use crate::relay_fixture::TestRelay as Relay;
use mousse_net_core::pairing::Ticket;
use mousse_net_core::relay::proof::invitation_tag;
use mousse_net_core::relay_endpoint::RelayRoute;
use mousse_net_io::store::hex;
use serde_json::{json, Value};

/// Fast re-registration and redials.
pub const FAST: [(&str, &str); 3] = [
    ("VIA_RELAY_RETRY_FIRST_MS", "100"),
    ("KEEP_RETRY_FIRST_MS", "100"),
    ("KEEP_RETRY_MAX_MS", "500"),
];

/// Host B on a relay, and the class map that hides its own route from A.
/// Bind it before the joiner's endpoint, so the joiner stops first.
pub struct RelayHost {
    pub relay: Relay,
    pub end: Endpoint,
    pub b: App,
    /// `TEST_CLASS_MAP` for A: B's port is `public`.
    pub map: String,
}

/// A link from B: the ticket, its code and its invitation id.
pub struct Link {
    pub uri: String,
    pub ticket: Ticket,
    pub code: String,
    pub inv: String,
}

impl Link {
    pub fn hash(&self) -> String {
        hex(&self.ticket.hash())
    }

    /// The ticket's invitation tag, as the relay sees it, in the clear.
    pub fn tag(&self) -> [u8; 32] {
        invitation_tag(&self.ticket.invitation, &self.ticket.secret)
    }
}

/// Greet `app` with protocol 1.1: the `hello` reply.
pub fn greet(app: &mut App) -> Value {
    let name = app.name.clone();
    let reply = app.call("hello", json!({"proto": [1, 1], "name": name}));
    app.identity = reply["identity"].as_str().unwrap().to_owned();
    reply
}

impl RelayHost {
    pub fn start(tag: &str) -> Self {
        Self::start_with(tag, &[])
    }

    pub fn start_with(tag: &str, overrides: &[(&'static str, u64)]) -> Self {
        let relay = Relay::start_with(overrides);
        let end = Endpoint::init(&format!("{tag}-b"));
        let mut b = end.app("hostB", &FAST);
        let port = greet(&mut b)["port"].as_u64().unwrap();
        let reply = b.call("relay.enroll", json!({"link": relay.link()}));
        assert_eq!(reply["relay"]["state"], "registered", "{reply}");
        Self {
            relay,
            end,
            b,
            map: format!("{port}=public"),
        }
    }

    pub fn destination(&self) -> String {
        self.relay.destination()
    }

    /// A's environment: [`FAST`], the class map and `extra`.
    pub fn env<'a>(&'a self, extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
        let mut env: Vec<(&str, &str)> = FAST.to_vec();
        env.push(("TEST_CLASS_MAP", self.map.as_str()));
        env.extend_from_slice(extra);
        env
    }

    /// Joiner A on `end`, with `extra` limits and `raw` test hooks.
    pub fn joiner(&self, end: &Endpoint, extra: &[(&str, &str)], raw: &[(&str, &Path)]) -> App {
        let mut a = end.app_raw("peerA", &self.env(extra), 0, raw);
        greet(&mut a);
        a
    }

    /// A new link whose only route A may take is the relay.
    pub fn link(&mut self) -> Link {
        let invite = self.b.call("invite.create", json!({"kind": "link"}));
        let uri = invite["uri"].as_str().unwrap().to_owned();
        let ticket = Ticket::from_fragment(&uri).unwrap();
        assert!(
            ticket
                .routes
                .iter()
                .any(|r| RelayRoute::parse_hint(r).is_some()),
            "no relay hint: {invite}"
        );
        Link {
            uri,
            ticket,
            code: invite["code"].as_str().unwrap().to_owned(),
            inv: invite["invitation"].as_str().unwrap().to_owned(),
        }
    }

    /// Start A's join of `link`, the relay approved, and type the code:
    /// the join's request id.
    pub fn join(&self, a: &mut App, link: &Link) -> u64 {
        let id = a.start(
            "join",
            json!({"ticket": link.uri, "arrival": "link", "approved": [self.destination()]}),
        );
        a.wait("join.code_needed", WAIT, |st| {
            st.messages
                .iter()
                .find(|m| m["ev"] == "join.code_needed" && m["invitation"] == link.inv.as_str())
                .cloned()
        });
        a.call(
            "join.code",
            json!({"invitation": link.inv, "code": link.code}),
        );
        id
    }

    /// A's join of a new link, stopped by the crash hook at `point` once B
    /// enrolled A.
    pub fn join_crashing(&mut self, a_end: &Endpoint, point: &str) -> Link {
        self.join_crashing_with(a_end, point, &[])
    }

    /// [`RelayHost::join_crashing`], A with `extra` limits.
    pub fn join_crashing_with(
        &mut self,
        a_end: &Endpoint,
        point: &str,
        extra: &[(&str, &str)],
    ) -> Link {
        let crash = [("MOUSSE_HELPER_TEST_CRASH", Path::new(point))];
        let mut a = self.joiner(a_end, extra, &crash);
        let link = self.link();
        self.join(&mut a, &link);
        assert_eq!(
            a.exit_within(WAIT),
            Some(86),
            "never stopped at {point}: {}",
            a.err()
        );
        self.b
            .event("enrolled", |m| m["invitation"] == link.inv.as_str());
        link
    }

    /// B's relay status for `identity` in `grants.list`.
    pub fn relay_status(&mut self, identity: &str) -> Value {
        let list = self.b.call("grants.list", json!({}));
        list["grants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["identity"] == identity)
            .map(|g| g["relay"].clone())
            .unwrap_or(Value::Null)
    }
}

/// `join.status` for `link` on `a`.
pub fn status(a: &mut App, link: &Link) -> Value {
    a.call("join.status", json!({"ticket_hash": link.hash()}))
}

/// What `dir`'s `relay-peers.json` keeps for the host `identity`.
pub fn relay_peer(dir: &Path, identity: &str) -> Value {
    let Ok(bytes) = std::fs::read(dir.join("relay-peers.json")) else {
        return Value::Null;
    };
    let file: Value = serde_json::from_slice(&bytes).unwrap();
    file["peers"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["identity"] == identity)
        .cloned()
        .unwrap_or(Value::Null)
}

/// The approvals in `dir`.
pub fn approvals(dir: &Path) -> Vec<Value> {
    match std::fs::read(dir.join("approvals.json")) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes).unwrap()["approvals"]
            .as_array()
            .unwrap()
            .clone(),
        Err(_) => Vec::new(),
    }
}

/// `dial` until it works: the outbound connection's `conn.up`.
pub fn dial_up(from: &mut App, to: &str) -> Value {
    let start = Instant::now();
    loop {
        let reply = from.request("dial", json!({"identity": to}));
        if let Some(conn) = reply["conn"].as_u64() {
            return from.event("conn.up", |m| m["conn"] == conn);
        }
        assert!(start.elapsed() < WAIT, "dial never worked: {reply}");
        std::thread::sleep(Duration::from_millis(100));
    }
}
