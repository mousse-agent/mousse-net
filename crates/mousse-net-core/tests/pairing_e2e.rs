//! End-to-end pairing vectors: `spec/vectors/pairing-e2e.json`.
//!
//! Each flow is a list of events (a host creates an invitation, a joiner
//! connects, a message arrives, the owner types a code...). The events run
//! against the real host and joiner state machines and gates, through the
//! public API only, with every random value taken in order from the flow's
//! scripted draws. Every message is therefore fixed byte for byte.
//!
//! `pairing_e2e_vectors` checks that the file matches the scenarios below,
//! then replays the file's own events and compares every output. Run it with
//! `MOUSSE_NET_WRITE_VECTORS=1` to rewrite the file.

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::path::PathBuf;

use mousse_net_core::authz::{CallerGate, CallerTraffic, ConnectionGate, Traffic, Verdict};
use mousse_net_core::control::{
    negotiate_version, AuthorizedState, ControlMessage, VersionSupport,
};
use mousse_net_core::grants::{GrantTable, OwnerRef, Role};
use mousse_net_core::identity::{IdentityPublicKey, SoftwareKey};
use mousse_net_core::mux::Frame;
use mousse_net_core::pairing::{
    attempt_sid, binding_transcript, AttemptId, CpaceExchangeFactory, HostAction, HostPairing,
    HostPairingError, InvitationId, InvitationKind, InvitationParams, InvitationStatus,
    JoinerAction, JoinerError, JoinerPairing, JoinerState, PairingCode, SessionExporters, Ticket,
    TicketSecret,
};
use mousse_net_core::{ConnectionId, ErrorCode, Millis, UnixTime};
use rand_core::{TryCryptoRng, TryRng};
use serde_json::{json, Value as J};
use sha2::{Digest, Sha256};

/// Wall time of every flow (host and joiner clocks agree).
const NOW: u64 = 1_790_000_000;
const HOST_SECRET: [u8; 32] = [0x11; 32];
const JOINER_SECRET: [u8; 32] = [0x22; 32];
const HOST_NAME: &str = "Desk";
const JOINER_NAME: &str = "Phone";
const ROLE: &str = "owner";
/// The host profile's id: the authorizing owner of every grant here.
const AUTHORIZING_OWNER: [u8; 16] = [0x51; 16];
const ROUTE: &str = "tcp://192.168.1.20:7443";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(v: &J) -> Vec<u8> {
    let text = v.as_str().expect("hex string");
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn s(v: &J) -> &str {
    v.as_str().expect("string")
}

fn u(v: &J) -> u64 {
    v.as_u64().expect("number")
}

fn code_by_name(name: &str) -> ErrorCode {
    (0..=u16::MAX)
        .map_while(ErrorCode::from_u16)
        .find(|c| c.name() == name)
        .unwrap_or_else(|| panic!("error code {name}"))
}

fn host_key() -> IdentityPublicKey {
    SoftwareKey::from_secret_bytes(&HOST_SECRET)
        .expect("key")
        .public_key()
}

fn joiner_key() -> IdentityPublicKey {
    SoftwareKey::from_secret_bytes(&JOINER_SECRET)
        .expect("key")
        .public_key()
}

fn exporters(v: &J) -> SessionExporters {
    SessionExporters {
        join: unhex(&v["join"]).try_into().expect("32 bytes"),
        pair: unhex(&v["pair"]).try_into().expect("32 bytes"),
    }
}

fn type_name(m: &ControlMessage) -> &'static str {
    match m {
        ControlMessage::Hello { .. } => "HELLO",
        ControlMessage::Authorized { .. } => "AUTHORIZED",
        ControlMessage::JoinProof { .. } => "JOIN_PROOF",
        ControlMessage::CodeExchange { .. } => "CODE_EXCHANGE",
        ControlMessage::CodeAbort { .. } => "CODE_ABORT",
        ControlMessage::Paired { .. } => "PAIRED",
    }
}

fn send(from: &str, conn: u64, m: &ControlMessage) -> J {
    let control = m.encode();
    let frame = Frame::Control {
        payload: control.clone(),
    }
    .encode();
    json!({ "send": { "from": from, "conn": conn, "type": type_name(m), "control": hex(&control), "frame": hex(&frame) } })
}

fn close(from: &str, conn: u64, code: ErrorCode) -> J {
    let frame = Frame::GoAway { code }.encode();
    json!({ "close": { "from": from, "conn": conn, "code": code.name(), "frame": hex(&frame) } })
}

fn joiner_state_name(state: JoinerState) -> String {
    match state {
        JoinerState::Connecting => "connecting".into(),
        JoinerState::AwaitingAdmission => "awaiting_admission".into(),
        JoinerState::AwaitingApproval => "awaiting_approval".into(),
        JoinerState::AwaitingCode => "awaiting_code".into(),
        JoinerState::Exchanging => "exchanging".into(),
        JoinerState::AwaitingPaired => "awaiting_paired".into(),
        JoinerState::Paired => "paired".into(),
        JoinerState::AlreadyPaired => "already_paired".into(),
        JoinerState::Failed(code) => format!("failed:{}", code.name()),
    }
}

fn joiner_error_name(e: JoinerError) -> &'static str {
    match e {
        JoinerError::WrongState => "wrong_state",
        JoinerError::AttemptsExhausted => "attempts_exhausted",
        JoinerError::Expired => "expired",
        JoinerError::InvalidName => "invalid_name",
    }
}

fn host_error_name(e: HostPairingError) -> &'static str {
    match e {
        HostPairingError::InvalidRoutes => "invalid_routes",
        HostPairingError::UnknownInvitation => "unknown_invitation",
        HostPairingError::NotOpen => "not_open",
        HostPairingError::WrongKind => "wrong_kind",
        HostPairingError::UnknownJoiner => "unknown_joiner",
    }
}

// ---------------------------------------------------------------------------
// Scripted randomness
// ---------------------------------------------------------------------------

/// Hands out the listed draws in order. A byte draw must match the requested
/// length; a `u32` draw answers `next_u32`.
struct Script {
    draws: VecDeque<J>,
}

impl Script {
    fn new(draws: &J) -> Self {
        Script {
            draws: draws
                .as_array()
                .map(|a| a.iter().cloned().collect())
                .unwrap_or_default(),
        }
    }

    fn next(&mut self) -> J {
        self.draws
            .pop_front()
            .expect("the flow drew more values than scripted")
    }
}

impl TryRng for Script {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let d = self.next();
        let value = d["u32"]
            .as_u64()
            .unwrap_or_else(|| panic!("expected a u32 draw, got {d}"));
        Ok(u32::try_from(value).expect("u32"))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        panic!("pairing draws no u64 values")
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let d = self.next();
        let bytes = unhex(&d["bytes"]);
        assert_eq!(bytes.len(), dst.len(), "draw {d}");
        dst.copy_from_slice(&bytes);
        Ok(())
    }
}

impl TryCryptoRng for Script {}

// ---------------------------------------------------------------------------
// The world: one host, any number of joiners
// ---------------------------------------------------------------------------

struct Joiner {
    pairing: Option<JoinerPairing<CpaceExchangeFactory>>,
    gate: CallerGate,
    rng: Script,
    conn: Option<u64>,
    exporters: Option<SessionExporters>,
}

struct World {
    host: HostPairing<CpaceExchangeFactory>,
    grants: GrantTable,
    host_rng: Script,
    gates: BTreeMap<u64, ConnectionGate>,
    host_exporters: BTreeMap<u64, SessionExporters>,
    joiners: BTreeMap<String, Joiner>,
    invitation: Option<InvitationId>,
}

impl World {
    fn new(draws: &J) -> Self {
        let joiners = draws["joiners"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(name, d)| {
                        (
                            name.clone(),
                            Joiner {
                                pairing: None,
                                gate: CallerGate::new(),
                                rng: Script::new(d),
                                conn: None,
                                exporters: None,
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        World {
            host: HostPairing::new(host_key(), HOST_NAME.into(), CpaceExchangeFactory),
            grants: GrantTable::new(),
            host_rng: Script::new(&draws["host"]),
            gates: BTreeMap::new(),
            host_exporters: BTreeMap::new(),
            joiners,
            invitation: None,
        }
    }

    fn joiner(&mut self, name: &str) -> &mut Joiner {
        self.joiners
            .get_mut(name)
            .unwrap_or_else(|| panic!("joiner {name} has no draws entry"))
    }

    fn joiner_on(&self, conn: u64) -> Option<String> {
        self.joiners
            .iter()
            .find(|(_, j)| j.conn == Some(conn))
            .map(|(n, _)| n.clone())
    }

    /// Run one event; return its outputs.
    fn apply(&mut self, step: &J) -> Vec<J> {
        let party = s(&step["party"]);
        let event = s(&step["event"]);
        let now = UnixTime(NOW);
        match (party, event) {
            ("host", "create") => {
                let kind = match u(&step["kind"]) {
                    1 => InvitationKind::InPerson,
                    2 => InvitationKind::SendLink,
                    k => panic!("kind {k}"),
                };
                let params = InvitationParams {
                    kind,
                    role: Role::new(ROLE).expect("role"),
                    authorizing_owner: OwnerRef::from_bytes(AUTHORIZING_OWNER),
                    routes: vec![ROUTE.into()],
                    grant_expires_at: None,
                };
                let created = self
                    .host
                    .create(params, now, &mut self.host_rng)
                    .expect("create");
                let t = &created.ticket;
                self.invitation = Some(t.invitation);
                vec![json!({ "ticket": {
                    "binary": hex(&t.encode()),
                    "fragment": created.fragment,
                    "hash": hex(&t.hash()),
                    "shown_code": self.host.code(&t.invitation).map(|c| c.as_str().to_owned()),
                } })]
            }
            ("host", "receive") => {
                let conn = u(&step["conn"]);
                let bytes = unhex(&step["control"]);
                let Ok(message) = ControlMessage::decode(&bytes) else {
                    return self.host_close(conn, ErrorCode::ProtocolError);
                };
                let gate = self.gates.get_mut(&conn).expect("connected");
                match gate.check(Traffic::of(&message)) {
                    Verdict::Ignore => return vec![json!({ "ignored": true })],
                    Verdict::Close(code) => return vec![close("host", conn, code)],
                    Verdict::Allow => {}
                }
                let peer = *gate.peer();
                let actions = match message {
                    ControlMessage::Hello {
                        major_version,
                        minor_version,
                    } => {
                        return match negotiate_version(
                            VersionSupport::LOCAL,
                            major_version,
                            minor_version,
                        ) {
                            Ok(v) => vec![json!({ "version": v })],
                            Err(code) => self.host_close(conn, code),
                        };
                    }
                    ControlMessage::JoinProof {
                        invitation,
                        mac,
                        name,
                    } => {
                        let exp = self.host_exporters[&conn];
                        self.host.on_join_proof(
                            ConnectionId(conn),
                            &peer,
                            &exp,
                            &invitation,
                            &mac,
                            &name,
                            &self.grants,
                            now,
                        )
                    }
                    ControlMessage::CodeExchange { attempt, payload } => {
                        self.host.on_code_exchange(
                            ConnectionId(conn),
                            attempt,
                            &payload,
                            &mut self.grants,
                            now,
                            &mut self.host_rng,
                        )
                    }
                    ControlMessage::CodeAbort { attempt, .. } => {
                        self.host.on_code_abort(ConnectionId(conn), attempt)
                    }
                    other => panic!("gate let {other:?} through"),
                };
                self.host_actions(actions)
            }
            ("host", "approve") => {
                let conn = u(&step["conn"]);
                let invitation = self.invitation.expect("created");
                match self
                    .host
                    .approve(&invitation, ConnectionId(conn), &mut self.grants, now)
                {
                    Ok(actions) => self.host_actions(actions),
                    Err(e) => vec![json!({ "error": host_error_name(e) })],
                }
            }
            (name, "start") => {
                let ticket = Ticket::decode(&unhex(&step["ticket"])).expect("ticket");
                let pairing = JoinerPairing::new(
                    ticket,
                    joiner_key(),
                    JOINER_NAME.into(),
                    CpaceExchangeFactory,
                    now,
                );
                match pairing {
                    Ok(p) => {
                        self.joiner(name).pairing = Some(p);
                        Vec::new()
                    }
                    Err(e) => vec![json!({ "error": joiner_error_name(e) })],
                }
            }
            (name, "connect") => {
                let conn = u(&step["conn"]);
                let exp = exporters(&step["exporters"]);
                let mut out = vec![send(name, conn, &ControlMessage::hello())];
                if step["host"] != false {
                    let host_exp = step.get("host_exporters").map(exporters).unwrap_or(exp);
                    let gate = ConnectionGate::open(
                        ConnectionId(conn),
                        joiner_key(),
                        &mut self.grants,
                        now,
                        Millis(0),
                    );
                    self.gates.insert(conn, gate);
                    self.host_exporters.insert(conn, host_exp);
                    out.push(send("host", conn, &ControlMessage::hello()));
                }
                let j = self.joiner(name);
                j.conn = Some(conn);
                j.exporters = Some(exp);
                j.gate = CallerGate::new();
                let proof = j.pairing.as_mut().expect("started").on_connected(exp, now);
                match proof {
                    Ok(m) => out.push(send(name, conn, &m)),
                    Err(e) => out.push(json!({ "error": joiner_error_name(e) })),
                }
                out
            }
            (name, "receive") => {
                let bytes = unhex(&step["control"]);
                let j = self.joiner(name);
                let conn = j.conn.expect("connected");
                let Ok(message) = ControlMessage::decode(&bytes) else {
                    j.gate.close(ErrorCode::ProtocolError);
                    return vec![close(name, conn, ErrorCode::ProtocolError)];
                };
                match j.gate.check(CallerTraffic::of(&message)) {
                    Verdict::Ignore => return vec![json!({ "ignored": true })],
                    Verdict::Close(code) => return vec![close(name, conn, code)],
                    Verdict::Allow => {}
                }
                let pairing = j.pairing.as_mut().expect("started");
                let actions = match message {
                    ControlMessage::Hello {
                        major_version,
                        minor_version,
                    } => {
                        return match negotiate_version(
                            VersionSupport::LOCAL,
                            major_version,
                            minor_version,
                        ) {
                            Ok(v) => vec![json!({ "version": v })],
                            Err(code) => {
                                j.gate.close(code);
                                vec![close(name, conn, code)]
                            }
                        };
                    }
                    ControlMessage::Authorized { state } => pairing.on_authorized(state),
                    ControlMessage::CodeExchange { attempt, payload } => {
                        pairing.on_code_exchange(attempt, &payload)
                    }
                    ControlMessage::CodeAbort { attempt, .. } => pairing.on_code_abort(attempt),
                    ControlMessage::Paired { host_name, role } => {
                        pairing.on_paired(host_name, role)
                    }
                    other => panic!("gate let {other:?} through"),
                };
                self.joiner_actions(name, actions)
            }
            (name, "goaway") => {
                let code = code_by_name(s(&step["code"]));
                let j = self.joiner(name);
                j.gate.close(code);
                let actions = j.pairing.as_mut().expect("started").on_closed(Some(code));
                self.joiner_actions(name, actions)
            }
            (name, "submit_code") => {
                let code = PairingCode::parse(s(&step["code"])).expect("six digits");
                let j = self.joiner(name);
                let pairing = j.pairing.as_mut().expect("started");
                match pairing.submit_code(&code, &mut j.rng) {
                    Ok(actions) => {
                        let mut out = self.attempt_info(name, &actions);
                        out.extend(self.joiner_actions(name, actions));
                        out
                    }
                    Err(e) => vec![json!({ "error": joiner_error_name(e) })],
                }
            }
            (party, event) => panic!("unknown event {party}/{event}"),
        }
    }

    fn host_close(&mut self, conn: u64, code: ErrorCode) -> Vec<J> {
        if let Some(gate) = self.gates.get_mut(&conn) {
            gate.close(code);
        }
        vec![close("host", conn, code)]
    }

    fn host_actions(&mut self, actions: Vec<HostAction>) -> Vec<J> {
        let mut out = Vec::new();
        for a in actions {
            match a {
                HostAction::Send { conn, message } => out.push(send("host", conn.0, &message)),
                HostAction::Close { conn, code } => out.extend(self.host_close(conn.0, code)),
                HostAction::AdmittedJoinOnly { conn, invitation } => {
                    if let Some(gate) = self.gates.get_mut(&conn.0) {
                        gate.admit_join_only(invitation);
                    }
                    out.push(json!({ "admitted_join_only": conn.0 }));
                }
                HostAction::AskApproval { conn, name, .. } => {
                    out.push(json!({ "ask_approval": { "conn": conn.0, "name": name } }));
                }
                HostAction::ShowCode { code, .. } => {
                    out.push(json!({ "show_code": code.as_str() }));
                }
                HostAction::Enrolled { conn, grant, .. } => {
                    if let Some(gate) = self.gates.get_mut(&conn.0) {
                        gate.promote(grant);
                    }
                    out.push(json!({ "enrolled": { "conn": conn.0 } }));
                }
                HostAction::InvitationEnded { reason, .. } => {
                    out.push(json!({ "invitation_ended": reason.name() }));
                }
                HostAction::Grant(e) => out.push(json!({ "grant_event": format!("{e:?}") })),
            }
        }
        out
    }

    fn joiner_actions(&mut self, name: &str, actions: Vec<JoinerAction>) -> Vec<J> {
        let j = self.joiner(name);
        let conn = j.conn.unwrap_or(0);
        let mut out = Vec::new();
        for a in actions {
            match a {
                JoinerAction::Send(m) => out.push(send(name, conn, &m)),
                JoinerAction::Paired(p) => {
                    j.gate.promote();
                    out.push(json!({ "paired": {
                        "host_identity": hex(p.identity.as_bytes()),
                        "host_name": p.name,
                        "role": p.role.as_str(),
                    } }));
                }
                JoinerAction::AlreadyPaired => out.push(json!({ "already_paired": true })),
                JoinerAction::CodeRejected { attempts_left } => {
                    out.push(json!({ "code_rejected": { "attempts_left": attempts_left } }));
                }
                JoinerAction::Failed(code) => out.push(json!({ "failed": code.name() })),
            }
        }
        out
    }

    /// The values a new attempt runs CPace with, derived from public inputs.
    fn attempt_info(&mut self, name: &str, actions: &[JoinerAction]) -> Vec<J> {
        let Some(attempt) = actions.iter().find_map(|a| match a {
            JoinerAction::Send(ControlMessage::CodeExchange { attempt, .. }) => Some(*attempt),
            _ => None,
        }) else {
            return Vec::new();
        };
        let j = self.joiner(name);
        let exp = j.exporters.expect("connected");
        let ticket = j.pairing.as_ref().expect("started").ticket().clone();
        let ci = binding_transcript(
            &ticket.hash(),
            ticket.kind,
            ticket.version,
            &ticket.host_identity,
            &joiner_key(),
            &exp.pair,
        );
        vec![json!({ "attempt": {
            "id": hex(&attempt.0),
            "ci": hex(ci.as_bytes()),
            "sid": hex(&attempt_sid(&attempt, &exp.pair)),
        } })]
    }

    /// Where each output goes next, for flows where both ends are real.
    fn deliveries(&self, out: &[J]) -> Vec<J> {
        let mut next = Vec::new();
        for o in out {
            if let Some(m) = o.get("send") {
                let conn = u(&m["conn"]);
                if m["from"] == "host" {
                    if let Some(name) = self.joiner_on(conn) {
                        next.push(
                            json!({ "party": name, "event": "receive", "control": m["control"] }),
                        );
                    }
                } else if self.gates.contains_key(&conn) {
                    next.push(json!({ "party": "host", "event": "receive", "conn": conn, "control": m["control"] }));
                }
            } else if let Some(c) = o.get("close") {
                if c["from"] == "host" {
                    if let Some(name) = self.joiner_on(u(&c["conn"])) {
                        next.push(json!({ "party": name, "event": "goaway", "code": c["code"] }));
                    }
                }
            }
        }
        next
    }

    fn summary(&self) -> J {
        let invitation = self.invitation.expect("created");
        let status = match self.host.status(&invitation).expect("status") {
            InvitationStatus::Open => "open".to_owned(),
            InvitationStatus::Consumed { .. } => "consumed".to_owned(),
            InvitationStatus::Ended(code) => format!("ended:{}", code.name()),
        };
        let grants: Vec<J> = self
            .grants
            .grants()
            .map(|g| {
                json!({
                    "identity": hex(g.identity.as_bytes()),
                    "name": g.name,
                    "role": g.role.as_str(),
                    "authorizing_owner": hex(g.authorizing_owner.as_bytes()),
                    "granted_at": g.granted_at.secs(),
                    "expires_at": g.expires_at.map(|t| t.secs()),
                    "bound_connections": self.gates.keys().filter(|c| self.grants.binding(ConnectionId(**c)) == Some(g.id)).collect::<Vec<_>>(),
                })
            })
            .collect();
        let joiners: serde_json::Map<String, J> = self
            .joiners
            .iter()
            .filter_map(|(n, j)| {
                let p = j.pairing.as_ref()?;
                Some((
                    n.clone(),
                    json!({
                        "state": joiner_state_name(p.state()),
                        "attempts_left": p.attempts_left(),
                        "live": j.gate.is_live(),
                    }),
                ))
            })
            .collect();
        json!({
            "host": {
                "status": status,
                "attempts_left": self.host.attempts_left(&invitation),
                "shown_code": self.host.code(&invitation).map(|c| c.as_str().to_owned()),
            },
            "grants": grants,
            "joiners": joiners,
        })
    }

    fn unused_draws(&self) -> usize {
        self.host_rng.draws.len()
            + self
                .joiners
                .values()
                .map(|j| j.rng.draws.len())
                .sum::<usize>()
    }
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// Fixed-looking random bytes for a draw: SHA-256 of a label, cut to `n`.
fn bytes_draw(what: &str, label: &str, n: usize) -> J {
    let digest = Sha256::digest(format!("mousse-pairing-e2e/{label}").as_bytes());
    let mut out = digest.to_vec();
    while out.len() < n {
        out.extend_from_slice(&Sha256::digest(&out));
    }
    out.truncate(n);
    json!({ "use": what, "bytes": hex(&out) })
}

fn u32_draw(what: &str, value: u32) -> J {
    json!({ "use": what, "u32": value })
}

fn exporter_pair(label: &str) -> J {
    let d = |which: &str| {
        hex(&Sha256::digest(
            format!("mousse-pairing-e2e/{label}/{which}").as_bytes(),
        ))
    };
    json!({ "join": d("join"), "pair": d("pair") })
}

fn ticket_draws(flow: &str) -> Vec<J> {
    vec![
        bytes_draw("invitation_id", &format!("{flow}/invitation"), 16),
        bytes_draw("ticket_secret", &format!("{flow}/secret"), 16),
    ]
}

fn attempt_draws(flow: &str, n: usize) -> Vec<J> {
    vec![
        bytes_draw("attempt_id", &format!("{flow}/attempt{n}"), 16),
        bytes_draw("cpace_scalar_ya", &format!("{flow}/ya{n}"), 32),
    ]
}

struct Recorder {
    world: World,
    draws: J,
    steps: Vec<J>,
    pump: bool,
}

impl Recorder {
    fn new(draws: J) -> Self {
        Recorder {
            world: World::new(&draws),
            draws,
            steps: Vec::new(),
            pump: true,
        }
    }

    /// Run an event, record it, then (unless pumping is off) deliver every
    /// message and close it causes until both ends are quiet.
    fn event(&mut self, step: J) -> Vec<J> {
        let mut queue = VecDeque::from([step]);
        let mut first = None;
        while let Some(step) = queue.pop_front() {
            let out = self.world.apply(&step);
            if self.pump {
                queue.extend(self.world.deliveries(&out));
            }
            let mut recorded = step;
            recorded["out"] = J::Array(out.clone());
            self.steps.push(recorded);
            first.get_or_insert(out);
        }
        first.unwrap_or_default()
    }

    fn ticket(&self) -> J {
        self.steps[0]["out"][0]["ticket"]["binary"].clone()
    }

    fn finish(self, name: &str, description: &str, kind: u64) -> J {
        assert_eq!(self.world.unused_draws(), 0, "{name}: unused draws");
        json!({
            "name": name,
            "description": description,
            "kind": kind,
            "draws": self.draws,
            "steps": self.steps,
            "end": self.world.summary(),
        })
    }
}

fn create(kind: u64) -> J {
    json!({ "party": "host", "event": "create", "kind": kind })
}

fn start(ticket: &J) -> J {
    json!({ "party": "a", "event": "start", "ticket": ticket })
}

fn connect(name: &str, conn: u64, exporters: J) -> J {
    json!({ "party": name, "event": "connect", "conn": conn, "exporters": exporters })
}

fn submit(code: &str) -> J {
    json!({ "party": "a", "event": "submit_code", "code": code })
}

fn in_person() -> J {
    let mut r = Recorder::new(json!({ "host": ticket_draws("in_person"), "joiners": { "a": [] } }));
    r.event(create(1));
    let t = r.ticket();
    r.event(start(&t));
    r.event(connect("a", 1, exporter_pair("in_person/conn1")));
    r.event(json!({ "party": "host", "event": "approve", "conn": 1 }));
    r.finish(
        "in_person",
        "In-person pairing: ticket, HELLO both ways, join proof, AUTHORIZED join-only, the owner approves, PAIRED, grant.",
        1,
    )
}

fn send_link() -> J {
    let mut host = ticket_draws("send_link");
    // The first code draw is above the rejection bound and is drawn again.
    host.push(u32_draw("code", 4_294_967_295));
    host.push(u32_draw("code", 4_293_123_456));
    host.push(u32_draw("next_code", 654_321));
    host.push(bytes_draw("cpace_scalar_yb", "send_link/yb1", 32));
    let mut r =
        Recorder::new(json!({ "host": host, "joiners": { "a": attempt_draws("send_link", 1) } }));
    r.event(create(2));
    let t = r.ticket();
    r.event(start(&t));
    r.event(connect("a", 1, exporter_pair("send_link/conn1")));
    r.event(submit("123456"));
    r.finish(
        "send_link",
        "Send-link pairing: ticket, HELLO both ways, join proof, AUTHORIZED join-only, the code shown, one CPace attempt (msg_a, msg_b with the host's confirmation, msg_c with the joiner's), PAIRED, grant. The first code draw is rejected and drawn again.",
        2,
    )
}

fn wrong_code_three_times() -> J {
    let flow = "wrong_code";
    let mut host = ticket_draws(flow);
    host.push(u32_draw("code", 271_828));
    host.push(u32_draw("next_code", 314_159));
    host.push(bytes_draw("cpace_scalar_yb", "wrong_code/yb1", 32));
    host.push(u32_draw("next_code", 161_803));
    host.push(bytes_draw("cpace_scalar_yb", "wrong_code/yb2", 32));
    host.push(bytes_draw("cpace_scalar_yb", "wrong_code/yb3", 32));
    let joiner: Vec<J> = (1..=3).flat_map(|n| attempt_draws(flow, n)).collect();
    let mut r = Recorder::new(json!({ "host": host, "joiners": { "a": joiner } }));
    r.event(create(2));
    let t = r.ticket();
    r.event(start(&t));
    r.event(connect("a", 1, exporter_pair("wrong_code/conn1")));
    for _ in 0..3 {
        r.event(submit("000000"));
    }
    r.event(submit("161803"));
    r.finish(
        "wrong_code_three_times",
        "Three wrong codes on one connection. Each attempt fails the host's confirmation on the joiner, which aborts it. A fresh code is shown at the start of attempts 1 and 2, none at attempt 3. After the third the invitation ends and the host closes with attempts_exhausted; the joiner's flow is over and refuses a fourth code.",
        2,
    )
}

fn joiner_cap_against_fake_host() -> J {
    let flow = "joiner_cap";
    let mut host = ticket_draws(flow);
    host.push(u32_draw("code", 123_456));
    let joiner: Vec<J> = (1..=3).flat_map(|n| attempt_draws(flow, n)).collect();
    let mut r = Recorder::new(json!({ "host": host, "joiners": { "a": joiner } }));
    r.event(create(2));
    let t = r.ticket();
    r.event(start(&t));
    // The far end is not the real host: it answers from a script.
    r.pump = false;
    let mut c = connect("a", 1, exporter_pair("joiner_cap/conn1"));
    c["host"] = json!(false);
    r.event(c);
    let from_fake = |m: ControlMessage| json!({ "party": "a", "event": "receive", "control": hex(&m.encode()) });
    r.event(from_fake(ControlMessage::hello()));
    r.event(from_fake(ControlMessage::Authorized {
        state: AuthorizedState::JoinOnly,
    }));
    for _ in 0..3 {
        let out = r.event(submit("123456"));
        let attempt = out
            .iter()
            .find_map(|o| o.get("attempt"))
            .map(|a| AttemptId(unhex(&a["id"]).try_into().expect("16 bytes")))
            .expect("attempt started");
        r.event(from_fake(ControlMessage::CodeAbort {
            attempt,
            code: ErrorCode::PairingFailed,
        }));
    }
    r.event(submit("123456"));
    r.finish(
        "joiner_cap_against_fake_host",
        "The joiner talks to a far end that aborts every attempt. The joiner stops after its own 3 attempts and refuses a fourth code; the real host's invitation is untouched.",
        2,
    )
}

fn tampered_tickets() -> J {
    let flow = "tampered";
    let mut host = ticket_draws(flow);
    host.push(u32_draw("code", 777_777));
    let mut r = Recorder::new(json!({ "host": host, "joiners": { "a": [], "b": [] } }));
    r.event(create(2));
    let real = Ticket::decode(&unhex(&r.ticket())).expect("ticket");
    let mut wrong_secret = real.clone();
    let mut secret = *real.secret.expose();
    secret[0] ^= 0x01;
    wrong_secret.secret = TicketSecret::from_bytes(secret);
    let mut wrong_invitation = real.clone();
    wrong_invitation.invitation.0[15] ^= 0x01;
    r.event(json!({ "party": "a", "event": "start", "ticket": hex(&wrong_secret.encode()) }));
    r.event(json!({ "party": "b", "event": "start", "ticket": hex(&wrong_invitation.encode()) }));
    r.event(connect("a", 1, exporter_pair("tampered/conn1")));
    r.event(connect("b", 2, exporter_pair("tampered/conn2")));
    r.finish(
        "tampered_tickets",
        "Joiner a holds the ticket with one bit of the secret flipped; joiner b with one bit of the invitation id flipped. The host closes both with invitation_invalid and the invitation stays open.",
        2,
    )
}

fn proof_on_another_session() -> J {
    let flow = "relayed_proof";
    let mut host = ticket_draws(flow);
    host.push(u32_draw("code", 424_242));
    let mut r = Recorder::new(json!({ "host": host, "joiners": { "a": [] } }));
    r.event(create(2));
    let t = r.ticket();
    r.event(start(&t));
    let mut c = connect("a", 1, exporter_pair("relayed_proof/joiner_session"));
    c["host_exporters"] = exporter_pair("relayed_proof/host_session");
    r.event(c);
    r.finish(
        "proof_on_another_session",
        "The joiner's TLS session is not the one the host sees (a relaying middle device): the join proof was made with another exporter. The host closes with invitation_invalid and the invitation stays open.",
        2,
    )
}

fn document() -> J {
    json!({
        "description": "End-to-end pairing (spec wire.md, sections 8, 10 and 11, and cpace.md). Each flow lists scripted random draws per party, then events in order with every output. Replaying the events with the same draws must give the same outputs byte for byte.",
        "conventions": {
            "time": NOW,
            "host": { "identity_secret": hex(&HOST_SECRET), "identity": hex(host_key().as_bytes()), "name": HOST_NAME },
            "joiner": { "identity_secret": hex(&JOINER_SECRET), "identity": hex(joiner_key().as_bytes()), "name": JOINER_NAME },
            "invitation": { "role": ROLE, "authorizing_owner": hex(&AUTHORIZING_OWNER), "routes": [ROUTE], "grant_expires_at": null },
            "draws": "Each party takes its draws in order. A `bytes` draw fills a request of exactly that length; a `u32` draw answers a request for a 32-bit integer. Host: invitation id (16), ticket secret (16), for send link the code (u32, drawn again while at least 4294000000); then for each new attempt the next code (u32, only while attempts are left after the debit) and the CPace scalar yb (32). Joiner: for each attempt the attempt id (16) and the CPace scalar ya (32). A CPace scalar is the 32 bytes with the top four bits of the last byte cleared, read little-endian.",
            "exporters": "Stand-in TLS exporter values per connection. Unless `host_exporters` is given, both ends see the same session.",
            "events": "host/create: create an invitation of `kind`. <joiner>/start: the joiner opens `ticket`. <joiner>/connect: a new TLS connection `conn`; both ends send HELLO, the host runs step 2 (no grant: await the join proof) and the joiner sends JOIN_PROOF; with `host: false` the far end is scripted. host/receive and <joiner>/receive: a CONTROL message arrives (checked by that end's gate first). <joiner>/goaway: the host's GOAWAY arrives. <joiner>/submit_code: the owner types `code`. host/approve: the host owner approves the device on `conn`.",
            "outputs": "send: a control message with its CONTROL frame. close: GOAWAY with its frame. attempt: the CPace inputs of a new attempt (CI is the binding transcript; sid as in wire.md). version: the minor version agreed from a HELLO. Others name host or joiner events: show_code, ask_approval, admitted_join_only, enrolled, invitation_ended, paired, code_rejected, failed, error, ignored.",
        },
        "flows": [
            in_person(),
            send_link(),
            wrong_code_three_times(),
            joiner_cap_against_fake_host(),
            tampered_tickets(),
            proof_on_another_session(),
        ],
    })
}

/// Replay a flow from the file: its own events and draws only.
fn replay(flow: &J) {
    let name = s(&flow["name"]);
    let mut world = World::new(&flow["draws"]);
    for (i, step) in flow["steps"].as_array().expect("steps").iter().enumerate() {
        let out = world.apply(step);
        assert_eq!(J::Array(out), step["out"], "{name} step {i}");
    }
    assert_eq!(world.summary(), flow["end"], "{name} end state");
    assert_eq!(world.unused_draws(), 0, "{name}: unused draws");
}

#[test]
fn pairing_e2e_vectors() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/pairing-e2e.json");
    let text = serde_json::to_string_pretty(&document()).expect("json") + "\n";
    if std::env::var_os("MOUSSE_NET_WRITE_VECTORS").is_some() {
        std::fs::write(&path, &text).expect("write");
    }
    let on_disk = std::fs::read_to_string(&path).expect("read pairing-e2e.json");
    assert!(
        on_disk == text,
        "pairing-e2e.json differs from the scenarios; rerun with MOUSSE_NET_WRITE_VECTORS=1 and review the diff"
    );
    let doc: J = serde_json::from_str(&on_disk).expect("json");
    for flow in doc["flows"].as_array().expect("flows") {
        replay(flow);
    }
}

#[test]
fn replay_catches_a_changed_byte() {
    let mut flow = send_link();
    // Flip one bit of msg_b as the joiner receives it: the joiner must
    // reject the host's confirmation, so the recorded outputs no longer hold.
    let step = flow["steps"]
        .as_array_mut()
        .expect("steps")
        .iter_mut()
        .find(|st| {
            st["party"] == "a"
                && st["out"].to_string().contains("CODE_EXCHANGE")
                && st["event"] == "receive"
        })
        .expect("the joiner receives msg_b");
    let mut bytes = unhex(&step["control"]);
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    step["control"] = json!(hex(&bytes));
    let result = std::panic::catch_unwind(|| replay(&flow));
    assert!(result.is_err(), "a tampered msg_b replayed cleanly");
}
