//! A simulated calling device: a joiner while pairing, then a paired device
//! with a pinned peer session, or an intruder with no grant. This module is
//! its I/O layer; decisions come from the core state machines.

use std::collections::{BTreeMap, BTreeSet};

use mousse_net_core::authz::{CallerGate, CallerTraffic, Verdict};
use mousse_net_core::control::{
    negotiate_version, AuthorizedState, ControlMessage, VersionSupport,
};
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::{MuxEvent, PriorityClass, StreamId};
use mousse_net_core::pairing::{
    CodeExchangeFactory, ExchangeRole, JoinerAction, JoinerPairing, JoinerState, PairedHost,
    PairingCode, Ticket,
};
use mousse_net_core::session::{PeerSession, SessionEvent, RENEW_LEAD_SECS};
use mousse_net_core::session_cert::SessionCertificate;
use mousse_net_core::{ConnectionId, ErrorCode};

use crate::certs;
use crate::check::Invariant;
use crate::exchange::CountingFactory;
use crate::sim::{flush_endpoint, AuthInfo, DevId, Endpoint, Side, Sim};
use crate::world::Script;
use crate::Bug;

/// The dial failure reason when step 1 finds another identity than the pin.
pub(crate) const WRONG_ENDPOINT: &str = "another endpoint answered (pin mismatch)";

pub(crate) enum Mode {
    /// Not started yet.
    Idle,
    Joining(Box<JoinerPairing<CountingFactory>>),
    Paired(PeerSession),
    Intruder,
    Done,
}

/// How a code-entry flow ended, for the agreement check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Pending,
    Paired(PairedHost),
    AlreadyPaired,
    Failed(ErrorCode),
}

pub(crate) struct CallerConn {
    pub ep: Endpoint,
    /// Deadline for connections outside the paired session (joining,
    /// intruding).
    own_session: Option<PeerSession>,
    /// The caller-side gate: what the host may send on this connection.
    gate: CallerGate,
    authorized: Option<AuthorizedState>,
    terminal: Option<StreamId>,
}

/// The person typing codes into the joiner.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Typist {
    /// Wrong codes to type before the right one.
    pub wrong_first: u8,
    /// Delay before typing, ms.
    pub delay: (u64, u64),
    /// Chance (per mille) of an impatient byte-identical resend.
    pub resend_permille: u32,
    /// Chance (per mille) of dropping the connection mid-attempt.
    pub abort_permille: u32,
    /// Chance (per mille) of switching route after a rejected code.
    pub switch_permille: u32,
}

pub(crate) struct CallerDev {
    pub id: DevId,
    pub label: &'static str,
    key_label: &'static str,
    pub identity: IdentityPublicKey,
    pub cert: SessionCertificate,
    pub cert_lifetime: u64,
    pub renew_lead: u64,
    pub mode: Mode,
    /// The identity this device must only ever talk to.
    pub expected_host: Option<IdentityPublicKey>,
    /// The device that is really that host (for checks).
    pub host_dev: DevId,
    pub ticket: Option<Ticket>,
    pub routes: Vec<usize>,
    pub route_pref: usize,
    pub conns: BTreeMap<ConnectionId, CallerConn>,
    dialing: BTreeSet<ConnectionId>,
    /// The connection the pairing flow runs on.
    active: Option<ConnectionId>,
    pub up: bool,
    pub flow: u64,
    instance: u64,
    pub typist: Typist,
    typing_scheduled: bool,
    pub outcome: Outcome,
    /// A paired device just finished pairing; the world checks the host.
    pub just_paired: Option<PairedHost>,
    /// Open streams right after `HELLO`, without waiting for `AUTHORIZED`.
    pub eager_streams: bool,
    /// Ms between terminal keystrokes (0 = no typing).
    pub keystroke_ms: (u64, u64),
    next_keystroke: Option<u64>,
    reconnect_at: Option<u64>,
    /// Retry a failed renewal or path-switch dial while the current path
    /// still works.
    retry_dial_at: Option<u64>,
    last_renew_dial: Option<u64>,
    /// Chance (per mille) that a reconnect re-sends the last code-exchange
    /// message of the previous connection.
    pub dup_permille: u32,
    last_exchange_msg: Option<ControlMessage>,
    not_authorized: u32,
    /// Terminal bytes the host echoed back.
    pub echoed: u64,
}

impl CallerDev {
    pub(crate) fn new(sim: &mut Sim, id: DevId, label: &'static str, lifetime: u64) -> Self {
        let key_label = sim.key_labels[id];
        Self {
            id,
            label,
            key_label,
            identity: certs::identity_key(key_label).public_key(),
            cert: certs::certificate(key_label, certs::grid(sim.wall(id)), lifetime),
            cert_lifetime: lifetime,
            renew_lead: RENEW_LEAD_SECS,
            mode: Mode::Idle,
            expected_host: None,
            host_dev: 0,
            ticket: None,
            routes: Vec::new(),
            route_pref: 0,
            conns: BTreeMap::new(),
            dialing: BTreeSet::new(),
            active: None,
            up: true,
            flow: 0,
            instance: 0,
            typist: Typist {
                wrong_first: 0,
                delay: (2_000, 20_000),
                resend_permille: 0,
                abort_permille: 0,
                switch_permille: 0,
            },
            typing_scheduled: false,
            outcome: Outcome::Pending,
            just_paired: None,
            eager_streams: false,
            keystroke_ms: (0, 0),
            next_keystroke: None,
            reconnect_at: None,
            retry_dial_at: None,
            last_renew_dial: None,
            dup_permille: 0,
            last_exchange_msg: None,
            not_authorized: 0,
            echoed: 0,
        }
    }

    pub(crate) fn is_settled(&self) -> bool {
        match self.mode {
            Mode::Done => true,
            Mode::Paired(_) => self.echoed > 0 || self.keystroke_ms.0 > 0,
            _ => false,
        }
    }

    fn new_flow_machine(&mut self, sim: &mut Sim) -> Option<JoinerPairing<CountingFactory>> {
        let ticket = self.ticket.clone()?;
        self.instance += 1;
        let factory = CountingFactory::new(self.id, self.instance, self.flow, sim.work.clone());
        match JoinerPairing::new(
            ticket,
            self.identity,
            self.label.to_owned(),
            factory,
            sim.wall(self.id),
        ) {
            Ok(flow) => Some(flow),
            Err(e) => {
                sim.say(self.id, format_args!("cannot start pairing: {e}"));
                self.outcome = Outcome::Failed(ErrorCode::InvitationInvalid);
                None
            }
        }
    }

    /// The owner opens the link (or scans the QR): a new code-entry flow.
    pub(crate) fn start_joining(&mut self, sim: &mut Sim) {
        if !self.up || matches!(self.mode, Mode::Paired(_)) {
            return;
        }
        self.flow += 1;
        self.typing_scheduled = false;
        match self.new_flow_machine(sim) {
            Some(flow) => {
                sim.say(
                    self.id,
                    format_args!("opens the pairing link (flow {})", self.flow),
                );
                self.mode = Mode::Joining(Box::new(flow));
                self.dial(sim);
            }
            None => self.mode = Mode::Done,
        }
    }

    /// A device that was paired before the run.
    pub(crate) fn start_paired(&mut self, sim: &mut Sim, pin: IdentityPublicKey) {
        sim.say(
            self.id,
            format_args!("starts, paired with {}", sim.who(&pin)),
        );
        self.mode = Mode::Paired(PeerSession::new(pin));
        self.dial(sim);
    }

    pub(crate) fn start_intruder(&mut self, sim: &mut Sim) {
        sim.say(
            self.id,
            format_args!("tries to reach the host without a grant"),
        );
        self.mode = Mode::Intruder;
        self.dial(sim);
    }

    /// The certificate to present (renewed first if due).
    pub(crate) fn current_cert(&mut self, sim: &mut Sim) -> SessionCertificate {
        let wall = sim.wall(self.id);
        let start = certs::grid(wall);
        if wall.plus(self.renew_lead) >= self.cert.window().not_after()
            && start > self.cert.window().not_before()
        {
            self.cert = certs::certificate(self.key_label, start, self.cert_lifetime);
            sim.say(
                self.id,
                format_args!(
                    "renews its certificate: {}..{}",
                    start.secs(),
                    self.cert.window().not_after().secs()
                ),
            );
        }
        self.cert.clone()
    }

    /// The pin handed to step 1 for this dial.
    pub(crate) fn pin_for_dial(&self, sim: &Sim) -> Option<IdentityPublicKey> {
        match &self.mode {
            Mode::Joining(flow) => Some(*flow.expected_host()),
            Mode::Paired(_) if sim.bug(Bug::NoPinOnReconnect) => None,
            Mode::Paired(s) => Some(*s.pin()),
            Mode::Intruder => self.expected_host,
            _ => None,
        }
    }

    pub(crate) fn wants(&self, conn: ConnectionId) -> bool {
        self.up && self.dialing.contains(&conn)
    }

    fn dial(&mut self, sim: &mut Sim) {
        if self.routes.is_empty() {
            return;
        }
        let route = self.routes[self.route_pref % self.routes.len()];
        let conn = sim.dial(self.id, route);
        let name = sim.routes[route].name;
        sim.say(self.id, format_args!("dials conn {} over {name}", conn.0));
        self.dialing.insert(conn);
        let events = match &mut self.mode {
            Mode::Paired(session) => session.begin_path(conn),
            _ => Vec::new(),
        };
        self.on_session_events(sim, events);
    }

    fn schedule_reconnect(&mut self, sim: &mut Sim) {
        if self.reconnect_at.is_none() && self.up {
            let delay = sim.range(500, 8_000);
            self.reconnect_at = Some(sim.now + delay);
        }
    }

    pub(crate) fn switch_route(&mut self) {
        self.route_pref = (self.route_pref + 1) % self.routes.len().max(1);
    }

    // ---- connection events --------------------------------------------------

    pub(crate) fn on_dial_failed(&mut self, sim: &mut Sim, conn: ConnectionId, why: &str) {
        if !self.dialing.remove(&conn) {
            return;
        }
        sim.say(self.id, format_args!("conn {} failed: {why}", conn.0));
        match &mut self.mode {
            Mode::Paired(session) => {
                session.on_path_closed(conn);
                let has_current = session.current().is_some();
                // Another endpoint answered: try the next candidate, with no
                // warning and no re-pin.
                let wrong_endpoint = why == WRONG_ENDPOINT;
                if wrong_endpoint || (self.routes.len() > 1 && sim.chance(500)) {
                    self.switch_route();
                }
                if !has_current {
                    self.schedule_reconnect(sim);
                } else if self.retry_dial_at.is_none() {
                    // A renewal or path-switch dial failed; the session will
                    // not ask again, so retry later.
                    let delay = if wrong_endpoint {
                        sim.range(100, 1_000)
                    } else {
                        sim.range(5_000, 30_000)
                    };
                    self.retry_dial_at = Some(sim.now + delay);
                }
            }
            Mode::Joining(_) => {
                if sim.chance(500) {
                    self.switch_route();
                }
                self.schedule_reconnect(sim);
            }
            Mode::Intruder => self.mode = Mode::Done,
            _ => {}
        }
    }

    pub(crate) fn on_connected(&mut self, sim: &mut Sim, conn: ConnectionId, auth: AuthInfo) {
        self.dialing.remove(&conn);
        let wall = sim.wall(self.id);
        let peer = auth.peer.identity;
        if Some(peer) != self.expected_host {
            sim.fail(
                Invariant::PinMatch,
                format!(
                    "{} authenticated {} on conn {}, but its pin is {}",
                    self.label,
                    sim.who(&peer),
                    conn.0,
                    self.expected_host.map_or("nobody", |p| sim.who(&p))
                ),
            );
        }
        let mut ep = Endpoint::new(conn, Side::Client, auth, sim.mono());
        ep.send(&ControlMessage::hello());
        let mut own_session = PeerSession::new(peer);
        own_session.begin_path(conn);
        let own_ok = own_session
            .on_authenticated(conn, &ep.auth.peer, ep.auth.local_window, wall)
            .is_ok();
        let _ = own_session.on_reopened(conn);
        let mut cc = CallerConn {
            ep,
            own_session: Some(own_session),
            gate: CallerGate::new(),
            authorized: None,
            terminal: None,
        };
        sim.say(
            self.id,
            format_args!("conn {} is up to {}", conn.0, sim.who(&peer)),
        );
        let mut close = if own_ok {
            None
        } else {
            Some(ErrorCode::CertExpired)
        };
        match &mut self.mode {
            Mode::Joining(flow) => match flow.on_connected(cc.ep.auth.exporters, wall) {
                Ok(proof) => {
                    sim.say(self.id, format_args!("conn {}: sends {proof:?}", conn.0));
                    cc.ep.send(&proof);
                    self.active = Some(conn);
                    if let Some(old) = self.last_exchange_msg.clone() {
                        if sim.chance(self.dup_permille) {
                            sim.say(
                                self.id,
                                format_args!(
                                    "conn {}: re-sends an old message from the previous connection: {old:?}",
                                    conn.0
                                ),
                            );
                            cc.ep.send(&old);
                        }
                    }
                }
                Err(e) => {
                    sim.say(self.id, format_args!("pairing refuses the connection: {e}"));
                    close = Some(ErrorCode::Cancelled);
                    if let JoinerState::Failed(code) = flow.state() {
                        self.outcome = Outcome::Failed(code);
                        self.mode = Mode::Done;
                    }
                }
            },
            Mode::Paired(session) => {
                cc.own_session = None;
                match session.on_authenticated(
                    conn,
                    &cc.ep.auth.peer,
                    cc.ep.auth.local_window,
                    wall,
                ) {
                    Ok(events) => {
                        if self.eager_streams {
                            Self::open_terminal(&mut cc);
                        }
                        self.conns.insert(conn, cc);
                        self.on_session_events(sim, events);
                        return;
                    }
                    Err(e) => {
                        sim.say(
                            self.id,
                            format_args!("session refuses conn {}: {e:?}", conn.0),
                        );
                        close = Some(ErrorCode::Cancelled);
                    }
                }
            }
            Mode::Intruder => {
                Self::open_terminal(&mut cc);
                if let Some(s) = cc.terminal {
                    let _ = cc.ep.mux.send(s, b"rpc: list sessions");
                }
            }
            Mode::Idle | Mode::Done => close = Some(ErrorCode::Cancelled),
        }
        self.conns.insert(conn, cc);
        if let Some(code) = close {
            self.close(sim, conn, code);
        }
    }

    fn open_terminal(cc: &mut CallerConn) {
        if cc.terminal.is_none() {
            if let Ok(s) = cc
                .ep
                .mux
                .open_stream(PriorityClass::Interactive, "terminal")
            {
                let _ = cc.ep.mux.send(s, b"$ ");
                cc.terminal = Some(s);
            }
        }
    }

    pub(crate) fn on_bytes(&mut self, sim: &mut Sim, conn: ConnectionId, bytes: &[u8]) {
        self.run_timers(sim);
        let mono = sim.mono();
        let Some(cc) = self.conns.get_mut(&conn) else {
            return;
        };
        if cc.ep.ended {
            return;
        }
        sim.check_deadline(self.id, &cc.ep, "processed received bytes");
        match cc.ep.mux.receive(bytes, mono) {
            Err(e) => {
                sim.say(
                    self.id,
                    format_args!("conn {}: mux error {:?}", conn.0, e.code),
                );
                self.close(sim, conn, e.code);
            }
            Ok(events) => {
                for event in events {
                    if self.conns.get(&conn).is_none_or(|c| c.ep.ended) {
                        break;
                    }
                    self.on_mux_event(sim, conn, event);
                }
            }
        }
    }

    fn on_mux_event(&mut self, sim: &mut Sim, conn: ConnectionId, event: MuxEvent) {
        match event {
            MuxEvent::Control(bytes) => match ControlMessage::decode(&bytes) {
                Ok(msg) => {
                    if self.gate_allows(sim, conn, CallerTraffic::of(&msg)) {
                        self.on_control(sim, conn, msg)
                    }
                }
                Err(_) => self.close(sim, conn, ErrorCode::ProtocolError),
            },
            MuxEvent::Data { stream, bytes } => {
                if self.gate_allows(sim, conn, CallerTraffic::Stream) {
                    if let Some(cc) = self.conns.get_mut(&conn) {
                        cc.ep.mux.release(stream, bytes.len() as u64);
                        self.echoed += bytes.len() as u64;
                    }
                }
            }
            MuxEvent::StreamOpened { .. } | MuxEvent::Finished { .. } | MuxEvent::Reset { .. } => {
                self.gate_allows(sim, conn, CallerTraffic::Stream);
            }
            MuxEvent::GoAway { code } => {
                sim.say(
                    self.id,
                    format_args!("conn {}: host closed with {code:?}", conn.0),
                );
                if let Some(cc) = self.conns.get_mut(&conn) {
                    cc.ep.peer_goaway = Some(code);
                }
                self.ended(sim, conn);
            }
            _ => {}
        }
    }

    /// Ask the caller gate about inbound traffic; close on its verdict.
    fn gate_allows(&mut self, sim: &mut Sim, conn: ConnectionId, traffic: CallerTraffic) -> bool {
        let Some(cc) = self.conns.get_mut(&conn) else {
            return false;
        };
        match cc.gate.check(traffic) {
            Verdict::Allow => true,
            Verdict::Ignore => false,
            Verdict::Close(code) => {
                sim.say(
                    self.id,
                    format_args!("conn {}: caller gate refuses {traffic:?}", conn.0),
                );
                self.close(sim, conn, code);
                false
            }
        }
    }

    fn on_control(&mut self, sim: &mut Sim, conn: ConnectionId, msg: ControlMessage) {
        if let ControlMessage::Hello {
            major_version,
            minor_version,
        } = msg
        {
            if let Err(code) =
                negotiate_version(VersionSupport::LOCAL, major_version, minor_version)
            {
                sim.say(
                    self.id,
                    format_args!("conn {}: no common protocol version", conn.0),
                );
                self.close(sim, conn, code);
            }
            return;
        }
        if !matches!(msg, ControlMessage::Hello { .. }) {
            sim.say(self.id, format_args!("conn {}: gets {msg:?}", conn.0));
        }
        match &mut self.mode {
            Mode::Joining(flow) => {
                if self.active != Some(conn) {
                    return;
                }
                let actions = match msg {
                    ControlMessage::Hello { .. } => return,
                    ControlMessage::Authorized { state } => flow.on_authorized(state),
                    ControlMessage::CodeExchange { attempt, payload } => {
                        flow.on_code_exchange(attempt, &payload)
                    }
                    ControlMessage::CodeAbort { attempt, .. } => flow.on_code_abort(attempt),
                    ControlMessage::Paired { host_name, role } => flow.on_paired(host_name, role),
                    ControlMessage::JoinProof { .. } => {
                        return self.close(sim, conn, ErrorCode::ProtocolError)
                    }
                };
                self.apply(sim, conn, actions);
                self.maybe_schedule_typing(sim);
            }
            Mode::Paired(session) => {
                if let ControlMessage::Authorized {
                    state: AuthorizedState::Live,
                } = msg
                {
                    let reopening = session
                        .candidate()
                        .is_some_and(|c| c.conn == conn && c.info.is_some());
                    let Some(cc) = self.conns.get_mut(&conn) else {
                        return;
                    };
                    cc.authorized = Some(AuthorizedState::Live);
                    self.not_authorized = 0;
                    Self::open_terminal(cc);
                    if reopening {
                        if let Ok(events) = session.on_reopened(conn) {
                            self.on_session_events(sim, events);
                        }
                    }
                    if self.next_keystroke.is_none() && self.keystroke_ms.0 > 0 {
                        let d = sim.range(self.keystroke_ms.0, self.keystroke_ms.1);
                        self.next_keystroke = Some(sim.now + d);
                    }
                }
            }
            _ => {}
        }
    }

    fn apply(&mut self, sim: &mut Sim, conn: ConnectionId, actions: Vec<JoinerAction>) {
        for action in actions {
            match action {
                JoinerAction::Send(msg) => {
                    if let ControlMessage::CodeExchange { .. } = msg {
                        self.last_exchange_msg = Some(msg.clone());
                    }
                    if let Some(cc) = self.conns.get_mut(&conn) {
                        sim.say(self.id, format_args!("conn {}: sends {msg:?}", conn.0));
                        cc.ep.send(&msg);
                    }
                    if sim.chance(self.typist.resend_permille) {
                        let delay = sim.range(100, 3_000);
                        sim.after(delay, Script::JoinerResends { dev: self.id });
                    }
                    if sim.chance(self.typist.abort_permille) {
                        let delay = sim.range(0, 400);
                        sim.after(delay, Script::JoinerDrops { dev: self.id });
                    }
                }
                JoinerAction::Paired(host) => {
                    sim.say(
                        self.id,
                        format_args!("paired with {} as {}", host.name, host.role.as_str()),
                    );
                    self.outcome = Outcome::Paired(host.clone());
                    self.just_paired = Some(host.clone());
                    self.become_paired(sim, conn, host.identity);
                }
                JoinerAction::AlreadyPaired => {
                    sim.say(self.id, format_args!("the host already grants this device"));
                    self.outcome = Outcome::AlreadyPaired;
                    if let Some(pin) = self.expected_host {
                        self.become_paired(sim, conn, pin);
                    }
                }
                JoinerAction::CodeRejected { attempts_left } => {
                    sim.say(
                        self.id,
                        format_args!("code rejected, {attempts_left} attempts left"),
                    );
                    self.typing_scheduled = false;
                    if sim.chance(self.typist.switch_permille) {
                        let delay = sim.range(100, 2_000);
                        sim.after(delay, Script::JoinerSwitchesRoute { dev: self.id });
                    }
                }
                JoinerAction::Failed(code) => {
                    sim.say(self.id, format_args!("pairing failed: {code:?}"));
                    self.outcome = Outcome::Failed(code);
                    self.mode = Mode::Done;
                    self.close(sim, conn, ErrorCode::NoError);
                }
            }
        }
    }

    /// After `PAIRED` (or "already paired"): the connection becomes the
    /// current path of a pinned session, and the terminal opens.
    fn become_paired(&mut self, sim: &mut Sim, conn: ConnectionId, pin: IdentityPublicKey) {
        let wall = sim.wall(self.id);
        let mut session = PeerSession::new(pin);
        if let Some(cc) = self.conns.get_mut(&conn) {
            session.begin_path(conn);
            if session
                .on_authenticated(conn, &cc.ep.auth.peer, cc.ep.auth.local_window, wall)
                .is_ok()
            {
                let _ = session.on_reopened(conn);
            }
            cc.own_session = None;
            cc.gate.promote();
            cc.authorized = Some(AuthorizedState::Live);
            Self::open_terminal(cc);
        }
        self.mode = Mode::Paired(session);
        self.active = None;
    }

    fn maybe_schedule_typing(&mut self, sim: &mut Sim) {
        if let Mode::Joining(flow) = &self.mode {
            if flow.state() == JoinerState::AwaitingCode && !self.typing_scheduled {
                self.typing_scheduled = true;
                let delay = sim.range(self.typist.delay.0, self.typist.delay.1);
                sim.after(delay, Script::TypeCode { dev: self.id });
            }
        }
    }

    /// The owner types a code (the right one once the wrong ones are used).
    pub(crate) fn type_code(&mut self, sim: &mut Sim, shown: Option<PairingCode>) {
        self.typing_scheduled = false;
        let Mode::Joining(flow) = &mut self.mode else {
            return;
        };
        if flow.state() != JoinerState::AwaitingCode {
            return;
        }
        let Some(conn) = self.active else {
            return;
        };
        let right = self.typist.wrong_first == 0 && shown.is_some();
        let code = match (&shown, right) {
            (Some(code), true) => code.clone(),
            _ => {
                self.typist.wrong_first = self.typist.wrong_first.saturating_sub(1);
                loop {
                    let c = PairingCode::generate(&mut sim.rng);
                    if Some(&c) != shown.as_ref() {
                        break c;
                    }
                }
            }
        };
        sim.say(
            self.id,
            format_args!(
                "owner types {} code",
                if right { "the right" } else { "a wrong" }
            ),
        );
        if sim.bug(Bug::JoinerWorkBeforeDebit) {
            // Planted bug: warm up the exchange before submitting the code.
            let factory = CountingFactory::new(self.id, self.instance, self.flow, sim.work.clone());
            if let Some(hc) = self.conns.get(&conn) {
                let ticket = flow.ticket();
                let binding = mousse_net_core::pairing::binding_transcript(
                    &ticket.hash(),
                    ticket.kind,
                    ticket.version,
                    &ticket.host_identity,
                    &self.identity,
                    &hc.ep.auth.exporters.pair,
                );
                let sid = [0; mousse_net_core::pairing::SID_LEN];
                let _ = factory.start(ExchangeRole::Initiator, &code, &binding, &sid, &mut sim.rng);
            }
        }
        match flow.submit_code(&code, &mut sim.rng) {
            Ok(actions) => self.apply(sim, conn, actions),
            Err(e) => sim.say(self.id, format_args!("cannot submit the code: {e}")),
        }
        self.maybe_schedule_typing(sim);
    }

    pub(crate) fn resend(&mut self, sim: &mut Sim) {
        let (Mode::Joining(flow), Some(conn)) = (&self.mode, self.active) else {
            return;
        };
        if let (Some(msg), Some(cc)) = (flow.resend(), self.conns.get_mut(&conn)) {
            sim.say(self.id, format_args!("conn {}: resends {msg:?}", conn.0));
            cc.ep.send(&msg);
        }
    }

    /// Drop the pairing connection (abort mid-attempt or switch route).
    pub(crate) fn drop_connection(&mut self, sim: &mut Sim, switch: bool) {
        let (Mode::Joining(_), Some(conn)) = (&self.mode, self.active) else {
            return;
        };
        if switch {
            self.switch_route();
        }
        sim.say(
            self.id,
            format_args!(
                "drops conn {}{}",
                conn.0,
                if switch { " to switch route" } else { "" }
            ),
        );
        self.close(sim, conn, ErrorCode::Cancelled);
    }

    /// A paired device moves to its other route (for example, Wi-Fi to
    /// cellular).
    pub(crate) fn path_switch(&mut self, sim: &mut Sim) {
        if !self.up || !matches!(self.mode, Mode::Paired(_)) || !self.dialing.is_empty() {
            return;
        }
        self.switch_route();
        sim.say(self.id, format_args!("switches path"));
        self.dial(sim);
    }

    fn on_session_events(&mut self, sim: &mut Sim, events: Vec<SessionEvent>) {
        for ev in events {
            match ev {
                SessionEvent::RenewDue { conn } => {
                    sim.say(self.id, format_args!("renewal due on conn {}", conn.0));
                    let recent = self.last_renew_dial.is_some_and(|t| sim.now < t + 30_000);
                    if !recent && self.dialing.is_empty() {
                        self.last_renew_dial = Some(sim.now);
                        self.current_cert(sim);
                        self.dial(sim);
                    }
                }
                SessionEvent::Reopen { .. } => {}
                SessionEvent::Switched { conn } => {
                    sim.say(
                        self.id,
                        format_args!("conn {} is now the current path", conn.0),
                    );
                }
                SessionEvent::Close { conn, code } => {
                    if self.dialing.remove(&conn) {
                        sim.say(self.id, format_args!("abandons dial {}", conn.0));
                    } else {
                        self.close(sim, conn, code);
                    }
                }
            }
        }
    }

    /// Close a connection from this side.
    pub(crate) fn close(&mut self, sim: &mut Sim, conn: ConnectionId, code: ErrorCode) {
        let Some(cc) = self.conns.get_mut(&conn) else {
            return;
        };
        if cc.ep.ended {
            return;
        }
        sim.say(
            self.id,
            format_args!("closes conn {} with {code:?}", conn.0),
        );
        cc.ep.mux.close(code);
        cc.gate.close(code);
        self.ended(sim, conn);
    }

    /// A connection ended (closed here, by the peer's `GOAWAY`, or by the
    /// pipe). Runs once per connection.
    fn ended(&mut self, sim: &mut Sim, conn: ConnectionId) {
        let Some(cc) = self.conns.get_mut(&conn) else {
            return;
        };
        if cc.ep.ended {
            return;
        }
        cc.ep.ended = true;
        let code = cc.ep.peer_goaway;
        let was_active = self.active == Some(conn);
        match &mut self.mode {
            Mode::Joining(flow) if was_active => {
                self.active = None;
                let actions = flow.on_closed(code);
                for a in &actions {
                    if let JoinerAction::Failed(c) = a {
                        sim.say(self.id, format_args!("pairing failed: {c:?}"));
                    }
                }
                match flow.state() {
                    JoinerState::Connecting => {
                        if sim.bug(Bug::JoinerNewFlowOnReconnect) {
                            if let Some(fresh) = self.new_flow_machine(sim) {
                                sim.say(self.id, format_args!("starts a fresh pairing machine"));
                                self.mode = Mode::Joining(Box::new(fresh));
                            }
                        }
                        self.typing_scheduled = false;
                        self.schedule_reconnect(sim);
                    }
                    JoinerState::Failed(c) => {
                        self.outcome = Outcome::Failed(c);
                        self.mode = Mode::Done;
                    }
                    _ => {}
                }
            }
            Mode::Paired(session) => {
                session.on_path_closed(conn);
                if code == Some(ErrorCode::NotAuthorized) {
                    self.not_authorized += 1;
                }
                if self.not_authorized >= 2 {
                    sim.say(self.id, format_args!("gives up: not authorized"));
                    self.mode = Mode::Done;
                } else if session.current().is_none()
                    && session.candidate().is_none()
                    && self.dialing.is_empty()
                {
                    self.schedule_reconnect(sim);
                }
            }
            Mode::Intruder => self.mode = Mode::Done,
            _ => {}
        }
    }

    pub(crate) fn on_pipe_closed(&mut self, sim: &mut Sim, conn: ConnectionId, abrupt: bool) {
        if let Some(cc) = self.conns.get(&conn) {
            if !cc.ep.ended {
                sim.say(
                    self.id,
                    format_args!(
                        "conn {} {}",
                        conn.0,
                        if abrupt {
                            "was reset"
                        } else {
                            "was closed by the host"
                        }
                    ),
                );
            }
        }
        self.ended(sim, conn);
        self.conns.remove(&conn);
    }

    // ---- timers -------------------------------------------------------------------

    pub(crate) fn run_timers(&mut self, sim: &mut Sim) {
        if !self.up {
            return;
        }
        let wall = sim.wall(self.id);
        let mono = sim.mono();
        let skip_deadline = sim.bug(Bug::SkipDeadline);
        if !skip_deadline {
            if let Mode::Paired(session) = &mut self.mode {
                let events = session.tick(wall);
                self.on_session_events(sim, events);
            }
        }
        let ids: Vec<ConnectionId> = self.conns.keys().copied().collect();
        for conn in ids {
            let Some(cc) = self.conns.get_mut(&conn) else {
                continue;
            };
            if cc.ep.ended {
                continue;
            }
            let mut close = None;
            if !skip_deadline {
                if let Some(s) = cc.own_session.as_mut() {
                    for ev in s.tick(wall) {
                        if let SessionEvent::Close { code, .. } = ev {
                            close = Some(code);
                        }
                    }
                }
            }
            if close.is_none() {
                if let Err(e) = cc.ep.mux.on_timeout(mono) {
                    close = Some(e.code);
                }
            }
            if let Some(code) = close {
                self.close(sim, conn, code);
            }
        }
        if self.next_keystroke.is_some_and(|t| t <= sim.now) {
            self.next_keystroke = None;
            self.keystroke(sim);
        }
        if self.retry_dial_at.is_some_and(|t| t <= sim.now) {
            self.retry_dial_at = None;
            if matches!(&self.mode, Mode::Paired(s) if s.current().is_some() && s.candidate().is_none())
                && self.dialing.is_empty()
            {
                self.dial(sim);
            }
        }
        if self.reconnect_at.is_some_and(|t| t <= sim.now) {
            self.reconnect_at = None;
            let has_path = match &self.mode {
                Mode::Paired(s) => s.current().is_some() || s.candidate().is_some(),
                Mode::Joining(_) => self.active.is_some(),
                _ => true,
            };
            if !has_path && self.dialing.is_empty() {
                self.dial(sim);
            }
        }
    }

    fn keystroke(&mut self, sim: &mut Sim) {
        if let Mode::Paired(session) = &self.mode {
            if let Some(path) = session.current() {
                if let Some(cc) = self.conns.get_mut(&path.conn) {
                    if let (Some(s), false) = (cc.terminal, cc.ep.ended) {
                        let n = sim.range(1, 64) as usize;
                        let _ = cc.ep.mux.send(s, &vec![b'x'; n]);
                    }
                }
            }
        }
        if self.keystroke_ms.0 > 0 && !matches!(self.mode, Mode::Done) {
            let d = sim.range(self.keystroke_ms.0, self.keystroke_ms.1);
            self.next_keystroke = Some(sim.now + d);
        }
    }

    pub(crate) fn next_wake(&self, sim: &Sim) -> Option<u64> {
        if !self.up {
            return None;
        }
        let mut next: Option<u64> = None;
        let mut take = |t: u64| next = Some(next.map_or(t, |n| n.min(t)));
        let skip_deadline = sim.bug(Bug::SkipDeadline);
        if let (Mode::Paired(s), false) = (&self.mode, skip_deadline) {
            if let Some(w) = s.next_deadline() {
                let mut t = sim.due_ms(self.id, w);
                if let Some(last) = self.last_renew_dial {
                    t = t.max(last + 30_000);
                }
                take(t);
            }
        }
        for cc in self.conns.values() {
            if cc.ep.ended {
                continue;
            }
            if let (Some(s), false) = (&cc.own_session, skip_deadline) {
                if let Some(w) = s.next_deadline() {
                    take(sim.due_ms(self.id, w));
                }
            }
            if let Some(m) = cc.ep.mux.poll_timeout() {
                take(m.ms().max(sim.now + 1));
            }
        }
        if let Some(t) = self.next_keystroke {
            take(t.max(sim.now + 1));
        }
        if let Some(t) = self.reconnect_at {
            take(t.max(sim.now + 1));
        }
        if let Some(t) = self.retry_dial_at {
            take(t.max(sim.now + 1));
        }
        next
    }

    pub(crate) fn flush(&mut self, sim: &mut Sim) {
        let mut done = Vec::new();
        for (conn, cc) in self.conns.iter_mut() {
            if flush_endpoint(sim, self.id, &mut cc.ep) {
                done.push(*conn);
            }
        }
        for conn in done {
            self.conns.remove(&conn);
        }
    }

    // ---- per-step checks --------------------------------------------------------

    pub(crate) fn check(&mut self, sim: &mut Sim) {
        let Mode::Joining(flow) = &self.mode else {
            return;
        };
        let work = sim.work.clone();
        let work = work.borrow();
        let mine = |w: &&crate::exchange::WorkRecord| {
            w.dev == self.id && w.role == ExchangeRole::Initiator
        };
        let in_machine = work
            .iter()
            .filter(mine)
            .filter(|w| w.instance == self.instance)
            .count();
        let in_flow = work
            .iter()
            .filter(mine)
            .filter(|w| w.flow == self.flow)
            .count();
        let debited = usize::from(3 - flow.attempts_left().min(3));
        if in_machine > debited {
            sim.fail(
                Invariant::DebitBeforeWork,
                format!(
                    "{} started {in_machine} exchanges but debited {debited}",
                    self.label
                ),
            );
        }
        if in_flow > 3 {
            sim.fail(
                Invariant::AttemptCap,
                format!(
                    "{} ran {in_flow} code attempts in flow {}",
                    self.label, self.flow
                ),
            );
        }
    }

    // ---- restart -------------------------------------------------------------------

    pub(crate) fn crash(&mut self, sim: &mut Sim) {
        for conn in self.conns.keys() {
            sim.crash_pipe(*conn, Side::Client);
        }
        self.conns.clear();
        self.dialing.clear();
        self.active = None;
        self.reconnect_at = None;
        self.retry_dial_at = None;
        self.next_keystroke = None;
        self.up = false;
    }
}
