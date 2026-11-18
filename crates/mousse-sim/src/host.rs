//! A simulated host: grant table, host pairing, one gate, mux and deadline
//! per connection. This module is the host's I/O layer; every decision is
//! made by the core state machines it drives.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use mousse_net_core::authz::{ConnectionGate, GateState, Traffic, Verdict};
use mousse_net_core::control::{
    negotiate_version, AuthorizedState, ControlMessage, VersionSupport,
};
use mousse_net_core::grants::{GrantEvent, GrantId, GrantTable, NewGrant, OwnerRef, Role};
use mousse_net_core::identity::IdentityPublicKey;
use mousse_net_core::mux::{MuxEvent, StreamId};
use mousse_net_core::pairing::{
    binding_transcript, CodeExchangeFactory, CreatedInvitation, ExchangeRole, HostAction,
    HostPairing, InvitationId, InvitationKind, InvitationParams, PairingCode, SID_LEN,
};
use mousse_net_core::session::{PeerSession, SessionEvent, RENEW_LEAD_SECS};
use mousse_net_core::session_cert::SessionCertificate;
use mousse_net_core::{ConnectionId, ErrorCode};

use crate::certs;
use crate::check::Invariant;
use crate::exchange::{contains, CountingFactory};
use crate::sim::{flush_endpoint, AuthInfo, DevId, Endpoint, Side, Sim};
use crate::Bug;

pub(crate) struct HostConn {
    pub ep: Endpoint,
    pub gate: ConnectionGate,
    /// Single-path session used for this connection's deadline.
    pub session: PeerSession,
    pub closing: bool,
}

/// What the host owner does when asked "Is the device next to you?".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnerChoice {
    Approve,
    Decline,
    Cancel,
}

pub(crate) struct HostDev {
    pub id: DevId,
    pub label: &'static str,
    key_label: &'static str,
    pub identity: IdentityPublicKey,
    pub cert: SessionCertificate,
    pub cert_lifetime: u64,
    pub renew_lead: u64,
    pub grants: GrantTable,
    pub pairing: HostPairing<CountingFactory>,
    /// Pairing instance; a restart starts a new one (invitations are not
    /// persisted).
    pub instance: u64,
    /// Invitations of the current instance, with their ticket hashes.
    pub invitations: Vec<(InvitationId, [u8; 32])>,
    last_attempts_left: BTreeMap<InvitationId, u8>,
    pub conns: BTreeMap<ConnectionId, HostConn>,
    pub up: bool,
    /// A fake host: accepts any proof and answers code attempts with junk.
    pub malicious: bool,
    /// Grant ids issued while the grant store survived.
    issued_grant_ids: BTreeSet<u64>,
    /// The code currently on screen.
    pub shown_code: Option<PairingCode>,
    /// `(invitation, joiner identity, grant, role)` for each enrollment.
    pub enrolled: Vec<(InvitationId, IdentityPublicKey, GrantId, Role)>,
    pub owner_choices: Vec<OwnerChoice>,
}

/// The profile that authorizes every grant in the simulation.
const PROFILE_ID: [u8; OwnerRef::LEN] = [0x51; OwnerRef::LEN];

fn classify(msg: &ControlMessage) -> Traffic {
    match msg {
        ControlMessage::Hello { .. } => Traffic::Hello,
        ControlMessage::JoinProof { .. } => Traffic::JoinProof,
        ControlMessage::CodeExchange { .. } | ControlMessage::CodeAbort { .. } => Traffic::Pairing,
        ControlMessage::Authorized { .. } | ControlMessage::Paired { .. } => Traffic::HostOnly,
    }
}

impl HostDev {
    pub(crate) fn new(sim: &mut Sim, id: DevId, label: &'static str, lifetime: u64) -> Self {
        let key_label = sim.key_labels[id];
        let identity = certs::identity_key(key_label).public_key();
        let cert = certs::certificate(key_label, certs::grid(sim.wall(id)), lifetime);
        let pairing = HostPairing::new(
            identity,
            label.to_owned(),
            CountingFactory::new(id, 1, 0, sim.work.clone()),
        );
        Self {
            id,
            label,
            key_label,
            identity,
            cert,
            cert_lifetime: lifetime,
            renew_lead: RENEW_LEAD_SECS,
            grants: GrantTable::new(),
            pairing,
            instance: 1,
            invitations: Vec::new(),
            last_attempts_left: BTreeMap::new(),
            conns: BTreeMap::new(),
            up: true,
            malicious: false,
            issued_grant_ids: BTreeSet::new(),
            shown_code: None,
            enrolled: Vec::new(),
            owner_choices: vec![OwnerChoice::Approve],
        }
    }

    /// Add a grant directly (a device paired before the run, or paired
    /// again by the owner).
    pub(crate) fn add_grant(
        &mut self,
        sim: &mut Sim,
        identity: IdentityPublicKey,
        name: &str,
        expires_in: Option<u64>,
    ) -> Option<GrantId> {
        let wall = sim.wall(self.id);
        let added = self.grants.add(
            NewGrant {
                identity,
                name: name.to_owned(),
                role: Role::owner(),
                authorizing_owner: OwnerRef::from_bytes(PROFILE_ID),
                expires_at: expires_in.map(|s| wall.plus(s)),
            },
            wall,
        );
        match added {
            Ok((id, events)) => {
                match expires_in {
                    Some(secs) => sim.say(
                        self.id,
                        format_args!("grants {name} as grant {} for {secs}s", id.0),
                    ),
                    None => sim.say(self.id, format_args!("grants {name} as grant {}", id.0)),
                }
                self.note_grant_id(sim, id);
                let actions = events.into_iter().map(HostAction::Grant).collect();
                self.apply(sim, actions);
                Some(id)
            }
            Err(e) => {
                sim.say(self.id, format_args!("cannot grant {name}: {e:?}"));
                None
            }
        }
    }

    fn note_grant_id(&mut self, sim: &mut Sim, id: GrantId) {
        if !self.issued_grant_ids.insert(id.0) {
            sim.fail(
                Invariant::GrantIdsUnique,
                format!("{} issued grant id {} a second time", self.label, id.0),
            );
        }
    }

    pub(crate) fn create_invitation(
        &mut self,
        sim: &mut Sim,
        kind: InvitationKind,
        routes: Vec<String>,
    ) -> CreatedInvitation {
        let wall = sim.wall(self.id);
        let created = self
            .pairing
            .create(
                InvitationParams {
                    kind,
                    role: Role::owner(),
                    authorizing_owner: OwnerRef::from_bytes(PROFILE_ID),
                    routes,
                    grant_expires_at: None,
                },
                wall,
                &mut sim.rng,
            )
            .expect("valid routes");
        self.invitations
            .push((created.ticket.invitation, created.ticket.hash()));
        sim.say(
            self.id,
            format_args!(
                "creates a {:?} invitation {:?}, open until wall {}",
                kind,
                created.ticket.invitation,
                created.ticket.expires_at.secs()
            ),
        );
        created
    }

    /// The certificate to present on a new connection (renewed first if due).
    pub(crate) fn current_cert(&mut self, sim: &mut Sim) -> SessionCertificate {
        self.maybe_renew(sim);
        self.cert.clone()
    }

    fn maybe_renew(&mut self, sim: &mut Sim) {
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
    }

    // ---- connection events --------------------------------------------------

    pub(crate) fn on_accepted(&mut self, sim: &mut Sim, conn: ConnectionId, auth: AuthInfo) {
        let wall = sim.wall(self.id);
        let mono = sim.mono();
        let peer = auth.peer.identity;
        let mut ep = Endpoint::new(conn, Side::Server, auth, mono);
        ep.send(&ControlMessage::hello());
        let mut session = PeerSession::new(peer);
        session.begin_path(conn);
        let mut close = None;
        match session.on_authenticated(conn, &ep.auth.peer, ep.auth.local_window, wall) {
            Ok(_) => {
                let _ = session.on_reopened(conn);
            }
            Err(_) => close = Some(ErrorCode::CertExpired),
        }
        let gate = if self.malicious {
            ConnectionGate::open(conn, peer, &mut GrantTable::new(), wall, mono)
        } else {
            ConnectionGate::open(conn, peer, &mut self.grants, wall, mono)
        };
        let state = match gate.state() {
            GateState::Live { .. } => "live",
            GateState::AwaitingJoinProof { .. } => "awaiting join proof",
            GateState::JoinOnly { .. } => "join-only",
            GateState::Closed(_) => "closed",
        };
        sim.say(
            self.id,
            format_args!(
                "accepts conn {} from {}: step 2 {state}",
                conn.0,
                sim.who(&peer)
            ),
        );
        match gate.state() {
            GateState::Live { .. } => ep.send(&ControlMessage::Authorized {
                state: AuthorizedState::Live,
            }),
            GateState::Closed(code) => close = close.or(Some(*code)),
            _ => {}
        }
        self.conns.insert(
            conn,
            HostConn {
                ep,
                gate,
                session,
                closing: false,
            },
        );
        if let Some(code) = close {
            self.close(sim, conn, code);
        }
    }

    pub(crate) fn on_bytes(&mut self, sim: &mut Sim, conn: ConnectionId, bytes: &[u8]) {
        self.run_timers(sim);
        let mono = sim.mono();
        let Some(hc) = self.conns.get_mut(&conn) else {
            return;
        };
        if hc.closing {
            return;
        }
        sim.check_deadline(self.id, &hc.ep, "processed received bytes");
        match hc.ep.mux.receive(bytes, mono) {
            Err(e) => {
                sim.say(
                    self.id,
                    format_args!("conn {}: mux error {:?}", conn.0, e.code),
                );
                self.close(sim, conn, e.code);
            }
            Ok(events) => {
                for event in events {
                    if self.conns.get(&conn).is_none_or(|c| c.closing) {
                        break;
                    }
                    self.on_mux_event(sim, conn, event);
                }
            }
        }
    }

    fn on_mux_event(&mut self, sim: &mut Sim, conn: ConnectionId, event: MuxEvent) {
        match event {
            MuxEvent::Control(bytes) => {
                let msg = match ControlMessage::decode(&bytes) {
                    Ok(m) => m,
                    Err(_) => return self.close(sim, conn, ErrorCode::ProtocolError),
                };
                if self.malicious {
                    return self.fake_host_control(sim, conn, msg);
                }
                let Some(hc) = self.conns.get_mut(&conn) else {
                    return;
                };
                match hc.gate.check(classify(&msg)) {
                    Verdict::Close(code) => {
                        sim.say(
                            self.id,
                            format_args!("conn {}: gate refuses {msg:?}", conn.0),
                        );
                        self.close(sim, conn, code)
                    }
                    Verdict::Ignore => sim.say(
                        self.id,
                        format_args!("conn {}: gate ignores {msg:?}", conn.0),
                    ),
                    Verdict::Allow => self.on_control(sim, conn, msg),
                }
            }
            MuxEvent::StreamOpened { stream, label, .. } => {
                if self.stream_allowed(sim, conn) {
                    sim.say(
                        self.id,
                        format_args!("conn {}: app accepts stream {} {label:?}", conn.0, stream.0),
                    );
                }
            }
            MuxEvent::Data { stream, bytes } => {
                if self.stream_allowed(sim, conn) {
                    self.on_app_data(conn, stream, bytes);
                }
            }
            MuxEvent::Finished { .. } | MuxEvent::Reset { .. } => {
                self.stream_allowed(sim, conn);
            }
            MuxEvent::Pong { .. } => {}
            MuxEvent::GoAway { code } => {
                sim.say(
                    self.id,
                    format_args!("conn {}: peer closed with {code:?}", conn.0),
                );
                if let Some(hc) = self.conns.get_mut(&conn) {
                    hc.ep.peer_goaway = Some(code);
                }
                self.close(sim, conn, code);
            }
        }
    }

    /// Ask the gate about a stream frame; if allowed, the application takes
    /// it, so check the grant binding right here.
    fn stream_allowed(&mut self, sim: &mut Sim, conn: ConnectionId) -> bool {
        let wall = sim.wall(self.id);
        let bypass = sim.bug(Bug::HostIgnoreGate);
        let Some(hc) = self.conns.get_mut(&conn) else {
            return false;
        };
        let verdict = if bypass {
            Verdict::Allow
        } else {
            hc.gate.check(Traffic::Stream)
        };
        match verdict {
            Verdict::Allow => {
                let peer = hc.ep.auth.peer.identity;
                let bound = match hc.gate.state() {
                    GateState::Live { grant } => Some(*grant),
                    _ => None,
                };
                let live = self.grants.live_grant(&peer, wall).map(|g| g.id);
                let ok = bound.is_some() && self.grants.binding(conn) == bound && live == bound;
                if !ok {
                    sim.fail(
                        Invariant::NoTrafficWithoutGrant,
                        format!(
                            "{} app accepted stream traffic from {} on conn {} (gate {:?}, binding {:?}, live grant {:?})",
                            self.label,
                            sim.who(&peer),
                            conn.0,
                            hc.gate.state(),
                            self.grants.binding(conn),
                            live
                        ),
                    );
                }
                true
            }
            Verdict::Ignore => false,
            Verdict::Close(code) => {
                sim.say(
                    self.id,
                    format_args!("conn {}: gate refuses stream traffic", conn.0),
                );
                self.close(sim, conn, code);
                false
            }
        }
    }

    fn on_app_data(&mut self, conn: ConnectionId, stream: StreamId, bytes: Vec<u8>) {
        if let Some(hc) = self.conns.get_mut(&conn) {
            hc.ep.mux.release(stream, bytes.len() as u64);
            // The terminal echoes what it gets.
            let _ = hc.ep.mux.send(stream, &bytes);
        }
    }

    fn on_control(&mut self, sim: &mut Sim, conn: ConnectionId, msg: ControlMessage) {
        let wall = sim.wall(self.id);
        let Some(hc) = self.conns.get(&conn) else {
            return;
        };
        let peer = hc.ep.auth.peer.identity;
        let exporters = hc.ep.auth.exporters;
        let actions = match msg {
            ControlMessage::Hello {
                major_version,
                minor_version,
            } => {
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
            ControlMessage::JoinProof {
                invitation,
                mac,
                name,
            } => {
                sim.say(
                    self.id,
                    format_args!("conn {}: join proof for {invitation:?}", conn.0),
                );
                self.pairing.on_join_proof(
                    conn,
                    &peer,
                    &exporters,
                    &invitation,
                    &mac,
                    &name,
                    &self.grants,
                    wall,
                )
            }
            ControlMessage::CodeExchange { attempt, payload } => {
                sim.say(
                    self.id,
                    format_args!(
                        "conn {}: code exchange {attempt:?}, {} bytes",
                        conn.0,
                        payload.len()
                    ),
                );
                self.pairing.on_code_exchange(
                    conn,
                    attempt,
                    &payload,
                    &mut self.grants,
                    wall,
                    &mut sim.rng,
                )
            }
            ControlMessage::CodeAbort { attempt, code } => {
                sim.say(
                    self.id,
                    format_args!("conn {}: code abort {attempt:?} {code:?}", conn.0),
                );
                self.pairing.on_code_abort(conn, attempt)
            }
            ControlMessage::Authorized { .. } | ControlMessage::Paired { .. } => return,
        };
        self.apply(sim, actions);
    }

    /// Apply host pairing actions, including the ones that closing a
    /// connection produces.
    fn apply(&mut self, sim: &mut Sim, actions: Vec<HostAction>) {
        let mut queue: VecDeque<HostAction> = actions.into();
        while let Some(action) = queue.pop_front() {
            match action {
                HostAction::Send { conn, message } => {
                    if let Some(hc) = self.conns.get_mut(&conn) {
                        if !hc.closing {
                            sim.say(self.id, format_args!("conn {}: sends {message:?}", conn.0));
                            hc.ep.send(&message);
                        }
                    }
                }
                HostAction::Close { conn, code } => queue.extend(self.close_inner(sim, conn, code)),
                HostAction::AdmittedJoinOnly { conn, invitation } => {
                    if let Some(hc) = self.conns.get_mut(&conn) {
                        hc.gate.admit_join_only(invitation);
                    }
                    if sim.bug(Bug::HostWorkBeforeDebit) {
                        self.precompute_share(sim, conn, invitation);
                    }
                }
                HostAction::AskApproval {
                    invitation, conn, ..
                } => {
                    sim.say(
                        self.id,
                        format_args!("asks its owner about the device on conn {}", conn.0),
                    );
                    let delay = sim.range(1_000, 8_000);
                    sim.after(
                        delay,
                        crate::world::Script::OwnerDecides {
                            host: self.id,
                            invitation,
                            conn,
                        },
                    );
                }
                HostAction::ShowCode { invitation, code } => {
                    sim.say(
                        self.id,
                        format_args!("shows the code for {invitation:?} on screen"),
                    );
                    self.shown_code = Some(code);
                }
                HostAction::Enrolled {
                    invitation,
                    conn,
                    grant,
                    identity,
                } => {
                    if let Some(hc) = self.conns.get_mut(&conn) {
                        hc.gate.promote(grant);
                    }
                    let role = self
                        .grants
                        .get(grant)
                        .map_or_else(Role::owner, |g| g.role.clone());
                    sim.say(
                        self.id,
                        format_args!(
                            "enrolls {} with grant {} on conn {}",
                            sim.who(&identity),
                            grant.0,
                            conn.0
                        ),
                    );
                    self.enrolled.push((invitation, identity, grant, role));
                    self.note_grant_id(sim, grant);
                    let n = sim.check.enrolled(self.id, self.instance, invitation.0);
                    if n > 1 {
                        sim.fail(
                            Invariant::SingleEnrollment,
                            format!("{} enrolled {n} devices for {invitation:?}", self.label),
                        );
                    }
                }
                HostAction::InvitationEnded { invitation, reason } => sim.say(
                    self.id,
                    format_args!("invitation {invitation:?} ended: {reason:?}"),
                ),
                HostAction::Grant(event) => queue.extend(self.on_grant_event(sim, event)),
            }
        }
    }

    fn on_grant_event(&mut self, sim: &mut Sim, event: GrantEvent) -> Vec<HostAction> {
        let GrantEvent::CloseChannels {
            grant,
            channels,
            code,
        } = event;
        let list: Vec<u64> = channels.iter().map(|c| c.0).collect();
        sim.say(
            self.id,
            format_args!(
                "grant {} ends: close channels {list:?} with {code:?}",
                grant.0
            ),
        );
        if sim.bug(Bug::KeepChannelAfterRemoval) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for c in channels {
            out.extend(self.close_inner(sim, c, code));
        }
        out
    }

    /// Planted bug: start the responder exchange at admission, before any
    /// attempt (and so any debit) exists.
    fn precompute_share(&mut self, sim: &mut Sim, conn: ConnectionId, invitation: InvitationId) {
        let (Some(hc), Some(code)) = (self.conns.get(&conn), self.pairing.code(&invitation)) else {
            return;
        };
        let Some((_, hash)) = self.invitations.iter().find(|(i, _)| *i == invitation) else {
            return;
        };
        let binding = binding_transcript(
            hash,
            InvitationKind::SendLink,
            1,
            &self.identity,
            &hc.ep.auth.peer.identity,
            &hc.ep.auth.exporters.pair,
        );
        let factory = CountingFactory::new(self.id, self.instance, 0, sim.work.clone());
        let sid = [0; SID_LEN];
        let _ = factory.start(ExchangeRole::Responder, code, &binding, &sid, &mut sim.rng);
        sim.say(self.id, format_args!("precomputes its exchange share"));
    }

    /// The owner answers the approval prompt.
    pub(crate) fn owner_decides(
        &mut self,
        sim: &mut Sim,
        invitation: InvitationId,
        conn: ConnectionId,
    ) {
        if !self.up {
            return;
        }
        let wall = sim.wall(self.id);
        let choice = sim.pick(&self.owner_choices);
        sim.say(
            self.id,
            format_args!("owner chooses {choice:?} for conn {}", conn.0),
        );
        let actions = match choice {
            OwnerChoice::Approve => {
                match self
                    .pairing
                    .approve(&invitation, conn, &mut self.grants, wall)
                {
                    Ok(actions) => actions,
                    Err(e) => {
                        sim.say(self.id, format_args!("approval refused: {e}"));
                        Vec::new()
                    }
                }
            }
            OwnerChoice::Decline => self.pairing.decline(&invitation),
            OwnerChoice::Cancel => self.pairing.cancel(&invitation),
        };
        self.apply(sim, actions);
    }

    pub(crate) fn cancel_invitations(&mut self, sim: &mut Sim) {
        let ids: Vec<InvitationId> = self.invitations.iter().map(|(i, _)| *i).collect();
        for id in ids {
            sim.say(self.id, format_args!("owner cancels {id:?}"));
            let actions = self.pairing.cancel(&id);
            self.apply(sim, actions);
        }
    }

    /// Remove (or deny) a device's grant, as the owner would.
    pub(crate) fn remove_device(&mut self, sim: &mut Sim, identity: IdentityPublicKey, deny: bool) {
        if !self.up {
            return;
        }
        let wall = sim.wall(self.id);
        let events = if deny {
            sim.say(self.id, format_args!("owner denies {}", sim.who(&identity)));
            self.grants.deny(identity, wall)
        } else {
            let Some(id) = self.grants.live_grant(&identity, wall).map(|g| g.id) else {
                sim.say(
                    self.id,
                    format_args!("owner finds no grant for {}", sim.who(&identity)),
                );
                return;
            };
            sim.say(
                self.id,
                format_args!("owner removes grant {} of {}", id.0, sim.who(&identity)),
            );
            self.grants.remove(id)
        };
        let actions = events.into_iter().map(HostAction::Grant).collect();
        self.apply(sim, actions);
    }

    /// Close a connection: gate, mux, grant binding, pairing state.
    pub(crate) fn close(&mut self, sim: &mut Sim, conn: ConnectionId, code: ErrorCode) {
        let actions = self.close_inner(sim, conn, code);
        self.apply(sim, actions);
    }

    fn close_inner(
        &mut self,
        sim: &mut Sim,
        conn: ConnectionId,
        code: ErrorCode,
    ) -> Vec<HostAction> {
        let Some(hc) = self.conns.get_mut(&conn) else {
            return Vec::new();
        };
        if hc.closing {
            return Vec::new();
        }
        hc.closing = true;
        hc.ep.ended = true;
        hc.gate.close(code);
        hc.ep.mux.close(code);
        hc.session.on_path_closed(conn);
        sim.say(
            self.id,
            format_args!("closes conn {} with {code:?}", conn.0),
        );
        self.grants.unbind(conn);
        self.pairing.on_connection_closed(conn)
    }

    /// The pipe ended under us (reset, or the peer's FIN).
    pub(crate) fn on_pipe_closed(&mut self, sim: &mut Sim, conn: ConnectionId, abrupt: bool) {
        let Some(hc) = self.conns.get(&conn) else {
            return;
        };
        if !hc.closing {
            sim.say(
                self.id,
                format_args!(
                    "conn {} {}",
                    conn.0,
                    if abrupt {
                        "was reset"
                    } else {
                        "was closed by the peer"
                    }
                ),
            );
            self.close(sim, conn, ErrorCode::NoError);
        }
        self.conns.remove(&conn);
    }

    // ---- timers ---------------------------------------------------------------

    pub(crate) fn run_timers(&mut self, sim: &mut Sim) {
        if !self.up {
            return;
        }
        let wall = sim.wall(self.id);
        let mono = sim.mono();
        self.maybe_renew(sim);
        let actions = self.pairing.tick(wall);
        self.apply(sim, actions);
        let events = self.grants.tick(wall);
        let actions = events.into_iter().map(HostAction::Grant).collect();
        self.apply(sim, actions);
        let skip_deadline = sim.bug(Bug::SkipDeadline);
        let ids: Vec<ConnectionId> = self.conns.keys().copied().collect();
        for conn in ids {
            let Some(hc) = self.conns.get_mut(&conn) else {
                continue;
            };
            if hc.closing {
                continue;
            }
            let mut close = None;
            if !skip_deadline {
                for ev in hc.session.tick(wall) {
                    if let SessionEvent::Close { code, .. } = ev {
                        close = Some(code);
                    }
                }
            }
            if close.is_none() {
                close = hc.gate.on_timeout(mono);
            }
            if close.is_none() {
                if let Err(e) = hc.ep.mux.on_timeout(mono) {
                    close = Some(e.code);
                }
            }
            if let Some(code) = close {
                self.close(sim, conn, code);
            }
        }
    }

    pub(crate) fn next_wake(&self, sim: &Sim) -> Option<u64> {
        if !self.up {
            return None;
        }
        let mut next: Option<u64> = None;
        let mut take = |t: u64| next = Some(next.map_or(t, |n| n.min(t)));
        let renew = self.cert.window().not_after().minus(self.renew_lead);
        take(sim.due_ms(self.id, renew));
        if let Some(w) = self.pairing.next_expiry() {
            take(sim.due_ms(self.id, w));
        }
        if let Some(w) = self.grants.next_expiry() {
            take(sim.due_ms(self.id, w));
        }
        let skip_deadline = sim.bug(Bug::SkipDeadline);
        for hc in self.conns.values() {
            if hc.closing {
                continue;
            }
            if !skip_deadline {
                if let Some(w) = hc.session.next_deadline() {
                    take(sim.due_ms(self.id, w));
                }
            }
            if let Some(m) = hc.gate.poll_timeout() {
                take(m.ms().max(sim.now + 1));
            }
            if let Some(m) = hc.ep.mux.poll_timeout() {
                take(m.ms().max(sim.now + 1));
            }
        }
        next
    }

    pub(crate) fn flush(&mut self, sim: &mut Sim) {
        let mut done = Vec::new();
        for (conn, hc) in self.conns.iter_mut() {
            if flush_endpoint(sim, self.id, &mut hc.ep) {
                done.push(*conn);
            }
        }
        for conn in done {
            self.conns.remove(&conn);
        }
    }

    // ---- per-step checks --------------------------------------------------------

    pub(crate) fn check(&mut self, sim: &mut Sim) {
        if !self.up {
            return;
        }
        let wall = sim.wall(self.id);
        // Removed grants have no open channels.
        for (conn, hc) in &self.conns {
            if hc.closing {
                continue;
            }
            if let GateState::Live { grant } = hc.gate.state() {
                let peer = hc.ep.auth.peer.identity;
                let live = self.grants.live_grant(&peer, wall).map(|g| g.id);
                if live != Some(*grant) || self.grants.binding(*conn) != Some(*grant) {
                    sim.fail(
                        Invariant::RemovedGrantClosed,
                        format!(
                            "{} conn {} of {} is still open on grant {} (live grant {:?}, binding {:?})",
                            self.label,
                            conn.0,
                            sim.who(&peer),
                            grant.0,
                            live,
                            self.grants.binding(*conn)
                        ),
                    );
                }
            }
        }
        // Debit before code work, at most 3 per invitation, never returned.
        let work = sim.work.clone();
        let work = work.borrow();
        for (invitation, hash) in &self.invitations {
            let Some(left) = self.pairing.attempts_left(invitation) else {
                continue;
            };
            let started = work
                .iter()
                .filter(|w| {
                    w.dev == self.id
                        && w.instance == self.instance
                        && w.role == ExchangeRole::Responder
                        && contains(&w.transcript, hash)
                })
                .count();
            let debited = usize::from(3 - left.min(3));
            if started > debited {
                sim.fail(
                    Invariant::DebitBeforeWork,
                    format!(
                        "{} started {started} exchanges for {invitation:?} but debited {debited}",
                        self.label
                    ),
                );
            }
            if started > 3 {
                sim.fail(
                    Invariant::AttemptCap,
                    format!("{} ran {started} attempts for {invitation:?}", self.label),
                );
            }
            if let Some(prev) = self.last_attempts_left.insert(*invitation, left) {
                if left > prev {
                    sim.fail(
                        Invariant::AttemptCap,
                        format!(
                            "{} returned a debit for {invitation:?}: {prev} -> {left}",
                            self.label
                        ),
                    );
                }
            }
        }
    }

    // ---- restart ------------------------------------------------------------------

    /// The process dies. Peers see their connections reset.
    pub(crate) fn crash(&mut self, sim: &mut Sim) {
        for conn in self.conns.keys() {
            sim.crash_pipe(*conn, Side::Server);
        }
        self.conns.clear();
        self.up = false;
    }

    /// The process starts again. The identity key always survives (key
    /// store). The grant store survives only if `keep`. Invitations never do:
    /// core keeps them in memory only.
    pub(crate) fn start_again(&mut self, sim: &mut Sim, keep: bool) {
        self.grants = if keep {
            let grants = self.grants.grants().cloned().collect();
            let denials = self.grants.denials().collect();
            let next_grant_id = self.grants.next_grant_id();
            GrantTable::restore(grants, denials, next_grant_id)
                .expect("a table restores from its own contents")
        } else {
            self.issued_grant_ids.clear();
            GrantTable::new()
        };
        self.instance += 1;
        self.pairing = HostPairing::new(
            self.identity,
            self.label.to_owned(),
            CountingFactory::new(self.id, self.instance, 0, sim.work.clone()),
        );
        self.invitations.clear();
        self.last_attempts_left.clear();
        self.shown_code = None;
        self.cert = certs::certificate(
            self.key_label,
            certs::grid(sim.wall(self.id)),
            self.cert_lifetime,
        );
        self.up = true;
    }

    // ---- fake host -------------------------------------------------------------------

    /// A fake host takes any proof and answers every attempt with junk, then
    /// drops the connection so the joiner has to reconnect.
    fn fake_host_control(&mut self, sim: &mut Sim, conn: ConnectionId, msg: ControlMessage) {
        let reply = match msg {
            ControlMessage::JoinProof { invitation, .. } => {
                if let Some(hc) = self.conns.get_mut(&conn) {
                    hc.gate.admit_join_only(invitation);
                }
                Some(ControlMessage::Authorized {
                    state: AuthorizedState::JoinOnly,
                })
            }
            ControlMessage::CodeExchange { attempt, .. } => {
                let len = sim.range(32, 96) as usize;
                let junk: Vec<u8> = (0..len).map(|_| sim.range(0, 255) as u8).collect();
                let delay = sim.range(500, 3_000);
                sim.after(
                    delay,
                    crate::world::Script::HostDrops {
                        host: self.id,
                        conn,
                    },
                );
                Some(ControlMessage::CodeExchange {
                    attempt,
                    payload: junk,
                })
            }
            _ => None,
        };
        if let (Some(reply), Some(hc)) = (reply, self.conns.get_mut(&conn)) {
            sim.say(
                self.id,
                format_args!("conn {}: fake host sends {reply:?}", conn.0),
            );
            hc.ep.send(&reply);
        }
    }
}
