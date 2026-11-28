//! `direct-joiner.json`: Pair with IP end to end (wire.md 10.9), the joiner
//! machine against the host machine, replayed byte for byte from listed
//! random draws, with every write the joiner asks for.

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use serde_json::{json, Value as J};

use super::{checked_in, hex, identity, unhex, Draws, IDENTITY_A, T};
use crate::authz::{CallerGate, CallerTraffic, ConnectionGate, GateState, Traffic, Verdict};
use crate::control::{AuthorizedState, ControlMessage, DIRECT_MINOR_VERSION};
use crate::grants::{GrantTable, OwnerRef, Role};
use crate::identity::IdentityPublicKey;
use crate::pairing::{
    AttemptId, CpaceExchangeFactory, DirectAddress, DirectCode, DirectEnd, DirectHostAction,
    DirectHostPairing, DirectInvitationParams, DirectJoinerAction, DirectJoinerPairing,
    DirectJoinerState, DirectLedger, DirectLookup, DirectPending, DirectRequestId, InvitationId,
    DIRECT_CODE_ALPHABET,
};
use crate::time::{Millis, UnixTime};
use crate::{ConnectionId, ErrorCode};

const ADDRESS: &str = "192.168.1.20:47100";
const JOINER_SECRET: [u8; 32] = [0x50; 32];
const JOINER_NAME: &str = "Laptop";
/// The code typed against fake hosts (they share its lookup).
const TYPED: &str = "K7QM-2XPA-9RTE";

fn sequences() -> Vec<J> {
    vec![
        json!({
            "name": "success",
            "description": "The code passes, the joiner stores its pending record before its confirmation, the owner allows, and the joiner pins the host only on PAIRED, then clears the record.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host", "state": "awaiting_allow", "ledger": 4, "pending": "pending", "pinned": false },
                { "op": "allow", "state": "ended:paired", "pending": null, "pinned": true, "granted": "committed" },
            ],
        }),
        json!({
            "name": "wrong_secret",
            "description": "A wrong secret fails at the joiner's check of the host's confirmation: it aborts, closes, and the flow ends with the attempts left. The next Connect is a new flow.",
            "steps": [
                { "op": "start", "code": "wrong", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host", "state": "ended:code_failed:4", "ledger": 4, "pending": null },
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 2, "host": "host", "state": "awaiting_allow", "ledger": 3 },
            ],
        }),
        json!({
            "name": "wrong_lookup",
            "description": "A typo in the first four characters: the host holds the connection, then closes it with invitation_invalid. Nothing is debited.",
            "steps": [
                { "op": "start", "code": "other_lookup", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host", "state": "ended:closed:invitation_invalid", "ledger": null, "pending": null },
            ],
        }),
        json!({
            "name": "far_end_changes_keys",
            "description": "Whatever answers at the typed address shows a new identity key on every Connect and does not know the secret. The ledger is kept by the typed lookup, so the five attempts run out all the same, and a sixth Connect is refused before dialing.",
            "steps": [
                { "op": "start", "code": "typed", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "fake1", "state": "ended:code_failed:4", "ledger": 4 },
                { "op": "start", "code": "typed", "result": "ok" },
                { "op": "connect", "conn": 2, "host": "fake2", "state": "ended:code_failed:3", "ledger": 3 },
                { "op": "start", "code": "typed", "result": "ok" },
                { "op": "connect", "conn": 3, "host": "fake3", "state": "ended:code_failed:2", "ledger": 2 },
                { "op": "start", "code": "typed", "result": "ok" },
                { "op": "connect", "conn": 4, "host": "fake4", "state": "ended:code_failed:1", "ledger": 1 },
                { "op": "start", "code": "typed", "result": "ok" },
                { "op": "connect", "conn": 5, "host": "fake5", "state": "ended:attempts_exhausted", "ledger": 0, "pending": null, "pinned": false },
                { "op": "start", "code": "typed", "result": "attempts_exhausted" },
            ],
        }),
        json!({
            "name": "own_device",
            "description": "The far end shows this device's own identity key: the joiner closes with pairing_failed and sends nothing else (the I/O layer refuses that key even before its own certificate goes out).",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "own", "state": "ended:own_device", "ledger": null },
            ],
        }),
        json!({
            "name": "minor_3_host",
            "description": "The host's HELLO agrees on minor 3: the joiner closes with unsupported_version before JOIN_DIRECT and reports that the host needs an update.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host", "minor": 3, "state": "ended:needs_update", "ledger": null },
            ],
        }),
        json!({
            "name": "declined",
            "description": "The owner declines: the host closes with pairing_declined, which settles and clears the pending record.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host" },
                { "op": "decline", "state": "ended:closed:pairing_declined", "pending": null, "pinned": false, "granted": null },
            ],
        }),
        json!({
            "name": "lost_paired_then_recovery",
            "description": "The owner allows, but the connection breaks before PAIRED arrives: the pending record stays. The recovery dials pinned, gets step 2's AUTHORIZED {live} and then PAIRED from the grant's receipt.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host" },
                { "op": "allow", "lose": "paired", "state": "away", "pending": "pending", "pinned": false, "granted": "provisional" },
                { "op": "connect", "conn": 2, "host": "host", "state": "ended:paired", "pending": null, "pinned": true },
            ],
        }),
        json!({
            "name": "allow_while_away",
            "description": "The connection drops while the device waits; the owner allows it while it is away. Its recovery is answered AUTHORIZED {join_only, I}, enrolled and sent PAIRED.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host" },
                { "op": "drop", "state": "away", "pending": "pending" },
                { "op": "allow", "granted": null },
                { "op": "connect", "conn": 2, "host": "host", "state": "ended:paired", "pending": null, "pinned": true, "granted": "committed" },
            ],
        }),
        json!({
            "name": "cancel_connected",
            "description": "The device cancels while connected: the pending record is marked cancelled first, then CODE_ABORT {A, cancelled} and a close with cancelled. Its next connection delivers the cancel and hears cancelled, which clears the record.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host" },
                { "op": "cancel", "state": "away", "pending": "cancelled" },
                { "op": "connect", "conn": 2, "host": "host", "state": "ended:closed:cancelled", "pending": null, "pinned": false, "granted": null },
            ],
        }),
        json!({
            "name": "cancel_away",
            "description": "The device cancels while away: the record is marked cancelled and the cancel goes with the next connection.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host" },
                { "op": "drop" },
                { "op": "cancel", "state": "away", "pending": "cancelled" },
                { "op": "connect", "conn": 2, "host": "host", "state": "ended:closed:cancelled", "pending": null, "granted": null },
            ],
        }),
        json!({
            "name": "cancel_crossing_allow",
            "description": "The owner allows while the device cancels. The host's PAIRED is on its way when the cancel leaves; the cancel reaches the host on the enrolled connection and the grant is removed. The joiner ignores the PAIRED that crossed its cancel and pins nothing; its recovery finds no invitation, which clears the record.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host" },
                { "op": "allow", "in_transit": true, "granted": "provisional" },
                { "op": "cancel", "state": "away", "pending": "cancelled", "pinned": false, "granted": null },
                { "op": "connect", "conn": 2, "host": "host", "state": "ended:closed:invitation_invalid", "pending": null, "pinned": false, "granted": null },
            ],
        }),
        json!({
            "name": "not_received",
            "description": "The connection breaks after the joiner stored its pending record but before its confirmation reached the host. The recovery hears AUTHORIZED {join_only, I, not_received}: the record is cleared and the person connects again with the code.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host", "lose": "msg_c", "state": "away", "pending": "pending" },
                { "op": "connect", "conn": 2, "host": "host", "state": "ended:not_received:4", "pending": null, "ledger": 4 },
            ],
        }),
        json!({
            "name": "crash_after_pending_mark",
            "description": "The app stops right after its confirmation went out. A new flow resumes from the stored pending record with no code, recovers, waits for Allow and pairs.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host", "crash": "after_msg_c", "pending": "pending" },
                { "op": "resume", "result": "ok" },
                { "op": "connect", "conn": 2, "host": "host", "state": "awaiting_allow" },
                { "op": "allow", "state": "ended:paired", "pending": null, "pinned": true, "granted": "committed" },
            ],
        }),
        json!({
            "name": "a_second_address_keeps_the_first_pending_record",
            "description": "A code passes at the typed address, the device goes away and cancels. The same code then passes at another address of the same host: its pending record is kept beside the first one, which still holds its cancel. Each is recovered on its own: the first delivers the cancel, the second hears it.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host" },
                { "op": "drop", "state": "away", "held": false },
                { "op": "cancel", "state": "away", "pending": "cancelled", "held": false },
                { "op": "start", "code": "right", "address": "192.168.1.21:47100", "result": "ok" },
                { "op": "connect", "conn": 2, "host": "host", "state": "awaiting_allow", "pendings": [["192.168.1.20:47100", "cancelled"], ["192.168.1.21:47100", "pending"]] },
                { "op": "drop", "state": "away" },
                { "op": "resume", "result": "ok" },
                { "op": "connect", "conn": 3, "host": "host", "state": "ended:closed:cancelled", "pendings": [["192.168.1.21:47100", "pending"]], "granted": null },
                { "op": "resume", "address": "192.168.1.21:47100", "result": "ok" },
                { "op": "connect", "conn": 4, "host": "host", "state": "ended:closed:cancelled", "pendings": [], "held": false },
            ],
        }),
        json!({
            "name": "a_held_lookup_is_busy",
            "description": "Another flow on this device holds the typed lookup: a Connect is refused before anything is loaded or dialled. A cancel while away that cannot get the hold leaves the flow away and its record as it was.",
            "steps": [
                { "op": "start", "code": "right", "held_elsewhere": true, "result": "busy", "ledger": null },
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host" },
                { "op": "drop", "state": "away" },
                { "op": "cancel", "held_elsewhere": true, "state": "away", "pending": "pending" },
            ],
        }),
        json!({
            "name": "the_ledger_window_ends_before_the_debit",
            "description": "The stored ledger has one attempt left and its 24 h end 10 s after the Connect starts. The debit comes at 20 s: the entry has ended, so the debit starts a new one with this attempt counted (4 left), written in place of the stored one.",
            "steps": [
                { "op": "stored_ledger", "attempts_left": 1, "first_debit_ago": 86390 },
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host", "at": 20, "state": "awaiting_allow", "ledger": 4 },
            ],
        }),
        json!({
            "name": "a_failed_cancel_write",
            "description": "The write that marks the pending record cancelled fails. Connected, the flow closes the connection with internal_error and ends; away, it ends with no connection to close. The record stays as it was.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host" },
                { "op": "fail_next_write" },
                { "op": "cancel", "state": "ended:closed:internal_error", "pending": "pending", "held": false },
                { "op": "resume", "result": "ok" },
                { "op": "connect", "conn": 2, "host": "host", "state": "awaiting_allow" },
                { "op": "drop", "state": "away" },
                { "op": "fail_next_write" },
                { "op": "cancel", "state": "ended:closed:internal_error", "pending": "pending", "held": false },
            ],
        }),
        json!({
            "name": "an_old_flow_never_takes_a_newer_record",
            "description": "Flow a loses its confirmation and goes away. A separate recovery learns not_received and clears a's record. A new Connect at the same address passes the code and goes away with its own pending record. Then the person cancels a: it takes the hold and reloads, finds no record its own attempt wrote, and ends as settled; the newer record stays as it was.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host", "lose": "msg_c", "state": "away", "pending": "pending" },
                { "op": "park", "as": "a" },
                { "op": "resume", "result": "ok" },
                { "op": "connect", "conn": 2, "host": "host", "state": "ended:not_received:4", "pending": null },
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 3, "host": "host", "state": "awaiting_allow", "pending": "pending" },
                { "op": "drop", "state": "away", "held": false },
                { "op": "park", "as": "c" },
                { "op": "unpark", "flow": "a" },
                { "op": "cancel", "state": "ended:settled", "pendings": [["192.168.1.20:47100", "pending"]], "held": false },
            ],
        }),
        json!({
            "name": "a_recovery_dial_is_pinned",
            "description": "The confirmation is lost; the recovery's TLS is pinned to the stored host key. A far end at the address showing another key fails the dial: the flow goes back away with its record and gives the hold back. An unreachable address does the same. A refused hold dials nothing. The next recovery reaches the host.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host", "lose": "msg_c", "state": "away", "pending": "pending" },
                { "op": "connect", "conn": 2, "host": "fake1", "state": "away", "pending": "pending", "held": false },
                { "op": "connect", "conn": 3, "host": "host", "unreachable": true, "state": "away", "pending": "pending", "held": false },
                { "op": "connect", "conn": 4, "host": "host", "held_elsewhere": true, "state": "away", "pending": "pending" },
                { "op": "connect", "conn": 5, "host": "host", "state": "ended:not_received:4", "pending": null, "held": false },
            ],
        }),
        json!({
            "name": "an_unreachable_first_contact",
            "description": "The typed address does not answer: the flow ends and gives the hold back; no attempt was spent.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host", "unreachable": true, "state": "ended:closed", "ledger": null, "held": false },
            ],
        }),
        json!({
            "name": "a_silent_host",
            "description": "The host never answers JOIN_DIRECT. After the 10 s wait the joiner closes with not_authorized: a first contact ends; a recovery goes away and keeps its pending record.",
            "steps": [
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 1, "host": "host", "silent": true, "state": "ended:closed:not_authorized", "ledger": null },
                { "op": "start", "code": "right", "result": "ok" },
                { "op": "connect", "conn": 2, "host": "host", "lose": "msg_c", "state": "away", "pending": "pending" },
                { "op": "connect", "conn": 3, "host": "host", "silent": true, "state": "away", "pending": "pending", "held": false },
            ],
        }),
    ]
}

fn state_name(s: Option<DirectJoinerState>) -> String {
    match s {
        None => "none".into(),
        Some(DirectJoinerState::Holding) => "holding".into(),
        Some(DirectJoinerState::Connecting) => "connecting".into(),
        Some(DirectJoinerState::AwaitingHello) => "awaiting_hello".into(),
        Some(DirectJoinerState::AwaitingAnswer) => "awaiting_answer".into(),
        Some(DirectJoinerState::Exchanging) => "exchanging".into(),
        Some(DirectJoinerState::AwaitingAllow) => "awaiting_allow".into(),
        Some(DirectJoinerState::Away) => "away".into(),
        Some(DirectJoinerState::Paired) => "paired".into(),
        Some(DirectJoinerState::Ended(end)) => format!("ended:{}", end_name(end)),
    }
}

fn end_name(end: DirectEnd) -> String {
    match end {
        DirectEnd::Paired => "paired".into(),
        DirectEnd::NeedsUpdate => "needs_update".into(),
        DirectEnd::OwnDevice => "own_device".into(),
        DirectEnd::CodeFailed { attempts_left } => format!("code_failed:{attempts_left}"),
        DirectEnd::AttemptsExhausted => "attempts_exhausted".into(),
        DirectEnd::NotReceived { attempts_left } => format!("not_received:{attempts_left}"),
        DirectEnd::Cancelled => "cancelled".into(),
        DirectEnd::Busy => "busy".into(),
        DirectEnd::BadRecord => "bad_record".into(),
        DirectEnd::Settled => "settled".into(),
        DirectEnd::Closed(Some(code)) => format!("closed:{}", code.name()),
        DirectEnd::Closed(None) => "closed".into(),
    }
}

/// The 12 drawn bytes that give `code`.
fn draw_for(code: &str) -> Vec<u8> {
    code.bytes()
        .filter(|c| *c != b'-')
        .map(|c| {
            DIRECT_CODE_ALPHABET
                .iter()
                .position(|a| *a == c)
                .expect("alphabet") as u8
        })
        .collect()
}

/// A fake host's draws: when recording, its code is forced to the typed
/// lookup with another secret; everything else comes from `inner`.
struct Forced {
    prefix: VecDeque<Vec<u8>>,
    inner: Draws,
}

impl TryRng for Forced {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        self.inner.try_next_u32()
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.inner.try_next_u64()
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        match self.prefix.pop_front() {
            Some(bytes) => {
                assert_eq!(bytes.len(), dst.len());
                dst.copy_from_slice(&bytes);
                self.inner.log.push(json!({ "bytes": hex(dst) }));
                Ok(())
            }
            None => self.inner.try_fill_bytes(dst),
        }
    }
}

impl TryCryptoRng for Forced {}

struct VHost {
    name: String,
    key: IdentityPublicKey,
    machine: DirectHostPairing<CpaceExchangeFactory>,
    rng: Forced,
    grants: GrantTable,
    invitation: InvitationId,
    code: DirectCode,
}

impl VHost {
    fn new(name: &str, index: u8, listed: Option<&J>) -> Self {
        let secret = if name == "host" {
            IDENTITY_A
        } else {
            [0x30 + index; 32]
        };
        let key = identity(&secret).public_key();
        let mut rng = match listed {
            Some(draws) => Forced {
                prefix: VecDeque::new(),
                inner: Draws::scripted(&draws[name]),
            },
            None => {
                let mut prefix = VecDeque::new();
                if name != "host" {
                    // The typed lookup with another secret, per fake.
                    prefix.push_back(vec![0x40 + index; 16]);
                    let mut code = draw_for(TYPED);
                    for b in &mut code[4..] {
                        *b = 31 - index;
                    }
                    prefix.push_back(code);
                }
                Forced {
                    prefix,
                    inner: Draws::recording(0x20 + index),
                }
            }
        };
        let mut machine = DirectHostPairing::new(key, "Desk".into(), CpaceExchangeFactory);
        let created = machine
            .create(
                DirectInvitationParams {
                    role: Role::owner(),
                    authorizing_owner: OwnerRef::from_bytes([0x51; 16]),
                    grant_expires_at: None,
                },
                UnixTime(T),
                &mut rng,
            )
            .expect("create");
        Self {
            name: name.into(),
            key,
            machine,
            rng,
            grants: GrantTable::new(),
            invitation: created.invitation,
            code: created.code,
        }
    }
}

/// The joiner's durable store: under the typed lookup, the ledger, the
/// pending records (one per typed address) and the lookup's hold; and its
/// pins.
#[derive(Default)]
struct Store {
    ledger: Option<DirectLedger>,
    pending: Vec<DirectPending>,
    held: bool,
    /// Another flow (not replayed here) has the hold.
    held_elsewhere: bool,
    /// The next write fails.
    fail_next: bool,
    pins: Vec<(IdentityPublicKey, InvitationId)>,
}

impl Store {
    fn pending_at(&self, address: &DirectAddress) -> Option<&DirectPending> {
        self.pending.iter().find(|p| p.address == *address)
    }
}

struct World {
    listed: Option<J>,
    hosts: Vec<VHost>,
    joiner_key: IdentityPublicKey,
    joiner_rng: Draws,
    flow: Option<DirectJoinerPairing<CpaceExchangeFactory>>,
    /// Flows set aside by `park`, with their typed address.
    parked: BTreeMap<String, (DirectJoinerPairing<CpaceExchangeFactory>, String)>,
    store: Store,
    /// The current connection and the host on it (`None`: the own key).
    conn: u64,
    host: Option<usize>,
    open: bool,
    lose: Option<String>,
    crash: Option<String>,
    exchanges_sent: u32,
    /// Host messages on their way to the joiner, not yet delivered.
    in_transit: Vec<ControlMessage>,
    hold_host_sends: bool,
    /// The host's gate and the joiner's gate of the current connection.
    host_gate: Option<ConnectionGate>,
    caller_gate: Option<CallerGate>,
    /// The host never answers `JOIN_DIRECT` on the current connection.
    silent: bool,
    /// The typed address of the current flow.
    address: String,
    now: UnixTime,
    out: Vec<J>,
}

impl World {
    fn new(listed: Option<&J>) -> Self {
        let joiner_rng = match listed {
            Some(draws) => Draws::scripted(&draws["joiner"]),
            None => Draws::recording(0x60),
        };
        let mut w = Self {
            listed: listed.cloned(),
            hosts: Vec::new(),
            joiner_key: identity(&JOINER_SECRET).public_key(),
            joiner_rng,
            flow: None,
            parked: BTreeMap::new(),
            store: Store::default(),
            conn: 0,
            host: None,
            open: false,
            lose: None,
            crash: None,
            exchanges_sent: 0,
            in_transit: Vec::new(),
            hold_host_sends: false,
            host_gate: None,
            caller_gate: None,
            silent: false,
            address: ADDRESS.to_owned(),
            now: UnixTime(T),
            out: Vec::new(),
        };
        w.host_index("host");
        w
    }

    fn host_index(&mut self, name: &str) -> usize {
        if let Some(i) = self.hosts.iter().position(|h| h.name == name) {
            return i;
        }
        let index = self.hosts.len() as u8;
        let host = VHost::new(name, index, self.listed.as_ref());
        self.hosts.push(host);
        self.hosts.len() - 1
    }

    fn real(&mut self) -> &mut VHost {
        &mut self.hosts[0]
    }

    fn sent(&mut self, from: &str, m: &ControlMessage) {
        let conn = self.conn;
        self.out
            .push(json!({ "send": { "from": from, "conn": conn, "control": hex(&m.encode()) } }));
    }

    /// The connection breaks: both sides see it close with no `GOAWAY`.
    fn break_connection(&mut self) -> Vec<DirectJoinerAction> {
        if !self.open {
            return Vec::new();
        }
        self.open = false;
        self.out.push(json!({ "broken": self.conn }));
        self.host_sees_close(None);
        match self.flow.as_mut() {
            Some(flow) => flow.on_closed(None),
            None => Vec::new(),
        }
    }

    fn host_sees_close(&mut self, code: Option<ErrorCode>) {
        let (conn, now) = (ConnectionId(self.conn), self.now);
        if let Some(i) = self.host {
            let h = &mut self.hosts[i];
            h.grants.unbind(conn);
            let actions = h
                .machine
                .on_connection_closed(conn, code, &mut h.grants, now);
            let _ = self.host_did(actions);
        }
    }

    /// Log the host's actions; return its messages for the joiner's
    /// connection.
    fn host_did(&mut self, actions: Vec<DirectHostAction>) -> Vec<ControlMessage> {
        let Some(i) = self.host else {
            return Vec::new();
        };
        let name = self.hosts[i].name.clone();
        let mut to_joiner = Vec::new();
        for a in actions {
            if let Some(gate) = self.host_gate.as_mut().filter(|g| g.conn().0 == self.conn) {
                match &a {
                    DirectHostAction::AdmittedJoinOnly { conn, invitation }
                        if conn.0 == self.conn =>
                    {
                        gate.admit_join_only(*invitation)
                    }
                    DirectHostAction::Enrolled {
                        conn,
                        grant,
                        attempt,
                        ..
                    } if conn.0 == self.conn => gate.bind_direct(*grant, true, *attempt),
                    DirectHostAction::Bound {
                        conn,
                        grant,
                        provisional,
                    } if conn.0 == self.conn => gate.bind_direct(*grant, *provisional, None),
                    DirectHostAction::Committed { bound, .. }
                        if bound.iter().any(|c| c.0 == self.conn) =>
                    {
                        gate.committed()
                    }
                    DirectHostAction::MissHold { conn, .. } if conn.0 == self.conn => gate.hold(),
                    DirectHostAction::Close { conn, code } if conn.0 == self.conn => {
                        gate.close(*code)
                    }
                    _ => {}
                }
            }
            match a {
                DirectHostAction::Send { conn, message } if conn.0 == self.conn => {
                    if !self.open {
                        continue;
                    }
                    self.sent(&name, &message);
                    to_joiner.push(message);
                }
                DirectHostAction::Close { conn, code } if conn.0 == self.conn && self.open => {
                    self.out.push(
                        json!({ "close": { "from": name, "conn": conn.0, "code": code.name() } }),
                    );
                    to_joiner.push(close_marker(code));
                }
                DirectHostAction::Committed { conn, grant, .. } if conn.0 == self.conn => {
                    self.out
                        .push(json!({ "committed": { "conn": conn.0, "grant": grant.0 } }));
                }
                DirectHostAction::MissHold { conn, hold_ms } if conn.0 == self.conn => {
                    // The I/O layer holds the connection, then closes it.
                    self.out
                        .push(json!({ "miss_hold": { "conn": conn.0, "hold_ms": hold_ms } }));
                    self.out.push(json!({ "close": {
                        "from": name, "conn": conn.0, "code": ErrorCode::InvitationInvalid.name(),
                    } }));
                    to_joiner.push(close_marker(ErrorCode::InvitationInvalid));
                }
                _ => {}
            }
        }
        to_joiner
    }

    /// Paired, the joiner's app opens its first stream on the connection,
    /// if it is still up and its own gate is live: the host's gate holds it
    /// until the host commits the provisional grant (wire.md 8.1).
    fn first_stream(&mut self) {
        let Some(i) = self.host else {
            return;
        };
        if !self.open || !self.caller_gate.as_ref().is_some_and(|g| g.is_live()) {
            return;
        }
        let (conn, now) = (ConnectionId(self.conn), self.now);
        let verdict = self
            .host_gate
            .as_mut()
            .expect("the host's gate")
            .check(Traffic::Stream);
        let name = match verdict {
            Verdict::Allow => "allow",
            Verdict::Commit(_) => "commit",
            Verdict::Ignore => "ignore",
            Verdict::Close(_) => "close",
        };
        self.out
            .push(json!({ "stream": { "conn": self.conn, "verdict": name } }));
        match verdict {
            Verdict::Commit(grant) => {
                let h = &mut self.hosts[i];
                let actions = h.machine.on_first_stream(conn, grant, &mut h.grants, now);
                let _ = self.host_did(actions);
                if self.open {
                    let again = self
                        .host_gate
                        .as_mut()
                        .expect("the host's gate")
                        .check(Traffic::Stream);
                    assert_eq!(again, Verdict::Allow, "the frame passes after the commit");
                }
            }
            Verdict::Close(code) => {
                let to_joiner = self.host_did(vec![DirectHostAction::Close { conn, code }]);
                let _ = to_joiner;
            }
            Verdict::Allow | Verdict::Ignore => {}
        }
    }

    /// The joiner's message reaches the host.
    fn deliver_to_host(&mut self, m: &ControlMessage) -> Vec<ControlMessage> {
        let Some(i) = self.host else {
            return Vec::new();
        };
        if self.silent && matches!(m, ControlMessage::JoinDirect { .. }) {
            // A silent host: the message is never answered.
            return Vec::new();
        }
        let (conn, now, joiner) = (ConnectionId(self.conn), self.now, self.joiner_key);
        let verdict = self
            .host_gate
            .as_mut()
            .expect("the host's gate")
            .check_message(m);
        match verdict {
            Verdict::Allow => {}
            Verdict::Close(code) => {
                return self.host_did(vec![DirectHostAction::Close { conn, code }]);
            }
            _ => {
                self.out
                    .push(json!({ "gate": { "conn": self.conn, "verdict": "ignore" } }));
                return Vec::new();
            }
        }
        let h = &mut self.hosts[i];
        let exporter = pair_exporter(self.conn);
        let actions = match m {
            ControlMessage::JoinDirect {
                lookup,
                name,
                recovery,
            } => h.machine.on_join_direct(
                conn,
                &joiner,
                &exporter,
                lookup,
                name,
                *recovery,
                &mut h.grants,
                now,
            ),
            ControlMessage::CodeExchange { attempt, payload } => h
                .machine
                .on_code_exchange(conn, *attempt, payload, now, &mut h.rng),
            ControlMessage::CodeAbort { attempt, code } => {
                h.machine
                    .on_code_abort(conn, *attempt, *code, &mut h.grants, now)
            }
            other => panic!("unexpected {other:?}"),
        };
        self.host_did(actions)
    }

    /// Run the joiner's actions and the messages they cause, in order,
    /// until both sides are quiet.
    fn pump(&mut self, actions: Vec<DirectJoinerAction>) {
        let mut queue: VecDeque<DirectJoinerAction> = actions.into();
        let mut inbox: VecDeque<ControlMessage> = VecDeque::new();
        loop {
            if self.flow.is_none() {
                // The app stopped: nothing more of it runs.
                break;
            }
            if let Some(a) = queue.pop_front() {
                let more = self.joiner_does(a, &mut inbox);
                for m in more.into_iter().rev() {
                    queue.push_front(m);
                }
                continue;
            }
            let Some(m) = inbox.pop_front() else {
                break;
            };
            if self.flow.is_none() || !self.open {
                continue;
            }
            let more = self.joiner_receives(m);
            queue.extend(more);
        }
    }

    fn joiner_does(
        &mut self,
        a: DirectJoinerAction,
        inbox: &mut VecDeque<ControlMessage>,
    ) -> Vec<DirectJoinerAction> {
        match a {
            DirectJoinerAction::Send(m) => {
                if !self.open {
                    return Vec::new();
                }
                if matches!(m, ControlMessage::CodeExchange { .. }) {
                    self.exchanges_sent += 1;
                    if self.exchanges_sent == 2 && self.lose.as_deref() == Some("msg_c") {
                        // The confirmation never reaches the host.
                        return self.break_connection();
                    }
                }
                self.sent("joiner", &m);
                if matches!(m, ControlMessage::JoinDirect { .. }) {
                    if let Some(gate) = self.caller_gate.as_mut() {
                        gate.sent_join_proof();
                    }
                }
                let replies = self.deliver_to_host(&m);
                if self.exchanges_sent == 2
                    && matches!(m, ControlMessage::CodeExchange { .. })
                    && self.crash.as_deref() == Some("after_msg_c")
                {
                    // The app stops: the flow is gone, the connection breaks.
                    self.flow = None;
                    // The OS gives the dead app's hold back.
                    self.store.held = false;
                    self.out.push(json!({ "crash": true }));
                    let _ = self.break_connection();
                    return Vec::new();
                }
                inbox.extend(replies);
                Vec::new()
            }
            DirectJoinerAction::Close(code) => {
                if !self.open {
                    return Vec::new();
                }
                let conn = self.conn;
                self.out.push(
                    json!({ "close": { "from": "joiner", "conn": conn, "code": code.name() } }),
                );
                self.open = false;
                self.host_sees_close(Some(code));
                Vec::new()
            }
            DirectJoinerAction::AcquireHold(lookup) => {
                if self.store.held || self.store.held_elsewhere {
                    self.out.push(json!({ "hold_refused": lookup.as_str() }));
                    return self
                        .flow
                        .as_mut()
                        .map(|f| f.on_hold_refused())
                        .unwrap_or_default();
                }
                self.store.held = true;
                self.out.push(json!({ "hold": lookup.as_str() }));
                let (ledger, pending, now) = (
                    self.store.ledger.clone(),
                    self.store.pending.clone(),
                    self.now,
                );
                self.flow
                    .as_mut()
                    .map(|f| f.on_records(ledger.as_ref(), &pending, now))
                    .unwrap_or_default()
            }
            DirectJoinerAction::ReleaseHold(lookup) => {
                assert!(self.store.held, "a release without the hold");
                self.store.held = false;
                self.out.push(json!({ "release": lookup.as_str() }));
                Vec::new()
            }
            DirectJoinerAction::PersistLedger { .. }
            | DirectJoinerAction::PersistPending { .. }
                if std::mem::take(&mut self.store.fail_next) =>
            {
                self.out.push(json!({ "write_failed": true }));
                self.flow
                    .as_mut()
                    .map(|f| f.on_persist_failed())
                    .unwrap_or_default()
            }
            DirectJoinerAction::PersistLedger { expected, record } => {
                assert!(self.store.held, "a write without the hold");
                assert_eq!(self.store.ledger, expected, "ledger compare-and-swap");
                self.out.push(json!({ "persist_ledger": {
                    "expected": expected.as_ref().map(|l| hex(&l.to_bytes())),
                    "record": hex(&record.to_bytes()),
                } }));
                self.store.ledger = Some(record);
                self.flow
                    .as_mut()
                    .map(|f| f.on_persisted())
                    .unwrap_or_default()
            }
            DirectJoinerAction::PersistPending { expected, record } => {
                assert!(self.store.held, "a write without the hold");
                let address = expected
                    .as_ref()
                    .or(record.as_ref())
                    .map(|p| p.address)
                    .expect("a record");
                assert!(
                    record.as_ref().is_none_or(|r| r.address == address),
                    "one address per write"
                );
                assert_eq!(
                    self.store.pending_at(&address),
                    expected.as_ref(),
                    "pending compare-and-swap"
                );
                self.out.push(json!({ "persist_pending": {
                    "expected": expected.as_ref().map(|p| hex(&p.to_bytes())),
                    "record": record.as_ref().map(|p| hex(&p.to_bytes())),
                } }));
                self.store.pending.retain(|p| p.address != address);
                self.store.pending.extend(record);
                self.flow
                    .as_mut()
                    .map(|f| f.on_persisted())
                    .unwrap_or_default()
            }
            DirectJoinerAction::CodePassed => {
                self.out.push(json!({ "joiner": "code_passed" }));
                Vec::new()
            }
            DirectJoinerAction::Paired(p) => {
                self.out.push(json!({ "joiner": { "paired": {
                    "host": hex(p.identity.as_bytes()),
                    "name": p.name,
                    "role": p.role.as_str(),
                    "invitation": hex(&p.invitation.0),
                    "address": p.address.to_text(),
                } } }));
                self.store.pins.push((p.identity, p.invitation));
                if let Some(gate) = self.caller_gate.as_mut() {
                    gate.promote_direct();
                    gate.promote();
                }
                self.flow
                    .as_mut()
                    .map(|f| f.on_pin_stored())
                    .unwrap_or_default()
            }
            DirectJoinerAction::Away => {
                self.out.push(json!({ "joiner": "away" }));
                Vec::new()
            }
            DirectJoinerAction::Ended(end) => {
                let paired = matches!(end, DirectEnd::Paired);
                self.out
                    .push(json!({ "joiner": { "ended": end_name(end) } }));
                if paired {
                    self.first_stream();
                }
                Vec::new()
            }
        }
    }

    fn joiner_receives(&mut self, m: ControlMessage) -> Vec<DirectJoinerAction> {
        let now = self.now;
        if let Some(code) = closed_code(&m) {
            self.open = false;
            return self
                .flow
                .as_mut()
                .map(|f| f.on_closed(Some(code)))
                .unwrap_or_default();
        }
        if self.hold_host_sends {
            self.in_transit.push(m);
            return Vec::new();
        }
        if self.lose.as_deref() == Some("paired") && matches!(m, ControlMessage::Paired { .. }) {
            return self.break_connection();
        }
        if let Some(gate) = self.caller_gate.as_mut() {
            match gate.check(CallerTraffic::of(&m)) {
                Verdict::Allow => {}
                Verdict::Close(code) => {
                    let conn = self.conn;
                    self.out.push(
                        json!({ "close": { "from": "joiner", "conn": conn, "code": code.name() } }),
                    );
                    self.open = false;
                    self.host_sees_close(Some(code));
                    return self
                        .flow
                        .as_mut()
                        .map(|f| f.on_closed(Some(code)))
                        .unwrap_or_default();
                }
                _ => return Vec::new(),
            }
        }
        let rng = &mut self.joiner_rng;
        let Some(flow) = self.flow.as_mut() else {
            return Vec::new();
        };
        match m {
            ControlMessage::Authorized { state } => flow.on_authorized(state),
            ControlMessage::AuthorizedDirect {
                invitation,
                not_received,
            } => flow.on_authorized_direct(invitation, not_received, now, rng),
            ControlMessage::CodeExchange { attempt, payload } => {
                flow.on_code_exchange(attempt, &payload, now)
            }
            ControlMessage::CodeAbort { attempt, .. } => flow.on_code_abort(attempt),
            ControlMessage::Paired { host_name, role } => flow.on_paired(host_name, role),
            other => panic!("unexpected {other:?}"),
        }
    }

    fn start(&mut self, step: &J) -> Result<(), String> {
        let code = match step["code"].as_str().expect("code") {
            "right" => self.real().code.to_display().to_string(),
            "wrong" => {
                let mut c = self.real().code.as_str().to_owned();
                let wrong = if c.ends_with("00000000") {
                    "00000001"
                } else {
                    "00000000"
                };
                c.replace_range(4.., wrong);
                c
            }
            "other_lookup" => {
                let mut c = self.real().code.as_str().to_owned();
                let other = if c.starts_with("0000") {
                    "0001"
                } else {
                    "0000"
                };
                c.replace_range(..4, other);
                c
            }
            "typed" => TYPED.to_owned(),
            other => panic!("code {other}"),
        };
        self.address = step["address"].as_str().unwrap_or(ADDRESS).to_owned();
        self.store.held_elsewhere = step["held_elsewhere"].as_bool().unwrap_or(false);
        let flow = DirectJoinerPairing::new(
            &self.address,
            &code,
            self.joiner_key,
            JOINER_NAME,
            CpaceExchangeFactory,
        )
        .map_err(|e| e.name().to_owned())?;
        self.begin(flow)
    }

    /// A new flow asks for the hold and gets its records; it ends there if
    /// they refuse it.
    fn begin(&mut self, mut flow: DirectJoinerPairing<CpaceExchangeFactory>) -> Result<(), String> {
        let actions = flow.start();
        self.flow = Some(flow);
        self.pump(actions);
        self.store.held_elsewhere = false;
        match self.flow.as_ref().map(|f| f.state()) {
            Some(DirectJoinerState::Ended(end)) => Err(end_name(end)),
            _ => Ok(()),
        }
    }

    fn connect(&mut self, step: &J) {
        self.conn = step["conn"].as_u64().expect("conn");
        self.open = true;
        self.exchanges_sent = 0;
        self.lose = step["lose"].as_str().map(str::to_owned);
        self.crash = step["crash"].as_str().map(str::to_owned);
        self.silent = step["silent"].as_bool().unwrap_or(false);
        let exporter = pair_exporter(self.conn);
        if self.flow.as_ref().map(|f| f.state()) == Some(DirectJoinerState::Away) {
            // Going on from away: the hold and the records first.
            self.store.held_elsewhere = step["held_elsewhere"].as_bool().unwrap_or(false);
            let actions = self.flow.as_mut().expect("a flow").start();
            self.pump(actions);
            self.store.held_elsewhere = false;
            if self.flow.as_ref().map(|f| f.state()) != Some(DirectJoinerState::Connecting) {
                self.open = false;
                return;
            }
        }
        let pinned = self.flow.as_ref().and_then(|f| f.pinned_host()).is_some();
        self.caller_gate = Some(if pinned {
            CallerGate::new()
        } else {
            CallerGate::pairing_only()
        });
        let who = step["host"].as_str().expect("host");
        let key = if who == "own" {
            self.host = None;
            self.joiner_key
        } else {
            let i = self.host_index(who);
            self.host = Some(i);
            self.hosts[i].key
        };
        // A recovery's TLS is pinned to the stored host key: another key
        // fails the dial, as does an unreachable address.
        let pin = self.flow.as_ref().and_then(|f| f.pinned_host());
        if step["unreachable"].as_bool().unwrap_or(false) || pin.is_some_and(|p| p != key) {
            self.open = false;
            self.out.push(json!({ "dial_failed": self.conn }));
            let actions = self.flow.as_mut().expect("a flow").on_dial_failed();
            self.pump(actions);
            return;
        }
        let actions = self
            .flow
            .as_mut()
            .expect("a flow")
            .on_connected(key, exporter);
        self.pump(actions);
        if !self.open || self.host.is_none() {
            return;
        }
        // Step 2 on the host, with its gate: a provisional or live grant
        // binds the connection and the host says AUTHORIZED {live} first.
        let i = self.host.expect("host");
        let (conn, now, joiner) = (ConnectionId(self.conn), self.now, self.joiner_key);
        let gate = ConnectionGate::open(conn, joiner, &mut self.hosts[i].grants, now, Millis(0));
        let live = matches!(gate.state(), GateState::Live { .. });
        self.host_gate = Some(gate);
        let mut inbox = Vec::new();
        if live {
            let m = ControlMessage::Authorized {
                state: AuthorizedState::Live,
            };
            let name = self.hosts[i].name.clone();
            self.sent(&name, &m);
            inbox.push(m);
        }
        let minor = step["minor"].as_u64().unwrap_or(DIRECT_MINOR_VERSION);
        let agreed = minor.min(DIRECT_MINOR_VERSION);
        let mut actions = self.flow.as_mut().expect("a flow").on_hello(agreed);
        // Step 2's notice arrives after the HELLO and before the answer.
        for m in inbox {
            actions.extend(self.joiner_receives(m));
        }
        self.pump(actions);
        if self.silent
            && self.flow.as_ref().map(|f| f.state()) == Some(DirectJoinerState::AwaitingAnswer)
        {
            // 10 s pass with no answer (wire.md 8.2).
            self.out.push(json!({ "answer_timeout": self.conn }));
            let actions = self.flow.as_mut().expect("a flow").on_answer_timeout();
            self.pump(actions);
        }
    }

    fn owner(&mut self, step: &J, allow: bool) {
        let request = DirectRequestId {
            invitation: self.hosts[0].invitation,
            identity: self.joiner_key,
        };
        let now = self.now;
        let h = &mut self.hosts[0];
        let actions = if allow {
            h.machine.allow(&request, None, &mut h.grants, now)
        } else {
            h.machine.decline(&request, now)
        }
        .expect("the owner's answer");
        let host = self.host;
        self.host = Some(0);
        if let Some(lose) = step["lose"].as_str() {
            self.lose = Some(lose.to_owned());
        }
        self.hold_host_sends = step["in_transit"].as_bool().unwrap_or(false);
        let to_joiner = self.host_did(actions);
        let mut answered = Vec::new();
        for m in to_joiner {
            if self.open {
                answered.extend(self.joiner_receives(m));
            }
        }
        self.hold_host_sends = false;
        self.pump(answered);
        if host.is_some() {
            self.host = host;
        }
    }

    fn step(&mut self, step: &J) -> Option<String> {
        if let Some(at) = step["at"].as_u64() {
            self.now = UnixTime(T + at);
        }
        match step["op"].as_str().expect("op") {
            "start" => {
                return Some(match self.start(step) {
                    Ok(()) => "ok".into(),
                    Err(e) => e,
                })
            }
            "resume" => {
                self.address = step["address"].as_str().unwrap_or(ADDRESS).to_owned();
                let address = DirectAddress::parse(&self.address).expect("address");
                let lookup = self.hosts[0].code.lookup();
                let flow = DirectJoinerPairing::resume(
                    address,
                    lookup,
                    self.joiner_key,
                    JOINER_NAME,
                    CpaceExchangeFactory,
                    &crate::limits::Limits::DEFAULT,
                );
                return Some(match flow {
                    Ok(flow) => match self.begin(flow) {
                        Ok(()) => "ok".into(),
                        Err(e) => e,
                    },
                    Err(e) => e.name().into(),
                });
            }
            "stored_ledger" => {
                // A ledger written earlier: `first_debit` is seconds before
                // the conventions' time.
                let ago = step["first_debit_ago"].as_u64().expect("first_debit_ago");
                self.store.ledger = Some(DirectLedger {
                    lookup: self.hosts[0].code.lookup(),
                    attempts_left: u8::try_from(step["attempts_left"].as_u64().expect("left"))
                        .expect("u8"),
                    first_debit: UnixTime(T - ago),
                });
            }
            "fail_next_write" => self.store.fail_next = true,
            "park" => {
                let flow = self.flow.take().expect("a flow");
                let name = step["as"].as_str().expect("as").to_owned();
                self.parked.insert(name, (flow, self.address.clone()));
            }
            "unpark" => {
                let name = step["flow"].as_str().expect("flow");
                let (flow, address) = self.parked.remove(name).expect("a parked flow");
                self.flow = Some(flow);
                self.address = address;
            }
            "connect" => self.connect(step),
            "allow" => self.owner(step, true),
            "decline" => self.owner(step, false),
            "drop" => {
                let actions = self.break_connection();
                self.pump(actions);
            }
            "cancel" => {
                let actions = self
                    .flow
                    .as_mut()
                    .expect("a flow")
                    .cancel()
                    .expect("cancel");
                if step["held_elsewhere"].as_bool().unwrap_or(false) {
                    self.store.held_elsewhere = true;
                }
                self.pump(actions);
                // What the host sent before the cancel reached it arrives
                // now, after the joiner's cancel.
                for m in std::mem::take(&mut self.in_transit) {
                    self.out
                        .push(json!({ "arrives_after_cancel": hex(&m.encode()) }));
                    let actions = match (self.flow.as_mut(), m) {
                        (Some(flow), ControlMessage::Paired { host_name, role }) => {
                            flow.on_paired(host_name, role)
                        }
                        _ => Vec::new(),
                    };
                    let was_open = self.open;
                    self.open = true;
                    self.pump(actions);
                    self.open = was_open;
                }
                self.store.held_elsewhere = false;
            }
            other => panic!("op {other}"),
        }
        None
    }
}

fn pair_exporter(conn: u64) -> [u8; 32] {
    [conn as u8 + 100; 32]
}

/// A host close travels in the joiner's inbox as this marker.
fn close_marker(code: ErrorCode) -> ControlMessage {
    ControlMessage::CodeAbort {
        attempt: crate::pairing::AttemptId([0xff; 16]),
        code,
    }
}

fn closed_code(m: &ControlMessage) -> Option<ErrorCode> {
    match m {
        ControlMessage::CodeAbort { attempt, code } if attempt.0 == [0xff; 16] => Some(*code),
        _ => None,
    }
}

fn run_sequence(seq: &J, listed: Option<&J>) -> J {
    let name = seq["name"].as_str().expect("name");
    let mut w = World::new(listed);
    let mut steps = Vec::new();
    for (i, step) in seq["steps"].as_array().expect("steps").iter().enumerate() {
        let ctx = format!("{name} step {i}");
        w.out.clear();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| w.step(step)))
            .unwrap_or_else(|_| panic!("{ctx}"));
        if let Some(r) = result {
            assert_eq!(step["result"].as_str(), Some(r.as_str()), "{ctx}: result");
        }
        if let Some(s) = step["state"].as_str() {
            assert_eq!(
                state_name(w.flow.as_ref().map(|f| f.state())),
                s,
                "{ctx}: state"
            );
        }
        if let Some(l) = step.get("ledger") {
            let got = w.store.ledger.as_ref().map(|l| u64::from(l.attempts_left));
            assert_eq!(got, l.as_u64(), "{ctx}: ledger");
        }
        if let Some(p) = step.get("pending") {
            let address = DirectAddress::parse(&w.address).expect("address");
            let got =
                w.store
                    .pending_at(&address)
                    .map(|p| if p.cancelled { "cancelled" } else { "pending" });
            assert_eq!(got, p.as_str(), "{ctx}: pending");
        }
        if let Some(list) = step["pendings"].as_array() {
            let mut got: Vec<J> = w
                .store
                .pending
                .iter()
                .map(|p| {
                    json!([
                        p.address.to_text(),
                        if p.cancelled { "cancelled" } else { "pending" }
                    ])
                })
                .collect();
            got.sort_by_key(|v| v.to_string());
            assert_eq!(&got, list, "{ctx}: pendings");
        }
        if let Some(h) = step["held"].as_bool() {
            assert_eq!(w.store.held, h, "{ctx}: held");
        }
        if let Some(p) = step["pinned"].as_bool() {
            assert_eq!(!w.store.pins.is_empty(), p, "{ctx}: pinned");
        }
        if let Some(g) = step.get("granted") {
            let (joiner, now) = (w.joiner_key, w.now);
            let invitation = w.hosts[0].invitation;
            let grants = &w.hosts[0].grants;
            let made = |g: &crate::grants::Grant| g.direct && g.enrolled_by == Some(invitation);
            let got = if grants.live_grant(&joiner, now).is_some_and(made) {
                Some("committed")
            } else if grants.provisional_grant(&joiner, now).is_some_and(made) {
                Some("provisional")
            } else {
                None
            };
            assert_eq!(got, g.as_str(), "{ctx}: granted");
        }
        let mut recorded = step.clone();
        recorded["out"] = J::Array(std::mem::take(&mut w.out));
        steps.push(recorded);
    }
    let mut draws = serde_json::Map::new();
    assert!(
        w.joiner_rng.script.is_empty(),
        "{name}: unused joiner draws"
    );
    draws.insert("joiner".into(), J::Array(w.joiner_rng.log.clone()));
    for h in &w.hosts {
        assert!(
            h.rng.inner.script.is_empty(),
            "{name}: unused draws of {}",
            h.name
        );
        draws.insert(h.name.clone(), J::Array(h.rng.inner.log.clone()));
    }
    let mut out = seq.clone();
    out["code"] = json!(w.hosts[0].code.to_display().as_str());
    out["draws"] = J::Object(draws);
    out["steps"] = J::Array(steps);
    out
}

/// Both record formats with times above 2^53 - 1: a reader keeps every
/// bit of the uint.
fn records() -> J {
    let lookup = DirectLookup::from_canonical("K7QM").expect("lookup");
    let big = UnixTime((1u64 << 53) + 1);
    let ledger = DirectLedger {
        lookup: lookup.clone(),
        attempts_left: 3,
        first_debit: big,
    };
    let pending = DirectPending {
        lookup,
        host: identity(&IDENTITY_A).public_key(),
        invitation: InvitationId([0x49; 16]),
        address: DirectAddress::parse("[fe80::1]:47100").expect("address"),
        verified_at: UnixTime(u64::MAX),
        cancelled: true,
        attempt: AttemptId([0x41; 16]),
    };
    json!([
        { "kind": "ledger", "lookup": "K7QM", "attempts_left": 3, "first_debit": big.0.to_string(), "bytes": hex(&ledger.to_bytes()) },
        { "kind": "pending", "lookup": "K7QM", "host": hex(pending.host.as_bytes()), "invitation": hex(&[0x49; 16]), "address": "[fe80::1]:47100", "verified_at": u64::MAX.to_string(), "cancelled": true, "attempt": hex(&[0x41; 16]), "bytes": hex(&pending.to_bytes()) },
    ])
}

pub(super) fn direct_joiner_vectors() -> J {
    let sequences: Vec<J> = sequences().iter().map(|s| run_sequence(s, None)).collect();
    json!({
        "description": "Pair with IP end to end (wire.md 10.9): the joiner machine against the host machine of direct-host.json, with the real code exchange, replayed byte for byte from the listed draws. Each sequence starts with the real host (`host`) holding one invitation created at `conventions.time` (`code`). Ops: start (the person types `conventions.address` and a code: right, wrong (the right lookup, secret 00000000 or 00000001), other_lookup (lookup 0000 or 0001, the right secret), typed (`conventions.typed`); `result` ok or the refusal, before any dial), `address` (default `conventions.address`) is the typed address, and with `held_elsewhere` another flow holds the lookup for that step only), resume (a new flow for the pending record stored at `address`, no code), connect (from away, the flow first takes the hold and reloads its records, and dials nothing when the hold is refused (with `held_elsewhere` another flow holds it for that step); then TLS with `host` on `conn`, pinned to the stored host key on a recovery: another key fails the dial, as does `unreachable`, listed as dial_failed; the joiner sees the far end's key, then the host's step 2 runs with its gate, then the host's HELLO agrees on min(`minor`, 4) (default 4); `own` shows the joiner's own key; `lose` msg_c breaks the connection instead of delivering the joiner's confirmation; `crash` after_msg_c stops the joiner's app right after its confirmation reached the host and breaks the connection, and its hold goes; `silent`: the host never answers JOIN_DIRECT and the joiner's answer timeout runs within the step, as if its 10 s had passed; the step's clock does not move), allow and decline (the real host's owner answers the joiner's request; `lose` paired breaks the connection instead of delivering PAIRED; with `in_transit` the host's messages stay on their way until the next cancel), drop (the connection breaks), cancel (the person cancels, with `held_elsewhere` while another flow holds the lookup for that step; host messages in transit then arrive), stored_ledger (a ledger stored before the sequence: `attempts_left`, first debit `first_debit_ago` seconds before `conventions.time`), fail_next_write (the next write the joiner asks for fails), park (the current flow is set aside under `as`; ops then act on no flow until the next start, resume or unpark), unpark (flow `flow` is the current one again). The store keeps one ledger per typed lookup, one pending record per typed lookup and address, and the lookup's hold: a flow asks for it (`hold`, or `hold_refused` when another flow has it) and gets the records loaded under it, and gives it back (`release`); every write needs it. Every write the joiner asks for otherwise lands at once (compare-and-swap checked against the record at its address), and every pin is stored at once. Every message passes the receiving side's gate: the host's (wire.md 8.1; `gate` ignore when it drops one) and the joiner's (8.2, pairing-only on a first contact, pinned on a recovery); the joiner's app opens its first stream only when its gate is live. A host's miss hold is shown with the close the I/O layer makes after it. Expectations: `state` (the joiner flow's), `ledger` (attempts left in the stored ledger, or null), `pending` (the pending record stored at the flow's typed address: pending, cancelled or null), `pendings` (every stored pending record: address and state, sorted by address text), `held` (the lookup's hold is taken), `pinned` (the joiner stored a pin), `granted` (a grant the real host's direct invitation made for the joiner: committed, provisional or null). Once the joiner ends paired and its connection is still up, its app opens the first stream there, and the host commits the provisional grant before the stream goes on. `out`: in order, control messages (`send`), closes (`close`, with who closed), miss holds, broken connections, the joiner's writes (`persist_ledger`, `persist_pending`: expected and new record bytes, null for none), what the joiner tells its UI (`code_passed`, `paired`, `away`, `ended`), the app's first stream (`stream`, with the host gate's verdict) and the host's commit (`committed`), the hold (`hold`, `hold_refused`, `release`), a failed dial (`dial_failed`), a failed write (`write_failed`), an answer timeout, a crash, and host messages that arrive after a cancel. HELLOs are not listed. `records`: both record formats (the pending record with the attempt that passed) with times above 2^53 - 1 (as decimal strings), each with its canonical bytes; a reader keeps the whole uint and writes the same bytes back.",
        "conventions": {
            "time": T,
            "address": ADDRESS,
            "typed": TYPED,
            "joiner": { "identity_secret": hex(&JOINER_SECRET), "name": JOINER_NAME },
            "hosts": "`host`: identity secret 0x11 repeated, name Desk, role owner, authorizing owner 0x51 repeated, the default limits. Fake host n (`fake1`, ...): identity secret 0x30 + its index (1 for the first fake) repeated; its invitation has the typed lookup and another secret, and is created when a step first names the fake host, before any TLS (also when that dial fails).",
            "exporters": "On connection n both ends see the pair exporter n + 100 repeated 32 times.",
            "draws": "Each party's random values in the order it takes them. Hosts: the invitation id (16), the code (12), then each attempt's yb (32), as in direct-host.json. Joiner: for each attempt the attempt id (16) and ya (32).",
        },
        "sequences": sequences,
        "records": records(),
    })
}

#[test]
fn direct_joiner_sequences_hold() {
    let text = checked_in("direct-joiner.json").expect("spec/vectors/direct-joiner.json");
    let doc: J = serde_json::from_str(&text).expect("json");
    for r in doc["records"].as_array().expect("records") {
        let bytes = unhex(r["bytes"].as_str().expect("bytes"));
        match r["kind"].as_str() {
            Some("ledger") => {
                let l = DirectLedger::from_bytes(&bytes).expect("ledger");
                assert_eq!(l.first_debit.0.to_string(), r["first_debit"]);
                assert_eq!(l.to_bytes(), bytes);
            }
            Some("pending") => {
                let p = DirectPending::from_bytes(&bytes).expect("pending");
                assert_eq!(p.verified_at.0.to_string(), r["verified_at"]);
                assert_eq!(p.to_bytes(), bytes);
            }
            other => panic!("record kind {other:?}"),
        }
    }
    for seq in doc["sequences"].as_array().expect("sequences") {
        let replayed = run_sequence(seq, Some(&seq["draws"]));
        assert_eq!(&replayed, seq, "{}", seq["name"]);
    }
}
