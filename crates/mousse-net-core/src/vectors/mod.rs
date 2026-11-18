//! Test vector generator and pairing-sequence checker.
//!
//! Every file in `spec/vectors/` (except the code-exchange ones, which have
//! their own owner) is produced here from fixed keys and times. The test
//! `vector_files_are_current` fails if a file differs from what this code
//! produces; run it with `MOUSSE_NET_WRITE_VECTORS=1` to rewrite them.
//! `tests/vectors.rs` then checks the files against the public API only.

use std::path::PathBuf;

use hkdf::Hkdf;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{json, Value as J};
use sha2::Sha256;

use crate::cbor::{self, Value};
use crate::control::{
    negotiate_version, AuthorizedState, ControlMessage, HelloOutcome, HelloState, VersionSupport,
};
use crate::grants::{GrantTable, OwnerRef, Role};
use crate::identity::{IdentityPublicKey, RawSignature, SoftwareKey};
use crate::mux::{Frame, PriorityClass, StreamId};
use crate::pairing::CpaceExchangeFactory;
use crate::pairing::{
    attempt_sid, binding_transcript, join_proof_input, join_proof_mac, AttemptId, HostAction,
    HostPairing, HostPairingError, InvitationId, InvitationKind, InvitationParams,
    InvitationStatus, JoinerAction, JoinerPairing, JoinerState, PairingCode, Route, RouteHost,
    SessionExporters, Ticket, TicketSecret, JOIN_PROOF_KEY_INFO, SID_DOMAIN, TICKET_VERSION,
};
use crate::session_cert::{
    self, build_certificate, PendingCertificate, SessionKey, ValidityWindow,
};
use crate::time::UnixTime;
use crate::{ConnectionId, ErrorCode, PROTOCOL_VERSION};

/// Base time of every vector: 2026-09-21T14:13:20Z.
const T: u64 = 1_790_000_000;
const DAY: u64 = 86_400;
const SKEW: u64 = 600;

/// The P-256 group order n, big-endian.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

const IDENTITY_A: [u8; 32] = [0x11; 32];
const IDENTITY_B: [u8; 32] = [0x22; 32];
const SESSION_1: [u8; 32] = [0x33; 32];
const SESSION_2: [u8; 32] = [0x44; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn identity(secret: &[u8; 32]) -> SoftwareKey {
    SoftwareKey::from_secret_bytes(secret).expect("fixed key")
}

fn session(secret: &[u8; 32]) -> SessionKey {
    SessionKey::from_secret_bytes(secret).expect("fixed key")
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

// ---------------------------------------------------------------------------
// Session certificates
// ---------------------------------------------------------------------------

/// A certificate whose identity signature is honest for its own SPKI and
/// window, with the given version.
fn honest_cert(id: &SoftwareKey, key: &SessionKey, nb: u64, na: u64, version: u64) -> Vec<u8> {
    let record = session_cert::session_record(&key.spki_der(), UnixTime(nb), UnixTime(na), version);
    let sig = id.sign_raw(&record);
    build_certificate(
        key,
        UnixTime(nb),
        UnixTime(na),
        version,
        id.public_key().as_bytes(),
        sig.as_bytes(),
    )
    .expect("encodable")
}

fn cert_case(
    name: &str,
    description: &str,
    cert: &[u8],
    now: u64,
    pin: Option<&IdentityPublicKey>,
    result: &str,
) -> J {
    json!({
        "name": name,
        "description": description,
        "certificate": hex(cert),
        "now": now,
        "expected_identity": pin.map(|k| hex(k.as_bytes())),
        "result": result,
    })
}

fn session_cert_vectors() -> J {
    let a = identity(&IDENTITY_A);
    let b = identity(&IDENTITY_B);
    let s1 = session(&SESSION_1);
    let s2 = session(&SESSION_2);
    let (nb, na) = (T, T + DAY);
    let window = ValidityWindow::new(UnixTime(nb), UnixTime(na)).expect("window");

    let pending = PendingCertificate::new(session(&SESSION_1), window);
    let record = pending.record().to_vec();
    let identity_signature = a.sign_raw(&record);
    let cert = pending
        .finish(a.public_key(), identity_signature)
        .expect("issue");
    let der = cert.der().to_vec();
    assert_eq!(der, honest_cert(&a, &s1, nb, na, PROTOCOL_VERSION));
    let spki = s1.spki_der();

    let tls_message = b"TLS 1.3 CertificateVerify content for the vector".to_vec();
    let tls_signature = s1.sign_tls(&tls_message);
    let wrong_tls_signature = s2.sign_tls(&tls_message);

    let pin_a = a.public_key();
    let pin_b = b.public_key();

    // The identity signs a record for session key 1, but the certificate
    // carries session key 2: the record rebuilt from the certificate differs.
    let wrong_key = build_certificate(
        &s2,
        UnixTime(nb),
        UnixTime(na),
        PROTOCOL_VERSION,
        pin_a.as_bytes(),
        identity_signature.as_bytes(),
    )
    .expect("encodable");
    let der_signature = build_certificate(
        &s1,
        UnixTime(nb),
        UnixTime(na),
        PROTOCOL_VERSION,
        pin_a.as_bytes(),
        &identity_signature.to_der(),
    )
    .expect("encodable");
    let mut bad_self = der.clone();
    let last = bad_self.len() - 1;
    bad_self[last] ^= 0x01;
    let mut off_curve = [0u8; 65];
    off_curve[0] = 0x04;
    let bad_identity_key = build_certificate(
        &s1,
        UnixTime(nb),
        UnixTime(na),
        PROTOCOL_VERSION,
        &off_curve,
        identity_signature.as_bytes(),
    )
    .expect("encodable");
    let mut trailing = der.clone();
    trailing.push(0);
    let other_endpoint = honest_cert(&b, &s2, nb, na, PROTOCOL_VERSION);

    // Error precedence. The same to-be-signed part with other signature
    // values: the profile requires strict DER; scalars out of range are a
    // self-signature error.
    let tbs = session_cert::tbs_der(
        s1.public_key().as_bytes(),
        UnixTime(nb),
        UnixTime(na),
        PROTOCOL_VERSION,
        pin_a.as_bytes(),
        identity_signature.as_bytes(),
    )
    .expect("encodable");
    // Outer header (4 bytes), tbs, the 12-byte algorithm, BIT STRING header
    // and its unused-bits byte (3 bytes), then the signature value.
    let self_der = der[4 + tbs.len() + 12 + 3..].to_vec();
    assert_eq!(
        session_cert::certificate_with_signature_value(&tbs, &self_der),
        der
    );
    let r_len = usize::from(self_der[3]);
    let s_part = &self_der[4 + r_len..];
    let with_r = |r_content: &[u8]| {
        let mut body = vec![0x02, r_content.len() as u8];
        body.extend_from_slice(r_content);
        body.extend_from_slice(s_part);
        let mut sig = vec![0x30, body.len() as u8];
        sig.extend_from_slice(&body);
        session_cert::certificate_with_signature_value(&tbs, &sig)
    };
    let mut padded_r = vec![0u8];
    padded_r.extend_from_slice(&self_der[4..4 + r_len]);
    let self_non_minimal = with_r(&padded_r);
    let mut r_order = vec![0u8];
    r_order.extend_from_slice(&P256_ORDER);
    let self_r_order = with_r(&r_order);
    let self_r_zero = with_r(&[0]);
    let compressed_identity = {
        let mut k = vec![0x02 | (pin_a.as_bytes()[64] & 1)];
        k.extend_from_slice(&pin_a.as_bytes()[1..33]);
        k
    };
    let identity_key_compressed = build_certificate(
        &s1,
        UnixTime(nb),
        UnixTime(na),
        PROTOCOL_VERSION,
        &compressed_identity,
        identity_signature.as_bytes(),
    )
    .expect("encodable");
    let identity_signature_63 = build_certificate(
        &s1,
        UnixTime(nb),
        UnixTime(na),
        PROTOCOL_VERSION,
        pin_a.as_bytes(),
        &identity_signature.as_bytes()[..63],
    )
    .expect("encodable");
    let mut zero_r = *identity_signature.as_bytes();
    zero_r[..32].fill(0);
    let identity_signature_r_zero = build_certificate(
        &s1,
        UnixTime(nb),
        UnixTime(na),
        PROTOCOL_VERSION,
        pin_a.as_bytes(),
        &zero_r,
    )
    .expect("encodable");
    let off_curve_and_der = build_certificate(
        &s1,
        UnixTime(nb),
        UnixTime(na),
        PROTOCOL_VERSION,
        &off_curve,
        &identity_signature.to_der(),
    )
    .expect("encodable");
    let version_2_off_curve =
        build_certificate(&s1, UnixTime(nb), UnixTime(na), 2, &off_curve, identity_signature.as_bytes())
            .expect("encodable");
    let short_signature_empty_window = build_certificate(
        &s1,
        UnixTime(nb),
        UnixTime(nb),
        PROTOCOL_VERSION,
        pin_a.as_bytes(),
        &identity_signature.as_bytes()[..63],
    )
    .expect("encodable");
    let empty_window_bad_self = {
        let mut c = honest_cert(&a, &s1, nb, nb, PROTOCOL_VERSION);
        let last = c.len() - 1;
        c[last] ^= 0x01;
        c
    };

    let cases = vec![
        cert_case("valid", "Valid certificate, pinned identity matches.", &der, T + 60, Some(&pin_a), "ok"),
        cert_case("valid_first_contact", "Valid certificate, no pin given (host before step 2).", &der, T + 60, None, "ok"),
        cert_case("skew_before_edge", "now = not_before - 600: still accepted.", &der, nb - SKEW, Some(&pin_a), "ok"),
        cert_case("skew_before_outside", "now = not_before - 601: outside the window.", &der, nb - SKEW - 1, Some(&pin_a), "outside_window"),
        cert_case("skew_after_edge", "now = not_after + 600: still accepted.", &der, na + SKEW, Some(&pin_a), "ok"),
        cert_case("expired", "now = not_after + 601: expired.", &der, na + SKEW + 1, Some(&pin_a), "outside_window"),
        cert_case("expired_long_ago", "An expired certificate, a day later.", &der, na + DAY, Some(&pin_a), "outside_window"),
        cert_case("pin_mismatch_on_reconnect", "Valid certificate from identity A where identity B is pinned.", &der, T + 60, Some(&pin_b), "pin_mismatch"),
        cert_case("another_endpoint_on_lan_address", "Dialling a LAN candidate for endpoint A, a valid certificate from endpoint B answers (for example another profile's helper, or another computer that took the address). Rejected before any data is sent; the caller tries the next candidate, with no warning and no change to the pin.", &other_endpoint, T + 60, Some(&pin_a), "pin_mismatch"),
        cert_case("delegation_over_wrong_tls_key", "Identity A's signature covers session key 1, but the certificate carries session key 2.", &wrong_key, T + 60, Some(&pin_a), "identity_signature_invalid"),
        cert_case("identity_signature_der", "The identity signature is DER, where 64-byte raw r||s is required.", &der_signature, T + 60, Some(&pin_a), "identity_signature_not_raw"),
        cert_case("window_too_long", "not_after - not_before = 86401 s.", &honest_cert(&a, &s1, nb, nb + DAY + 1, PROTOCOL_VERSION), T + 60, Some(&pin_a), "window_invalid"),
        cert_case("window_empty", "not_before = not_after.", &honest_cert(&a, &s1, nb, nb, PROTOCOL_VERSION), T, Some(&pin_a), "window_invalid"),
        cert_case("bad_self_signature", "Last byte of the self-signature changed.", &bad_self, T + 60, Some(&pin_a), "self_signature_invalid"),
        cert_case("unsupported_version", "Binding extension version 2.", &honest_cert(&a, &s1, nb, na, 2), T + 60, Some(&pin_a), "unsupported_version"),
        cert_case("identity_key_off_curve", "Identity key 0x04 followed by zeros.", &bad_identity_key, T + 60, Some(&pin_a), "identity_key_invalid"),
        cert_case("trailing_byte", "One byte after the certificate.", &trailing, T + 60, Some(&pin_a), "malformed"),
        cert_case("truncated", "Last byte missing.", &der[..der.len() - 1], T + 60, Some(&pin_a), "malformed"),
        cert_case("self_signature_not_strict_der", "The self-signature's r has an extra leading zero byte: not strict DER, so not the profile (check 1).", &self_non_minimal, T + 60, Some(&pin_a), "malformed"),
        cert_case("self_signature_r_is_group_order", "The self-signature's r is a well-formed INTEGER equal to the P-256 group order: out of range, a self-signature error (check 7).", &self_r_order, T + 60, Some(&pin_a), "self_signature_invalid"),
        cert_case("self_signature_r_is_zero", "The self-signature's r is a well-formed INTEGER 0: a self-signature error (check 7).", &self_r_zero, T + 60, Some(&pin_a), "self_signature_invalid"),
        cert_case("identity_key_compressed", "The identity key is the 33-byte compressed form of a valid key. Its length is not a profile check; check 3 rejects it.", &identity_key_compressed, T + 60, Some(&pin_a), "identity_key_invalid"),
        cert_case("identity_signature_63_bytes", "The identity signature is 63 bytes. Its length is not a profile check; check 5 rejects it.", &identity_signature_63, T + 60, Some(&pin_a), "identity_signature_not_raw"),
        cert_case("identity_signature_r_zero", "The identity signature is 64 bytes with r = 0. It passes check 5 and fails check 8.", &identity_signature_r_zero, T + 60, Some(&pin_a), "identity_signature_invalid"),
        cert_case("precedence_identity_key_before_signature_form", "Off-curve identity key and a DER identity signature: check 3 comes before check 5.", &off_curve_and_der, T + 60, Some(&pin_a), "identity_key_invalid"),
        cert_case("precedence_version_before_identity_key", "Version 2 and an off-curve identity key: check 2 comes before check 3.", &version_2_off_curve, T + 60, Some(&pin_a), "unsupported_version"),
        cert_case("precedence_signature_form_before_window", "A 63-byte identity signature and an empty window: check 5 comes before check 6.", &short_signature_empty_window, T, Some(&pin_a), "identity_signature_not_raw"),
        cert_case("precedence_window_before_self_signature", "An empty window and a changed self-signature: check 6 comes before check 7.", &empty_window_bad_self, T, Some(&pin_a), "window_invalid"),
    ];

    json!({
        "description": "Session certificates (spec wire.md, \"Session certificate\"). Verify each case with `now` and `expected_identity` (null = no pin) and compare the result: \"ok\" or the rejection name.",
        "valid": {
            "identity_secret": hex(&IDENTITY_A),
            "identity_public": hex(pin_a.as_bytes()),
            "session_secret": hex(&SESSION_1),
            "session_public": hex(s1.public_key().as_bytes()),
            "spki": hex(&spki),
            "serial": hex(&session_cert::serial_for(&spki)),
            "not_before": nb,
            "not_after": na,
            "version": PROTOCOL_VERSION,
            "record": hex(&record),
            "identity_signature": hex(identity_signature.as_bytes()),
            "extension_value": hex(&session_cert::binding_der(PROTOCOL_VERSION, pin_a.as_bytes(), identity_signature.as_bytes())),
            "certificate": hex(&der),
            "tls_signature": {
                "description": "CertificateVerify-style signature (DER, as TLS carries it) by the session key over `message`, and one by another key that must fail.",
                "message": hex(&tls_message),
                "signature": hex(&tls_signature),
                "wrong_key_signature": hex(&wrong_tls_signature),
            },
        },
        "other_identity_public": hex(pin_b.as_bytes()),
        "cases": cases,
        "pending": [
            {
                "name": "browser_worker_certificate",
                "status": "pending",
                "note": "A certificate issued in a browser Worker with a WebCrypto identity key. Added when the web client lands; it must verify exactly like `valid`.",
            }
        ],
    })
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

fn session_lifecycle_vectors() -> J {
    let a = identity(&IDENTITY_A);
    let peer = honest_cert(&a, &session(&SESSION_1), T, T + DAY, PROTOCOL_VERSION);
    let local_nb = T + 3_600;
    let local_na = T + 3_600 + 43_200;
    let deadline = local_na + SKEW;
    let renew_at = local_na - crate::session::RENEW_LEAD_SECS;
    json!({
        "description": "A live path closes with cert_expired at the first second after the effective deadline (earlier not_after + 600). Renewal is due 1800 s before the earlier not_after; while no new path with a later renewal time is current it is asked for again after 30 s, then 60, 120, 240 and every 300 s, until the deadline. Replay: begin_path(1), on_authenticated(1, verify(peer_certificate, authenticated_at, pin), local window, authenticated_at), on_reopened(1), then tick at each `now`.",
        "peer_certificate": hex(&peer),
        "pin": hex(a.public_key().as_bytes()),
        "local_window": { "not_before": local_nb, "not_after": local_na },
        "authenticated_at": local_nb + 60,
        "renew_at": renew_at,
        "deadline": deadline,
        "ticks": [
            { "now": renew_at - 1, "events": [] },
            { "now": renew_at, "events": [{ "event": "renew_due", "conn": 1 }] },
            { "now": renew_at + 1, "events": [] },
            { "now": renew_at + 29, "events": [] },
            { "now": renew_at + 30, "events": [{ "event": "renew_due", "conn": 1 }] },
            { "now": renew_at + 89, "events": [] },
            { "now": renew_at + 90, "events": [{ "event": "renew_due", "conn": 1 }] },
            { "now": renew_at + 210, "events": [{ "event": "renew_due", "conn": 1 }] },
            { "now": renew_at + 450, "events": [{ "event": "renew_due", "conn": 1 }] },
            { "now": renew_at + 750, "events": [{ "event": "renew_due", "conn": 1 }] },
            { "now": renew_at + 1049, "events": [] },
            { "now": renew_at + 1050, "events": [{ "event": "renew_due", "conn": 1 }] },
            { "now": deadline, "events": [{ "event": "renew_due", "conn": 1 }] },
            { "now": deadline + 1, "events": [{ "event": "close", "conn": 1, "code": "cert_expired" }] },
            { "now": deadline + 2, "events": [] },
        ],
        "switch_without_renewal": {
            "description": "A fresh replay of the same path. After the first renew_due, a new path (conn 2) comes up at `switch_at` and becomes current, but the peer has not renewed: it carries the same peer certificate and the same local window, so its renewal time is no later. The pending retries keep their schedule and waits. Replay: as above up to the tick at renew_at, then begin_path(2), on_authenticated(2, same certificate, same local window, switch_at), on_reopened(2), then tick at each `now`.",
            "switch_at": renew_at + 5,
            "ticks": [
                { "now": renew_at + 6, "events": [] },
                { "now": renew_at + 29, "events": [] },
                { "now": renew_at + 30, "events": [{ "event": "renew_due", "conn": 2 }] },
                { "now": renew_at + 89, "events": [] },
                { "now": renew_at + 90, "events": [{ "event": "renew_due", "conn": 2 }] },
                { "now": renew_at + 210, "events": [{ "event": "renew_due", "conn": 2 }] },
            ],
        },
        "new_connection_after_deadline": {
            "description": "A new connection with the same peer certificate after its own not_after + 600 fails step 1.",
            "now": T + DAY + SKEW + 1,
            "result": "outside_window",
        },
    })
}

// ---------------------------------------------------------------------------
// Authorization (step 2 and the connection gate)
// ---------------------------------------------------------------------------

fn authz_vectors() -> J {
    let a = hex(identity(&IDENTITY_A).public_key().as_bytes());
    let b = hex(identity(&IDENTITY_B).public_key().as_bytes());
    let now = T + 60;
    json!({
        "description": "Step 2 on the host after step 1 passed (`cases`), and the caller's gate (`caller_cases`). Host cases: `grants` and `denied` set up the table (grants added in order, then denials), the gate opens at wall time `now` and monotonic time 0 ms, then `steps` run in order. Caller cases: the gate starts awaiting AUTHORIZED; `promote` means the joiner accepted PAIRED; `state` is the gate state after the step. Verdicts: allow, ignore, close:<code>.",
        "identities": { "a": a, "b": b },
        "cases": [
            {
                "name": "no_grant_attempts_rpc",
                "description": "A valid identity with no grant opens a stream before any join proof: the connection closes.",
                "grants": [], "denied": [], "peer": "b", "now": now,
                "step2": "await_join_proof",
                "steps": [
                    { "op": "check", "traffic": "keepalive", "verdict": "allow" },
                    { "op": "check", "traffic": "hello", "verdict": "allow" },
                    { "op": "check", "traffic": "stream", "verdict": "close:not_authorized" },
                    { "op": "check", "traffic": "keepalive", "verdict": "ignore" },
                ],
            },
            {
                "name": "no_grant_code_exchange_before_proof",
                "grants": [], "denied": [], "peer": "b", "now": now,
                "step2": "await_join_proof",
                "steps": [{ "op": "check", "traffic": "pairing", "verdict": "close:not_authorized" }],
            },
            {
                "name": "join_proof_deadline",
                "description": "No join proof within 10 s.",
                "grants": [], "denied": [], "peer": "b", "now": now,
                "step2": "await_join_proof",
                "steps": [
                    { "op": "timeout", "mono_ms": 9_999, "result": null },
                    { "op": "timeout", "mono_ms": 10_000, "result": "not_authorized" },
                ],
            },
            {
                "name": "join_only_is_pairing_only",
                "grants": [], "denied": [], "peer": "b", "now": now,
                "step2": "await_join_proof",
                "steps": [
                    { "op": "check", "traffic": "join_proof", "verdict": "allow" },
                    { "op": "admit_join_only" },
                    { "op": "check", "traffic": "pairing", "verdict": "allow" },
                    { "op": "check", "traffic": "join_proof", "verdict": "close:protocol_error" },
                ],
            },
            {
                "name": "join_only_attempts_rpc",
                "grants": [], "denied": [], "peer": "b", "now": now,
                "step2": "await_join_proof",
                "steps": [
                    { "op": "admit_join_only" },
                    { "op": "check", "traffic": "stream", "verdict": "close:not_authorized" },
                ],
            },
            {
                "name": "live_grant",
                "grants": [{ "identity": "a", "role": "owner", "expires_at": null }], "denied": [], "peer": "a", "now": now,
                "step2": "live",
                "steps": [
                    { "op": "check", "traffic": "stream", "verdict": "allow" },
                    { "op": "check", "traffic": "join_proof", "verdict": "ignore" },
                    { "op": "check", "traffic": "pairing", "verdict": "ignore" },
                    { "op": "check", "traffic": "host_only", "verdict": "close:protocol_error" },
                ],
            },
            {
                "name": "grant_of_another_identity",
                "grants": [{ "identity": "a", "role": "owner", "expires_at": null }], "denied": [], "peer": "b", "now": now,
                "step2": "await_join_proof",
                "steps": [{ "op": "check", "traffic": "stream", "verdict": "close:not_authorized" }],
            },
            {
                "name": "grant_expired_at_this_second",
                "grants": [{ "identity": "a", "role": "client", "expires_at": now }], "denied": [], "peer": "a", "now": now,
                "step2": "await_join_proof",
                "steps": [{ "op": "check", "traffic": "stream", "verdict": "close:not_authorized" }],
            },
            {
                "name": "grant_expires_next_second",
                "grants": [{ "identity": "a", "role": "client", "expires_at": now + 1 }], "denied": [], "peer": "a", "now": now,
                "step2": "live",
                "steps": [{ "op": "check", "traffic": "stream", "verdict": "allow" }],
            },
            {
                "name": "denied_identity",
                "description": "A local denial overrides the grant (the grant is removed) and refuses at once.",
                "grants": [{ "identity": "a", "role": "owner", "expires_at": null }], "denied": ["a"], "peer": "a", "now": now,
                "step2": "close:not_authorized",
                "steps": [{ "op": "check", "traffic": "stream", "verdict": "ignore" }],
            },
        ],
        "caller_cases": [
            {
                "name": "host_stream_before_authorized",
                "description": "The host opens a stream before AUTHORIZED: the caller closes.",
                "steps": [
                    { "op": "check", "traffic": "hello", "verdict": "allow", "state": "awaiting_authorization" },
                    { "op": "check", "traffic": "keepalive", "verdict": "allow", "state": "awaiting_authorization" },
                    { "op": "check", "traffic": "stream", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
                    { "op": "check", "traffic": "authorized_live", "verdict": "ignore", "state": "closed:protocol_error" },
                ],
            },
            {
                "name": "authorized_live",
                "steps": [
                    { "op": "check", "traffic": "authorized_live", "verdict": "allow", "state": "live" },
                    { "op": "check", "traffic": "stream", "verdict": "allow", "state": "live" },
                    { "op": "check", "traffic": "pairing", "verdict": "ignore", "state": "live" },
                    { "op": "check", "traffic": "authorized_live", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
                ],
            },
            {
                "name": "pairing_before_authorized",
                "steps": [{ "op": "check", "traffic": "pairing", "verdict": "close:protocol_error", "state": "closed:protocol_error" }],
            },
            {
                "name": "paired_before_authorized",
                "steps": [{ "op": "check", "traffic": "paired", "verdict": "close:protocol_error", "state": "closed:protocol_error" }],
            },
            {
                "name": "join_only_then_paired",
                "steps": [
                    { "op": "check", "traffic": "authorized_join_only", "verdict": "allow", "state": "join_only" },
                    { "op": "check", "traffic": "pairing", "verdict": "allow", "state": "join_only" },
                    { "op": "check", "traffic": "paired", "verdict": "allow", "state": "join_only" },
                    { "op": "promote", "state": "live" },
                    { "op": "check", "traffic": "stream", "verdict": "allow", "state": "live" },
                    { "op": "check", "traffic": "paired", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
                ],
            },
            {
                "name": "join_only_host_stream",
                "steps": [
                    { "op": "check", "traffic": "authorized_join_only", "verdict": "allow", "state": "join_only" },
                    { "op": "check", "traffic": "stream", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
                ],
            },
            {
                "name": "join_only_second_authorized",
                "steps": [
                    { "op": "check", "traffic": "authorized_join_only", "verdict": "allow", "state": "join_only" },
                    { "op": "check", "traffic": "authorized_live", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
                ],
            },
            {
                "name": "join_proof_from_host",
                "steps": [
                    { "op": "check", "traffic": "authorized_live", "verdict": "allow", "state": "live" },
                    { "op": "check", "traffic": "caller_only", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
                ],
            },
        ],
    })
}

// ---------------------------------------------------------------------------
// Tickets, join proof, binding transcript
// ---------------------------------------------------------------------------

const INVITATION: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const SECRET: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const ROUTE: &str = "tcp://192.168.1.20:7443";

fn ticket(kind: InvitationKind) -> Ticket {
    Ticket {
        version: TICKET_VERSION,
        kind,
        host_identity: identity(&IDENTITY_A).public_key(),
        invitation: InvitationId(INVITATION),
        secret: TicketSecret::from_bytes(SECRET),
        expires_at: UnixTime(T + 600),
        routes: vec![ROUTE.to_owned(), "tcp://[fd00::20]:7443".to_owned()],
    }
}

fn ticket_fields(kind: u64) -> Vec<(u64, Value)> {
    vec![
        (1, Value::Uint(TICKET_VERSION)),
        (2, Value::Uint(kind)),
        (
            3,
            Value::Bytes(identity(&IDENTITY_A).public_key().as_bytes().to_vec()),
        ),
        (4, Value::Bytes(INVITATION.to_vec())),
        (5, Value::Bytes(SECRET.to_vec())),
        (6, Value::Uint(T + 600)),
        (7, Value::Array(vec![Value::Text(ROUTE.to_owned())])),
    ]
}

fn with(mut fields: Vec<(u64, Value)>, key: u64, value: Option<Value>) -> Vec<u8> {
    fields.retain(|(k, _)| *k != key);
    if let Some(v) = value {
        fields.push((key, v));
    }
    cbor::encode(&Value::Map(fields))
}

fn ticket_json(t: &Ticket) -> J {
    json!({
        "version": t.version,
        "kind": t.kind.as_u64(),
        "host_identity": hex(t.host_identity.as_bytes()),
        "invitation": hex(&t.invitation.0),
        "secret": hex(t.secret.expose()),
        "expires_at": t.expires_at.secs(),
        "routes": t.routes,
        "binary": hex(&t.encode()),
        "fragment": t.to_fragment(),
        "hash": hex(&t.hash()),
    })
}

fn ticket_vectors() -> J {
    let valid = ticket(InvitationKind::SendLink);
    let in_person = ticket(InvitationKind::InPerson);
    let base = || ticket_fields(2);
    let routes =
        |n: usize, s: &str| Value::Array((0..n).map(|_| Value::Text(s.to_owned())).collect());
    let mut off_curve = vec![0u8; 65];
    off_curve[0] = 0x04;
    let mut unsorted = cbor::encode(&Value::Map(base()));
    // Swap the first two entries (keys 1 and 2, one byte each plus a
    // one-byte value) so the keys are out of order.
    unsorted.swap(1, 3);
    let mut trailing = cbor::encode(&Value::Map(base()));
    trailing.push(0);
    let mut v2_unknown = base();
    v2_unknown.retain(|(k, _)| *k != 1);
    v2_unknown.push((1, Value::Uint(2)));
    v2_unknown.push((8, Value::Uint(0)));

    let binary_case = |name: &str, bytes: Vec<u8>, result: &str| json!({ "name": name, "binary": hex(&bytes), "result": result });
    let fragment = valid.to_fragment();
    json!({
        "description": "Pairing tickets (spec wire.md, \"Pairing ticket\"). `valid` gives the fields and every encoding. Rejection cases give `binary` (decode the CBOR) or `fragment` (decode base64url first). Result names: encoding, cbor, field, unsupported_version, unknown_kind.",
        "valid": ticket_json(&valid),
        "valid_in_person": ticket_json(&in_person),
        "rejections": [
            binary_case("version_2", with(base(), 1, Some(Value::Uint(2))), "unsupported_version"),
            binary_case("version_checked_first", cbor::encode(&Value::Map(v2_unknown)), "unsupported_version"),
            binary_case("kind_3", with(base(), 2, Some(Value::Uint(3))), "unknown_kind"),
            binary_case("unknown_key", with(base(), 8, Some(Value::Uint(0))), "field"),
            binary_case("missing_routes", with(base(), 7, None), "field"),
            binary_case("nine_routes", with(base(), 7, Some(routes(9, ROUTE))), "field"),
            binary_case("empty_route", with(base(), 7, Some(routes(1, ""))), "field"),
            binary_case("route_256_bytes", with(base(), 7, Some(routes(1, &"a".repeat(256)))), "field"),
            binary_case("secret_15_bytes", with(base(), 5, Some(Value::Bytes(SECRET[..15].to_vec()))), "field"),
            binary_case("invitation_17_bytes", with(base(), 4, Some(Value::Bytes([0u8; 17].to_vec()))), "field"),
            binary_case("host_identity_off_curve", with(base(), 3, Some(Value::Bytes(off_curve))), "field"),
            binary_case("expires_at_as_text", with(base(), 6, Some(Value::Text("soon".into()))), "field"),
            binary_case("keys_out_of_order", unsorted, "cbor"),
            binary_case("trailing_byte", trailing, "cbor"),
            { "name": "fragment_with_padding", "fragment": format!("{fragment}=="), "result": "encoding" },
            { "name": "fragment_with_hash", "fragment": format!("#{fragment}"), "result": "encoding" },
            { "name": "fragment_standard_alphabet", "fragment": fragment.replace('-', "+").replace('_', "/") + "+", "result": "encoding" },
        ],
        "route_hints": route_hint_vectors(),
        "joiner_freshness": {
            "description": "The joiner accepts the ticket while now < expires_at + 600.",
            "expires_at": T + 600,
            "cases": [
                { "now": T + 600 + SKEW - 1, "result": "ok" },
                { "now": T + 600 + SKEW, "result": "expired" },
            ],
        },
    })
}

fn route_hint_vectors() -> J {
    let hints = [
        "tcp://192.168.1.20:7443",
        "tcp://[fd00::20]:7443",
        "tcp://[::ffff:192.168.1.20]:1",
        "tcp://Desk-1.example.org:65535",
        "mdns:Desk",
        "mdns:Bureau d’Anaïs",
        "tcp://192.168.1.20",
        "tcp://192.168.1.20:0",
        "tcp://192.168.1.20:65536",
        "tcp://192.168.1.20:07443",
        "tcp://192.168.01.20:7443",
        "tcp://192.168.1.256:7443",
        "tcp://1.2.3:7443",
        "tcp://fd00::20:7443",
        "tcp://[fe80::1%25eth0]:7443",
        "tcp://[::ffff:192.168.01.20]:7443",
        "tcp://-desk.local:7443",
        "tcp://desk..local:7443",
        "tcp://desk.local.:7443",
        "tcp://desk_1.local:7443",
        "tcp://desk.123:7443",
        "tcp://user@desk.local:7443",
        "tcp://desk.local:7443/",
        "tcp:desk.local:7443",
        "mdns:",
        "mdns:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "mdns:a\tb",
        "ssh://desk.local",
        "ws://desk.local/x",
        "wss://desk.local/x",
        "relay:abc",
        "quic://desk.local:7443",
        "TCP://desk.local:7443",
        "desk.local:7443",
        "desk",
    ];
    let cases: Vec<J> = hints
        .iter()
        .map(|hint| {
            let result = match Route::parse(hint) {
                Ok(Route::Tcp { host, port }) => {
                    let host = match host {
                        RouteHost::Ipv4(a) => json!({ "ipv4": a.to_string() }),
                        RouteHost::Ipv6(a) => json!({ "ipv6": a.to_string() }),
                        RouteHost::Dns(name) => json!({ "dns": name }),
                    };
                    json!({ "tcp": { "host": host, "port": port } })
                }
                Ok(Route::Mdns { instance }) => json!({ "mdns": instance }),
                Err(skip) => json!({ "skip": skip.name() }),
            };
            json!({ "hint": hint, "result": result })
        })
        .collect();
    json!({
        "description": "Route hints (spec wire.md, \"Route hints\"). Each hint reads as a tcp route (host as ipv4, ipv6 in its shortest text form, or a lowercased dns name, and a port), an mdns instance, or is skipped with a reason: reserved, unknown_scheme or malformed.",
        "cases": cases,
    })
}

fn proof_vectors() -> J {
    let t = ticket(InvitationKind::SendLink);
    let host = identity(&IDENTITY_A).public_key();
    let joiner = identity(&IDENTITY_B).public_key();
    let join_exporter = [0xe1u8; 32];
    let pair_exporter = [0xe2u8; 32];
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&INVITATION), &SECRET)
        .expand(JOIN_PROOF_KEY_INFO.as_bytes(), &mut key)
        .expect("hkdf");
    let mac = join_proof_mac(&t.secret, &t.invitation, &host, &joiner, &join_exporter);
    let transcript =
        binding_transcript(&t.hash(), t.kind, t.version, &host, &joiner, &pair_exporter);
    let attempt = AttemptId([0xa7; 16]);
    let sid_input = cbor::encode(&Value::Map(vec![
        (1, Value::Text(SID_DOMAIN.to_owned())),
        (2, Value::Bytes(attempt.0.to_vec())),
        (3, Value::Bytes(pair_exporter.to_vec())),
    ]));
    json!({
        "description": "Join proof, binding transcript and attempt session id (spec wire.md, \"Join proof\", \"Binding transcript\" and \"Session id\"). Exporter values are fixed stand-ins for the TLS exporters.",
        "ticket_binary": hex(&t.encode()),
        "ticket_hash": hex(&t.hash()),
        "host_identity": hex(host.as_bytes()),
        "joiner_identity": hex(joiner.as_bytes()),
        "join_proof": {
            "invitation": hex(&INVITATION),
            "secret": hex(&SECRET),
            "join_exporter": hex(&join_exporter),
            "key": hex(&key),
            "input": hex(&join_proof_input(&t.invitation, &host, &joiner, &join_exporter)),
            "mac": hex(&mac),
        },
        "binding_transcript": {
            "kind": t.kind.as_u64(),
            "ticket_version": t.version,
            "pair_exporter": hex(&pair_exporter),
            "transcript": hex(transcript.as_bytes()),
        },
        "sid": {
            "attempt": hex(&attempt.0),
            "pair_exporter": hex(&pair_exporter),
            "input": hex(&sid_input),
            "sid": hex(&attempt_sid(&attempt, &pair_exporter)),
        },
    })
}

// ---------------------------------------------------------------------------
// CBOR and DER-to-raw
// ---------------------------------------------------------------------------

fn cbor_vectors() -> J {
    let valid = [
        ("0", "00"),
        ("23", "17"),
        ("24", "1818"),
        ("255", "18ff"),
        ("256", "190100"),
        ("65536", "1a00010000"),
        ("4294967296", "1b0000000100000000"),
        ("h''", "40"),
        ("h'0102'", "420102"),
        ("\"a\"", "6161"),
        ("[]", "80"),
        ("[1, [2]]", "82018102"),
        ("{}", "a0"),
        ("{1: \"x\", 2: h'00'}", "a201617802 4100"),
        ("8 nested arrays", "818181818181818100"),
    ];
    let invalid = [
        ("empty input", "", "truncated"),
        ("bytes length past end", "4201", "truncated"),
        ("24 in two bytes", "1817", "non_canonical"),
        ("255 in three bytes", "1900ff", "non_canonical"),
        ("indefinite byte string", "5f4101ff", "non_canonical"),
        ("indefinite array", "9f01ff", "non_canonical"),
        ("keys out of order", "a202010101", "unsorted_keys"),
        ("duplicate key", "a201010101", "unsorted_keys"),
        ("text key", "a1616101", "non_integer_key"),
        ("negative integer", "20", "unsupported"),
        ("tag", "c000", "unsupported"),
        ("half float", "f93c00", "unsupported"),
        ("true", "f5", "unsupported"),
        ("null", "f6", "unsupported"),
        ("bad UTF-8", "62c328", "invalid_utf8"),
        ("trailing byte", "0000", "trailing_bytes"),
        ("9 nested arrays", "81818181818181818100", "too_deep"),
    ];
    let valid: Vec<J> = valid
        .iter()
        .map(|(d, h)| {
            let h = h.replace(' ', "");
            let bytes = unhex(&h);
            let value = cbor::decode(&bytes).expect("valid vector");
            assert_eq!(cbor::encode(&value), bytes);
            json!({ "diagnostic": d, "hex": h })
        })
        .collect();
    let invalid: Vec<J> = invalid
        .iter()
        .map(|(d, h, e)| {
            let err = cbor::decode(&unhex(h)).expect_err("invalid vector");
            assert_eq!(err.code(), *e, "{d}");
            json!({ "description": d, "hex": h, "error": e })
        })
        .collect();
    json!({
        "description": "The canonical CBOR subset (spec wire.md, \"Canonical CBOR\"). Valid items decode and re-encode to the same bytes. Invalid items are rejected with the given error.",
        "valid": valid,
        "invalid": invalid,
    })
}

fn der_raw_vectors() -> J {
    let key = identity(&IDENTITY_A);
    // Deterministic signatures with interesting `r` shapes.
    let mut high = None;
    let mut short = None;
    let mut plain = None;
    for i in 0u32.. {
        let sig = key.sign_raw(format!("der-raw vector {i}").as_bytes());
        let r0 = sig.as_bytes()[0];
        let s0 = sig.as_bytes()[32];
        if r0 >= 0x80 && high.is_none() {
            high = Some(sig);
        } else if r0 == 0 && short.is_none() {
            short = Some(sig);
        } else if (0x01..0x80).contains(&r0) && (0x01..0x80).contains(&s0) && plain.is_none() {
            plain = Some(sig);
        }
        if high.is_some() && short.is_some() && plain.is_some() {
            break;
        }
    }
    let (high, short, plain) = (
        high.expect("found"),
        short.expect("found"),
        plain.expect("found"),
    );
    let ok = |name: &str, sig: &RawSignature| json!({ "name": name, "der": hex(&sig.to_der()), "raw": hex(sig.as_bytes()) });
    let bad = |name: &str, der: &str, error: &str| json!({ "name": name, "der": der.replace(' ', ""), "error": error });
    let r = "2a".repeat(32);
    let s = "3b".repeat(32);
    let raw_plain = hex(plain.as_bytes());
    json!({
        "description": "DER Ecdsa-Sig-Value to 64-byte raw r||s (spec wire.md, \"DER to raw\"). `der_to_raw` cases convert; `raw_only` cases are inputs where raw is required.",
        "der_to_raw": [
            ok("plain", &plain),
            ok("r_high_bit_needs_zero_byte", &high),
            ok("r_shorter_than_32_bytes", &short),
            bad("integer_with_extra_zero", &format!("3045 0221 00{r} 0220 {s}"), "bad_der"),
            bad("negative_integer", &format!("3044 0220 {} 0220 {s}", "ff".repeat(32)), "bad_der"),
            bad("trailing_byte", &format!("3044 0220 {r} 0220 {s} 00"), "bad_der"),
            bad("long_form_length", &format!("308144 0220 {r} 0220 {s}"), "bad_der"),
            bad("three_integers", &format!("3047 0220 {r} 0220 {s} 020101"), "bad_der"),
            bad("r_is_33_bytes", &format!("3045 0221 01{r} 0220 {s}"), "out_of_range"),
            bad("r_is_zero", &format!("3025 020100 0220 {s}"), "out_of_range"),
            bad("not_a_sequence", &format!("3144 0220 {r} 0220 {s}"), "bad_der"),
        ],
        "raw_only": [
            { "name": "raw_64_bytes", "input": raw_plain, "result": "ok" },
            { "name": "der_given_as_raw", "input": hex(&plain.to_der()), "result": "not_raw" },
            { "name": "63_bytes", "input": raw_plain[..126], "result": "not_raw" },
            { "name": "r_zero", "input": format!("{}{s}", "00".repeat(32)), "result": "out_of_range" },
        ],
    })
}

// ---------------------------------------------------------------------------
// Mux frames and control messages
// ---------------------------------------------------------------------------

fn frame_json(frame: &Frame) -> J {
    match frame {
        Frame::Data { stream, payload } => {
            json!({ "type": "data", "stream": stream.0, "payload": hex(payload) })
        }
        Frame::Open {
            stream,
            class,
            label,
        } => {
            json!({ "type": "open", "stream": stream.0, "class": *class as u8, "label": label })
        }
        Frame::Credit { stream, increment } => {
            json!({ "type": "credit", "stream": stream.0, "increment": increment })
        }
        Frame::Fin { stream } => json!({ "type": "fin", "stream": stream.0 }),
        Frame::Reset { stream, code } => {
            json!({ "type": "reset", "stream": stream.0, "code": code.as_u16() })
        }
        Frame::Ping { opaque } => json!({ "type": "ping", "opaque": hex(opaque) }),
        Frame::Pong { opaque } => json!({ "type": "pong", "opaque": hex(opaque) }),
        Frame::Control { payload } => json!({ "type": "control", "payload": hex(payload) }),
        Frame::GoAway { code } => json!({ "type": "goaway", "code": code.as_u16() }),
    }
}

fn header(stream: u32, kind: u8, len: u32) -> String {
    let mut out = stream.to_be_bytes().to_vec();
    out.push(kind);
    out.extend_from_slice(&len.to_be_bytes());
    hex(&out)
}

fn mux_vectors() -> J {
    let hello = ControlMessage::hello().encode();
    let frames = [
        Frame::Data {
            stream: StreamId(1),
            payload: b"hi".to_vec(),
        },
        Frame::Open {
            stream: StreamId(1),
            class: PriorityClass::Interactive,
            label: "rpc".into(),
        },
        Frame::Open {
            stream: StreamId(2),
            class: PriorityClass::Bulk,
            label: "files".into(),
        },
        Frame::Credit {
            stream: StreamId(3),
            increment: 65_536,
        },
        Frame::Fin {
            stream: StreamId(5),
        },
        Frame::Reset {
            stream: StreamId(7),
            code: ErrorCode::Cancelled,
        },
        Frame::Ping {
            opaque: [1, 2, 3, 4, 5, 6, 7, 8],
        },
        Frame::Pong {
            opaque: [1, 2, 3, 4, 5, 6, 7, 8],
        },
        Frame::Control { payload: hello },
        Frame::GoAway {
            code: ErrorCode::IdleTimeout,
        },
    ];
    let valid: Vec<J> = frames
        .iter()
        .map(|f| json!({ "hex": hex(&f.encode()), "frame": frame_json(f) }))
        .collect();
    let open = |class: u64, label: &str| {
        cbor::encode(&Value::Map(vec![
            (1, Value::Uint(class)),
            (2, Value::Text(label.into())),
        ]))
    };
    let with_payload = |stream: u32, kind: u8, payload: &[u8]| {
        format!(
            "{}{}",
            header(stream, kind, payload.len() as u32),
            hex(payload)
        )
    };
    // Class 0 written as 0x18 0x00 instead of 0x00.
    let open_non_canonical = [0xa2, 0x01, 0x18, 0x00, 0x02, 0x61, 0x78];
    let bad =
        |name: &str, h: String, result: &str| json!({ "name": name, "hex": h, "result": result });
    json!({
        "description": "Mux frames (spec wire.md, \"Mux framing\"). `valid` frames decode to `frame` and re-encode to `hex`. `invalid` inputs give the decode result: need_more (wait for bytes), or an error that closes the connection (too_large -> frame_too_large, others -> protocol_error).",
        "valid": valid,
        "unknown_error_code": {
            "description": "A RESET with a code this build does not know is still a valid frame.",
            "hex": header(1, 4, 2) + "03e7",
        },
        "invalid": [
            bad("header_incomplete", header(1, 0, 2)[..16].to_owned(), "need_more"),
            bad("payload_incomplete", header(1, 0, 3) + "6869", "need_more"),
            bad("unknown_type", header(1, 9, 0), "unknown_type"),
            bad("data_over_limit", header(1, 0, 65_537), "too_large"),
            bad("control_over_limit", header(0, 7, 16_385), "too_large"),
            bad("open_over_limit", header(1, 1, 257), "too_large"),
            bad("data_on_stream_0", with_payload(0, 0, b"x"), "bad_stream"),
            bad("control_on_stream_1", with_payload(1, 7, &[0xa0]), "bad_stream"),
            bad("ping_on_stream_1", with_payload(1, 5, &[0; 8]), "bad_stream"),
            bad("goaway_on_stream_1", with_payload(1, 8, &[0, 0]), "bad_stream"),
            bad("open_on_stream_0", with_payload(0, 1, &open(0, "rpc")), "bad_stream"),
            bad("empty_data", header(1, 0, 0), "bad_payload"),
            bad("empty_control", header(0, 7, 0), "bad_payload"),
            bad("ping_7_bytes", with_payload(0, 5, &[0; 7]), "bad_payload"),
            bad("credit_zero", with_payload(1, 2, &[0; 4]), "bad_payload"),
            bad("credit_3_bytes", with_payload(1, 2, &[0, 0, 1]), "bad_payload"),
            bad("fin_with_payload", with_payload(1, 3, &[0]), "bad_payload"),
            bad("reset_1_byte", with_payload(1, 4, &[0]), "bad_payload"),
            bad("open_empty_label", with_payload(1, 1, &open(0, "")), "bad_payload"),
            bad("open_label_65_bytes", with_payload(1, 1, &open(0, &"l".repeat(65))), "bad_payload"),
            bad("open_class_2", with_payload(1, 1, &open(2, "rpc")), "bad_payload"),
            bad("open_non_canonical", with_payload(1, 1, &open_non_canonical), "bad_payload"),
        ],
    })
}

fn control_vectors() -> J {
    let messages = [
        ControlMessage::hello(),
        ControlMessage::Hello {
            major_version: 1,
            minor_version: 300,
        },
        ControlMessage::Authorized {
            state: AuthorizedState::Live,
        },
        ControlMessage::Authorized {
            state: AuthorizedState::JoinOnly,
        },
        ControlMessage::JoinProof {
            invitation: InvitationId(INVITATION),
            mac: [0xaa; 32],
            name: "Phone".into(),
        },
        ControlMessage::CodeExchange {
            attempt: AttemptId([0xbb; 16]),
            payload: vec![1, 2, 3],
        },
        ControlMessage::CodeAbort {
            attempt: AttemptId([0xbb; 16]),
            code: ErrorCode::PairingFailed,
        },
        ControlMessage::Paired {
            host_name: "Desk".into(),
            role: Role::owner(),
        },
    ];
    let valid: Vec<J> = messages
        .iter()
        .map(|m| {
            let bytes = m.encode();
            assert_eq!(&ControlMessage::decode(&bytes).expect("round trip"), m);
            json!({ "type": m.type_number(), "hex": hex(&bytes) })
        })
        .collect();
    let enc = |entries: Vec<(u64, Value)>| hex(&cbor::encode(&Value::Map(entries)));
    json!({
        "description": "Control messages (spec wire.md, \"Control messages\"). Valid messages decode and re-encode to `hex`. Invalid ones are rejected; the connection closes with protocol_error.",
        "valid": valid,
        "invalid": [
            { "name": "unknown_type", "hex": enc(vec![(0, Value::Uint(99))]) },
            { "name": "extra_key", "hex": enc(vec![(0, Value::Uint(1)), (1, Value::Uint(1)), (2, Value::Uint(0)), (3, Value::Uint(0))]) },
            { "name": "hello_without_minor", "hex": enc(vec![(0, Value::Uint(1)), (1, Value::Uint(1))]) },
            { "name": "hello_major_as_text", "hex": enc(vec![(0, Value::Uint(1)), (1, Value::Text("1".into())), (2, Value::Uint(0))]) },
            { "name": "missing_type", "hex": enc(vec![(1, Value::Uint(0))]) },
            { "name": "authorized_state_3", "hex": enc(vec![(0, Value::Uint(2)), (1, Value::Uint(3))]) },
            { "name": "join_proof_mac_31_bytes", "hex": enc(vec![
                (0, Value::Uint(3)), (1, Value::Bytes(INVITATION.to_vec())), (2, Value::Bytes(vec![0; 31])), (3, Value::Text("x".into())),
            ]) },
            { "name": "join_proof_empty_name", "hex": enc(vec![
                (0, Value::Uint(3)), (1, Value::Bytes(INVITATION.to_vec())), (2, Value::Bytes(vec![0; 32])), (3, Value::Text(String::new())),
            ]) },
            { "name": "code_exchange_empty_payload", "hex": enc(vec![
                (0, Value::Uint(4)), (1, Value::Bytes(vec![0; 16])), (2, Value::Bytes(Vec::new())),
            ]) },
            { "name": "code_abort_code_over_16_bits", "hex": enc(vec![
                (0, Value::Uint(5)), (1, Value::Bytes(vec![0; 16])), (2, Value::Uint(65_536)),
            ]) },
            { "name": "code_exchange_payload_1025_bytes", "hex": enc(vec![
                (0, Value::Uint(4)), (1, Value::Bytes(vec![0; 16])), (2, Value::Bytes(vec![0; 1025])),
            ]) },
        ],
    })
}

fn hello_vectors() -> J {
    let support = |major: u64, minor: u64, oldest_minor: u64| VersionSupport {
        major,
        minor,
        oldest_minor,
    };
    let case = |name: &str, local: VersionSupport, peer: (u64, u64)| {
        let result = match negotiate_version(local, peer.0, peer.1) {
            Ok(minor) => json!(minor),
            Err(code) => json!(format!("close:{}", code.name())),
        };
        json!({
            "name": name,
            "local": { "major": local.major, "minor": local.minor, "oldest_minor": local.oldest_minor },
            "peer": { "major": peer.0, "minor": peer.1 },
            "result": result,
        })
    };
    let local = VersionSupport::LOCAL;
    let later = support(1, 4, 3);
    // Several HELLOs on one connection: only the first counts.
    let sequence = |name: &str, local: VersionSupport, peers: &[(u64, u64)]| {
        let mut state = HelloState::new(local);
        let hellos: Vec<J> = peers
            .iter()
            .map(|&(major_version, minor_version)| {
                let message = ControlMessage::Hello {
                    major_version,
                    minor_version,
                };
                let result = match state.on_hello(major_version, minor_version) {
                    HelloOutcome::Agreed(minor) => json!(minor),
                    HelloOutcome::Ignored => json!("ignored"),
                    HelloOutcome::Close(code) => json!(format!("close:{}", code.name())),
                };
                json!({ "control": hex(&message.encode()), "result": result })
            })
            .collect();
        json!({
            "name": name,
            "local": { "major": local.major, "minor": local.minor, "oldest_minor": local.oldest_minor },
            "hellos": hellos,
            "agreed": state.agreed(),
        })
    };
    json!({
        "description": "HELLO version negotiation (spec wire.md, \"Versions\"). `local` is what the receiving side speaks (its newest and oldest minor version), `peer` is the HELLO it received. `result` is the minor version both sides use, or the close code. `this_build` is what mousse-net-core version 1.0 speaks; `hello` is its HELLO. `repeated`: several HELLOs arrive on one connection, as control-message bytes, in order. Only the first counts; each later one is `ignored`, whatever it holds. `agreed` is the connection's minor version at the end (null if the first HELLO closed it).",
        "this_build": { "major": local.major, "minor": local.minor, "oldest_minor": local.oldest_minor },
        "hello": hex(&ControlMessage::hello().encode()),
        "cases": [
            case("same_version", local, (1, 0)),
            case("peer_newer_minor", local, (1, 7)),
            case("peer_major_2", local, (2, 0)),
            case("peer_major_0", local, (0, 0)),
            case("lower_minor_taken", later, (1, 9)),
            case("previous_minor_supported", later, (1, 3)),
            case("minor_too_old", later, (1, 2)),
            case("minor_zero_too_old", later, (1, 0)),
            case("major_checked_before_minor", later, (2, 4)),
        ],
        "repeated": [
            sequence("second_hello_same", local, &[(1, 0), (1, 0)]),
            sequence("second_hello_other_minor", later, &[(1, 3), (1, 9)]),
            sequence("second_hello_other_major", local, &[(1, 0), (2, 0)]),
            sequence("first_hello_refused", local, &[(2, 0), (1, 0)]),
        ],
    })
}

// ---------------------------------------------------------------------------
// Pairing attempt limits (behavioural sequences)
// ---------------------------------------------------------------------------

fn pairing_attempt_vectors() -> J {
    json!({
        "description": "Attempt-limit sequences for the send-link flow (spec wire.md, \"Send-link flow and the code\" and \"Attempt limits\"), plus one-enrollment for in person. Each step runs one operation and then the listed expectations hold. Ops: connect (joiner proves the ticket on conn), submit (joiner enters a code; messages flow until both sides stop), submit_first (only the joiner's first message reaches the host), redeliver (that first message reaches the host again on conn), drop (conn closes mid-attempt), approve (host owner taps for conn). Codes: right (the code the host shows now), wrong (any other code), stale (the code the host showed when the previous attempt started). `new_code` says whether the host showed a fresh code during the step. `closed` lists connections the host closed during the step. `reply: code_abort` means the host's only answer was CODE_ABORT for that attempt.",
        "sequences": [
            {
                "name": "three_wrong_codes",
                "kind": "send_link",
                "steps": [
                    { "op": "connect", "joiner": "a", "conn": 1, "host_attempts_left": 3, "joiner_attempts_left": 3, "joiner_state": "awaiting_code" },
                    { "op": "submit", "joiner": "a", "conn": 1, "code": "wrong", "host_attempts_left": 2, "joiner_attempts_left": 2, "joiner_state": "awaiting_code", "host_status": "open", "new_code": true },
                    { "op": "submit", "joiner": "a", "conn": 1, "code": "wrong", "host_attempts_left": 1, "joiner_attempts_left": 1, "joiner_state": "awaiting_code", "host_status": "open", "new_code": true },
                    { "op": "submit", "joiner": "a", "conn": 1, "code": "wrong", "host_attempts_left": 0, "joiner_attempts_left": 0, "joiner_state": "failed:attempts_exhausted", "host_status": "ended:attempts_exhausted", "closed": [[1, "attempts_exhausted"]], "new_code": false },
                    { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "result": "wrong_state" },
                ],
            },
            {
                "name": "wrong_then_right",
                "kind": "send_link",
                "steps": [
                    { "op": "connect", "joiner": "a", "conn": 1 },
                    { "op": "submit", "joiner": "a", "conn": 1, "code": "wrong", "host_attempts_left": 2, "joiner_attempts_left": 2 },
                    { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 1, "joiner_attempts_left": 1, "joiner_state": "paired", "host_status": "consumed" },
                ],
            },
            {
                "name": "stale_code_is_refused",
                "kind": "send_link",
                "steps": [
                    { "op": "connect", "joiner": "a", "conn": 1 },
                    { "op": "submit", "joiner": "a", "conn": 1, "code": "wrong", "host_attempts_left": 2, "new_code": true },
                    { "op": "submit", "joiner": "a", "conn": 1, "code": "stale", "host_attempts_left": 1, "joiner_attempts_left": 1, "joiner_state": "awaiting_code", "host_status": "open", "new_code": true },
                    { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 0, "joiner_state": "paired", "host_status": "consumed", "new_code": false },
                ],
            },
            {
                "name": "resend_is_not_a_new_attempt",
                "kind": "send_link",
                "steps": [
                    { "op": "connect", "joiner": "a", "conn": 1 },
                    { "op": "submit_first", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 2, "joiner_attempts_left": 2 },
                    { "op": "redeliver", "joiner": "a", "conn": 1, "same_reply": true, "host_attempts_left": 2, "new_code": false },
                    { "op": "redeliver", "joiner": "a", "conn": 1, "same_reply": true, "host_attempts_left": 2, "new_code": false },
                ],
            },
            {
                "name": "attempt_replayed_on_another_connection_is_refused",
                "description": "Joiner a's first message is replayed on b's connection. The attempt id was already seen on another connection, so the host refuses it with code_abort before any debit or exchange work, and shows no new code.",
                "kind": "send_link",
                "steps": [
                    { "op": "connect", "joiner": "a", "conn": 1 },
                    { "op": "submit_first", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 2 },
                    { "op": "connect", "joiner": "b", "conn": 2 },
                    { "op": "redeliver", "joiner": "a", "conn": 2, "reply": "code_abort", "host_attempts_left": 2, "host_status": "open", "new_code": false },
                    { "op": "drop", "joiner": "a", "conn": 1, "host_attempts_left": 2 },
                    { "op": "redeliver", "joiner": "a", "conn": 2, "reply": "code_abort", "host_attempts_left": 2, "new_code": false },
                ],
            },
            {
                "name": "attempts_shared_across_routes",
                "kind": "send_link",
                "steps": [
                    { "op": "connect", "joiner": "a", "conn": 1 },
                    { "op": "submit", "joiner": "a", "conn": 1, "code": "wrong", "host_attempts_left": 2 },
                    { "op": "connect", "joiner": "b", "conn": 2 },
                    { "op": "submit", "joiner": "b", "conn": 2, "code": "wrong", "host_attempts_left": 1 },
                    { "op": "connect", "joiner": "c", "conn": 3 },
                    { "op": "submit", "joiner": "c", "conn": 3, "code": "wrong", "host_attempts_left": 0, "host_status": "ended:attempts_exhausted", "closed": [[1, "attempts_exhausted"], [2, "attempts_exhausted"], [3, "attempts_exhausted"]] },
                ],
            },
            {
                "name": "dropped_attempt_keeps_its_debit",
                "kind": "send_link",
                "steps": [
                    { "op": "connect", "joiner": "a", "conn": 1 },
                    { "op": "submit_first", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 2, "joiner_attempts_left": 2 },
                    { "op": "drop", "joiner": "a", "conn": 1, "host_attempts_left": 2, "joiner_attempts_left": 2, "joiner_state": "connecting", "host_status": "open" },
                ],
            },
            {
                "name": "two_joiners_one_enrollment",
                "kind": "in_person",
                "steps": [
                    { "op": "connect", "joiner": "a", "conn": 1, "joiner_state": "awaiting_approval" },
                    { "op": "connect", "joiner": "b", "conn": 2, "joiner_state": "awaiting_approval" },
                    { "op": "approve", "conn": 2, "result": "ok", "host_status": "consumed", "closed": [[1, "invitation_invalid"]] },
                    { "op": "approve", "conn": 1, "result": "not_open" },
                ],
            },
        ],
    })
}

fn joiner_state_name(s: JoinerState) -> String {
    match s {
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

fn host_status_name(s: InvitationStatus) -> String {
    match s {
        InvitationStatus::Open => "open".into(),
        InvitationStatus::Consumed { .. } => "consumed".into(),
        InvitationStatus::Ended(code) => format!("ended:{}", code.name()),
    }
}

/// Replays one sequence from `pairing-attempts.json`.
struct Replay {
    rng: ChaCha20Rng,
    joiner_rng: ChaCha20Rng,
    host: HostPairing<CpaceExchangeFactory>,
    grants: GrantTable,
    ticket: Ticket,
    joiners: Vec<(String, u8, JoinerPairing<CpaceExchangeFactory>)>,
    first: Vec<(String, ControlMessage)>,
    last_reply: Option<Vec<ControlMessage>>,
    shown_at_last_submit: Option<PairingCode>,
    new_code: bool,
}

/// The messages the host sent, without display actions.
fn sent(actions: &[HostAction]) -> Vec<ControlMessage> {
    actions
        .iter()
        .filter_map(|a| match a {
            HostAction::Send { message, .. } => Some(message.clone()),
            _ => None,
        })
        .collect()
}

impl Replay {
    fn new(kind: InvitationKind) -> Self {
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let mut host = HostPairing::new(
            identity(&IDENTITY_A).public_key(),
            "Desk".into(),
            CpaceExchangeFactory,
        );
        let params = InvitationParams {
            kind,
            role: Role::owner(),
            authorizing_owner: OwnerRef::from_bytes([0x51; 16]),
            routes: vec![ROUTE.into()],
            grant_expires_at: None,
        };
        let ticket = host
            .create(params, UnixTime(T), &mut rng)
            .expect("create")
            .ticket;
        Self {
            rng,
            joiner_rng: ChaCha20Rng::from_seed([9; 32]),
            host,
            grants: GrantTable::new(),
            ticket,
            joiners: Vec::new(),
            first: Vec::new(),
            last_reply: None,
            shown_at_last_submit: None,
            new_code: false,
        }
    }

    fn joiner(&mut self, name: &str) -> &mut JoinerPairing<CpaceExchangeFactory> {
        if !self.joiners.iter().any(|(n, _, _)| n == name) {
            let seed = 0x50 + self.joiners.len() as u8;
            let key = identity(&[seed; 32]).public_key();
            let j = JoinerPairing::new(
                self.ticket.clone(),
                key,
                name.into(),
                CpaceExchangeFactory,
                UnixTime(T),
            )
            .expect("joiner");
            self.joiners.push((name.into(), seed, j));
        }
        let i = self
            .joiners
            .iter()
            .position(|(n, _, _)| n == name)
            .expect("present");
        &mut self.joiners[i].2
    }

    fn joiner_key(&self, name: &str) -> IdentityPublicKey {
        let seed = self
            .joiners
            .iter()
            .find(|(n, _, _)| n == name)
            .expect("present")
            .1;
        identity(&[seed; 32]).public_key()
    }

    fn deliver_to_host(&mut self, conn: u64, m: ControlMessage) -> Vec<HostAction> {
        let now = UnixTime(T);
        match m {
            ControlMessage::CodeExchange { attempt, payload } => self.host.on_code_exchange(
                ConnectionId(conn),
                attempt,
                &payload,
                &mut self.grants,
                now,
                &mut self.rng,
            ),
            ControlMessage::CodeAbort { attempt, .. } => {
                self.host.on_code_abort(ConnectionId(conn), attempt)
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Run one step; returns connections the host closed.
    fn step(&mut self, step: &J) -> Vec<(u64, String)> {
        let op = step["op"].as_str().expect("op");
        let conn = step["conn"].as_u64().unwrap_or(0);
        let who = step["joiner"].as_str().unwrap_or("").to_owned();
        let mut host_log: Vec<HostAction> = Vec::new();
        match op {
            "connect" => {
                let exporters = SessionExporters {
                    join: [conn as u8; 32],
                    pair: [conn as u8 + 100; 32],
                };
                let proof = self
                    .joiner(&who)
                    .on_connected(exporters, UnixTime(T))
                    .expect("connect");
                let ControlMessage::JoinProof {
                    invitation,
                    mac,
                    name,
                } = proof
                else {
                    panic!("proof")
                };
                let key = self.joiner_key(&who);
                let actions = self.host.on_join_proof(
                    ConnectionId(conn),
                    &key,
                    &exporters,
                    &invitation,
                    &mac,
                    &name,
                    &self.grants,
                    UnixTime(T),
                );
                if actions
                    .iter()
                    .any(|a| matches!(a, HostAction::AdmittedJoinOnly { .. }))
                {
                    self.joiner(&who).on_authorized(AuthorizedState::JoinOnly);
                }
                host_log.extend(actions);
            }
            "submit" | "submit_first" => {
                let shown = self.host.code(&self.ticket.invitation).cloned();
                let fallback = PairingCode::parse("000000").expect("code");
                let code = match step["code"].as_str() {
                    Some("right") => shown.clone().unwrap_or(fallback),
                    Some("stale") => self
                        .shown_at_last_submit
                        .clone()
                        .expect("a previous attempt"),
                    _ => {
                        let other = PairingCode::parse("000001").expect("code");
                        if shown.as_ref() == Some(&fallback) {
                            other
                        } else {
                            fallback
                        }
                    }
                };
                if step["code"] == "stale" {
                    assert_ne!(shown.as_ref(), Some(&code), "stale code still shown");
                }
                self.shown_at_last_submit = shown;
                let mut rng = self.joiner_rng.clone();
                let result = self.joiner(&who).submit_code(&code, &mut rng);
                self.joiner_rng = rng;
                let actions = match result {
                    Ok(a) => a,
                    Err(e) => {
                        let name = match e {
                            crate::pairing::JoinerError::WrongState => "wrong_state",
                            crate::pairing::JoinerError::AttemptsExhausted => "attempts_exhausted",
                            other => panic!("unexpected {other:?}"),
                        };
                        assert_eq!(step["result"], name);
                        return Vec::new();
                    }
                };
                let mut to_host: Vec<ControlMessage> = actions
                    .into_iter()
                    .filter_map(|a| match a {
                        JoinerAction::Send(m) => Some(m),
                        _ => None,
                    })
                    .collect();
                if let Some(m) = to_host.first() {
                    self.first.retain(|(n, _)| *n != who);
                    self.first.push((who.clone(), m.clone()));
                }
                let mut rounds = 0;
                while !to_host.is_empty() {
                    rounds += 1;
                    assert!(rounds < 16, "exchange does not settle");
                    let mut to_joiner = Vec::new();
                    for m in std::mem::take(&mut to_host) {
                        let actions = self.deliver_to_host(conn, m.clone());
                        self.last_reply = Some(sent(&actions));
                        for a in &actions {
                            if let HostAction::Send { conn: c, message } = a {
                                if c.0 == conn {
                                    to_joiner.push(message.clone());
                                }
                            }
                        }
                        host_log.extend(actions);
                    }
                    if op == "submit_first" {
                        break;
                    }
                    for m in to_joiner {
                        let j = self.joiner(&who);
                        let actions = match m {
                            ControlMessage::CodeExchange { attempt, payload } => {
                                j.on_code_exchange(attempt, &payload)
                            }
                            ControlMessage::CodeAbort { attempt, .. } => j.on_code_abort(attempt),
                            ControlMessage::Paired { host_name, role } => {
                                j.on_paired(host_name, role)
                            }
                            other => panic!("unexpected {other:?}"),
                        };
                        to_host.extend(actions.into_iter().filter_map(|a| match a {
                            JoinerAction::Send(m) => Some(m),
                            _ => None,
                        }));
                    }
                }
                // Closes reach the joiner as a closed connection.
                if host_log
                    .iter()
                    .any(|a| matches!(a, HostAction::Close { conn: c, .. } if c.0 == conn))
                {
                    let code = host_log.iter().find_map(|a| match a {
                        HostAction::Close { conn: c, code } if c.0 == conn => Some(*code),
                        _ => None,
                    });
                    self.joiner(&who).on_closed(code);
                }
            }
            "redeliver" => {
                let m = self
                    .first
                    .iter()
                    .find(|(n, _)| *n == who)
                    .expect("first message")
                    .1
                    .clone();
                let before = self.last_reply.clone();
                let actions = self.deliver_to_host(conn, m.clone());
                if step["same_reply"] == true {
                    assert_eq!(Some(sent(&actions)), before, "resend reply differs");
                }
                if step["reply"] == "code_abort" {
                    let ControlMessage::CodeExchange { attempt, .. } = m else {
                        panic!("first message")
                    };
                    assert_eq!(
                        actions,
                        vec![HostAction::Send {
                            conn: ConnectionId(conn),
                            message: ControlMessage::CodeAbort {
                                attempt,
                                code: ErrorCode::PairingFailed,
                            },
                        }],
                        "refused without work"
                    );
                }
                self.last_reply = Some(sent(&actions));
                host_log.extend(actions);
            }
            "drop" => {
                host_log.extend(self.host.on_connection_closed(ConnectionId(conn)));
                self.joiner(&who).on_closed(None);
            }
            "approve" => {
                let invitation = self.ticket.invitation;
                match self.host.approve(
                    &invitation,
                    ConnectionId(conn),
                    &mut self.grants,
                    UnixTime(T),
                ) {
                    Ok(actions) => {
                        assert_eq!(step["result"], "ok");
                        host_log.extend(actions);
                    }
                    Err(HostPairingError::NotOpen) => assert_eq!(step["result"], "not_open"),
                    Err(other) => panic!("unexpected {other:?}"),
                }
            }
            other => panic!("unknown op {other}"),
        }
        self.new_code = host_log
            .iter()
            .any(|a| matches!(a, HostAction::ShowCode { .. }));
        host_log
            .iter()
            .filter_map(|a| match a {
                HostAction::Close { conn, code } => Some((conn.0, code.name().to_owned())),
                _ => None,
            })
            .collect()
    }
}

#[test]
fn pairing_attempt_sequences_hold() {
    let file = vectors_dir().join("pairing-attempts.json");
    let text = std::fs::read_to_string(&file)
        .unwrap_or_else(|_| serde_json::to_string(&pairing_attempt_vectors()).expect("json"));
    let doc: J = serde_json::from_str(&text).expect("json");
    for seq in doc["sequences"].as_array().expect("sequences") {
        let name = seq["name"].as_str().expect("name");
        let kind = match seq["kind"].as_str() {
            Some("send_link") => InvitationKind::SendLink,
            Some("in_person") => InvitationKind::InPerson,
            other => panic!("kind {other:?}"),
        };
        let mut r = Replay::new(kind);
        for (i, step) in seq["steps"].as_array().expect("steps").iter().enumerate() {
            let ctx = format!("{name} step {i}");
            let closed = r.step(step);
            if let Some(n) = step["host_attempts_left"].as_u64() {
                assert_eq!(
                    r.host.attempts_left(&r.ticket.invitation).map(u64::from),
                    Some(n),
                    "{ctx}"
                );
            }
            if let Some(who) = step["joiner"].as_str() {
                if let Some(n) = step["joiner_attempts_left"].as_u64() {
                    assert_eq!(u64::from(r.joiner(who).attempts_left()), n, "{ctx}");
                }
                if let Some(s) = step["joiner_state"].as_str() {
                    assert_eq!(joiner_state_name(r.joiner(who).state()), s, "{ctx}");
                }
            }
            if let Some(b) = step["new_code"].as_bool() {
                assert_eq!(r.new_code, b, "{ctx}");
            }
            if let Some(s) = step["host_status"].as_str() {
                assert_eq!(
                    host_status_name(r.host.status(&r.ticket.invitation).expect("status")),
                    s,
                    "{ctx}"
                );
            }
            let mut expected: Vec<(u64, String)> = step["closed"]
                .as_array()
                .map(|list| {
                    list.iter()
                        .map(|c| {
                            (
                                c[0].as_u64().expect("conn"),
                                c[1].as_str().expect("code").to_owned(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut closed = closed;
            closed.sort();
            closed.dedup();
            expected.sort();
            assert_eq!(closed, expected, "{ctx}");
        }
    }
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

fn all_vectors() -> Vec<(&'static str, J)> {
    vec![
        ("session-cert.json", session_cert_vectors()),
        ("session-lifecycle.json", session_lifecycle_vectors()),
        ("authz.json", authz_vectors()),
        ("ticket.json", ticket_vectors()),
        ("join-proof.json", proof_vectors()),
        ("cbor.json", cbor_vectors()),
        ("der-raw.json", der_raw_vectors()),
        ("mux.json", mux_vectors()),
        ("control.json", control_vectors()),
        ("hello.json", hello_vectors()),
        ("pairing-attempts.json", pairing_attempt_vectors()),
    ]
}

#[test]
fn vector_files_are_current() {
    let dir = vectors_dir();
    let write = std::env::var_os("MOUSSE_NET_WRITE_VECTORS").is_some();
    let mut stale = Vec::new();
    for (name, value) in all_vectors() {
        let text = serde_json::to_string_pretty(&value).expect("json") + "\n";
        let path = dir.join(name);
        if write {
            std::fs::create_dir_all(&dir).expect("create dir");
            std::fs::write(&path, &text).expect("write");
        } else if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
            stale.push(name);
        }
    }
    assert!(
        stale.is_empty(),
        "vector files differ from the generator: {stale:?}; rerun with MOUSSE_NET_WRITE_VECTORS=1 and review the diff"
    );
}

#[test]
fn generation_is_deterministic() {
    let a = serde_json::to_string(&all_vectors()).expect("json");
    let b = serde_json::to_string(&all_vectors()).expect("json");
    assert_eq!(a, b);
}
