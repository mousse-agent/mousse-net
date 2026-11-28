//! Test vector generator and pairing-sequence checker.
//!
//! Every file in `spec/vectors/` (except the code-exchange ones, which have
//! their own owner) is produced here from fixed keys and times. The test
//! `vector_files_are_current` fails if a file differs from what this code
//! produces; run it with `MOUSSE_NET_WRITE_VECTORS=1` to rewrite them.
//! `tests/vectors.rs` then checks the files against the public API only.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

mod direct;
mod relay;

use std::collections::VecDeque;
use std::convert::Infallible;
use std::path::PathBuf;

use hkdf::Hkdf;
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng, TryCryptoRng, TryRng};
use serde_json::{json, Value as J};
use sha2::Sha256;

use crate::cbor::FieldError;
use crate::cbor::{self, Value};
use crate::control::{
    connection_version, negotiate_version, AuthorizedState, ControlError, ControlMessage,
    DirectRecovery, HelloOutcome, HelloState, VersionSupport, DIRECT_MINOR_VERSION,
};
use crate::grants::{GrantTable, OwnerRef, Role};
use crate::identity::{IdentityPublicKey, RawSignature, SoftwareKey};
use crate::mux::{Frame, PriorityClass, StreamId};
use crate::pairing::CpaceExchangeFactory;
use crate::pairing::{
    attempt_sid, binding_transcript, join_proof_input, join_proof_mac, Arrival, AttemptId,
    HostAction, HostPairing, HostPairingError, InvitationId, InvitationKind, InvitationParams,
    InvitationStatus, JoinerAction, JoinerName, JoinerPairing, JoinerState, PairingCode, Route,
    RouteHost, SessionExporters, Ticket, TicketSecret, JOIN_PROOF_KEY_INFO, SID_DOMAIN,
    TICKET_VERSION,
};
use crate::pairing::{DirectCode, DirectLookup, DIRECT_CODE_ALPHABET, DIRECT_CODE_LEN};
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

/// A checked-in vector file.
#[cfg(not(target_arch = "wasm32"))]
fn checked_in(name: &str) -> Option<String> {
    std::fs::read_to_string(vectors_dir().join(name)).ok()
}

/// A checked-in vector file. wasm32 has no file system, so there the
/// files are compiled in.
#[cfg(target_arch = "wasm32")]
fn checked_in(name: &str) -> Option<String> {
    macro_rules! files {
        ($($file:literal,)*) => {
            match name {
                $($file => Some(include_str!(concat!("../../../../spec/vectors/", $file)).to_string()),)*
                _ => None,
            }
        };
    }
    files!(
        "authz.json",
        "cbor.json",
        "control.json",
        "der-raw.json",
        "direct-code.json",
        "direct-host.json",
        "hello.json",
        "join-proof.json",
        "mux.json",
        "pairing-attempts.json",
        "relay-admission.json",
        "session-cert.json",
        "session-lifecycle.json",
        "ticket.json",
    )
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

/// A session certificate made in a real browser by `spikes/browser-worker`
/// (Phase 0 spike 2). A dedicated Worker's non-extractable WebCrypto P-256
/// identity key signed the session record, and `mousse-net-core` compiled to
/// wasm32 assembled the certificate. The bytes are recorded from those runs,
/// not generated; the generator only checks them.
struct BrowserWorkerCert {
    name: &'static str,
    browser: &'static str,
    not_before: u64,
    certificate: &'static str,
    identity_public: &'static str,
    record: &'static str,
    identity_signature: &'static str,
}

const BROWSER_WORKER_CERTS: [BrowserWorkerCert; 2] = [
    BrowserWorkerCert {
        name: "browser_worker_certificate_chromium",
        browser: "Microsoft Edge 157.0.4341.60 (Chromium), headless, Windows 11 x64",
        not_before: 1795014973,
        certificate: "308201da30820180a00302010202104434f5908f439d36d5a2736296ed6d42300a06082a8648ce3d04030230193117301506035504030c0e6d6f757373652d73657373696f6e301e170d3236313131383135313631335a170d3236313131393135313631335a30193117301506035504030c0e6d6f757373652d73657373696f6e3059301306072a8648ce3d020106082a8648ce3d030107034200043059996ffeeee681a898907e2e84eb716984f517e12727b2d0ff8de55832fa08875f61f4536d44032a6d137f9ebd82a4466d0c316c5a902b600d96c7786b7ef5a381a93081a63081a3061369e595e3c0fbf68a84f595c9dabef4e2f7be0504818b3081880201010441049ed06f5dc71a53935e534ba0a96af5bf208714df62fc2bfdcc46d932b7494058ea60d6dbfdf40745d735b3d6aff516da744c0c85ce4ede9cf3e2ad14e7323778044078a099bb3c1d2788043a174d8db8c97698059a3f6877aa04cb96d2823f750335f197b4f899a91c54b36d4602945509a04362cd1232710661a8922f7ca5687120300a06082a8648ce3d040302034800304502205e17492a1c12ada778b3355c29e3100e64f62d1f3c3fc25bfe46ee4253c1ac8e022100e166eb662360849963c26e94e0c669e19738e7b3e7101feb6a328ed8f6e0d48b",
        identity_public: "049ed06f5dc71a53935e534ba0a96af5bf208714df62fc2bfdcc46d932b7494058ea60d6dbfdf40745d735b3d6aff516da744c0c85ce4ede9cf3e2ad14e7323778",
        record: "a501716d6f757373652d73657373696f6e2d763102585b3059301306072a8648ce3d020106082a8648ce3d030107034200043059996ffeeee681a898907e2e84eb716984f517e12727b2d0ff8de55832fa08875f61f4536d44032a6d137f9ebd82a4466d0c316c5a902b600d96c7786b7ef5031a6afdc13d041a6aff12bd0501",
        identity_signature: "78a099bb3c1d2788043a174d8db8c97698059a3f6877aa04cb96d2823f750335f197b4f899a91c54b36d4602945509a04362cd1232710661a8922f7ca5687120",
    },
    BrowserWorkerCert {
        name: "browser_worker_certificate_firefox",
        browser: "Firefox 159.0, headless, Windows 11 x64",
        not_before: 1795014979,
        certificate: "308201da30820180a00302010202106681f50ce9834a70ee6ff79252337954300a06082a8648ce3d04030230193117301506035504030c0e6d6f757373652d73657373696f6e301e170d3236313131383135313631395a170d3236313131393135313631395a30193117301506035504030c0e6d6f757373652d73657373696f6e3059301306072a8648ce3d020106082a8648ce3d03010703420004fdd095f1701a9cfaf34141ce09588b4aca8a9f7eed57a0d5af7a3e7cf587e2a66f5d9552e5074e6c918d74c4911558e97b93a3f38ca3a10c9fe6e500a592d41ca381a93081a63081a3061369e595e3c0fbf68a84f595c9dabef4e2f7be0504818b3081880201010441040ec807c0051448c20c037c3d2e1bd9b942e973bbaa2b238954a887cf78eb4d8b67050ed3e84ab370a643687a2cf23fcb0fb9aba4a0db3935100fea97b566ef8504408944a4081a29b509a1d6c2e7d1137f6bd222dd8ebca9ceaaf5f1db71fddf7d0e74148a9b4b6c46a74755b9dc5eecaef3ab00f6b7b6116d2148f611decbde8106300a06082a8648ce3d0403020348003045022100cfc448dc685624712eaff7179ce59b58e9558603b08e91aae453d762ce6f36030220065947cdc6ba375ecf6902b229bc8c5a31a7985c19dba1ebc7ee314176da561c",
        identity_public: "040ec807c0051448c20c037c3d2e1bd9b942e973bbaa2b238954a887cf78eb4d8b67050ed3e84ab370a643687a2cf23fcb0fb9aba4a0db3935100fea97b566ef85",
        record: "a501716d6f757373652d73657373696f6e2d763102585b3059301306072a8648ce3d020106082a8648ce3d03010703420004fdd095f1701a9cfaf34141ce09588b4aca8a9f7eed57a0d5af7a3e7cf587e2a66f5d9552e5074e6c918d74c4911558e97b93a3f38ca3a10c9fe6e500a592d41c031a6afdc143041a6aff12c30501",
        identity_signature: "8944a4081a29b509a1d6c2e7d1137f6bd222dd8ebca9ceaaf5f1db71fddf7d0e74148a9b4b6c46a74755b9dc5eecaef3ab00f6b7b6116d2148f611decbde8106",
    },
];

/// Check each browser-made certificate with the native verifier and return
/// the `browser_worker` entries and their verification cases.
fn browser_worker_vectors() -> (Vec<J>, Vec<J>) {
    let mut entries = Vec::new();
    let mut cases = Vec::new();
    for c in &BROWSER_WORKER_CERTS {
        let der = unhex(c.certificate);
        let identity =
            IdentityPublicKey::from_sec1(&unhex(c.identity_public)).expect("browser identity key");
        let now = c.not_before + 60;
        let verified = session_cert::verify(&der, UnixTime(now), Some(&identity))
            .expect("the native verifier accepts the browser certificate");
        assert_eq!(verified.window.not_before().0, c.not_before, "{}", c.name);
        let record = session_cert::session_record(
            &verified.spki_der,
            verified.window.not_before(),
            verified.window.not_after(),
            verified.version,
        );
        assert_eq!(hex(&record), c.record, "{}: session record", c.name);
        let signature =
            RawSignature::from_slice(&unhex(c.identity_signature)).expect("raw identity signature");
        identity
            .verify(&record, &signature)
            .expect("the WebCrypto identity signature verifies");
        cases.push(cert_case(
            c.name,
            &format!(
                "A certificate made in a browser Worker ({}): the identity signature is from a non-extractable WebCrypto key. It verifies exactly like `valid`.",
                c.browser
            ),
            &der,
            now,
            Some(&identity),
            "ok",
        ));
        entries.push(json!({
            "name": c.name,
            "browser": c.browser,
            "certificate": c.certificate,
            "identity_public": c.identity_public,
            "spki": hex(&verified.spki_der),
            "not_before": c.not_before,
            "not_after": verified.window.not_after().0,
            "record": c.record,
            "identity_signature": c.identity_signature,
        }));
    }
    (entries, cases)
}

fn session_cert_vectors() -> J {
    let a = identity(&IDENTITY_A);
    let b = identity(&IDENTITY_B);
    let s1 = session(&SESSION_1);
    let s2 = session(&SESSION_2);
    let (nb, na) = (T, T + DAY);
    let window = ValidityWindow::new(UnixTime(nb), UnixTime(na)).expect("window");

    let pending = PendingCertificate::new(session(&SESSION_1), window);
    let record = pending.record().as_bytes().to_vec();
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
    let version_2_off_curve = build_certificate(
        &s1,
        UnixTime(nb),
        UnixTime(na),
        2,
        &off_curve,
        identity_signature.as_bytes(),
    )
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

    let mut cases = vec![
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
        cert_case("precedence_pin_before_window", "Dialling a candidate address for endpoint A, endpoint B answers with a certificate that is also a day past its window. Check 9 (the pin) comes before check 10 (the window): the caller reads \"not this peer\" and tries the next candidate, not a clock error.", &other_endpoint, na + DAY, Some(&pin_a), "pin_mismatch"),
        cert_case("expired_with_no_pin", "An expired certificate with no pin given: check 10.", &der, na + DAY, None, "outside_window"),
    ];
    let (browser_worker, browser_cases) = browser_worker_vectors();
    cases.extend(browser_cases);

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
        "browser_worker": browser_worker,
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
    let renew_at = local_na - crate::Limits::DEFAULT.renew_lead_secs();
    json!({
        "description": "A live path closes with cert_expired at the first second after the effective deadline (earlier not_after + 600). Renewal is due 1800 s before the earlier not_after; while no new path with a later renewal time is current it is asked for again after 30 s, then 60, 120, 240 and every 300 s, until the deadline. Replay: begin_path(1), on_authenticated(1, verify(peer_certificate, authenticated_at, pin), local window, authenticated_at, monotonic 0 ms), on_reopened(1), then tick at each `now`. Monotonic clock: a tick (or a later on_authenticated) without `mono_ms` reads (now - authenticated_at) x 1000 ms, as if no one touched the wall clock.",
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
        "retry_while_candidate": {
            "description": "A fresh replay of the same path. Each wait starts when its retry actually runs. A retry that falls due while a candidate path is still being brought up is skipped but counts as run: the next wait starts then and doubles, and the skipped retry is not made up when the candidate fails. Replay: as above up to the tick at renew_at, then apply each step in order: `tick` at `now` and compare events; `begin_path` and `path_closed` for `conn` (begin_path returns no events here).",
            "steps": [
                { "op": "tick", "now": renew_at + 30, "events": [{ "event": "renew_due", "conn": 1 }] },
                { "op": "begin_path", "conn": 2 },
                { "op": "tick", "now": renew_at + 90, "events": [] },
                { "op": "path_closed", "conn": 2 },
                { "op": "tick", "now": renew_at + 91, "events": [] },
                { "op": "tick", "now": renew_at + 209, "events": [] },
                { "op": "tick", "now": renew_at + 250, "events": [{ "event": "renew_due", "conn": 1 }] },
                { "op": "tick", "now": renew_at + 489, "events": [] },
                { "op": "tick", "now": renew_at + 490, "events": [{ "event": "renew_due", "conn": 1 }] },
            ],
        },
        "candidate_at_first_renewal": {
            "description": "A fresh replay of the same path, with a candidate already being brought up when renewal first falls due. That first request is skipped but counts as run: the 30 s wait starts at that tick. Replay: begin_path(1), on_authenticated(1, ...), on_reopened(1) as above, then apply each step in order, as in `retry_while_candidate` (here with no tick at renew_at first).",
            "steps": [
                { "op": "begin_path", "conn": 2 },
                { "op": "tick", "now": renew_at - 1, "events": [] },
                { "op": "tick", "now": renew_at, "events": [] },
                { "op": "path_closed", "conn": 2 },
                { "op": "tick", "now": renew_at + 1, "events": [] },
                { "op": "tick", "now": renew_at + 29, "events": [] },
                { "op": "tick", "now": renew_at + 30, "events": [{ "event": "renew_due", "conn": 1 }] },
                { "op": "tick", "now": renew_at + 89, "events": [] },
                { "op": "tick", "now": renew_at + 90, "events": [{ "event": "renew_due", "conn": 1 }] },
            ],
        },
        "clock_rollback": {
            "description": "A fresh replay of the same path. The wall clock is set back to just after authentication and stays there, while the monotonic clock keeps running. The path still closes when the monotonic time left at authentication runs out: at (deadline + 1 - authenticated_at) x 1000 ms. Replay: begin_path(1), on_authenticated(1, ...), on_reopened(1) as above, then tick at each `now` and `mono_ms`.",
            "mono_deadline_ms": (deadline + 1 - (local_nb + 60)) * 1000,
            "ticks": [
                { "now": local_nb + 61, "mono_ms": (deadline - (local_nb + 60)) * 1000, "events": [] },
                { "now": local_nb + 61, "mono_ms": (deadline + 1 - (local_nb + 60)) * 1000 - 1, "events": [] },
                { "now": local_nb + 61, "mono_ms": (deadline + 1 - (local_nb + 60)) * 1000, "events": [{ "event": "close", "conn": 1, "code": "cert_expired" }] },
                { "now": local_nb + 62, "mono_ms": (deadline + 2 - (local_nb + 60)) * 1000, "events": [] },
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
    let mut doc = json!({
        "description": "Step 2 on the host after step 1 passed (`cases`), and the caller's gate (`caller_cases`). Host cases: `grants` and `denied` set up the table (grants added in order, then denials), the gate opens at wall time `now` and monotonic time 0 ms, then `steps` run in order. Caller cases: the gate starts awaiting AUTHORIZED; `sent_join_proof` means this side queued a JOIN_PROOF; `promote` means the joiner accepted PAIRED; `host_stream` asks what the host identity `host` may do on a stream it opened, from the caller endpoint's own `local_grants` at `now` (the role of its live grant, or none; wire.md 8.2); `state` is the gate state after the step. Verdicts: allow, ignore, close:<code>.",
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
                    { "op": "check", "traffic": "pairing", "verdict": "ignore" },
                    { "op": "check", "traffic": "host_only", "verdict": "close:protocol_error" },
                ],
            },
            {
                "name": "live_grant_one_proof",
                "description": "A granted device may send one JOIN_PROOF, before any stream; the host answers it (wire.md 8). A second proof closes the connection.",
                "grants": [{ "identity": "a", "role": "owner", "expires_at": null }], "denied": [], "peer": "a", "now": now,
                "step2": "live",
                "steps": [
                    { "op": "check", "traffic": "join_proof", "verdict": "allow" },
                    { "op": "check", "traffic": "join_proof", "verdict": "close:protocol_error" },
                ],
            },
            {
                "name": "live_grant_proof_after_stream",
                "grants": [{ "identity": "a", "role": "owner", "expires_at": null }], "denied": [], "peer": "a", "now": now,
                "step2": "live",
                "steps": [
                    { "op": "check", "traffic": "stream", "verdict": "allow" },
                    { "op": "check", "traffic": "join_proof", "verdict": "close:protocol_error" },
                ],
            },
            {
                "name": "live_grant_pairs_again",
                "description": "The proof was valid for an open invitation: the live connection becomes pairing only until enrollment replaces the grant.",
                "grants": [{ "identity": "a", "role": "owner", "expires_at": null }], "denied": [], "peer": "a", "now": now,
                "step2": "live",
                "steps": [
                    { "op": "check", "traffic": "join_proof", "verdict": "allow" },
                    { "op": "admit_join_only" },
                    { "op": "check", "traffic": "pairing", "verdict": "allow" },
                    { "op": "check", "traffic": "stream", "verdict": "close:not_authorized" },
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
                "name": "proof_answer_after_live_notice",
                "description": "This side sent a JOIN_PROOF. The host's first AUTHORIZED live is step 2's notice; the next AUTHORIZED answers the proof.",
                "steps": [
                    { "op": "sent_join_proof", "state": "awaiting_authorization" },
                    { "op": "check", "traffic": "authorized_live", "verdict": "allow", "state": "awaiting_proof_answer" },
                    { "op": "check", "traffic": "authorized_join_only", "verdict": "allow", "state": "join_only" },
                    { "op": "check", "traffic": "pairing", "verdict": "allow", "state": "join_only" },
                ],
            },
            {
                "name": "proof_answered_live",
                "steps": [
                    { "op": "sent_join_proof", "state": "awaiting_authorization" },
                    { "op": "check", "traffic": "authorized_live", "verdict": "allow", "state": "awaiting_proof_answer" },
                    { "op": "check", "traffic": "authorized_live", "verdict": "allow", "state": "live" },
                    { "op": "check", "traffic": "stream", "verdict": "allow", "state": "live" },
                ],
            },
            {
                "name": "live_notice_read_before_the_proof_went_out",
                "steps": [
                    { "op": "check", "traffic": "authorized_live", "verdict": "allow", "state": "live" },
                    { "op": "sent_join_proof", "state": "awaiting_proof_answer" },
                ],
            },
            {
                "name": "host_stream_before_the_proof_answer",
                "description": "A host opens no stream before the caller has; here before its answer to the proof.",
                "steps": [
                    { "op": "sent_join_proof", "state": "awaiting_authorization" },
                    { "op": "check", "traffic": "authorized_live", "verdict": "allow", "state": "awaiting_proof_answer" },
                    { "op": "check", "traffic": "stream", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
                ],
            },
            {
                "name": "proof_answered_with_paired",
                "description": "This side sent a JOIN_PROOF and the host's grant for it was made by that proof's invitation: after step 2's notice the host answers with PAIRED again (its enrollment receipt, wire.md 10.6 rule 7), and the connection is live.",
                "steps": [
                    { "op": "sent_join_proof", "state": "awaiting_authorization" },
                    { "op": "check", "traffic": "authorized_live", "verdict": "allow", "state": "awaiting_proof_answer" },
                    { "op": "check", "traffic": "paired", "verdict": "allow", "state": "live" },
                    { "op": "check", "traffic": "stream", "verdict": "allow", "state": "live" },
                    { "op": "check", "traffic": "paired", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
                ],
            },
            {
                "name": "host_opened_stream_needs_the_callers_grant",
                "description": "The host's AUTHORIZED lets the caller use the host, never the reverse. A live caller accepts a stream the host opens, but privileged work on it needs the caller's own grant for the host identity: here b (the host) holds one with role owner in the caller's table, and a holds none. Before the gate is live the answer is none whatever the table says.",
                "now": now,
                "local_grants": [{ "identity": "b", "role": "owner", "expires_at": null }],
                "steps": [
                    { "op": "host_stream", "host": "b", "result": "none", "state": "awaiting_authorization" },
                    { "op": "check", "traffic": "authorized_live", "verdict": "allow", "state": "live" },
                    { "op": "check", "traffic": "stream", "verdict": "allow", "state": "live" },
                    { "op": "host_stream", "host": "b", "result": "owner", "state": "live" },
                    { "op": "host_stream", "host": "a", "result": "none", "state": "live" },
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
    });
    doc["description"] = json!(format!(
        "{} {}",
        s_of(&doc["description"]),
        "Host traffic `join_direct` is a JOIN_DIRECT, which follows the JOIN_PROOF rows. Caller cases with `start` `pairing_only` begin in the pairing-only state of an unpinned Pair with IP connection (wire.md 8.2), shown as `pairing_only:<step>`; `promote_direct` means the pairing layer verified the host's confirmation and accepted PAIRED."
    ));
    extend(&mut doc["cases"], direct_host_cases(now));
    extend(&mut doc["caller_cases"], direct_caller_cases());
    doc
}

fn s_of(v: &J) -> &str {
    v.as_str().expect("string")
}

fn extend(list: &mut J, more: Vec<J>) {
    list.as_array_mut().expect("array").extend(more);
}

/// Host gate rows for `JOIN_DIRECT` (Pair with IP): those of `JOIN_PROOF`.
fn direct_host_cases(now: u64) -> Vec<J> {
    vec![
        json!({
            "name": "no_grant_join_direct",
            "description": "A JOIN_DIRECT from a device with no grant is let through like a JOIN_PROOF; once admitted, the connection is pairing only.",
            "grants": [], "denied": [], "peer": "b", "now": now,
            "step2": "await_join_proof",
            "steps": [
                { "op": "check", "traffic": "join_direct", "verdict": "allow" },
                { "op": "admit_join_only" },
                { "op": "check", "traffic": "pairing", "verdict": "allow" },
                { "op": "check", "traffic": "join_direct", "verdict": "close:protocol_error" },
            ],
        }),
        json!({
            "name": "no_grant_two_proofs_before_admission",
            "description": "One proof per connection, even before the host admits it: a JOIN_PROOF after a JOIN_DIRECT closes.",
            "grants": [], "denied": [], "peer": "b", "now": now,
            "step2": "await_join_proof",
            "steps": [
                { "op": "check", "traffic": "join_direct", "verdict": "allow" },
                { "op": "check", "traffic": "join_proof", "verdict": "close:protocol_error" },
            ],
        }),
        json!({
            "name": "no_grant_join_direct_after_join_proof",
            "grants": [], "denied": [], "peer": "b", "now": now,
            "step2": "await_join_proof",
            "steps": [
                { "op": "check", "traffic": "join_proof", "verdict": "allow" },
                { "op": "check", "traffic": "join_direct", "verdict": "close:protocol_error" },
            ],
        }),
        json!({
            "name": "live_grant_one_join_direct",
            "description": "A granted device may send one JOIN_DIRECT or JOIN_PROOF, before any stream; a second one of either closes.",
            "grants": [{ "identity": "a", "role": "owner", "expires_at": null }], "denied": [], "peer": "a", "now": now,
            "step2": "live",
            "steps": [
                { "op": "check", "traffic": "join_direct", "verdict": "allow" },
                { "op": "check", "traffic": "join_proof", "verdict": "close:protocol_error" },
            ],
        }),
        json!({
            "name": "live_grant_join_direct_after_stream",
            "grants": [{ "identity": "a", "role": "owner", "expires_at": null }], "denied": [], "peer": "a", "now": now,
            "step2": "live",
            "steps": [
                { "op": "check", "traffic": "stream", "verdict": "allow" },
                { "op": "check", "traffic": "join_direct", "verdict": "close:protocol_error" },
            ],
        }),
    ]
}

/// The pairing-only caller state.
fn direct_caller_cases() -> Vec<J> {
    vec![
        json!({
            "name": "pairing_only_pairs",
            "description": "An unpinned Pair with IP connection: the host answers JOIN_DIRECT with AUTHORIZED join_only, the code exchange runs, PAIRED arrives, and only promote_direct makes the connection live.",
            "start": "pairing_only",
            "steps": [
                { "op": "check", "traffic": "hello", "verdict": "allow", "state": "pairing_only:awaiting_answer" },
                { "op": "check", "traffic": "keepalive", "verdict": "allow", "state": "pairing_only:awaiting_answer" },
                { "op": "check", "traffic": "authorized_join_only", "verdict": "allow", "state": "pairing_only:join_only" },
                { "op": "check", "traffic": "pairing", "verdict": "allow", "state": "pairing_only:join_only" },
                { "op": "promote_direct", "state": "pairing_only:join_only" },
                { "op": "check", "traffic": "paired", "verdict": "allow", "state": "pairing_only:paired" },
                { "op": "check", "traffic": "pairing", "verdict": "ignore", "state": "pairing_only:paired" },
                { "op": "promote_direct", "state": "live" },
                { "op": "check", "traffic": "stream", "verdict": "allow", "state": "live" },
            ],
        }),
        json!({
            "name": "pairing_only_live_notice_then_answer",
            "description": "The host already grants this device: step 2's AUTHORIZED live is only a notice and the connection stays pairing only.",
            "start": "pairing_only",
            "steps": [
                { "op": "check", "traffic": "authorized_live", "verdict": "allow", "state": "pairing_only:notice_seen" },
                { "op": "check", "traffic": "authorized_join_only", "verdict": "allow", "state": "pairing_only:join_only" },
            ],
        }),
        json!({
            "name": "pairing_only_second_authorized_live",
            "start": "pairing_only",
            "steps": [
                { "op": "check", "traffic": "authorized_live", "verdict": "allow", "state": "pairing_only:notice_seen" },
                { "op": "check", "traffic": "authorized_live", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
            ],
        }),
        json!({
            "name": "pairing_only_code_exchange_before_join_only",
            "start": "pairing_only",
            "steps": [
                { "op": "check", "traffic": "authorized_live", "verdict": "allow", "state": "pairing_only:notice_seen" },
                { "op": "check", "traffic": "pairing", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
            ],
        }),
        json!({
            "name": "pairing_only_paired_before_join_only",
            "start": "pairing_only",
            "steps": [
                { "op": "check", "traffic": "paired", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
            ],
        }),
        json!({
            "name": "pairing_only_refuses_streams",
            "description": "No stream at any step before promote_direct.",
            "start": "pairing_only",
            "steps": [
                { "op": "check", "traffic": "authorized_join_only", "verdict": "allow", "state": "pairing_only:join_only" },
                { "op": "check", "traffic": "paired", "verdict": "allow", "state": "pairing_only:paired" },
                { "op": "check", "traffic": "stream", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
            ],
        }),
        json!({
            "name": "pairing_only_stream_first",
            "start": "pairing_only",
            "steps": [
                { "op": "check", "traffic": "stream", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
            ],
        }),
        json!({
            "name": "pairing_only_second_join_only",
            "start": "pairing_only",
            "steps": [
                { "op": "check", "traffic": "authorized_join_only", "verdict": "allow", "state": "pairing_only:join_only" },
                { "op": "check", "traffic": "authorized_join_only", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
            ],
        }),
        json!({
            "name": "pairing_only_join_direct_from_host",
            "start": "pairing_only",
            "steps": [
                { "op": "check", "traffic": "caller_only", "verdict": "close:protocol_error", "state": "closed:protocol_error" },
            ],
        }),
    ]
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
            { "name": "fragment_length_1_mod_4", "fragment": format!("{fragment}{}", "A".repeat((5 - fragment.len() % 4) % 4)), "result": "encoding" },
            { "name": "fragment_unused_bits_set", "fragment": dirty_fragment(&fragment), "result": "encoding" },
        ],
        "route_hints": route_hint_vectors(),
        "relay_hints": relay_hint_vectors(),
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

/// The fragment with a non-zero unused bit in its last character (or, if it
/// has no unused bits, with a one-byte tail whose unused bits are set). It
/// decodes to the same bytes in a lax decoder.
fn dirty_fragment(fragment: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    if fragment.len().is_multiple_of(4) {
        return format!("{fragment}AB");
    }
    let mut bytes = fragment.as_bytes().to_vec();
    let last = bytes.len() - 1;
    let index = ALPHABET
        .iter()
        .position(|c| *c == bytes[last])
        .expect("alphabet");
    bytes[last] = ALPHABET[index | 1];
    String::from_utf8(bytes).expect("ascii")
}

fn host_json(host: &RouteHost) -> J {
    match host {
        RouteHost::Ipv4(a) => json!({ "ipv4": a.to_string() }),
        RouteHost::Ipv6(a) => json!({ "ipv6": hex(&a.octets()) }),
        RouteHost::Dns(name) => json!({ "dns": name }),
    }
}

fn route_hint_vectors() -> J {
    let hints = [
        "tcp://192.168.1.20:7443",
        "tcp://[fd00::20]:7443",
        "tcp://[::ffff:192.168.1.20]:1",
        "tcp://Desk-1.example.org:65535",
        "tcp://DESK.EXAMPLE.ORG:1",
        "tcp://[FD00:0:0::20]:7443",
        "tcp://[fd00:0000:0000:0000:0000:0000:0000:0020]:7443",
        "tcp://[::ffff:c0a8:114]:1",
        "tcp://[::1.2.3.4]:1",
        "tcp://[::]:7443",
        "tcp://[fd00::00020]:7443",
        "tcp://[fd00::20::1]:7443",
        "tcp://[1:2:3:4:5:6:7:8:9]:7443",
        "tcp://[1::2:3:4:5:6:7:8]:7443",
        "tcp://[1.2.3.4::]:7443",
        "tcp://[fd00::g]:7443",
        "tcp://[]:7443",
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
        "wss://desk.local/mousse-net/1",
        "wss://Tunnel.Example:8443/a/b_c.d~e-f/mousse-net/1",
        "wss://[fd00::20]/mousse-net/1",
        "wss://203.0.113.7:7443/mousse-net/1",
        "wss://desk.local/mousse-net/2",
        "wss://desk.local/mousse-net/1/",
        "wss://desk.local/mousse-net/1?x=1",
        "wss://desk.local/a%2Fb/mousse-net/1",
        "wss://user@desk.local/mousse-net/1",
        "wss://desk.local:0/mousse-net/1",
        "wss://desk.local",
        "ws://127.0.0.1:8080/mousse-net/1",
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
                    json!({ "tcp": { "host": host_json(&host), "port": port } })
                }
                Ok(Route::Wss { host, port, path }) => {
                    json!({ "wss": { "host": host_json(&host), "port": port, "path": path } })
                }
                Ok(Route::Mdns { instance }) => json!({ "mdns": instance }),
                Err(skip) => json!({ "skip": skip.name() }),
            };
            json!({ "hint": hint, "result": result })
        })
        .collect();
    json!({
        "description": "Route hints (spec wire.md, \"Route hints\"). Each hint reads as a tcp route (host as ipv4 in dotted decimal, ipv6 as its 16 bytes in hex, or a dns name lowercased, and a port), a wss route (the same host, the port, 443 when the hint has none, and the path), an mdns instance, or is skipped with a reason: reserved, unknown_scheme or malformed.",
        "cases": cases,
    })
}

fn relay_hint_vectors() -> J {
    use crate::base64url;
    use crate::relay_endpoint::RelayRoute;
    let id = base64url::encode(&[0x11; 32]);
    let handle = base64url::encode(&[0x22; 32]);
    let short = base64url::encode(&[0x11; 31]);
    let hints = vec![
        format!("relay://relay.example:443/{id}/{handle}"),
        format!("relay://203.0.113.5:7000/{id}/{handle}"),
        format!("relay://[2001:db8::5]:443/{id}/{handle}"),
        format!("relay://Relay.Example:443/{id}/{handle}"),
        format!("relay://relay.example/{id}/{handle}"),
        format!("relay://relay.example:443/{short}/{handle}"),
        format!("relay://relay.example:443/{id}"),
        format!("relay://relay.example:443/{id}/{handle}/x"),
        format!("relay://relay.example:443/{id}={handle}"),
        format!("relay://relay.example:0/{id}/{handle}"),
        format!("relay://relay.example:443/+{}/{handle}", &id[1..]),
        format!("relay:relay.example:443/{id}/{handle}"),
        format!("relay://relay.example:443/{id}/{handle}{}", "a".repeat(200)),
    ];
    let cases: Vec<J> = hints
        .iter()
        .map(|hint| {
            let result = match RelayRoute::parse_hint(hint) {
                Some(r) => json!({
                    "endpoint": r.endpoint.to_string(),
                    "destination": r.endpoint.destination(),
                    "relay": hex(&r.relay.0),
                    "handle": hex(&r.handle),
                }),
                None => json!("malformed"),
            };
            json!({ "hint": hint, "result": result })
        })
        .collect();
    json!({
        "description": "Relay route hints (spec wire.md, \"Route hints\", relay; Phase 3). relay://<host>:<port>/<base64url relay id>/<base64url handle>, host and port as in a tcp hint, both ids 32 bytes in base64url without padding, at most 255 bytes. The destination an owner approves is relay://<lower-case host>:<port>. A reader that does not dial relays skips the hint as reserved (route_hints).",
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
        ("indefinite text string", "7f6161ff", "non_canonical"),
        ("indefinite map", "bf0101ff", "non_canonical"),
        (
            "additional info 31 on an unsigned integer",
            "1f",
            "non_canonical",
        ),
        ("break byte alone", "ff", "unsupported"),
        ("reserved additional info 28", "1c", "unsupported"),
        ("reserved additional info 30 on bytes", "5e", "unsupported"),
        (
            "array count above the bytes left, before its items",
            "8220",
            "truncated",
        ),
        (
            "map count above half the bytes left",
            "a2010102",
            "truncated",
        ),
        ("negative integer as map key", "a12001", "non_integer_key"),
        ("indefinite head on a map key", "a11f01", "non_canonical"),
        (
            "key order checked before the value",
            "a202000120",
            "unsorted_keys",
        ),
        ("major type checked before the head", "3b00", "unsupported"),
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
        "description": "The canonical CBOR subset (spec wire.md, \"Canonical CBOR\"). Valid items decode and re-encode to the same bytes. Invalid items are rejected with the given error; where an input breaks several rules, the error is the first one in the order wire.md gives.",
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
// Direct code
// ---------------------------------------------------------------------------

fn direct_code_json(code: &DirectCode) -> J {
    json!({
        "code": code.as_str(),
        "lookup": code.lookup().as_str(),
        "secret": hex(code.secret().as_bytes()),
    })
}

fn direct_code_vectors() -> J {
    let mut seeded = [0u8; DIRECT_CODE_LEN];
    ChaCha20Rng::from_seed([0x5a; 32]).fill_bytes(&mut seeded);
    let ascending: [u8; DIRECT_CODE_LEN] = std::array::from_fn(|i| i as u8);
    let draws: [(&str, [u8; DIRECT_CODE_LEN]); 7] = [
        ("all_zero", [0x00; DIRECT_CODE_LEN]),
        ("all_ones", [0xff; DIRECT_CODE_LEN]),
        ("digits", ascending),
        ("high_bits_ignored", ascending.map(|b| b | 0xe0)),
        ("first_letters", ascending.map(|b| b + 0x0a)),
        ("last_letters", ascending.map(|b| b + 0x14)),
        ("seeded", seeded),
    ];
    let draws: Vec<J> = draws
        .iter()
        .map(|(name, draw)| {
            let code = DirectCode::from_draw(draw);
            let mut case = direct_code_json(&code);
            case["name"] = json!(name);
            case["draw"] = json!(hex(draw));
            case["display"] = json!(code.to_display().as_str());
            case
        })
        .collect();
    let accepted: Vec<J> = [
        ("canonical", "K7QM2XPA9RTE"),
        ("display_form", "K7QM-2XPA-9RTE"),
        ("lowercase", "k7qm-2xpa-9rte"),
        ("mixed_case", "k7Qm2xPa9rTe"),
        ("spaces", "K7QM 2XPA 9RTE"),
        ("leading_and_trailing_spaces", "  K7QM2XPA9RTE  "),
        ("extra_dashes", "--K7QM--2XPA--9RTE--"),
        ("spaces_and_dashes_anywhere", "K 7-Q M2X-P A9R-T E"),
        ("o_reads_as_zero", "OoOo-0000-0000"),
        ("i_and_l_read_as_one", "IiLl-1111-1111"),
        ("all_folding_lowercase", "oil0-ilo1-loil"),
    ]
    .iter()
    .map(|(name, input)| {
        let code = DirectCode::parse(input).expect("accepted input");
        let mut case = direct_code_json(&code);
        case["name"] = json!(name);
        case["input"] = json!(input);
        case
    })
    .collect();
    let rejected: Vec<J> = [
        ("empty", ""),
        ("only_separators", " - - "),
        ("eleven_characters", "K7QM-2XPA-9RT"),
        ("thirteen_characters", "K7QM-2XPA-9RTEX"),
        ("u_is_not_in_the_alphabet", "K7QM-2XPA-9RTU"),
        ("lowercase_u", "k7qm-2xpa-9rtu"),
        ("dot_separator", "K7QM.2XPA.9RTE"),
        ("underscore_separator", "K7QM_2XPA_9RTE"),
        ("tab", "K7QM\t2XPA9RTE"),
        ("newline", "K7QM2XPA9RTE\n"),
        ("non_ascii_letter", "K7QM-2XPA-9RTÉ"),
        ("fullwidth_digits", "１２３４５６７８９０１２"),
        ("cyrillic_o", "K7QМ-2XPA-9RTО"),
        ("no_break_space", "K7QM\u{a0}2XPA9RTE"),
        ("bad_character_before_length", "K7QM!"),
        ("bad_character_after_twelve", "K7QM2XPA9RTE!"),
        ("bad_character_after_thirteen", "K7QM2XPA9RTEX!"),
        ("long_s_is_not_ascii", "K7QM2XPA9RT\u{17f}"),
    ]
    .iter()
    .map(|(name, input)| {
        let error = DirectCode::parse(input).expect_err("rejected input");
        json!({ "name": name, "input": input, "error": error.code() })
    })
    .collect();
    json!({
        "description": "The direct code (spec wire.md 10.9). `draws`: 12 drawn bytes to the code, its display form, the lookup (characters 1 to 4) and the secret (characters 5 to 12, as hex of their ASCII bytes). `accepted`: typed text to the canonical code. `rejected`: typed text that is not a code, with the error; a bad character is reported before a wrong length.",
        "alphabet": std::str::from_utf8(DIRECT_CODE_ALPHABET).expect("ascii"),
        "draws": draws,
        "accepted": accepted,
        "rejected": rejected,
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
        "streams": mux_stream_vectors(),
    })
}

/// Stream rules on a receiving mux. Results are written by hand: they pin
/// the rules, not this implementation's output.
fn mux_stream_vectors() -> J {
    let open = |id: u32| Frame::Open {
        stream: StreamId(id),
        class: PriorityClass::Interactive,
        label: "rpc".into(),
    };
    let data = |id: u32| Frame::Data {
        stream: StreamId(id),
        payload: b"hi".to_vec(),
    };
    let credit = |id: u32| Frame::Credit {
        stream: StreamId(id),
        increment: 1,
    };
    let fin = |id: u32| Frame::Fin {
        stream: StreamId(id),
    };
    let reset = |id: u32| Frame::Reset {
        stream: StreamId(id),
        code: ErrorCode::Cancelled,
    };
    let step = |f: Frame, result: J| json!({ "hex": hex(&f.encode()), "frame": frame_json(&f), "result": result });
    let case = |name: &str, role: &str, steps: Vec<J>| json!({ "name": name, "role": role, "steps": steps });
    let protocol = json!("close:protocol_error");
    json!({
        "description": "Stream rules (spec wire.md, \"Streams\") on a mux that receives each step's frame in order. `role` is the receiving side: a host's peer opens odd ids from 1, a caller's peer even ids from 2, in order with no gaps. `result` is the list of events the frame produced (opened:<id>, data:<id>:<bytes>, finished:<id>, reset:<id>:<code>; an empty list means the frame was ignored), or close:<code> (the mux closes and its next frame out is GOAWAY with that code; no later step follows).",
        "cases": [
            case("open_in_order", "host", vec![
                step(open(1), json!(["opened:1"])),
                step(open(3), json!(["opened:3"])),
            ]),
            case("first_open_skips_an_id", "host", vec![step(open(3), protocol.clone())]),
            case("open_skips_an_id", "host", vec![
                step(open(1), json!(["opened:1"])),
                step(open(5), protocol.clone()),
            ]),
            case("host_open_skips_an_id", "caller", vec![
                step(open(2), json!(["opened:2"])),
                step(open(6), protocol.clone()),
            ]),
            case("open_repeated", "host", vec![
                step(open(1), json!(["opened:1"])),
                step(open(1), protocol.clone()),
            ]),
            case("open_wrong_parity", "host", vec![step(open(2), protocol.clone())]),
            case("data_on_a_never_opened_id", "host", vec![
                step(open(1), json!(["opened:1"])),
                step(data(3), protocol.clone()),
            ]),
            case("credit_on_an_own_id_never_opened", "host", vec![step(credit(2), protocol.clone())]),
            case("frames_on_a_gone_stream_are_ignored", "host", vec![
                step(open(1), json!(["opened:1"])),
                step(data(1), json!(["data:1:2"])),
                step(reset(1), json!(["reset:1:cancelled"])),
                step(data(1), json!([])),
                step(credit(1), json!([])),
                step(fin(1), json!([])),
                step(reset(1), json!([])),
            ]),
            case("data_after_fin", "host", vec![
                step(open(1), json!(["opened:1"])),
                step(fin(1), json!(["finished:1"])),
                step(data(1), json!("close:stream_closed")),
            ]),
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
    let mut valid: Vec<J> = messages
        .iter()
        .map(|m| {
            let bytes = m.encode();
            assert_eq!(&ControlMessage::decode(&bytes).expect("round trip"), m);
            json!({ "type": m.type_number(), "hex": hex(&bytes) })
        })
        .collect();
    let lookup = DirectLookup::from_canonical("K7QM").expect("lookup");
    let receipt = InvitationId([0xcc; 16]);
    let direct = [
        (
            "join_direct",
            ControlMessage::JoinDirect {
                lookup: lookup.clone(),
                name: "Laptop".into(),
                recovery: None,
            },
        ),
        (
            "join_direct_recovery",
            ControlMessage::JoinDirect {
                lookup: lookup.clone(),
                name: "Laptop".into(),
                recovery: Some(DirectRecovery {
                    receipt,
                    cancel: false,
                }),
            },
        ),
        (
            "join_direct_cancel",
            ControlMessage::JoinDirect {
                lookup,
                name: "Laptop".into(),
                recovery: Some(DirectRecovery {
                    receipt,
                    cancel: true,
                }),
            },
        ),
        (
            "authorized_direct",
            ControlMessage::AuthorizedDirect {
                invitation: receipt,
                not_received: false,
            },
        ),
        (
            "authorized_direct_not_received",
            ControlMessage::AuthorizedDirect {
                invitation: receipt,
                not_received: true,
            },
        ),
    ];
    let mut before_minor_4 = Vec::new();
    for (name, m) in &direct {
        let bytes = m.encode();
        assert_eq!(
            &ControlMessage::decode_at(&bytes, DIRECT_MINOR_VERSION).expect("round trip"),
            m
        );
        valid.push(json!({ "name": name, "type": m.type_number(), "minor": DIRECT_MINOR_VERSION, "hex": hex(&bytes) }));
        let error = ControlMessage::decode_at(&bytes, DIRECT_MINOR_VERSION - 1)
            .expect_err("not at minor 3");
        before_minor_4
            .push(json!({ "name": name, "hex": hex(&bytes), "error": control_error_name(&error) }));
    }
    let enc = |entries: Vec<(u64, Value)>| hex(&cbor::encode(&Value::Map(entries)));
    let mut doc = json!({
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
    });
    extend(&mut doc["invalid"], direct_invalid_controls());
    doc["before_minor_4"] = json!(before_minor_4);
    doc["description"] = json!(format!(
        "{} {}",
        s_of(&doc["description"]),
        "Cases with `minor` hold messages defined from that agreed minor version on (JOIN_DIRECT, AUTHORIZED keys 2 and 3, wire.md 11); they are decoded as on a connection that agreed it. Every rejection closes with protocol_error; for diagnostics, the minor-4 cases also name the first rule broken in `error`: unknown_type, missing:<key>, unknown_field:<key>, wrong_type:<key>, invalid:<key> or cbor. `before_minor_4`: valid minor-4 messages received on a connection that agreed minor 3, rejected as a minor-3 decoder rejects them."
    ));
    doc
}

/// The name of a control-message error in vectors.
fn control_error_name(e: &ControlError) -> String {
    match e {
        ControlError::TooLarge => "too_large".into(),
        ControlError::UnknownType(_) => "unknown_type".into(),
        ControlError::Field(FieldError::Cbor(_)) => "cbor".into(),
        ControlError::Field(FieldError::NotAMap) => "not_a_map".into(),
        ControlError::Field(FieldError::Missing(k)) => format!("missing:{k}"),
        ControlError::Field(FieldError::Unknown(k)) => format!("unknown_field:{k}"),
        ControlError::Field(FieldError::WrongType(k)) => format!("wrong_type:{k}"),
        ControlError::Field(FieldError::Invalid(k)) => format!("invalid:{k}"),
    }
}

/// Malformed `JOIN_DIRECT` and `AUTHORIZED` keys 2 and 3, decoded at minor 4.
fn direct_invalid_controls() -> Vec<J> {
    let id = || Value::Bytes(vec![0xcc; 16]);
    let text = |s: &str| Value::Text(s.into());
    let join = |extra: Vec<(u64, Value)>| {
        let mut e = vec![(0, Value::Uint(7)), (1, text("K7QM")), (2, text("Laptop"))];
        e.extend(extra);
        e
    };
    let authorized = |state: u64, extra: Vec<(u64, Value)>| {
        let mut e = vec![(0, Value::Uint(2)), (1, Value::Uint(state))];
        e.extend(extra);
        e
    };
    // Canonical CBOR has no `true` (wire.md 3): the last value byte `01`
    // becomes `f5`.
    let with_true = |entries: Vec<(u64, Value)>| {
        let mut bytes = cbor::encode(&Value::Map(entries));
        if let Some(last) = bytes.last_mut() {
            *last = 0xf5;
        }
        bytes
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "join_direct_lookup_3_characters",
            cbor::encode(&Value::Map(vec![
                (0, Value::Uint(7)),
                (1, text("K7Q")),
                (2, text("Laptop")),
            ])),
        ),
        (
            "join_direct_lookup_5_characters",
            cbor::encode(&Value::Map(vec![
                (0, Value::Uint(7)),
                (1, text("K7QM2")),
                (2, text("Laptop")),
            ])),
        ),
        (
            "join_direct_lookup_lowercase",
            cbor::encode(&Value::Map(vec![
                (0, Value::Uint(7)),
                (1, text("k7qm")),
                (2, text("Laptop")),
            ])),
        ),
        (
            "join_direct_lookup_letter_o",
            cbor::encode(&Value::Map(vec![
                (0, Value::Uint(7)),
                (1, text("K7QO")),
                (2, text("Laptop")),
            ])),
        ),
        (
            "join_direct_lookup_as_bytes",
            cbor::encode(&Value::Map(vec![
                (0, Value::Uint(7)),
                (1, Value::Bytes(b"K7QM".to_vec())),
                (2, text("Laptop")),
            ])),
        ),
        (
            "join_direct_without_lookup",
            cbor::encode(&Value::Map(vec![(0, Value::Uint(7)), (2, text("Laptop"))])),
        ),
        (
            "join_direct_without_name",
            cbor::encode(&Value::Map(vec![(0, Value::Uint(7)), (1, text("K7QM"))])),
        ),
        (
            "join_direct_empty_name",
            cbor::encode(&Value::Map(vec![
                (0, Value::Uint(7)),
                (1, text("K7QM")),
                (2, text("")),
            ])),
        ),
        (
            "join_direct_name_129_bytes",
            cbor::encode(&Value::Map(vec![
                (0, Value::Uint(7)),
                (1, text("K7QM")),
                (2, text(&"n".repeat(129))),
            ])),
        ),
        (
            "join_direct_receipt_15_bytes",
            cbor::encode(&Value::Map(join(vec![(3, Value::Bytes(vec![0xcc; 15]))]))),
        ),
        (
            "join_direct_receipt_as_text",
            cbor::encode(&Value::Map(join(vec![(3, text("receipt"))]))),
        ),
        (
            "join_direct_cancel_without_receipt",
            cbor::encode(&Value::Map(join(vec![(4, Value::Uint(1))]))),
        ),
        (
            "join_direct_cancel_0",
            cbor::encode(&Value::Map(join(vec![(3, id()), (4, Value::Uint(0))]))),
        ),
        (
            "join_direct_cancel_2",
            cbor::encode(&Value::Map(join(vec![(3, id()), (4, Value::Uint(2))]))),
        ),
        (
            "join_direct_cancel_true",
            with_true(join(vec![(3, id()), (4, Value::Uint(1))])),
        ),
        (
            "join_direct_extra_key",
            cbor::encode(&Value::Map(join(vec![(3, id()), (5, Value::Uint(1))]))),
        ),
        (
            "authorized_invitation_with_live",
            cbor::encode(&Value::Map(authorized(1, vec![(2, id())]))),
        ),
        (
            "authorized_invitation_15_bytes",
            cbor::encode(&Value::Map(authorized(
                2,
                vec![(2, Value::Bytes(vec![0xcc; 15]))],
            ))),
        ),
        (
            "authorized_not_received_without_invitation",
            cbor::encode(&Value::Map(authorized(2, vec![(3, Value::Uint(1))]))),
        ),
        (
            "authorized_not_received_with_live",
            cbor::encode(&Value::Map(authorized(
                1,
                vec![(2, id()), (3, Value::Uint(1))],
            ))),
        ),
        (
            "authorized_not_received_0",
            cbor::encode(&Value::Map(authorized(
                2,
                vec![(2, id()), (3, Value::Uint(0))],
            ))),
        ),
        (
            "authorized_not_received_true",
            with_true(authorized(2, vec![(2, id()), (3, Value::Uint(1))])),
        ),
        (
            "authorized_extra_key",
            cbor::encode(&Value::Map(authorized(
                2,
                vec![(2, id()), (4, Value::Uint(1))],
            ))),
        ),
    ];
    cases
        .into_iter()
        .map(|(name, bytes)| {
            let error = ControlMessage::decode_at(&bytes, DIRECT_MINOR_VERSION)
                .expect_err("invalid control message");
            json!({ "name": name, "minor": DIRECT_MINOR_VERSION, "hex": hex(&bytes), "error": control_error_name(&error) })
        })
        .collect()
}

fn hello_vectors() -> J {
    let support = |major: u64, minor: u64, oldest_minor: u64| VersionSupport {
        major,
        minor,
        oldest_minor,
    };
    let case = |name: &str, local: VersionSupport, peer: (u64, u64)| {
        let outcome = |r: Result<u64, ErrorCode>| match r {
            Ok(minor) => json!(minor),
            Err(code) => json!(format!("close:{}", code.name())),
        };
        json!({
            "name": name,
            "local": { "major": local.major, "minor": local.minor, "oldest_minor": local.oldest_minor },
            "peer": { "major": peer.0, "minor": peer.1 },
            "result": outcome(negotiate_version(local, peer.0, peer.1)),
            "connection": outcome(connection_version(local, peer.0, peer.1)),
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
        "description": "HELLO version negotiation (spec wire.md, \"Versions\"). `local` is what the receiving side speaks (its newest and oldest minor version), `peer` is the HELLO it received. `result` is the minor version from the receiving side's own range (steps 1 to 4), or the close code. `connection` is what the connection does: the same, except that it also closes with `UNSUPPORTED_VERSION` when the peer would refuse `result` (below the peer's minor - 1, which a peer never speaks). `this_build` is what this mousse-net-core build speaks; `hello` is its HELLO. `repeated`: several HELLOs arrive on one connection, as control-message bytes, in order. Only the first counts; each later one is `ignored`, whatever it holds. `agreed` is the connection's minor version at the end (null if the first HELLO closed it).",
        "this_build": { "major": local.major, "minor": local.minor, "oldest_minor": local.oldest_minor },
        "hello": hex(&ControlMessage::hello().encode()),
        "cases": [
            case("same_version", local, (1, local.minor)),
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
            sequence(
                "second_hello_same",
                local,
                &[(1, local.minor), (1, local.minor)],
            ),
            sequence("second_hello_other_minor", later, &[(1, 3), (1, 9)]),
            sequence(
                "second_hello_other_major",
                local,
                &[(1, local.minor), (2, 0)],
            ),
            sequence(
                "first_hello_refused",
                local,
                &[(2, 0), (1, local.minor)],
            ),
        ],
    })
}

// ---------------------------------------------------------------------------
// Pairing attempt limits (behavioural sequences)
// ---------------------------------------------------------------------------

/// An attempt id that no joiner drew, for injected messages.
const FOREIGN_ATTEMPT: [u8; 16] = [0xee; 16];

/// `msg_a` whose share is the identity element (32 zero bytes), empty AD.
fn identity_point_msg_a() -> Vec<u8> {
    let mut m = vec![0x20];
    m.extend_from_slice(&[0u8; 32]);
    m.push(0x00);
    m
}

/// `msg_a` whose first byte is not the share length 0x20.
fn malformed_msg_a() -> Vec<u8> {
    let mut m = identity_point_msg_a();
    m[0] = 0x21;
    m
}

fn attempt_sequences() -> Vec<J> {
    let identity_share = hex(&identity_point_msg_a());
    let malformed_share = hex(&malformed_msg_a());
    let first_foreign = hex(&[0x0a; 16]);
    let second_foreign = hex(&[0x0b; 16]);
    let zero_tag = hex(&[0u8; 64]);
    vec![
        json!({
            "name": "three_wrong_codes",
            "kind": "send_link",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1, "host_attempts_left": 3, "joiner_attempts_left": 3, "joiner_state": "awaiting_code" },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "wrong", "host_attempts_left": 2, "joiner_attempts_left": 2, "joiner_state": "awaiting_code", "host_status": "open", "new_code": true },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "wrong", "host_attempts_left": 1, "joiner_attempts_left": 1, "joiner_state": "awaiting_code", "host_status": "open", "new_code": true },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "wrong", "host_attempts_left": 0, "joiner_attempts_left": 0, "joiner_state": "failed:attempts_exhausted", "host_status": "ended:attempts_exhausted", "closed": [[1, "attempts_exhausted"]], "new_code": false },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "result": "wrong_state" },
            ],
        }),
        json!({
            "name": "wrong_then_right",
            "kind": "send_link",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "wrong", "host_attempts_left": 2, "joiner_attempts_left": 2 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 1, "joiner_attempts_left": 1, "joiner_state": "paired", "host_status": "consumed" },
            ],
        }),
        json!({
            "name": "stale_code_is_refused",
            "kind": "send_link",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "wrong", "host_attempts_left": 2, "new_code": true },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "stale", "host_attempts_left": 1, "joiner_attempts_left": 1, "joiner_state": "awaiting_code", "host_status": "open", "new_code": true },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 0, "joiner_state": "paired", "host_status": "consumed", "new_code": false },
            ],
        }),
        json!({
            "name": "a_repeated_message_fails_the_attempt",
            "description": "The joiner's msg_a reaches the host twice on the same connection. The second copy does not fit the attempt's next step, so the attempt fails with code_abort and no new debit. Anything more for the ended attempt gets code_abort and no work.",
            "kind": "send_link",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit_first", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 2, "joiner_attempts_left": 2 },
                { "op": "redeliver", "joiner": "a", "conn": 1, "reply": "code_abort", "host_attempts_left": 2, "new_code": false },
                { "op": "redeliver", "joiner": "a", "conn": 1, "reply": "code_abort", "host_attempts_left": 2, "new_code": false },
            ],
        }),
        json!({
            "name": "messages_after_the_joiner_aborted",
            "description": "The host answered msg_a; then the joiner aborts the attempt. The abort ends the attempt and keeps its debit. msg_a again, or any other payload, on the ended attempt gets code_abort, with no debit. An abort for an attempt the host does not have is ignored.",
            "kind": "send_link",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit_first", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 2 },
                { "op": "inject", "joiner": "a", "conn": 1, "message": "code_abort", "attempt": "current", "reply": "none", "host_attempts_left": 2, "host_status": "open", "new_code": false },
                { "op": "redeliver", "joiner": "a", "conn": 1, "reply": "code_abort", "host_attempts_left": 2, "new_code": false },
                { "op": "inject", "joiner": "a", "conn": 1, "message": "code_exchange", "attempt": "current", "payload": zero_tag, "reply": "code_abort", "host_attempts_left": 2, "new_code": false },
                { "op": "inject", "joiner": "a", "conn": 1, "message": "code_abort", "attempt": hex(&FOREIGN_ATTEMPT), "reply": "none", "host_attempts_left": 2, "host_status": "open" },
            ],
        }),
        json!({
            "name": "different_payload_on_a_running_attempt_is_the_next_message",
            "description": "After msg_a, a different payload on the running attempt is read as msg_c: 64 zero bytes are a wrong confirmation, so the attempt fails with code_abort. msg_a again, on the ended attempt: code_abort, with no debit.",
            "kind": "send_link",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit_first", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 2 },
                { "op": "inject", "joiner": "a", "conn": 1, "message": "code_exchange", "attempt": "current", "payload": zero_tag, "reply": "code_abort", "host_attempts_left": 2, "host_status": "open", "new_code": false },
                { "op": "redeliver", "joiner": "a", "conn": 1, "reply": "code_abort", "host_attempts_left": 2, "new_code": false },
            ],
        }),
        json!({
            "name": "bad_first_message_still_uses_the_draws",
            "description": "First messages of two new attempts that fail before any group work: a share that is the identity point, then a share with a wrong length byte. Each is debited and the host draws the next code and the CPace scalar before reading it, then answers code_abort. The right code then pairs. The draws list shows the order.",
            "kind": "send_link",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "inject", "joiner": "a", "conn": 1, "message": "code_exchange", "attempt": first_foreign, "payload": identity_share, "reply": "code_abort", "host_attempts_left": 2, "new_code": true },
                { "op": "inject", "joiner": "a", "conn": 1, "message": "code_exchange", "attempt": second_foreign, "payload": malformed_share, "reply": "code_abort", "host_attempts_left": 1, "new_code": true },
                { "op": "inject", "joiner": "a", "conn": 1, "message": "code_exchange", "attempt": second_foreign, "payload": malformed_share, "reply": "code_abort", "host_attempts_left": 1, "new_code": false },
                { "op": "submit", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 0, "joiner_state": "paired", "host_status": "consumed", "new_code": false },
            ],
        }),
        json!({
            "name": "attempt_replayed_on_another_connection_is_debited",
            "description": "Joiner a's first message is replayed on b's connection. Attempts are kept per connection, so there it is a new attempt: debited first, a fresh code is shown, and the host answers msg_b. It can never succeed: its binding holds b's identity and b's session exporter. Dropping b's connection ends it; the debit stays.",
            "kind": "send_link",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit_first", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 2 },
                { "op": "connect", "joiner": "b", "conn": 2 },
                { "op": "redeliver", "joiner": "a", "conn": 2, "reply": "code_exchange", "host_attempts_left": 1, "host_status": "open", "new_code": true },
                { "op": "drop", "joiner": "b", "conn": 2, "host_attempts_left": 1, "host_status": "open" },
            ],
        }),
        json!({
            "name": "join_proof_from_own_identity",
            "description": "A join proof made with the host's own identity key, valid for the open invitation: a device never pairs with itself, so the host closes with not_authorized and the invitation stays open (wire.md 10.3).",
            "kind": "send_link",
            "steps": [
                { "op": "connect_as_host", "joiner": "a", "conn": 1, "closed": [[1, "not_authorized"]], "host_status": "open", "host_attempts_left": 3, "new_code": false },
            ],
        }),
        json!({
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
        }),
        json!({
            "name": "dropped_attempt_keeps_its_debit",
            "kind": "send_link",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1 },
                { "op": "submit_first", "joiner": "a", "conn": 1, "code": "right", "host_attempts_left": 2, "joiner_attempts_left": 2 },
                { "op": "drop", "joiner": "a", "conn": 1, "host_attempts_left": 2, "joiner_attempts_left": 2, "joiner_state": "connecting", "host_status": "open" },
            ],
        }),
        json!({
            "name": "two_joiners_one_enrollment",
            "kind": "in_person",
            "steps": [
                { "op": "connect", "joiner": "a", "conn": 1, "joiner_state": "awaiting_approval" },
                { "op": "connect", "joiner": "b", "conn": 2, "joiner_state": "awaiting_approval" },
                { "op": "approve", "conn": 2, "result": "ok", "host_status": "consumed", "closed": [[1, "invitation_invalid"]] },
                { "op": "approve", "conn": 1, "result": "not_open" },
            ],
        }),
    ]
}

fn pairing_attempt_vectors() -> J {
    let sequences: Vec<J> = attempt_sequences()
        .iter()
        .map(|seq| run_attempt_sequence(seq, None))
        .collect();
    json!({
        "description": "Attempt-limit and repeat sequences for the send-link flow (spec wire.md, \"Send-link flow and the code\" and \"Attempt limits\"), plus one-enrollment for in person. Each step runs one operation and then the listed expectations hold. Ops: connect (the connection starts; after the two HELLO messages the joiner sends its join proof on conn and the host's AUTHORIZED, if any, reaches the joiner), submit (the joiner enters a code; messages flow until both sides stop), submit_first (only the joiner's first message reaches the host; the host's reply is recorded in `out` but not delivered to the joiner), redeliver (the joiner's last first message reaches the host again on conn, as a repeat or a replay; the reply is recorded, not delivered), connect_as_host (like connect, but the join proof is made with the host's own identity key), inject (the joiner's side sends `message` for `attempt`, \"current\" meaning the attempt of its last submit, with `payload`; the reply is recorded, not delivered), drop (conn closes), approve (host owner taps for conn). Codes: right (the code the host shows now), wrong (000000, or 000001 if 000000 is shown), stale (the code the host showed when the previous attempt started). `reply`: code_exchange (the host's only answer is one CODE_EXCHANGE for that attempt), code_abort (the host's only answer is CODE_ABORT pairing_failed for that attempt), none (no answer). `new_code` says whether the host showed a fresh code during the step. `closed` lists connections the host closed during the step. When `joiner_state` becomes failed with a code, the joiner also closes the connection with GOAWAY of that code after its listed messages, unless the host had already closed it (wire.md 10.6 rule 9); that close is not listed. `out` lists, in order, every control message each side sent during the step (`send`), host closes (`close`) and codes the host showed (`show_code`), except the HELLO each side sends first on every connection (wire.md, \"Connection start and step 2\"): a replay over real connections exchanges both HELLOs, checks the agreed version and starts comparing at JOIN_PROOF. Each side's sends keep their own order; on connect the two sides send independently, and `out` lists the joiner's before the host's.",
        "conventions": {
            "time": T,
            "host": { "identity_secret": hex(&IDENTITY_A), "name": "Desk" },
            "invitation": { "role": "owner", "authorizing_owner": hex(&[0x51; 16]), "routes": [ROUTE], "grant_expires_at": null },
            "joiners": "Each joiner's identity secret is one byte repeated 32 times: 0x50 for the first joiner a sequence names, 0x51 for the second, and so on. Its computer name is its letter and its profile label is `Work`, so its JOIN_PROOF name is `<letter> (Work)` for in person and `<letter>` for send link (wire.md 10.3). Every flow-record write the joiner asks for (wire.md 10.7) lands at once and is not listed.",
            "exporters": "On connection n both ends see the join exporter n repeated 32 times and the pair exporter n + 100 repeated 32 times.",
            "draws": "`draws` lists each party's random values in the order it takes them. A `bytes` draw fills a request of exactly that length; a `u32` draw answers a request for a 32-bit integer. Host: invitation id (16), ticket secret (16), for send link the first code (u32, drawn again while at least 4294000000); then for each new attempt, after the debit and before reading its first message, the next code (u32, only while attempts are left) and the CPace scalar yb (32). Joiner: for each attempt the attempt id (16) and the CPace scalar ya (32).",
        },
        "sequences": sequences,
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

/// One party's random values: taken from a seeded generator and logged
/// (when making the file), or handed out from the file's list.
struct Draws {
    source: Option<ChaCha20Rng>,
    script: VecDeque<J>,
    log: Vec<J>,
}

impl Draws {
    fn recording(seed: u8) -> Self {
        Self {
            source: Some(ChaCha20Rng::from_seed([seed; 32])),
            script: VecDeque::new(),
            log: Vec::new(),
        }
    }

    fn scripted(list: &J) -> Self {
        Self {
            source: None,
            script: list
                .as_array()
                .map(|a| a.iter().cloned().collect())
                .unwrap_or_default(),
            log: Vec::new(),
        }
    }

    fn next_listed(&mut self) -> J {
        self.script
            .pop_front()
            .expect("the sequence drew more values than listed")
    }
}

impl TryRng for Draws {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let value = match self.source.as_mut() {
            Some(rng) => rng.next_u32(),
            None => {
                let d = self.next_listed();
                let v = d["u32"]
                    .as_u64()
                    .unwrap_or_else(|| panic!("expected a u32 draw, got {d}"));
                u32::try_from(v).expect("u32")
            }
        };
        self.log.push(json!({ "u32": value }));
        Ok(value)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        panic!("pairing draws no u64 values")
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        match self.source.as_mut() {
            Some(rng) => rng.fill_bytes(dst),
            None => {
                let d = self.next_listed();
                let bytes = unhex(d["bytes"].as_str().expect("bytes draw"));
                assert_eq!(bytes.len(), dst.len(), "draw {d}");
                dst.copy_from_slice(&bytes);
            }
        }
        self.log.push(json!({ "bytes": hex(dst) }));
        Ok(())
    }
}

impl TryCryptoRng for Draws {}

/// Complete every flow-record write at once (wire.md 10.7) and every pin
/// store, as a well-behaved app does; returns the other actions in order.
fn settle(
    pairing: &mut JoinerPairing<CpaceExchangeFactory>,
    actions: Vec<JoinerAction>,
) -> Vec<JoinerAction> {
    let mut queue: std::collections::VecDeque<JoinerAction> = actions.into();
    let mut out = Vec::new();
    while let Some(a) = queue.pop_front() {
        let more = match &a {
            JoinerAction::Persist { .. } => pairing.on_persisted(),
            JoinerAction::Paired(_) | JoinerAction::AlreadyPaired => {
                out.push(a);
                pairing.on_pin_stored()
            }
            _ => {
                out.push(a);
                Vec::new()
            }
        };
        for m in more.into_iter().rev() {
            queue.push_front(m);
        }
    }
    out
}

struct ReplayJoiner {
    name: String,
    seed: u8,
    pairing: JoinerPairing<CpaceExchangeFactory>,
    rng: Draws,
    /// The first message of its last attempt.
    first: Option<ControlMessage>,
}

/// Runs one sequence of `pairing-attempts.json`.
struct Replay {
    host_rng: Draws,
    listed: Option<J>,
    host: HostPairing<CpaceExchangeFactory>,
    grants: GrantTable,
    ticket: Ticket,
    joiners: Vec<ReplayJoiner>,
    shown_at_last_submit: Option<PairingCode>,
    out: Vec<J>,
}

impl Replay {
    fn new(kind: InvitationKind, listed: Option<&J>) -> Self {
        let mut host_rng = match listed {
            Some(draws) => Draws::scripted(&draws["host"]),
            None => Draws::recording(7),
        };
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
            .create(params, UnixTime(T), &mut host_rng)
            .expect("create")
            .ticket;
        Self {
            host_rng,
            listed: listed.cloned(),
            host,
            grants: GrantTable::new(),
            ticket,
            joiners: Vec::new(),
            shown_at_last_submit: None,
            out: Vec::new(),
        }
    }

    fn joiner(&mut self, name: &str) -> &mut ReplayJoiner {
        if !self.joiners.iter().any(|j| j.name == name) {
            let seed = 0x50 + self.joiners.len() as u8;
            let key = identity(&[seed; 32]).public_key();
            let arrival = match self.ticket.kind {
                InvitationKind::InPerson => Arrival::InAppScan,
                InvitationKind::SendLink => Arrival::Link,
            };
            let pairing = JoinerPairing::new(
                self.ticket.clone(),
                arrival,
                key,
                JoinerName {
                    computer: name.into(),
                    profile: Some("Work".into()),
                },
                CpaceExchangeFactory,
                None,
                UnixTime(T),
            )
            .expect("joiner");
            let rng = match &self.listed {
                Some(draws) => Draws::scripted(&draws[name]),
                None => Draws::recording(0x60 + self.joiners.len() as u8),
            };
            self.joiners.push(ReplayJoiner {
                name: name.into(),
                seed,
                pairing,
                rng,
                first: None,
            });
        }
        self.joiners
            .iter_mut()
            .find(|j| j.name == name)
            .expect("present")
    }

    fn sent(&mut self, from: &str, conn: u64, m: &ControlMessage) {
        self.out
            .push(json!({ "send": { "from": from, "conn": conn, "control": hex(&m.encode()) } }));
    }

    /// Log the host's actions; return the messages it sent on `conn`.
    fn host_did(&mut self, actions: &[HostAction], conn: u64) -> Vec<ControlMessage> {
        let mut on_conn = Vec::new();
        for a in actions {
            match a {
                HostAction::Send { conn: c, message } => {
                    self.sent("host", c.0, message);
                    if c.0 == conn {
                        on_conn.push(message.clone());
                    }
                }
                HostAction::Close { conn: c, code } => {
                    self.out.push(
                        json!({ "close": { "from": "host", "conn": c.0, "code": code.name() } }),
                    );
                }
                HostAction::ShowCode { code, .. } => {
                    self.out.push(json!({ "show_code": code.as_str() }));
                }
                _ => {}
            }
        }
        on_conn
    }

    fn deliver_to_host(
        &mut self,
        who: &str,
        conn: u64,
        m: &ControlMessage,
    ) -> (Vec<HostAction>, Vec<ControlMessage>) {
        self.sent(who, conn, m);
        let now = UnixTime(T);
        let actions = match m {
            ControlMessage::CodeExchange { attempt, payload } => self.host.on_code_exchange(
                ConnectionId(conn),
                *attempt,
                payload,
                &mut self.grants,
                now,
                &mut self.host_rng,
            ),
            ControlMessage::CodeAbort { attempt, .. } => {
                self.host.on_code_abort(ConnectionId(conn), *attempt)
            }
            other => panic!("unexpected {other:?}"),
        };
        let reply = self.host_did(&actions, conn);
        (actions, reply)
    }

    fn check_reply(&self, step: &J, who: &str, attempt: AttemptId, reply: &[ControlMessage]) {
        match step["reply"].as_str() {
            None => {}
            Some("none") => assert!(reply.is_empty(), "expected no answer"),
            Some("code_abort") => assert_eq!(
                reply,
                [ControlMessage::CodeAbort {
                    attempt,
                    code: ErrorCode::PairingFailed,
                }],
                "refused without work"
            ),
            Some("code_exchange") => assert!(
                matches!(
                    reply,
                    [ControlMessage::CodeExchange { attempt: a, .. }] if *a == attempt
                ),
                "expected one CODE_EXCHANGE for {who}'s attempt"
            ),
            Some(other) => panic!("reply {other}"),
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
                let j = self.joiner(&who);
                let seed = j.seed;
                let proof = j
                    .pairing
                    .on_connected(exporters, UnixTime(T))
                    .expect("connect");
                self.sent(&who, conn, &proof);
                let ControlMessage::JoinProof {
                    invitation,
                    mac,
                    name,
                } = proof
                else {
                    panic!("proof")
                };
                let key = identity(&[seed; 32]).public_key();
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
                self.host_did(&actions, conn);
                if actions
                    .iter()
                    .any(|a| matches!(a, HostAction::AdmittedJoinOnly { .. }))
                {
                    let j = self.joiner(&who);
                    let actions = j.pairing.on_authorized(AuthorizedState::JoinOnly);
                    settle(&mut j.pairing, actions);
                }
                host_log.extend(actions);
            }
            "connect_as_host" => {
                // A join proof made with the host's own identity key.
                let exporters = SessionExporters {
                    join: [conn as u8; 32],
                    pair: [conn as u8 + 100; 32],
                };
                let host_key = identity(&IDENTITY_A).public_key();
                let invitation = self.ticket.invitation;
                let mac = join_proof_mac(
                    &self.ticket.secret,
                    &invitation,
                    &host_key,
                    &host_key,
                    &exporters.join,
                );
                let proof = ControlMessage::JoinProof {
                    invitation,
                    mac,
                    name: who.clone(),
                };
                self.sent(&who, conn, &proof);
                let actions = self.host.on_join_proof(
                    ConnectionId(conn),
                    &host_key,
                    &exporters,
                    &invitation,
                    &mac,
                    &who,
                    &self.grants,
                    UnixTime(T),
                );
                self.host_did(&actions, conn);
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
                let j = self.joiner(&who);
                let actions = match j.pairing.submit_code(&code, &mut j.rng) {
                    Ok(a) => settle(&mut j.pairing, a),
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
                let mut first = to_host.first().cloned();
                let mut rounds = 0;
                while !to_host.is_empty() {
                    rounds += 1;
                    assert!(rounds < 16, "exchange does not settle");
                    let mut to_joiner = Vec::new();
                    for m in std::mem::take(&mut to_host) {
                        let (actions, reply) = self.deliver_to_host(&who, conn, &m);
                        if let Some(f) = first.take() {
                            self.joiner(&who).first = Some(f);
                        }
                        to_joiner.extend(reply);
                        host_log.extend(actions);
                    }
                    if op == "submit_first" {
                        break;
                    }
                    for m in to_joiner {
                        let j = self.joiner(&who);
                        let actions = match m {
                            ControlMessage::CodeExchange { attempt, payload } => {
                                j.pairing.on_code_exchange(attempt, &payload)
                            }
                            ControlMessage::CodeAbort { attempt, .. } => {
                                j.pairing.on_code_abort(attempt)
                            }
                            ControlMessage::Paired { host_name, role } => {
                                j.pairing.on_paired(host_name, role)
                            }
                            other => panic!("unexpected {other:?}"),
                        };
                        let actions = settle(&mut j.pairing, actions);
                        to_host.extend(actions.into_iter().filter_map(|a| match a {
                            JoinerAction::Send(m) => Some(m),
                            _ => None,
                        }));
                    }
                }
                // Closes reach the joiner as a closed connection.
                let code = host_log.iter().find_map(|a| match a {
                    HostAction::Close { conn: c, code } if c.0 == conn => Some(*code),
                    _ => None,
                });
                if code.is_some() {
                    let j = self.joiner(&who);
                    let actions = j.pairing.on_closed(code);
                    settle(&mut j.pairing, actions);
                }
            }
            "redeliver" => {
                let m = self
                    .joiner(&who)
                    .first
                    .as_ref()
                    .expect("first message")
                    .clone();
                let ControlMessage::CodeExchange { attempt, .. } = m else {
                    panic!("first message")
                };
                let (actions, reply) = self.deliver_to_host(&who, conn, &m);
                self.check_reply(step, &who, attempt, &reply);
                host_log.extend(actions);
            }
            "inject" => {
                let attempt = match step["attempt"].as_str().expect("attempt") {
                    "current" => match self.joiner(&who).first.as_ref() {
                        Some(ControlMessage::CodeExchange { attempt, .. }) => *attempt,
                        _ => panic!("no current attempt"),
                    },
                    id => AttemptId(unhex(id).try_into().expect("16 bytes")),
                };
                let m = match step["message"].as_str() {
                    Some("code_exchange") => ControlMessage::CodeExchange {
                        attempt,
                        payload: unhex(step["payload"].as_str().expect("payload")),
                    },
                    Some("code_abort") => ControlMessage::CodeAbort {
                        attempt,
                        code: ErrorCode::PairingFailed,
                    },
                    other => panic!("message {other:?}"),
                };
                let (actions, reply) = self.deliver_to_host(&who, conn, &m);
                self.check_reply(step, &who, attempt, &reply);
                host_log.extend(actions);
            }
            "drop" => {
                let actions = self.host.on_connection_closed(ConnectionId(conn));
                self.host_did(&actions, conn);
                host_log.extend(actions);
                let j = self.joiner(&who);
                let actions = j.pairing.on_closed(None);
                settle(&mut j.pairing, actions);
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
                        self.host_did(&actions, conn);
                        host_log.extend(actions);
                    }
                    Err(HostPairingError::NotOpen) => assert_eq!(step["result"], "not_open"),
                    Err(other) => panic!("unexpected {other:?}"),
                }
            }
            other => panic!("unknown op {other}"),
        }
        if let Some(b) = step["new_code"].as_bool() {
            let shown = host_log
                .iter()
                .any(|a| matches!(a, HostAction::ShowCode { .. }));
            assert_eq!(shown, b, "new_code");
        }
        host_log
            .iter()
            .filter_map(|a| match a {
                HostAction::Close { conn, code } => Some((conn.0, code.name().to_owned())),
                _ => None,
            })
            .collect()
    }
}

/// Run one sequence and check every expectation in its steps. With
/// `listed`, the random values come from that list; without, from seeded
/// generators. Returns the sequence with its ticket, draws and each step's
/// `out`, as the file holds it.
fn run_attempt_sequence(seq: &J, listed: Option<&J>) -> J {
    let name = seq["name"].as_str().expect("name");
    let kind = match seq["kind"].as_str() {
        Some("send_link") => InvitationKind::SendLink,
        Some("in_person") => InvitationKind::InPerson,
        other => panic!("kind {other:?}"),
    };
    let mut r = Replay::new(kind, listed);
    let mut steps = Vec::new();
    for (i, step) in seq["steps"].as_array().expect("steps").iter().enumerate() {
        let ctx = format!("{name} step {i}");
        r.out.clear();
        let closed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| r.step(step)))
            .unwrap_or_else(|_| panic!("{ctx}"));
        if let Some(n) = step["host_attempts_left"].as_u64() {
            assert_eq!(
                r.host.attempts_left(&r.ticket.invitation).map(u64::from),
                Some(n),
                "{ctx}"
            );
        }
        if let Some(who) = step["joiner"].as_str() {
            if let Some(n) = step["joiner_attempts_left"].as_u64() {
                assert_eq!(u64::from(r.joiner(who).pairing.attempts_left()), n, "{ctx}");
            }
            if let Some(s) = step["joiner_state"].as_str() {
                assert_eq!(joiner_state_name(r.joiner(who).pairing.state()), s, "{ctx}");
            }
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
        let mut recorded = step.clone();
        recorded["out"] = J::Array(std::mem::take(&mut r.out));
        steps.push(recorded);
    }
    let mut draws = serde_json::Map::new();
    draws.insert("host".into(), J::Array(r.host_rng.log.clone()));
    assert!(r.host_rng.script.is_empty(), "{name}: unused host draws");
    for j in &r.joiners {
        assert!(
            j.rng.script.is_empty(),
            "{name}: unused draws of {}",
            j.name
        );
        draws.insert(j.name.clone(), J::Array(j.rng.log.clone()));
    }
    let mut out = seq.clone();
    out["ticket"] = json!(hex(&r.ticket.encode()));
    out["draws"] = J::Object(draws);
    out["steps"] = J::Array(steps);
    out
}

#[test]
fn pairing_attempt_sequences_hold() {
    let text = checked_in("pairing-attempts.json")
        .unwrap_or_else(|| serde_json::to_string(&pairing_attempt_vectors()).expect("json"));
    let doc: J = serde_json::from_str(&text).expect("json");
    for seq in doc["sequences"].as_array().expect("sequences") {
        // Replay from the file's own draws: every message must come out
        // byte for byte as listed.
        let replayed = run_attempt_sequence(seq, Some(&seq["draws"]));
        assert_eq!(&replayed, seq, "{}", seq["name"]);
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
        ("direct-code.json", direct_code_vectors()),
        ("mux.json", mux_vectors()),
        ("control.json", control_vectors()),
        ("hello.json", hello_vectors()),
        ("pairing-attempts.json", pairing_attempt_vectors()),
        ("direct-host.json", direct::direct_host_vectors()),
        ("relay-admission.json", relay::relay_admission_vectors()),
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
        } else if checked_in(name).as_deref() != Some(text.as_str()) {
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
