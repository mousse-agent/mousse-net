//! Native checks: every compiled provider pair, both transports, the
//! negotiated group, the exporter, and the deliberately broken mode.
#![cfg(not(target_arch = "wasm32"))]

use tls_matrix::handshake::{Case, Params};
use tls_matrix::matrix::{self, Transport};
use tls_matrix::provider::Provider;

const NOW: u64 = 1_795_000_000;

fn params(client: Provider, server: Provider) -> Params {
    Params {
        client,
        server,
        now_unix_secs: NOW,
        break_pin: false,
    }
}

#[test]
fn every_compiled_pair_passes_on_pipe_and_tcp() {
    let pairs = matrix::pairs(true);
    assert!(!pairs.is_empty(), "no provider compiled in");
    for (c, s) in pairs {
        let (result, cases) = matrix::run(
            params(c, s),
            &Transport::available(),
            tls_matrix::TARGET,
            "test",
        );
        assert_eq!(
            result.outcome, "PASS",
            "{}: {}",
            result.provider, result.details
        );
        assert_eq!(cases.len(), Case::ALL.len() * 2);
    }
}

#[cfg(feature = "aws-lc")]
#[test]
fn aws_lc_rs_on_both_ends_negotiates_the_hybrid_group() {
    for t in Transport::available() {
        let r = matrix::run_case(
            Case::Mutual,
            t,
            &params(Provider::AwsLcRs, Provider::AwsLcRs),
        );
        assert!(r.pass, "{}", r.note);
        let est = r.established.expect("established");
        assert_eq!(est.client.kx_group, "X25519MLKEM768");
        assert_eq!(est.server.kx_group, "X25519MLKEM768");
        assert_eq!(est.client.version, "TLSv1_3");
        assert_eq!(est.client.kind, "Full");
    }
}

#[cfg(all(feature = "aws-lc", feature = "ring"))]
#[test]
fn hybrid_client_falls_back_to_x25519_without_a_retry() {
    // A native client talking to a classical-only peer (ring, as on wasm32)
    // still needs one round trip: the hybrid ClientHello also carries an
    // X25519 share, so there is no HelloRetryRequest.
    let r = matrix::run_case(
        Case::Mutual,
        Transport::Pipe,
        &params(Provider::AwsLcRs, Provider::Ring),
    );
    assert!(r.pass, "{}", r.note);
    let est = r.established.expect("established");
    assert_eq!(est.client.kx_group, "X25519");
    assert_eq!(est.client.kind, "Full");
}

#[test]
fn both_sides_export_the_same_value_and_sessions_differ() {
    let p = Provider::compiled()[0];
    let a = matrix::run_case(Case::Mutual, Transport::Pipe, &params(p, p));
    let b = matrix::run_case(Case::Mutual, Transport::Pipe, &params(p, p));
    let (a, b) = (a.established.expect("a"), b.established.expect("b"));
    assert_eq!(a.client.exporter, a.server.exporter);
    assert_eq!(a.client.exporter.len(), 32);
    assert_ne!(a.client.exporter, b.client.exporter);
}

#[test]
fn broken_mode_fails() {
    for (c, s) in matrix::pairs(false) {
        let mut p = params(c, s);
        p.break_pin = true;
        let (result, _) = matrix::run(p, &[Transport::Pipe], tls_matrix::TARGET, "test");
        assert_eq!(
            result.outcome, "FAIL",
            "{} passed in broken mode",
            result.provider
        );
        assert!(result.kx_group.is_empty());
    }
}

#[test]
fn a_refusal_case_that_connects_is_judged_fail() {
    // The judge must be able to fail: a working handshake judged as a case
    // that should have been refused.
    let p = Provider::compiled()[0];
    let setup = tls_matrix::handshake::build(Case::Mutual, params(p, p)).expect("setup");
    let outcome = matrix::run_transport(Transport::Pipe, &setup);
    assert!(outcome.is_ok());
    for case in [
        Case::WrongServerPin,
        Case::WrongClientPin,
        Case::MissingClientCert,
        Case::Tls12Only,
    ] {
        let (pass, note) = matrix::judge(case, &params(p, p), &outcome);
        assert!(!pass, "{}: {note}", case.name());
    }
}

#[test]
fn result_json_has_the_kit_fields() {
    let p = Provider::compiled()[0];
    let (result, _) = matrix::run(params(p, p), &[Transport::Pipe], "t", "abc+debug");
    let v: serde_json::Value = serde_json::to_value(&result).expect("json");
    for key in [
        "check", "target", "provider", "outcome", "kx_group", "suite", "build", "details",
    ] {
        assert!(v.get(key).is_some_and(|x| x.is_string()), "missing {key}");
    }
    assert_eq!(v["check"], "phase0.crypto-matrix");
}

#[cfg(all(
    feature = "aws-lc",
    feature = "ring",
    feature = "rustcrypto",
    feature = "pq-pure"
))]
#[test]
fn pure_rust_hybrid_interoperates_with_aws_lc_rs_both_ways() {
    for (c, s) in [
        (Provider::AwsLcRs, Provider::RingPq),
        (Provider::RingPq, Provider::AwsLcRs),
        (Provider::AwsLcRs, Provider::RustCryptoPq),
        (Provider::RustCryptoPq, Provider::AwsLcRs),
    ] {
        let r = matrix::run_case(Case::Mutual, Transport::Tcp, &params(c, s));
        assert!(r.pass, "{}>{}: {}", c.name(), s.name(), r.note);
        let est = r.established.expect("established");
        assert_eq!(
            est.client.kx_group,
            "X25519MLKEM768",
            "{}>{}",
            c.name(),
            s.name()
        );
        assert_eq!(est.client.kind, "Full");
    }
}

#[cfg(all(feature = "ring", feature = "pq-pure"))]
#[test]
fn pure_rust_hybrid_client_uses_its_x25519_half_with_a_classical_server() {
    let r = matrix::run_case(
        Case::Mutual,
        Transport::Pipe,
        &params(Provider::RingPq, Provider::Ring),
    );
    assert!(r.pass, "{}", r.note);
    let est = r.established.expect("established");
    assert_eq!(est.client.kx_group, "X25519");
    assert_eq!(est.client.kind, "Full", "no HelloRetryRequest expected");
}

#[cfg(feature = "pq-pure")]
mod pq_group {
    use tls_matrix::pq::X25519MLKEM768;

    const CLIENT_SHARE: usize = 1184 + 32;
    const SERVER_SHARE: usize = 1088 + 32;

    #[test]
    fn both_halves_derive_the_same_secret() {
        let client = X25519MLKEM768.start().expect("start");
        assert_eq!(client.pub_key().len(), CLIENT_SHARE);
        let server = X25519MLKEM768
            .start_and_complete(client.pub_key())
            .expect("server");
        assert_eq!(server.pub_key.len(), SERVER_SHARE);
        let secret = client.complete(&server.pub_key).expect("client");
        assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());
        assert_eq!(secret.secret_bytes().len(), 64);
    }

    #[test]
    fn a_tampered_ciphertext_gives_a_different_secret() {
        // ML-KEM rejects implicitly: decapsulation succeeds with a different
        // secret, so the handshake later fails on Finished.
        let client = X25519MLKEM768.start().expect("start");
        let server = X25519MLKEM768
            .start_and_complete(client.pub_key())
            .expect("server");
        let mut share = server.pub_key.clone();
        share[10] ^= 1;
        let secret = client.complete(&share).expect("client");
        assert_ne!(secret.secret_bytes(), server.secret.secret_bytes());
    }

    #[test]
    fn wrong_share_lengths_are_refused() {
        let client = X25519MLKEM768.start().expect("start");
        let mut long = client.pub_key().to_vec();
        long.push(0);
        assert!(X25519MLKEM768.start_and_complete(&long).is_err());
        assert!(X25519MLKEM768
            .start_and_complete(&client.pub_key()[..CLIENT_SHARE - 1])
            .is_err());
        assert!(client.complete(&[0u8; SERVER_SHARE - 1]).is_err());
    }

    #[test]
    fn an_all_zero_x25519_key_is_refused() {
        let client = X25519MLKEM768.start().expect("start");
        let mut share = client.pub_key().to_vec();
        share[1184..].fill(0);
        assert!(X25519MLKEM768.start_and_complete(&share).is_err());
    }
}
