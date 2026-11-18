//! Runs every case for one provider pair and judges the results.

use serde::{Deserialize, Serialize};

use crate::handshake::{self, Case, Established, Outcome, Params, Refused};
use crate::provider::Provider;

/// Check name the owner test kit looks for.
pub const CHECK: &str = "phase0.crypto-matrix";

/// Prefix of result lines printed to a log, collected by
/// `scripts/matrix-results.mjs --stdin`.
pub const RESULT_LINE_PREFIX: &str = "MATRIX_RESULT ";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Both endpoints in one process, records passed through memory.
    Pipe,
    /// A real socket on 127.0.0.1 (native only).
    Tcp,
}

impl Transport {
    pub fn name(self) -> &'static str {
        match self {
            Transport::Pipe => "pipe",
            Transport::Tcp => "tcp",
        }
    }

    /// Transports this target can run.
    pub fn available() -> Vec<Transport> {
        if cfg!(target_arch = "wasm32") {
            vec![Transport::Pipe]
        } else {
            vec![Transport::Pipe, Transport::Tcp]
        }
    }
}

/// One machine-readable result per run (one provider pair on one target).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixResult {
    pub check: String,
    pub target: String,
    pub provider: String,
    /// PASS, FAIL or INCOMPLETE.
    pub outcome: String,
    pub kx_group: String,
    pub suite: String,
    pub build: String,
    pub details: String,
}

#[derive(Clone, Debug)]
pub struct CaseResult {
    pub transport: Transport,
    pub case: Case,
    pub pass: bool,
    pub note: String,
    pub established: Option<Established>,
}

/// Every ordered (client, server) pair of compiled providers: same-provider
/// pairs first, then cross pairs.
pub fn pairs(include_cross: bool) -> Vec<(Provider, Provider)> {
    let all = Provider::compiled();
    let mut out: Vec<(Provider, Provider)> = all.iter().map(|p| (*p, *p)).collect();
    if include_cross {
        for c in &all {
            for s in &all {
                if c != s {
                    out.push((*c, *s));
                }
            }
        }
    }
    out
}

/// Label for the `provider` field: one name, or `client>server` for a cross pair.
pub fn provider_label(client: Provider, server: Provider) -> String {
    if client == server {
        client.name().to_string()
    } else {
        format!("{}>{}", client.name(), server.name())
    }
}

/// The hybrid post-quantum group is expected exactly when both ends offer it.
pub fn expect_pq(params: &Params) -> bool {
    params.client.has_pq() && params.server.has_pq()
}

pub fn is_pq_group(name: &str) -> bool {
    name.contains("MLKEM")
}

fn short(e: &Option<rustls::Error>) -> String {
    match e {
        Some(e) => format!("{e:?}"),
        None => "none".to_string(),
    }
}

fn refused_note(r: &Refused) -> String {
    format!("client={} server={}", short(&r.client), short(&r.server))
}

fn judge_mutual(params: &Params, outcome: &Outcome) -> (bool, String) {
    let est = match outcome {
        Ok(est) => est,
        Err(r) => return (false, format!("refused, must succeed: {}", refused_note(r))),
    };
    let (c, s) = (&est.client, &est.server);
    let mut problems = Vec::new();
    if c.kx_group != s.kx_group {
        problems.push(format!(
            "kx differs: client {} server {}",
            c.kx_group, s.kx_group
        ));
    }
    if c.suite != s.suite {
        problems.push(format!(
            "suite differs: client {} server {}",
            c.suite, s.suite
        ));
    }
    if c.version != "TLSv1_3" || s.version != "TLSv1_3" {
        problems.push(format!(
            "version: client {} server {}",
            c.version, s.version
        ));
    }
    if c.exporter != s.exporter {
        problems.push("exporter values differ between sides".to_string());
    }
    if c.exporter.iter().all(|b| *b == 0) {
        problems.push("exporter is all zero".to_string());
    }
    if is_pq_group(&c.kx_group) != expect_pq(params) {
        problems.push(format!(
            "kx {} but post-quantum expected = {}",
            c.kx_group,
            expect_pq(params)
        ));
    }
    let base = format!(
        "kx={} suite={} handshake={} exporter equal on both sides ({} bytes)",
        c.kx_group,
        c.suite,
        c.kind,
        c.exporter.len()
    );
    if problems.is_empty() {
        (true, base)
    } else {
        (false, format!("{base}; {}", problems.join("; ")))
    }
}

/// Judges a case that must be refused. `side_ok` checks the error on the side
/// that is expected to detect the problem; the other side must also fail.
fn judge_refusal(
    outcome: &Outcome,
    detector: &str,
    side_ok: impl Fn(&Refused) -> bool,
) -> (bool, String) {
    match outcome {
        Ok(est) => (
            false,
            format!("accepted, must be refused (kx={})", est.client.kx_group),
        ),
        Err(r) => {
            let both = r.client.is_some() && r.server.is_some();
            let pass = side_ok(r) && both;
            let note = format!("refused by {detector}: {}", refused_note(r));
            if pass {
                (true, note)
            } else {
                (false, format!("unexpected refusal: {note}"))
            }
        }
    }
}

pub fn judge(case: Case, params: &Params, outcome: &Outcome) -> (bool, String) {
    use rustls::{CertificateError, Error};
    let pin_mismatch = |e: &Option<Error>| {
        matches!(
            e,
            Some(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure
            ))
        )
    };
    match case {
        Case::Mutual => judge_mutual(params, outcome),
        Case::WrongServerPin => judge_refusal(outcome, "client", |r| pin_mismatch(&r.client)),
        Case::WrongClientPin => judge_refusal(outcome, "server", |r| pin_mismatch(&r.server)),
        Case::MissingClientCert => judge_refusal(outcome, "server", |r| {
            matches!(r.server, Some(Error::NoCertificatesPresented))
        }),
        Case::Tls12Only => judge_refusal(outcome, "server", |r| {
            matches!(r.server, Some(Error::PeerIncompatible(_)))
        }),
    }
}

pub fn run_transport(transport: Transport, setup: &handshake::Setup) -> Outcome {
    match transport {
        Transport::Pipe => handshake::run_pipe(setup),
        #[cfg(not(target_arch = "wasm32"))]
        Transport::Tcp => crate::tcp::run_tcp(setup),
        #[cfg(target_arch = "wasm32")]
        Transport::Tcp => Err(Box::new(Refused {
            client: Some(rustls::Error::General("no TCP on wasm32".into())),
            server: None,
        })),
    }
}

pub fn run_case(case: Case, transport: Transport, params: &Params) -> CaseResult {
    let setup = match handshake::build(case, *params) {
        Ok(s) => s,
        Err(e) => {
            return CaseResult {
                transport,
                case,
                pass: false,
                note: format!("setup failed: {e}"),
                established: None,
            }
        }
    };
    let outcome = run_transport(transport, &setup);
    let (pass, note) = judge(case, params, &outcome);
    CaseResult {
        transport,
        case,
        pass,
        note,
        established: outcome.ok(),
    }
}

/// Runs every case on every transport for one provider pair.
pub fn run(
    params: Params,
    transports: &[Transport],
    target: &str,
    build: &str,
) -> (MatrixResult, Vec<CaseResult>) {
    let mut cases = Vec::new();
    for t in transports {
        for case in Case::ALL {
            cases.push(run_case(case, *t, &params));
        }
    }

    let mut extra = Vec::new();
    // Separate sessions must not derive the same exporter value.
    let exporters: Vec<&Vec<u8>> = cases
        .iter()
        .filter_map(|c| c.established.as_ref().map(|e| &e.client.exporter))
        .collect();
    for (i, a) in exporters.iter().enumerate() {
        if exporters[i + 1..].iter().any(|b| b == a) {
            extra.push("exporter value repeated across sessions".to_string());
        }
    }

    let pass = cases.iter().all(|c| c.pass) && extra.is_empty() && !cases.is_empty();
    let first = cases
        .iter()
        .find(|c| c.case == Case::Mutual && c.established.is_some())
        .and_then(|c| c.established.as_ref());

    let mut details = vec![format!(
        "client {} offers {:?}; server {} accepts {:?}",
        params.client.name(),
        params.client.kx_groups(),
        params.server.name(),
        params.server.kx_groups()
    )];
    if params.break_pin {
        details.push("broken mode: the client pins the wrong server key".to_string());
    }
    for c in &cases {
        details.push(format!(
            "{}/{}: {} {}",
            c.transport.name(),
            c.case.name(),
            if c.pass { "PASS" } else { "FAIL" },
            c.note
        ));
    }
    details.extend(extra);

    let result = MatrixResult {
        check: CHECK.to_string(),
        target: target.to_string(),
        provider: provider_label(params.client, params.server),
        outcome: if pass { "PASS" } else { "FAIL" }.to_string(),
        kx_group: first.map(|e| e.client.kx_group.clone()).unwrap_or_default(),
        suite: first.map(|e| e.client.suite.clone()).unwrap_or_default(),
        build: build.to_string(),
        details: details.join(" | "),
    };
    (result, cases)
}

/// File name for a result: `<target>__<client>__<server>.json`.
pub fn result_file_name(result_target: &str, client: Provider, server: Provider) -> String {
    format!(
        "{}__{}__{}.json",
        result_target,
        client.name(),
        server.name()
    )
}
