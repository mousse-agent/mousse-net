//! The route probe against an in-process host on loopback TCP, with a
//! stand-in app that counts what reaches it and refuses editor tunnels.
//!
//! The pre-auth cap here is the stand-in listener's, not the helper's (the
//! helper's pools are `phase1b.admission`'s), so the admission case shows
//! the probe tells a held connection from a refused one.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use mousse_check::probe::observe::Observer;
use mousse_check::probe::session::Target;
use mousse_check::probe::{self, tunnel, CaseResult, Plan, Waits};
use mousse_net_core::grants::OwnerRef;
use mousse_net_core::identity::SoftwareKey;
use mousse_net_core::pairing::{CpaceExchangeFactory, InvitationKind};
use mousse_net_io::rng::os_rng;
use mousse_net_io::{Host, HostConfig, Limits, SystemClock};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The stand-in app's counters, as the observer reports them.
#[derive(Default)]
struct Counters(Mutex<BTreeMap<&'static str, u64>>);

impl Counters {
    fn add(&self, k: &'static str) {
        *self.0.lock().unwrap().entry(k).or_default() += 1;
    }

    fn json(&self) -> String {
        let c = self.0.lock().unwrap();
        let get = |k| c.get(k).copied().unwrap_or(0);
        json!({
            "conn_up": get("conn_up"),
            "streams": get("streams"),
            "authorized_calls": get("authorized_calls"),
            "endpoint_sessions": get("endpoint_sessions"),
            "ledger_rows": get("ledger_rows"),
            "refusals": get("refusals"),
        })
        .to_string()
    }
}

/// What the stand-in app does wrong, to show the probe sees it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AppFault {
    None,
    /// Announces every connection before step 2 settles.
    AnnounceEarly,
    /// Starts an endpoint session for a tunnel although the editor is off.
    IgnoreEditorOff,
}

struct Rig {
    host: Host,
    addr: SocketAddr,
    observe: String,
    counters: Arc<Counters>,
}

async fn rig(preauth_cap: Option<usize>, fault: AppFault) -> Rig {
    let clock = Arc::new(SystemClock::new());
    let limits = Limits::DEFAULT
        .with_overrides(&[("JOIN_PROOF_WAIT_MS", 1_000)])
        .unwrap();
    let config = HostConfig {
        name: "probe host".into(),
        state_dir: None,
        owner: OwnerRef::from_bytes([0x5a; 16]),
        limits,
        clock,
        ticket_identity: None,
        streams: None,
    };
    let signer = Arc::new(SoftwareKey::generate(&mut os_rng()));
    let (host, _events) = Host::new(signer, config, CpaceExchangeFactory).unwrap();
    // Keep the event channel open for the host's lifetime.
    std::mem::forget(_events);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counters = Arc::new(Counters::default());
    let pending = Arc::new(AtomicUsize::new(0));
    {
        let host = host.clone();
        let counters = counters.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                if let Some(cap) = preauth_cap {
                    if pending.load(Ordering::SeqCst) >= cap {
                        drop(tcp);
                        continue;
                    }
                }
                pending.fetch_add(1, Ordering::SeqCst);
                let (host, counters, pending) = (host.clone(), counters.clone(), pending.clone());
                tokio::spawn(async move {
                    let accepted = host.accept(tcp).await;
                    let Ok(conn) = accepted else {
                        pending.fetch_sub(1, Ordering::SeqCst);
                        return;
                    };
                    let live = if fault == AppFault::AnnounceEarly {
                        counters.add("conn_up");
                        conn.settled(true).await.is_live()
                    } else {
                        let live = conn.settled(true).await.is_live();
                        if live {
                            counters.add("conn_up");
                        }
                        live
                    };
                    pending.fetch_sub(1, Ordering::SeqCst);
                    if !live {
                        return;
                    }
                    while let Some(stream) = conn.accept_stream().await {
                        counters.add("streams");
                        let label = stream.label().to_owned();
                        let (mut rd, wr) = stream.split();
                        let counters = counters.clone();
                        tokio::spawn(async move {
                            if label == "mousse.rpc" {
                                counters.add("authorized_calls");
                                return;
                            }
                            if label != "mousse.tunnel" {
                                return;
                            }
                            let mut got = Vec::new();
                            while !tunnel::complete(&got) {
                                match rd.read().await {
                                    Ok(Some(b)) => got.extend(b),
                                    _ => return,
                                }
                            }
                            if fault == AppFault::IgnoreEditorOff {
                                counters.add("endpoint_sessions");
                                let ready = tunnel::encode(&json!({"t": "tunnel.ready"}));
                                let _ = wr.write(&ready).await;
                            } else {
                                counters.add("refusals");
                                counters.add("ledger_rows");
                                let close = tunnel::encode(&json!({
                                    "t": "tunnel.close", "tunnel": "x", "reason": "editor_off"
                                }));
                                let _ = wr.write(&close).await;
                            }
                            wr.finish();
                        });
                    }
                });
            }
        });
    }
    let observe = serve_observer(counters.clone()).await;
    Rig {
        host,
        addr,
        observe,
        counters,
    }
}

/// A loopback HTTP server answering the counters.
async fn serve_observer(counters: Arc<Counters>) -> String {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let url = format!("http://{}/counters", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let body = counters.json();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    url
}

fn waits(cap: usize) -> Waits {
    Waits::from_vars(|k| match k {
        "MOUSSE_NET_JOIN_PROOF_WAIT_MS" => Some("1000".into()),
        "MOUSSE_CHECK_PROBE_SETTLE_MS" => Some("200".into()),
        "MOUSSE_CHECK_PROBE_CLOSE_MS" => Some("3000".into()),
        "MOUSSE_NET_PREAUTH_TCP" => Some(cap.to_string()),
        _ => None,
    })
    .unwrap()
}

const CAP: usize = 4;

async fn probe_rig(r: &Rig, cases: &[&'static str], cap: usize) -> Vec<CaseResult> {
    let invite = r
        .host
        .invite(InvitationKind::SendLink, vec![format!("tcp://{}", r.addr)])
        .unwrap();
    let removed = SoftwareKey::generate(&mut os_rng());
    let (grant, _) = r
        .host
        .add_grant(removed.public_key(), "removed".into(), None)
        .unwrap();
    r.host.remove_grant(grant.id).unwrap();
    let editor_off = SoftwareKey::generate(&mut os_rng());
    r.host
        .add_grant(editor_off.public_key(), "editor off".into(), None)
        .unwrap();
    let plan = Plan {
        target: Target::Tcp(r.addr),
        pin: Some(r.host.identity()),
        ticket: Some(invite.ticket),
        granted_editor_off: Some(editor_off),
        removed: Some(removed),
        observer: Some(Observer::parse(&r.observe).unwrap()),
        cases: cases.to_vec(),
        marker: "probe".into(),
        json: None,
        waits: waits(cap),
    };
    probe::run(&plan).await.unwrap()
}

fn show(results: &[CaseResult]) -> String {
    results
        .iter()
        .map(|r| {
            format!(
                "{}: want {:?} got {:?} app {:?} error {:?} -> {:?}",
                r.case,
                r.want,
                r.got,
                r.app,
                r.error,
                r.reason()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn reason_of(results: &[CaseResult], case: &str) -> Option<&'static str> {
    results.iter().find(|r| r.case == case).unwrap().reason()
}

#[tokio::test]
async fn every_tcp_case_passes_against_a_host_that_keeps_the_rules() {
    let r = rig(Some(CAP), AppFault::None).await;
    let cases = probe::cases_for(&Target::Tcp(r.addr));
    let results = probe_rig(&r, &cases, CAP).await;
    assert_eq!(probe::verdict(&results), None, "{}", show(&results));
    assert_eq!(results.len(), cases.len());
    // The editor-off case reached the app, as it must, and was refused.
    let c = r.counters.json();
    assert!(c.contains("\"refusals\":1"), "{c}");
    assert!(c.contains("\"endpoint_sessions\":0"), "{c}");
}

#[tokio::test]
async fn a_host_without_a_preauth_cap_fails_the_admission_case_on_the_wire() {
    let r = rig(None, AppFault::None).await;
    let results = probe_rig(&r, &["admission"], CAP).await;
    assert_eq!(
        reason_of(&results, "admission"),
        Some("wire_accepted"),
        "{}",
        show(&results)
    );
}

#[tokio::test]
async fn an_app_that_hears_of_a_connection_before_it_is_live_fails_with_probe_reached_app() {
    let r = rig(Some(CAP), AppFault::AnnounceEarly).await;
    let results = probe_rig(&r, &["fresh-open-rpc", "not-tls"], CAP).await;
    // The wire was right; the app record was not.
    let fresh = &results[0];
    assert_eq!(fresh.got, fresh.want, "{}", show(&results));
    assert_eq!(
        fresh.reason(),
        Some("probe_reached_app"),
        "{}",
        show(&results)
    );
    assert_eq!(probe::verdict(&results), Some("probe_reached_app"));
}

#[tokio::test]
async fn an_editor_tunnel_that_starts_a_session_fails_with_probe_reached_app() {
    let r = rig(Some(CAP), AppFault::IgnoreEditorOff).await;
    let results = probe_rig(&r, &["editor-off-tunnel"], CAP).await;
    assert_eq!(
        reason_of(&results, "editor-off-tunnel"),
        Some("probe_reached_app"),
        "{}",
        show(&results)
    );
}

#[tokio::test]
async fn an_observer_that_lies_about_nothing_still_needs_every_counter() {
    // A missing observer is an error, not a pass.
    let r = rig(Some(CAP), AppFault::None).await;
    let plan = Plan {
        target: Target::Tcp(r.addr),
        pin: Some(r.host.identity()),
        ticket: None,
        granted_editor_off: None,
        removed: None,
        observer: Some(Observer::parse("http://127.0.0.1:9/nothing").unwrap()),
        cases: vec!["not-tls"],
        marker: "probe".into(),
        json: None,
        waits: waits(CAP),
    };
    assert!(probe::run(&plan).await.is_err());
    // A case without its input is a probe error, never a pass.
    let plan = Plan {
        observer: None,
        cases: vec!["fresh-bad-proof"],
        ..plan
    };
    let results = probe::run(&plan).await.unwrap();
    assert_eq!(probe::verdict(&results), Some("probe_error"));
}
