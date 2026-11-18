//! Two profiles on one computer are two endpoints, each paired with its own
//! peer. Removing one endpoint's peer leaves the other endpoint alone, and
//! neither endpoint's peer can reach the other endpoint.
//!
//! The control tests run the same scenario with a deliberately broken setup
//! (one key or one grant table for both endpoints) and require it to fail.

mod common;

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use mousse_net_core::ErrorCode;
use mousse_net_io::keystore::KeyStorage;
use mousse_net_io::pipe::connect_tcp;
use mousse_net_io::{
    Caller, ConnStatus, Connection, Endpoint, HostConfig, ManualClock, PortChoice, SharedSigner,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Setup {
    /// Each endpoint has its own key and grant table.
    Separate,
    /// Broken: endpoint B signs with endpoint A's key.
    OneKey,
    /// Broken: endpoint B keeps its grants in endpoint A's grant file.
    OneGrantTable,
}

type Outcome = Result<(), String>;

fn check(ok: bool, what: &str) -> Outcome {
    if ok {
        Ok(())
    } else {
        Err(what.to_owned())
    }
}

/// Connect to `host` and require `AUTHORIZED {live}` straight away.
async fn dial_live(caller: &Caller, host: &TestHost) -> Result<Connection, String> {
    let pipe = connect_tcp(&host.route())
        .await
        .map_err(|e| e.to_string())?;
    let conn = caller
        .connect(pipe, host.identity())
        .await
        .map_err(|e| format!("handshake: {e}"))?;
    match tokio::time::timeout(Duration::from_secs(3), conn.settled(false)).await {
        Ok(status) if status.is_live() => Ok(conn),
        Ok(status) => Err(format!("not live: {status:?}")),
        Err(_) => Err("not authorized (still waiting for a join proof)".into()),
    }
}

/// Connect to `host` pinning `pin` and require a refusal: a pin mismatch in
/// the handshake, or `NOT_AUTHORIZED` from the host.
async fn expect_refused(
    caller: &Caller,
    host: &TestHost,
    pin: mousse_net_core::identity::IdentityPublicKey,
    want: &str,
) -> Outcome {
    let before = host.accepted.load(Ordering::SeqCst);
    let pipe = connect_tcp(&host.route())
        .await
        .map_err(|e| e.to_string())?;
    let conn = match caller.connect(pipe, pin).await {
        Err(e) if is_pin_mismatch(&e) => return check(want == "pin", "refused by pin, not grant"),
        Err(e) => return Err(format!("{want}: unexpected error {e}")),
        Ok(conn) if want == "pin" => {
            drop(conn);
            return Err("the other endpoint answered with the pinned identity".into());
        }
        Ok(conn) => conn,
    };
    within("host accepted", async {
        while host.accepted.load(Ordering::SeqCst) == before {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if conn.status().is_live() {
        return Err(format!("{want}: the other endpoint authorized the peer"));
    }
    host.skip_join_wait();
    match within("refusal", conn.settled(false)).await {
        ConnStatus::Closed(reason) if reason.code() == Some(ErrorCode::NotAuthorized) => Ok(()),
        other => Err(format!("{want}: expected NOT_AUTHORIZED, got {other:?}")),
    }
}

async fn start_b(endpoint: &mut Endpoint, signer: SharedSigner, grants_dir: &Path) -> TestHost {
    let clock = Arc::new(ManualClock::new());
    let mut config =
        HostConfig::for_endpoint(endpoint, "shared (B)".into(), clock.clone()).unwrap();
    config.state_dir = Some(grants_dir.to_path_buf());
    let listener = endpoint.bind(LOOPBACK, PortChoice::Kept).await.unwrap();
    TestHost::run(signer, config, clock, listener)
}

async fn scenario(setup: Setup, a_dir: &Path, b_dir: &Path) -> Outcome {
    // The shared computer: endpoints A and B, one state directory each.
    let (mut a_ep, a_key) = Endpoint::create(a_dir, None, KeyStorage::InsecureFile).unwrap();
    let (mut b_ep, b_key) = Endpoint::create(b_dir, None, KeyStorage::InsecureFile).unwrap();
    check(
        a_ep.identity() != b_ep.identity(),
        "endpoints got the same key",
    )?;
    let a_signer: SharedSigner = Arc::new(a_key);
    let b_signer: SharedSigner = match setup {
        Setup::OneKey => a_signer.clone(),
        _ => Arc::new(b_key),
    };
    let b_grants = match setup {
        Setup::OneGrantTable => a_dir.to_path_buf(),
        _ => b_dir.to_path_buf(),
    };
    let mut a = TestHost::start_endpoint(&mut a_ep, a_signer, "shared (A)").await;
    let mut b = start_b(&mut b_ep, b_signer, &b_grants).await;
    check(a.addr.port() != b.addr.port(), "both endpoints on one port")?;

    // Each endpoint pairs with its own peer; both have a live terminal.
    let pa = new_caller(new_signer());
    let pb = new_caller(new_signer());
    let pa_conn = pair(&pa, &mut a, "peer of A").await;
    let mut pa_term = open_echo(&pa_conn).await;
    let pb_conn = pair(&pb, &mut b, "peer of B").await;
    let mut pb_term = open_echo(&pb_conn).await;

    // B removes its peer: B's channel closes at once.
    let grant = b
        .grant_of(&pb.identity())
        .ok_or("B has no grant for its peer")?;
    check(
        matches!(b.host.remove_grant(grant), Ok(true)),
        "B could not remove its peer",
    )?;
    check(
        close_code(&pb_conn).await == Some(ErrorCode::GrantRevoked),
        "B's channel did not close with GRANT_REVOKED",
    )?;
    check(
        pb_term.reader.read().await.is_err(),
        "B's terminal stayed open",
    )?;

    // A's terminal stays open and A still knows its peer.
    check(pa_conn.status().is_live(), "A's channel closed")?;
    assert_echo(&mut pa_term, b"still here\n").await;
    check(a.grant_of(&pa.identity()).is_some(), "A lost its grant")?;

    // Neither endpoint's peer reaches the other endpoint.
    expect_refused(&pa, &b, a.identity(), "pin").await?;
    expect_refused(&pa, &b, b.identity(), "grant").await?;
    expect_refused(&pb, &a, a.identity(), "grant").await?;

    // Discovery hands A's peer both addresses: B's is skipped, A's is used.
    let (via_lan, used) = within(
        "candidates",
        pa.dial_candidates(&[b.route(), a.route()], a.identity()),
    )
    .await
    .map_err(|e| format!("A's peer could not find A among the candidates: {e}"))?;
    check(used == a.route(), "A's peer settled on B's address")?;
    drop(via_lan);

    // A restarts; its peer reconnects and opens a terminal again.
    drop(pa_term);
    drop(pa_conn);
    a.stop().await;
    drop(a_ep);
    let mut a_ep = Endpoint::open(a_dir).unwrap();
    let a_signer = endpoint_signer(&a_ep);
    let a = TestHost::start_endpoint(&mut a_ep, a_signer, "shared (A)").await;
    let pa_conn = dial_live(&pa, &a)
        .await
        .map_err(|e| format!("A's peer could not reconnect after A restarted: {e}"))?;
    open_echo(&pa_conn).await;
    expect_refused(&pb, &a, a.identity(), "grant").await?;

    drop(pa_conn);
    a.stop().await;
    b.stop().await;
    Ok(())
}

async fn run(setup: Setup, tag: &str) -> Outcome {
    let a_dir = temp_dir(&format!("{tag}-a"));
    let b_dir = temp_dir(&format!("{tag}-b"));
    let outcome = scenario(setup, &a_dir, &b_dir).await;
    let _ = std::fs::remove_dir_all(&a_dir);
    let _ = std::fs::remove_dir_all(&b_dir);
    outcome
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_endpoints_on_one_computer_stay_separate() {
    if let Err(e) = run(Setup::Separate, "sep").await {
        panic!("FAIL: {e}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_one_key_for_both_endpoints_fails_the_scenario() {
    match run(Setup::OneKey, "onekey").await {
        Err(e) => println!("control FAIL as required: {e}"),
        Ok(()) => panic!("the scenario passed with one key for both endpoints"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_one_grant_table_for_both_endpoints_fails_the_scenario() {
    match run(Setup::OneGrantTable, "onetable").await {
        Err(e) => println!("control FAIL as required: {e}"),
        Ok(()) => panic!("the scenario passed with one grant table for both endpoints"),
    }
}
