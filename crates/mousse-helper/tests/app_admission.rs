//! E10: pre-auth admission per listener kind (Phase 1b §6.2). Per-kind
//! pools taken at accept, per-source shares on TCP (IPv4 address or IPv6
//! /64), places held through join-only until the invitation ends, a
//! re-pair from live that takes a new place and meets the fence, the
//! admission fence at gate registration and enrollment on every listener
//! kind, the bounded IPC reader, and tighten-only limits. The check cell
//! `phase1b.admission` runs this file.
//!
//! The engine cases run a `Host` in this process, so a handshake can be
//! held at an exact TLS record while the fence is set or the pool fills.
//! The helper cases run `serve`.

mod common;

use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use mousse_net_core::grants::{GrantId, OwnerRef};
use mousse_net_core::identity::SoftwareKey;
use mousse_net_core::pairing::{Arrival, CpaceExchangeFactory, InvitationKind, Ticket};
use mousse_net_core::ErrorCode;
use mousse_net_io::preauth::PreAuthFull;
use mousse_net_io::rng::os_rng;
use mousse_net_io::{
    ApprovalRequest, Caller, Clock, CloseReason, ConnStatus, Connection, Host, HostConfig,
    HostEvent, JoinOutcome, Limits, ListenerKind, ManualClock, NetError, Refusal,
};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, Notify};

// ---------------------------------------------------------------------
// Engine cases: a host in this process.
// ---------------------------------------------------------------------

struct Engine {
    host: Host,
    events: mpsc::UnboundedReceiver<HostEvent>,
    clock: Arc<ManualClock>,
}

/// A host with these limits overridden (names without `MOUSSE_NET_`).
fn engine(overrides: &[(&str, u64)]) -> Engine {
    let clock = Arc::new(ManualClock::new());
    let config = HostConfig {
        name: "desk".into(),
        state_dir: None,
        owner: OwnerRef([1; OwnerRef::LEN]),
        limits: Limits::DEFAULT.with_overrides(overrides).unwrap(),
        clock: clock.clone(),
        ticket_identity: None,
        streams: None,
    };
    let key = Arc::new(SoftwareKey::generate(&mut os_rng()));
    let (host, events) = Host::new(key, config, CpaceExchangeFactory).unwrap();
    Engine {
        host,
        events,
        clock,
    }
}

fn new_caller() -> Caller {
    Caller::new(
        Arc::new(SoftwareKey::generate(&mut os_rng())),
        Arc::new(ManualClock::new()),
        Limits::DEFAULT,
    )
}

/// A caller the host grants.
fn granted_caller(host: &Host) -> (Caller, GrantId) {
    let caller = new_caller();
    let (grant, _) = host
        .add_grant(caller.identity(), "laptop".into(), None)
        .unwrap();
    (caller, grant.id)
}

fn in_person(host: &Host) -> Ticket {
    host.invite(InvitationKind::InPerson, Vec::new())
        .unwrap()
        .ticket
}

async fn within<T>(what: &str, fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .unwrap_or_else(|_| panic!("timed out: {what}"))
}

/// Wait until `ok` holds, for up to five seconds.
async fn until(what: &str, ok: impl Fn() -> bool) {
    within(what, async {
        while !ok() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
}

async fn next_request(events: &mut mpsc::UnboundedReceiver<HostEvent>) -> ApprovalRequest {
    within("an approval request", async {
        loop {
            if let Some(HostEvent::ApprovalRequested(request)) = events.recv().await {
                return request;
            }
        }
    })
    .await
}

/// Whether no approval was asked for within `ms`.
async fn no_request_within(events: &mut mpsc::UnboundedReceiver<HostEvent>, ms: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Some(HostEvent::ApprovalRequested(_))) => return false,
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => return true,
        }
    }
}

fn open(host: &Host, kind: ListenerKind) -> u64 {
    host.preauth_stats().open(kind)
}

type Accepted = tokio::task::JoinHandle<Result<Connection, NetError>>;
type Joining = tokio::task::JoinHandle<Result<(Connection, JoinOutcome), NetError>>;

/// The host accepts `pipe` holding a place of `kind`, taken now.
fn accept_as(host: &Host, kind: ListenerKind, pipe: DuplexStream) -> Accepted {
    let slot = host.admit(kind, None).unwrap();
    let host = host.clone();
    tokio::spawn(async move { host.accept_admitted(pipe, slot).await })
}

fn join(caller: Caller, pipe: DuplexStream, ticket: Ticket) -> Joining {
    tokio::spawn(async move {
        caller
            .join(pipe, &ticket, Arrival::InAppScan, "laptop")
            .await
    })
}

/// Where [`held_pipe`] stops the caller's bytes.
enum Stop {
    /// Before the first byte: the handshake has not begun.
    BeforeFirst,
    /// After the caller's encrypted record that made the connection live
    /// under this grant: the handshake is done and step 2 said live, and
    /// what the caller sends next (its `JOIN_PROOF`) waits.
    AfterLive(Host, GrantId),
}

/// A pipe stopped at a TLS record boundary until `release` is notified;
/// `reached` is notified when it stops.
struct Held {
    reached: Arc<Notify>,
    release: Arc<Notify>,
}

/// A pipe between a caller (first) and the host (second) whose
/// caller-to-host direction stops as `stop` says.
fn held_pipe(stop: Stop) -> (DuplexStream, DuplexStream, Held) {
    let (caller_end, relay_c) = tokio::io::duplex(1 << 16);
    let (relay_h, host_end) = tokio::io::duplex(1 << 16);
    let (mut c_rd, mut c_wr) = tokio::io::split(relay_c);
    let (mut h_rd, mut h_wr) = tokio::io::split(relay_h);
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut h_rd, &mut c_wr).await;
        let _ = c_wr.shutdown().await;
    });
    let held = Held {
        reached: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    };
    let (reached, release) = (held.reached.clone(), held.release.clone());
    tokio::spawn(async move {
        if matches!(stop, Stop::BeforeFirst) {
            reached.notify_one();
            release.notified().await;
        }
        let mut stopped = false;
        loop {
            let mut header = [0u8; 5];
            if c_rd.read_exact(&mut header).await.is_err() {
                break;
            }
            let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            let mut body = vec![0u8; len];
            if c_rd.read_exact(&mut body).await.is_err() {
                break;
            }
            if h_wr.write_all(&header).await.is_err() || h_wr.write_all(&body).await.is_err() {
                break;
            }
            let _ = h_wr.flush().await;
            // An encrypted record (TLS 1.3 wraps the caller's Finished in
            // one): stop once the host has the connection live.
            if let (Stop::AfterLive(host, grant), false, 23) = (&stop, stopped, header[0]) {
                for _ in 0..50 {
                    if host.connections_for(*grant) > 0 {
                        stopped = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                if stopped {
                    reached.notify_one();
                    release.notified().await;
                }
            }
        }
        let _ = h_wr.shutdown().await;
    });
    (caller_end, host_end, held)
}

/// The pools do not share: with the ws pool full, a pipe and a TCP
/// connection still get a place. One more of a full kind is refused and
/// counted.
#[tokio::test(flavor = "multi_thread")]
async fn each_listener_kind_has_its_own_pool() {
    let e = engine(&[("PREAUTH_TCP", 1), ("PREAUTH_WS", 1), ("PREAUTH_PIPE", 1)]);
    let _ws = e.host.admit(ListenerKind::Ws, None).unwrap();
    assert_eq!(
        e.host.admit(ListenerKind::Ws, None).unwrap_err(),
        Refusal::Full(PreAuthFull::Pool(ListenerKind::Ws))
    );
    let _pipe = e
        .host
        .admit(ListenerKind::Pipe, None)
        .expect("a full ws pool took the pipe's place");
    let _tcp = e
        .host
        .admit(ListenerKind::Tcp, Some([127, 0, 0, 1].into()))
        .expect("a full ws pool took the TCP place");
    assert_eq!(
        e.host.admit(ListenerKind::Pipe, None).unwrap_err(),
        Refusal::Full(PreAuthFull::Pool(ListenerKind::Pipe))
    );
    let stats = e.host.preauth_stats();
    for kind in ListenerKind::ALL {
        assert_eq!(stats.open(kind), 1, "{kind:?}");
    }
    assert_eq!(stats.refused(ListenerKind::Ws), 1);
    assert_eq!(stats.refused(ListenerKind::Pipe), 1);
    assert_eq!(stats.refused(ListenerKind::Tcp), 0);
}

/// On TCP each IPv4 address, or each IPv6 /64, has its own share; an
/// IPv4-mapped IPv6 address counts as its IPv4 address.
#[tokio::test(flavor = "multi_thread")]
async fn tcp_sources_count_per_ipv4_address_and_per_ipv6_64() {
    let e = engine(&[("PREAUTH_PER_SOURCE", 1)]);
    let tcp = ListenerKind::Tcp;
    let ip = |text: &str| Some(text.parse::<std::net::IpAddr>().unwrap());
    let _a = e.host.admit(tcp, ip("2001:db8:1:2::1")).unwrap();
    assert_eq!(
        e.host.admit(tcp, ip("2001:db8:1:2:ffff::9")).unwrap_err(),
        Refusal::Full(PreAuthFull::Source),
        "another address in the same /64"
    );
    let _b = e.host.admit(tcp, ip("2001:db8:1:3::1")).unwrap();
    let _c = e.host.admit(tcp, ip("192.168.1.7")).unwrap();
    assert_eq!(
        e.host.admit(tcp, ip("::ffff:192.168.1.7")).unwrap_err(),
        Refusal::Full(PreAuthFull::Source)
    );
    let _d = e.host.admit(tcp, ip("192.168.1.8")).unwrap();
}

/// A join-only connection keeps its place while the owner decides, so a
/// flood of valid-ticket joins cannot grow past the pool; enrollment frees
/// it.
#[tokio::test(flavor = "multi_thread")]
async fn a_join_only_connection_holds_its_place_until_enrolled() {
    let mut e = engine(&[("PREAUTH_TCP", 1)]);
    let ticket = in_person(&e.host);
    let (a, b) = tokio::io::duplex(1 << 16);
    let _hosted = accept_as(&e.host, ListenerKind::Tcp, a);
    let joining = join(new_caller(), b, ticket);
    let request = next_request(&mut e.events).await;
    assert_eq!(open(&e.host, ListenerKind::Tcp), 1);
    assert_eq!(
        e.host.admit(ListenerKind::Tcp, None).unwrap_err(),
        Refusal::Full(PreAuthFull::Pool(ListenerKind::Tcp))
    );
    e.host.approve(&request).unwrap();
    let (_conn, outcome) = within("the join", joining).await.unwrap().unwrap();
    assert!(matches!(outcome, JoinOutcome::Paired(_)));
    until("the place is free", || {
        open(&e.host, ListenerKind::Tcp) == 0
    })
    .await;
    e.host.admit(ListenerKind::Tcp, None).unwrap();
}

/// How an invitation ends while a joiner waits.
enum Ending {
    Cancel,
    Decline,
    Expire,
}

/// The invitation ends while its joiner is join-only: the host closes the
/// connection and its place is free.
async fn ending_frees_the_place(ending: Ending) {
    let mut e = engine(&[]);
    let ticket = in_person(&e.host);
    let invitation = ticket.invitation;
    let expires_at = ticket.expires_at;
    let (a, b) = tokio::io::duplex(1 << 16);
    let _hosted = accept_as(&e.host, ListenerKind::Tcp, a);
    let joining = join(new_caller(), b, ticket);
    next_request(&mut e.events).await;
    assert_eq!(open(&e.host, ListenerKind::Tcp), 1);
    match ending {
        Ending::Cancel => e.host.cancel(&invitation),
        Ending::Decline => e.host.decline(&invitation),
        Ending::Expire => {
            let left = expires_at.0.saturating_sub(e.clock.now().0);
            e.clock.advance(i64::try_from(left).unwrap() + 1);
        }
    }
    let ended = within("the join ends", joining).await.unwrap();
    assert!(ended.is_err(), "the join went on");
    until("the place is free", || {
        open(&e.host, ListenerKind::Tcp) == 0
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_invitation_closes_its_join_only_connection_and_frees_the_place() {
    ending_frees_the_place(Ending::Cancel).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declined_join_closes_and_frees_the_place() {
    ending_frees_the_place(Ending::Decline).await;
}

/// The invitation's expiry bounds how long a join-only connection holds
/// its place.
#[tokio::test(flavor = "multi_thread")]
async fn an_expired_invitation_closes_its_join_only_connection_and_frees_the_place() {
    ending_frees_the_place(Ending::Expire).await;
}

/// A granted device whose handshake began before the fence was set and
/// finished after it: the fence at gate registration closes it, whatever
/// its listener let in at accept.
async fn the_fence_closes_at_registration(kind: ListenerKind) {
    let e = engine(&[]);
    let (caller, grant) = granted_caller(&e.host);
    let (caller_end, host_end, held) = held_pipe(Stop::BeforeFirst);
    let hosted = accept_as(&e.host, kind, host_end);
    let identity = e.host.identity();
    let _dialled = tokio::spawn(async move { caller.dial(caller_end, identity).await });
    within("the handshake is held", held.reached.notified()).await;
    e.host.set_fence(true);
    held.release.notify_one();
    let conn = within("the handshake", hosted).await.unwrap().unwrap();
    assert_eq!(
        within(
            &format!("{kind:?} is closed at registration"),
            conn.closed()
        )
        .await,
        CloseReason::Local(ErrorCode::InternalError),
    );
    assert_eq!(e.host.connections_for(grant), 0);
    until("the place is free", || open(&e.host, kind) == 0).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handshake_finishing_after_the_fence_is_set_is_closed_at_registration() {
    the_fence_closes_at_registration(ListenerKind::Tcp).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_fence_at_registration_covers_ws_and_pipe() {
    the_fence_closes_at_registration(ListenerKind::Ws).await;
    the_fence_closes_at_registration(ListenerKind::Pipe).await;
}

/// Setting the fence closes a connection waiting for its proof and a
/// join-only one; a live one stays. Listeners get no place meanwhile.
#[tokio::test(flavor = "multi_thread")]
async fn setting_the_fence_closes_waiting_and_join_only_connections_but_not_live_ones() {
    let mut e = engine(&[]);
    let (live_caller, grant) = granted_caller(&e.host);
    let (a, b) = tokio::io::duplex(1 << 16);
    let identity = e.host.identity();
    let live = accept_as(&e.host, ListenerKind::Tcp, a);
    let _live_dial = tokio::spawn(async move { live_caller.dial(b, identity).await });
    let live = within("live", live).await.unwrap().unwrap();
    until("live", || e.host.connections_for(grant) == 1).await;

    let (a, b) = tokio::io::duplex(1 << 16);
    let waiting = accept_as(&e.host, ListenerKind::Ws, a);
    let stranger = new_caller();
    let _waiting_dial = tokio::spawn(async move { stranger.dial(b, identity).await });
    let waiting = within("waiting", waiting).await.unwrap().unwrap();

    let ticket = in_person(&e.host);
    let (a, b) = tokio::io::duplex(1 << 16);
    let joiner = accept_as(&e.host, ListenerKind::Pipe, a);
    let joining = join(new_caller(), b, ticket);
    next_request(&mut e.events).await;
    let joiner = within("join-only", joiner).await.unwrap().unwrap();

    e.host.set_fence(true);
    for (what, conn) in [("waiting", &waiting), ("join-only", &joiner)] {
        assert_eq!(
            within(what, conn.closed()).await,
            CloseReason::Local(ErrorCode::InternalError),
            "{what}"
        );
    }
    assert!(within("the join", joining).await.unwrap().is_err());
    assert_eq!(e.host.connections_for(grant), 1);
    assert_eq!(live.status(), ConnStatus::Live);
    for kind in ListenerKind::ALL {
        assert_eq!(e.host.admit(kind, None).unwrap_err(), Refusal::Fenced);
    }
    e.host.set_fence(false);
    e.host.admit(ListenerKind::Tcp, None).unwrap();
}

/// The owner says yes after the fence was set: nothing is enrolled.
#[tokio::test(flavor = "multi_thread")]
async fn an_approval_while_fenced_enrolls_nothing() {
    let mut e = engine(&[]);
    let caller = new_caller();
    let identity = caller.identity();
    let ticket = in_person(&e.host);
    let (a, b) = tokio::io::duplex(1 << 16);
    let _hosted = accept_as(&e.host, ListenerKind::Tcp, a);
    let joining = join(caller, b, ticket);
    let request = next_request(&mut e.events).await;
    e.host.set_fence(true);
    assert!(e.host.approve(&request).is_err());
    assert!(e.host.grants().iter().all(|g| g.identity != identity));
    let ended = within("the join ends", joining).await.unwrap();
    assert!(ended.is_err(), "the join was paired while fenced");
}

/// What happens at the moment a granted device's re-pair proof arrives on
/// its live connection.
enum AtRepair {
    Nothing,
    FillPool,
    SetFence,
}

/// A granted device re-pairs: it is live when its proof arrives. The
/// proof goes join-only only with a free place in its kind's pool and no
/// fence; otherwise it opens nothing and the connection stays live.
async fn repair(at: AtRepair) {
    let mut e = engine(&[("PREAUTH_TCP", 2)]);
    let (caller, grant) = granted_caller(&e.host);
    let ticket = in_person(&e.host);
    let (caller_end, host_end, held) = held_pipe(Stop::AfterLive(e.host.clone(), grant));
    let _hosted = accept_as(&e.host, ListenerKind::Tcp, host_end);
    let _joining = join(caller, caller_end, ticket);
    within("live before the proof", held.reached.notified()).await;
    // Live: its place is free.
    assert_eq!(open(&e.host, ListenerKind::Tcp), 0);
    let mut fill = Vec::new();
    match at {
        AtRepair::Nothing => {}
        AtRepair::FillPool => {
            for _ in 0..2 {
                fill.push(e.host.admit(ListenerKind::Tcp, None).unwrap());
            }
            assert!(
                e.host.admit(ListenerKind::Tcp, None).is_err(),
                "the pool is not full"
            );
        }
        AtRepair::SetFence => e.host.set_fence(true),
    }
    held.release.notify_one();
    match at {
        AtRepair::Nothing => {
            next_request(&mut e.events).await;
            // Join-only again, on a new place.
            assert_eq!(open(&e.host, ListenerKind::Tcp), 1);
        }
        AtRepair::FillPool | AtRepair::SetFence => {
            assert!(
                no_request_within(&mut e.events, 1_500).await,
                "the re-pair went join-only"
            );
            assert_eq!(e.host.connections_for(grant), 1, "no longer live");
            assert_eq!(open(&e.host, ListenerKind::Tcp), fill.len() as u64);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repair_from_live_takes_a_new_place() {
    repair(AtRepair::Nothing).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repair_from_live_with_the_pool_full_opens_nothing() {
    repair(AtRepair::FillPool).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repair_from_live_while_fenced_opens_nothing() {
    repair(AtRepair::SetFence).await;
}

// ---------------------------------------------------------------------
// Helper cases: `serve`.
// ---------------------------------------------------------------------

/// A TCP connection to `port` that sends nothing: a handshake that never
/// starts.
fn silent_to(port: u16) -> std::net::TcpStream {
    let s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    s
}

fn port_of(route: &str) -> u16 {
    route.rsplit(':').next().unwrap().parse().unwrap()
}

/// Whether the helper dropped `s` (true) or still holds it open waiting
/// for its handshake (false).
fn dropped(mut s: &std::net::TcpStream) -> bool {
    let start = Instant::now();
    loop {
        match s.read(&mut [0u8; 64]) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return false
            }
            Err(_) => return true,
        }
        if start.elapsed() > WAIT {
            return false;
        }
    }
}

/// A silent connection to `port` that the helper holds, once a place
/// is free; fails if none frees up within WAIT.
fn admitted_soon(port: u16) -> std::net::TcpStream {
    let start = Instant::now();
    loop {
        let next = silent_to(port);
        if !dropped(&next) {
            return next;
        }
        assert!(start.elapsed() < WAIT, "the place never came back");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Inbound TCP connections that are not live hold a place from accept,
/// before any read, until they are live or closed: at most
/// PREAUTH_PER_SOURCE from one address and PREAUTH_TCP in all. One more
/// is dropped before any handshake work.
#[test]
fn tcp_connections_waiting_for_authorization_are_capped_per_source_and_in_all() {
    // From one address: a peer with no grant waiting out its join-proof
    // time is past its handshake but not live, and keeps its place.
    let a_end = Endpoint::init("preauth");
    let mut a = a_end.app(
        "hostA",
        &[("PREAUTH_PER_SOURCE", "1"), ("JOIN_PROOF_WAIT_MS", "3000")],
    );
    a.hello();
    let a_route = route_of(&mut a);
    let port = port_of(&a_route);
    let c_end = Endpoint::init("preauthc");
    let mut c = c_end.app("peerC", &[]);
    c.hello();
    // C stores A, but A never granted C.
    c.call(
        "peer.add",
        json!({"identity": a.identity, "name": a.name, "routes": [a_route]}),
    );
    let dial = c.start("dial", json!({"identity": a.identity}));
    // Past the handshake, waiting for step 2.
    std::thread::sleep(Duration::from_millis(1000));
    assert!(
        c.st().messages.iter().all(|m| m["re"] != dial),
        "C's dial ended early"
    );
    let late = silent_to(port);
    assert!(
        dropped(&late),
        "a second connection from the address got in"
    );
    assert!(
        a_end.log().contains("PREAUTH_PER_SOURCE"),
        "{}",
        a_end.log()
    );
    // Step 2 ends (refused): the place is free again.
    let reply = c.reply(dial);
    assert!(reply.get("error").is_some(), "{reply}");
    let _again = admitted_soon(port);

    // In all: two places, both taken by handshakes that never start.
    let b_end = Endpoint::init("preauthb");
    let mut b = b_end.app(
        "hostB",
        &[("PREAUTH_TCP", "2"), ("PREAUTH_PER_SOURCE", "2")],
    );
    b.hello();
    let port = port_of(&route_of(&mut b));
    let first = silent_to(port);
    let second = silent_to(port);
    assert!(!dropped(&first) && !dropped(&second));
    let third = silent_to(port);
    assert!(dropped(&third), "a third connection got in");
    assert!(b_end.log().contains("PREAUTH_TCP"), "{}", b_end.log());
    // `stats` counts them per kind.
    let stats = b.stats();
    assert_eq!(stats["preauth_open"], json!({"tcp": 2, "ws": 0, "pipe": 0}));
    assert_eq!(stats["preauth_refused"]["tcp"], 1);
    drop(first);
    // The helper sees the end of the first one's handshake and frees its
    // place.
    let _next = admitted_soon(port);
}

/// Make the grant table unsavable: a folder (with a file in it) where the
/// table is renamed to.
fn block_grant_saves(dir: &Path) {
    let table = dir.join("grants.json");
    std::fs::remove_file(&table).unwrap();
    std::fs::create_dir_all(table.join("in-the-way")).unwrap();
}

/// While a removal is not saved, the listener closes every new connection
/// at accept.
#[test]
fn the_listener_takes_nothing_while_a_removal_is_not_saved() {
    let mut p = pair_up("fenceaccept", &[("REMOVAL_RETRY_MS", "60000")], &[]);
    let port = port_of(&route_of(&mut p.a));
    let b_identity = p.b.identity.clone();
    let grants = p.a.call("grants.list", json!({}));
    let grant = grants["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["identity"] == b_identity.as_str())
        .unwrap()["grant"]
        .clone();
    block_grant_saves(&p.a_end.dir);
    let removed = p.a.call("grant.remove", json!({"grant": grant}));
    assert_eq!(removed["paused"], true);
    p.a.event("net.paused", |_| true);
    let s = silent_to(port);
    assert!(dropped(&s), "a connection got in while paused");
    let log = p.a_end.log();
    assert!(log.contains("networking is paused"), "{log}");
}

/// The pre-auth and IPC caps can be lowered but never raised.
#[test]
fn preauth_and_ipc_limits_can_only_be_tightened() {
    let dir = temp_dir("tighten");
    for (name, value, range) in [
        ("MOUSSE_NET_PREAUTH_TCP", "49", "1 to 48"),
        ("MOUSSE_NET_PREAUTH_WS", "17", "1 to 16"),
        ("MOUSSE_NET_PREAUTH_PIPE", "5", "1 to 4"),
        ("MOUSSE_NET_PREAUTH_PER_SOURCE", "9", "1 to 8"),
        ("MOUSSE_NET_IPC_LINE_MAX_BYTES", "65537", "1024 to 65536"),
        ("MOUSSE_NET_IPC_FIRST_LINE_WAIT_MS", "2001", "100 to 2000"),
    ] {
        let out = std::process::Command::new(bin())
            .arg("--state")
            .arg(&dir)
            .arg("id")
            .env(name, value)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{name}={value}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "{name}={value} is out of range; allowed range is {range}"
            )),
            "{name}={value}: {stderr}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `serve` (not app mode) on any port, its control channel listening.
fn control_serve(end: &Endpoint, env: &[(&str, &str)]) -> Cli {
    let cli = end.cli_env(
        &["serve", "--no-mdns", "--port", "0", "--name", "hostA"],
        env,
    );
    cli.wait_for("ready ");
    cli
}

/// A raw connection to the control channel of the `serve` in `dir`, and
/// its token.
#[cfg(windows)]
fn control_raw(dir: &Path) -> (std::fs::File, String) {
    let file: Value =
        serde_json::from_slice(&std::fs::read(dir.join("control.json")).unwrap()).unwrap();
    let pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(file["addr"].as_str().unwrap())
        .unwrap();
    (pipe, file["token"].as_str().unwrap().to_owned())
}

#[cfg(not(windows))]
fn control_raw(dir: &Path) -> (std::os::unix::net::UnixStream, String) {
    let file: Value =
        serde_json::from_slice(&std::fs::read(dir.join("control.json")).unwrap()).unwrap();
    let sock = std::os::unix::net::UnixStream::connect(dir.join("control.sock")).unwrap();
    (sock, file["token"].as_str().unwrap().to_owned())
}

/// What a read on `conn` gives within `limit`: `Some(bytes)` (empty at the
/// end of the stream or on an error), `None` if it still waits.
fn read_within<R: Read + Send + 'static>(mut conn: R, limit: Duration) -> Option<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match conn.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    got.extend_from_slice(&buf[..n]);
                    if got.ends_with(b"\n") {
                        break;
                    }
                }
            }
        }
        let _ = tx.send(got);
    });
    rx.recv_timeout(limit).ok()
}

/// A control-channel line at IPC_LINE_MAX_BYTES is read; one byte more
/// closes the channel without an answer.
#[test]
fn an_ipc_line_past_the_cap_closes_the_channel() {
    let end = Endpoint::init("ipcline");
    let _serve = control_serve(&end, &[("MOUSSE_NET_IPC_LINE_MAX_BYTES", "4096")]);
    let line = |token: &str, len: usize| {
        let head = format!(r#"{{"cmd":"status","token":"{token}","pad":""#);
        let tail = r#""}"#;
        let pad = "x".repeat(len - head.len() - tail.len());
        format!("{head}{pad}{tail}\n")
    };

    let (mut conn, token) = control_raw(&end.dir);
    conn.write_all(line(&token, 4096).as_bytes()).unwrap();
    let reply = read_within(conn, Duration::from_secs(5)).expect("no answer");
    let reply: Value = serde_json::from_slice(&reply).unwrap();
    assert!(reply.get("device").is_some(), "{reply}");

    let (mut conn, token) = control_raw(&end.dir);
    let _ = conn.write_all(line(&token, 4097).as_bytes());
    let got = read_within(conn, Duration::from_secs(5)).expect("the channel stayed open");
    assert!(got.is_empty(), "{}", String::from_utf8_lossy(&got));
}

/// A local client that sends nothing is closed after
/// IPC_FIRST_LINE_WAIT_MS.
#[test]
fn an_ipc_client_that_sends_nothing_is_closed() {
    let end = Endpoint::init("ipcfirst");
    let _serve = control_serve(&end, &[("MOUSSE_NET_IPC_FIRST_LINE_WAIT_MS", "200")]);
    let (conn, _token) = control_raw(&end.dir);
    let started = Instant::now();
    let got = read_within(conn, Duration::from_secs(5)).expect("the channel stayed open");
    assert!(got.is_empty(), "{}", String::from_utf8_lossy(&got));
    assert!(started.elapsed() >= Duration::from_millis(150));
}

/// The ws listener's port from `hello`.
fn ws_port_of(app: &mut App) -> u16 {
    app.call("hello", json!({"proto": [1, 0]}))["ws_port"]
        .as_u64()
        .expect("no ws listener") as u16
}

/// A ws connection takes its place at accept, before a byte of its upgrade
/// is read: with the ws pool full, the next connection is closed at once,
/// not after it was read for WS_UPGRADE_WAIT_MS.
#[test]
fn a_ws_connection_takes_its_place_before_any_byte_is_read() {
    let end = Endpoint::init("wsslot");
    let mut a = end.app_args("hostA", &[("PREAUTH_WS", "1")], &["--ws-port", "0"]);
    a.hello();
    let port = ws_port_of(&mut a);
    let first = silent_to(port);
    assert!(!dropped(&first), "the only place was refused");
    let second = silent_to(port);
    assert!(dropped(&second), "a second ws connection was read");
    assert_eq!(a.stats()["preauth_refused"]["ws"], 1);
    assert_eq!(a.stats()["preauth_open"]["ws"], 1);
}

/// The fence covers the ws listener too: a connection accepted before the
/// pause that sends its upgrade during it gets 503.
#[test]
fn the_fence_at_the_ws_upgrade_answers_503() {
    let a_end = Endpoint::init("wsfencea");
    let b_end = Endpoint::init("wsfenceb");
    let mut a = a_end.app_args(
        "hostA",
        &[("REMOVAL_RETRY_MS", "60000")],
        &["--ws-port", "0"],
    );
    a.hello();
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    pair_apps(&mut a, &mut b);
    let port = ws_port_of(&mut a);
    let mut early = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    early
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    // Accepted, holding its place, nothing read yet.
    std::thread::sleep(Duration::from_millis(200));

    let b_identity = b.identity.clone();
    let grants = a.call("grants.list", json!({}));
    let grant = grants["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["identity"] == b_identity.as_str())
        .unwrap()["grant"]
        .clone();
    block_grant_saves(&a_end.dir);
    assert_eq!(
        a.call("grant.remove", json!({"grant": grant}))["paused"],
        true
    );
    a.event("net.paused", |_| true);

    early
        .write_all(
            b"GET /mousse-net/1 HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Protocol: mousse.1\r\n\r\n",
        )
        .unwrap();
    let mut got = String::new();
    let _ = early.read_to_string(&mut got);
    assert!(got.starts_with("HTTP/1.1 503"), "{got}");
    // And a new one is closed at accept.
    let late = silent_to(port);
    assert!(dropped(&late), "a ws connection got in while paused");
}
