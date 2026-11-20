//! E7: user routes (Phase 1b §1). The check cell `phase1b.routes` runs this
//! file: the route grammar and the allowlist classifier, who may supply
//! which route and the approvals that record it, resolving a name once and
//! dialling the classified address, the bounded tiered search, renewals
//! and the last working route filtered by approvals, the addresses bound
//! and advertised, `routes.config` and `routes.test`.
//!
//! The engine cases run a `Host` and a `Caller` in this process, with
//! stand-in dialers for the `ws` and `ssh` tiers that record when the
//! search started them. The helper cases run `serve --app`. Everything
//! listens on loopback only; `MOUSSE_NET_TEST_CLASS_MAP` relabels a
//! loopback port as a tailnet or internet address, and the bind decisions
//! for other classes are checked as functions, never by binding them.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use mousse_net_core::grants::OwnerRef;
use mousse_net_core::identity::{IdentityPublicKey, SoftwareKey};
use mousse_net_core::pairing::{
    Arrival, CpaceExchangeFactory, InvitationKind, Route, RouteSkip, Ticket,
};
use mousse_net_io::limits::CoreLimits;
use mousse_net_io::pipe::{
    classify, AddrClass, AddrPolicy, BoxPipe, DialFuture, LocalRoute, ResolveFuture, Resolver,
    RouteDialer,
};
use mousse_net_io::rng::os_rng;
use mousse_net_io::routes::RoutesConfig;
use mousse_net_io::{
    Caller, CandidateSource, Clock, Host, HostConfig, HostEvent, JoinOutcome, Limits, ManualClock,
    NetError, PathEvent, RouteClass, Search,
};
use serde_json::{json, Value};

// ---------------------------------------------------------------------
// Engine cases: a host and a caller in this process.
// ---------------------------------------------------------------------

/// A host on loopback that approves every in-person request.
struct Engine {
    host: Host,
    addr: SocketAddr,
    clock: Arc<ManualClock>,
}

async fn engine() -> Engine {
    let clock = Arc::new(ManualClock::new());
    let config = HostConfig {
        name: "desk".into(),
        state_dir: None,
        owner: OwnerRef([1; OwnerRef::LEN]),
        limits: Limits::DEFAULT,
        clock: clock.clone(),
        ticket_identity: None,
        streams: None,
    };
    let key = Arc::new(SoftwareKey::generate(&mut os_rng()));
    let (host, mut events) = Host::new(key, config, CpaceExchangeFactory).unwrap();
    let approving = host.clone();
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            if let HostEvent::ApprovalRequested(request) = event {
                let _ = approving.approve(&request);
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepting = host.clone();
    tokio::spawn(async move {
        // The connections stay open while their tasks are held.
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            let host = accepting.clone();
            held.push(tokio::spawn(async move { host.accept(tcp).await }));
        }
    });
    Engine { host, addr, clock }
}

/// A caller with these limits overridden, classifying as a debug build
/// does (loopback is `lan`), that the host grants.
fn granted(e: &Engine, clock: Arc<dyn Clock>, overrides: &[(&str, u64)]) -> Caller {
    let mut caller = Caller::new(
        Arc::new(SoftwareKey::generate(&mut os_rng())),
        clock,
        Limits::DEFAULT.with_overrides(overrides).unwrap(),
    );
    caller.use_addr_policy(AddrPolicy::debug());
    e.host
        .add_grant(caller.identity(), "laptop".into(), None)
        .unwrap();
    caller
}

fn tcp(addr: SocketAddr) -> LocalRoute {
    LocalRoute::tcp(addr)
}

fn route(text: &str) -> LocalRoute {
    LocalRoute::parse(text).unwrap()
}

/// A loopback address that accepts TCP and then says nothing; counts the
/// connections it took.
async fn silent() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            held.push(tcp);
        }
    });
    (addr, count)
}

/// A loopback relay to `to` that counts the connections it took.
async fn relay(to: SocketAddr) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if let Ok(mut outbound) = tokio::net::TcpStream::connect(to).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    (addr, count)
}

/// When the search started each try of a stand-in dialer, and the address
/// it was given.
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<Start>>>);

/// When a try started, from the start of the search, and its address.
type Start = (Duration, Option<SocketAddr>);

impl Seen {
    fn starts(&self) -> Vec<Start> {
        self.0.lock().unwrap().clone()
    }
}

/// A stand-in `ws` or `ssh` dialer: records the try, then connects to
/// `connect` (the host), or never answers.
fn standin(t0: Instant, seen: &Seen, connect: Option<SocketAddr>) -> Arc<dyn RouteDialer> {
    let seen = seen.clone();
    Arc::new(
        move |_route: &LocalRoute, addr: Option<SocketAddr>, _within: Duration| -> DialFuture {
            seen.0.lock().unwrap().push((t0.elapsed(), addr));
            Box::pin(async move {
                match connect {
                    Some(to) => {
                        let tcp = tokio::net::TcpStream::connect(to).await?;
                        Ok(Box::new(tcp) as BoxPipe)
                    }
                    None => std::future::pending().await,
                }
            })
        },
    )
}

/// A resolver that gives its answers in turn (the last one again after
/// that) and counts the lookups.
struct Answers {
    calls: AtomicUsize,
    answers: Vec<Vec<SocketAddr>>,
}

impl Resolver for Answers {
    fn resolve<'a>(&'a self, _name: &'a str, _port: u16) -> ResolveFuture<'a> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = self.answers[n.min(self.answers.len() - 1)].clone();
        Box::pin(async move { Ok(answer) })
    }
}

async fn within<T>(what: &str, limit: Duration, fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(limit, fut)
        .await
        .unwrap_or_else(|_| panic!("{what} took more than {limit:?}"))
}

/// The classifier is an allowlist: ranges in none of the listed classes
/// are `forbidden`, not public.
#[test]
fn addresses_outside_the_listed_ranges_are_forbidden() {
    for unlisted in [
        "4000::1",
        "8000::1",
        "192.0.2.1",
        "198.51.100.7",
        "203.0.113.7",
        "240.0.0.1",
        "224.0.0.251",
        "0.1.2.3",
        "::8.8.8.8",
        "64:ff9b::808:808",
        "2001:db8::1",
        "2002:808:808::1",
        "fe80::1",
        "::1",
        "127.0.0.1",
    ] {
        let ip: IpAddr = unlisted.parse().unwrap();
        assert_eq!(classify(ip), AddrClass::Forbidden, "{unlisted}");
    }
}

/// Each listed range takes its class; an IPv4-mapped address that of its
/// IPv4 address.
#[test]
fn listed_ranges_take_their_class() {
    for (text, class) in [
        ("10.1.2.3", AddrClass::Lan),
        ("169.254.3.4", AddrClass::Lan),
        ("fd12::9", AddrClass::Lan),
        ("100.64.0.1", AddrClass::Tailnet),
        ("fd7a:115c:a1e0::1", AddrClass::Tailnet),
        ("8.8.8.8", AddrClass::Public),
        ("2606:4700::1111", AddrClass::Public),
        ("::ffff:100.100.1.1", AddrClass::Tailnet),
    ] {
        assert_eq!(classify(text.parse().unwrap()), class, "{text}");
    }
}

/// Release builds never dial loopback; debug builds count it as `lan`,
/// and the class map relabels a loopback port.
#[test]
fn the_release_policy_never_dials_loopback() {
    let local: SocketAddr = "127.0.0.1:7443".parse().unwrap();
    let release = AddrPolicy::release();
    assert_eq!(release.class_of(local), AddrClass::Forbidden);
    assert!(!release.automatic(&tcp(local)));
    assert!(release.names_forbidden(&tcp(local)));
    assert_eq!(AddrPolicy::debug().class_of(local), AddrClass::Lan);
    assert!(AddrPolicy::debug().automatic(&tcp(local)));
    let mapped = AddrPolicy::debug()
        .with_class_map("7443=public,7444=tailnet")
        .unwrap();
    assert_eq!(mapped.class_of(local), AddrClass::Public);
    assert!(!mapped.automatic(&tcp(local)), "public needs an approval");
    assert_eq!(
        mapped.class_of("[::1]:7444".parse().unwrap()),
        AddrClass::Tailnet
    );
    assert!(release.with_class_map("7443=public").is_err());
}

/// A caller under the release policy never dials a ticket's loopback hint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_release_build_does_not_dial_a_loopback_hint() {
    let e = engine().await;
    let (front, taken) = relay(e.addr).await;
    let mut caller = granted(&e, Arc::new(ManualClock::new()), &[]);
    caller.use_addr_policy(AddrPolicy::release());
    let pin = e.host.identity();
    let result = within(
        "the search",
        Duration::from_secs(15),
        caller.search(Search::of(vec![tcp(front)]), pin),
    )
    .await;
    assert!(
        matches!(result, Err(NetError::Forbidden(_))),
        "{:?}",
        result.map(|(_, r)| r)
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        taken.load(Ordering::SeqCst),
        0,
        "the loopback hint was dialled"
    );
}

/// The owner-entered kinds: plain `ws` only to a loopback literal with a
/// port, `ssh` with the user and target grammar; canonical forms keep an
/// explicit port and a lower-case host.
#[test]
fn route_grammar_and_canonical_forms() {
    for (text, uri) in [
        ("tcp://Mac.Local:7443", "tcp://mac.local:7443"),
        (
            "wss://X.example/mousse-net/1",
            "wss://x.example:443/mousse-net/1",
        ),
        (
            "ws://127.0.0.1:8080/mousse-net/1",
            "ws://127.0.0.1:8080/mousse-net/1",
        ),
        ("ssh://me@Box_1:2222", "ssh://me@box_1:2222"),
        ("ssh://alias", "ssh://alias"),
    ] {
        assert_eq!(route(text).uri(), uri, "{text}");
    }
    for bad in [
        "ws://10.0.0.2:80/mousse-net/1",
        "ws://localhost:80/mousse-net/1",
        "ws://127.0.0.1/mousse-net/1",
        "wss://x.example/other",
        "ssh://-oProxyCommand=x",
        "ssh://me@-x",
        "ssh://a b",
    ] {
        assert!(LocalRoute::parse(bad).is_err(), "{bad}");
    }
    // On the wire, ws and ssh stay reserved: a ticket's hint is skipped.
    for reserved in ["ws://127.0.0.1:1/mousse-net/1", "ssh://me@box"] {
        assert_eq!(
            Route::parse(reserved),
            Err(RouteSkip::Reserved),
            "{reserved}"
        );
    }
}

/// A name is resolved once per try and exactly the classified address is
/// dialled: an answer that changes on a second lookup is never used.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_is_resolved_once_and_the_classified_address_dialled() {
    let e = engine().await;
    let (decoy, decoy_taken) = silent().await;
    let mut caller = granted(
        &e,
        Arc::new(ManualClock::new()),
        &[("DIAL_TIMEOUT_MS", 1_000)],
    );
    let answers = Arc::new(Answers {
        calls: AtomicUsize::new(0),
        answers: vec![vec![e.addr], vec![decoy]],
    });
    caller.use_resolver(answers.clone());
    let named = route("tcp://desk.test:7443");
    let (conn, reached) = within(
        "the search",
        Duration::from_secs(15),
        caller.search(Search::of(vec![named.clone()]), e.host.identity()),
    )
    .await
    .unwrap();
    assert_eq!(reached.route, named);
    assert_eq!(reached.class, RouteClass::Lan);
    assert!(conn.status().is_live());
    assert_eq!(answers.calls.load(Ordering::SeqCst), 1, "resolved again");
    assert_eq!(decoy_taken.load(Ordering::SeqCst), 0);
}

/// A name whose addresses are all forbidden is not dialled at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_resolving_only_to_forbidden_addresses_is_not_dialled() {
    let e = engine().await;
    let mut caller = granted(
        &e,
        Arc::new(ManualClock::new()),
        &[("CONNECT_TIMEOUT_MS", 100), ("DIAL_TIMEOUT_MS", 300)],
    );
    caller.use_resolver(Arc::new(Answers {
        calls: AtomicUsize::new(0),
        answers: vec![vec![
            "192.0.2.10:7443".parse().unwrap(),
            "0.0.0.0:7443".parse().unwrap(),
        ]],
    }));
    let result = within(
        "the search",
        Duration::from_secs(15),
        caller.search(
            Search::of(vec![route("tcp://desk.test:7443")]),
            e.host.identity(),
        ),
    )
    .await;
    assert!(
        matches!(result, Err(NetError::Forbidden(_))),
        "{:?}",
        result.map(|(_, r)| r)
    );
}

/// At most DIAL_MAX_CANDIDATES candidates are tried in one search, in the
/// order given.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_search_tries_at_most_dial_max_candidates() {
    let e = engine().await;
    let mut dead = Vec::new();
    for _ in 0..5 {
        dead.push(silent().await);
    }
    let caller = granted(
        &e,
        Arc::new(ManualClock::new()),
        &[("DIAL_MAX_CANDIDATES", 2), ("DIAL_TIMEOUT_MS", 300)],
    );
    let candidates = dead.iter().map(|(a, _)| tcp(*a)).collect();
    let result = within(
        "the search",
        Duration::from_secs(15),
        caller.search(Search::of(candidates), e.host.identity()),
    )
    .await;
    assert!(result.is_err());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let taken: Vec<usize> = dead.iter().map(|(_, n)| n.load(Ordering::SeqCst)).collect();
    assert_eq!(taken, [1, 1, 0, 0, 0]);
}

/// The whole search ends after DIAL_SEARCH_MS, however long its tries
/// could take.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_search_ends_after_dial_search_ms() {
    let e = engine().await;
    let mut caller = granted(
        &e,
        Arc::new(ManualClock::new()),
        &[("DIAL_SEARCH_MS", 5_000), ("SSH_DIAL_TIMEOUT_MS", 120_000)],
    );
    let seen = Seen::default();
    caller.use_ssh_dialer(standin(Instant::now(), &seen, None));
    let started = Instant::now();
    let result = within(
        "the search",
        Duration::from_secs(20),
        caller.search(Search::of(vec![route("ssh://me@box")]), e.host.identity()),
    )
    .await;
    assert!(matches!(result, Err(NetError::Timeout(_))));
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(4_500) && took < Duration::from_secs(10),
        "{took:?}"
    );
    assert_eq!(seen.starts().len(), 1);
}

/// `ssh` never races a LAN path: with a `tcp` candidate still trying, the
/// `ssh` tier waits until it is done.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_waits_until_the_faster_tiers_are_done() {
    let e = engine().await;
    let (dead, _) = silent().await;
    let mut caller = granted(
        &e,
        Arc::new(ManualClock::new()),
        &[
            ("DIAL_TIMEOUT_MS", 1_500),
            ("DIAL_FAST_TIERS_MS", 60_000),
            ("SSH_DIAL_TIMEOUT_MS", 1_000),
        ],
    );
    let seen = Seen::default();
    let t0 = Instant::now();
    caller.use_ssh_dialer(standin(t0, &seen, None));
    let result = within(
        "the search",
        Duration::from_secs(20),
        caller.search(
            Search::of(vec![tcp(dead), route("ssh://me@box")]),
            e.host.identity(),
        ),
    )
    .await;
    assert!(result.is_err());
    let starts = seen.starts();
    assert_eq!(starts.len(), 1);
    assert!(
        starts[0].0 >= Duration::from_millis(1_300),
        "ssh started at {:?}, with tcp still trying",
        starts[0].0
    );
}

/// The `ssh` tier starts DIAL_FAST_TIERS_MS into the search when the
/// faster tiers are still trying, and its pipe carries the session like
/// any other.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_starts_at_dial_fast_tiers_ms_and_can_win() {
    let e = engine().await;
    let (dead, _) = silent().await;
    let mut caller = granted(
        &e,
        Arc::new(ManualClock::new()),
        &[("DIAL_TIMEOUT_MS", 10_000), ("DIAL_FAST_TIERS_MS", 1_000)],
    );
    let seen = Seen::default();
    let t0 = Instant::now();
    caller.use_ssh_dialer(standin(t0, &seen, Some(e.addr)));
    let (_conn, reached) = within(
        "the search",
        Duration::from_secs(20),
        caller.search(
            Search::of(vec![tcp(dead), route("ssh://me@box")]),
            e.host.identity(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(reached.class, RouteClass::Ssh);
    let starts = seen.starts();
    assert_eq!(starts.len(), 1);
    assert!(
        starts[0].0 >= Duration::from_millis(900) && starts[0].0 < Duration::from_secs(5),
        "{:?}",
        starts[0].0
    );
    assert_eq!(starts[0].1, None, "ssh resolves its own target");
}

/// When the last working route was `ssh`, the `ssh` tier starts after the
/// head start instead of waiting for the faster tiers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_starts_after_the_head_start_when_the_last_route_was_ssh() {
    let e = engine().await;
    let (dead, _) = silent().await;
    let mut caller = granted(
        &e,
        Arc::new(ManualClock::new()),
        &[
            ("DIAL_TIMEOUT_MS", 10_000),
            ("DIAL_FAST_TIERS_MS", 60_000),
            ("TIER_HEAD_START_MS", 400),
        ],
    );
    let seen = Seen::default();
    let t0 = Instant::now();
    caller.use_ssh_dialer(standin(t0, &seen, Some(e.addr)));
    let search = Search {
        candidates: vec![route("ssh://me@box"), tcp(dead)],
        ssh_first: true,
        later: None,
    };
    let (_conn, reached) = within(
        "the search",
        Duration::from_secs(20),
        caller.search(search, e.host.identity()),
    )
    .await
    .unwrap();
    assert_eq!(reached.class, RouteClass::Ssh);
    let start = seen.starts()[0].0;
    assert!(
        start >= Duration::from_millis(350) && start < Duration::from_secs(5),
        "{start:?}"
    );
}

/// `ws` candidates start TIER_HEAD_START_MS after `tcp`, with the address
/// the caller classified, and the ws pipe carries the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_starts_after_the_head_start_with_the_classified_address() {
    let e = engine().await;
    let (dead, _) = silent().await;
    let mut caller = granted(
        &e,
        Arc::new(ManualClock::new()),
        &[("DIAL_TIMEOUT_MS", 10_000), ("TIER_HEAD_START_MS", 600)],
    );
    let tunnel: SocketAddr = "127.0.0.1:9".parse().unwrap();
    caller.use_resolver(Arc::new(Answers {
        calls: AtomicUsize::new(0),
        answers: vec![vec![tunnel]],
    }));
    let seen = Seen::default();
    let t0 = Instant::now();
    caller.use_ws_dialer(standin(t0, &seen, Some(e.addr)));
    let (_conn, reached) = within(
        "the search",
        Duration::from_secs(20),
        caller.search(
            Search::of(vec![tcp(dead), route("wss://t.example/x/mousse-net/1")]),
            e.host.identity(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(reached.class, RouteClass::Tunnel);
    let starts = seen.starts();
    assert_eq!(starts[0].1, Some(tunnel));
    assert!(
        starts[0].0 >= Duration::from_millis(500) && starts[0].0 < Duration::from_secs(5),
        "{:?}",
        starts[0].0
    );
}

/// With no `tcp` candidate, `ws` starts at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_starts_at_once_without_tcp_candidates() {
    let e = engine().await;
    let mut caller = granted(
        &e,
        Arc::new(ManualClock::new()),
        &[("TIER_HEAD_START_MS", 5_000)],
    );
    let seen = Seen::default();
    caller.use_ws_dialer(standin(Instant::now(), &seen, Some(e.addr)));
    let (_conn, reached) = within(
        "the search",
        Duration::from_secs(20),
        caller.search(
            Search::of(vec![route("ws://127.0.0.1:9/mousse-net/1")]),
            e.host.identity(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(reached.class, RouteClass::Tunnel);
    assert!(seen.starts()[0].0 < Duration::from_millis(2_000));
}

/// The built-in ws client carries a search to a host behind a loopback ws
/// listener (the tunnel's local hop).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_ws_tier_dials_with_the_built_in_ws_client() {
    let e = engine().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let host = e.host.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            let host = host.clone();
            held.push(tokio::spawn(async move {
                let io = *Limits::DEFAULT.io();
                match mousse_net_io::pipe::ws::accept(tcp, &io, || false).await {
                    Ok(pipe) => host.accept(pipe).await.ok(),
                    Err(_) => None,
                }
            }));
        }
    });
    let caller = granted(&e, Arc::new(ManualClock::new()), &[]);
    let ws = route(&format!("ws://127.0.0.1:{port}/mousse-net/1"));
    let (conn, reached) = within(
        "the search",
        Duration::from_secs(20),
        caller.search(Search::of(vec![ws.clone()]), e.host.identity()),
    )
    .await
    .unwrap();
    assert_eq!(reached.route, ws);
    assert_eq!(reached.class, RouteClass::Tunnel);
    assert!(conn.status().is_live());
}

/// A join runs over a pipe from any dialer: here a stand-in `ws` dialer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_join_runs_over_a_pipe_of_any_kind() {
    let e = engine().await;
    let mut caller = Caller::new(
        Arc::new(SoftwareKey::generate(&mut os_rng())),
        Arc::new(ManualClock::new()),
        Limits::DEFAULT,
    );
    caller.use_addr_policy(AddrPolicy::debug());
    let seen = Seen::default();
    caller.use_ws_dialer(standin(Instant::now(), &seen, Some(e.addr)));
    let created = e.host.invite(InvitationKind::InPerson, vec![]).unwrap();
    let ticket = Ticket::from_fragment(&created.fragment).unwrap();
    let (pipe, class) = caller
        .open_route(&route("ws://127.0.0.1:9/mousse-net/1"))
        .await
        .unwrap();
    assert_eq!(class, RouteClass::Tunnel);
    let (_conn, outcome) = within(
        "the join",
        Duration::from_secs(20),
        caller.join(pipe, &ticket, Arrival::InAppScan, "laptop"),
    )
    .await
    .unwrap();
    assert!(matches!(outcome, JoinOutcome::Paired(_)));
    assert_eq!(seen.starts().len(), 1);
}

/// Candidates from the store, changeable by the test.
struct Store(Mutex<Vec<LocalRoute>>);

impl CandidateSource for Store {
    fn search(&self, _pin: &IdentityPublicKey) -> Search {
        Search::of(self.0.lock().unwrap().clone())
    }
}

/// Move both clocks to the renewal time of `conn`.
fn to_renewal(e: &Engine, clock: &ManualClock, conn: &mousse_net_io::Connection) {
    let core = CoreLimits::DEFAULT;
    let renew_at = conn.deadline().0 - core.clock_skew_secs() - core.renew_lead_secs();
    let skip = renew_at as i64 - clock.now().0 as i64;
    clock.advance(skip);
    e.clock.advance(skip);
}

/// A renewal searches the store as it is now: after the owner replaced an
/// address, the old one is never dialled again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renewal_dials_the_addresses_as_they_are_now() {
    let e = engine().await;
    let clock = Arc::new(ManualClock::new());
    let (old_addr, old_taken) = relay(e.addr).await;
    let (new_addr, new_taken) = relay(e.addr).await;
    let store = Arc::new(Store(Mutex::new(vec![tcp(old_addr)])));
    let mut caller = granted(&e, clock.clone(), &[]);
    caller.use_candidates(store.clone());
    let caller = Arc::new(caller);
    let mut paths = caller.start_renewals();
    let pin = e.host.identity();
    let (old, _) = caller
        .search(Search::of(vec![tcp(old_addr)]), pin)
        .await
        .unwrap();
    // The owner edits the host's addresses.
    *store.0.lock().unwrap() = vec![tcp(new_addr)];
    caller.forget_routes(Some(&pin));
    to_renewal(&e, &clock, &old);
    match within("the renewal", Duration::from_secs(20), paths.recv()).await {
        Some(PathEvent::Reopen { .. }) => {}
        other => panic!("expected a renewed path, got {other:?}"),
    }
    assert_eq!(
        old_taken.load(Ordering::SeqCst),
        1,
        "the old address was dialled again"
    );
    assert_eq!(new_taken.load(Ordering::SeqCst), 1);
}

/// Without a store to ask, a renewal uses the routes kept at the current
/// generation: once they are forgotten, nothing remembered is dialled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forgotten_routes_are_not_dialled_by_a_renewal() {
    let e = engine().await;
    let clock = Arc::new(ManualClock::new());
    let (front, taken) = relay(e.addr).await;
    let caller = Arc::new(granted(&e, clock.clone(), &[]));
    let mut paths = caller.start_renewals();
    let pin = e.host.identity();
    let (old, _) = caller
        .search(Search::of(vec![tcp(front)]), pin)
        .await
        .unwrap();
    caller.forget_routes(Some(&pin));
    to_renewal(&e, &clock, &old);
    match within("the renewal", Duration::from_secs(20), paths.recv()).await {
        Some(PathEvent::RenewFailed { .. }) => {}
        other => panic!("expected the renewal to fail, got {other:?}"),
    }
    assert_eq!(taken.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------
// This computer's routes (§1.5), as functions.
// ---------------------------------------------------------------------

fn ips(list: &[&str]) -> Vec<IpAddr> {
    list.iter().map(|t| t.parse().unwrap()).collect()
}

const INTERFACES: [&str; 5] = [
    "127.0.0.1",
    "192.168.1.20",
    "100.101.7.2",
    "fd7a:115c:a1e0::2",
    "169.254.9.9",
];

/// LAN on binds every interface; LAN off binds only what is selected, and
/// nothing selected binds loopback only.
#[test]
fn only_selected_addresses_are_bound() {
    let ifaces = ips(&INTERFACES);
    let lan = RoutesConfig {
        lan: true,
        tailnet: true,
        ..RoutesConfig::default()
    };
    assert_eq!(lan.bind_plan(&ifaces), ips(&["0.0.0.0"]));
    let tailnet = RoutesConfig {
        tailnet: true,
        ..RoutesConfig::default()
    };
    assert_eq!(tailnet.bind_plan(&ifaces), ips(&["100.101.7.2"]));
    let forward = RoutesConfig {
        public: vec!["tcp://8.8.4.4:7443".into()],
        forward_to: Some("192.168.1.20".parse().unwrap()),
        ..RoutesConfig::default()
    };
    assert_eq!(forward.bind_plan(&ifaces), ips(&["192.168.1.20"]));
    let both = RoutesConfig {
        tailnet: true,
        ..forward.clone()
    };
    assert_eq!(
        both.bind_plan(&ifaces),
        ips(&["100.101.7.2", "192.168.1.20"])
    );
    assert_eq!(
        RoutesConfig::default().bind_plan(&ifaces),
        ips(&["127.0.0.1"])
    );
}

/// Only what the listener serves is advertised: no IPv6, no link-local, no
/// tailnet address that is not bound, at most 8 routes.
#[test]
fn only_served_addresses_are_advertised() {
    let ifaces = ips(&INTERFACES);
    let lan = RoutesConfig {
        lan: true,
        tunnels: vec!["wss://t.example:443/mousse-net/1".into()],
        ..RoutesConfig::default()
    };
    assert_eq!(
        lan.advertised(&ifaces, &ips(&["0.0.0.0"]), 7443),
        [
            "tcp://192.168.1.20:7443",
            "wss://t.example:443/mousse-net/1"
        ]
    );
    let tailnet = RoutesConfig {
        tailnet: true,
        ..RoutesConfig::default()
    };
    assert_eq!(
        tailnet.advertised(&ifaces, &ips(&["100.101.7.2"]), 7443),
        ["tcp://100.101.7.2:7443"]
    );
    assert!(tailnet.advertised(&ifaces, &[], 7443).is_empty(), "unbound");
    assert!(RoutesConfig::default()
        .advertised(&ifaces, &ips(&["127.0.0.1"]), 7443)
        .is_empty());
    let many: Vec<String> = (1..=12).map(|n| format!("tcp://8.8.8.{n}:7443")).collect();
    let crowded = RoutesConfig {
        public: many,
        ..RoutesConfig::default()
    };
    assert_eq!(crowded.advertised(&ifaces, &[], 7443).len(), 8);
}

/// Settings changes that move sockets need a restart; other list changes
/// reach the next ticket.
#[test]
fn which_changes_need_a_restart() {
    let base = RoutesConfig {
        tailnet: true,
        public: vec!["tcp://8.8.4.4:7443".into()],
        forward_to: Some("192.168.1.20".parse().unwrap()),
        tunnels: vec!["wss://a.example:443/mousse-net/1".into()],
        ..RoutesConfig::default()
    };
    let restart = |change: &dyn Fn(&mut RoutesConfig)| {
        let mut next = base.clone();
        change(&mut next);
        base.restart_needed(&next)
    };
    assert!(restart(&|c| c.lan = true));
    assert!(restart(&|c| c.tailnet = false));
    assert!(restart(&|c| c.port = Some(7444)));
    assert!(restart(&|c| c.public.clear()));
    assert!(restart(
        &|c| c.forward_to = Some("192.168.1.21".parse().unwrap())
    ));
    assert!(restart(&|c| c.tunnels.clear()));
    assert!(!restart(&|c| c.public = vec!["tcp://8.8.4.5:7443".into()]));
    assert!(!restart(&|c| c
        .tunnels
        .push("wss://b.example:443/mousse-net/1".into())));
    let none = RoutesConfig::default();
    assert!(none.restart_needed(&RoutesConfig {
        tunnels: vec!["wss://a.example:443/mousse-net/1".into()],
        ..RoutesConfig::default()
    }));
}

/// `routes.json` takes `tcp` port forwards and `wss` tunnels naming no
/// forbidden address, and a forwarded-to address of this computer.
#[test]
fn the_routes_config_is_checked() {
    let policy = AddrPolicy::debug();
    let ifaces = ips(&INTERFACES);
    let ok = RoutesConfig {
        public: vec!["tcp://8.8.4.4:7443".into(), "tcp://8.8.4.4:7443".into()],
        forward_to: Some("192.168.1.20".parse().unwrap()),
        tunnels: vec!["wss://T.example/mousse-net/1".into()],
        ..RoutesConfig::default()
    }
    .checked(&policy, &ifaces)
    .unwrap();
    assert_eq!(ok.public, ["tcp://8.8.4.4:7443"]);
    assert_eq!(ok.tunnels, ["wss://t.example:443/mousse-net/1"]);
    for bad in [
        RoutesConfig {
            public: vec!["tcp://192.0.2.1:7443".into()],
            lan: true,
            ..RoutesConfig::default()
        },
        RoutesConfig {
            tunnels: vec!["tcp://8.8.4.4:7443".into()],
            ..RoutesConfig::default()
        },
        RoutesConfig {
            public: vec!["tcp://8.8.4.4:7443".into()],
            ..RoutesConfig::default()
        },
        RoutesConfig {
            public: vec!["tcp://8.8.4.4:7443".into()],
            forward_to: Some("10.9.9.9".parse().unwrap()),
            ..RoutesConfig::default()
        },
    ] {
        assert!(bad.clone().checked(&policy, &ifaces).is_err(), "{bad:?}");
    }
}

// ---------------------------------------------------------------------
// Helper cases: `serve --app`.
// ---------------------------------------------------------------------

fn port_of(route: &str) -> u16 {
    route.rsplit(':').next().unwrap().parse().unwrap()
}

fn approvals(app: &mut App, identity: &str) -> Vec<Value> {
    app.call("approvals.list", json!({"identity": identity}))["approvals"]
        .as_array()
        .unwrap()
        .clone()
}

fn inbound_ups(app: &App, identity: &str) -> usize {
    app.events("conn.up")
        .iter()
        .filter(|m| m["dir"] == "in" && m["identity"] == identity)
        .count()
}

/// A ticket's public hint is dialled only after the owner approved it at
/// Connect, and the approval is then stored with its source.
#[test]
fn a_tickets_public_hint_is_dialled_only_when_approved() {
    let a_end = Endpoint::init("upa");
    let b_end = Endpoint::init("upb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let a_route = route_of(&mut a);
    let map = format!("{}=public", port_of(&a_route));
    let mut b = b_end.app("peerB", &[("TEST_CLASS_MAP", &map)]);
    b.hello();
    let invite = a.call("invite.create", json!({}));
    let refused = b.request("join", json!({"ticket": invite["uri"], "pinned": true}));
    assert_eq!(refused["error"], "no_route", "{refused}");
    assert!(b.events("join.progress").is_empty());
    assert!(a.events("approval").is_empty());

    let join = b.start(
        "join",
        json!({"ticket": invite["uri"], "pinned": true, "approved": [a_route]}),
    );
    let approval = a.event("approval", |_| true);
    a.call(
        "approval.answer",
        json!({"request": approval["request"], "yes": true}),
    );
    let joined = b.reply(join);
    assert!(joined.get("error").is_none(), "{joined}");
    let up = b.event("conn.up", |m| m["dir"] == "out");
    assert_eq!(up["route"], json!({"kind": "tcp", "class": "public"}));
    let stored = approvals(&mut b, &a.identity);
    assert_eq!(stored.len(), 1, "{stored:?}");
    assert_eq!(stored[0]["destination"], a_route.as_str());
    assert_eq!(stored[0]["source"], "ticket");
}

/// A ticket's plain `ws` hint is skipped, approved or not: plain ws is the
/// owner's local tunnel hop only.
#[test]
fn a_tickets_plain_ws_hint_is_never_dialled() {
    let a_end = Endpoint::init("pwa");
    let b_end = Endpoint::init("pwb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    let a_route = route_of(&mut a);
    let invite = a.call("invite.create", json!({}));
    let mut ticket = Ticket::from_fragment(invite["uri"].as_str().unwrap()).unwrap();
    let ws = format!("ws://127.0.0.1:{}/mousse-net/1", port_of(&a_route));
    ticket.routes = vec![ws.clone()];
    let reply = b.request(
        "join",
        json!({"ticket": ticket.to_fragment(), "pinned": true, "approved": [ws]}),
    );
    assert_eq!(reply["error"], "no_route", "{reply}");
    assert!(
        b.events("join.progress").is_empty(),
        "{:?}",
        b.events("join.progress")
    );
}

/// A peer never names an `ssh` route, nor a plain `ws` one: not in its
/// pairback routes and not among the routes it offers. Offered `tcp` and
/// `wss` routes are kept as suggestions and never dialled.
#[test]
fn a_peer_never_names_ssh_and_its_offers_are_not_dialled() {
    let b_end = Endpoint::init("psb");
    let (dead, dead_taken) = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for s in listener.incoming().flatten() {
                seen.fetch_add(1, Ordering::SeqCst);
                held.push(s);
            }
        });
        (addr, count)
    };
    let map = format!("{}=public", dead.port());
    let mut b = b_end.app("peerB", &[("TEST_CLASS_MAP", &map)]);
    b.hello();
    let host = some_identity();
    for bad in [
        "ssh://me@box",
        "ssh://box:22",
        "ws://127.0.0.1:9/mousse-net/1",
    ] {
        for field in ["routes", "offered"] {
            let mut request = json!({"identity": host, "name": "far"});
            request[field] = json!([bad]);
            let reply = b.request("peer.add", request);
            assert_eq!(reply["error"], "bad_route", "{field} {bad}: {reply}");
        }
    }
    assert!(peer_of(&mut b, &host).is_null(), "nothing stored");
    let offer = format!("tcp://{dead}");
    b.call(
        "peer.add",
        json!({"identity": host, "name": "far", "routes": [],
               "offered": [offer, "wss://t.example/mousse-net/1"]}),
    );
    let stored = peer_of(&mut b, &host);
    assert_eq!(
        stored["offered"],
        json!([offer, "wss://t.example:443/mousse-net/1"])
    );
    b.event("dial.failed", |m| m["identity"] == host.as_str());
    assert_eq!(dead_taken.load(Ordering::SeqCst), 0, "an offer was dialled");
}

/// The owner's addresses may be of every kind; each is an `owner`
/// approval, the ones dropped from the list lose theirs, and the host is
/// reached over the approved public address.
#[test]
fn owner_addresses_of_every_kind_are_owner_approvals() {
    let a_end = Endpoint::init("oaa");
    let b_end = Endpoint::init("oab");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let a_route = route_of(&mut a);
    let map = format!("{}=public", port_of(&a_route));
    let mut b = b_end.app("peerB", &[("TEST_CLASS_MAP", &map)]);
    b.hello();
    trust(&mut a, &mut b, &[]);
    let set = b.call(
        "peer.addresses.set",
        json!({"identity": a.identity, "routes": [
            a_route,
            "wss://127.0.0.1:9/mousse-net/1",
            "ws://127.0.0.1:9/mousse-net/1",
            "ssh://me@Box",
        ]}),
    );
    assert_eq!(
        set["routes"],
        json!([
            a_route,
            "wss://127.0.0.1:9/mousse-net/1",
            "ws://127.0.0.1:9/mousse-net/1",
            "ssh://me@box"
        ])
    );
    let stored = approvals(&mut b, &a.identity);
    assert_eq!(stored.len(), 4, "{stored:?}");
    assert!(stored.iter().all(|s| s["source"] == "owner"));
    wait_outbound(&b, &a.identity, 0);
    let up = b.event("conn.up", |m| m["dir"] == "out");
    assert_eq!(up["route"], json!({"kind": "tcp", "class": "public"}));
    b.call(
        "peer.addresses.set",
        json!({"identity": a.identity, "routes": [a_route]}),
    );
    let stored = approvals(&mut b, &a.identity);
    assert_eq!(stored.len(), 1, "{stored:?}");
    assert_eq!(stored[0]["destination"], a_route.as_str());
    b.call("peer.forget", json!({"identity": a.identity}));
    assert!(approvals(&mut b, &a.identity).is_empty());
}

/// A last working route that lost its approval is dropped, and neither the
/// keeper nor a restart dials it.
#[test]
fn a_last_route_that_lost_its_approval_is_not_dialled() {
    let a_end = Endpoint::init("lra");
    let b_end = Endpoint::init("lrb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let a_route = route_of(&mut a);
    let map = format!("{}=tailnet", port_of(&a_route));
    let env = [
        ("TEST_CLASS_MAP", map.as_str()),
        ("KEEP_RETRY_FIRST_MS", "100"),
        ("KEEP_RETRY_MAX_MS", "200"),
    ];
    let mut b = b_end.app("peerB", &env);
    b.hello();
    trust(&mut a, &mut b, &[]);
    b.call(
        "peer.addresses.set",
        json!({"identity": a.identity, "routes": [a_route]}),
    );
    wait_outbound(&b, &a.identity, 0);
    assert_eq!(peer_of(&mut b, &a.identity)["last_route"], a_route.as_str());
    let up = b.event("conn.up", |m| m["dir"] == "out");
    assert_eq!(up["route"], json!({"kind": "tcp", "class": "tailnet"}));
    b.call(
        "peer.addresses.set",
        json!({"identity": a.identity, "routes": []}),
    );
    assert!(peer_of(&mut b, &a.identity)["last_route"].is_null());
    b.kill();
    let seen = inbound_ups(&a, &b.identity);
    let mut b = b_end.app("peerB", &env);
    b.hello();
    b.event("dial.failed", |m| m["identity"] == a.identity.as_str());
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        inbound_ups(&a, &b.identity),
        seen,
        "dialled without approval"
    );
}

/// A store from 1.0 has no `approvals.json`: its stored routes count only
/// under the automatic rule, so a tailnet route stays undialled.
#[test]
fn a_1_0_stores_routes_count_only_under_the_automatic_rule() {
    let a_end = Endpoint::init("u1a");
    let b_end = Endpoint::init("u1b");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let a_route = route_of(&mut a);
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    let b_identity = b.identity.clone();
    b.kill();
    a.call(
        "grant.add",
        json!({"identity": b_identity, "name": "peerB"}),
    );
    let peers = json!({"version": 1, "peers": [{
        "name": "hostA",
        "identity": a.identity,
        "role": "owner",
        "routes": [a_route],
        "last_route": a_route,
        "paired_at": 1,
    }]});
    std::fs::write(
        b_end.dir.join("peers.json"),
        serde_json::to_vec(&peers).unwrap(),
    )
    .unwrap();
    let map = format!("{}=tailnet", port_of(&a_route));
    let mut b = b_end.app("peerB", &[("TEST_CLASS_MAP", &map)]);
    b.hello();
    b.event("dial.failed", |m| m["identity"] == a.identity.as_str());
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(inbound_ups(&a, &b_identity), 0, "a 1.0 route was trusted");
    assert!(approvals(&mut b, &a.identity).is_empty());
    assert!(!b_end.dir.join("approvals.json").exists());
    // The same store's private (here: loopback) route is still dialled.
    b.kill();
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    wait_outbound(&b, &a.identity, 0);
}

/// `conn.up` names the route on both sides: `tcp` over the LAN class.
#[test]
fn conn_up_names_the_route_on_both_sides() {
    let pair = pair_up("cur", &[], &[]);
    let out = pair.b.event("conn.up", |m| m["conn"] == json!(pair.b_conn));
    assert_eq!(out["route"], json!({"kind": "tcp", "class": "lan"}));
    let inb = pair.a.event("conn.up", |m| m["conn"] == json!(pair.a_conn));
    assert_eq!(inb["route"], json!({"kind": "tcp", "class": "lan"}));
}

/// `routes.config` writes `routes.json` and says when a restart is
/// needed; what it refuses is not written.
#[test]
fn routes_config_says_when_a_restart_is_needed() {
    let b_end = Endpoint::init("rcb");
    std::fs::write(
        b_end.dir.join("routes.json"),
        r#"{"lan": false, "tailnet": false, "tunnels": ["wss://a.example/mousse-net/1"]}"#,
    )
    .unwrap();
    let mut b = b_end.app("peerB", &[]);
    let hello = b.hello();
    assert_eq!(hello["routes_config"]["lan"], false);
    assert_eq!(hello["routes"], json!(["wss://a.example:443/mousse-net/1"]));
    let more = b.call(
        "routes.config",
        json!({"tunnels": ["wss://a.example/mousse-net/1", "wss://b.example/mousse-net/1"]}),
    );
    assert_eq!(more["restart_needed"], false, "{more}");
    assert_eq!(
        more["routes"],
        json!([
            "wss://a.example:443/mousse-net/1",
            "wss://b.example:443/mousse-net/1"
        ])
    );
    for change in [
        json!({"tunnels": []}),
        json!({"tailnet": true}),
        json!({"port": 7999}),
    ] {
        let reply = b.call("routes.config", change.clone());
        assert_eq!(reply["restart_needed"], true, "{change}: {reply}");
    }
    for bad in [
        json!({"public": ["tcp://8.8.4.4:7443"]}),
        json!({"public": ["tcp://192.0.2.1:7443"], "lan": true}),
        json!({"tunnels": ["ws://127.0.0.1:9/mousse-net/1"]}),
        json!({"nope": 1}),
    ] {
        let reply = b.request("routes.config", bad.clone());
        assert_eq!(reply["error"], "bad_route", "{bad}: {reply}");
    }
    let stored: Value =
        serde_json::from_slice(&std::fs::read(b_end.dir.join("routes.json")).unwrap()).unwrap();
    assert_eq!(stored["port"], 7999);
    assert_eq!(stored["tailnet"], true);
    assert_eq!(stored["tunnels"], json!([]));
}

/// With nothing selected the helper listens on loopback only and
/// advertises nothing.
#[test]
fn nothing_selected_listens_on_loopback_and_advertises_nothing() {
    let b_end = Endpoint::init("nsb");
    std::fs::write(b_end.dir.join("routes.json"), "{}").unwrap();
    let mut b = b_end.app("peerB", &[]);
    let hello = b.hello();
    assert_eq!(hello["routes"], json!([]));
    assert_eq!(hello["unbound"], json!([]));
    let port = hello["port"].as_u64().unwrap() as u16;
    std::net::TcpStream::connect(("127.0.0.1", port)).expect("loopback is served");
}

/// A selected address that does not bind is listed as `unbound`, and the
/// helper starts anyway.
#[test]
fn an_address_that_does_not_bind_is_unbound() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let b_end = Endpoint::init("ubb");
    std::fs::write(
        b_end.dir.join("routes.json"),
        format!(r#"{{"port": {port}}}"#),
    )
    .unwrap();
    let mut b = b_end.app("peerB", &[]);
    let hello = b.hello();
    assert_eq!(hello["unbound"], json!(["127.0.0.1"]), "{hello}");
    assert_eq!(hello["port"], port);
    assert_eq!(hello["routes"], json!([]));
    drop(taken);
}

/// `routes.test` dials this helper's own route and passes step 1; a route
/// that does not answer reads "Couldn't confirm from this network".
#[test]
fn routes_test_confirms_its_own_route() {
    let b_end = Endpoint::init("rtb");
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    let own = route_of(&mut b);
    let ok = b.call("routes.test", json!({"route": own}));
    assert_eq!(ok["ok"], true, "{ok}");
    assert!(ok["ms"].as_u64().is_some());
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let failed = b.call("routes.test", json!({"route": format!("tcp://{dead}")}));
    assert_eq!(failed["ok"], false, "{failed}");
    assert_eq!(failed["reason"], "Couldn't confirm from this network");
    let refused = b.request("routes.test", json!({"route": "ssh://me@box"}));
    assert_eq!(refused["error"], "bad_route", "{refused}");
}

/// A plain `ws` route is the owner's local tunnel hop: under the release
/// policy, which never dials `tcp` to loopback, it is still allowed and
/// dialled (§1.1, Decision 2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plain_ws_tunnel_hop_is_dialled_in_release_builds() {
    let release = AddrPolicy::release();
    let hop = route("ws://127.0.0.1:8080/mousse-net/1");
    assert!(!release.names_forbidden(&hop));
    assert!(!release.automatic(&hop), "an owner address, not automatic");
    assert!(release.names_forbidden(&route("tcp://127.0.0.1:8080")));
    let e = engine().await;
    let mut caller = granted(&e, Arc::new(ManualClock::new()), &[]);
    caller.use_addr_policy(AddrPolicy::release());
    let seen = Seen::default();
    caller.use_ws_dialer(standin(Instant::now(), &seen, Some(e.addr)));
    let (_conn, reached) = within(
        "the search",
        Duration::from_secs(20),
        caller.search(Search::of(vec![hop]), e.host.identity()),
    )
    .await
    .unwrap();
    assert_eq!(reached.class, RouteClass::Tunnel);
    assert_eq!(seen.starts()[0].1, Some("127.0.0.1:8080".parse().unwrap()));
}

/// A loopback listener for the standalone cases: counts what it accepts.
fn counting_listener() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in listener.incoming().flatten() {
            seen.fetch_add(1, Ordering::SeqCst);
            held.push(s);
        }
    });
    (addr, count)
}

/// Standalone `join` applies the same policy: a ticket's public hint is
/// not dialled without the owner's approval, and an owner `--route` naming
/// a forbidden address is refused.
#[test]
fn standalone_join_dials_only_what_the_policy_allows() {
    let a_end = Endpoint::init("sja");
    let b_end = Endpoint::init("sjb");
    let mut a = a_end.app("hostA", &[]);
    a.hello();
    let invite = a.call("invite.create", json!({"kind": "link"}));
    let (public, taken) = counting_listener();
    let mut ticket = Ticket::from_fragment(invite["uri"].as_str().unwrap()).unwrap();
    ticket.routes = vec![format!("tcp://{public}")];
    let map = format!("{}=public", public.port());
    let env = [("MOUSSE_NET_TEST_CLASS_MAP", map.as_str())];
    let mut join = b_end.cli_env(&["join", &ticket.to_fragment()], &env);
    join.end_stdin();
    assert_ne!(join.exit_within(WAIT), Some(0), "{}", join.out());
    assert!(
        join.out().contains("not dialled without approval"),
        "{}",
        join.out()
    );
    assert_eq!(
        taken.load(Ordering::SeqCst),
        0,
        "the public hint was dialled"
    );
    let mut typed = b_end.cli_env(
        &[
            "join",
            &ticket.to_fragment(),
            "--route",
            "tcp://0.0.0.0:7443",
        ],
        &env,
    );
    typed.end_stdin();
    assert_ne!(typed.exit_within(WAIT), Some(0));
    assert!(typed.err().contains("never dialled"), "{}", typed.err());
}

/// Standalone `term` dials the stored routes the policy allows: an
/// unapproved public route is not dialled.
#[test]
fn standalone_term_dials_only_stored_routes_the_policy_allows() {
    let b_end = Endpoint::init("stb");
    let (public, taken) = counting_listener();
    let peers = json!({"version": 1, "peers": [{
        "name": "far",
        "identity": some_identity(),
        "role": "owner",
        "routes": [format!("tcp://{public}")],
        "last_route": format!("tcp://{public}"),
        "paired_at": 1,
    }]});
    std::fs::write(
        b_end.dir.join("peers.json"),
        serde_json::to_vec(&peers).unwrap(),
    )
    .unwrap();
    let map = format!("{}=public", public.port());
    let mut term = b_end.cli_env(
        &["term", "far", "--", "echo"],
        &[("MOUSSE_NET_TEST_CLASS_MAP", map.as_str())],
    );
    term.end_stdin();
    assert_eq!(term.exit_within(WAIT), Some(2), "{}", term.err());
    assert_eq!(
        taken.load(Ordering::SeqCst),
        0,
        "an unapproved route was dialled"
    );
}

/// A `routes.config` list edit that needs no restart reaches the next
/// ticket at once.
#[test]
fn a_routes_config_list_edit_reaches_the_next_ticket() {
    let b_end = Endpoint::init("rlb");
    std::fs::write(
        b_end.dir.join("routes.json"),
        r#"{"tunnels": ["wss://a.example/mousse-net/1"]}"#,
    )
    .unwrap();
    let mut b = b_end.app("peerB", &[]);
    b.hello();
    let edit = b.call(
        "routes.config",
        json!({"tunnels": ["wss://b.example/mousse-net/1"]}),
    );
    assert_eq!(edit["restart_needed"], false, "{edit}");
    let invite = b.call("invite.create", json!({}));
    assert_eq!(
        invite["routes"],
        json!(["wss://b.example:443/mousse-net/1"])
    );
    let ticket = Ticket::from_fragment(invite["uri"].as_str().unwrap()).unwrap();
    assert_eq!(ticket.routes, ["wss://b.example:443/mousse-net/1"]);
    let hello = b.call("hello", json!({"proto": [1, 0]}));
    assert_eq!(hello["routes"], json!(["wss://b.example:443/mousse-net/1"]));
}

/// A fresh identity no helper here has.
fn some_identity() -> String {
    use mousse_net_core::identity::IdentitySigner;
    let key = SoftwareKey::generate(&mut os_rng());
    mousse_net_io::store::hex(IdentitySigner::public_key(&key).as_bytes())
}

/// A port nothing listens on right now.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// With a class map, an inbound connection takes the class the map gives
/// the listener's port it arrived on, not the caller's source port, so a
/// check judges the host's side by class as well as kind.
#[test]
fn an_inbound_connection_takes_the_class_of_the_port_it_arrived_on() {
    let port = free_port();
    let map = format!("{port}=public");
    let a_end = Endpoint::init("inca");
    let b_end = Endpoint::init("incb");
    let mut a = a_end.app_with("hostA", &[("TEST_CLASS_MAP", &map)], port, None);
    a.hello();
    let a_route = route_of(&mut a);
    assert_eq!(port_of(&a_route), port);
    let mut b = b_end.app("peerB", &[("TEST_CLASS_MAP", &map)]);
    b.hello();
    trust(&mut a, &mut b, &[]);
    b.call(
        "peer.addresses.set",
        json!({"identity": a.identity, "routes": [a_route]}),
    );
    let out = b.event("conn.up", |m| m["dir"] == "out");
    assert_eq!(out["route"], json!({"kind": "tcp", "class": "public"}));
    let b_identity = b.identity.clone();
    let inbound = a.event("conn.up", |m| {
        m["dir"] == "in" && m["identity"] == b_identity.as_str()
    });
    assert_eq!(inbound["route"], json!({"kind": "tcp", "class": "public"}));
}

/// `*=<class>` names the class of every loopback port the map leaves out;
/// an inbound connection's listener port wins over its source port.
#[test]
fn the_class_map_default_covers_unmapped_loopback_ports() {
    let policy = mousse_net_io::pipe::AddrPolicy::debug()
        .with_class_map("7443=tailnet,*=public")
        .unwrap();
    let at = |port: u16| SocketAddr::from(([127, 0, 0, 1], port));
    assert_eq!(policy.class_of(at(7443)), AddrClass::Tailnet);
    assert_eq!(policy.class_of(at(50_000)), AddrClass::Public);
    assert_eq!(
        policy.class_of_inbound(at(50_000), Some(at(7443))),
        AddrClass::Tailnet
    );
    let plain = mousse_net_io::pipe::AddrPolicy::debug()
        .with_class_map("7443=tailnet")
        .unwrap();
    assert_eq!(plain.class_of(at(50_000)), AddrClass::Lan);
    assert_eq!(
        plain.class_of_inbound(at(50_000), Some(at(7443))),
        AddrClass::Tailnet
    );
}

/// Move both helpers' wall clocks to the moment `deadline`'s path is due
/// for renewal.
fn clocks_to_renewal(a: &mut App, b: &mut App, deadline: i64) {
    let now = b.call("test.clock", json!({}))["now"].as_i64().unwrap();
    let due = deadline
        - CoreLimits::DEFAULT.clock_skew_secs() as i64
        - CoreLimits::DEFAULT.renew_lead_secs() as i64;
    for app in [a, b] {
        app.call("test.clock", json!({"advance_secs": due - now}));
    }
}

/// A renewed path's `conn.up` carries its route like any other, on both
/// sides, so a path switch is judged by route too.
#[test]
fn a_renewed_path_carries_its_route() {
    let port = free_port();
    let map = format!("{port}=tailnet");
    let clock = [("MOUSSE_HELPER_MANUAL_CLOCK", std::path::Path::new("1"))];
    let a_end = Endpoint::init("rra");
    let b_end = Endpoint::init("rrb");
    let mut a = a_end.app_raw("hostA", &[("TEST_CLASS_MAP", &map)], port, &clock);
    a.hello();
    let a_route = route_of(&mut a);
    let mut b = b_end.app_raw("peerB", &[("TEST_CLASS_MAP", &map)], 0, &clock);
    b.hello();
    trust(&mut a, &mut b, &[]);
    b.call(
        "peer.addresses.set",
        json!({"identity": a.identity, "routes": [a_route]}),
    );
    let a_id = a.identity.clone();
    let first = b.event("conn.up", |m| {
        m["dir"] == "out" && m["identity"] == a_id.as_str()
    });
    let tailnet = json!({"kind": "tcp", "class": "tailnet"});
    assert_eq!(first["route"], tailnet);
    let deadline = first["deadline"].as_i64().unwrap();
    clocks_to_renewal(&mut a, &mut b, deadline);
    let reopen = b.event("path.reopen", |m| m["identity"] == a_id.as_str());
    let renewed = reopen["conn"].clone();
    let up = b.event("conn.up", |m| m["conn"] == renewed);
    assert_eq!(up["route"], tailnet, "{up}");
    let b_id = b.identity.clone();
    let inbound = a.wait("the renewed path on A", WAIT, |st| {
        st.messages
            .iter()
            .filter(|m| m["ev"] == "conn.up" && m["dir"] == "in" && m["identity"] == b_id.as_str())
            .nth(1)
            .cloned()
    });
    assert_eq!(inbound["route"], tailnet, "{inbound}");
}
