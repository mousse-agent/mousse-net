//! E8: the `ws` route (Phase 1b §4). The loopback listener's upgrade
//! checks and caps, binary-only messages, and the caller's `ws`/`wss`
//! client: plain `ws` only to loopback, `wss` through a TLS-terminating
//! stand-in for a tunnel with the debug-only extra root, redirects
//! refused. The check cell `phase1b.ws` runs this file.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use common::*;
use mousse_net_core::control::{ControlMessage, VersionSupport};
use mousse_net_core::identity::{IdentityPublicKey, SoftwareKey};
use mousse_net_core::mux::Frame;
use mousse_net_core::pairing::RouteHost;
use mousse_net_core::session_cert::SessionCertificate;
use mousse_net_io::certs::CertManager;
use mousse_net_io::pipe::ws::{self, WsTarget};
use mousse_net_io::rng::os_rng;
use mousse_net_io::store::{hex, unhex};
use mousse_net_io::tls::{self, TlsPolicy};
use mousse_net_io::{Caller, ConnStatus, Limits, ManualClock, NetError, SystemClock};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A helper with its ws listener on: the state, the app, the ws port.
fn ws_app(tag: &str, env: &[(&str, &str)]) -> (Endpoint, App, u16) {
    let end = Endpoint::init(tag);
    let mut app = end.app_args("hostA", env, &["--ws-port", "0"]);
    let hello = app.hello();
    let port = hello["ws_port"].as_u64().expect("no ws_port in hello") as u16;
    (end, app, port)
}

fn upgrade(method: &str, path: &str, extra: &str) -> String {
    format!(
        "{method} {path} HTTP/1.1\r\nHost: tunnel.example\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n{extra}\r\n"
    )
}

const MOUSSE: &str = "Sec-WebSocket-Protocol: mousse.1\r\n";

fn connect(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

/// What the listener answers up to the end of its headers, or until it
/// closes.
fn answer(s: &mut TcpStream) -> String {
    let mut got = Vec::new();
    let mut byte = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        match s.read(&mut byte) {
            Ok(1) => got.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

fn status_of(port: u16, request: &str) -> String {
    let mut s = connect(port);
    s.write_all(request.as_bytes()).unwrap();
    answer(&mut s).lines().next().unwrap_or("").to_owned()
}

/// Whether the peer closed `s` within `limit` without sending anything
/// (`Some(true)`), sent bytes (`Some(false)`), or neither (`None`).
fn closed_within(s: &mut TcpStream, limit: Duration) -> Option<bool> {
    s.set_read_timeout(Some(limit)).unwrap();
    match s.read(&mut [0u8; 64]) {
        Ok(0) => Some(true),
        Ok(_) => Some(false),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            None
        }
        Err(_) => Some(true),
    }
}

/// A masked client frame.
fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [0x37u8, 0xfa, 0x21, 0x3d];
    let mut out = vec![0x80 | opcode];
    match payload.len() {
        n if n < 126 => out.push(0x80 | n as u8),
        n if n < 65_536 => {
            out.push(0x80 | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(0x80 | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

/// One server frame: opcode and payload.
fn read_frame(s: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).ok()?;
    let len = match head[1] & 0x7f {
        126 => {
            let mut b = [0u8; 2];
            s.read_exact(&mut b).ok()?;
            usize::from(u16::from_be_bytes(b))
        }
        127 => {
            let mut b = [0u8; 8];
            s.read_exact(&mut b).ok()?;
            u64::from_be_bytes(b) as usize
        }
        n => usize::from(n),
    };
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).ok()?;
    Some((head[0] & 0x0f, payload))
}

/// A connection the listener upgraded.
fn upgraded(port: u16) -> TcpStream {
    let mut s = connect(port);
    s.write_all(upgrade("GET", "/mousse-net/1", MOUSSE).as_bytes())
        .unwrap();
    let got = answer(&mut s);
    assert!(got.starts_with("HTTP/1.1 101"), "{got}");
    s
}

#[test]
fn the_app_origin_is_available_before_a_tunnel_is_configured() {
    let end = Endpoint::init("ws-origin");
    let mut app = end.app("hostA", &[]);
    let hello = app.hello();
    let port = u16::try_from(hello["ws_port"].as_u64().expect("no local origin")).unwrap();
    assert!(hello["routes_config"]["tunnels"]
        .as_array()
        .unwrap()
        .is_empty());
    drop(upgraded(port));
    drop(app);

    let mut restarted = end.app("hostA", &[]);
    assert_eq!(restarted.hello()["ws_port"], port);
    drop(upgraded(port));
}

#[test]
fn an_upgrade_offering_mousse_1_is_accepted_and_selects_it() {
    let (_end, _a, port) = ws_app("wsok", &[]);
    let mut s = connect(port);
    s.write_all(
        upgrade(
            "GET",
            "/tunnel/x/mousse-net/1",
            "Sec-WebSocket-Protocol: other, mousse.1\r\n",
        )
        .as_bytes(),
    )
    .unwrap();
    let got = answer(&mut s);
    assert!(got.starts_with("HTTP/1.1 101"), "{got}");
    assert!(
        got.to_ascii_lowercase()
            .contains("sec-websocket-protocol: mousse.1"),
        "{got}"
    );
}

#[test]
fn a_request_that_is_not_get_is_refused() {
    let (_end, _a, port) = ws_app("wspost", &[]);
    let got = status_of(port, &upgrade("POST", "/mousse-net/1", MOUSSE));
    assert!(got.starts_with("HTTP/1.1 405"), "{got}");
}

#[test]
fn a_path_without_the_mousse_suffix_gets_404() {
    let (_end, _a, port) = ws_app("wspath", &[]);
    for path in ["/", "/mousse-net/2", "/mousse-net/1/", "/mousse-net/1?x=1"] {
        let got = status_of(port, &upgrade("GET", path, MOUSSE));
        assert!(got.starts_with("HTTP/1.1 404"), "{path}: {got}");
    }
}

/// Browsers always send `Origin`; the tunnel client never does.
#[test]
fn a_request_with_origin_gets_403() {
    let (_end, _a, port) = ws_app("wsorigin", &[]);
    let extra = format!("{MOUSSE}Origin: https://evil.example\r\n");
    let got = status_of(port, &upgrade("GET", "/mousse-net/1", &extra));
    assert!(got.starts_with("HTTP/1.1 403"), "{got}");
}

#[test]
fn a_request_without_the_subprotocol_gets_400() {
    let (_end, _a, port) = ws_app("wsproto", &[]);
    for extra in ["", "Sec-WebSocket-Protocol: mousse.2\r\n"] {
        let got = status_of(port, &upgrade("GET", "/mousse-net/1", extra));
        assert!(got.starts_with("HTTP/1.1 400"), "{extra:?}: {got}");
    }
}

#[test]
fn an_upgrade_request_past_the_size_cap_is_closed_unanswered() {
    let (_end, _a, port) = ws_app("wsbig", &[("WS_HEADER_MAX_BYTES", "1024")]);
    let pad = format!("X-Pad: {}\r\n", "a".repeat(1100));
    let mut s = connect(port);
    let _ = s.write_all(upgrade("GET", "/mousse-net/1", &format!("{MOUSSE}{pad}")).as_bytes());
    assert_eq!(closed_within(&mut s, Duration::from_secs(5)), Some(true));
}

#[test]
fn an_upgrade_request_trickled_past_the_wait_is_closed_unanswered() {
    let (_end, _a, port) = ws_app("wsslow", &[("WS_UPGRADE_WAIT_MS", "300")]);
    let mut s = connect(port);
    let start = Instant::now();
    s.write_all(b"GET /mousse-net/1 HTTP/1.1\r\n").unwrap();
    // A header line every 100 ms, never the end.
    let mut closed = None;
    for _ in 0..20 {
        if s.write_all(b"X-Slow: 1\r\n").is_err() {
            closed = Some(true);
            break;
        }
        if let Some(c) = closed_within(&mut s, Duration::from_millis(100)) {
            closed = Some(c);
            break;
        }
    }
    assert_eq!(closed, Some(true), "the trickle was kept");
    assert!(start.elapsed() < Duration::from_millis(1500));
}

#[test]
fn a_text_message_closes_with_1003() {
    let (_end, _a, port) = ws_app("wstext", &[]);
    let mut s = upgraded(port);
    s.write_all(&frame(0x1, b"hello")).unwrap();
    let (opcode, payload) = read_frame(&mut s).expect("no close frame");
    assert_eq!(opcode, 0x8);
    assert_eq!(&payload[..2], &1003u16.to_be_bytes());
}

#[test]
fn a_message_past_the_cap_ends_the_connection() {
    let (_end, _a, port) = ws_app("wscap", &[("WS_MESSAGE_MAX_BYTES", "16384")]);
    let mut s = upgraded(port);
    let _ = s.write_all(&frame(0x2, &[0x16; 20_000]));
    let start = Instant::now();
    loop {
        match read_frame(&mut s) {
            None => break,
            Some((0x8, _)) => break,
            Some(_) => {}
        }
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}

#[test]
fn pings_are_answered() {
    let (_end, _a, port) = ws_app("wsping", &[]);
    let mut s = upgraded(port);
    s.write_all(&frame(0x9, b"ping")).unwrap();
    assert_eq!(read_frame(&mut s), Some((0xA, b"ping".to_vec())));
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn new_caller() -> Caller {
    Caller::new(
        Arc::new(SoftwareKey::generate(&mut os_rng())),
        Arc::new(ManualClock::new()),
        Limits::DEFAULT,
    )
}

fn identity_of(app: &App) -> IdentityPublicKey {
    IdentityPublicKey::from_sec1(&unhex(&app.identity).unwrap()).unwrap()
}

fn loopback_target(port: u16) -> WsTarget {
    WsTarget::parse(&format!("ws://127.0.0.1:{port}/mousse-net/1")).unwrap()
}

/// A caller the helper grants reaches it over plain `ws` to loopback, as
/// a tunnel client's local hop does, and goes live.
#[test]
fn a_granted_caller_goes_live_over_ws() {
    let (_end, mut a, port) = ws_app("wslive", &[]);
    let caller = new_caller();
    a.call(
        "grant.add",
        json!({"identity": hex(caller.identity().as_bytes()), "name": "laptop"}),
    );
    let host = identity_of(&a);
    let rt = runtime();
    let conn = rt.block_on(async {
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let pipe = ws::dial(&loopback_target(port), addr, Limits::DEFAULT.io())
            .await
            .unwrap();
        caller.dial(pipe, host).await.unwrap()
    });
    assert_eq!(conn.status(), ConnStatus::Live);
    let me = hex(caller.identity().as_bytes());
    a.event("conn.up", |m| {
        m["dir"] == "in" && m["identity"] == me.as_str()
    });
}

/// A test root and a certificate for `localhost` it signs.
struct Pki {
    root: CertificateDer<'static>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn test_pki(label: &str) -> Pki {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, format!("mousse-net test root {label}"));
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    leaf.distinguished_name
        .push(DnType::CommonName, "localhost");
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let leaf_cert = leaf.signed_by(&leaf_key, &issuer).unwrap();
    Pki {
        root: ca_cert.der().clone(),
        chain: vec![leaf_cert.der().clone(), ca_cert.der().clone()],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    }
}

/// The root this test binary trusts through `MOUSSE_NET_TEST_EXTRA_ROOT`,
/// set once for every test in it.
fn trusted_pki() -> &'static Pki {
    static PKI: OnceLock<(Pki, PathBuf)> = OnceLock::new();
    let (pki, _) = PKI.get_or_init(|| {
        let pki = test_pki("trusted");
        let dir = temp_dir("wsroot");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("root.der");
        std::fs::write(&file, pki.root.as_ref()).unwrap();
        std::env::set_var(ws::TEST_EXTRA_ROOT_VAR, &file);
        (pki, file)
    });
    pki
}

/// A TLS-terminating stand-in for a tunnel: TLS on a loopback port with
/// `pki`'s certificate, plain bytes on to `target`. Its port.
async fn stand_in(pki: &Pki, target: u16) -> u16 {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(pki.chain.clone(), pki.key.clone_key())
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut plain) = tokio::net::TcpStream::connect(("127.0.0.1", target)).await
                else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut plain).await;
            });
        }
    });
    port
}

fn tunnel_target(port: u16) -> WsTarget {
    WsTarget {
        secure: true,
        host: RouteHost::Dns("localhost".into()),
        port,
        path: "/t/mousse-net/1".into(),
    }
}

/// `wss` through a stand-in that terminates the outer TLS, as a tunnel
/// does: the platform verifier plus the debug-only root, SNI by name, TCP
/// to the given address. The pinned session runs inside.
#[test]
fn wss_through_a_tls_terminating_stand_in_goes_live() {
    let pki = trusted_pki();
    let (_end, mut a, port) = ws_app("wsstls", &[]);
    let caller = new_caller();
    a.call(
        "grant.add",
        json!({"identity": hex(caller.identity().as_bytes()), "name": "laptop"}),
    );
    let host = identity_of(&a);
    let rt = runtime();
    let conn = rt.block_on(async {
        let tunnel = stand_in(pki, port).await;
        let addr: SocketAddr = ([127, 0, 0, 1], tunnel).into();
        let pipe = ws::dial(&tunnel_target(tunnel), addr, Limits::DEFAULT.io())
            .await
            .unwrap();
        caller.dial(pipe, host).await.unwrap()
    });
    assert_eq!(conn.status(), ConnStatus::Live);
}

#[test]
fn a_tunnel_reconnect_reports_two_way_support_even_with_a_delayed_hello() {
    let (_end, mut a, port) = ws_app("ws-delayed-hello", &[]);
    let (cert, me) = granted_caller(&mut a);
    let host = identity_of(&a);
    let rt = runtime();
    let _conn = rt.block_on(async {
        let mut conn = tunnel_tls(port, &cert, host).await;
        // On reconnect the saved grant makes the host live as soon as TLS
        // finishes. Delay the caller's HELLO as a slower path would.
        tokio::time::sleep(Duration::from_millis(250)).await;
        let hello = ControlMessage::Hello {
            major_version: VersionSupport::LOCAL.major,
            minor_version: VersionSupport::LOCAL.minor,
        };
        conn.write_all(
            &Frame::Control {
                payload: hello.encode(),
            }
            .encode(),
        )
        .await
        .unwrap();
        conn.flush().await.unwrap();
        conn
    });
    let up = a.event("conn.up", |m| {
        m["dir"] == "in" && m["identity"] == me.as_str()
    });
    assert_eq!(up["route"]["class"], "tunnel", "{up}");
    assert_eq!(up["both"], true, "{up}");
}

/// A granted caller that is live but never sends HELLO is closed after
/// `INBOUND_HELLO_WAIT_MS`, before the first keepalive, and never
/// announced.
#[test]
fn a_caller_that_never_sends_hello_is_closed_unannounced() {
    let (_end, mut a, port) = ws_app("ws-no-hello", &[("INBOUND_HELLO_WAIT_MS", "300")]);
    let (cert, me) = granted_caller(&mut a);
    let host = identity_of(&a);
    let rt = runtime();
    let closed = rt.block_on(async {
        let mut conn = tunnel_tls(port, &cert, host).await;
        let mut buf = [0u8; 4096];
        let until_closed = async { while matches!(conn.read(&mut buf).await, Ok(n) if n > 0) {} };
        tokio::time::timeout(Duration::from_secs(10), until_closed)
            .await
            .is_ok()
    });
    assert!(closed, "the host kept a connection that sent no HELLO");
    let ups = a.events("conn.up");
    assert!(ups.iter().all(|m| m["identity"] != me.as_str()), "{ups:?}");
}

/// A session certificate for a new device, granted by `a`, and its
/// identity in hex.
fn granted_caller(a: &mut App) -> (SessionCertificate, String) {
    let cert = CertManager::new(
        Arc::new(SoftwareKey::generate(&mut os_rng())),
        Arc::new(SystemClock::new()),
    )
    .current()
    .unwrap();
    let me = hex(cert.identity().as_bytes());
    a.call("grant.add", json!({"identity": me, "name": "laptop"}));
    (cert, me)
}

/// Reach the helper on ws `port` through a TLS-terminating tunnel stand-in
/// as `cert`, up to the end of the inner TLS. Nothing of the mux is sent.
async fn tunnel_tls(
    port: u16,
    cert: &SessionCertificate,
    host: IdentityPublicKey,
) -> impl AsyncRead + AsyncWrite + Unpin {
    let tunnel = stand_in(trusted_pki(), port).await;
    let addr = ([127, 0, 0, 1], tunnel).into();
    let pipe = ws::dial(&tunnel_target(tunnel), addr, Limits::DEFAULT.io())
        .await
        .unwrap();
    let clock = Arc::new(SystemClock::new());
    let (conn, _) = tls::connect(pipe, cert, host, clock, TlsPolicy::default())
        .await
        .unwrap();
    conn
}

/// A tunnel certificate no root vouches for is refused at the outer TLS.
#[test]
fn wss_to_a_certificate_no_root_vouches_for_is_refused() {
    let _ = trusted_pki();
    let other = test_pki("untrusted");
    let (_end, _a, port) = ws_app("wssbad", &[]);
    let rt = runtime();
    let result = rt.block_on(async {
        let tunnel = stand_in(&other, port).await;
        let addr: SocketAddr = ([127, 0, 0, 1], tunnel).into();
        ws::dial(&tunnel_target(tunnel), addr, Limits::DEFAULT.io())
            .await
            .map(|_| ())
    });
    assert!(result.is_err(), "an unknown root was accepted");
}

/// Plain `ws` is only the local hop of a tunnel client: never dialled off
/// this computer.
#[test]
fn plain_ws_goes_only_to_loopback() {
    let rt = runtime();
    let target = WsTarget {
        secure: false,
        host: RouteHost::Ipv4([192, 0, 2, 1].into()),
        port: 80,
        path: "/mousse-net/1".into(),
    };
    let result = rt.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(3),
            ws::dial(&target, ([192, 0, 2, 1], 80).into(), Limits::DEFAULT.io()),
        )
        .await
    });
    match result {
        Ok(Err(NetError::Refused(why))) => assert!(why.contains("loopback"), "{why}"),
        Ok(Err(other)) => panic!("dialled: {other}"),
        Ok(Ok(_)) => panic!("dialled"),
        Err(_) => panic!("dialled and waited"),
    }
}

#[test]
fn a_release_build_never_reads_the_test_root() {
    assert!(!ws::reads_test_root(true));
    assert!(ws::reads_test_root(false));
}

/// No redirects: a tunnel answering 302 fails with `ws_redirect`.
#[test]
fn a_redirect_fails_with_ws_redirect() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = answer(&mut s);
            let _ = s.write_all(
                b"HTTP/1.1 302 Found\r\nLocation: ws://127.0.0.1:1/mousse-net/1\r\nContent-Length: 0\r\n\r\n",
            );
        }
    });
    let rt = runtime();
    let result = rt.block_on(async {
        ws::dial(
            &loopback_target(port),
            ([127, 0, 0, 1], port).into(),
            Limits::DEFAULT.io(),
        )
        .await
        .map(|_| ())
    });
    match result {
        Err(NetError::Refused(why)) => assert_eq!(why, "ws_redirect"),
        other => panic!("{other:?}"),
    }
}
