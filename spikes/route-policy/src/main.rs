//! Phase 1b spike S2. See README.md.
//!
//! - `local`: resolve once, dial the classified address, outer TLS with
//!   the platform verifier plus one extra root, `client_async` on the TLS
//!   stream, subprotocol `mousse.1`, binary messages, the 65 536-byte cap.
//! - `search`: the bounded dial search over dead loopback candidates, timed.
//! - `ws-echo`: a plain loopback ws echo listener (the tunnel's local hop).
//! - `dial-wss`: dial a real `wss://` URL once (the cloudflared observation).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

const PATH_SUFFIX: &str = "/mousse-net/1";
const SUBPROTOCOL: &str = "mousse.1";
const WS_MESSAGE_MAX_BYTES: usize = 65536;

fn env_ms(name: &str, default: u64) -> Duration {
    Duration::from_millis(
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default),
    )
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(WS_MESSAGE_MAX_BYTES))
        .max_frame_size(Some(WS_MESSAGE_MAX_BYTES))
}

// ---------------------------------------------------------------- classify

/// §1.2, enough for the spike: `lan`, `tailnet`, `public` or `forbidden`.
fn classify(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_v4(v4);
            }
            let s = v6.segments();
            if s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0 {
                "tailnet"
            } else if s[0] & 0xfe00 == 0xfc00 {
                "lan"
            } else if s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
                && s[0] != 0x2002
            {
                "public"
            } else {
                "forbidden"
            }
        }
    }
}

fn classify_v4(ip: Ipv4Addr) -> &'static str {
    let o = ip.octets();
    if o[0] == 100 && (o[1] & 0xc0) == 64 {
        "tailnet"
    } else if ip.is_private() || ip.is_link_local() {
        "lan"
    } else if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
    {
        "forbidden"
    } else {
        "public"
    }
}

// ----------------------------------------------------------------- resolve

static RESOLVES: AtomicUsize = AtomicUsize::new(0);

/// The only name lookup in a try. `fixed` stands in for DNS in the local
/// check (a `.invalid` name nothing else can resolve).
async fn resolve_once(
    host: &str,
    port: u16,
    fixed: &HashMap<String, IpAddr>,
) -> std::io::Result<Vec<SocketAddr>> {
    RESOLVES.fetch_add(1, Ordering::SeqCst);
    if let Some(ip) = fixed.get(host) {
        return Ok(vec![SocketAddr::new(*ip, port)]);
    }
    Ok(tokio::net::lookup_host((host, port)).await?.collect())
}

// --------------------------------------------------------------------- PKI

struct Pki {
    root: CertificateDer<'static>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn test_pki(names: &[&str]) -> Pki {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "route-policy spike root");
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf =
        CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    leaf.distinguished_name.push(DnType::CommonName, names[0]);
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let leaf_cert = leaf.signed_by(&leaf_key, &issuer).unwrap();
    Pki {
        root: ca_cert.der().clone(),
        chain: vec![leaf_cert.der().clone(), ca_cert.der().clone()],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    }
}

fn platform_verifier(extra: Option<CertificateDer<'static>>) -> Arc<dyn ServerCertVerifier> {
    let v = match extra {
        Some(root) => rustls_platform_verifier::Verifier::new_with_extra_roots([root], provider()),
        None => rustls_platform_verifier::Verifier::new(provider()),
    };
    Arc::new(v.expect("platform verifier"))
}

fn connector(verifier: Arc<dyn ServerCertVerifier>) -> TlsConnector {
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(cfg))
}

fn acceptor(pki: &Pki, sni_log: Arc<Mutex<Vec<String>>>) -> TlsAcceptor {
    #[derive(Debug)]
    struct LogSni {
        inner: Arc<rustls::sign::CertifiedKey>,
        log: Arc<Mutex<Vec<String>>>,
    }
    impl rustls::server::ResolvesServerCert for LogSni {
        fn resolve(
            &self,
            hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            self.log
                .lock()
                .unwrap()
                .push(hello.server_name().unwrap_or("<none>").to_string());
            Some(self.inner.clone())
        }
    }
    let key = provider()
        .key_provider
        .load_private_key(pki.key.clone_key())
        .unwrap();
    let certified = Arc::new(rustls::sign::CertifiedKey::new(pki.chain.clone(), key));
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(LogSni {
            inner: certified,
            log: sni_log,
        }));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(cfg))
}

// -------------------------------------------------------------- ws server

/// §4.1's upgrade checks (path, no `Origin`, `mousse.1`), then echo binary
/// messages. A one-byte `0xFF` asks for one message over the cap.
async fn serve_ws<S: AsyncRead + AsyncWrite + Unpin>(stream: S, peer: String, verbose: bool) {
    let callback = move |req: &Request, mut resp: Response| -> Result<Response, ErrorResponse> {
        if verbose {
            println!("[server] {} {} from {peer}", req.method(), req.uri());
            for (k, v) in req.headers() {
                println!("[server]   {k}: {}", v.to_str().unwrap_or("<bin>"));
            }
        }
        let reject = |code: StatusCode| {
            let mut r = ErrorResponse::new(None);
            *r.status_mut() = code;
            r
        };
        if !req.uri().path().ends_with(PATH_SUFFIX) {
            return Err(reject(StatusCode::NOT_FOUND));
        }
        if req.headers().contains_key("origin") {
            return Err(reject(StatusCode::FORBIDDEN));
        }
        let offered = req
            .headers()
            .get_all("sec-websocket-protocol")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|p| p.trim() == SUBPROTOCOL);
        if !offered {
            return Err(reject(StatusCode::BAD_REQUEST));
        }
        resp.headers_mut().insert(
            "sec-websocket-protocol",
            HeaderValue::from_static(SUBPROTOCOL),
        );
        Ok(resp)
    };
    let mut ws =
        match tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(ws_config()))
            .await
        {
            Ok(ws) => ws,
            Err(e) => {
                println!("[server] upgrade failed: {e}");
                return;
            }
        };
    while let Some(msg) = ws.next().await {
        match msg {
            Ok(Message::Binary(b)) => {
                let reply = if b.len() == 1 && b[0] == 0xFF {
                    vec![7u8; WS_MESSAGE_MAX_BYTES + 1]
                } else {
                    b.to_vec()
                };
                if ws.send(Message::binary(reply)).await.is_err() {
                    break;
                }
            }
            Ok(Message::Text(_)) => {
                let _ = ws
                    .close(Some(CloseFrame {
                        code: CloseCode::Unsupported,
                        reason: "binary only".into(),
                    }))
                    .await;
                break;
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
            Err(e) => {
                println!("[server] read ended: {e}");
                break;
            }
        }
    }
}

// -------------------------------------------------------------- ws client

struct Dialed<S> {
    ws: WebSocketStream<S>,
    protocol: Option<String>,
    tcp_ms: u128,
    tls_ms: u128,
    upgrade_ms: u128,
}

async fn dial_wss(
    host: &str,
    port: u16,
    path: &str,
    addr: SocketAddr,
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<Dialed<tokio_rustls::client::TlsStream<TcpStream>>, String> {
    let t0 = Instant::now();
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("tcp: {e}"))?;
    tcp.set_nodelay(true).ok();
    let tcp_ms = t0.elapsed().as_millis();
    let name = ServerName::try_from(host.to_string()).map_err(|e| format!("name: {e}"))?;
    let tls = connector(verifier)
        .connect(name, tcp)
        .await
        .map_err(|e| format!("tls: {e}"))?;
    let tls_ms = t0.elapsed().as_millis();
    let url = if port == 443 {
        format!("wss://{host}{path}")
    } else {
        format!("wss://{host}:{port}{path}")
    };
    let mut req = url
        .into_client_request()
        .map_err(|e| format!("request: {e}"))?;
    req.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(SUBPROTOCOL),
    );
    let (ws, resp) = tokio_tungstenite::client_async_with_config(req, tls, Some(ws_config()))
        .await
        .map_err(|e| format!("upgrade: {e}"))?;
    let upgrade_ms = t0.elapsed().as_millis();
    let protocol = resp
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    Ok(Dialed {
        ws,
        protocol,
        tcp_ms,
        tls_ms,
        upgrade_ms,
    })
}

/// Echo checks on an open socket: RTTs of small messages, 16 KiB, the
/// exact cap, and one message over the cap from each side.
async fn exercise<S: AsyncRead + AsyncWrite + Unpin>(ws: &mut WebSocketStream<S>) {
    let mut rtts = Vec::new();
    for i in 0..10u8 {
        let msg = vec![i; 1024];
        let t = Instant::now();
        ws.send(Message::binary(msg.clone())).await.unwrap();
        match ws.next().await {
            Some(Ok(Message::Binary(b))) if b[..] == msg[..] => rtts.push(t.elapsed().as_millis()),
            other => {
                println!("== small echo: FAIL {other:?}");
                return;
            }
        }
    }
    rtts.sort();
    println!(
        "== 1 KiB echo RTT ms: min={} median={} max={} all={rtts:?}",
        rtts[0],
        rtts[rtts.len() / 2],
        rtts[rtts.len() - 1]
    );
    for size in [16 * 1024, WS_MESSAGE_MAX_BYTES] {
        let msg: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
        let t = Instant::now();
        ws.send(Message::binary(msg.clone())).await.unwrap();
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => println!(
                "== {size}-byte message echo: {} in {} ms",
                if b[..] == msg[..] {
                    "PASS"
                } else {
                    "FAIL (bytes differ)"
                },
                t.elapsed().as_millis()
            ),
            other => println!("== {size}-byte message echo: FAIL {other:?}"),
        }
    }
    // The client's own cap: the server sends 65 537 bytes.
    ws.send(Message::binary(vec![0xFFu8])).await.unwrap();
    match ws.next().await {
        Some(Err(e)) => println!("== client cap (server sends 65537): refused: {e}"),
        other => println!("== client cap (server sends 65537): NOT refused: {other:?}"),
    }
}

async fn over_cap_from_client<S: AsyncRead + AsyncWrite + Unpin>(mut ws: WebSocketStream<S>) {
    let _ = ws
        .send(Message::binary(vec![1u8; WS_MESSAGE_MAX_BYTES + 1]))
        .await;
    let res = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
    println!("== server cap (client sends 65537): {res:?}");
}

// ------------------------------------------------------------------- local

async fn local() {
    let host = "spike.invalid";
    let pki = test_pki(&[host]);
    let sni = Arc::new(Mutex::new(Vec::new()));
    let tls = acceptor(&pki, sni.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (tcp, peer) = listener.accept().await.unwrap();
            let tls = tls.clone();
            tokio::spawn(async move {
                match tls.accept(tcp).await {
                    Ok(s) => serve_ws(s, peer.to_string(), false).await,
                    Err(e) => println!("[server] tls accept failed: {e}"),
                }
            });
        }
    });

    let fixed: HashMap<String, IpAddr> = [(host.to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST))]
        .into_iter()
        .collect();
    let path = "/x/mousse-net/1";

    // Negative control: the platform verifier alone does not trust the test root.
    let addrs = resolve_once(host, port, &fixed).await.unwrap();
    match dial_wss(host, port, path, addrs[0], platform_verifier(None)).await {
        Ok(_) => println!("== control, no extra root: FAIL (connected)"),
        Err(e) => println!("== control, no extra root: PASS (refused: {e})"),
    }
    // A system lookup of the same name fails, so a second lookup anywhere
    // below would have broken the dial.
    match tokio::net::lookup_host((host, port)).await {
        Ok(a) => println!(
            "== system lookup of {host}: resolved {:?} (unexpected)",
            a.collect::<Vec<_>>()
        ),
        Err(e) => println!("== system lookup of {host}: fails ({e})"),
    }

    RESOLVES.store(0, Ordering::SeqCst);
    let addrs = resolve_once(host, port, &fixed).await.unwrap();
    let addr = addrs[0];
    println!(
        "== resolved {host} once -> {addr} class={} (loopback: debug builds only)",
        classify(addr.ip())
    );
    let mut d = dial_wss(
        host,
        port,
        path,
        addr,
        platform_verifier(Some(pki.root.clone())),
    )
    .await
    .expect("dial");
    println!(
        "== dial: PASS tcp={}ms tls={}ms upgrade={}ms subprotocol={:?} sni_seen_by_server={:?}",
        d.tcp_ms,
        d.tls_ms,
        d.upgrade_ms,
        d.protocol,
        sni.lock().unwrap()
    );
    exercise(&mut d.ws).await;
    let d2 = dial_wss(
        host,
        port,
        path,
        addr,
        platform_verifier(Some(pki.root.clone())),
    )
    .await
    .expect("dial");
    over_cap_from_client(d2.ws).await;
    println!(
        "== name lookups during the run: {} (one per try; the two dials above reused the address)",
        RESOLVES.load(Ordering::SeqCst)
    );

    // Upgrade checks.
    for (label, path, origin, proto) in [
        ("wrong path", "/x/other", false, true),
        ("Origin present", path, true, true),
        ("no mousse.1", path, false, false),
    ] {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let tls = connector(platform_verifier(Some(pki.root.clone())))
            .connect(ServerName::try_from(host.to_string()).unwrap(), tcp)
            .await
            .unwrap();
        let mut req = format!("wss://{host}:{port}{path}")
            .into_client_request()
            .unwrap();
        if origin {
            req.headers_mut()
                .insert("origin", HeaderValue::from_static("https://evil.example"));
        }
        if proto {
            req.headers_mut().insert(
                "sec-websocket-protocol",
                HeaderValue::from_static(SUBPROTOCOL),
            );
        }
        match tokio_tungstenite::client_async(req, tls).await {
            Ok(_) => println!("== upgrade check, {label}: FAIL (accepted)"),
            Err(e) => println!("== upgrade check, {label}: refused ({e})"),
        }
    }
}

// ------------------------------------------------------------------ search

#[derive(Clone, Copy, Debug)]
enum Kind {
    Refused,
    Silent,
    Live,
}

async fn try_one(
    addr: SocketAddr,
    verifier: Arc<dyn ServerCertVerifier>,
    limit: Duration,
) -> Result<(), String> {
    let fut = async {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("tcp: {e}"))?;
        connector(verifier)
            .connect(ServerName::try_from("spike.invalid").unwrap(), tcp)
            .await
            .map_err(|e| format!("tls: {e}"))?;
        Ok::<(), String>(())
    };
    match tokio::time::timeout(limit, fut).await {
        Ok(r) => r,
        Err(_) => Err("timeout".into()),
    }
}

/// 1a's race: `parallel` tries at once, in order, the first to pass wins.
async fn search(
    cands: &[(Kind, SocketAddr)],
    parallel: usize,
    limit: Duration,
    verifier: Arc<dyn ServerCertVerifier>,
) -> (Option<usize>, u128, Vec<(usize, Kind, String, u128)>) {
    let start = Instant::now();
    let mut set = JoinSet::new();
    let mut next = 0;
    let mut log = Vec::new();
    let spawn = |set: &mut JoinSet<_>, i: usize| {
        let (kind, addr) = cands[i];
        let v = verifier.clone();
        set.spawn(async move {
            let t = Instant::now();
            let r = try_one(addr, v, limit).await;
            (i, kind, r, t.elapsed().as_millis())
        });
    };
    while next < cands.len().min(parallel) {
        spawn(&mut set, next);
        next += 1;
    }
    while let Some(res) = set.join_next().await {
        let (i, kind, r, ms) = res.unwrap();
        log.push((i, kind, r.clone().err().unwrap_or_else(|| "ok".into()), ms));
        if r.is_ok() {
            set.abort_all();
            return (Some(i), start.elapsed().as_millis(), log);
        }
        if next < cands.len() {
            spawn(&mut set, next);
            next += 1;
        }
    }
    (None, start.elapsed().as_millis(), log)
}

async fn search_main() {
    let parallel: usize = std::env::var("DIAL_PARALLEL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    let limit = env_ms("DIAL_TIMEOUT_MS", 2000);
    let pki = test_pki(&["spike.invalid"]);
    let verifier = platform_verifier(Some(pki.root.clone()));

    // One refused connect, timed alone.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let t = Instant::now();
    let r = TcpStream::connect(closed).await;
    println!(
        "== one connect to a closed loopback port: {} in {} ms",
        r.err()
            .map(|e| e.to_string())
            .unwrap_or("connected?".into()),
        t.elapsed().as_millis()
    );

    let mut keep = Vec::new();
    let mut silent = Vec::new();
    for _ in 0..17 {
        // Accepts the TCP connection (the kernel does), never answers TLS.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        silent.push(l.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = l.accept().await {
                held.push(s);
            }
        });
    }
    let mut refused = Vec::new();
    for _ in 0..17 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        refused.push(l.local_addr().unwrap());
    }
    let live = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let tls = acceptor(&pki, Arc::new(Mutex::new(Vec::new())));
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let tls = tls.clone();
                tokio::spawn(async move {
                    if let Ok(s) = tls.accept(s).await {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        drop(s);
                    }
                });
            }
        });
        addr
    };
    keep.push(live);

    let mixed = |n: usize| -> Vec<(Kind, SocketAddr)> {
        (0..n)
            .map(|i| {
                if i % 2 == 0 {
                    (Kind::Refused, refused[i])
                } else {
                    (Kind::Silent, silent[i])
                }
            })
            .collect()
    };
    let scenarios: Vec<(&str, Vec<(Kind, SocketAddr)>)> = vec![
        ("16 dead, mixed refused/silent", mixed(16)),
        ("15 dead + live 16th (the cap)", {
            let mut v = mixed(15);
            v.push((Kind::Live, live));
            v
        }),
        ("16 dead + live 17th (over the cap)", {
            let mut v = mixed(16);
            v.push((Kind::Live, live));
            v
        }),
        (
            "16 refused",
            refused[..16].iter().map(|a| (Kind::Refused, *a)).collect(),
        ),
        (
            "16 silent",
            silent[..16].iter().map(|a| (Kind::Silent, *a)).collect(),
        ),
    ];
    println!(
        "DIAL_PARALLEL={parallel} DIAL_TIMEOUT_MS={}",
        limit.as_millis()
    );
    for (name, cands) in scenarios {
        let (winner, total, log) = search(&cands, parallel, limit, verifier.clone()).await;
        let refused_ms: Vec<u128> = log
            .iter()
            .filter(|l| matches!(l.1, Kind::Refused))
            .map(|l| l.3)
            .collect();
        let silent_ms: Vec<u128> = log
            .iter()
            .filter(|l| matches!(l.1, Kind::Silent))
            .map(|l| l.3)
            .collect();
        println!(
            "== search [{name}]: winner={winner:?} total={total} ms; refused tries ms={refused_ms:?}; silent tries ms={silent_ms:?}"
        );
        let reasons: std::collections::BTreeSet<String> = log.iter().map(|l| l.2.clone()).collect();
        println!("   outcomes: {reasons:?}");
    }
}

// ---------------------------------------------------- ws-echo and dial-wss

async fn ws_echo(listen: &str, secs: u64) {
    let listener = TcpListener::bind(listen).await.unwrap();
    println!("ws-echo listening {}", listener.local_addr().unwrap());
    let serve = async {
        loop {
            let (tcp, peer) = listener.accept().await.unwrap();
            tokio::spawn(serve_ws(tcp, peer.to_string(), true));
        }
    };
    tokio::select! {
        _ = serve => {}
        _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
    }
}

async fn dial_url(url: &str) {
    let rest = url.strip_prefix("wss://").expect("wss:// URL");
    let (hostport, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap()),
        None => (hostport.to_string(), 443u16),
    };
    RESOLVES.store(0, Ordering::SeqCst);
    let t = Instant::now();
    let addrs = resolve_once(&host, port, &HashMap::new())
        .await
        .expect("resolve");
    println!("== resolved {host} once in {} ms:", t.elapsed().as_millis());
    for a in &addrs {
        println!("     {a} class={}", classify(a.ip()));
    }
    let Some(addr) = addrs
        .iter()
        .find(|a| a.is_ipv4() && classify(a.ip()) == "public")
        .or_else(|| addrs.iter().find(|a| classify(a.ip()) == "public"))
        .copied()
    else {
        println!("== no public address");
        return;
    };
    let t = Instant::now();
    match dial_wss(&host, port, path, addr, platform_verifier(None)).await {
        Ok(mut d) => {
            println!(
                "== dial {addr}: PASS tcp={}ms tls={}ms upgrade={}ms subprotocol={:?} (total {} ms)",
                d.tcp_ms,
                d.tls_ms,
                d.upgrade_ms,
                d.protocol,
                t.elapsed().as_millis()
            );
            exercise(&mut d.ws).await;
            if let Ok(d2) = dial_wss(&host, port, path, addr, platform_verifier(None)).await {
                over_cap_from_client(d2.ws).await;
            }
        }
        Err(e) => println!("== dial {addr}: FAIL {e}"),
    }
    println!("== name lookups: {}", RESOLVES.load(Ordering::SeqCst));
    let _ = Ipv6Addr::LOCALHOST;
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("local") => local().await,
        Some("search") => search_main().await,
        Some("ws-echo") => {
            let secs = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(900);
            ws_echo(args.get(1).expect("ADDR"), secs).await
        }
        Some("dial-wss") => dial_url(args.get(1).expect("URL")).await,
        _ => {
            eprintln!("usage: route-policy local | search | ws-echo ADDR [SECS] | dial-wss URL");
            std::process::exit(64);
        }
    }
}
