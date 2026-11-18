//! Spike 3: the phone byte path. A WebSocket server on 127.0.0.1, run by the
//! engine's runtime, that only accepts an upgrade when:
//! - `Host` is exactly `127.0.0.1:<port>` (DNS rebinding can't reach it),
//! - `Origin` is exactly the app's own WebView origin,
//! - the path is `/bytes` and the `t` query parameter equals the per-launch token.
//!
//! Everything else gets 403 before any WebSocket traffic. The app's web page
//! (`web/bytepath.html`) pushes terminal-like and file-like traffic through it and
//! posts its measurements back over the same socket.
//!
//! Protocol (text frames are control, binary frames are file bytes):
//! - `e:<text>`: echoed back unchanged (terminal-like small writes).
//! - `upload:<n>`, then n bytes of the shared pattern; the server verifies every
//!   byte and answers `upload-ok:<n>:<1|0>:<server microseconds>`.
//! - `download:<n>`: the server sends n pattern bytes in 64 KiB frames, then
//!   `download-done:<n>`.
//! - `report:<json>`: the page's measurements; ends the run.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_util::sync::CancellationToken;

use crate::engine::{AbortOnDrop, Emitter, Engine, EventKind, NetError, SocketGuard, pattern_byte};
use crate::report::Report;

const FRAME: usize = 64 * 1024;
/// Budgets a phone has to meet, set before measuring. Terminal echo within one
/// 60 Hz frame; file bytes no slower than a fast relay link (80 Mbit/s).
const BUDGET_TERMINAL_P95_MS: f64 = 16.0;
const BUDGET_FILE_MBPS: f64 = 10.0;

#[derive(Debug, Clone, uniffi::Record)]
pub struct BytePathConfig {
    /// The only Origin accepted, e.g. `mousse-app://localhost` or `https://localhost`.
    pub allowed_origin: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct BytePathInfo {
    pub port: u16,
    /// Per-launch token, 32 random bytes as hex.
    pub token: String,
    /// `ws://127.0.0.1:<port>/bytes`; the page adds `?t=<token>`.
    pub url: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ProbeResult {
    pub case_name: String,
    /// HTTP status of the upgrade answer; 0 if the server closed without one.
    pub status: u16,
    pub expect_accept: bool,
    pub ok: bool,
}

pub(crate) struct Server {
    port: u16,
    token: String,
    origin: String,
    check_token: bool,
    accepted: AtomicU64,
    refusals: Mutex<Vec<String>>,
    uploads_verified: AtomicU64,
    upload_failures: AtomicU64,
    report: watch::Sender<Option<String>>,
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn query_param<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    query?.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then_some(v)
    })
}

impl Server {
    fn check(&self, req: &Request) -> Result<(), &'static str> {
        let header = |name: &str| req.headers().get(name).and_then(|v| v.to_str().ok());
        let host = header("host").ok_or("missing host")?;
        if host != format!("127.0.0.1:{}", self.port) {
            return Err("bad host");
        }
        let origin = header("origin").ok_or("missing origin")?;
        if origin != self.origin {
            return Err("bad origin");
        }
        if req.uri().path() != "/bytes" {
            return Err("bad path");
        }
        if self.check_token {
            let tok = query_param(req.uri().query(), "t").ok_or("missing token")?;
            if !ct_eq(tok.as_bytes(), self.token.as_bytes()) {
                return Err("bad token");
            }
        }
        Ok(())
    }

    fn refuse(&self, why: &str) {
        let mut r = self.refusals.lock().unwrap_or_else(|p| p.into_inner());
        if r.len() < 64 {
            r.push(why.to_string());
        }
    }
}

fn random_token() -> Result<String, NetError> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| NetError::Io { msg: e.to_string() })?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

// The handshake callback's error type is tungstenite's HTTP response.
#[allow(clippy::result_large_err)]
async fn session(
    stream: TcpStream,
    srv: Arc<Server>,
    em: Emitter,
    conn: u64,
) -> Result<(), NetError> {
    let s2 = srv.clone();
    let mut refused: Option<&'static str> = None;
    let cb = |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        match s2.check(req) {
            Ok(()) => Ok(resp),
            Err(why) => {
                refused = Some(why);
                let mut e = ErrorResponse::new(Some(why.to_string()));
                *e.status_mut() = StatusCode::FORBIDDEN;
                Err(e)
            }
        }
    };
    let ws = tokio_tungstenite::accept_hdr_async(stream, cb).await;
    let mut ws = match ws {
        Ok(ws) => ws,
        Err(e) => {
            let why = refused.unwrap_or("bad handshake");
            srv.refuse(why);
            em.emit(EventKind::ByteClientRefused, conn, why);
            return Err(NetError::Protocol { msg: e.to_string() });
        }
    };
    srv.accepted.fetch_add(1, Ordering::SeqCst);
    em.emit(EventKind::ByteClientOpen, conn, "");

    // (total, received, all bytes matched, started)
    let mut upload: Option<(u64, u64, bool, Instant)> = None;
    while let Some(msg) = ws.next().await {
        let msg = msg.map_err(|e| NetError::Io { msg: e.to_string() })?;
        match msg {
            Message::Text(t) => {
                let t = t.as_str();
                if t.starts_with("e:") {
                    ws.send(Message::text(t)).await.map_err(io)?;
                } else if let Some(n) = t.strip_prefix("upload:") {
                    let n: u64 = n.parse().map_err(|_| proto("bad upload length"))?;
                    upload = Some((n, 0, true, Instant::now()));
                } else if let Some(n) = t.strip_prefix("download:") {
                    let n: u64 = n.parse().map_err(|_| proto("bad download length"))?;
                    let mut off = 0u64;
                    while off < n {
                        let len = ((n - off) as usize).min(FRAME);
                        let chunk: Vec<u8> =
                            (0..len as u64).map(|i| pattern_byte(off + i)).collect();
                        ws.feed(Message::binary(chunk)).await.map_err(io)?;
                        off += len as u64;
                    }
                    ws.flush().await.map_err(io)?;
                    ws.send(Message::text(format!("download-done:{n}")))
                        .await
                        .map_err(io)?;
                } else if let Some(j) = t.strip_prefix("report:") {
                    srv.report.send_replace(Some(j.to_string()));
                }
            }
            Message::Binary(b) => {
                let Some((total, got, ok, started)) = upload.as_mut() else {
                    return Err(proto("binary frame outside an upload"));
                };
                if *ok {
                    *ok = b
                        .iter()
                        .enumerate()
                        .all(|(i, x)| *x == pattern_byte(*got + i as u64));
                }
                *got += b.len() as u64;
                if *got >= *total {
                    let good = *ok && *got == *total;
                    if good {
                        srv.uploads_verified.fetch_add(1, Ordering::SeqCst);
                    } else {
                        srv.upload_failures.fetch_add(1, Ordering::SeqCst);
                    }
                    let us = started.elapsed().as_micros();
                    let reply = format!("upload-ok:{got}:{}:{us}", u8::from(good));
                    upload = None;
                    ws.send(Message::text(reply)).await.map_err(io)?;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    em.emit(EventKind::ByteClientClosed, conn, "");
    Ok(())
}

fn io(e: impl std::fmt::Display) -> NetError {
    NetError::Io { msg: e.to_string() }
}

fn proto(msg: &str) -> NetError {
    NetError::Protocol {
        msg: msg.to_string(),
    }
}

/// Sends a hand-written upgrade request and returns the status code of the answer.
async fn probe(port: u16, host: Option<&str>, origin: Option<&str>, query: &str) -> u16 {
    let attempt = async {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        let mut req = format!("GET /bytes{query} HTTP/1.1\r\n");
        if let Some(h) = host {
            req.push_str(&format!("Host: {h}\r\n"));
        }
        if let Some(o) = origin {
            req.push_str(&format!("Origin: {o}\r\n"));
        }
        req.push_str(
            "Upgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        );
        s.write_all(req.as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 8192 {
            let n = s.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let text = String::from_utf8_lossy(&buf);
        text.split_whitespace().nth(1)?.parse::<u16>().ok()
    };
    tokio::time::timeout(Duration::from_secs(3), attempt)
        .await
        .ok()
        .flatten()
        .unwrap_or(0)
}

fn num(v: &serde_json::Value, path: &[&str]) -> Option<f64> {
    let mut cur = v;
    for p in path {
        cur = cur.get(p)?;
    }
    cur.as_f64()
}

fn flag(v: &serde_json::Value, path: &[&str]) -> bool {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(x) => cur = x,
            None => return false,
        }
    }
    cur.as_bool().unwrap_or(false)
}

#[uniffi::export]
impl Engine {
    /// Starts the loopback WebSocket server with a fresh token.
    pub fn start_byte_path(&self, config: BytePathConfig) -> Result<BytePathInfo, NetError> {
        let check_token = !self.breaks("token");
        let shared = self.shared.clone();
        self.with_running(|run| {
            if run.byte_path.is_some() {
                return Err(NetError::AlreadyRunning);
            }
            let std_l = std::net::TcpListener::bind("127.0.0.1:0")?;
            std_l.set_nonblocking(true)?;
            let port = std_l.local_addr()?.port();
            let token = random_token()?;
            let (report, _) = watch::channel(None);
            let srv = Arc::new(Server {
                port,
                token: token.clone(),
                origin: config.allowed_origin.clone(),
                check_token,
                accepted: AtomicU64::new(0),
                refusals: Mutex::new(Vec::new()),
                uploads_verified: AtomicU64::new(0),
                upload_failures: AtomicU64::new(0),
                report,
            });
            run.byte_path = Some(srv.clone());
            let _enter = run.handle().enter();
            let listener = TcpListener::from_std(std_l)?;
            let root: CancellationToken = run.root.clone();
            let em = run.emitter.clone();
            run.handle().spawn(async move {
                let _sock = SocketGuard::new(&shared);
                let mut conn = 0u64;
                loop {
                    let accepted = tokio::select! {
                        _ = root.cancelled() => break,
                        a = listener.accept() => a,
                    };
                    let Ok((s, _)) = accepted else { continue };
                    let _ = s.set_nodelay(true);
                    conn += 1;
                    let guard = SocketGuard::new(&shared);
                    let (srv, em, root) = (srv.clone(), em.clone(), root.clone());
                    tokio::spawn(async move {
                        let _guard = guard;
                        tokio::select! {
                            _ = root.cancelled() => {}
                            _ = session(s, srv, em, conn) => {}
                        }
                    });
                }
            });
            Ok(BytePathInfo {
                port,
                token,
                url: format!("ws://127.0.0.1:{port}/bytes"),
            })
        })
    }

    /// Sends hand-written upgrade requests from inside the app: one valid (must be
    /// accepted, so the probes can tell refusal from breakage) and every refusal case.
    pub async fn probe_byte_path(&self) -> Result<Vec<ProbeResult>, NetError> {
        let (srv, handle) = self.with_running(|run| {
            let srv = run.byte_path.clone().ok_or(NetError::NotRunning)?;
            Ok((srv, run.handle()))
        })?;
        let task = handle.spawn(async move {
            let p = srv.port;
            let host = format!("127.0.0.1:{p}");
            let tok = format!("?t={}", srv.token);
            let wrong_tok = format!("?t={}", "0".repeat(64));
            let o = srv.origin.as_str();
            // (name, Host, Origin, query, must be accepted)
            type Case<'a> = (&'a str, Option<String>, Option<&'a str>, String, bool);
            let cases: Vec<Case> = vec![
                ("valid", Some(host.clone()), Some(o), tok.clone(), true),
                ("wrong-token", Some(host.clone()), Some(o), wrong_tok, false),
                (
                    "missing-token",
                    Some(host.clone()),
                    Some(o),
                    String::new(),
                    false,
                ),
                (
                    "wrong-host",
                    Some(format!("evil.example:{p}")),
                    Some(o),
                    tok.clone(),
                    false,
                ),
                (
                    "localhost-host",
                    Some(format!("localhost:{p}")),
                    Some(o),
                    tok.clone(),
                    false,
                ),
                ("missing-host", None, Some(o), tok.clone(), false),
                (
                    "wrong-origin",
                    Some(host.clone()),
                    Some("https://evil.example"),
                    tok.clone(),
                    false,
                ),
                (
                    "null-origin",
                    Some(host.clone()),
                    Some("null"),
                    tok.clone(),
                    false,
                ),
                (
                    "missing-origin",
                    Some(host.clone()),
                    None,
                    tok.clone(),
                    false,
                ),
            ];
            let mut out = Vec::new();
            for (name, h, origin, q, accept) in cases {
                let status = probe(p, h.as_deref(), origin, &q).await;
                let ok = if accept { status == 101 } else { status != 101 };
                out.push(ProbeResult {
                    case_name: name.into(),
                    status,
                    expect_accept: accept,
                    ok,
                });
            }
            out
        });
        AbortOnDrop(Some(task)).join().await
    }

    /// Waits for the page's report, runs the probes, and records every byte-path
    /// step (and the budgets) into `report`.
    pub async fn finish_byte_path(
        &self,
        report: Arc<Report>,
        timeout_ms: u32,
    ) -> Result<(), NetError> {
        let (srv, handle) = self.with_running(|run| {
            let srv = run.byte_path.clone().ok_or(NetError::NotRunning)?;
            Ok((srv, run.handle()))
        })?;
        let mut rx = srv.report.subscribe();
        let wait = Duration::from_millis(timeout_ms as u64);
        let task = handle.spawn(async move {
            match tokio::time::timeout(wait, rx.wait_for(|r| r.is_some())).await {
                Ok(Ok(r)) => r.clone(),
                _ => None,
            }
        });
        let page = AbortOnDrop(Some(task)).join().await?;
        let probes = self.probe_byte_path().await?;

        let r = &report;
        let page: Option<serde_json::Value> = page.and_then(|p| serde_json::from_str(&p).ok());
        r.step("page-report".into(), page.is_some(), None, String::new());
        let page = page.unwrap_or(serde_json::Value::Null);
        if page.is_object() {
            let errors = page.get("errors").cloned().unwrap_or_default();
            r.step(
                "page-no-errors".into(),
                errors.as_array().is_some_and(|a| a.is_empty()),
                None,
                errors.to_string(),
            );
            r.step(
                "page-wrong-token-refused".into(),
                flag(&page, &["wrongTokenRefused"]),
                None,
                String::new(),
            );
            let n = num(&page, &["echo", "n"]).unwrap_or(0.0);
            let ok_n = num(&page, &["echo", "ok"]).unwrap_or(-1.0);
            let p95 = num(&page, &["echo", "p95Ms"]);
            r.step(
                "terminal-echo".into(),
                n > 0.0 && n == ok_n,
                p95,
                String::new(),
            );
            r.step(
                "terminal-burst".into(),
                flag(&page, &["burst", "ok"]),
                num(&page, &["burst", "ms"]),
                String::new(),
            );
            let up = num(&page, &["upload", "mbps"]);
            let down = num(&page, &["download", "mbps"]);
            r.step(
                "file-upload".into(),
                flag(&page, &["upload", "ok"]),
                up,
                String::new(),
            );
            r.step(
                "file-download".into(),
                flag(&page, &["download", "ok"]),
                down,
                String::new(),
            );
            r.step(
                "budget-terminal-p95".into(),
                p95.is_some_and(|v| v <= BUDGET_TERMINAL_P95_MS),
                p95,
                format!("<= {BUDGET_TERMINAL_P95_MS} ms"),
            );
            let slowest = up.zip(down).map(|(a, b)| a.min(b));
            r.step(
                "budget-file-throughput".into(),
                slowest.is_some_and(|v| v >= BUDGET_FILE_MBPS),
                slowest,
                format!(">= {BUDGET_FILE_MBPS} MB/s"),
            );
        }
        let verified = srv.uploads_verified.load(Ordering::SeqCst);
        let failed = srv.upload_failures.load(Ordering::SeqCst);
        r.step(
            "server-verified-upload".into(),
            verified >= 1 && failed == 0,
            None,
            format!("{verified} ok, {failed} bad"),
        );
        let refusals = srv
            .refusals
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        r.step(
            "server-refused-page-wrong-token".into(),
            refusals.iter().any(|w| w == "bad token"),
            None,
            String::new(),
        );
        for p in &probes {
            r.step(
                format!("probe-{}", p.case_name),
                p.ok,
                None,
                format!("status {}", p.status),
            );
        }
        let probes_json: Vec<serde_json::Value> = probes
            .iter()
            .map(|p| serde_json::json!({"case": p.case_name, "status": p.status, "expectAccept": p.expect_accept, "ok": p.ok}))
            .collect();
        r.detail_value("page", page);
        r.detail_value("probes", serde_json::Value::Array(probes_json));
        r.detail_value(
            "server",
            serde_json::json!({
                "acceptedConnections": srv.accepted.load(Ordering::SeqCst),
                "refusals": refusals,
                "tokenCheck": srv.check_token,
                "allowedOrigin": srv.origin,
            }),
        );
        r.detail_value(
            "budgets",
            serde_json::json!({
                "terminalP95Ms": BUDGET_TERMINAL_P95_MS,
                "fileMBps": BUDGET_FILE_MBPS,
            }),
        );
        Ok(())
    }
}
