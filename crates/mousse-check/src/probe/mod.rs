//! `mousse-check probe`: traffic that must never reach RPC, sent to a real
//! host on one route (Phase 1b §6.3).
//!
//! Each case has two assertions. **Wire:** the probe records how the host
//! ended the case; a missing or different close fails with
//! `wire_accepted`. **App:** the counters an observer reports (see
//! [`observe`]) must change only as the case allows; anything else fails
//! with `probe_reached_app`, even when the wire looked right. When a run
//! fails both ways, `probe_reached_app` is the reason it reports.
//!
//! Output: one line per case (`PASS <marker> <case>` or `FAIL <marker>
//! <case> reason=<word> ...`), then `PASS <marker>` or `FAIL <marker>
//! reason=<word>`. `--json <file>` writes the same as JSON.

pub mod observe;
pub mod session;
pub mod tunnel;
pub mod ws;

use std::path::PathBuf;
use std::time::Duration;

use mousse_net_core::identity::{IdentityPublicKey, SoftwareKey};
use mousse_net_core::pairing::{InvitationKind, Ticket};
use mousse_net_io::store::{hex, identity_from_hex, unhex};
use serde_json::json;

use self::observe::{AppExpect, Counts, Observer};
use self::session::{Device, Raw, Target, TlsMode};

/// Every case, in the order they run. The silent and the flood cases come
/// last, so a slow host shows up after the quick answers.
pub const CASES: [&str; 21] = [
    "not-tls",
    "ws-plain-get",
    "ws-wrong-path",
    "ws-origin",
    "ws-no-subprotocol",
    "ws-large-headers",
    "ws-text-message",
    "tls-no-cert",
    "tls-1.2",
    "tls-wrong-alpn",
    "fresh-open-rpc",
    "fresh-open-tunnel",
    "fresh-bad-proof",
    "join-only-open-rpc",
    "join-only-open-hello",
    "join-only-open-tunnel",
    "join-only-garbage-code",
    "removed-open-rpc",
    "editor-off-tunnel",
    "fresh-silence",
    "admission",
];

/// Cases only the ws route has. `ws-slow-headers` is in the list too, run
/// after `admission`.
fn ws_only(case: &str) -> bool {
    case.starts_with("ws-")
}

/// The full list for a route.
pub fn cases_for(target: &Target) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = CASES
        .iter()
        .copied()
        .filter(|c| matches!(target, Target::Ws { .. }) || !ws_only(c))
        .collect();
    if matches!(target, Target::Ws { .. }) {
        out.push("ws-slow-headers");
    }
    out
}

fn known(case: &str) -> bool {
    CASES.contains(&case) || case == "ws-slow-headers"
}

/// The probe's waits and the host limits it tests. Engine limits are read
/// from the same `MOUSSE_NET_*` variables the host reads, so a check that
/// tightens one for the host tightens it for the probe too. The probe's own
/// waits are `MOUSSE_CHECK_PROBE_*`.
#[derive(Clone, Debug)]
pub struct Waits {
    /// `MOUSSE_CHECK_PROBE_CONNECT_MS` (5000): one TCP connect.
    pub connect: Duration,
    /// `MOUSSE_CHECK_PROBE_CLOSE_MS` (5000): how long the host has to
    /// answer or close once it should.
    pub close: Duration,
    /// `MOUSSE_CHECK_PROBE_SETTLE_MS` (1000): after a case ends, before the
    /// app's counters are read again.
    pub settle: Duration,
    /// `MOUSSE_NET_JOIN_PROOF_WAIT_MS` (10000).
    pub proof_wait: Duration,
    /// `MOUSSE_NET_WS_UPGRADE_WAIT_MS` (5000).
    pub upgrade_wait: Duration,
    /// `MOUSSE_NET_WS_HEADER_MAX_BYTES` (8192).
    pub header_max: usize,
    /// `MOUSSE_NET_PREAUTH_TCP` (48).
    pub preauth_tcp: usize,
    /// `MOUSSE_NET_PREAUTH_WS` (16).
    pub preauth_ws: usize,
    /// `MOUSSE_NET_PREAUTH_PER_SOURCE` (8).
    pub preauth_per_source: usize,
}

impl Waits {
    pub fn from_env() -> Result<Self, String> {
        Self::from_vars(|k| std::env::var(k).ok())
    }

    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let num = |name: &str, default: u64| -> Result<u64, String> {
            match get(name) {
                None => Ok(default),
                Some(v) => v
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| format!("{name}={v:?} is not a positive whole number")),
            }
        };
        let ms = |name: &str, default: u64| num(name, default).map(Duration::from_millis);
        Ok(Self {
            connect: ms("MOUSSE_CHECK_PROBE_CONNECT_MS", 5_000)?,
            close: ms("MOUSSE_CHECK_PROBE_CLOSE_MS", 5_000)?,
            settle: ms("MOUSSE_CHECK_PROBE_SETTLE_MS", 1_000)?,
            proof_wait: ms("MOUSSE_NET_JOIN_PROOF_WAIT_MS", 10_000)?,
            upgrade_wait: ms("MOUSSE_NET_WS_UPGRADE_WAIT_MS", 5_000)?,
            header_max: num("MOUSSE_NET_WS_HEADER_MAX_BYTES", 8_192)? as usize,
            preauth_tcp: num("MOUSSE_NET_PREAUTH_TCP", 48)? as usize,
            preauth_ws: num("MOUSSE_NET_PREAUTH_WS", 16)? as usize,
            preauth_per_source: num("MOUSSE_NET_PREAUTH_PER_SOURCE", 8)? as usize,
        })
    }

    /// How soon a refusal must come to count as an answer to what the
    /// probe sent, not the proof wait running out: half the proof wait.
    pub fn prompt(&self) -> Duration {
        self.proof_wait / 2
    }

    /// Silent connections the host keeps on this route before it refuses
    /// one: all of the probe's come from one loopback address.
    pub fn preauth_cap(&self, target: &Target) -> usize {
        match target {
            Target::Tcp(_) => self.preauth_tcp.min(self.preauth_per_source),
            Target::Ws { .. } => self.preauth_ws,
        }
    }
}

/// What the probe was asked to do.
pub struct Plan {
    pub target: Target,
    pub pin: Option<IdentityPublicKey>,
    pub ticket: Option<Ticket>,
    pub granted_editor_off: Option<SoftwareKey>,
    pub removed: Option<SoftwareKey>,
    pub observer: Option<Observer>,
    pub cases: Vec<&'static str>,
    pub marker: String,
    pub json: Option<PathBuf>,
    pub waits: Waits,
}

/// One case's result.
#[derive(Clone, Debug)]
pub struct CaseResult {
    pub case: &'static str,
    pub want: String,
    pub got: String,
    pub app: Option<Result<String, String>>,
    pub error: Option<String>,
}

impl CaseResult {
    /// The reason it failed, if it did. The app's record wins over the wire.
    pub fn reason(&self) -> Option<&'static str> {
        if let Some(Err(_)) = &self.app {
            return Some("probe_reached_app");
        }
        if self.error.is_some() {
            return Some("probe_error");
        }
        (self.got != self.want).then_some("wire_accepted")
    }
}

/// The run's reason: `probe_reached_app` over `wire_accepted` over
/// `probe_error`.
pub fn verdict(results: &[CaseResult]) -> Option<&'static str> {
    let reasons: Vec<&str> = results.iter().filter_map(CaseResult::reason).collect();
    ["probe_reached_app", "wire_accepted", "probe_error"]
        .into_iter()
        .find(|r| reasons.contains(r))
}

const HELP: &str = "\
mousse-check probe --route <hint> [--invite <ticket>] [--pin <identity hex>]
                   [--grant-key <file>] [--removed-key <file>]
                   (--observe <url> | --no-app) [--cases <a,b,...>]
                   [--marker <id>] [--json <file>]
  Sends Phase 1b §6.3's cases to a host on one route and checks each close
  on the wire and, through the observer, in the app.
  --route       tcp://<ip>:<port> or ws://<loopback ip>:<port>/<path>
  --invite      an open invitation's ticket (fragment, or a link ending in
                #<fragment>); its host identity is the pin unless --pin says
  --grant-key   key of a granted device whose editor is off
  --removed-key key of a device whose grant was removed
  --observe     http://<loopback>:<port>/<path> answering the app's counters
  --no-app      wire only (build smoke); no app assertions
mousse-check probe key <file>
  Writes a fresh throwaway device key to <file> and prints its identity
  (hex), for grant.add.
";

/// `mousse-check probe ...`. Returns the process exit code.
pub fn main(args: &[String]) -> Result<u8, String> {
    if args.first().map(String::as_str) == Some("key") {
        let path = args.get(1).ok_or("probe key needs a file")?;
        println!("{}", new_key(&PathBuf::from(path))?);
        return Ok(0);
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{HELP}");
        return Ok(0);
    }
    let plan = parse(args)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let results = rt.block_on(run(&plan))?;
    Ok(report(&plan, &results))
}

fn parse(args: &[String]) -> Result<Plan, String> {
    let mut route = None;
    let mut invite = None;
    let mut pin = None;
    let mut grant = None;
    let mut removed = None;
    let mut observe = None;
    let mut no_app = false;
    let mut cases = None;
    let mut marker = "probe".to_owned();
    let mut json_out = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{a} needs a value"))
        };
        match a.as_str() {
            "--route" => route = Some(value()?),
            "--invite" => invite = Some(value()?),
            "--pin" => pin = Some(value()?),
            "--grant-key" => grant = Some(value()?),
            "--removed-key" => removed = Some(value()?),
            "--observe" => observe = Some(value()?),
            "--no-app" => no_app = true,
            "--cases" => cases = Some(value()?),
            "--marker" => marker = value()?,
            "--json" => json_out = Some(PathBuf::from(value()?)),
            other => return Err(format!("probe: unknown option {other} (see probe --help)")),
        }
    }
    let target = Target::parse(&route.ok_or("probe needs --route")?)?;
    let ticket = invite
        .map(|t| {
            let fragment = t.rsplit('#').next().unwrap_or(&t).to_owned();
            Ticket::from_fragment(fragment.trim()).map_err(|e| format!("--invite: {e:?}"))
        })
        .transpose()?;
    let pin = match pin {
        Some(p) => Some(identity_from_hex(&p).map_err(|e| format!("--pin: {e}"))?),
        None => ticket.as_ref().map(|t| t.host_identity),
    };
    let observer = match (observe, no_app) {
        (Some(_), true) => return Err("probe: --observe and --no-app together".into()),
        (Some(url), false) => Some(Observer::parse(&url)?),
        (None, true) => None,
        (None, false) => {
            return Err("probe needs --observe <url> (or --no-app for wire-only checks)".into())
        }
    };
    let all = cases_for(&target);
    let cases = match cases {
        None => all,
        Some(list) => {
            let mut out = Vec::new();
            for c in list.split(',').map(str::trim).filter(|c| !c.is_empty()) {
                let found = all.iter().copied().find(|k| *k == c).ok_or_else(|| {
                    if known(c) {
                        format!("probe: case {c} is not on the {} route", target.kind())
                    } else {
                        format!("probe: no case {c}")
                    }
                })?;
                out.push(found);
            }
            out
        }
    };
    Ok(Plan {
        target,
        pin,
        ticket,
        granted_editor_off: grant.map(|p| load_key(&p)).transpose()?,
        removed: removed.map(|p| load_key(&p)).transpose()?,
        observer,
        cases,
        marker,
        json: json_out,
        waits: Waits::from_env()?,
    })
}

fn new_key(path: &PathBuf) -> Result<String, String> {
    let key = SoftwareKey::generate(&mut mousse_net_io::rng::os_rng());
    let secret = key.secret_bytes();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    std::io::Write::write_all(&mut f, hex(&secret[..]).as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(hex(key.public_key().as_bytes()))
}

fn load_key(path: &str) -> Result<SoftwareKey, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let bytes: [u8; 32] = unhex(text.trim())
        .map_err(|e| format!("{path}: {e}"))?
        .try_into()
        .map_err(|_| format!("{path}: not a 32-byte key"))?;
    SoftwareKey::from_secret_bytes(&bytes).map_err(|e| format!("{path}: {e:?}"))
}

/// Run every planned case in order.
pub async fn run(plan: &Plan) -> Result<Vec<CaseResult>, String> {
    let mut out = Vec::new();
    for case in &plan.cases {
        let before = match &plan.observer {
            Some(o) => Some(o.read(plan.waits.close).await?),
            None => None,
        };
        let (want, got, error) = match one(plan, case).await {
            Ok((want, got)) => (want, got, None),
            Err(e) => (String::new(), String::new(), Some(e)),
        };
        let app = match (&plan.observer, before) {
            (Some(o), Some(before)) => {
                tokio::time::sleep(plan.waits.settle).await;
                let after: Counts = o.read(plan.waits.close).await?;
                Some(observe::judge(&before, &after, app_expect(case)))
            }
            _ => None,
        };
        out.push(CaseResult {
            case,
            want,
            got,
            app,
            error,
        });
    }
    Ok(out)
}

fn app_expect(case: &str) -> AppExpect {
    if case == "editor-off-tunnel" {
        AppExpect::EditorRefusal
    } else {
        AppExpect::Nothing
    }
}

fn need<'a, T>(v: &'a Option<T>, flag: &str, case: &str) -> Result<&'a T, String> {
    v.as_ref()
        .ok_or_else(|| format!("case {case} needs {flag}"))
}

/// Run one case: `(want, got)`.
async fn one(plan: &Plan, case: &str) -> Result<(String, String), String> {
    let w = &plan.waits;
    let t = &plan.target;
    let goaway = |code: &str| format!("goaway:{code}");
    match case {
        "not-tls" => Ok((
            "tls_refused".into(),
            session::not_tls(t.pipe(w).await?, w.close).await,
        )),
        "ws-plain-get" | "ws-wrong-path" | "ws-origin" | "ws-no-subprotocol"
        | "ws-large-headers" => {
            let Target::Ws { addr, path } = t else {
                return Err("not a ws route".into());
            };
            let mut req = ws::Request::good(*addr, path);
            let want = match case {
                "ws-plain-get" => {
                    req.path = "/".into();
                    req.upgrade = false;
                    req.subprotocol = None;
                    "404"
                }
                "ws-wrong-path" => {
                    req.path = "/not-mousse".into();
                    "404"
                }
                "ws-origin" => {
                    req.origin = Some("https://example.invalid".into());
                    "403"
                }
                "ws-no-subprotocol" => {
                    req.subprotocol = None;
                    "400"
                }
                _ => {
                    req.padding = w.header_max + 1024;
                    "closed"
                }
            };
            let tcp = session::tcp(*addr, w).await?;
            let (_, status) = ws::upgrade(tcp, &req, w).await?;
            Ok((want.into(), status))
        }
        "ws-slow-headers" => {
            let Target::Ws { addr, path } = t else {
                return Err("not a ws route".into());
            };
            let tcp = session::tcp(*addr, w).await?;
            let req = ws::Request::good(*addr, path);
            // Trickle so the request cannot finish before the wait ends.
            let step = (w.upgrade_wait / (req.bytes().len() as u32 / 2).max(1))
                .max(Duration::from_millis(20));
            Ok((
                "closed".into(),
                ws::trickle(tcp, &req, w.upgrade_wait + w.close, step).await,
            ))
        }
        "ws-text-message" => {
            let Target::Ws { addr, path } = t else {
                return Err("not a ws route".into());
            };
            let tcp = session::tcp(*addr, w).await?;
            let (tcp, status) = ws::upgrade(tcp, &ws::Request::good(*addr, path), w).await?;
            let tcp = tcp.ok_or_else(|| format!("the upgrade got {status}, not 101"))?;
            Ok(("close:1003".into(), ws::text_message(tcp, w.close).await))
        }
        "tls-1.2" => Ok((
            "tls_refused".into(),
            session::tls12_only(t.pipe(w).await?, w.close).await,
        )),
        "tls-no-cert" | "tls-wrong-alpn" => {
            let mode = match case {
                "tls-no-cert" => TlsMode::NoCert,
                _ => TlsMode::WrongAlpn,
            };
            let device = Device::fresh()?;
            let pin = device.identity();
            let got = match Raw::connect(t.pipe(w).await?, &device, pin, mode, w).await {
                Err(_) => "tls_refused".into(),
                Ok(mut raw) => session::refused_after_handshake(&mut raw, w.close).await,
            };
            Ok(("tls_refused".into(), got))
        }
        "fresh-open-rpc" | "fresh-open-tunnel" => {
            let mut raw = proper(plan, &Device::fresh()?, case).await?;
            raw.hello().await?;
            raw.open(if case == "fresh-open-rpc" {
                "mousse.rpc"
            } else {
                "mousse.tunnel"
            })
            .await?;
            let end = raw.until_close(w.close).await;
            Ok((goaway("not_authorized"), end.refusal(Some(w.prompt()))))
        }
        "fresh-silence" => {
            let mut raw = proper(plan, &Device::fresh()?, case).await?;
            raw.hello().await?;
            let end = raw.until_close(w.proof_wait + w.close).await;
            Ok((goaway("not_authorized"), end.refusal(None)))
        }
        "fresh-bad-proof" => {
            let ticket = need(&plan.ticket, "--invite", case)?;
            let device = Device::fresh()?;
            let mut raw = proper(plan, &device, case).await?;
            raw.hello().await?;
            raw.join_proof(ticket, &device.identity(), true).await?;
            let end = raw.until_close(w.close).await;
            Ok((goaway("invitation_invalid"), end.refusal(Some(w.prompt()))))
        }
        "join-only-open-rpc"
        | "join-only-open-hello"
        | "join-only-open-tunnel"
        | "join-only-garbage-code" => {
            let ticket = need(&plan.ticket, "--invite", case)?;
            if case == "join-only-garbage-code" && ticket.kind != InvitationKind::SendLink {
                return Err(format!(
                    "case {case} needs a Send link invitation (kind 2); --invite is kind {}",
                    ticket.kind.as_u64()
                ));
            }
            let device = Device::fresh()?;
            let mut raw = proper(plan, &device, case).await?;
            raw.hello().await?;
            raw.join_proof(ticket, &device.identity(), false).await?;
            let state = raw.answer_to_proof(w.close).await;
            if state.as_deref() != Ok("joinonly") {
                // The case needs a join-only connection to probe; anything
                // else is the host's answer, recorded as the wire result.
                return Ok((
                    goaway("not_authorized"),
                    format!("no join-only ({})", state.unwrap_or_else(|e| e)),
                ));
            }
            let want = match case {
                "join-only-garbage-code" => {
                    raw.garbage_code().await?;
                    "code_abort:pairing_failed".to_owned()
                }
                _ => {
                    let label = match case {
                        "join-only-open-rpc" => "mousse.rpc",
                        "join-only-open-hello" => "mousse.hello",
                        _ => "mousse.tunnel",
                    };
                    raw.open(label).await?;
                    goaway("not_authorized")
                }
            };
            let end = raw.until_close(w.close).await;
            raw.goodbye().await;
            Ok((want, end.refusal(None)))
        }
        "removed-open-rpc" => {
            let key = need(&plan.removed, "--removed-key", case)?;
            let device = Device::from_key(clone_key(key))?;
            let mut raw = proper(plan, &device, case).await?;
            raw.hello().await?;
            raw.open("mousse.rpc").await?;
            let end = raw.until_close(w.close).await;
            Ok((goaway("not_authorized"), end.refusal(Some(w.prompt()))))
        }
        "editor-off-tunnel" => {
            let key = need(&plan.granted_editor_off, "--grant-key", case)?;
            let device = Device::from_key(clone_key(key))?;
            let mut raw = proper(plan, &device, case).await?;
            raw.hello().await?;
            let state = raw.authorized(w.close).await;
            if state.as_deref() != Ok("live") {
                return Ok((
                    "tunnel.close:editor_off".into(),
                    format!("not live ({})", state.unwrap_or_else(|e| e)),
                ));
            }
            let stream = raw.open("mousse.tunnel").await?;
            raw.send(&mousse_net_core::mux::Frame::Data {
                stream,
                payload: tunnel::open_message(),
            })
            .await?;
            let (bytes, end) = raw.stream_bytes(stream, w.close).await;
            raw.goodbye().await;
            let got = if bytes.is_empty() {
                end
            } else {
                tunnel::word(&bytes)
            };
            Ok(("tunnel.close:editor_off".into(), got))
        }
        "admission" => admission(t, w).await,
        other => Err(format!("no case {other}")),
    }
}

async fn proper(plan: &Plan, device: &Device, case: &str) -> Result<Raw, String> {
    let pin = *need(&plan.pin, "--pin or --invite", case)?;
    Raw::connect(
        plan.target.pipe(&plan.waits).await?,
        device,
        pin,
        TlsMode::Proper,
        &plan.waits,
    )
    .await
}

fn clone_key(k: &SoftwareKey) -> SoftwareKey {
    SoftwareKey::from_secret_bytes(&k.secret_bytes()).expect("a key's own bytes load")
}

/// Fill the route's pre-auth pool with silent connections, then one more:
/// the host keeps the first `cap` and refuses the last.
async fn admission(t: &Target, w: &Waits) -> Result<(String, String), String> {
    let cap = w.preauth_cap(t);
    let want = format!("held {cap}, refused the next");
    let mut held = Vec::with_capacity(cap);
    for _ in 0..cap {
        held.push(session::silent(t, w).await?);
    }
    let mut extra = session::silent(t, w).await;
    let extra_refused = match &mut extra {
        Ok(s) => session::closed_within(s, w.close).await,
        Err(_) => true,
    };
    // The first `cap` must still be open: check each briefly.
    let mut early = 0;
    for s in &mut held {
        if session::closed_within(s, Duration::from_millis(50)).await {
            early += 1;
        }
    }
    drop(held);
    drop(extra);
    let got = match (early, extra_refused) {
        (0, true) => want.clone(),
        (0, false) => format!("held {}, refused none", cap + 1),
        (n, _) => format!("closed {n} of the first {cap}"),
    };
    Ok((want, got))
}

fn report(plan: &Plan, results: &[CaseResult]) -> u8 {
    let route = plan.target.kind();
    for r in results {
        let app = match &r.app {
            None => "app=not-observed".to_owned(),
            Some(Ok(s)) => format!("app=[{s}]"),
            Some(Err(s)) => format!("app=[{s}]"),
        };
        match (r.reason(), &r.error) {
            (None, _) => println!(
                "PASS {} {route}:{} wire={} {app}",
                plan.marker, r.case, r.got
            ),
            (Some(reason), Some(e)) => println!(
                "FAIL {} {route}:{} reason={reason} error={e:?} {app}",
                plan.marker, r.case
            ),
            (Some(reason), None) => println!(
                "FAIL {} {route}:{} reason={reason} wire={:?} want={:?} {app}",
                plan.marker, r.case, r.got, r.want
            ),
        }
    }
    let verdict = verdict(results);
    if let Some(path) = &plan.json {
        let doc = json!({
            "route": route,
            "verdict": if verdict.is_none() { "PASS" } else { "FAIL" },
            "reason": verdict,
            "cases": results.iter().map(|r| json!({
                "case": r.case,
                "want": r.want,
                "got": r.got,
                "app": r.app.as_ref().map(|a| match a { Ok(s) | Err(s) => s.clone() }),
                "app_ok": r.app.as_ref().map(Result::is_ok),
                "error": r.error,
                "reason": r.reason(),
            })).collect::<Vec<_>>(),
        });
        if let Err(e) = std::fs::write(path, serde_json::to_vec_pretty(&doc).unwrap_or_default()) {
            eprintln!("probe: {}: {e}", path.display());
        }
    }
    match verdict {
        None => {
            println!("PASS {}", plan.marker);
            0
        }
        Some(reason) => {
            println!("FAIL {} reason={reason}", plan.marker);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(case: &'static str, want: &str, got: &str, app: Option<Result<&str, &str>>) -> CaseResult {
        CaseResult {
            case,
            want: want.into(),
            got: got.into(),
            app: app.map(|a| a.map(str::to_owned).map_err(str::to_owned)),
            error: None,
        }
    }

    #[test]
    fn the_app_record_wins_over_the_wire_and_the_wire_over_errors() {
        let pass = r("not-tls", "x", "x", Some(Ok("")));
        let wire = r(
            "fresh-open-rpc",
            "goaway:not_authorized",
            "open",
            Some(Ok("")),
        );
        let app = r("fresh-open-rpc", "x", "x", Some(Err("conn_up+1")));
        let both = r("fresh-open-rpc", "x", "open", Some(Err("conn_up+1")));
        assert_eq!(verdict(std::slice::from_ref(&pass)), None);
        assert_eq!(
            verdict(&[pass.clone(), wire.clone()]),
            Some("wire_accepted")
        );
        assert_eq!(verdict(&[wire.clone(), app]), Some("probe_reached_app"));
        assert_eq!(both.reason(), Some("probe_reached_app"));
        let mut err = pass;
        err.error = Some("no route".into());
        assert_eq!(verdict(&[err.clone()]), Some("probe_error"));
        assert_eq!(verdict(&[err, wire]), Some("wire_accepted"));
    }

    #[test]
    fn engine_limits_come_from_the_engines_variables_and_bad_values_are_refused() {
        let w = Waits::from_vars(|k| match k {
            "MOUSSE_NET_PREAUTH_TCP" => Some("4".into()),
            "MOUSSE_NET_PREAUTH_PER_SOURCE" => Some("6".into()),
            _ => None,
        })
        .unwrap();
        let tcp = Target::parse("tcp://127.0.0.1:1").unwrap();
        let ws = Target::parse("ws://127.0.0.1:1/mousse-net/1").unwrap();
        assert_eq!(w.preauth_cap(&tcp), 4);
        assert_eq!(w.preauth_cap(&ws), 16);
        assert_eq!(w.proof_wait, Duration::from_secs(10));
        assert!(
            Waits::from_vars(|k| (k == "MOUSSE_CHECK_PROBE_CLOSE_MS").then(|| "0".into())).is_err()
        );
    }

    #[test]
    fn routes_are_ip_literals_and_plain_ws_is_loopback_only() {
        assert!(Target::parse("tcp://example.com:7443").is_err());
        assert!(Target::parse("ws://192.168.1.2:80/mousse-net/1").is_err());
        assert!(Target::parse("ssh://me@host").unwrap_err().contains("E9"));
        let ws = Target::parse("ws://127.0.0.1:9/a/mousse-net/1").unwrap();
        assert_eq!(
            ws,
            Target::Ws {
                addr: "127.0.0.1:9".parse().unwrap(),
                path: "/a/mousse-net/1".into()
            }
        );
        assert!(cases_for(&ws).contains(&"ws-slow-headers"));
        let tcp = Target::parse("tcp://[::1]:9").unwrap();
        assert!(!cases_for(&tcp).iter().any(|c| c.starts_with("ws-")));
    }
}
