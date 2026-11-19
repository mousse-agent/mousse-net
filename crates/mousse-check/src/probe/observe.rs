//! The app side of each case: counters read from an observer the app check
//! serves on loopback, before and after the case.
//!
//! `GET <url>` answers a JSON object with at least these totals, each a
//! count since the observer started:
//!
//! - `conn_up`: connections the helper announced to the app;
//! - `streams`: streams delivered to the app;
//! - `authorized_calls`: calls the app's dispatcher authorized and ran;
//! - `endpoint_sessions`: editor endpoint sessions started;
//! - `ledger_rows`: rows written to the access ledger;
//! - `refusals`: refusals the app sent (such as `editor_off`).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The counters every observer must report.
pub const COUNTERS: [&str; 6] = [
    "conn_up",
    "streams",
    "authorized_calls",
    "endpoint_sessions",
    "ledger_rows",
    "refusals",
];

pub type Counts = BTreeMap<String, u64>;

#[derive(Clone, Debug)]
pub struct Observer {
    addr: SocketAddr,
    path: String,
}

impl Observer {
    /// `http://<loopback ip>:<port>/<path>`.
    pub fn parse(url: &str) -> Result<Self, String> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| format!("--observe {url}: needs http://<loopback>:<port>/<path>"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_owned()),
            None => (rest, "/".to_owned()),
        };
        let addr: SocketAddr = authority
            .parse()
            .map_err(|_| format!("--observe {url}: needs an IP literal and a port"))?;
        if !addr.ip().is_loopback() {
            return Err(format!("--observe {url}: the observer must be on loopback"));
        }
        Ok(Self { addr, path })
    }

    /// The current totals.
    pub async fn read(&self, wait: Duration) -> Result<Counts, String> {
        let fetch = async {
            let mut s = TcpStream::connect(self.addr)
                .await
                .map_err(|e| format!("observer {}: {e}", self.addr))?;
            let req = format!(
                "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
                self.path, self.addr
            );
            s.write_all(req.as_bytes())
                .await
                .map_err(|e| format!("observer: {e}"))?;
            let mut body = Vec::new();
            s.read_to_end(&mut body)
                .await
                .map_err(|e| format!("observer: {e}"))?;
            Ok::<_, String>(body)
        };
        let raw = tokio::time::timeout(wait, fetch)
            .await
            .map_err(|_| "observer: timed out".to_owned())??;
        parse_response(&raw)
    }
}

pub fn parse_response(raw: &[u8]) -> Result<Counts, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("observer: no HTTP head")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        return Err(format!("observer answered {status}"));
    }
    let v: serde_json::Value =
        serde_json::from_slice(&raw[split + 4..]).map_err(|e| format!("observer JSON: {e}"))?;
    let obj = v.as_object().ok_or("observer: not a JSON object")?;
    let mut out = Counts::new();
    for name in COUNTERS {
        let n = obj
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("observer: no count {name}"))?;
        out.insert(name.to_owned(), n);
    }
    Ok(out)
}

/// What a case may leave behind in the app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppExpect {
    /// No `conn.up`, no stream, no authorized call, no endpoint session, no
    /// ledger row.
    Nothing,
    /// The editor-off tunnel: one `conn.up`, one stream, one refusal, no
    /// endpoint session or authorized call, and no ledger row beyond the
    /// refusal's.
    EditorRefusal,
}

/// Judge the change between two snapshots. `Err` says what was wrong.
pub fn judge(before: &Counts, after: &Counts, expect: AppExpect) -> Result<String, String> {
    let d = |k: &str| {
        after
            .get(k)
            .copied()
            .unwrap_or(0)
            .saturating_sub(before.get(k).copied().unwrap_or(0))
    };
    let summary = COUNTERS
        .iter()
        .map(|k| format!("{k}+{}", d(k)))
        .collect::<Vec<_>>()
        .join(" ");
    let ok = match expect {
        AppExpect::Nothing => COUNTERS.iter().all(|k| d(k) == 0),
        AppExpect::EditorRefusal => {
            d("conn_up") == 1
                && d("streams") == 1
                && d("refusals") == 1
                && d("authorized_calls") == 0
                && d("endpoint_sessions") == 0
                && d("ledger_rows") <= 1
        }
    };
    if ok {
        Ok(summary)
    } else {
        Err(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(v: [u64; 6]) -> Counts {
        COUNTERS
            .iter()
            .zip(v)
            .map(|(k, n)| (k.to_string(), n))
            .collect()
    }

    #[test]
    fn a_response_needs_every_counter() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"conn_up\":1,\"streams\":2,\"authorized_calls\":3,\"endpoint_sessions\":4,\"ledger_rows\":5,\"refusals\":6,\"extra\":9}";
        assert_eq!(parse_response(ok).unwrap(), counts([1, 2, 3, 4, 5, 6]));
        let short = b"HTTP/1.1 200 OK\r\n\r\n{\"conn_up\":1}";
        assert!(parse_response(short).unwrap_err().contains("streams"));
        assert!(parse_response(b"HTTP/1.1 500 x\r\n\r\n{}").is_err());
    }

    #[test]
    fn only_the_editor_refusal_may_leave_a_trace() {
        let base = counts([5, 5, 5, 5, 5, 5]);
        assert!(judge(&base, &base, AppExpect::Nothing).is_ok());
        let conn = counts([6, 5, 5, 5, 5, 5]);
        assert!(judge(&base, &conn, AppExpect::Nothing).is_err());
        let refusal = counts([6, 6, 5, 5, 6, 6]);
        assert!(judge(&base, &refusal, AppExpect::EditorRefusal).is_ok());
        let session = counts([6, 6, 5, 6, 6, 6]);
        assert!(judge(&base, &session, AppExpect::EditorRefusal).is_err());
        assert!(judge(&base, &base, AppExpect::EditorRefusal).is_err());
    }
}
