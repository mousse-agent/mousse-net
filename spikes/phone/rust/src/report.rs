//! Collects the steps a host app ran and writes the result JSON:
//! `{ check, target, outcome, build, details }`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use crate::{BUILD_ID, TARGET_TRIPLE};

#[derive(Default)]
struct Agg {
    runs: u64,
    failures: u64,
    values: Vec<f64>,
}

#[derive(Default)]
struct Inner {
    steps: BTreeMap<String, Agg>,
    failures: Vec<Value>,
    details: Map<String, Value>,
}

#[derive(uniffi::Object)]
pub struct Report {
    check: String,
    inner: Mutex<Inner>,
}

fn pct(sorted: &[f64], p: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    Some((sorted[idx.min(sorted.len() - 1)] * 1000.0).round() / 1000.0)
}

impl Report {
    pub(crate) fn detail_value(&self, key: &str, v: Value) {
        self.lock().details.insert(key.to_string(), v);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[uniffi::export]
impl Report {
    /// `check` is `phase0.phone-lifecycle` or `phase0.phone-byte-path`.
    #[uniffi::constructor]
    pub fn new(check: String) -> Arc<Self> {
        Arc::new(Report {
            check,
            inner: Mutex::new(Inner::default()),
        })
    }

    /// Records one run of a step. `value` (ms, MB/s, ...) is summarised per step.
    pub fn step(&self, name: String, ok: bool, value: Option<f64>, note: String) {
        let mut g = self.lock();
        let agg = g.steps.entry(name.clone()).or_default();
        agg.runs += 1;
        if !ok {
            agg.failures += 1;
        }
        if let Some(v) = value.filter(|v| v.is_finite()) {
            agg.values.push(v);
        }
        if !ok && g.failures.len() < 20 {
            g.failures
                .push(json!({"step": name, "value": value, "note": note}));
        }
    }

    /// Adds a detail; `json` is stored parsed if it is valid JSON, else as a string.
    pub fn detail(&self, key: String, json: String) {
        let v = serde_json::from_str(&json).unwrap_or(Value::String(json));
        self.detail_value(&key, v);
    }

    /// PASS when every recorded step passed, FAIL if any failed, INCOMPLETE if none ran.
    pub fn outcome(&self) -> String {
        let g = self.lock();
        if g.steps.is_empty() {
            "INCOMPLETE"
        } else if g.steps.values().any(|a| a.failures > 0) {
            "FAIL"
        } else {
            "PASS"
        }
        .to_string()
    }

    /// The result JSON, on one line.
    pub fn finish(&self, target: String) -> String {
        let outcome = self.outcome();
        let g = self.lock();
        let mut steps = Map::new();
        for (name, a) in &g.steps {
            let mut v = a.values.clone();
            v.sort_by(f64::total_cmp);
            steps.insert(
                name.clone(),
                json!({
                    "runs": a.runs,
                    "failures": a.failures,
                    "p50": pct(&v, 50.0),
                    "p95": pct(&v, 95.0),
                    "max": v.last().copied(),
                }),
            );
        }
        let mut details = g.details.clone();
        details.insert("libTarget".into(), json!(TARGET_TRIPLE));
        details.insert("steps".into(), Value::Object(steps));
        details.insert("failures".into(), Value::Array(g.failures.clone()));
        json!({
            "check": self.check,
            "target": target,
            "outcome": outcome,
            "build": BUILD_ID,
            "details": details,
        })
        .to_string()
    }

    /// `<check>__<target>.json`
    pub fn file_name(&self, target: String) -> String {
        format!("{}__{}.json", self.check, target)
    }
}
