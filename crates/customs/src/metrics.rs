//! Prometheus text exposition, hand-rolled.
//!
//! The metric set is small and fixed, so a few mutex-guarded maps are simpler than pulling
//! in a client library, and the output is easy to assert on in tests.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::Duration;

const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

#[derive(Debug, Clone)]
struct Histogram {
    counts: Vec<u64>,
    sum: f64,
    count: u64,
}

impl Histogram {
    fn new() -> Self {
        Self {
            counts: vec![0; LATENCY_BUCKETS.len()],
            sum: 0.0,
            count: 0,
        }
    }

    fn observe(&mut self, v: f64) {
        for (i, b) in LATENCY_BUCKETS.iter().enumerate() {
            if v <= *b {
                self.counts[i] += 1;
            }
        }
        self.sum += v;
        self.count += 1;
    }

    fn render(&self, out: &mut String, name: &str, labels: &str) {
        let sep = if labels.is_empty() { "" } else { "," };
        for (i, b) in LATENCY_BUCKETS.iter().enumerate() {
            let _ = writeln!(
                out,
                "{name}_bucket{{{labels}{sep}le=\"{b}\"}} {}",
                self.counts[i]
            );
        }
        let _ = writeln!(
            out,
            "{name}_bucket{{{labels}{sep}le=\"+Inf\"}} {}",
            self.count
        );
        let braces = if labels.is_empty() {
            String::new()
        } else {
            format!("{{{labels}}}")
        };
        let _ = writeln!(out, "{name}_sum{braces} {}", self.sum);
        let _ = writeln!(out, "{name}_count{braces} {}", self.count);
    }
}

#[derive(Debug, Default)]
struct Inner {
    requests: BTreeMap<(String, u16), u64>,
    verdicts: BTreeMap<(String, String), u64>,
    events: BTreeMap<String, u64>,
    cache: BTreeMap<String, u64>,
    singleflight_joins: u64,
    notifications: BTreeMap<String, u64>,
    scan: Option<Histogram>,
    upstream: BTreeMap<String, Histogram>,
}

#[derive(Debug, Default)]
pub struct Metrics {
    inner: Mutex<Inner>,
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut g)
    }

    pub fn request(&self, route: &str, status: u16) {
        self.with(|m| *m.requests.entry((route.to_string(), status)).or_default() += 1);
    }

    pub fn verdict(&self, decision: &str, ecosystem: &str) {
        self.with(|m| {
            *m.verdicts
                .entry((decision.to_string(), ecosystem.to_string()))
                .or_default() += 1
        });
    }

    pub fn event(&self, kind: &str) {
        self.with(|m| *m.events.entry(kind.to_string()).or_default() += 1);
    }

    /// `kind` is `artifact_hit`, `artifact_miss`, `scan_hit`, or `scan_miss`.
    pub fn cache(&self, kind: &str) {
        self.with(|m| *m.cache.entry(kind.to_string()).or_default() += 1);
    }

    /// `outcome` is `sent`, `failed`, `repeat`, `rate_limited`, or `dropped`.
    pub fn notification(&self, outcome: &str) {
        self.with(|m| *m.notifications.entry(outcome.to_string()).or_default() += 1);
    }

    pub fn singleflight_join(&self) {
        self.with(|m| m.singleflight_joins += 1);
    }

    pub fn scan_latency(&self, d: Duration) {
        self.with(|m| {
            m.scan
                .get_or_insert_with(Histogram::new)
                .observe(d.as_secs_f64())
        });
    }

    pub fn upstream_latency(&self, kind: &str, d: Duration) {
        self.with(|m| {
            m.upstream
                .entry(kind.to_string())
                .or_insert_with(Histogram::new)
                .observe(d.as_secs_f64())
        });
    }

    pub fn render(&self) -> String {
        self.with(|m| {
            let mut out = String::new();
            out.push_str("# HELP customs_http_requests_total HTTP requests by route and status.\n");
            out.push_str("# TYPE customs_http_requests_total counter\n");
            for ((route, status), n) in &m.requests {
                let _ = writeln!(
                    out,
                    "customs_http_requests_total{{route=\"{}\",status=\"{status}\"}} {n}",
                    escape(route)
                );
            }
            out.push_str("# HELP customs_verdicts_total Verdicts by decision and ecosystem.\n");
            out.push_str("# TYPE customs_verdicts_total counter\n");
            for ((d, e), n) in &m.verdicts {
                let _ = writeln!(
                    out,
                    "customs_verdicts_total{{decision=\"{d}\",ecosystem=\"{e}\"}} {n}"
                );
            }
            out.push_str("# HELP customs_events_total Recorded events by kind.\n");
            out.push_str("# TYPE customs_events_total counter\n");
            for (k, n) in &m.events {
                let _ = writeln!(out, "customs_events_total{{kind=\"{k}\"}} {n}");
            }
            out.push_str("# HELP customs_cache_total Artifact and scan cache lookups.\n");
            out.push_str("# TYPE customs_cache_total counter\n");
            for (k, n) in &m.cache {
                let _ = writeln!(out, "customs_cache_total{{result=\"{k}\"}} {n}");
            }
            out.push_str("# HELP customs_singleflight_joins_total Requests that waited on an in-flight scan of the same artifact.\n");
            out.push_str("# TYPE customs_singleflight_joins_total counter\n");
            let _ = writeln!(out, "customs_singleflight_joins_total {}", m.singleflight_joins);
            out.push_str("# HELP customs_notifications_total Webhook notifications by outcome.\n");
            out.push_str("# TYPE customs_notifications_total counter\n");
            for (k, n) in &m.notifications {
                let _ = writeln!(out, "customs_notifications_total{{outcome=\"{k}\"}} {n}");
            }
            out.push_str("# HELP customs_scan_duration_seconds Time to scan and score one artifact.\n");
            out.push_str("# TYPE customs_scan_duration_seconds histogram\n");
            m.scan
                .clone()
                .unwrap_or_else(Histogram::new)
                .render(&mut out, "customs_scan_duration_seconds", "");
            out.push_str("# HELP customs_upstream_fetch_duration_seconds Upstream registry fetch latency by kind.\n");
            out.push_str("# TYPE customs_upstream_fetch_duration_seconds histogram\n");
            for (k, h) in &m.upstream {
                h.render(
                    &mut out,
                    "customs_upstream_fetch_duration_seconds",
                    &format!("kind=\"{k}\""),
                );
            }
            out
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_text() {
        let m = Metrics::new();
        m.request("/pypi/files/{*path}", 200);
        m.request("/pypi/files/{*path}", 200);
        m.verdict("block", "npm");
        m.scan_latency(Duration::from_millis(30));
        m.upstream_latency("artifact", Duration::from_millis(200));
        let t = m.render();
        assert!(t.contains(
            "customs_http_requests_total{route=\"/pypi/files/{*path}\",status=\"200\"} 2"
        ));
        assert!(t.contains("customs_verdicts_total{decision=\"block\",ecosystem=\"npm\"} 1"));
        assert!(t.contains("customs_scan_duration_seconds_bucket{le=\"0.05\"} 1"));
        assert!(t.contains("customs_scan_duration_seconds_bucket{le=\"0.025\"} 0"));
        assert!(t.contains("customs_scan_duration_seconds_count 1"));
        assert!(t.contains(
            "customs_upstream_fetch_duration_seconds_bucket{kind=\"artifact\",le=\"0.25\"} 1"
        ));
    }
}
