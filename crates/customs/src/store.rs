//! SQLite persistence: events, verdicts, the scan cache, and the artifact index.
//!
//! Every operation is a single short statement, so one connection behind a mutex is
//! enough; WAL mode keeps readers (the dashboard) from blocking the proxy's writes.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use customs_model::Decision;
use customs_scan::Ecosystem;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::policy_log::PolicyChange;
use crate::util::{ecosystem_str, now_ts, parse_ecosystem};
use crate::verdict::{Event, EventKind, Verdict};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    sha256 TEXT,
    decision TEXT NOT NULL,
    risk REAL,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    client TEXT,
    kind TEXT NOT NULL,
    decision TEXT,
    risk REAL,
    verdict_id INTEGER REFERENCES verdicts(id)
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS scan_cache (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    model_version TEXT NOT NULL,
    created TEXT NOT NULL,
    json TEXT NOT NULL,
    PRIMARY KEY (ecosystem, name, version, sha256, model_version)
);
CREATE TABLE IF NOT EXISTS artifacts (
    url TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    filename TEXT NOT NULL,
    size INTEGER NOT NULL,
    fetched TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    remote TEXT,
    client TEXT,
    auth TEXT NOT NULL,
    changes TEXT NOT NULL
);
"#;

/// Key of the verdict (scan) cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanKey {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: Option<String>,
    pub sha256: String,
    /// Everything else the cached result depends on: the model version followed by the
    /// scanner and summary versions and the scan limit (the engine's scan identity).
    pub model_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRow {
    pub sha256: String,
    pub filename: String,
    pub size: u64,
}

/// A new event before it has an id and timestamp.
#[derive(Debug, Clone)]
pub struct NewEvent {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: Option<String>,
    pub client: Option<String>,
    pub kind: EventKind,
    pub decision: Option<Decision>,
    pub risk: Option<f64>,
    pub verdict_id: Option<i64>,
}

/// Counts by decision.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct DecisionCounts {
    pub allow: u64,
    pub warn: u64,
    pub block: u64,
}

impl DecisionCounts {
    fn add(&mut self, decision: &str, n: u64) {
        match decision {
            "allow" => self.allow += n,
            "warn" => self.warn += n,
            "block" => self.block += n,
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct KindCounts {
    pub install: u64,
    pub check: u64,
    pub nonexistent_package: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DayCount {
    /// `YYYY-MM-DD` (UTC).
    pub date: String,
    /// Block decisions that day.
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ReasonCount {
    /// Model feature name (`inst_proc_exec`, `name_min_edit_distance`) or policy rule name
    /// (`min_age_days`, `block_nonexistent`).
    pub feature: String,
    pub label: String,
    pub count: u64,
}

/// `GET /api/stats`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Stats {
    /// Number of events.
    pub total: u64,
    pub by_decision: DecisionCounts,
    pub by_ecosystem: BTreeMap<String, DecisionCounts>,
    pub by_kind: KindCounts,
    /// One entry per day for the last `days` days (oldest first), zeros included.
    pub blocks_per_day: Vec<DayCount>,
    /// Most frequent reasons among warn and block verdicts in the same window.
    pub top_reasons: Vec<ReasonCount>,
}

/// Filters for `GET /api/events`.
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    pub before: Option<i64>,
    pub decision: Option<String>,
    pub ecosystem: Option<String>,
    pub kind: Option<String>,
    /// Substring of the package name.
    pub q: Option<String>,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(SCHEMA).context("creating schema")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn with<R>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<R>) -> Result<R> {
        let g = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        Ok(f(&g)?)
    }

    pub fn insert_verdict(&self, v: &Verdict) -> Result<i64> {
        let json = serde_json::to_string(v)?;
        self.with(|c| {
            c.execute(
                "INSERT INTO verdicts (ts, ecosystem, name, version, sha256, decision, risk, json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    v.ts,
                    ecosystem_str(v.ecosystem),
                    v.name,
                    v.version,
                    v.sha256,
                    v.decision.as_str(),
                    v.risk,
                    json
                ],
            )?;
            Ok(c.last_insert_rowid())
        })
    }

    pub fn verdict(&self, id: i64) -> Result<Option<Verdict>> {
        let json: Option<String> = self.with(|c| {
            c.query_row("SELECT json FROM verdicts WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()
        })?;
        match json {
            Some(j) => {
                let mut v: Verdict = serde_json::from_str(&j)?;
                v.id = Some(id);
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }

    pub fn insert_event(&self, e: NewEvent) -> Result<Event> {
        let ts = now_ts();
        let id = self.with(|c| {
            c.execute(
                "INSERT INTO events (ts, ecosystem, name, version, client, kind, decision, risk, verdict_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    ts,
                    ecosystem_str(e.ecosystem),
                    e.name,
                    e.version,
                    e.client,
                    e.kind.as_str(),
                    e.decision.map(|d| d.as_str()),
                    e.risk,
                    e.verdict_id
                ],
            )?;
            Ok(c.last_insert_rowid())
        })?;
        Ok(Event {
            id,
            ts,
            ecosystem: e.ecosystem,
            name: e.name,
            version: e.version,
            client: e.client,
            kind: e.kind,
            decision: e.decision,
            risk: e.risk,
            verdict_id: e.verdict_id,
        })
    }

    /// Record a policy change; `id` and `ts` of the argument are replaced.
    pub fn insert_policy_change(&self, mut ch: PolicyChange) -> Result<PolicyChange> {
        ch.ts = now_ts();
        let changes = serde_json::to_string(&ch.changes)?;
        ch.id = self.with(|c| {
            c.execute(
                "INSERT INTO policy_changes (ts, remote, client, auth, changes)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![ch.ts, ch.remote, ch.client, ch.auth, changes],
            )?;
            Ok(c.last_insert_rowid())
        })?;
        Ok(ch)
    }

    /// Newest first.
    pub fn policy_changes(&self, limit: u32) -> Result<Vec<PolicyChange>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, ts, remote, client, auth, changes FROM policy_changes
                 ORDER BY id DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit], |r| {
                let changes: String = r.get(5)?;
                Ok(PolicyChange {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    remote: r.get(2)?,
                    client: r.get(3)?,
                    auth: r.get(4)?,
                    changes: serde_json::from_str(&changes).unwrap_or_default(),
                })
            })?;
            rows.collect()
        })
    }

    /// Newest first; `before` is an event id for pagination.
    pub fn events(&self, limit: u32, f: &EventFilter) -> Result<Vec<Event>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, ts, ecosystem, name, version, client, kind, decision, risk, verdict_id
                 FROM events
                 WHERE id < ?1
                   AND (?2 IS NULL OR decision = ?2)
                   AND (?3 IS NULL OR ecosystem = ?3)
                   AND (?4 IS NULL OR kind = ?4)
                   AND (?5 IS NULL OR instr(lower(name), lower(?5)) > 0)
                 ORDER BY id DESC LIMIT ?6",
            )?;
            let rows = stmt.query_map(
                params![
                    f.before.unwrap_or(i64::MAX),
                    f.decision,
                    f.ecosystem,
                    f.kind,
                    f.q,
                    limit
                ],
                |r| {
                    let eco: String = r.get(2)?;
                    let kind: String = r.get(6)?;
                    let decision: Option<String> = r.get(7)?;
                    Ok(Event {
                        id: r.get(0)?,
                        ts: r.get(1)?,
                        ecosystem: parse_ecosystem(&eco).unwrap_or(Ecosystem::Pypi),
                        name: r.get(3)?,
                        version: r.get(4)?,
                        client: r.get(5)?,
                        kind: EventKind::parse(&kind).unwrap_or(EventKind::Install),
                        decision: decision.as_deref().and_then(Decision::parse),
                        risk: r.get(8)?,
                        verdict_id: r.get(9)?,
                    })
                },
            )?;
            rows.collect()
        })
    }

    pub fn scan_cache_get(&self, k: &ScanKey) -> Result<Option<String>> {
        self.with(|c| {
            c.query_row(
                "SELECT json FROM scan_cache WHERE ecosystem = ?1 AND name = ?2 AND version = ?3
                 AND sha256 = ?4 AND model_version = ?5",
                params![
                    ecosystem_str(k.ecosystem),
                    k.name,
                    k.version.as_deref().unwrap_or(""),
                    k.sha256,
                    k.model_version
                ],
                |r| r.get(0),
            )
            .optional()
        })
    }

    pub fn scan_cache_put(&self, k: &ScanKey, json: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT OR REPLACE INTO scan_cache (ecosystem, name, version, sha256, model_version, created, json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    ecosystem_str(k.ecosystem),
                    k.name,
                    k.version.as_deref().unwrap_or(""),
                    k.sha256,
                    k.model_version,
                    now_ts(),
                    json
                ],
            )?;
            Ok(())
        })
    }

    /// Delete scan cache rows whose identity does not end with `suffix` (the current
    /// scanner, summary version and scan limit). Rows of other model versions with the same
    /// scanner stay, since another engine on the same data directory may use them.
    pub fn scan_cache_prune(&self, suffix: &str) -> Result<usize> {
        self.with(|c| {
            c.execute(
                "DELETE FROM scan_cache
                 WHERE substr(model_version, length(model_version) - length(?1) + 1) != ?1",
                [suffix],
            )
        })
    }

    pub fn artifact_get(&self, url: &str) -> Result<Option<ArtifactRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT sha256, filename, size FROM artifacts WHERE url = ?1",
                [url],
                |r| {
                    Ok(ArtifactRow {
                        sha256: r.get(0)?,
                        filename: r.get(1)?,
                        size: r.get::<_, i64>(2)? as u64,
                    })
                },
            )
            .optional()
        })
    }

    pub fn artifact_put(&self, url: &str, a: &ArtifactRow) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT OR REPLACE INTO artifacts (url, sha256, filename, size, fetched)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![url, a.sha256, a.filename, a.size as i64, now_ts()],
            )?;
            Ok(())
        })
    }

    pub fn stats(&self, days: u32) -> Result<Stats> {
        let days = days.clamp(1, 366);
        let since = (Utc::now() - Duration::days(days as i64 - 1))
            .format("%Y-%m-%d")
            .to_string();
        self.with(|c| {
            let total: i64 = c.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
            let mut by_decision = DecisionCounts::default();
            let mut by_ecosystem: BTreeMap<String, DecisionCounts> = ["pypi", "npm"]
                .iter()
                .map(|e| (e.to_string(), DecisionCounts::default()))
                .collect();
            let mut stmt = c.prepare(
                "SELECT ecosystem, decision, COUNT(*) FROM events WHERE decision IS NOT NULL
                 GROUP BY ecosystem, decision",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)? as u64,
                ))
            })?;
            for row in rows {
                let (eco, decision, n) = row?;
                by_decision.add(&decision, n);
                by_ecosystem.entry(eco).or_default().add(&decision, n);
            }
            let mut by_kind = KindCounts::default();
            let mut stmt = c.prepare("SELECT kind, COUNT(*) FROM events GROUP BY kind")?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })?;
            for row in rows {
                let (kind, n) = row?;
                match kind.as_str() {
                    "install" => by_kind.install += n,
                    "check" => by_kind.check += n,
                    "nonexistent_package" => by_kind.nonexistent_package += n,
                    _ => {}
                }
            }

            let mut per_day: BTreeMap<String, u64> = (0..days)
                .rev()
                .map(|i| {
                    (
                        (Utc::now() - Duration::days(i as i64))
                            .format("%Y-%m-%d")
                            .to_string(),
                        0,
                    )
                })
                .collect();
            let mut stmt = c.prepare(
                "SELECT substr(ts, 1, 10) AS day, COUNT(*) FROM events
                 WHERE ts >= ?1 AND decision = 'block' GROUP BY day",
            )?;
            let rows = stmt.query_map([&since], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })?;
            for row in rows {
                let (day, n) = row?;
                if let Some(d) = per_day.get_mut(&day) {
                    *d += n;
                }
            }

            let mut counts: BTreeMap<String, (String, u64)> = BTreeMap::new();
            let mut stmt = c.prepare(
                "SELECT json FROM verdicts WHERE decision IN ('warn', 'block') AND ts >= ?1
                 ORDER BY id DESC LIMIT 5000",
            )?;
            let rows = stmt.query_map([&since], |r| r.get::<_, String>(0))?;
            for json in rows {
                let Ok(v) = serde_json::from_str::<Verdict>(&json?) else {
                    continue;
                };
                for h in v
                    .policy_hits
                    .iter()
                    .filter(|h| h.severity >= Decision::Warn)
                {
                    let e = counts
                        .entry(h.rule.clone())
                        .or_insert_with(|| (rule_label(&h.rule), 0));
                    e.1 += 1;
                }
                if v.model_decision >= Decision::Warn {
                    for r in v.reasons.iter().take(3) {
                        let e = counts
                            .entry(r.feature.clone())
                            .or_insert_with(|| (r.label.clone(), 0));
                        e.1 += 1;
                    }
                }
            }
            let mut top_reasons: Vec<ReasonCount> = counts
                .into_iter()
                .map(|(feature, (label, count))| ReasonCount {
                    feature,
                    label,
                    count,
                })
                .collect();
            top_reasons.sort_by(|a, b| b.count.cmp(&a.count).then(a.feature.cmp(&b.feature)));
            top_reasons.truncate(10);

            Ok(Stats {
                total: total as u64,
                by_decision,
                by_ecosystem,
                by_kind,
                blocks_per_day: per_day
                    .into_iter()
                    .map(|(date, count)| DayCount { date, count })
                    .collect(),
                top_reasons,
            })
        })
    }
}

/// Human phrase for a policy rule name.
pub fn rule_label(rule: &str) -> String {
    match rule {
        "deny" => "On the deny list".into(),
        "allow" => "On the allow list".into(),
        "established" => "Established release of a popular package".into(),
        "block_nonexistent" => "Package does not exist (possible hallucination)".into(),
        "min_age_days" => "Published too recently".into(),
        "block_install_scripts_from_new" => "New package with install scripts".into(),
        "scan_error" => "Archive could not be scanned".into(),
        "not_scanned" => "Archive too large to scan".into(),
        "also_checked" => "The release's other archive was checked too".into(),
        "provenance_dropped" => "Release lost its provenance attestation".into(),
        "install_script_added" => "Release added or changed an install script".into(),
        "publisher_changed" => "Release published by a new account".into(),
        "dormant_revival" => "First release after a long dormancy".into(),
        "version_anomaly" => "Unusual version jump".into(),
        "nonregistry_dependency_added" => {
            "Release added a dependency from outside the registry".into()
        }
        "young_dependency_added" => "Release added a brand-new dependency".into(),
        "unread_code" => "Code the scanner could not read".into(),
        "startup_hook" => ".pth file runs code at every Python start".into(),
        "agent_bypass" => "Install-time code runs an AI agent without permission checks".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(identity: &str) -> ScanKey {
        ScanKey {
            ecosystem: Ecosystem::Pypi,
            name: "p".into(),
            version: Some("1.0".into()),
            sha256: "ab".into(),
            model_version: identity.into(),
        }
    }

    #[test]
    fn scan_cache_prune_keeps_only_the_current_scanner() {
        let s = Store::open_in_memory().unwrap();
        for id in [
            "m1",
            "m1|scan:1.1|summary:1|max:9",
            "m2|scan:1.1|summary:1|max:9",
            "m1|scan:0.1|summary:1|max:9",
        ] {
            s.scan_cache_put(&key(id), "{}").unwrap();
        }
        assert_eq!(s.scan_cache_prune("|scan:1.1|summary:1|max:9").unwrap(), 2);
        assert!(s.scan_cache_get(&key("m1")).unwrap().is_none());
        assert!(s
            .scan_cache_get(&key("m1|scan:0.1|summary:1|max:9"))
            .unwrap()
            .is_none());
        assert!(s
            .scan_cache_get(&key("m1|scan:1.1|summary:1|max:9"))
            .unwrap()
            .is_some());
        assert!(s
            .scan_cache_get(&key("m2|scan:1.1|summary:1|max:9"))
            .unwrap()
            .is_some());
    }
}
