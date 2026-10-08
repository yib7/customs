//! Webhook notifications for warn and block verdicts (`customs serve --notify-url`).
//!
//! A background task follows the same event stream as the dashboard's live view and posts
//! one message per new verdict at or above the configured decision. Repeats of the same
//! verdict (an agent retrying an install) are sent once per [`REPEAT_WINDOW`], and a token
//! bucket caps bursts; what it holds back is counted in the next message that goes out.
//! Every policy change made through the API is announced too, outside the rate limit:
//! they are rare, and switching to monitor mode turns protection off for everyone.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use customs_model::Decision;
use serde_json::{json, Value};
use tokio::sync::broadcast::error::RecvError;

use crate::config::Mode;
use crate::engine::Engine;
use crate::policy_log::{describe, loosens, PolicyChange};
use crate::util::ecosystem_str;
use crate::verdict::{Event, EventKind, Verdict};

/// The same package, version and decision is announced once per window.
pub const REPEAT_WINDOW: Duration = Duration::from_secs(3600);
/// Burst size of the token bucket.
const BURST: f64 = 20.0;
/// Tokens added per second (20 per minute).
const REFILL_PER_SEC: f64 = 20.0 / 60.0;
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Delays before the second and third attempt.
const RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(4)];
/// Discord rejects content over 2000 characters; Slack truncates far later.
const MAX_TEXT_CHARS: usize = 1900;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// `{"text", "event", "verdict", "url"}`, for any receiver that reads JSON.
    Json,
    /// Slack incoming webhook: `{"text"}` with Slack's escaping.
    Slack,
    /// Discord webhook: `{"content"}` with mentions disabled.
    Discord,
}

impl Format {
    /// Pick the format from the webhook's host when none was given.
    pub fn detect(url: &str) -> Format {
        let host = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
            .unwrap_or_default();
        if host == "hooks.slack.com" {
            Format::Slack
        } else if [
            "discord.com",
            "discordapp.com",
            "ptb.discord.com",
            "canary.discord.com",
        ]
        .contains(&host.as_str())
        {
            Format::Discord
        } else {
            Format::Json
        }
    }
}

#[derive(Debug, Clone)]
pub struct NotifyConfig {
    pub url: String,
    pub format: Format,
    /// The least severe decision that is announced.
    pub min_decision: Decision,
    /// Base URL of the dashboard, for links to the verdict page.
    pub public_url: Option<String>,
}

impl NotifyConfig {
    pub fn validate(&self) -> Result<(), String> {
        let u = url::Url::parse(&self.url).map_err(|e| format!("notify URL: {e}"))?;
        if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
            return Err("notify URL must be an http or https URL with a host".into());
        }
        if self.min_decision == Decision::Allow {
            return Err("notifications start at warn or block".into());
        }
        Ok(())
    }

    /// The webhook's host, for logs: the path of a webhook URL is its secret.
    pub fn host(&self) -> String {
        url::Url::parse(&self.url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_default()
    }
}

/// Repeat suppression and the token bucket.
#[derive(Debug)]
pub struct Limiter {
    last_sent: HashMap<String, Instant>,
    tokens: f64,
    refilled: Instant,
    /// Messages held back since the last one sent.
    pub held: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Admit {
    Send,
    Repeat,
    RateLimited,
}

impl Limiter {
    pub fn new(now: Instant) -> Self {
        Self {
            last_sent: HashMap::new(),
            tokens: BURST,
            refilled: now,
            held: 0,
        }
    }

    pub fn admit(&mut self, key: &str, now: Instant) -> Admit {
        if self
            .last_sent
            .get(key)
            .is_some_and(|t| now.duration_since(*t) < REPEAT_WINDOW)
        {
            return Admit::Repeat;
        }
        let elapsed = now.duration_since(self.refilled).as_secs_f64();
        self.tokens = (self.tokens + elapsed * REFILL_PER_SEC).min(BURST);
        self.refilled = now;
        if self.tokens < 1.0 {
            self.held += 1;
            return Admit::RateLimited;
        }
        self.tokens -= 1.0;
        if self.last_sent.len() > 10_000 {
            self.last_sent
                .retain(|_, t| now.duration_since(*t) < REPEAT_WINDOW);
        }
        self.last_sent.insert(key.to_string(), now);
        Admit::Send
    }
}

fn repeat_key(ev: &Event) -> String {
    format!(
        "{}:{}@{}:{}",
        ecosystem_str(ev.ecosystem),
        ev.name,
        ev.version.as_deref().unwrap_or(""),
        ev.decision.map_or("", |d| d.as_str())
    )
}

/// The message text, before any receiver-specific escaping.
pub fn message(ev: &Event, v: &Verdict, link: Option<&str>, held: u64) -> String {
    let eco = ecosystem_str(ev.ecosystem);
    let what = match &ev.version {
        Some(ver) => format!("{eco} package {} {ver}", ev.name),
        None => format!("{eco} package {}", ev.name),
    };
    let verb = match (v.decision, v.mode) {
        (Decision::Block, Mode::Enforce) => "blocked",
        (Decision::Block, Mode::Monitor) => "would block (monitor mode, served)",
        _ => "warned on",
    };
    let how = match ev.kind {
        EventKind::Install => "install",
        EventKind::Check => "check",
        EventKind::NonexistentPackage => "a name the registry does not know",
    };
    let mut text = format!("Customs {verb} {what} ({how}");
    if let Some(c) = ev.client.as_deref().filter(|c| !c.is_empty()) {
        text.push_str(&format!(", client {c}"));
    }
    text.push_str(")\n");
    text.push_str(&v.headline());
    if let Some(l) = link {
        text.push('\n');
        text.push_str(l);
    }
    if held > 0 {
        text.push_str(&format!(
            "\n({held} earlier notification{} held back by the rate limit; see the dashboard)",
            if held == 1 { "" } else { "s" }
        ));
    }
    if text.chars().count() > MAX_TEXT_CHARS {
        text = text.chars().take(MAX_TEXT_CHARS - 3).collect::<String>() + "...";
    }
    text
}

fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn payload(format: Format, text: &str, ev: &Event, v: &Verdict, link: Option<&str>) -> Value {
    match format {
        Format::Slack => json!({ "text": slack_escape(text) }),
        // A scoped npm name such as `@everyone/x` must not ping a channel.
        Format::Discord => json!({ "content": text, "allowed_mentions": { "parse": [] } }),
        Format::Json => json!({
            "text": text,
            "event": ev,
            "verdict": {
                "id": v.id,
                "decision": v.decision,
                "mode": v.mode,
                "risk": v.risk,
                "headline": v.headline(),
                "policy_hits": v.policy_hits,
                "reasons": v.reasons.iter().take(5).map(|r| &r.label).collect::<Vec<_>>(),
                "artifact": v.artifact,
                "sha256": v.sha256,
            },
            "url": link,
        }),
    }
}

/// Text for a policy change: who made it, then one line per changed field. A change
/// that can let through what the old policy stopped says so first.
pub fn policy_message(ch: &PolicyChange, link: Option<&str>) -> String {
    let verb = if ch.changes.iter().any(loosens) {
        "loosened"
    } else {
        "changed"
    };
    let mut who = Vec::new();
    if let Some(r) = &ch.remote {
        who.push(format!("from {r}"));
    }
    if let Some(c) = &ch.client {
        who.push(format!("client {c}"));
    }
    who.push(if ch.auth == "token" {
        "with the admin token".into()
    } else {
        "without a token".into()
    });
    let mut text = format!("Customs policy {verb} ({})", who.join(", "));
    for c in &ch.changes {
        text.push_str("\n- ");
        text.push_str(&describe(c));
    }
    if let Some(l) = link {
        text.push('\n');
        text.push_str(l);
    }
    if text.chars().count() > MAX_TEXT_CHARS {
        text = text.chars().take(MAX_TEXT_CHARS - 3).collect::<String>() + "...";
    }
    text
}

pub fn policy_payload(format: Format, text: &str, ch: &PolicyChange) -> Value {
    match format {
        Format::Slack => json!({ "text": slack_escape(text) }),
        Format::Discord => json!({ "content": text, "allowed_mentions": { "parse": [] } }),
        Format::Json => json!({
            "text": text,
            "policy_change": ch,
            "loosened": ch.changes.iter().any(loosens),
        }),
    }
}

/// Follow the engine's events until the process exits.
pub fn spawn(engine: Arc<Engine>, cfg: NotifyConfig) -> tokio::task::JoinHandle<()> {
    let rx = engine.subscribe();
    let policy_rx = engine.subscribe_policy_changes();
    tokio::spawn(run(engine, cfg, rx, policy_rx))
}

async fn send(engine: &Engine, cfg: &NotifyConfig, body: &Value, what: &str) {
    match deliver(engine, &cfg.url, body).await {
        Ok(()) => engine.metrics.notification("sent"),
        Err(e) => {
            engine.metrics.notification("failed");
            tracing::warn!(host = %cfg.host(), what, "webhook notification failed: {e}");
        }
    }
}

async fn run(
    engine: Arc<Engine>,
    cfg: NotifyConfig,
    mut rx: tokio::sync::broadcast::Receiver<Event>,
    mut policy_rx: tokio::sync::broadcast::Receiver<PolicyChange>,
) {
    let host = cfg.host();
    tracing::info!(%host, format = ?cfg.format, on = cfg.min_decision.as_str(), "webhook notifications on");
    let mut limiter = Limiter::new(Instant::now());
    let mut policy_open = true;
    loop {
        let received = tokio::select! {
            r = rx.recv() => r,
            ch = policy_rx.recv(), if policy_open => {
                match ch {
                    Ok(ch) => {
                        let link = cfg
                            .public_url
                            .as_deref()
                            .map(|base| format!("{}/policy", base.trim_end_matches('/')));
                        let text = policy_message(&ch, link.as_deref());
                        send(&engine, &cfg, &policy_payload(cfg.format, &text, &ch), "policy change").await;
                    }
                    Err(RecvError::Lagged(_)) => engine.metrics.notification("dropped"),
                    Err(RecvError::Closed) => policy_open = false,
                }
                continue;
            }
        };
        let ev = match received {
            Ok(ev) => ev,
            Err(RecvError::Lagged(n)) => {
                limiter.held += n;
                engine.metrics.notification("dropped");
                continue;
            }
            Err(RecvError::Closed) => return,
        };
        if ev.decision.is_none_or(|d| d < cfg.min_decision) {
            continue;
        }
        match limiter.admit(&repeat_key(&ev), Instant::now()) {
            Admit::Send => {}
            Admit::Repeat => {
                engine.metrics.notification("repeat");
                continue;
            }
            Admit::RateLimited => {
                engine.metrics.notification("rate_limited");
                continue;
            }
        }
        let Some(v) = ev
            .verdict_id
            .and_then(|id| engine.store.verdict(id).ok().flatten())
        else {
            continue;
        };
        let link = cfg.public_url.as_deref().and_then(|base| {
            v.id.map(|id| format!("{}/verdicts/{id}", base.trim_end_matches('/')))
        });
        let held = std::mem::take(&mut limiter.held);
        let text = message(&ev, &v, link.as_deref(), held);
        let body = payload(cfg.format, &text, &ev, &v, link.as_deref());
        send(&engine, &cfg, &body, &ev.name).await;
    }
}

async fn deliver(engine: &Engine, url: &str, body: &Value) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 0..=RETRY_DELAYS.len() {
        if attempt > 0 {
            tokio::time::sleep(RETRY_DELAYS[attempt - 1]).await;
        }
        let r = engine
            .registry
            .client()
            .post(url)
            .timeout(SEND_TIMEOUT)
            .json(body)
            .send()
            .await;
        match r {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            // A 4xx other than 429 will not change on retry (a revoked or wrong URL).
            Ok(resp)
                if resp.status().is_client_error()
                    && resp.status() != reqwest::StatusCode::TOO_MANY_REQUESTS =>
            {
                return Err(format!("HTTP {}", resp.status().as_u16()));
            }
            Ok(resp) => last = format!("HTTP {}", resp.status().as_u16()),
            // reqwest errors carry the URL, whose path is the webhook's secret.
            Err(e) => last = e.without_url().to_string(),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::PolicyHit;
    use customs_scan::Ecosystem;

    fn event(decision: Decision) -> Event {
        Event {
            id: 1,
            ts: "2026-01-01T00:00:00Z".into(),
            ecosystem: Ecosystem::Npm,
            name: "@everyone/evil".into(),
            version: Some("1.0.0".into()),
            client: Some("127.0.0.1".into()),
            kind: EventKind::Install,
            decision: Some(decision),
            risk: Some(0.97),
            verdict_id: Some(7),
        }
    }

    fn verdict(mode: Mode) -> Verdict {
        let mut v: Verdict = serde_json::from_value(json!({
            "id": 7, "ts": "t", "ecosystem": "npm", "name": "@everyone/evil",
            "version": "1.0.0", "artifact": null, "sha256": null, "decision": "block",
            "risk": 0.97, "model_decision": "allow",
            "thresholds": {"warn": 0.5, "block": 0.9},
            "scores": {}, "policy_hits": [], "reasons": [], "evidence": [],
            "scanned_ms": 1, "model_version": "m", "cached": false, "mode": "enforce"
        }))
        .unwrap();
        v.mode = mode;
        v.policy_hits.push(PolicyHit {
            rule: "install_script_added".into(),
            severity: Decision::Block,
            detail: "postinstall <runs> curl & sh".into(),
        });
        v
    }

    #[test]
    fn detects_receivers() {
        assert_eq!(
            Format::detect("https://hooks.slack.com/services/T/B/x"),
            Format::Slack
        );
        assert_eq!(
            Format::detect("https://discord.com/api/webhooks/1/x"),
            Format::Discord
        );
        assert_eq!(Format::detect("https://alerts.example/hook"), Format::Json);
        assert_eq!(Format::detect("not a url"), Format::Json);
    }

    #[test]
    fn validates_config() {
        let mut c = NotifyConfig {
            url: "https://alerts.example/hook/secret".into(),
            format: Format::Json,
            min_decision: Decision::Block,
            public_url: None,
        };
        assert!(c.validate().is_ok());
        assert_eq!(c.host(), "alerts.example");
        c.url = "file:///etc/passwd".into();
        assert!(c.validate().is_err());
        c.url = "https://alerts.example/".into();
        c.min_decision = Decision::Allow;
        assert!(c.validate().is_err());
    }

    #[test]
    fn message_names_package_rule_and_link() {
        let ev = event(Decision::Block);
        let v = verdict(Mode::Enforce);
        let t = message(&ev, &v, Some("http://c:7878/verdicts/7"), 0);
        assert!(
            t.starts_with(
                "Customs blocked npm package @everyone/evil 1.0.0 (install, client 127.0.0.1)\n"
            ),
            "{t}"
        );
        assert!(t.contains("install_script_added: postinstall"), "{t}");
        assert!(t.ends_with("http://c:7878/verdicts/7"), "{t}");
        let t = message(&ev, &verdict(Mode::Monitor), None, 3);
        assert!(t.contains("would block (monitor mode, served)"), "{t}");
        assert!(t.contains("3 earlier notifications held back"), "{t}");
    }

    #[test]
    fn policy_change_message() {
        let mut ch = PolicyChange {
            id: 3,
            ts: "t".into(),
            remote: Some("10.0.0.5".into()),
            client: Some("Mozilla/5.0".into()),
            auth: "token".into(),
            changes: vec![crate::policy_log::FieldChange {
                field: "mode".into(),
                before: json!("enforce"),
                after: json!("monitor"),
            }],
        };
        let t = policy_message(&ch, Some("http://c:7878/policy"));
        assert_eq!(
            t,
            "Customs policy loosened (from 10.0.0.5, client Mozilla/5.0, with the admin token)\n\
             - mode: enforce -> monitor\nhttp://c:7878/policy"
        );
        ch.changes[0].before = json!("monitor");
        ch.changes[0].after = json!("enforce");
        ch.auth = "none".into();
        ch.client = None;
        let t = policy_message(&ch, None);
        assert_eq!(
            t,
            "Customs policy changed (from 10.0.0.5, without a token)\n- mode: monitor -> enforce"
        );
        let j = policy_payload(Format::Json, &t, &ch);
        assert_eq!(j["loosened"], json!(false));
        assert_eq!(j["policy_change"]["changes"][0]["after"], json!("enforce"));
    }

    #[test]
    fn payloads_escape_for_their_receiver() {
        let ev = event(Decision::Block);
        let v = verdict(Mode::Enforce);
        let text = message(&ev, &v, None, 0);
        let s = payload(Format::Slack, &text, &ev, &v, None);
        let s = s["text"].as_str().unwrap();
        assert!(
            s.contains("&lt;runs&gt; curl &amp; sh") && !s.contains('<'),
            "{s}"
        );
        let d = payload(Format::Discord, &text, &ev, &v, None);
        assert_eq!(d["allowed_mentions"]["parse"], json!([]));
        let j = payload(Format::Json, &text, &ev, &v, Some("http://x/verdicts/7"));
        assert_eq!(j["verdict"]["decision"], "block");
        assert_eq!(j["event"]["name"], "@everyone/evil");
        assert_eq!(j["url"], "http://x/verdicts/7");
    }

    #[test]
    fn long_messages_are_cut() {
        let ev = event(Decision::Block);
        let mut v = verdict(Mode::Enforce);
        v.policy_hits[0].detail = "x".repeat(5000);
        assert_eq!(message(&ev, &v, None, 0).chars().count(), MAX_TEXT_CHARS);
    }

    #[test]
    fn repeats_and_bursts_are_held() {
        let t0 = Instant::now();
        let mut l = Limiter::new(t0);
        assert_eq!(l.admit("a", t0), Admit::Send);
        assert_eq!(l.admit("a", t0 + Duration::from_secs(60)), Admit::Repeat);
        assert_eq!(l.admit("a", t0 + REPEAT_WINDOW), Admit::Send);
        let mut l = Limiter::new(t0);
        for i in 0..20 {
            assert_eq!(l.admit(&format!("k{i}"), t0), Admit::Send);
        }
        assert_eq!(l.admit("k20", t0), Admit::RateLimited);
        assert_eq!(l.held, 1);
        // Three seconds refill one token.
        assert_eq!(l.admit("k21", t0 + Duration::from_secs(3)), Admit::Send);
    }
}
