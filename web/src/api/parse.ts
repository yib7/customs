// Runtime-tolerant parsers for API responses. Unknown fields are ignored, missing optional
// fields get safe defaults, and values of the wrong type are treated as missing. A parser
// only throws (ParseError) when a response is unusable, for example a verdict without a name.

import type {
  CustomsEvent,
  DayCount,
  DependencyChange,
  FileChange,
  FileDiff,
  MetaChange,
  ReleaseDiff,
  ReleaseSide,
  Decision,
  DecisionCounts,
  Ecosystem,
  EventKind,
  Evidence,
  GuardDogComparison,
  MetricValue,
  ModelInfo,
  ModelMetrics,
  Policy,
  PolicyChange,
  PolicyFieldChange,
  PolicyHit,
  PolicyMode,
  Reason,
  RuleSeverity,
  Scores,
  Stats,
  Threshold,
  Thresholds,
  TopReason,
  Verdict,
} from './types';

export class ParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ParseError';
  }
}

type Rec = Record<string, unknown>;

export function isRecord(v: unknown): v is Rec {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function asRecord(v: unknown): Rec {
  return isRecord(v) ? v : {};
}

function asString(v: unknown): string | null {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  return null;
}

function asNumber(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v);
    if (Number.isFinite(n)) return n;
  }
  return null;
}

function asBool(v: unknown, fallback: boolean): boolean {
  if (typeof v === 'boolean') return v;
  if (v === 'true') return true;
  if (v === 'false') return false;
  return fallback;
}

function asProbability(v: unknown): number | null {
  const n = asNumber(v);
  if (n === null) return null;
  return Math.min(1, Math.max(0, n));
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function asStringArray(v: unknown): string[] {
  return asArray(v).filter((x): x is string => typeof x === 'string');
}

function parseDecision(v: unknown): Decision | null {
  if (typeof v !== 'string') return null;
  const d = v.toLowerCase();
  return d === 'allow' || d === 'warn' || d === 'block' ? d : null;
}

function parseEcosystem(v: unknown): Ecosystem {
  const s = asString(v);
  if (!s) return 'unknown';
  const lower = s.toLowerCase();
  return lower === 'pypi' || lower === 'npm' ? lower : s;
}

function parseKind(v: unknown): EventKind {
  if (v === 'check' || v === 'nonexistent_package' || v === 'install') return v;
  return 'install';
}

/** Normalizes ISO strings, unix seconds, and unix milliseconds to an ISO string. */
export function parseTimestamp(v: unknown): string | null {
  if (typeof v === 'number' && Number.isFinite(v)) {
    const ms = v < 1e12 ? v * 1000 : v;
    const d = new Date(ms);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }
  if (typeof v === 'string' && v.trim() !== '') {
    if (/^\d+(\.\d+)?$/.test(v.trim())) return parseTimestamp(Number(v));
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }
  return null;
}

function parseScores(v: unknown): Scores {
  const r = asRecord(v);
  return {
    code_gbdt: asProbability(r.code_gbdt),
    code_nn: asProbability(r.code_nn),
    name: asProbability(r.name),
  };
}

function parsePolicyHit(v: unknown): PolicyHit | null {
  if (!isRecord(v)) return null;
  const rule = asString(v.rule);
  if (!rule) return null;
  return {
    rule,
    severity: parseDecision(v.severity) ?? 'warn',
    detail: asString(v.detail) ?? '',
  };
}

function parseReason(v: unknown): Reason | null {
  if (!isRecord(v)) return null;
  const feature = asString(v.feature);
  const contribution = asNumber(v.contribution);
  if (!feature || contribution === null) return null;
  return {
    feature,
    value: asNumber(v.value),
    contribution,
    label: asString(v.label),
  };
}

function parseEvidence(v: unknown): Evidence | null {
  if (!isRecord(v)) return null;
  const indicator = asString(v.indicator);
  if (!indicator) return null;
  const line = asNumber(v.line);
  return {
    indicator,
    file: asString(v.file) ?? '',
    line: line !== null && line >= 0 ? Math.floor(line) : null,
    snippet: asString(v.snippet) ?? '',
  };
}

function parseThresholds(v: unknown): Thresholds | null {
  if (!isRecord(v)) return null;
  const warn = asProbability(v.warn);
  const block = asProbability(v.block);
  if (warn === null || block === null) return null;
  const t: Thresholds = { warn, block };
  const target = asNumber(v.target_fpr_block);
  if (target !== null) t.target_fpr_block = target;
  return t;
}

function compact<T>(items: (T | null)[]): T[] {
  return items.filter((x): x is T => x !== null);
}

export function parseVerdict(body: unknown): Verdict {
  if (!isRecord(body)) throw new ParseError('verdict is not an object');
  const name = asString(body.name);
  if (!name) throw new ParseError('verdict has no package name');
  // Never guess a missing decision: allow-list hits carry severity allow, so a guess could
  // show a package as allowed.
  const decision = parseDecision(body.decision);
  if (!decision) throw new ParseError('verdict has no decision');
  const reasons = compact(asArray(body.reasons).map(parseReason));
  reasons.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));
  return {
    id: asString(body.id),
    ecosystem: parseEcosystem(body.ecosystem),
    name,
    version: asString(body.version),
    artifact: asString(body.artifact),
    sha256: asString(body.sha256),
    decision,
    risk: asProbability(body.risk),
    scores: parseScores(body.scores),
    policy_hits: compact(asArray(body.policy_hits).map(parsePolicyHit)),
    reasons,
    evidence: compact(asArray(body.evidence).map(parseEvidence)),
    scanned_ms: asNumber(body.scanned_ms),
    model_version: asString(body.model_version),
    cached: asBool(body.cached, false),
    thresholds: parseThresholds(body.thresholds),
    model_decision: parseDecision(body.model_decision),
    mode: body.mode === 'enforce' || body.mode === 'monitor' ? body.mode : null,
  };
}

export function parseEvent(v: unknown): CustomsEvent | null {
  if (!isRecord(v)) return null;
  const id = asString(v.id);
  const name = asString(v.name);
  const ts = parseTimestamp(v.ts);
  if (!id || !name || !ts) return null;
  const kind = parseKind(v.kind);
  return {
    id,
    ts,
    ecosystem: parseEcosystem(v.ecosystem),
    name,
    version: asString(v.version),
    client: asString(v.client),
    kind,
    decision: parseDecision(v.decision),
    risk: asProbability(v.risk),
    verdict_id: asString(v.verdict_id),
  };
}

/** `GET /api/events`: a bare array. */
export function parseEventList(v: unknown): CustomsEvent[] {
  return compact(asArray(v).map(parseEvent));
}

function parseDecisionCounts(v: unknown): DecisionCounts {
  const r = asRecord(v);
  return {
    allow: asNumber(r.allow) ?? 0,
    warn: asNumber(r.warn) ?? 0,
    block: asNumber(r.block) ?? 0,
  };
}

function parseDayCounts(v: unknown): DayCount[] {
  return compact(
    asArray(v).map((item) => {
      if (!isRecord(item)) return null;
      const date = asString(item.date);
      if (!date) return null;
      return { date: date.slice(0, 10), count: asNumber(item.count) ?? 0 };
    }),
  ).sort((a, b) => a.date.localeCompare(b.date));
}

function parseTopReasons(v: unknown): TopReason[] {
  return compact(
    asArray(v).map((item) => {
      if (!isRecord(item)) return null;
      const feature = asString(item.feature);
      if (!feature) return null;
      return { feature, label: asString(item.label), count: asNumber(item.count) ?? 0 };
    }),
  ).sort((a, b) => b.count - a.count);
}

/** `GET /api/stats` (`Stats` in `crates/customs/src/store.rs`). */
export function parseStats(v: unknown): Stats {
  const r = asRecord(v);
  const byDecision = parseDecisionCounts(r.by_decision);
  const byEcoRaw = asRecord(r.by_ecosystem);
  const byEcosystem: Record<string, DecisionCounts> = {};
  for (const [eco, counts] of Object.entries(byEcoRaw)) {
    byEcosystem[parseEcosystem(eco)] = parseDecisionCounts(counts);
  }
  const kinds = asRecord(r.by_kind);
  const total =
    asNumber(r.total) ?? byDecision.allow + byDecision.warn + byDecision.block;
  return {
    total,
    by_decision: byDecision,
    by_ecosystem: byEcosystem,
    by_kind: {
      install: asNumber(kinds.install) ?? 0,
      check: asNumber(kinds.check) ?? 0,
      nonexistent_package: asNumber(kinds.nonexistent_package) ?? 0,
    },
    blocks_per_day: parseDayCounts(r.blocks_per_day),
    top_reasons: parseTopReasons(r.top_reasons),
  };
}

function parseThreshold(v: unknown): Threshold {
  if (v === 'model') return 'model';
  const n = asNumber(v);
  return n === null ? 'model' : n;
}

function parseMode(v: unknown): PolicyMode {
  return v === 'monitor' ? 'monitor' : 'enforce';
}

function parseRuleSeverity(v: unknown, fallback: RuleSeverity): RuleSeverity {
  return v === 'off' || v === 'warn' || v === 'block' ? v : fallback;
}

/** `GET /api/policy`. Missing fields get the server's defaults (`crates/customs/src/config.rs`). */
export function parsePolicy(v: unknown): Policy {
  if (!isRecord(v)) throw new ParseError('policy is not an object');
  const r = v;
  const upstreamRaw = asRecord(r.upstream);
  const upstream: Record<string, string> = {};
  for (const [k, val] of Object.entries(upstreamRaw)) {
    if (typeof val === 'string') upstream[k] = val;
  }
  const minAge = asNumber(r.min_age_days);
  const dormantDays = asNumber(r.dormant_days);
  const historyWindow = asNumber(r.history_window_days);
  const youngDays = asNumber(r.young_dependency_days);
  const est = asRecord(r.established);
  const estTop = asNumber(est.top);
  const estAge = asNumber(est.min_age_days);
  return {
    mode: parseMode(r.mode),
    warn_threshold: parseThreshold(r.warn_threshold),
    block_threshold: parseThreshold(r.block_threshold),
    min_age_days: minAge === null ? 3 : minAge,
    min_age_severity: r.min_age_severity === 'warn' ? 'warn' : 'block',
    hide_young_versions: asBool(r.hide_young_versions, true),
    block_nonexistent: asBool(r.block_nonexistent, true),
    block_install_scripts_from_new: asBool(r.block_install_scripts_from_new, true),
    provenance_dropped: parseRuleSeverity(r.provenance_dropped, 'warn'),
    install_script_added: parseRuleSeverity(r.install_script_added, 'block'),
    publisher_changed: parseRuleSeverity(r.publisher_changed, 'warn'),
    dormant_revival: parseRuleSeverity(r.dormant_revival, 'warn'),
    dormant_days: dormantDays === null ? 365 : dormantDays,
    history_window_days: historyWindow === null ? 90 : historyWindow,
    version_anomaly: parseRuleSeverity(r.version_anomaly, 'off'),
    nonregistry_dependency_added: parseRuleSeverity(r.nonregistry_dependency_added, 'block'),
    young_dependency_added: parseRuleSeverity(r.young_dependency_added, 'block'),
    young_dependency_days: youngDays === null ? 7 : youngDays,
    unread_code: parseRuleSeverity(r.unread_code, 'block'),
    startup_hook: parseRuleSeverity(r.startup_hook, 'block'),
    agent_bypass: parseRuleSeverity(r.agent_bypass, 'block'),
    scan_error: parseRuleSeverity(r.scan_error, 'block'),
    allow: asStringArray(r.allow),
    deny: asStringArray(r.deny),
    established: {
      enabled: asBool(est.enabled, true),
      top: estTop === null ? 5000 : estTop,
      min_age_days: estAge === null ? 30 : estAge,
    },
    upstream,
  };
}

/** A bare number or `{value, ci_low, ci_high}`, as `models/metrics.json` writes them. */
function parseMetric(v: unknown): MetricValue | null {
  const n = asNumber(v);
  if (n !== null) return { value: n };
  if (!isRecord(v)) return null;
  const value = asNumber(v.value);
  if (value === null) return null;
  const m: MetricValue = { value };
  const lo = asNumber(v.ci_low);
  const hi = asNumber(v.ci_high);
  if (lo !== null) m.ci_low = lo;
  if (hi !== null) m.ci_high = hi;
  return m;
}

function parseGuardDog(v: unknown): GuardDogComparison | null {
  if (!isRecord(v)) return null;
  const out: GuardDogComparison = {
    fpr: asNumber(v.fpr),
    recall: asNumber(v.recall),
    customs_recall: asNumber(v.customs_recall_at_matched_fpr),
  };
  return out.fpr === null && out.recall === null && out.customs_recall === null ? null : out;
}

/** The `metrics` object of `models/metrics.json` (written by `python/customs_ml/evaluate.py`). */
function parseModelMetrics(m: unknown): ModelMetrics | null {
  if (!isRecord(m)) return null;
  return {
    split: asString(m.split),
    roc_auc: parseMetric(m.roc_auc),
    pr_auc: parseMetric(m.pr_auc),
    recall_at_fpr_0_001: parseMetric(m.recall_at_fpr_0_001),
    recall_at_fpr_0_01: parseMetric(m.recall_at_fpr_0_01),
    brier: parseMetric(m.brier),
    n_test_malicious: asNumber(m.n_test_malicious),
    n_test_benign: asNumber(m.n_test_benign),
    guarddog: parseGuardDog(asRecord(m.baselines).guarddog),
  };
}

/** `GET /api/model`: `thresholds` has the policy overrides applied, `model_thresholds` is the model's own. */
export function parseModelInfo(v: unknown): ModelInfo {
  const r = asRecord(v);
  return {
    model_version: asString(r.model_version) ?? 'unknown',
    feature_schema_version: asNumber(r.feature_schema_version),
    thresholds: parseThresholds(r.thresholds),
    model_thresholds: parseThresholds(r.model_thresholds),
    untrained: asBool(r.untrained, false),
    metrics: parseModelMetrics(r.metrics),
  };
}

function parsePolicyFieldChange(v: unknown): PolicyFieldChange | null {
  if (!isRecord(v)) return null;
  const field = asString(v.field);
  if (!field) return null;
  return { field, before: v.before ?? null, after: v.after ?? null };
}

/** `GET /api/policy/changes`: `{changes: [...]}`, newest first. Entries without an id are dropped. */
export function parsePolicyChanges(v: unknown): PolicyChange[] {
  const list = isRecord(v) ? asArray(v.changes) : asArray(v);
  const out: PolicyChange[] = [];
  for (const item of list) {
    if (!isRecord(item)) continue;
    const id = asNumber(item.id);
    const ts = parseTimestamp(item.ts);
    if (id === null || ts === null) continue;
    out.push({
      id,
      ts,
      remote: asString(item.remote),
      client: asString(item.client),
      auth: item.auth === 'token' ? 'token' : 'none',
      changes: compact(asArray(item.changes).map(parsePolicyFieldChange)),
    });
  }
  return out;
}

function parseReleaseSide(v: unknown): ReleaseSide | null {
  if (!isRecord(v)) return null;
  const version = asString(v.version);
  if (!version) return null;
  return { version, published: parseTimestamp(v.published), filename: asString(v.filename) };
}

function parseChange(v: unknown, key: 'field' | 'name'): { key: string; before: string | null; after: string | null } | null {
  if (!isRecord(v)) return null;
  const k = asString(v[key]);
  if (!k) return null;
  return { key: k, before: asString(v.before), after: asString(v.after) };
}

function parseFileChange(v: unknown): FileChange | null {
  if (!isRecord(v)) return null;
  const path = asString(v.path);
  if (!path) return null;
  return {
    path,
    size: Math.max(0, asNumber(v.size) ?? 0),
    lines_added: asNumber(v.lines_added),
    lines_removed: asNumber(v.lines_removed),
  };
}

function parseFileDiff(v: unknown): FileDiff | null {
  if (!isRecord(v)) return null;
  const list = (x: unknown) => compact(asArray(x).map(parseFileChange));
  return {
    added: list(v.added),
    modified: list(v.modified),
    removed: list(v.removed),
    unchanged: Math.max(0, asNumber(v.unchanged) ?? 0),
  };
}

export function parseReleaseDiff(v: unknown): ReleaseDiff {
  if (!isRecord(v)) throw new ParseError('release diff is not an object');
  const name = asString(v.name);
  const from = parseReleaseSide(v.from);
  const to = parseReleaseSide(v.to);
  if (!name || !from || !to) throw new ParseError('release diff has no package or versions');
  return {
    ecosystem: parseEcosystem(v.ecosystem),
    name,
    from,
    to,
    metadata: compact(asArray(v.metadata).map((c) => parseChange(c, 'field'))).map(
      ({ key, before, after }): MetaChange => ({ field: key, before, after }),
    ),
    dependencies: compact(asArray(v.dependencies).map((c) => parseChange(c, 'name'))).map(
      ({ key, before, after }): DependencyChange => ({ name: key, before, after }),
    ),
    files: parseFileDiff(v.files),
    files_note: asString(v.files_note),
    new_evidence: compact(asArray(v.new_evidence).map(parseEvidence)),
    new_install_surface: asStringArray(v.new_install_surface),
  };
}
