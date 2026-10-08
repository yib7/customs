// Runtime-tolerant parsers for API responses. Unknown fields are ignored, missing optional
// fields get safe defaults, and values of the wrong type are treated as missing. A parser
// only throws (ParseError) when a response is unusable, for example a verdict without a name.

import type {
  CustomsEvent,
  DayCount,
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

export function asString(v: unknown): string | null {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  return null;
}

export function asNumber(v: unknown): number | null {
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

export function parseDecision(v: unknown): Decision | null {
  if (typeof v !== 'string') return null;
  const d = v.toLowerCase();
  return d === 'allow' || d === 'warn' || d === 'block' ? d : null;
}

export function parseEcosystem(v: unknown): Ecosystem {
  const s = asString(v);
  if (!s) return 'unknown';
  const lower = s.toLowerCase();
  return lower === 'pypi' || lower === 'npm' ? lower : s;
}

export function parseKind(v: unknown): EventKind {
  if (v === 'check' || v === 'nonexistent_package' || v === 'install') return v;
  if (v === 'nonexistent') return 'nonexistent_package';
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

export function parseScores(v: unknown): Scores {
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

export function parseThresholds(v: unknown): Thresholds | null {
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

export function parseVerdict(v: unknown): Verdict {
  // Some servers wrap the verdict: { verdict: {...}, id }.
  let body = v;
  let wrapperId: string | null = null;
  if (isRecord(v) && isRecord(v.verdict)) {
    body = v.verdict;
    wrapperId = asString(v.id) ?? asString(v.verdict_id);
  }
  if (!isRecord(body)) throw new ParseError('verdict is not an object');
  const name = asString(body.name);
  if (!name) throw new ParseError('verdict has no package name');
  const policyHits = compact(asArray(body.policy_hits).map(parsePolicyHit));
  const decision = parseDecision(body.decision) ?? mostSevere(policyHits.map((h) => h.severity)) ?? 'warn';
  const reasons = compact(asArray(body.reasons).map(parseReason));
  reasons.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));
  return {
    id: asString(body.id) ?? asString(body.verdict_id) ?? wrapperId,
    ecosystem: parseEcosystem(body.ecosystem),
    name,
    version: asString(body.version),
    artifact: asString(body.artifact),
    sha256: asString(body.sha256),
    decision,
    risk: asProbability(body.risk),
    scores: parseScores(body.scores),
    policy_hits: policyHits,
    reasons,
    evidence: compact(asArray(body.evidence).map(parseEvidence)),
    scanned_ms: asNumber(body.scanned_ms),
    model_version: asString(body.model_version),
    cached: asBool(body.cached, false),
    thresholds: parseThresholds(body.thresholds),
  };
}

const SEVERITY: Record<Decision, number> = { allow: 0, warn: 1, block: 2 };

export function mostSevere(decisions: Decision[]): Decision | null {
  let best: Decision | null = null;
  for (const d of decisions) {
    if (best === null || SEVERITY[d] > SEVERITY[best]) best = d;
  }
  return best;
}

export function parseEvent(v: unknown): CustomsEvent | null {
  if (!isRecord(v)) return null;
  const id = asString(v.id);
  const name = asString(v.name);
  const ts = parseTimestamp(v.ts ?? v.timestamp);
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

/** Accepts a bare array or an object wrapping one under `events`, `items`, or `data`. */
export function parseEventList(v: unknown): CustomsEvent[] {
  let list: unknown = v;
  if (isRecord(v)) list = v.events ?? v.items ?? v.data;
  return compact(asArray(list).map(parseEvent));
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
  let out: DayCount[];
  if (isRecord(v)) {
    // Map form: { "2026-10-01": 3 }
    out = Object.entries(v)
      .map(([date, count]) => ({ date, count: asNumber(count) ?? 0 }))
      .filter((d) => /^\d{4}-\d{2}-\d{2}/.test(d.date));
  } else {
    out = compact(
      asArray(v).map((item) => {
        if (Array.isArray(item)) {
          const date = asString(item[0]);
          return date ? { date, count: asNumber(item[1]) ?? 0 } : null;
        }
        if (!isRecord(item)) return null;
        const date = asString(item.date ?? item.day);
        if (!date) return null;
        return { date: date.slice(0, 10), count: asNumber(item.count ?? item.blocks ?? item.value) ?? 0 };
      }),
    );
  }
  return out.sort((a, b) => a.date.localeCompare(b.date));
}

function parseTopReasons(v: unknown): TopReason[] {
  return compact(
    asArray(v).map((item) => {
      if (!isRecord(item)) return null;
      const feature = asString(item.feature ?? item.rule);
      if (!feature) return null;
      return { feature, label: asString(item.label), count: asNumber(item.count) ?? 0 };
    }),
  ).sort((a, b) => b.count - a.count);
}

export function parseStats(v: unknown): Stats {
  const r = asRecord(v);
  const byDecision = parseDecisionCounts(r.by_decision ?? r.decisions);
  const byEcoRaw = asRecord(r.by_ecosystem ?? r.ecosystems);
  const byEcosystem: Record<string, DecisionCounts> = {};
  for (const [eco, counts] of Object.entries(byEcoRaw)) {
    byEcosystem[parseEcosystem(eco)] = parseDecisionCounts(counts);
  }
  const kinds = asRecord(r.by_kind ?? r.kinds);
  const total =
    asNumber(r.total) ?? byDecision.allow + byDecision.warn + byDecision.block;
  return {
    total,
    by_decision: byDecision,
    by_ecosystem: byEcosystem,
    by_kind: {
      install: asNumber(kinds.install) ?? 0,
      check: asNumber(kinds.check) ?? 0,
      nonexistent_package:
        asNumber(kinds.nonexistent_package) ?? asNumber(r.nonexistent_package) ?? asNumber(r.nonexistent) ?? 0,
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

export function parsePolicy(v: unknown): Policy {
  const r = isRecord(v) && isRecord(v.policy) ? v.policy : asRecord(v);
  const upstreamRaw = asRecord(r.upstream);
  const upstream: Record<string, string> = {};
  for (const [k, val] of Object.entries(upstreamRaw)) {
    if (typeof val === 'string') upstream[k] = val;
  }
  const minAge = asNumber(r.min_age_days);
  const dormantDays = asNumber(r.dormant_days);
  const youngDays = asNumber(r.young_dependency_days);
  return {
    mode: parseMode(r.mode),
    warn_threshold: parseThreshold(r.warn_threshold),
    block_threshold: parseThreshold(r.block_threshold),
    min_age_days: minAge === null ? 0 : minAge,
    block_nonexistent: asBool(r.block_nonexistent, true),
    block_install_scripts_from_new: asBool(r.block_install_scripts_from_new, true),
    provenance_dropped: parseRuleSeverity(r.provenance_dropped, 'warn'),
    install_script_added: parseRuleSeverity(r.install_script_added, 'block'),
    publisher_changed: parseRuleSeverity(r.publisher_changed, 'warn'),
    dormant_revival: parseRuleSeverity(r.dormant_revival, 'warn'),
    dormant_days: dormantDays === null ? 365 : dormantDays,
    version_anomaly: parseRuleSeverity(r.version_anomaly, 'off'),
    nonregistry_dependency_added: parseRuleSeverity(r.nonregistry_dependency_added, 'block'),
    young_dependency_added: parseRuleSeverity(r.young_dependency_added, 'block'),
    young_dependency_days: youngDays === null ? 7 : youngDays,
    unread_code: parseRuleSeverity(r.unread_code, 'block'),
    startup_hook: parseRuleSeverity(r.startup_hook, 'block'),
    scan_error: parseRuleSeverity(r.scan_error, 'block'),
    allow: asStringArray(r.allow),
    deny: asStringArray(r.deny),
    upstream,
  };
}

function parseMetric(v: unknown): MetricValue | null {
  const n = asNumber(v);
  if (n !== null) return { value: n };
  if (!isRecord(v)) return null;
  const value = asNumber(v.value ?? v.mean ?? v.point);
  if (value === null) return null;
  const m: MetricValue = { value };
  const ci = Array.isArray(v.ci) ? v.ci : Array.isArray(v.ci95) ? v.ci95 : null;
  const lo = asNumber(v.ci_low ?? v.lo ?? (ci ? ci[0] : undefined));
  const hi = asNumber(v.ci_high ?? v.hi ?? (ci ? ci[1] : undefined));
  if (lo !== null) m.ci_low = lo;
  if (hi !== null) m.ci_high = hi;
  return m;
}

function pick(r: Rec, keys: string[]): unknown {
  for (const k of keys) {
    if (r[k] !== undefined) return r[k];
  }
  return undefined;
}

function parseGuardDog(v: unknown): GuardDogComparison | null {
  if (!isRecord(v)) return null;
  const out: GuardDogComparison = {
    fpr: asNumber(v.fpr),
    recall: asNumber(v.recall),
    customs_recall: asNumber(pick(v, ['customs_recall', 'customs_recall_at_matched_fpr', 'customs_recall_at_same_fpr'])),
  };
  return out.fpr === null && out.recall === null && out.customs_recall === null ? null : out;
}

export function parseModelMetrics(v: unknown, root: Rec = {}): ModelMetrics | null {
  if (!isRecord(v)) return null;
  // Metrics may be keyed by split: { temporal: {...}, random: {...} }. Prefer temporal.
  let m: Rec = v;
  let split = asString(v.split);
  if (isRecord(v.temporal)) {
    m = v.temporal;
    split = split ?? 'temporal';
  }
  const baselines = asRecord(m.baselines ?? v.baselines ?? root.baselines);
  const out: ModelMetrics = {
    split,
    roc_auc: parseMetric(pick(m, ['roc_auc', 'auc', 'auroc'])),
    pr_auc: parseMetric(pick(m, ['pr_auc', 'average_precision', 'auprc'])),
    recall_at_fpr_0_001: parseMetric(
      pick(m, ['recall_at_fpr_0_001', 'recall_at_fpr_0.001', 'recall_at_0_1pct_fpr', 'recall_at_fpr_0_1pct']),
    ),
    recall_at_fpr_0_01: parseMetric(
      pick(m, ['recall_at_fpr_0_01', 'recall_at_fpr_0.01', 'recall_at_1pct_fpr', 'recall_at_fpr_1pct']),
    ),
    brier: parseMetric(m.brier),
    n_test_malicious: asNumber(m.n_test_malicious ?? m.n_malicious),
    n_test_benign: asNumber(m.n_test_benign ?? m.n_benign),
    guarddog: parseGuardDog(baselines.guarddog ?? m.guarddog),
  };
  return out;
}

export function parseModelInfo(v: unknown): ModelInfo {
  const r = asRecord(v);
  const manifest = asRecord(r.manifest);
  const version = asString(r.model_version) ?? asString(manifest.model_version) ?? 'unknown';
  const schema = asNumber(r.feature_schema_version ?? manifest.feature_schema_version);
  const ensemble = asRecord(r.ensemble);
  return {
    model_version: version,
    feature_schema_version: schema,
    thresholds: parseThresholds(r.thresholds ?? ensemble.thresholds ?? ensemble),
    metrics: parseModelMetrics(r.metrics, r),
  };
}
