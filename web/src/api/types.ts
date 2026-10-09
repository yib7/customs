// Types mirroring docs/DESIGN.md sections 6 (Verdict), 7 (HTTP interface) and 8 (Policy).
// Every value that originates from a package (name, version, file paths, snippets,
// labels derived from registry metadata) is attacker-controlled and must only ever be
// rendered as text.

/** Known ecosystems. Unknown values from the server are passed through as strings. */
export type KnownEcosystem = 'pypi' | 'npm';
export type Ecosystem = KnownEcosystem | (string & {});

export type Decision = 'allow' | 'warn' | 'block';

export type EventKind = 'install' | 'check' | 'nonexistent_package';

/** Per-model probabilities (DESIGN.md section 6, `scores`). Null when a model did not run. */
export interface Scores {
  code_gbdt: number | null;
  code_nn: number | null;
  name: number | null;
}

export interface PolicyHit {
  rule: string;
  severity: Decision;
  detail: string;
}

export interface Reason {
  feature: string;
  value: number | null;
  /** Signed contribution to the model logit. Positive pushes toward malicious. */
  contribution: number;
  label: string | null;
}

export interface Evidence {
  indicator: string;
  file: string;
  line: number | null;
  snippet: string;
}

export interface Thresholds {
  warn: number;
  block: number;
  target_fpr_block?: number;
}

export interface Verdict {
  /** Not part of the DESIGN.md verdict body; present when the server includes it. */
  id: string | null;
  ecosystem: Ecosystem;
  name: string;
  version: string | null;
  artifact: string | null;
  sha256: string | null;
  decision: Decision;
  /** Calibrated ensemble probability in [0, 1]. Null when no archive was scanned. */
  risk: number | null;
  scores: Scores;
  policy_hits: PolicyHit[];
  reasons: Reason[];
  evidence: Evidence[];
  scanned_ms: number | null;
  model_version: string | null;
  cached: boolean;
  /** Optional extension: thresholds in effect when the verdict was made. */
  thresholds: Thresholds | null;
  /** Decision from the model alone, before policy rules. Null when the server did not say. */
  model_decision: Decision | null;
  /** Policy mode the verdict was made in; in `monitor` mode nothing is refused. */
  mode: PolicyMode | null;
}

export interface CustomsEvent {
  id: string;
  /** ISO 8601 timestamp. */
  ts: string;
  ecosystem: Ecosystem;
  name: string;
  version: string | null;
  client: string | null;
  kind: EventKind;
  decision: Decision | null;
  risk: number | null;
  verdict_id: string | null;
}

export interface DecisionCounts {
  allow: number;
  warn: number;
  block: number;
}

export interface DayCount {
  /** YYYY-MM-DD */
  date: string;
  count: number;
}

export interface TopReason {
  feature: string;
  label: string | null;
  count: number;
}

export interface Stats {
  total: number;
  by_decision: DecisionCounts;
  by_ecosystem: Record<string, DecisionCounts>;
  by_kind: Record<EventKind, number>;
  blocks_per_day: DayCount[];
  top_reasons: TopReason[];
}

export type Threshold = 'model' | number;
export type PolicyMode = 'enforce' | 'monitor';
/** Severity of a rule that can be switched off (the release history rules). */
export type RuleSeverity = 'off' | 'warn' | 'block';

/** Policy keys of the release history rules. */
export type HistoryRule =
  | 'provenance_dropped'
  | 'install_script_added'
  | 'publisher_changed'
  | 'dormant_revival'
  | 'version_anomaly'
  | 'nonregistry_dependency_added'
  | 'young_dependency_added';

/**
 * The established-release prior: a release of one of the `top` most popular names, published
 * at least `min_age_days` ago and not yanked, is allowed whatever the model scores it.
 */
export interface EstablishedPolicy {
  enabled: boolean;
  top: number;
  min_age_days: number;
}

export interface Policy {
  mode: PolicyMode;
  warn_threshold: Threshold;
  block_threshold: Threshold;
  min_age_days: number;
  min_age_severity: 'block' | 'warn';
  hide_young_versions: boolean;
  block_nonexistent: boolean;
  block_install_scripts_from_new: boolean;
  provenance_dropped: RuleSeverity;
  install_script_added: RuleSeverity;
  publisher_changed: RuleSeverity;
  dormant_revival: RuleSeverity;
  dormant_days: number;
  /** Age limit for the circumstantial history rules; 0 applies them at any age. */
  history_window_days: number;
  version_anomaly: RuleSeverity;
  nonregistry_dependency_added: RuleSeverity;
  young_dependency_added: RuleSeverity;
  young_dependency_days: number;
  unread_code: RuleSeverity;
  startup_hook: RuleSeverity;
  agent_bypass: RuleSeverity;
  scan_error: RuleSeverity;
  allow: string[];
  deny: string[];
  established: EstablishedPolicy;
  upstream: Record<string, string>;
}

export interface MetricValue {
  value: number;
  ci_low?: number;
  ci_high?: number;
}

export interface GuardDogComparison {
  /** False positive rate GuardDog achieved on the benign test set. */
  fpr: number | null;
  /** GuardDog recall at that FPR. */
  recall: number | null;
  /** Customs recall at the same (matched) FPR. */
  customs_recall: number | null;
}

export interface ModelMetrics {
  split: string | null;
  roc_auc: MetricValue | null;
  pr_auc: MetricValue | null;
  recall_at_fpr_0_001: MetricValue | null;
  recall_at_fpr_0_01: MetricValue | null;
  brier: MetricValue | null;
  n_test_malicious: number | null;
  n_test_benign: number | null;
  guarddog: GuardDogComparison | null;
}

export interface ModelInfo {
  model_version: string;
  feature_schema_version: number | null;
  thresholds: Thresholds | null;
  metrics: ModelMetrics | null;
}

export interface CheckRequest {
  ecosystem: KnownEcosystem;
  name: string;
  version: string | null;
}

export interface EventQuery {
  limit?: number;
  before?: string;
  decision?: Decision;
  ecosystem?: KnownEcosystem;
  kind?: EventKind;
  q?: string;
}

/** One field of a policy change, named by its dotted path (`mode`, `upstream.npm`). */
export interface PolicyFieldChange {
  field: string;
  before: unknown;
  after: unknown;
}

/** A policy change made through PUT /api/policy, from GET /api/policy/changes. */
export interface PolicyChange {
  id: number;
  ts: string;
  /** Address of the connection the change came in on. */
  remote: string | null;
  /** First token of the User-Agent. */
  client: string | null;
  /** `token` when the admin token authorized it, `none` when the server needs none. */
  auth: 'token' | 'none';
  changes: PolicyFieldChange[];
}

/** One side of a release comparison (GET /api/diff). */
export interface ReleaseSide {
  version: string;
  published: string | null;
  filename: string | null;
}

/** A registry fact that differs between two releases; null means absent on that side. */
export interface MetaChange {
  /** `publisher`, `provenance`, or `install script <name>`. */
  field: string;
  before: string | null;
  after: string | null;
}

export interface DependencyChange {
  name: string;
  before: string | null;
  after: string | null;
}

export interface FileChange {
  path: string;
  size: number;
  lines_added: number | null;
  lines_removed: number | null;
}

export interface FileDiff {
  added: FileChange[];
  modified: FileChange[];
  removed: FileChange[];
  unchanged: number;
}

/** What release `to` changes relative to `from` (DESIGN.md section 7, GET /api/diff). */
export interface ReleaseDiff {
  ecosystem: Ecosystem;
  name: string;
  from: ReleaseSide;
  to: ReleaseSide;
  metadata: MetaChange[];
  dependencies: DependencyChange[];
  files: FileDiff | null;
  files_note: string | null;
  new_evidence: Evidence[];
  new_install_surface: string[];
  verdict: Verdict | null;
}
