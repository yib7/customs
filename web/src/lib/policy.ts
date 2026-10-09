import type { HistoryRule, Policy, RuleSeverity } from '../api/types';

/** Release history rules, in the order the policy page shows them. */
export const HISTORY_RULES: readonly HistoryRule[] = [
  'provenance_dropped',
  'install_script_added',
  'publisher_changed',
  'dormant_revival',
  'version_anomaly',
  'nonregistry_dependency_added',
  'young_dependency_added',
];

export type PolicyField =
  | 'mode'
  | 'warn_threshold'
  | 'block_threshold'
  | 'min_age_days'
  | 'dormant_days'
  | 'history_window_days'
  | 'young_dependency_days'
  | 'established.top'
  | 'established.min_age_days'
  | 'allow'
  | 'deny';

export type PolicyErrors = Partial<Record<PolicyField, string>>;

/** Form state: thresholds are edited as text so partial input can be shown and validated. */
export interface PolicyDraft {
  mode: Policy['mode'];
  warnModel: boolean;
  warnValue: string;
  blockModel: boolean;
  blockValue: string;
  minAgeDays: string;
  min_age_severity: Policy['min_age_severity'];
  hide_young_versions: boolean;
  block_nonexistent: boolean;
  block_install_scripts_from_new: boolean;
  history: Record<HistoryRule, RuleSeverity>;
  dormantDays: string;
  historyWindowDays: string;
  youngDependencyDays: string;
  unread_code: RuleSeverity;
  startup_hook: RuleSeverity;
  agent_bypass: RuleSeverity;
  scan_error: RuleSeverity;
  allow: string[];
  deny: string[];
  establishedEnabled: boolean;
  establishedTop: string;
  establishedMinAgeDays: string;
}

const LIST_ENTRY = /^(pypi|npm):(@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*(@[A-Za-z0-9.+!_-]+)?$/i;
const PYPI_ENTRY = /^pypi:[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?(@[A-Za-z0-9.+!_-]+)?$/;

/** Validates an allow or deny entry: `ecosystem:name` or `ecosystem:name@version`. */
export function validateListEntry(entry: string): string | null {
  const s = entry.trim();
  if (!s) return 'Entry is empty.';
  if (s.length > 260) return 'Entry is too long.';
  if (!s.includes(':')) return 'Use the form ecosystem:name, for example pypi:requests or npm:react.';
  const eco = s.slice(0, s.indexOf(':')).toLowerCase();
  if (eco !== 'pypi' && eco !== 'npm') return 'Ecosystem must be pypi or npm.';
  const ok = eco === 'pypi' ? PYPI_ENTRY.test(s) : LIST_ENTRY.test(s);
  if (!ok) return `Not a valid ${eco === 'pypi' ? 'PyPI' : 'npm'} package name. Optional version goes after @.`;
  return null;
}

export function policyToDraft(p: Policy): PolicyDraft {
  return {
    mode: p.mode,
    warnModel: p.warn_threshold === 'model',
    warnValue: p.warn_threshold === 'model' ? '' : String(p.warn_threshold),
    blockModel: p.block_threshold === 'model',
    blockValue: p.block_threshold === 'model' ? '' : String(p.block_threshold),
    minAgeDays: String(p.min_age_days),
    min_age_severity: p.min_age_severity,
    hide_young_versions: p.hide_young_versions,
    block_nonexistent: p.block_nonexistent,
    block_install_scripts_from_new: p.block_install_scripts_from_new,
    history: {
      provenance_dropped: p.provenance_dropped,
      install_script_added: p.install_script_added,
      publisher_changed: p.publisher_changed,
      dormant_revival: p.dormant_revival,
      version_anomaly: p.version_anomaly,
      nonregistry_dependency_added: p.nonregistry_dependency_added,
      young_dependency_added: p.young_dependency_added,
    },
    dormantDays: String(p.dormant_days),
    historyWindowDays: String(p.history_window_days),
    youngDependencyDays: String(p.young_dependency_days),
    unread_code: p.unread_code,
    startup_hook: p.startup_hook,
    agent_bypass: p.agent_bypass,
    scan_error: p.scan_error,
    allow: [...p.allow],
    deny: [...p.deny],
    establishedEnabled: p.established.enabled,
    establishedTop: String(p.established.top),
    establishedMinAgeDays: String(p.established.min_age_days),
  };
}

function parseThresholdText(s: string): number | null {
  const t = s.trim();
  if (!/^(0(\.\d+)?|1(\.0+)?|\.\d+)$/.test(t)) return null;
  return Number(t);
}

export interface DraftResult {
  errors: PolicyErrors;
  policy: Omit<Policy, 'upstream'> | null;
}

/** Validates a draft and converts it to a policy. `policy` is null when there are errors. */
export function validateDraft(d: PolicyDraft): DraftResult {
  const errors: PolicyErrors = {};
  let warn: Policy['warn_threshold'] = 'model';
  let block: Policy['block_threshold'] = 'model';

  if (!d.warnModel) {
    const n = parseThresholdText(d.warnValue);
    if (n === null) errors.warn_threshold = 'Enter a probability between 0 and 1, for example 0.35.';
    else warn = n;
  }
  if (!d.blockModel) {
    const n = parseThresholdText(d.blockValue);
    if (n === null) errors.block_threshold = 'Enter a probability between 0 and 1, for example 0.8.';
    else block = n;
  }
  if (typeof warn === 'number' && typeof block === 'number' && !errors.warn_threshold && !errors.block_threshold) {
    if (warn >= block) errors.block_threshold = 'Block threshold must be higher than the warn threshold.';
  }

  const ageText = d.minAgeDays.trim();
  const age = Number(ageText);
  if (!/^\d+$/.test(ageText) || !Number.isInteger(age)) errors.min_age_days = 'Enter a whole number of days (0 disables the rule).';
  else if (age > 3650) errors.min_age_days = 'Use at most 3650 days.';

  const dormantText = d.dormantDays.trim();
  const dormant = Number(dormantText);
  if (!/^\d+$/.test(dormantText) || dormant < 1 || dormant > 3650) {
    errors.dormant_days = 'Enter a whole number of days from 1 to 3650.';
  }

  const windowText = d.historyWindowDays.trim();
  const historyWindow = Number(windowText);
  if (!/^\d+$/.test(windowText) || historyWindow > 3650) {
    errors.history_window_days = 'Enter a whole number of days up to 3650 (0 applies the rules at any age).';
  }

  const youngText = d.youngDependencyDays.trim();
  const young = Number(youngText);
  if (!/^\d+$/.test(youngText) || young < 1 || young > 365) {
    errors.young_dependency_days = 'Enter a whole number of days from 1 to 365.';
  }

  const topText = d.establishedTop.trim();
  const top = Number(topText);
  if (!/^\d+$/.test(topText) || top < 1) {
    errors['established.top'] = 'Enter a whole number of at least 1 (the lists hold 5,000 names).';
  }

  const estAgeText = d.establishedMinAgeDays.trim();
  const estAge = Number(estAgeText);
  if (!/^\d+$/.test(estAgeText) || estAge < 1 || estAge > 3650) {
    errors['established.min_age_days'] = 'Enter a whole number of days from 1 to 3650.';
  }

  const badAllow = d.allow.find((e) => validateListEntry(e) !== null);
  if (badAllow !== undefined) errors.allow = `Invalid entry: ${badAllow.slice(0, 80)}`;
  const badDeny = d.deny.find((e) => validateListEntry(e) !== null);
  if (badDeny !== undefined) errors.deny = `Invalid entry: ${badDeny.slice(0, 80)}`;
  if (!errors.allow && !errors.deny) {
    const allowSet = new Set(d.allow.map((e) => e.toLowerCase()));
    const both = d.deny.find((e) => allowSet.has(e.toLowerCase()));
    if (both) errors.deny = `${both.slice(0, 80)} is also on the allow list. Remove it from one list.`;
  }

  if (Object.keys(errors).length > 0) return { errors, policy: null };
  return {
    errors,
    policy: {
      mode: d.mode,
      warn_threshold: warn,
      block_threshold: block,
      min_age_days: age,
      min_age_severity: d.min_age_severity,
      hide_young_versions: d.hide_young_versions,
      block_nonexistent: d.block_nonexistent,
      block_install_scripts_from_new: d.block_install_scripts_from_new,
      ...d.history,
      dormant_days: dormant,
      history_window_days: historyWindow,
      young_dependency_days: young,
      unread_code: d.unread_code,
      startup_hook: d.startup_hook,
      agent_bypass: d.agent_bypass,
      scan_error: d.scan_error,
      allow: d.allow.map((e) => e.trim()),
      deny: d.deny.map((e) => e.trim()),
      established: { enabled: d.establishedEnabled, top, min_age_days: estAge },
    },
  };
}
