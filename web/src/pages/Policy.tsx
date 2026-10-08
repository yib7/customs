import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { ApiError, api } from '../api/client';
import type { HistoryRule, ModelInfo, Policy, RuleSeverity } from '../api/types';
import { ChipInput } from '../components/ChipInput';
import { IconCheck } from '../components/Icons';
import { btn, errorMessage, inputCls } from '../components/styles';
import { Card, ErrorBox, Loading, PageHeader } from '../components/ui';
import { safeLabel } from '../lib/format';
import {
  HISTORY_RULES,
  policyToDraft,
  validateDraft,
  validateListEntry,
  type PolicyDraft,
  type PolicyErrors,
  type PolicyField,
} from '../lib/policy';
import { useTitle } from '../lib/useTitle';

function Switch({
  checked,
  onChange,
  label,
  description,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  description: string;
}) {
  return (
    <label className="flex cursor-pointer items-start justify-between gap-4 py-3">
      <span className="min-w-0">
        <span className="block text-sm font-medium text-ink">{label}</span>
        <span className="block text-xs text-muted">{description}</span>
      </span>
      <span className="relative mt-0.5 inline-flex shrink-0">
        <input
          type="checkbox"
          role="switch"
          className="peer sr-only"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
        />
        <span
          aria-hidden="true"
          className="h-6 w-11 rounded-full border border-line-strong bg-surface-3 transition-colors peer-checked:border-accent peer-checked:bg-accent peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-focus"
        />
        <span
          aria-hidden="true"
          className="absolute top-1 left-1 h-4 w-4 rounded-full bg-surface shadow transition-transform peer-checked:translate-x-5"
        />
      </span>
    </label>
  );
}

const HISTORY_RULE_TEXT: Record<HistoryRule, { label: string; description: string }> = {
  provenance_dropped: {
    label: 'Provenance dropped',
    description: 'npm: this version has no provenance attestation, but the previous release had one.',
  },
  install_script_added: {
    label: 'Install script added',
    description: 'npm: this version adds an install script or changes its command. Rare in legitimate releases, so it blocks by default.',
  },
  publisher_changed: {
    label: 'New publisher',
    description: 'npm: published by an account that published none of the previous five releases.',
  },
  dormant_revival: {
    label: 'Dormant package revived',
    description: 'The previous release is older than the dormancy period below.',
  },
  nonregistry_dependency_added: {
    label: 'Off-registry dependency added',
    description: 'npm: this version adds a git, URL or local dependency, which npm fetches without the registry and so without this proxy.',
  },
  young_dependency_added: {
    label: 'Brand-new dependency added',
    description: 'npm: this version adds a dependency first published within the window below by accounts that do not maintain this package, or one the registry does not know.',
  },
  version_anomaly: {
    label: 'Unusual version jump',
    description: 'More than one major version up, or a release on an old major line that had gone quiet. Noisy, so off by default.',
  },
};

const SEVERITY_LABELS: Record<RuleSeverity, string> = { off: 'Off', warn: 'Warn', block: 'Block' };

function SeverityField({
  id,
  label,
  description,
  value,
  onChange,
}: {
  id: string;
  label: string;
  description: string;
  value: RuleSeverity;
  onChange: (v: RuleSeverity) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-4 py-3">
      <span className="min-w-0">
        <label htmlFor={id} className="block text-sm font-medium text-ink">
          {label}
        </label>
        <span className="block text-xs text-muted">{description}</span>
      </span>
      <select
        id={id}
        className={`${inputCls} w-28 shrink-0 pr-8`}
        value={value}
        onChange={(e) => {
          const v = e.target.value;
          if (v === 'off' || v === 'warn' || v === 'block') onChange(v);
        }}
      >
        {(['off', 'warn', 'block'] as const).map((s) => (
          <option key={s} value={s}>
            {SEVERITY_LABELS[s]}
          </option>
        ))}
      </select>
    </div>
  );
}

function FieldError({ id, children }: { id: string; children?: ReactNode }) {
  if (!children) return null;
  return (
    <p id={id} className="mt-1 text-xs text-block-ink">
      {children}
    </p>
  );
}

function ThresholdField({
  name,
  label,
  modelValue,
  useModel,
  value,
  onUseModel,
  onValue,
  error,
}: {
  name: 'warn' | 'block';
  label: string;
  modelValue: number | null;
  useModel: boolean;
  value: string;
  onUseModel: (v: boolean) => void;
  onValue: (v: string) => void;
  error?: string;
}) {
  const errId = `${name}-threshold-error`;
  return (
    <fieldset className="min-w-0">
      <legend className="text-sm font-medium text-ink">{label}</legend>
      <div className="mt-2 flex flex-col gap-2">
        <label className="flex items-center gap-2 text-sm text-ink-2">
          <input
            type="radio"
            name={`${name}-threshold-mode`}
            checked={useModel}
            onChange={() => onUseModel(true)}
            className="accent-[var(--c-accent)]"
          />
          Model default{modelValue !== null ? ` (${modelValue.toFixed(2)})` : ''}
        </label>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-2 text-sm text-ink-2">
            <input
              type="radio"
              name={`${name}-threshold-mode`}
              checked={!useModel}
              onChange={() => onUseModel(false)}
              className="accent-[var(--c-accent)]"
            />
            Custom
          </label>
          <input
            type="text"
            inputMode="decimal"
            className={`${inputCls} w-28 font-mono`}
            aria-label={`${label}, custom value between 0 and 1`}
            value={value}
            placeholder={modelValue !== null ? modelValue.toFixed(2) : '0.50'}
            disabled={useModel}
            onChange={(e) => onValue(e.target.value)}
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? errId : undefined}
          />
        </div>
      </div>
      <FieldError id={errId}>{error}</FieldError>
    </fieldset>
  );
}

function PolicyForm({
  policy,
  raw,
  model,
  initiallySaved,
  onSaved,
}: {
  policy: Policy;
  raw: Record<string, unknown>;
  model: ModelInfo | null;
  initiallySaved: boolean;
  onSaved: (p: Policy, raw: Record<string, unknown>) => void;
}) {
  const initial = useMemo(() => policyToDraft(policy), [policy]);
  const [draft, setDraft] = useState<PolicyDraft>(initial);
  const [attempted, setAttempted] = useState(false);
  const [saving, setSaving] = useState(false);
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});
  const [serverMessage, setServerMessage] = useState<string | null>(null);
  const [saved, setSaved] = useState(initiallySaved);
  const statusRef = useRef<HTMLDivElement>(null);

  const { errors: clientErrors, policy: valid } = validateDraft(draft);
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);
  const errors: PolicyErrors = { ...(attempted ? clientErrors : {}) };
  for (const [f, msg] of Object.entries(serverErrors)) {
    if (!errors[f as PolicyField]) errors[f as PolicyField] = msg;
  }
  const unknownServerErrors = Object.entries(serverErrors).filter(
    ([f]) =>
      !['mode', 'warn_threshold', 'block_threshold', 'min_age_days', 'dormant_days', 'young_dependency_days', 'allow', 'deny'].includes(f),
  );

  const set = <K extends keyof PolicyDraft>(k: K, v: PolicyDraft[K], field?: PolicyField) => {
    setDraft((d) => ({ ...d, [k]: v }));
    setSaved(false);
    if (field && serverErrors[field]) {
      setServerErrors((s) => Object.fromEntries(Object.entries(s).filter(([k]) => k !== field)));
    }
  };

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setAttempted(true);
    setServerMessage(null);
    setSaved(false);
    if (!valid) {
      requestAnimationFrame(() => {
        document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
      });
      return;
    }
    setSaving(true);
    try {
      const next = await api.savePolicy({ ...valid, upstream: policy.upstream }, raw);
      setServerErrors({});
      setAttempted(false);
      setSaved(true);
      onSaved(next, { ...raw, ...next });
    } catch (err) {
      if (err instanceof ApiError) {
        setServerErrors(err.fieldErrors);
        setServerMessage(err.message);
      } else {
        setServerMessage(errorMessage(err));
      }
    } finally {
      setSaving(false);
      requestAnimationFrame(() => statusRef.current?.focus());
    }
  };

  const modelT = model?.thresholds ?? null;

  return (
    <form onSubmit={(e) => void onSubmit(e)} noValidate className="flex flex-col gap-4" aria-label="Policy">
      <div ref={statusRef} tabIndex={-1} className="outline-none" aria-live="polite">
        {serverMessage ? (
          <div role="alert" className="rounded-lg border border-block/40 bg-block-soft px-4 py-3 text-sm" data-testid="policy-server-error">
            <p className="font-medium text-block-ink">The server rejected this policy</p>
            <p className="mt-0.5 text-ink-2">{safeLabel(serverMessage, 300)}</p>
            {unknownServerErrors.length > 0 ? (
              <ul className="mt-1 list-disc pl-5 text-ink-2">
                {unknownServerErrors.map(([f, m]) => (
                  <li key={f}>
                    <code className="font-mono">{safeLabel(f, 40)}</code>: {safeLabel(m, 200)}
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        ) : null}
        {saved ? (
          <div role="status" className="flex items-center gap-2 rounded-lg border border-accent/40 bg-accent-soft px-4 py-3 text-sm text-ink" data-testid="policy-saved">
            <IconCheck size={16} /> Policy saved. New installs use it immediately.
          </div>
        ) : null}
      </div>

      <Card id="mode" title="Mode">
        <fieldset>
          <legend className="sr-only">Enforcement mode</legend>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {(
              [
                ['enforce', 'Enforce', 'Blocked packages are refused. Warned packages are allowed, and agents are asked to confirm.'],
                ['monitor', 'Monitor', 'Every verdict is recorded but nothing is refused. Useful while tuning thresholds.'],
              ] as const
            ).map(([value, title, desc]) => (
              <label
                key={value}
                className={`flex cursor-pointer gap-3 rounded-lg border p-3 has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-focus ${
                  draft.mode === value ? 'border-accent bg-accent-soft' : 'border-line-strong hover:bg-surface-2'
                }`}
              >
                <input
                  type="radio"
                  name="mode"
                  value={value}
                  checked={draft.mode === value}
                  onChange={() => set('mode', value, 'mode')}
                  className="mt-1 accent-[var(--c-accent)]"
                />
                <span>
                  <span className="block text-sm font-medium text-ink">{title}</span>
                  <span className="block text-xs text-ink-2">{desc}</span>
                </span>
              </label>
            ))}
          </div>
          <FieldError id="mode-error">{errors.mode}</FieldError>
        </fieldset>
      </Card>

      <Card id="thresholds" title="Risk thresholds" description="Probabilities from the calibrated model. Packages at or above a threshold are warned or blocked.">
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
          <ThresholdField
            name="warn"
            label="Warn threshold"
            modelValue={modelT?.warn ?? null}
            useModel={draft.warnModel}
            value={draft.warnValue}
            onUseModel={(v) => set('warnModel', v, 'warn_threshold')}
            onValue={(v) => set('warnValue', v, 'warn_threshold')}
            error={errors.warn_threshold}
          />
          <ThresholdField
            name="block"
            label="Block threshold"
            modelValue={modelT?.block ?? null}
            useModel={draft.blockModel}
            value={draft.blockValue}
            onUseModel={(v) => set('blockModel', v, 'block_threshold')}
            onValue={(v) => set('blockValue', v, 'block_threshold')}
            error={errors.block_threshold}
          />
        </div>
        {modelT?.target_fpr_block ? (
          <p className="mt-3 text-xs text-muted">
            The model's block threshold was chosen for a {(modelT.target_fpr_block * 100).toFixed(1)}% false positive rate on validation data.
          </p>
        ) : null}
      </Card>

      <Card id="registry-rules" title="Registry rules" description="Signals from registry metadata, applied before the model runs">
        <div className="max-w-xs">
          <label htmlFor="min-age" className="text-sm font-medium text-ink">
            Minimum age (days)
          </label>
          <p className="text-xs text-muted">Block versions published more recently than this. 0 disables the rule.</p>
          <input
            id="min-age"
            type="text"
            inputMode="numeric"
            className={`${inputCls} mt-2 w-28 font-mono`}
            value={draft.minAgeDays}
            onChange={(e) => set('minAgeDays', e.target.value, 'min_age_days')}
            aria-invalid={errors.min_age_days ? true : undefined}
            aria-describedby={errors.min_age_days ? 'min-age-error' : undefined}
          />
          <FieldError id="min-age-error">{errors.min_age_days}</FieldError>
        </div>
        <div className="mt-3 divide-y divide-line border-t border-line">
          <Switch
            checked={draft.block_nonexistent}
            onChange={(v) => set('block_nonexistent', v)}
            label="Block nonexistent packages"
            description="Deny agent installs of names the registry does not know. These are often hallucinated names (slopsquatting)."
          />
          <Switch
            checked={draft.block_install_scripts_from_new}
            onChange={(v) => set('block_install_scripts_from_new', v)}
            label="Block install scripts from new packages"
            description="Refuse npm packages with install scripts when they are younger than the minimum age."
          />
        </div>
      </Card>

      <Card id="scan-coverage" title="Scanner rules" description="Package contents that decide the verdict on their own, whatever the model says">
        <SeverityField
          id="rule-startup_hook"
          label="Startup hook in a .pth file"
          description="The package installs a .pth file that launches a process, opens a connection, downloads, or reads secrets. Python runs .pth import lines at every interpreter start, so the code runs in every later Python process, not only at install. No benign package in the training corpus has one, so it blocks by default."
          value={draft.startup_hook}
          onChange={(v) => set('startup_hook', v)}
        />
        <div className="border-t border-line">
          <SeverityField
            id="rule-unread_code"
            label="Code too large to scan"
            description="The package ships a code file or manifest over the scanner's 32 MiB per-file limit. The installer still runs it, and padding a payload past the limit hides it from every rule and the model. No benign package in the training corpus has one, so it blocks by default."
            value={draft.unread_code}
            onChange={(v) => set('unread_code', v)}
          />
        </div>
        <div className="border-t border-line">
          <SeverityField
            id="rule-scan_error"
            label="Archive could not be scanned"
            description="The scanner rejected the archive: over 20,000 files or 256 MiB unpacked, an archive bomb, or a corrupt or unknown format. Making a package unscannable is cheap for an attacker, and no benign package in the training corpus is, so it blocks by default."
            value={draft.scan_error}
            onChange={(v) => set('scan_error', v)}
          />
        </div>
      </Card>

      <Card
        id="release-history"
        title="Release history"
        description="Compare a version with the releases before it to catch compromised releases of established packages. These heuristics also fire on legitimate changes (new CI, new maintainers), so most warn by default and the model still judges the code. An added install script is rare in legitimate releases and blocks."
      >
        <div className="divide-y divide-line">
          {HISTORY_RULES.map((rule) => (
            <SeverityField
              key={rule}
              id={`rule-${rule}`}
              label={HISTORY_RULE_TEXT[rule].label}
              description={HISTORY_RULE_TEXT[rule].description}
              value={draft.history[rule]}
              onChange={(v) => set('history', { ...draft.history, [rule]: v })}
            />
          ))}
        </div>
        <div className="mt-3 max-w-xs border-t border-line pt-3">
          <label htmlFor="dormant-days" className="text-sm font-medium text-ink">
            Dormancy period (days)
          </label>
          <p className="text-xs text-muted">A release this long after the previous one counts as a revival.</p>
          <input
            id="dormant-days"
            type="text"
            inputMode="numeric"
            className={`${inputCls} mt-2 w-28 font-mono`}
            value={draft.dormantDays}
            onChange={(e) => set('dormantDays', e.target.value, 'dormant_days')}
            aria-invalid={errors.dormant_days ? true : undefined}
            aria-describedby={errors.dormant_days ? 'dormant-days-error' : undefined}
          />
          <FieldError id="dormant-days-error">{errors.dormant_days}</FieldError>
        </div>
        <div className="mt-3 max-w-xs border-t border-line pt-3">
          <label htmlFor="young-dependency-days" className="text-sm font-medium text-ink">
            New dependency window (days)
          </label>
          <p className="text-xs text-muted">An added dependency first published this recently counts as brand-new.</p>
          <input
            id="young-dependency-days"
            type="text"
            inputMode="numeric"
            className={`${inputCls} mt-2 w-28 font-mono`}
            value={draft.youngDependencyDays}
            onChange={(e) => set('youngDependencyDays', e.target.value, 'young_dependency_days')}
            aria-invalid={errors.young_dependency_days ? true : undefined}
            aria-describedby={errors.young_dependency_days ? 'young-dependency-days-error' : undefined}
          />
          <FieldError id="young-dependency-days-error">{errors.young_dependency_days}</FieldError>
        </div>
      </Card>

      <Card id="lists" title="Allow and deny lists" description="Exact package names, optionally pinned to a version. Lists override the model.">
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <ChipInput
            label="Always allow"
            description="For example pypi:requests or npm:react@18.3.1"
            values={draft.allow}
            onChange={(v) => set('allow', v, 'allow')}
            validate={validateListEntry}
            placeholder="pypi:name"
            error={errors.allow}
            tone="allow"
          />
          <ChipInput
            label="Always deny"
            description="For example npm:event-stream@3.3.6"
            values={draft.deny}
            onChange={(v) => set('deny', v, 'deny')}
            validate={validateListEntry}
            placeholder="npm:name@version"
            error={errors.deny}
            tone="block"
          />
        </div>
      </Card>

      {Object.keys(policy.upstream).length > 0 ? (
        <Card id="upstream" title="Upstream registries" description="Read-only here. Change these in customs.toml.">
          <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
            {Object.entries(policy.upstream).map(([k, v]) => (
              <div key={k} className="min-w-0">
                <dt className="font-mono text-muted">{safeLabel(k, 40)}</dt>
                <dd className="truncate font-mono text-ink" title={v}>
                  {safeLabel(v, 120)}
                </dd>
              </div>
            ))}
          </dl>
        </Card>
      ) : null}

      <div className="sticky bottom-0 z-10 -mx-4 flex flex-wrap items-center justify-end gap-2 border-t border-line bg-bg/95 px-4 py-3 backdrop-blur sm:mx-0 sm:rounded-xl sm:border sm:bg-surface">
        <span className="mr-auto text-xs text-muted">{dirty ? 'Unsaved changes' : 'No changes'}</span>
        <button
          type="button"
          className={btn.secondary}
          disabled={!dirty || saving}
          onClick={() => {
            setDraft(initial);
            setAttempted(false);
            setServerErrors({});
            setServerMessage(null);
          }}
        >
          Discard
        </button>
        <button type="submit" className={btn.primary} disabled={saving || !dirty}>
          {saving ? 'Saving' : 'Save policy'}
        </button>
      </div>
    </form>
  );
}

export function PolicyPage() {
  useTitle('Policy');
  const [state, setState] = useState<{ policy: Policy; raw: Record<string, unknown> } | null>(null);
  const [model, setModel] = useState<ModelInfo | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [version, setVersion] = useState(0);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const ctrl = new AbortController();
    api.policyWithRaw(ctrl.signal).then(
      (r) => {
        setState(r);
        setError(null);
      },
      (e: unknown) => {
        if (!(e instanceof DOMException && e.name === 'AbortError')) setError(e);
      },
    );
    api.model(ctrl.signal).then(setModel, () => undefined);
    return () => ctrl.abort();
  }, [tick]);

  return (
    <>
      <PageHeader
        title="Policy"
        subtitle="Rules that decide what happens after a scan. Changes apply to the running server and are written to customs.toml."
      />
      {error && !state ? <ErrorBox error={error} title="Could not load the policy" onRetry={() => setTick((t) => t + 1)} /> : null}
      {!state && !error ? <Loading label="Loading policy" /> : null}
      {state ? (
        <PolicyForm
          key={version}
          policy={state.policy}
          raw={state.raw}
          model={model}
          initiallySaved={version > 0}
          onSaved={(p, raw) => {
            setState({ policy: p, raw });
            setVersion((v) => v + 1);
          }}
        />
      ) : null}
    </>
  );
}
