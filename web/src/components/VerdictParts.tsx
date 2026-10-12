import type { Decision, Evidence, PolicyHit, Reason, Scores, Thresholds } from '../api/types';
import { featureLabel, indicatorDescription, indicatorLabel, policyRuleLabel } from '../lib/features';
import { formatPercent, formatSigned, hasInvisible, safeLabel, safeSnippet, truncateMiddle } from '../lib/format';
import { DecisionBadge } from './Badges';
import { IconFile, IconInfo } from './Icons';

const SCORE_ROWS: { key: keyof Scores; label: string; help: string }[] = [
  { key: 'code_gbdt', label: 'Code model', help: 'Gradient-boosted trees over static code features' },
  { key: 'code_nn', label: 'Code neural net', help: 'Convolutional network over install-time code tokens' },
  { key: 'name', label: 'Name model', help: 'Typosquat and lookalike-name signals' },
];

export function ComponentScores({ scores, thresholds }: { scores: Scores; thresholds: Thresholds | null }) {
  return (
    <ul className="flex flex-col gap-3" aria-label="Component model scores">
      {SCORE_ROWS.map(({ key, label, help }) => {
        const v = scores[key];
        return (
          <li key={key}>
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-sm font-medium text-ink">{label}</span>
              <span className="text-sm text-ink tabular">{v === null ? 'not run' : formatPercent(v)}</span>
            </div>
            <p className="text-xs text-muted">{help}</p>
            <div
              className="relative mt-1.5 h-2 rounded-full bg-surface-3"
              role="meter"
              aria-label={`${label} score`}
              aria-valuemin={0}
              aria-valuemax={1}
              aria-valuenow={v ?? 0}
              aria-valuetext={v === null ? 'not run' : formatPercent(v)}
            >
              {v !== null ? (
                <div className="h-full rounded-full bg-ink-2" style={{ width: `${Math.max(1, v * 100)}%` }} />
              ) : null}
              {thresholds
                ? [thresholds.warn, thresholds.block].map((t) => (
                    <span
                      key={t}
                      className="absolute -top-0.5 h-3 w-px bg-ink"
                      style={{ left: `${t * 100}%` }}
                      aria-hidden="true"
                    />
                  ))
                : null}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

export function PolicyHits({ hits, decision }: { hits: PolicyHit[]; decision: Decision }) {
  if (hits.length === 0) {
    return (
      <p className="text-sm text-ink-2">
        No policy rules matched. The decision comes from the model risk alone.
      </p>
    );
  }
  return (
    <ul className="flex flex-col gap-2" aria-label="Policy rules that matched">
      {hits.map((h, i) => (
        <li key={`${h.rule}-${i}`} className="flex items-start gap-3 rounded-lg border border-line bg-surface-2 px-3 py-2">
          <DecisionBadge decision={h.severity} size="sm" />
          <div className="min-w-0">
            <p className="text-sm font-medium text-ink">{policyRuleLabel(h.rule)}</p>
            <p className="text-xs break-words text-ink-2">
              <code className="font-mono text-muted">{safeLabel(h.rule, 40)}</code>
              {h.detail ? <>: {safeLabel(h.detail, 200)}</> : null}
            </p>
          </div>
        </li>
      ))}
      <li className="text-xs text-muted">{precedence(hits, decision)}</li>
    </ul>
  );
}

/** How the server combined the rules with the model (`PolicyOutcome::decide_with` in policy.rs). */
function precedence(hits: PolicyHit[], decision: Decision): string {
  const has = (rule: string) => hits.some((h) => h.rule === rule);
  if (has('deny')) return 'The deny list blocks this package outright, whatever the model and the other rules say.';
  if (has('allow')) return 'The allow list allows this package outright, whatever the model and the other rules say.';
  if (has('established')) {
    return `The established-release rule sets the model decision aside; the final decision (${decision}) is the most severe of the rules above.`;
  }
  return `The final decision (${decision}) is the most severe of the model decision and every rule above.`;
}

export function ContributionBars({ reasons, limit = 10 }: { reasons: Reason[]; limit?: number }) {
  if (reasons.length === 0) {
    return <p className="text-sm text-muted">The model did not report feature contributions for this verdict.</p>;
  }
  const shown = reasons.slice(0, limit);
  const max = Math.max(0.01, ...shown.map((r) => Math.abs(r.contribution)));
  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-ink-2" aria-hidden="true">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-4 rounded-sm" style={{ background: 'var(--c-neg)' }} />
          Pushes toward safe (left, minus)
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-4 rounded-sm" style={{ background: 'var(--c-pos)' }} />
          Pushes toward malicious (right, plus)
        </span>
      </div>
      <ul className="flex flex-col gap-3" aria-label="Feature contributions" data-testid="reasons">
        {shown.map((r, i) => {
          const pct = (Math.abs(r.contribution) / max) * 50;
          const positive = r.contribution > 0;
          const label = r.label ? safeLabel(r.label, 140) : featureLabel(r.feature);
          return (
            <li key={`${r.feature}-${i}`} className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_3.5rem] sm:items-center">
              <div className="min-w-0">
                <p className="text-sm text-ink">{label}</p>
                <p className="truncate font-mono text-[11px] text-muted">
                  {safeLabel(r.feature, 48)}
                  {r.value !== null ? ` = ${Number.isInteger(r.value) ? r.value : r.value.toFixed(2)}` : ''}
                </p>
              </div>
              <div className="flex items-center gap-2 sm:contents">
                <div className="relative h-3 flex-1 rounded-sm bg-surface-2" aria-hidden="true">
                  <div className="absolute inset-y-0 left-1/2 w-px bg-line-strong" />
                  <div
                    className="absolute inset-y-0.5 rounded-sm"
                    style={{
                      background: positive ? 'var(--c-pos)' : 'var(--c-neg)',
                      left: positive ? '50%' : `${50 - pct}%`,
                      width: `${Math.max(pct, 0.6)}%`,
                    }}
                  />
                </div>
                <span className={`w-14 shrink-0 text-right font-mono text-xs tabular ${positive ? 'text-block-ink' : 'text-allow-ink'}`}>
                  <span className="sr-only">{positive ? 'toward malicious ' : 'toward safe '}</span>
                  {formatSigned(r.contribution)}
                </span>
              </div>
            </li>
          );
        })}
      </ul>
      {reasons.length > limit ? (
        <p className="mt-3 text-xs text-muted">{reasons.length - limit} smaller contributions not shown.</p>
      ) : null}
    </div>
  );
}

function EvidenceItem({ ev }: { ev: Evidence }) {
  const location = `${truncateMiddle(safeLabel(ev.file || '(unknown file)', 400), 72)}${ev.line !== null ? `:${ev.line}` : ''}`;
  const hidden = hasInvisible(ev.snippet) || hasInvisible(ev.file);
  return (
    <li className="overflow-hidden rounded-lg border border-line" data-testid="evidence-item">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-line bg-surface-2 px-3 py-2">
        <span
          className="rounded bg-surface-3 px-1.5 py-0.5 text-[11px] font-semibold tracking-wide text-ink-2 uppercase"
          title={indicatorDescription(ev.indicator)}
        >
          {indicatorLabel(ev.indicator)}
        </span>
        <span className="flex min-w-0 items-center gap-1 font-mono text-xs text-ink-2" title={ev.file}>
          <IconFile size={13} className="shrink-0" />
          <span className="min-w-0 break-all">{location}</span>
        </span>
      </div>
      {ev.snippet ? (
        <pre className="m-0 overflow-x-auto bg-code px-3 py-2.5 font-mono text-xs leading-relaxed whitespace-pre-wrap text-ink [overflow-wrap:anywhere]">
          <code data-testid="evidence-snippet">{safeSnippet(ev.snippet)}</code>
        </pre>
      ) : null}
      {hidden ? (
        <p className="flex items-center gap-1.5 border-t border-line px-3 py-1.5 text-xs text-warn-ink">
          <IconInfo size={13} />
          Contains invisible or bidirectional control characters, shown as &lt;U+XXXX&gt;. These can make code look different from what runs.
        </p>
      ) : null}
    </li>
  );
}

export function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  if (evidence.length === 0) {
    return <p className="text-sm text-muted">No suspicious code locations were recorded.</p>;
  }
  return (
    <>
      <p className="mb-3 text-xs text-muted">
        Snippets come from the package itself and are shown as plain text. They were never executed.
      </p>
      <ul className="flex flex-col gap-3" aria-label="Evidence">
        {evidence.slice(0, 50).map((ev, i) => (
          <EvidenceItem key={`${ev.file}-${ev.line}-${i}`} ev={ev} />
        ))}
      </ul>
      {evidence.length > 50 ? <p className="mt-2 text-xs text-muted">{evidence.length - 50} more locations not shown.</p> : null}
    </>
  );
}
