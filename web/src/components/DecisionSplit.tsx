import type { Decision, DecisionCounts } from '../api/types';
import { ecosystemLabel, formatCount, formatPercent } from '../lib/format';
import { EcosystemBadge } from './Badges';
import { DECISION_META } from './decisionMeta';

const ORDER: Decision[] = ['allow', 'warn', 'block'];

function DecisionLegend() {
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-2" aria-label="Legend">
      {ORDER.map((d) => {
        const m = DECISION_META[d];
        return (
          <li key={d} className="flex items-center gap-1.5">
            <span className="decision-swatch inline-block h-2.5 w-2.5 rounded-sm" style={{ background: m.swatch }} aria-hidden="true" />
            <m.Icon size={13} />
            {m.label}
          </li>
        );
      })}
    </ul>
  );
}

export function DecisionSplit({ byEcosystem }: { byEcosystem: Record<string, DecisionCounts> }) {
  const rows = Object.entries(byEcosystem).sort(([a], [b]) => a.localeCompare(b));
  if (rows.length === 0) return <p className="text-sm text-muted">No installs recorded yet.</p>;
  return (
    <div className="flex flex-col gap-4">
      <DecisionLegend />
      {rows.map(([eco, counts]) => {
        const total = counts.allow + counts.warn + counts.block;
        const label = `${ecosystemLabel(eco)}: ${ORDER.map((d) => `${counts[d]} ${DECISION_META[d].label.toLowerCase()}`).join(', ')}`;
        return (
          <div key={eco}>
            <div className="mb-1.5 flex items-center justify-between gap-2">
              <EcosystemBadge ecosystem={eco} />
              <span className="text-xs text-muted tabular">{formatCount(total)} total</span>
            </div>
            <div className="flex h-3 w-full gap-[2px] overflow-hidden rounded" role="img" aria-label={label}>
              {total === 0 ? <div className="h-full w-full rounded bg-surface-3" /> : null}
              {ORDER.map((d) =>
                counts[d] > 0 ? (
                  <div
                    key={d}
                    className="decision-swatch h-full first:rounded-l last:rounded-r"
                    style={{
                      width: `${(counts[d] / total) * 100}%`,
                      minWidth: 4,
                      background: DECISION_META[d].swatch,
                    }}
                    title={`${DECISION_META[d].label}: ${counts[d]} (${formatPercent(counts[d] / total)})`}
                  />
                ) : null,
              )}
            </div>
            <p className="mt-1.5 flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-ink-2" aria-hidden="true">
              {ORDER.map((d) => {
                const m = DECISION_META[d];
                return (
                  <span key={d} className="flex items-center gap-1 tabular">
                    <m.Icon size={12} />
                    {formatCount(counts[d])} <span className="text-muted">{m.label.toLowerCase()}</span>
                  </span>
                );
              })}
            </p>
          </div>
        );
      })}
    </div>
  );
}
