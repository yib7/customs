import type { TopReason } from '../api/types';
import { featureLabel, policyRuleLabel } from '../lib/features';
import { formatCount, safeLabel } from '../lib/format';

function reasonLabel(r: TopReason): string {
  if (r.label) return safeLabel(r.label, 90);
  if (/^(block_|min_age|deny)/.test(r.feature)) return policyRuleLabel(r.feature);
  return featureLabel(r.feature);
}

export function TopReasons({ reasons }: { reasons: TopReason[] }) {
  if (reasons.length === 0) return <p className="text-sm text-muted">No warnings or blocks yet.</p>;
  const max = Math.max(1, ...reasons.map((r) => r.count));
  return (
    <ol className="flex flex-col gap-3">
      {reasons.slice(0, 6).map((r) => (
        <li key={r.feature} className="min-w-0">
          <div className="flex items-baseline justify-between gap-3">
            <span className="min-w-0 truncate text-sm text-ink" title={reasonLabel(r)}>
              {reasonLabel(r)}
            </span>
            <span className="shrink-0 text-xs text-ink-2 tabular">{formatCount(r.count)}</span>
          </div>
          <div className="mt-1 flex items-center gap-2">
            <div className="h-1.5 flex-1 rounded-full bg-surface-3">
              <div className="h-full rounded-full bg-accent" style={{ width: `${(r.count / max) * 100}%` }} />
            </div>
            <code className="hidden max-w-[45%] truncate font-mono text-[11px] text-muted sm:block">{safeLabel(r.feature, 40)}</code>
          </div>
        </li>
      ))}
    </ol>
  );
}
