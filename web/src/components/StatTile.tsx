import type { ReactNode } from 'react';

export function StatTile({
  label,
  value,
  sub,
  icon,
  tone = 'neutral',
  testId,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  icon?: ReactNode;
  tone?: 'neutral' | 'allow' | 'warn' | 'block' | 'ghost';
  testId?: string;
}) {
  const iconCls = {
    neutral: 'bg-surface-3 text-ink-2',
    allow: 'bg-allow-soft text-allow-ink',
    warn: 'bg-warn-soft text-warn-ink',
    block: 'bg-block-soft text-block-ink',
    ghost: 'bg-ghost-soft text-ghost-ink',
  }[tone];
  return (
    <div className="min-w-0 rounded-xl border border-line bg-surface p-4 shadow-card" data-testid={testId}>
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-medium text-ink-2">{label}</p>
        {icon ? <span className={`grid h-7 w-7 shrink-0 place-items-center rounded-lg ${iconCls}`}>{icon}</span> : null}
      </div>
      <p className="mt-1 text-2xl font-semibold tracking-tight text-ink sm:text-[28px]">{value}</p>
      {sub ? <p className="mt-0.5 text-xs text-muted">{sub}</p> : null}
    </div>
  );
}
