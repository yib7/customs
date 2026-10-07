import type { Decision, Ecosystem, EventKind } from '../api/types';
import { ecosystemLabel } from '../lib/format';
import { DECISION_META } from './decisionMeta';
import { IconGhost } from './Icons';

export function DecisionIcon({ decision, size = 16 }: { decision: Decision; size?: number }) {
  const { Icon } = DECISION_META[decision];
  return <Icon size={size} />;
}

export function DecisionBadge({
  decision,
  kind,
  size = 'md',
}: {
  decision: Decision | null;
  kind?: EventKind;
  size?: 'sm' | 'md' | 'lg';
}) {
  const pad = size === 'lg' ? 'px-3 py-1 text-sm gap-1.5' : size === 'sm' ? 'px-1.5 py-0.5 text-xs gap-1' : 'px-2 py-0.5 text-xs gap-1';
  const iconSize = size === 'lg' ? 18 : 14;
  if (kind === 'nonexistent_package') {
    return (
      <span className={`inline-flex items-center rounded-full font-medium whitespace-nowrap bg-ghost-soft text-ghost-ink ${pad}`}>
        <IconGhost size={iconSize} />
        Not found
      </span>
    );
  }
  if (!decision) {
    return (
      <span className={`inline-flex items-center rounded-full font-medium whitespace-nowrap bg-surface-3 text-ink-2 ${pad}`}>
        Unknown
      </span>
    );
  }
  const m = DECISION_META[decision];
  return (
    <span className={`inline-flex items-center rounded-full font-medium whitespace-nowrap ${m.cls} ${pad}`}>
      <m.Icon size={iconSize} />
      {m.label}
    </span>
  );
}

export function EcosystemBadge({ ecosystem }: { ecosystem: Ecosystem }) {
  // Ecosystems are deliberately neutral so they never compete with decision colors.
  return (
    <span
      className="inline-flex items-center rounded border border-line-strong bg-surface-2 px-1.5 py-px font-mono text-[11px] font-semibold tracking-wide text-ink-2 whitespace-nowrap"
    >
      {ecosystemLabel(ecosystem)}
    </span>
  );
}

export function KindLabel({ kind }: { kind: EventKind }) {
  const label = kind === 'install' ? 'Install' : kind === 'check' ? 'Check' : 'Nonexistent';
  return <span className="text-ink-2">{label}</span>;
}
