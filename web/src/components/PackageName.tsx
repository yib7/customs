import { safeLabel } from '../lib/format';

/** Package name and version as text. Both are attacker-controlled, so they are sanitized and truncated. */
export function PackageName({ name, version, max = 60, className = '' }: { name: string; version: string | null; max?: number; className?: string }) {
  const n = safeLabel(name, max);
  const v = version ? safeLabel(version, 24) : null;
  return (
    <span className={`min-w-0 font-mono text-[13px] break-all ${className}`} title={version ? `${name}@${version}` : name}>
      <span className="font-medium text-ink">{n}</span>
      {v ? <span className="text-muted">@{v}</span> : null}
    </span>
  );
}
