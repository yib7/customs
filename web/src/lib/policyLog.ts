import type { PolicyFieldChange } from '../api/types';

function show(v: unknown): string {
  if (typeof v === 'string') return v;
  if (v === null || v === undefined) return 'unset';
  return JSON.stringify(v);
}

/**
 * One line for a changed policy field, as the server's webhook message words it:
 * `mode: enforce -> monitor`, or for a list the entries added and removed.
 */
export function describeFieldChange(c: PolicyFieldChange): string {
  if (Array.isArray(c.before) && Array.isArray(c.after)) {
    const before = c.before.map(show);
    const after = c.after.map(show);
    const added = after.filter((v) => !before.includes(v));
    const removed = before.filter((v) => !after.includes(v));
    const parts: string[] = [];
    if (added.length > 0) parts.push(`added ${added.join(', ')}`);
    if (removed.length > 0) parts.push(`removed ${removed.join(', ')}`);
    return `${c.field}: ${parts.length > 0 ? parts.join('; ') : 'reordered'}`;
  }
  return `${c.field}: ${show(c.before)} -> ${show(c.after)}`;
}

/** Field paths whose JSON differs between two policy objects, sorted, nested objects flattened. */
export function diffPolicies(a: Record<string, unknown>, b: Record<string, unknown>, prefix = ''): PolicyFieldChange[] {
  const out: PolicyFieldChange[] = [];
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  for (const k of keys) {
    const field = prefix ? `${prefix}.${k}` : k;
    const x = a[k];
    const y = b[k];
    const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
    if (isObj(x) && isObj(y)) out.push(...diffPolicies(x, y, field));
    else if (JSON.stringify(x) !== JSON.stringify(y)) out.push({ field, before: x ?? null, after: y ?? null });
  }
  return out;
}
