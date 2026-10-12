// Formatting helpers. Anything that takes an attacker-controlled string returns plain text
// for React to escape; nothing here produces HTML.

import type { Ecosystem } from '../api/types';

const ELLIPSIS = '\u2026';

/** Truncates to at most `max` characters (code points), appending an ellipsis. */
export function truncate(s: string, max: number): string {
  const chars = Array.from(s);
  if (chars.length <= max) return s;
  return chars.slice(0, Math.max(0, max - 1)).join('') + ELLIPSIS;
}

/** Truncates the middle, keeping the start and end visible (useful for file paths). */
export function truncateMiddle(s: string, max: number): string {
  const chars = Array.from(s);
  if (chars.length <= max) return s;
  const keep = Math.max(2, max - 1);
  const head = Math.ceil(keep / 2);
  const tail = keep - head;
  return chars.slice(0, head).join('') + ELLIPSIS + chars.slice(chars.length - tail).join('');
}

// Bidirectional overrides and isolates (Trojan Source), zero-width characters, and other
// invisible format characters. Shown as visible markers so a snippet cannot hide code.
const INVISIBLE = /[\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;
// C0 controls other than tab and newline, DEL, and C1 controls.
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

function marker(ch: string): string {
  return `<U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}>`;
}

/** Replaces invisible, bidi-control, and control characters with visible `<U+XXXX>` markers. */
export function revealInvisible(s: string): string {
  return s.replace(INVISIBLE, marker).replace(CONTROL, marker);
}

/** True when the string contains characters that `revealInvisible` would replace. */
export function hasInvisible(s: string): boolean {
  INVISIBLE.lastIndex = 0;
  CONTROL.lastIndex = 0;
  const found = INVISIBLE.test(s) || CONTROL.test(s);
  INVISIBLE.lastIndex = 0;
  CONTROL.lastIndex = 0;
  return found;
}

/** Sanitizes an untrusted single-line label: reveals hidden characters, collapses whitespace, truncates. */
export function safeLabel(s: string, max = 120): string {
  return truncate(revealInvisible(s.replace(/[\r\n\t]+/g, ' ')), max);
}

/** Prepares an untrusted code snippet for display in a <pre>: reveal hidden characters, cap size. */
export function safeSnippet(s: string, maxChars = 600, maxLines = 12): string {
  const lines = revealInvisible(s).split('\n');
  let out = lines.slice(0, maxLines).join('\n');
  let cut = lines.length > maxLines;
  if (Array.from(out).length > maxChars) {
    out = Array.from(out).slice(0, maxChars).join('');
    cut = true;
  }
  return cut ? out + ELLIPSIS : out;
}

export function shortSha(sha: string | null, n = 12): string {
  if (!sha) return '';
  return sha.slice(0, n);
}

/** Formats a probability in [0, 1] as a percentage. */
export function formatPercent(p: number | null | undefined, digits = 1): string {
  if (p === null || p === undefined || !Number.isFinite(p)) return 'n/a';
  const pct = p * 100;
  if (pct > 0 && pct < 0.1 && digits <= 1) return '<0.1%';
  if (pct < 100 && pct > 99.9 && digits <= 1) return '>99.9%';
  return `${pct.toFixed(digits).replace(/\.0+$/, '')}%`;
}

const compactFmt = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 });
const intFmt = new Intl.NumberFormat('en-US');

export function formatCount(n: number): string {
  if (!Number.isFinite(n)) return '0';
  return Math.abs(n) >= 10000 ? compactFmt.format(n) : intFmt.format(Math.round(n));
}

export function formatSigned(n: number, digits = 2): string {
  const s = Math.abs(n).toFixed(digits);
  return n < 0 ? `\u2212${s}` : `+${s}`;
}

export function formatDuration(ms: number | null): string {
  if (ms === null || !Number.isFinite(ms)) return 'n/a';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

export function relativeTime(iso: string, now: number = Date.now()): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '';
  const diff = Math.round((now - t) / 1000);
  if (diff < 0) return 'just now';
  if (diff < 10) return 'just now';
  if (diff < 60) return `${diff}s ago`;
  const min = Math.floor(diff / 60);
  if (min < 60) return `${min} min ago`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d} d ago`;
  return new Date(t).toISOString().slice(0, 10);
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function formatDay(date: string): string {
  const d = new Date(`${date.slice(0, 10)}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return date;
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' });
}

export function ecosystemLabel(eco: Ecosystem): string {
  if (eco === 'pypi') return 'PyPI';
  if (eco === 'npm') return 'npm';
  return truncate(eco, 16);
}

const SAFE_PYPI = /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const SAFE_NPM = /^(@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i;

/** True when `name` is a syntactically valid package name for the ecosystem. */
export function isValidPackageName(eco: Ecosystem, name: string): boolean {
  if (name.length === 0 || name.length > 214) return false;
  if (eco === 'pypi') return SAFE_PYPI.test(name);
  if (eco === 'npm') return SAFE_NPM.test(name);
  return false;
}

/**
 * Registry page for a package. Built only from ecosystem constants plus the encoded name;
 * never from a URL supplied by the server or the package. Returns null for names that are
 * not valid package names.
 */
export function registryUrl(eco: Ecosystem, name: string): string | null {
  if (!isValidPackageName(eco, name)) return null;
  if (eco === 'pypi') return `https://pypi.org/project/${encodeURIComponent(name)}/`;
  if (eco === 'npm') {
    if (name.startsWith('@')) {
      const slash = name.indexOf('/');
      const scope = name.slice(1, slash);
      const pkg = name.slice(slash + 1);
      return `https://www.npmjs.com/package/@${encodeURIComponent(scope)}/${encodeURIComponent(pkg)}`;
    }
    return `https://www.npmjs.com/package/${encodeURIComponent(name)}`;
  }
  return null;
}

/** Quotes a value for POSIX shells. Plain package-like tokens are left as they are. */
export function shellQuote(s: string): string {
  if (/^[A-Za-z0-9@%+=:,./_-]+$/.test(s)) return s;
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** `ecosystem:name[@version]` as used by the policy allow and deny lists. */
export function policySpec(eco: Ecosystem, name: string, version?: string | null): string {
  return `${eco}:${name}${version ? `@${version}` : ''}`;
}

export interface PackageSpec {
  name: string;
  version: string | null;
}

/**
 * Splits user input such as `requests==2.32.3`, `requests`, `react@18.3.1`, or
 * `@types/node@22.7.4` into name and version.
 */
export function parsePackageSpec(eco: Ecosystem, input: string): PackageSpec {
  const s = input.trim();
  if (eco === 'pypi') {
    const m = /^([^=<>!~\s[]+)(?:\[[^\]]*\])?\s*(?:===?\s*([^\s,;]+))?\s*$/.exec(s);
    if (m && m[1]) return { name: m[1], version: m[2] ?? null };
    return { name: s, version: null };
  }
  const at = s.lastIndexOf('@');
  if (at > 0) return { name: s.slice(0, at), version: s.slice(at + 1) || null };
  return { name: s, version: null };
}
