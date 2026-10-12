import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { api } from '../api/client';
import type { FileChange, ReleaseDiff, Verdict } from '../api/types';
import { formatDateTime, safeLabel } from '../lib/format';
import { btn, errorMessage, fieldCls } from './styles';
import { Card } from './ui';
import { EvidenceList } from './VerdictParts';

const SHOWN_FILES = 30;

function orNone(v: string | null): string {
  if (v === null) return '(none)';
  if (v === '') return '(set)';
  return safeLabel(v, 200);
}

function fileDetail(sign: '+' | '~' | '-', f: FileChange): string {
  if (sign === '~' && f.lines_added !== null && f.lines_removed !== null) return `+${f.lines_added} -${f.lines_removed} lines`;
  if (sign === '+' && f.lines_added !== null) return `${f.lines_added} lines`;
  if (sign === '-' && f.lines_removed !== null) return `${f.lines_removed} lines`;
  return `${f.size} bytes`;
}

function FileList({ sign, files, label }: { sign: '+' | '~' | '-'; files: FileChange[]; label: string }) {
  if (files.length === 0) return null;
  return (
    <ul aria-label={label} className="font-mono text-xs">
      {files.slice(0, SHOWN_FILES).map((f) => (
        <li key={f.path} className="break-all">
          {sign} {safeLabel(f.path, 200)} <span className="text-muted">({fileDetail(sign, f)})</span>
        </li>
      ))}
      {files.length > SHOWN_FILES ? (
        <li className="text-muted">
          {sign} {files.length - SHOWN_FILES} more
        </li>
      ) : null}
    </ul>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="mt-4 first:mt-0">
      <h3 className="mb-1 text-xs font-semibold tracking-wide text-ink-2 uppercase">{title}</h3>
      {children}
    </div>
  );
}

function DiffBody({ d }: { d: ReleaseDiff }) {
  const when = (t: string | null) => (t ? formatDateTime(t) : 'unknown date');
  const to = safeLabel(d.to.version, 60);
  return (
    <div data-testid="release-diff">
      <p className="text-sm text-ink">
        <span className="font-mono">{safeLabel(d.from.version, 60)}</span> (published {when(d.from.published)}) to{' '}
        <span className="font-mono">{to}</span> (published {when(d.to.published)})
      </p>
      {d.metadata.length > 0 ? (
        <Section title="Registry metadata">
          <ul className="font-mono text-xs">
            {d.metadata.map((m) => (
              <li key={m.field} className="break-all">
                {safeLabel(m.field, 80)}: {orNone(m.before)} -&gt; {orNone(m.after)}
              </li>
            ))}
          </ul>
        </Section>
      ) : null}
      {d.dependencies.length > 0 ? (
        <Section title="Dependencies">
          <ul className="font-mono text-xs">
            {d.dependencies.map((c) => (
              <li key={c.name} className="break-all">
                {c.before === null
                  ? `+ ${safeLabel(c.name, 120)} ${orNone(c.after)}`
                  : c.after === null
                    ? `- ${safeLabel(c.name, 120)} ${orNone(c.before)}`
                    : `~ ${safeLabel(c.name, 120)} ${orNone(c.before)} -> ${orNone(c.after)}`}
              </li>
            ))}
          </ul>
        </Section>
      ) : null}
      <Section title="Files">
        {d.files ? (
          <>
            <p className="mb-1 text-sm text-ink-2">
              {d.files.added.length} added, {d.files.modified.length} modified, {d.files.removed.length} removed,{' '}
              {d.files.unchanged} unchanged
            </p>
            <FileList sign="+" files={d.files.added} label="Added files" />
            <FileList sign="~" files={d.files.modified} label="Modified files" />
            <FileList sign="-" files={d.files.removed} label="Removed files" />
          </>
        ) : (
          <p className="text-sm text-muted">Not compared{d.files_note ? `: ${safeLabel(d.files_note, 200)}` : ''}.</p>
        )}
      </Section>
      {d.new_install_surface.length > 0 ? (
        <Section title={`Install-time code new in ${to}`}>
          <ul className="font-mono text-xs">
            {d.new_install_surface.map((e) => (
              <li key={e} className="break-all">
                {safeLabel(e, 200)}
              </li>
            ))}
          </ul>
        </Section>
      ) : null}
      <Section title={`Scanner findings new in ${to}`}>
        {d.new_evidence.length > 0 ? (
          <EvidenceList evidence={d.new_evidence} />
        ) : (
          <p className="text-sm text-muted">None: every finding in {to} was already in {safeLabel(d.from.version, 60)}.</p>
        )}
      </Section>
    </div>
  );
}

/**
 * Compares the verdict's release with an earlier one (GET /api/diff) on request: the
 * comparison downloads and scans the earlier release, so it does not run on page load.
 */
export function ReleaseDiffCard({ verdict }: { verdict: Verdict }) {
  const [from, setFrom] = useState('');
  const [diff, setDiff] = useState<ReleaseDiff | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const ctrl = useRef<AbortController | null>(null);
  useEffect(() => () => ctrl.current?.abort(), []);
  if (!verdict.version) return null;
  const version = verdict.version;

  const compare = (e: FormEvent) => {
    e.preventDefault();
    ctrl.current?.abort();
    const c = new AbortController();
    ctrl.current = c;
    setBusy(true);
    setError(null);
    api
      .diff({ ecosystem: verdict.ecosystem, name: verdict.name, to: version, from: from.trim() || undefined }, c.signal)
      .then(
        (d) => {
          setDiff(d);
          setBusy(false);
        },
        (err: unknown) => {
          if (err instanceof DOMException && err.name === 'AbortError') return;
          setDiff(null);
          setError(errorMessage(err));
          setBusy(false);
        },
      );
  };

  return (
    <Card
      id="release-diff"
      title="Changes since an earlier release"
      description="Files, dependencies, install scripts and scanner findings this release adds. Comparing downloads and scans the earlier release."
      className="mt-4"
    >
      <form className="flex flex-wrap items-end gap-2" onSubmit={compare}>
        <label className="flex min-w-0 flex-col gap-1 text-xs text-ink-2">
          Earlier version
          <input
            className={`${fieldCls} w-44 font-mono`}
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            placeholder="the previous release"
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        <button type="submit" className={btn.secondary} disabled={busy}>
          {busy ? 'Comparing...' : 'Compare'}
        </button>
      </form>
      {error ? (
        <p role="alert" className="mt-3 text-sm text-block-ink">
          {safeLabel(error, 300)}
        </p>
      ) : null}
      {diff ? (
        <div className="mt-4">
          <DiffBody d={diff} />
        </div>
      ) : null}
    </Card>
  );
}
