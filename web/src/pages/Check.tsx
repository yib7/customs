import { useRef, useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import { api } from '../api/client';
import type { KnownEcosystem, Verdict } from '../api/types';
import { IconGhost, IconSearch } from '../components/Icons';
import { VerdictView } from '../components/VerdictView';
import { btn, inputCls } from '../components/styles';
import { ErrorBox, PageHeader } from '../components/ui';
import { ecosystemLabel, isValidPackageName, parsePackageSpec, safeLabel } from '../lib/format';
import { useThresholds } from '../lib/thresholds';
import { useTitle } from '../lib/useTitle';

type Result =
  | { kind: 'verdict'; verdict: Verdict }
  | { kind: 'nonexistent'; ecosystem: KnownEcosystem; name: string; message: string }
  | { kind: 'error'; error: unknown };

/**
 * The server's reason when the registry does not know the name: the verdict's
 * `block_nonexistent` hit (a block, or a warn with the rule off). Errors, including 404s for
 * a missing version or file, are not this.
 */
function nonexistentReason(v: Verdict): string | null {
  return v.policy_hits.find((h) => h.rule === 'block_nonexistent')?.detail ?? null;
}

/** What `CheckRequest.version` takes: an exact version, a range (`>=1,<2`, `^1.2`) or a dist-tag. */
const VERSION_SPEC = /^[^\s\p{Cc}]{1,64}$/u;

export function CheckPage() {
  useTitle('Check a package');
  const [params] = useSearchParams();
  const [ecosystem, setEcosystem] = useState<KnownEcosystem>(params.get('ecosystem') === 'npm' ? 'npm' : 'pypi');
  const [name, setName] = useState(params.get('name')?.slice(0, 214) ?? '');
  const [version, setVersion] = useState(params.get('version')?.slice(0, 64) ?? '');
  const [errors, setErrors] = useState<{ name?: string; version?: string }>({});
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const ctrlRef = useRef<AbortController | null>(null);
  const nameRef = useRef<HTMLInputElement>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const thresholds = useThresholds(result?.kind === 'verdict' ? result.verdict : null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const spec = parsePackageSpec(ecosystem, name);
    const ver = version.trim() || spec.version || '';
    const next: typeof errors = {};
    if (!spec.name) next.name = 'Enter a package name.';
    else if (!isValidPackageName(ecosystem, spec.name)) {
      next.name =
        ecosystem === 'pypi'
          ? 'Not a valid PyPI name. Use letters, digits, ".", "_" and "-".'
          : 'Not a valid npm name. Use lowercase letters, digits, "-", "." and "_", with an optional @scope/.';
    }
    if (ver && !VERSION_SPEC.test(ver)) next.version = 'Not a valid version. Use a version, a range or a tag, for example 2.32.3 or >=2,<3.';
    setErrors(next);
    if (next.name || next.version) {
      if (next.name) nameRef.current?.focus();
      return;
    }
    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;
    setPending(true);
    setResult(null);
    try {
      const verdict = await api.check({ ecosystem, name: spec.name, version: ver || null }, ctrl.signal);
      const missing = nonexistentReason(verdict);
      setResult(missing === null ? { kind: 'verdict', verdict } : { kind: 'nonexistent', ecosystem, name: spec.name, message: missing });
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') return;
      setResult({ kind: 'error', error: err });
    } finally {
      if (ctrlRef.current === ctrl) setPending(false);
    }
    requestAnimationFrame(() => resultRef.current?.focus());
  };

  return (
    <>
      <PageHeader
        title="Check a package"
        subtitle="Vet a dependency before anyone installs it, for example one your coding agent just suggested. Customs fetches the archive, scans it, and applies your policy. Nothing is installed."
      />
      <form
        onSubmit={(e) => void submit(e)}
        noValidate
        className="rounded-xl border border-line bg-surface p-4 shadow-card sm:p-5"
        aria-label="Check a package"
      >
        <div className="grid grid-cols-1 gap-4 md:grid-cols-[auto_minmax(0,2fr)_minmax(0,1fr)_auto] md:items-start">
          <fieldset className="min-w-0">
            <legend className="mb-1 text-xs font-medium text-ink-2">Ecosystem</legend>
            <div className="inline-flex rounded-lg border border-line-strong bg-surface-2 p-0.5">
              {(['pypi', 'npm'] as const).map((eco) => (
                <label
                  key={eco}
                  className={`cursor-pointer rounded-md px-3 py-1.5 text-sm font-medium has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-focus ${
                    ecosystem === eco ? 'bg-surface text-ink shadow-sm' : 'text-ink-2 hover:text-ink'
                  }`}
                >
                  <input
                    type="radio"
                    name="ecosystem"
                    value={eco}
                    checked={ecosystem === eco}
                    onChange={() => setEcosystem(eco)}
                    className="sr-only"
                  />
                  {ecosystemLabel(eco)}
                </label>
              ))}
            </div>
          </fieldset>
          <div className="flex min-w-0 flex-col gap-1">
            <label htmlFor="check-name" className="text-xs font-medium text-ink-2">
              Package name
            </label>
            <input
              id="check-name"
              ref={nameRef}
              className={`${inputCls} font-mono`}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={ecosystem === 'pypi' ? 'requests or requests==2.32.3' : 'react or @types/node@22.7.4'}
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              maxLength={260}
              aria-invalid={errors.name ? true : undefined}
              aria-describedby={errors.name ? 'check-name-error' : 'check-name-help'}
            />
            {errors.name ? (
              <p id="check-name-error" className="text-xs text-block-ink">
                {errors.name}
              </p>
            ) : (
              <p id="check-name-help" className="text-xs text-muted">
                You can paste a pinned requirement; the version is picked up automatically.
              </p>
            )}
          </div>
          <div className="flex min-w-0 flex-col gap-1">
            <label htmlFor="check-version" className="text-xs font-medium text-ink-2">
              Version <span className="font-normal text-muted">(optional)</span>
            </label>
            <input
              id="check-version"
              className={`${inputCls} font-mono`}
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              placeholder="latest"
              autoComplete="off"
              spellCheck={false}
              maxLength={64}
              aria-invalid={errors.version ? true : undefined}
              aria-describedby={errors.version ? 'check-version-error' : undefined}
            />
            {errors.version ? (
              <p id="check-version-error" className="text-xs text-block-ink">
                {errors.version}
              </p>
            ) : null}
          </div>
          <div className="md:pt-5">
            <button type="submit" className={`${btn.primary} w-full md:w-auto`} disabled={pending}>
              <IconSearch size={15} />
              {pending ? 'Scanning' : 'Check'}
            </button>
          </div>
        </div>
      </form>

      <div ref={resultRef} tabIndex={-1} className="mt-5 outline-none" aria-live="polite" aria-busy={pending}>
        {pending ? (
          <div role="status" className="flex items-center gap-3 rounded-xl border border-line bg-surface p-5 text-sm text-ink-2">
            <span className="h-4 w-4 animate-spin rounded-full border-2 border-line-strong border-t-accent" aria-hidden="true" />
            Fetching and scanning the archive.
          </div>
        ) : null}
        {result?.kind === 'error' ? <ErrorBox error={result.error} title="The check failed" /> : null}
        {result?.kind === 'nonexistent' ? (
          <section
            className="rounded-xl border border-ghost/50 bg-ghost-soft p-5"
            aria-labelledby="nonexistent-title"
            data-testid="nonexistent-result"
          >
            <div className="flex items-start gap-3">
              <span className="mt-0.5 text-ghost-ink">
                <IconGhost size={22} />
              </span>
              <div className="min-w-0">
                <h2 id="nonexistent-title" className="font-semibold text-ink">
                  <span className="font-mono break-all">{safeLabel(result.name, 120)}</span> does not exist on{' '}
                  {ecosystemLabel(result.ecosystem)}
                </h2>
                <p className="mt-1 text-sm text-ink-2">
                  Coding agents sometimes invent plausible package names. Attackers watch for these and register them
                  (slopsquatting). Do not install or publish this name; find the real package in the project's
                  documentation instead.
                </p>
                <p className="mt-2 text-xs text-muted">Server said: {safeLabel(result.message, 200)}</p>
              </div>
            </div>
          </section>
        ) : null}
        {result?.kind === 'verdict' ? (
          <>
            {result.verdict.id ? (
              <p className="mb-3 text-sm">
                <Link
                  to={`/verdicts/${encodeURIComponent(result.verdict.id)}`}
                  state={{ kind: 'check' }}
                  className="font-medium text-accent hover:underline"
                >
                  Open the full verdict page
                </Link>
              </p>
            ) : null}
            <VerdictView verdict={result.verdict} thresholds={thresholds} kind="check" headingLevel={2} />
          </>
        ) : null}
      </div>
    </>
  );
}
