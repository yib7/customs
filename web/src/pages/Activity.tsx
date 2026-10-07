import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { api } from '../api/client';
import type { CustomsEvent, Decision, EventKind, EventQuery, KnownEcosystem } from '../api/types';
import { DecisionBadge, EcosystemBadge, KindLabel } from '../components/Badges';
import { IconBot, IconChevronLeft, IconChevronRight, IconSearch, IconX } from '../components/Icons';
import { PackageName } from '../components/PackageName';
import { btn, inputCls } from '../components/styles';
import { EmptyState, ErrorBox, Loading, PageHeader } from '../components/ui';
import { useLiveEvents } from '../live/context';
import { matchesFilter } from '../lib/filters';
import { formatDateTime, formatPercent, relativeTime, safeLabel } from '../lib/format';
import { isAgentClient, useNow } from '../lib/hooks';
import { useAsync } from '../lib/useAsync';
import { useTitle } from '../lib/useTitle';

const PAGE_SIZE = 25;
const DECISIONS: Decision[] = ['allow', 'warn', 'block'];
const ECOSYSTEMS: KnownEcosystem[] = ['pypi', 'npm'];
const KINDS: EventKind[] = ['install', 'check', 'nonexistent_package'];

function oneOf<T extends string>(v: string | null, options: readonly T[]): T | undefined {
  return options.find((o) => o === v);
}

function Select<T extends string>({
  label,
  value,
  options,
  onChange,
  render,
}: {
  label: string;
  value: T | undefined;
  options: readonly T[];
  onChange: (v: T | undefined) => void;
  render: (v: T) => string;
}) {
  const id = `filter-${label.toLowerCase().replace(/\s+/g, '-')}`;
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <label htmlFor={id} className="text-xs font-medium text-ink-2">
        {label}
      </label>
      <select
        id={id}
        className={`${inputCls} pr-8`}
        value={value ?? ''}
        onChange={(e) => onChange(oneOf(e.target.value, options))}
      >
        <option value="">All</option>
        {options.map((o) => (
          <option key={o} value={o}>
            {render(o)}
          </option>
        ))}
      </select>
    </div>
  );
}

export function ActivityPage() {
  useTitle('Activity');
  const [params, setParams] = useSearchParams();
  const now = useNow(30000);
  const query: EventQuery = useMemo(
    () => ({
      limit: PAGE_SIZE,
      decision: oneOf(params.get('decision'), DECISIONS),
      ecosystem: oneOf(params.get('ecosystem'), ECOSYSTEMS),
      kind: oneOf(params.get('kind'), KINDS),
      q: params.get('q')?.slice(0, 100) || undefined,
      before: params.get('before') || undefined,
    }),
    [params],
  );
  const [search, setSearch] = useState(query.q ?? '');
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const [live, setLive] = useState<CustomsEvent[]>([]);

  const key = JSON.stringify(query);
  const page = useAsync((signal) => api.events(query, signal), key);

  // Reset the live buffer whenever the query changes (render-time adjustment).
  const [liveKey, setLiveKey] = useState(key);
  if (liveKey !== key) {
    setLiveKey(key);
    setLive([]);
  }

  useLiveEvents((e) => {
    if (query.before || !matchesFilter(e, query)) return;
    setLive((prev) => (prev.some((p) => p.id === e.id) ? prev : [e, ...prev].slice(0, 50)));
  });

  // Debounce the text search into the URL.
  // Latest URL params, read when the debounce fires (the closure may be stale by then).
  const paramsRef = useRef(params);
  useEffect(() => {
    paramsRef.current = params;
  }, [params]);
  useEffect(() => {
    const t = setTimeout(() => {
      const trimmed = search.trim();
      if ((paramsRef.current.get('q') ?? '') === trimmed) return;
      update({ q: trimmed || undefined, before: undefined }, true);
    }, 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  function update(patch: Partial<Record<'decision' | 'ecosystem' | 'kind' | 'q' | 'before', string | undefined>>, resetPaging: boolean) {
    const next = new URLSearchParams(paramsRef.current);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (resetPaging) {
      next.delete('before');
      setCursorStack([]);
    }
    setParams(next, { replace: resetPaging });
  }

  const rows = useMemo(() => {
    const fetched = (page.data ?? []).filter((e) => matchesFilter(e, query));
    const ids = new Set(fetched.map((e) => e.id));
    return [...live.filter((e) => !ids.has(e.id)), ...fetched];
  }, [page.data, live, query]);
  const liveIds = useMemo(() => new Set(live.map((e) => e.id)), [live]);
  const fetchedCount = page.data?.length ?? 0;
  const hasOlder = fetchedCount >= PAGE_SIZE;
  const lastId = page.data?.[page.data.length - 1]?.id ?? null;
  const filtersActive = Boolean(query.decision || query.ecosystem || query.kind || query.q);

  return (
    <>
      <PageHeader title="Activity" subtitle="Every install attempt and check, newest first. Select a package to see its verdict." />

      <form
        className="mb-4 grid grid-cols-2 gap-3 rounded-xl border border-line bg-surface p-4 shadow-card sm:grid-cols-4 lg:grid-cols-[minmax(0,2fr)_repeat(3,minmax(0,1fr))_auto]"
        role="search"
        aria-label="Filter events"
        onSubmit={(e) => e.preventDefault()}
      >
        <div className="col-span-2 flex min-w-0 flex-col gap-1 sm:col-span-4 lg:col-span-1">
          <label htmlFor="filter-search" className="text-xs font-medium text-ink-2">
            Package name
          </label>
          <div className="relative">
            <IconSearch size={15} className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-muted" />
            <input
              id="filter-search"
              type="search"
              className={`${inputCls} pl-9`}
              placeholder="Search by name"
              value={search}
              maxLength={100}
              onChange={(e) => setSearch(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
        </div>
        <Select
          label="Decision"
          value={query.decision}
          options={DECISIONS}
          onChange={(v) => update({ decision: v }, true)}
          render={(d) => ({ allow: 'Allowed', warn: 'Warned', block: 'Blocked' })[d]}
        />
        <Select
          label="Ecosystem"
          value={query.ecosystem}
          options={ECOSYSTEMS}
          onChange={(v) => update({ ecosystem: v }, true)}
          render={(e) => (e === 'pypi' ? 'PyPI' : 'npm')}
        />
        <Select
          label="Kind"
          value={query.kind}
          options={KINDS}
          onChange={(v) => update({ kind: v }, true)}
          render={(k) => ({ install: 'Install', check: 'Check', nonexistent_package: 'Nonexistent package' })[k]}
        />
        <div className="flex items-end">
          <button
            type="button"
            className={`${btn.secondary} w-full`}
            disabled={!filtersActive}
            onClick={() => {
              setSearch('');
              setCursorStack([]);
              setParams(new URLSearchParams(), { replace: true });
            }}
          >
            <IconX size={14} /> Clear
          </button>
        </div>
      </form>

      <section aria-labelledby="events-heading" className="min-w-0 rounded-xl border border-line bg-surface shadow-card">
        <h2 id="events-heading" className="sr-only">
          Events
        </h2>
        {page.error ? (
          <div className="p-4">
            <ErrorBox error={page.error} title="Could not load events" onRetry={page.reload} />
          </div>
        ) : page.loading && !page.data ? (
          <div className="p-4">
            <Loading label="Loading events" />
          </div>
        ) : rows.length === 0 ? (
          <div className="p-4">
            <EmptyState title={filtersActive ? 'No events match these filters' : 'No events yet'}>
              {filtersActive ? 'Try clearing a filter.' : 'Install attempts will appear here.'}
            </EmptyState>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm" data-testid="events-table">
              <thead className="border-b border-line text-xs text-muted">
                <tr>
                  <th scope="col" className="px-4 py-2.5 font-medium sm:px-5">
                    Package
                  </th>
                  <th scope="col" className="px-3 py-2.5 font-medium">
                    Decision
                  </th>
                  <th scope="col" className="hidden px-3 py-2.5 text-right font-medium md:table-cell">
                    Risk
                  </th>
                  <th scope="col" className="hidden px-3 py-2.5 font-medium lg:table-cell">
                    Kind
                  </th>
                  <th scope="col" className="hidden px-3 py-2.5 font-medium md:table-cell">
                    Client
                  </th>
                  <th scope="col" className="hidden px-4 py-2.5 text-right font-medium sm:table-cell sm:px-5">
                    Time
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id} className={`border-b border-line last:border-b-0 hover:bg-surface-2 ${liveIds.has(e.id) ? 'feed-new' : ''}`} data-testid="event-row">
                    <td className="max-w-0 px-4 py-2.5 sm:px-5" style={{ width: '45%' }}>
                      <div className="flex min-w-0 items-center gap-2">
                        <EcosystemBadge ecosystem={e.ecosystem} />
                        {e.verdict_id ? (
                          <Link
                            to={`/verdicts/${encodeURIComponent(e.verdict_id)}`}
                            className="min-w-0 truncate rounded hover:underline"
                            aria-label={`View verdict for ${safeLabel(e.name, 80)}${e.version ? ` version ${safeLabel(e.version, 20)}` : ''}`}
                          >
                            <PackageName name={e.name} version={e.version} max={56} />
                          </Link>
                        ) : (
                          <span className="min-w-0 truncate">
                            <PackageName name={e.name} version={e.version} max={56} />
                          </span>
                        )}
                      </div>
                      <div className="mt-0.5 text-xs text-muted sm:hidden">
                        {relativeTime(e.ts, now)}
                        {e.client ? ` \u00B7 ${safeLabel(e.client, 24)}` : ''}
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      <DecisionBadge decision={e.decision} kind={e.kind} size="sm" />
                    </td>
                    <td className="hidden px-3 py-2.5 text-right text-ink-2 tabular md:table-cell">
                      {e.risk === null ? <span className="text-muted">n/a</span> : formatPercent(e.risk)}
                    </td>
                    <td className="hidden px-3 py-2.5 lg:table-cell">
                      <KindLabel kind={e.kind} />
                    </td>
                    <td className="hidden max-w-[12rem] px-3 py-2.5 md:table-cell">
                      <span className="flex items-center gap-1 truncate text-ink-2">
                        {isAgentClient(e.client) ? <IconBot size={14} title="Coding agent" className="shrink-0" /> : null}
                        <span className="truncate">{e.client ? safeLabel(e.client, 32) : 'unknown'}</span>
                      </span>
                    </td>
                    <td className="hidden px-4 py-2.5 text-right whitespace-nowrap text-ink-2 tabular sm:table-cell sm:px-5">
                      <time dateTime={e.ts} title={formatDateTime(e.ts)}>
                        {relativeTime(e.ts, now)}
                      </time>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <nav aria-label="Pagination" className="flex items-center justify-between gap-2 border-t border-line px-4 py-3 sm:px-5">
          <span className="text-xs text-muted" aria-live="polite">
            {page.data ? `Showing ${rows.length} event${rows.length === 1 ? '' : 's'}${query.before ? ' (older page)' : ''}` : ''}
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              className={btn.secondary}
              disabled={!query.before}
              onClick={() => {
                const stack = [...cursorStack];
                const prev = stack.pop();
                setCursorStack(stack);
                update({ before: prev }, false);
              }}
            >
              <IconChevronLeft size={15} /> Newer
            </button>
            <button
              type="button"
              className={btn.secondary}
              disabled={!hasOlder || !lastId}
              onClick={() => {
                if (!lastId) return;
                setCursorStack((s) => [...s, query.before ?? '']);
                update({ before: lastId }, false);
              }}
            >
              Older <IconChevronRight size={15} />
            </button>
          </div>
        </nav>
      </section>
    </>
  );
}
