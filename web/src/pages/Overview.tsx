import { useEffect, useRef } from 'react';
import { Link } from 'react-router';
import { api } from '../api/client';
import { BlocksChart } from '../components/BlocksChart';
import { DecisionSplit } from '../components/DecisionSplit';
import { IconBlock, IconGhost, IconShield, IconWarn } from '../components/Icons';
import { LiveFeed } from '../components/LiveFeed';
import { StatTile } from '../components/StatTile';
import { TopReasons } from '../components/TopReasons';
import { Card, ErrorBox, PageHeader, Skeleton } from '../components/ui';
import { useLive } from '../live/context';
import { formatCount, formatPercent } from '../lib/format';
import { useAsync } from '../lib/useAsync';
import { useTitle } from '../lib/useTitle';

export function OverviewPage() {
  useTitle('Overview');
  const stats = useAsync((signal) => api.stats(signal), 'stats');
  const { revision } = useLive();
  const { reload } = stats;

  // Refresh aggregates shortly after live events arrive (debounced).
  const lastRevision = useRef(revision);
  useEffect(() => {
    if (revision === lastRevision.current) return;
    lastRevision.current = revision;
    const t = setTimeout(reload, 1200);
    return () => clearTimeout(t);
  }, [revision, reload]);

  const s = stats.data;
  const total = s?.total ?? 0;

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="What your package managers and coding agents tried to install, and what Customs did about it."
      />
      {stats.error && !s ? <ErrorBox error={stats.error} title="Could not load statistics" onRetry={reload} /> : null}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4" aria-busy={stats.loading && !s}>
        {s ? (
          <>
            <StatTile
              testId="tile-total"
              label="Installs scanned"
              value={formatCount(total)}
              sub={`${formatCount(s.by_kind.check)} agent and CLI checks`}
              icon={<IconShield size={16} />}
              tone="neutral"
            />
            <StatTile
              testId="tile-blocked"
              label="Blocked"
              value={formatCount(s.by_decision.block)}
              sub={`${formatPercent(total ? s.by_decision.block / total : 0)} of all attempts`}
              icon={<IconBlock size={16} />}
              tone="block"
            />
            <StatTile
              testId="tile-warned"
              label="Warned"
              value={formatCount(s.by_decision.warn)}
              sub="Allowed, but worth a look"
              icon={<IconWarn size={16} />}
              tone="warn"
            />
            <StatTile
              testId="tile-slopsquat"
              label="Possible slopsquats"
              value={formatCount(s.by_kind.nonexistent_package)}
              sub="Requests for names that do not exist"
              icon={<IconGhost size={16} />}
              tone="ghost"
            />
          </>
        ) : (
          [0, 1, 2, 3].map((i) => (
            <div key={i} className="rounded-xl border border-line bg-surface p-4">
              <Skeleton className="h-3 w-24" />
              <Skeleton className="mt-3 h-7 w-16" />
              <Skeleton className="mt-2 h-3 w-32" />
            </div>
          ))
        )}
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card
          className="xl:col-span-2"
          id="blocks-per-day"
          title="Blocked installs per day"
          description="Last 14 days, all ecosystems"
        >
          {s ? <BlocksChart data={s.blocks_per_day.slice(-14)} /> : <Skeleton className="h-[190px] w-full" />}
        </Card>
        <Card id="decision-split" title="Decisions by ecosystem">
          {s ? <DecisionSplit byEcosystem={s.by_ecosystem} /> : <Skeleton className="h-32 w-full" />}
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <section
          aria-labelledby="live-feed-title"
          className="min-w-0 rounded-xl border border-line bg-surface shadow-card xl:col-span-2"
        >
          <header className="flex items-center justify-between gap-2 px-4 pt-4 pb-3 sm:px-5">
            <div>
              <h2 id="live-feed-title" className="text-sm font-semibold text-ink">
                Live feed
              </h2>
              <p className="mt-0.5 text-xs text-muted">New install attempts appear here as they happen</p>
            </div>
            <Link to="/activity" className="shrink-0 rounded-md px-2 py-1 text-sm font-medium whitespace-nowrap text-accent hover:underline">
              All activity
            </Link>
          </header>
          <div className="border-t border-line">
            <LiveFeed limit={10} />
          </div>
        </section>
        <Card id="top-reasons" title="Top reasons" description="Most common signals behind warnings and blocks">
          {s ? <TopReasons reasons={s.top_reasons} /> : <Skeleton className="h-40 w-full" />}
        </Card>
      </div>
    </>
  );
}
