import { Link } from 'react-router';
import type { CustomsEvent } from '../api/types';
import { useLive } from '../live/context';
import { formatDateTime, formatPercent, relativeTime, safeLabel } from '../lib/format';
import { isAgentClient, useNow } from '../lib/hooks';
import { DecisionBadge, EcosystemBadge } from './Badges';
import { IconBot } from './Icons';
import { PackageName } from './PackageName';
import { EmptyState, ErrorBox, Loading } from './ui';

function ClientLabel({ client }: { client: string | null }) {
  if (!client) return null;
  const agent = isAgentClient(client);
  return (
    <span className="inline-flex items-center gap-1 text-xs text-muted">
      {agent ? <IconBot size={13} title="Coding agent" /> : null}
      {safeLabel(client, 28)}
    </span>
  );
}

function FeedRow({ e, now, isNew }: { e: CustomsEvent; now: number; isNew: boolean }) {
  const body = (
    <>
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <div className="flex min-w-0 items-center gap-2">
          <EcosystemBadge ecosystem={e.ecosystem} />
          <PackageName name={e.name} version={e.version} max={48} className="truncate" />
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5">
          <ClientLabel client={e.client} />
          {e.risk !== null ? <span className="text-xs text-muted tabular">risk {formatPercent(e.risk)}</span> : null}
          {e.kind === 'nonexistent_package' ? <span className="text-xs text-ghost-ink">possible slopsquat</span> : null}
        </div>
      </div>
      <div className="flex shrink-0 flex-col items-end gap-1">
        <DecisionBadge decision={e.decision} kind={e.kind} size="sm" />
        <time dateTime={e.ts} title={formatDateTime(e.ts)} className="text-xs text-muted tabular">
          {relativeTime(e.ts, now)}
        </time>
      </div>
    </>
  );
  const cls = `flex items-center gap-3 px-4 py-2.5 sm:px-5 ${isNew ? 'feed-new' : ''}`;
  return (
    <li className="border-t border-line first:border-t-0" data-testid="feed-row" data-event-id={e.id}>
      {e.verdict_id ? (
        <Link to={`/verdicts/${encodeURIComponent(e.verdict_id)}`} className={`${cls} hover:bg-surface-2`}>
          {body}
        </Link>
      ) : (
        <div className={cls}>{body}</div>
      )}
    </li>
  );
}

export function LiveFeed({ limit = 10 }: { limit?: number }) {
  const { events, loaded, error, liveIds } = useLive();
  const now = useNow(15000);
  const shown = events.slice(0, limit);
  const latestLive = events.find((e) => liveIds.has(e.id));
  if (!loaded) return <div className="px-4 pb-4 sm:px-5"><Loading label="Loading events" /></div>;
  if (error && events.length === 0) return <div className="px-4 pb-4 sm:px-5"><ErrorBox error={error} title="Could not load events" /></div>;
  if (shown.length === 0) {
    return (
      <div className="px-4 pb-4 sm:px-5">
        <EmptyState title="No installs yet">Point pip or npm at Customs and new installs will appear here as they happen.</EmptyState>
      </div>
    );
  }
  return (
    <>
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {latestLive
          ? `New event: ${safeLabel(latestLive.name, 60)} ${latestLive.kind === 'nonexistent_package' ? 'not found' : (latestLive.decision ?? '')}`
          : ''}
      </div>
      <ul aria-label="Recent install attempts" data-testid="live-feed">
        {shown.map((e) => (
          <FeedRow key={e.id} e={e} now={now} isNew={liveIds.has(e.id)} />
        ))}
      </ul>
    </>
  );
}
