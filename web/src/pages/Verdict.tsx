import { Link, useLocation, useNavigate, useParams } from 'react-router';
import { ApiError, api } from '../api/client';
import type { EventKind } from '../api/types';
import { IconArrowLeft } from '../components/Icons';
import { ReleaseDiffCard } from '../components/ReleaseDiffCard';
import { VerdictView } from '../components/VerdictView';
import { btn } from '../components/styles';
import { EmptyState, ErrorBox, Loading } from '../components/ui';
import { safeLabel } from '../lib/format';
import { useThresholds } from '../lib/thresholds';
import { useAsync } from '../lib/useAsync';
import { useTitle } from '../lib/useTitle';

function eventKind(state: unknown): EventKind | null {
  const kind = typeof state === 'object' && state !== null ? (state as { kind?: unknown }).kind : null;
  return kind === 'install' || kind === 'check' || kind === 'nonexistent_package' ? kind : null;
}

export function VerdictPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  // The event kind, passed by the links from the activity list, the live feed and the check page.
  const kind = eventKind(location.state);
  // Verdict ids are integers; anything else cannot name one, so do not ask the server.
  const validId = /^[0-9]{1,18}$/.test(id);
  const verdict = useAsync(
    (signal) => (validId ? api.verdict(id, signal) : Promise.reject(new ApiError(404, 'not a verdict id'))),
    `verdict:${id}`,
  );
  const thresholds = useThresholds(verdict.data);
  const v = verdict.data;
  useTitle(v ? `${safeLabel(v.name, 60)} verdict` : 'Verdict');

  return (
    <>
      <div className="mb-4">
        <button
          type="button"
          className={btn.ghost}
          onClick={() => {
            // 'default' is the entry the app was opened on: nothing in the app to go back to.
            if (location.key !== 'default') navigate(-1);
            else navigate('/activity');
          }}
        >
          <IconArrowLeft size={15} /> Back
        </button>
      </div>
      {verdict.loading && !v ? <Loading label="Loading verdict" /> : null}
      {verdict.error ? (
        verdict.error instanceof ApiError && (verdict.error.status === 404 || verdict.error.status === 400) ? (
          <EmptyState title="Verdict not found">
            It may have been pruned from the local database.{' '}
            <Link to="/activity" className="text-accent hover:underline">
              Back to activity
            </Link>
          </EmptyState>
        ) : (
          <ErrorBox error={verdict.error} title="Could not load this verdict" onRetry={verdict.reload} />
        )
      ) : null}
      {v ? <VerdictView verdict={v} thresholds={thresholds} kind={kind} /> : null}
      {v ? <ReleaseDiffCard key={v.id ?? v.name} verdict={v} /> : null}
    </>
  );
}
