import { Link, useNavigate, useParams } from 'react-router';
import { ApiError, api } from '../api/client';
import { IconArrowLeft } from '../components/Icons';
import { VerdictView } from '../components/VerdictView';
import { btn } from '../components/styles';
import { EmptyState, ErrorBox, Loading } from '../components/ui';
import { safeLabel } from '../lib/format';
import { useThresholds } from '../lib/thresholds';
import { useAsync } from '../lib/useAsync';
import { useTitle } from '../lib/useTitle';

export function VerdictPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const verdict = useAsync((signal) => api.verdict(id, signal), `verdict:${id}`);
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
            if (window.history.length > 1) navigate(-1);
            else navigate('/activity');
          }}
        >
          <IconArrowLeft size={15} /> Back
        </button>
      </div>
      {verdict.loading && !v ? <Loading label="Loading verdict" /> : null}
      {verdict.error ? (
        verdict.error instanceof ApiError && verdict.error.status === 404 ? (
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
      {v ? <VerdictView verdict={v} thresholds={thresholds} /> : null}
    </>
  );
}
