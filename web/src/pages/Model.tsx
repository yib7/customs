import { api } from '../api/client';
import type { GuardDogComparison, MetricValue, ModelInfo } from '../api/types';
import { Card, ErrorBox, Loading, PageHeader } from '../components/ui';
import { formatCount, formatPercent, safeLabel } from '../lib/format';
import { useAsync } from '../lib/useAsync';
import { useTitle } from '../lib/useTitle';

function Metric({ label, help, m, asPercent = false }: { label: string; help: string; m: MetricValue | null; asPercent?: boolean }) {
  const fmt = (v: number) => (asPercent ? formatPercent(v, 1) : v.toFixed(3));
  return (
    <div className="min-w-0 rounded-xl border border-line bg-surface p-4 shadow-card">
      <p className="text-xs font-medium text-ink-2">{label}</p>
      <p className="mt-1 text-2xl font-semibold tracking-tight text-ink">{m ? fmt(m.value) : 'n/a'}</p>
      {m && m.ci_low !== undefined && m.ci_high !== undefined ? (
        <p className="text-xs text-muted tabular">
          95% CI {fmt(m.ci_low)} to {fmt(m.ci_high)}
        </p>
      ) : null}
      <p className="mt-1.5 text-xs text-muted">{help}</p>
    </div>
  );
}

function GuardDogCompare({ g }: { g: GuardDogComparison }) {
  const rows = [
    { name: 'Customs', value: g.customs_recall, color: 'var(--c-accent)' },
    { name: 'GuardDog', value: g.recall, color: 'var(--c-ink-2)' },
  ];
  return (
    <Card
      id="guarddog"
      title="Compared with GuardDog"
      description={
        g.fpr !== null
          ? `Share of malicious packages caught when both tools flag the same share of benign packages (${formatPercent(g.fpr, 1)} false positive rate)`
          : 'Share of malicious packages caught at a matched false positive rate'
      }
    >
      <ul className="flex flex-col gap-3" aria-label="Recall at matched false positive rate">
        {rows.map((r) => (
          <li key={r.name} className="grid grid-cols-[5.5rem_minmax(0,1fr)_3.5rem] items-center gap-3">
            <span className="text-sm font-medium text-ink">{r.name}</span>
            <div className="h-3 rounded-full bg-surface-3" aria-hidden="true">
              {r.value !== null ? (
                <div className="h-full rounded-full" style={{ width: `${r.value * 100}%`, background: r.color }} />
              ) : null}
            </div>
            <span className="text-right text-sm text-ink tabular">{r.value !== null ? formatPercent(r.value, 1) : 'n/a'}</span>
          </li>
        ))}
      </ul>
      <p className="mt-3 text-xs text-muted">
        GuardDog is Datadog's open-source rule-based scanner, run on the same held-out archives.
      </p>
    </Card>
  );
}

const STEPS: { title: string; body: string }[] = [
  {
    title: 'Unpack safely and extract features',
    body: 'The archive is opened in memory with strict limits on size, file count, and path tricks. Nothing in it is ever run. Customs counts patterns such as shell commands, network calls, credential paths, and obfuscation, separately for code that runs at install time and for the rest of the package.',
  },
  {
    title: 'Score with three models',
    body: 'A gradient-boosted tree model reads those counts. A small neural network reads the install-time code itself as a sequence of tokens. A name model looks for typosquats and lookalikes of popular packages.',
  },
  {
    title: 'Combine and calibrate',
    body: 'The three scores are combined and calibrated so the result reads as a probability: a risk of 0.9 means roughly nine in ten packages with that score in held-out data were malicious.',
  },
  {
    title: 'Apply thresholds and policy',
    body: 'The risk is compared with the warn and block thresholds, then policy rules such as package age and nonexistent names can make the decision stricter. Three rules override the model instead: the deny list always blocks, the allow list always allows, and an established release of a popular package sets the model score aside.',
  },
];

/**
 * The split name and its detail from metrics.json's `split`, for example
 * `temporal (test: malware found from 2026-02-13)` -> `temporal`, `malware found from 2026-02-13`.
 */
function splitInfo(split: string | null | undefined): { name: string; detail: string | null } | null {
  const m = /^\s*([^()]+?)\s*(?:\((.*)\))?\s*$/.exec(split ?? '');
  if (!m?.[1]) return null;
  const detail = m[2]?.replace(/^\s*test:\s*/i, '').trim();
  return { name: safeLabel(m[1], 30), detail: detail ? safeLabel(detail, 80) : null };
}

function ModelBody({ m }: { m: ModelInfo }) {
  const metrics = m.metrics;
  const split = splitInfo(metrics?.split);
  // The model's own thresholds; the policy may override them (see the Policy page).
  const t = m.model_thresholds;
  return (
    <div className="flex flex-col gap-4">
      {m.untrained ? (
        <p role="status" className="rounded-lg border border-warn/60 bg-warn-soft px-4 py-3 text-sm text-ink">
          These are placeholder models that were not trained on data. Their scores mean nothing; policy rules still apply.
        </p>
      ) : null}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="min-w-0 rounded-xl border border-line bg-surface p-4 shadow-card">
          <p className="text-xs font-medium text-ink-2">Model version</p>
          <p className="mt-1 truncate font-mono text-lg font-semibold text-ink" data-testid="model-version">
            {safeLabel(m.model_version, 40)}
          </p>
          <p className="text-xs text-muted">Feature schema {m.feature_schema_version ?? 'n/a'}</p>
        </div>
        <div className="min-w-0 rounded-xl border border-line bg-surface p-4 shadow-card">
          <p className="text-xs font-medium text-ink-2">Warn threshold</p>
          <p className="mt-1 text-lg font-semibold text-ink tabular">{t ? t.warn.toFixed(2) : 'n/a'}</p>
          <p className="text-xs text-muted">From validation data</p>
        </div>
        <div className="min-w-0 rounded-xl border border-line bg-surface p-4 shadow-card">
          <p className="text-xs font-medium text-ink-2">Block threshold</p>
          <p className="mt-1 text-lg font-semibold text-ink tabular" data-testid="model-block-threshold">
            {t ? t.block.toFixed(2) : 'n/a'}
          </p>
          <p className="text-xs text-muted">
            {t?.target_fpr_block !== undefined
              ? `Targets ${formatPercent(t.target_fpr_block, 1)} false positives`
              : 'From validation data'}
          </p>
        </div>
        <div className="min-w-0 rounded-xl border border-line bg-surface p-4 shadow-card">
          <p className="text-xs font-medium text-ink-2">Test set</p>
          <p className="mt-1 text-lg font-semibold text-ink tabular">
            {metrics?.n_test_malicious !== null && metrics?.n_test_malicious !== undefined ? formatCount(metrics.n_test_malicious) : 'n/a'}
          </p>
          <p className="text-xs text-muted">
            malicious{metrics?.n_test_benign ? `, ${formatCount(metrics.n_test_benign)} benign` : ''}
          </p>
        </div>
      </div>

      {metrics ? (
        <section aria-labelledby="metrics-heading">
          <h2 id="metrics-heading" className="mb-1 text-sm font-semibold text-ink">
            Held-out evaluation{split ? ` (${split.name} split)` : ''}
          </h2>
          <p className="mb-3 text-xs text-muted">
            {split?.name === 'temporal'
              ? `Trained on packages first seen before a cutoff date and tested on packages seen after it, so these numbers reflect malware the model had never seen.${
                  split.detail ? ` Test set: ${split.detail}.` : ''
                }`
              : 'Measured on packages held out from training, grouped so no malware campaign appears in both sets.'}
          </p>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Metric
              label="Recall at 0.1% FPR"
              help="Malicious packages caught when only 1 in 1,000 benign packages is flagged."
              m={metrics.recall_at_fpr_0_001}
              asPercent
            />
            <Metric label="Recall at 1% FPR" help="Malicious packages caught at 1 in 100 benign flagged." m={metrics.recall_at_fpr_0_01} asPercent />
            <Metric label="ROC AUC" help="How well risk ranks malicious above benign, from 0.5 (chance) to 1." m={metrics.roc_auc} />
            <Metric label="PR AUC" help="Precision and recall traded off across all thresholds." m={metrics.pr_auc} />
          </div>
          {metrics.brier ? (
            <p className="mt-2 text-xs text-muted">
              Brier score {metrics.brier.value.toFixed(4)} (lower is better; measures how well risk matches observed rates).
            </p>
          ) : null}
        </section>
      ) : (
        <Card title="Evaluation">
          <p className="text-sm text-muted">The server did not report evaluation metrics for this model.</p>
        </Card>
      )}

      {metrics?.guarddog ? <GuardDogCompare g={metrics.guarddog} /> : null}

      <Card id="how-scoring-works" title="How scoring works">
        <ol className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {STEPS.map((s, i) => (
            <li key={s.title} className="flex gap-3">
              <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-accent-soft text-xs font-semibold text-ink">
                {i + 1}
              </span>
              <div>
                <p className="text-sm font-medium text-ink">{s.title}</p>
                <p className="mt-0.5 text-sm text-ink-2">{s.body}</p>
              </div>
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}

export function ModelPage() {
  useTitle('Model');
  const model = useAsync((signal) => api.model(signal), 'model');
  return (
    <>
      <PageHeader title="Model" subtitle="The malware classifier behind every verdict, and how well it performed on packages it never saw in training." />
      {model.error ? <ErrorBox error={model.error} title="Could not load model information" onRetry={model.reload} /> : null}
      {model.loading && !model.data ? <Loading label="Loading model information" /> : null}
      {model.data ? <ModelBody m={model.data} /> : null}
    </>
  );
}
