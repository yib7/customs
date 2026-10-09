import { Link } from 'react-router';
import type { EventKind, Thresholds, Verdict } from '../api/types';
import { allowlistSnippet, checkCommand } from '../lib/commands';
import { formatDuration, registryUrl, safeLabel, shortSha } from '../lib/format';
import { DecisionBadge, EcosystemBadge } from './Badges';
import { IconExternal, IconTerminal } from './Icons';
import { RiskGauge } from './RiskGauge';
import { Card, CommandBlock, CopyButton } from './ui';
import { ComponentScores, ContributionBars, EvidenceList, PolicyHits } from './VerdictParts';

/**
 * One sentence on what the decision meant. `kind` is how the verdict came about, when known:
 * a check (`/api/check`) installs nothing, and in monitor mode a blocked install went through.
 */
function summary(v: Verdict, kind: EventKind | null): string {
  const check = kind === 'check';
  if (v.decision === 'allow') return 'Customs found nothing that warrants action.';
  if (v.decision === 'warn') {
    return check
      ? 'Customs would let this package through with a warning. Review the signals below.'
      : 'Customs let this package through with a warning. Review the signals below.';
  }
  if (check) {
    return v.mode === 'monitor'
      ? 'Customs would block this package in enforce mode. The policy is in monitor mode, so an install would go through.'
      : 'Customs would block this package.';
  }
  if (v.mode === 'monitor') {
    return kind === null ? 'Would have been blocked (monitor mode).' : 'Would have been blocked (monitor mode). It was installed.';
  }
  return 'Customs blocked this package. It was not installed.';
}

function HowToProceed({ v, level }: { v: Verdict; level: 2 | 3 }) {
  const reg = registryUrl(v.ecosystem, v.name);
  const nameReason = v.reasons.find((r) => r.feature.startsWith('name_') && r.contribution > 0);
  return (
    <Card level={level} id="next-steps" title="How to proceed">
      <div className="flex flex-col gap-4 text-sm text-ink-2">
        {v.decision === 'allow' ? (
          <p>No action needed. To re-scan later, for example after a new release:</p>
        ) : (
          <ol className="flex list-decimal flex-col gap-1.5 pl-5">
            {nameReason ? (
              <li>
                Double-check the name. Lookalike names are a common trick, and coding agents sometimes invent package
                names that attackers then register.
              </li>
            ) : null}
            <li>Read the evidence above. Install-time network calls, shell commands, and credential access are rarely legitimate.</li>
            <li>
              If a coding agent suggested this package, ask it for the source of the recommendation, or pick a well-known
              alternative.
            </li>
            {v.decision === 'block' ? (
              <li>Only if you are certain this is a false positive, allowlist this exact version (see below).</li>
            ) : null}
          </ol>
        )}
        <div>
          <p className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-ink">
            <IconTerminal size={14} /> Check it again from a terminal
          </p>
          <CommandBlock command={checkCommand(v)} label="Copy check command" />
        </div>
        {v.decision !== 'allow' ? (
          <div>
            <p className="mb-1.5 text-xs font-medium text-ink">
              Allowlist this exact version in <code className="font-mono">customs.toml</code> (or on the{' '}
              <Link to="/policy" className="text-accent underline-offset-2 hover:underline">
                Policy page
              </Link>
              )
            </p>
            <CommandBlock command={allowlistSnippet(v)} label="Copy allowlist entry" />
          </div>
        ) : null}
        {reg ? (
          <a
            href={reg}
            target="_blank"
            rel="noopener noreferrer nofollow"
            className="inline-flex items-center gap-1 self-start text-sm font-medium text-accent underline-offset-2 hover:underline"
          >
            View on {v.ecosystem === 'pypi' ? 'PyPI' : 'npm'}
            {v.decision === 'block' ? ' (and report it there)' : ''}
            <IconExternal size={14} />
          </a>
        ) : null}
      </div>
    </Card>
  );
}

export function VerdictView({
  verdict: v,
  thresholds,
  kind = null,
  headingLevel = 1,
}: {
  verdict: Verdict;
  thresholds: Thresholds | null;
  /** How the verdict came about (the event kind), when known. */
  kind?: EventKind | null;
  headingLevel?: 1 | 2;
}) {
  const Heading = headingLevel === 1 ? 'h1' : 'h2';
  const sub = headingLevel === 1 ? 2 : 3;
  return (
    <div className="flex flex-col gap-4" data-testid="verdict">
      <section
        aria-labelledby="verdict-title"
        className={`rounded-xl border bg-surface p-4 shadow-card sm:p-5 ${
          v.decision === 'block' ? 'border-block/50' : v.decision === 'warn' ? 'border-warn/60' : 'border-line'
        }`}
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="mb-1.5 flex flex-wrap items-center gap-2">
              <EcosystemBadge ecosystem={v.ecosystem} />
              {v.cached ? <span className="text-xs text-muted">cached verdict</span> : null}
            </div>
            <Heading id="verdict-title" className="font-mono text-xl font-semibold break-all text-ink sm:text-2xl" title={v.name}>
              {safeLabel(v.name, 120)}
              {v.version ? <span className="font-normal text-muted">@{safeLabel(v.version, 40)}</span> : null}
            </Heading>
          </div>
          <DecisionBadge decision={v.decision} size="lg" />
        </div>
        <p className="mt-2 text-sm text-ink-2">{summary(v, kind)}</p>
        <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-2 text-xs sm:grid-cols-2 lg:grid-cols-4">
          <div className="min-w-0">
            <dt className="text-muted">Archive</dt>
            <dd className="truncate font-mono text-ink" title={v.artifact ?? undefined}>
              {v.artifact ? safeLabel(v.artifact, 80) : 'n/a'}
            </dd>
          </div>
          <div className="min-w-0">
            <dt className="text-muted">SHA-256</dt>
            <dd className="flex items-center gap-1.5 font-mono text-ink">
              {v.sha256 ? (
                <>
                  <span title={v.sha256} data-testid="sha-short">
                    {shortSha(v.sha256)}
                  </span>
                  <CopyButton text={v.sha256} label="Copy full SHA-256" />
                </>
              ) : (
                'n/a'
              )}
            </dd>
          </div>
          <div>
            <dt className="text-muted">Scan time</dt>
            <dd className="text-ink tabular">{formatDuration(v.scanned_ms)}</dd>
          </div>
          <div>
            <dt className="text-muted">Model version</dt>
            <dd className="font-mono text-ink">{v.model_version ? safeLabel(v.model_version, 30) : 'n/a'}</dd>
          </div>
        </dl>
      </section>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <Card level={sub} id="risk" className="xl:col-span-3" title="Risk" description="Ensemble of three models, calibrated on held-out data">
          <div className="grid grid-cols-1 items-center gap-6 md:grid-cols-2">
            <RiskGauge risk={v.risk} thresholds={thresholds} />
            <ComponentScores scores={v.scores} thresholds={thresholds} />
          </div>
        </Card>
        <Card level={sub} id="decision" className="xl:col-span-2" title="Decision" description="Model decision combined with policy rules">
          <div className="mb-4 flex items-center gap-2">
            <DecisionBadge decision={v.decision} />
            {thresholds && v.risk !== null ? (
              <span className="text-xs text-muted">
                Thresholds: warn at {thresholds.warn.toFixed(2)}, block at {thresholds.block.toFixed(2)}
              </span>
            ) : null}
          </div>
          <PolicyHits hits={v.policy_hits} decision={v.decision} />
        </Card>
      </div>

      <Card level={sub} id="why" title="Why" description="Features that moved the code model's score, largest first">
        <ContributionBars reasons={v.reasons} />
      </Card>

      <Card level={sub} id="evidence" title="Evidence" description="Where the suspicious patterns were found in the archive">
        <EvidenceList evidence={v.evidence} />
      </Card>

      <HowToProceed v={v} level={sub} />
    </div>
  );
}
