import { describe, expect, it } from 'vitest';
import { errorFromBody } from './client';
import {
  ParseError,
  parseEvent,
  parseEventList,
  parseModelInfo,
  parsePolicy,
  parseStats,
  parseTimestamp,
  parseVerdict,
} from './parse';

// The verdict example from docs/DESIGN.md section 6, verbatim.
const DESIGN_VERDICT = {
  ecosystem: 'pypi',
  name: 'foo',
  version: '1.0.0',
  artifact: 'foo-1.0.0.tar.gz',
  sha256: 'ab'.repeat(32),
  decision: 'block',
  risk: 0.97,
  scores: { code_gbdt: 0.99, code_nn: 0.93, name: 0.71 },
  policy_hits: [{ rule: 'min_age_days', severity: 'block', detail: 'published 2 hours ago (policy: 3 days)' }],
  reasons: [{ feature: 'inst_proc_exec', value: 2, contribution: 1.84, label: 'Runs shell commands at install time' }],
  evidence: [{ indicator: 'proc_exec', file: 'setup.py', line: 12, snippet: 'os.system("curl ...")' }],
  scanned_ms: 14,
  model_version: '2026.10.0',
  cached: false,
};

describe('parseVerdict', () => {
  it('parses the DESIGN.md example exactly', () => {
    const v = parseVerdict(DESIGN_VERDICT);
    expect(v).toMatchObject({
      ecosystem: 'pypi',
      name: 'foo',
      version: '1.0.0',
      decision: 'block',
      risk: 0.97,
      scores: { code_gbdt: 0.99, code_nn: 0.93, name: 0.71 },
      scanned_ms: 14,
      model_version: '2026.10.0',
      cached: false,
      id: null,
      thresholds: null,
    });
    expect(v.policy_hits).toEqual(DESIGN_VERDICT.policy_hits);
    expect(v.reasons[0]).toEqual(DESIGN_VERDICT.reasons[0]);
    expect(v.evidence[0]).toEqual(DESIGN_VERDICT.evidence[0]);
  });

  it('ignores unknown fields and tolerates missing optional ones', () => {
    const v = parseVerdict({ name: 'bar', decision: 'allow', future_field: { x: 1 } });
    expect(v.name).toBe('bar');
    expect(v.version).toBeNull();
    expect(v.risk).toBeNull();
    expect(v.scores).toEqual({ code_gbdt: null, code_nn: null, name: null });
    expect(v.reasons).toEqual([]);
    expect(v.evidence).toEqual([]);
    expect(v.cached).toBe(false);
    expect(v).not.toHaveProperty('future_field');
  });

  it('drops malformed list items and clamps risk', () => {
    const v = parseVerdict({
      ...DESIGN_VERDICT,
      risk: 1.7,
      reasons: [{ feature: 'x' }, 'junk', { feature: 'y', contribution: -0.5 }, { feature: 'z', contribution: 2 }],
      evidence: [null, { indicator: 'network', line: -3 }],
      policy_hits: [{ severity: 'block' }],
    });
    expect(v.risk).toBe(1);
    expect(v.reasons.map((r) => r.feature)).toEqual(['z', 'y']);
    expect(v.evidence).toEqual([{ indicator: 'network', file: '', line: null, snippet: '' }]);
    expect(v.policy_hits).toEqual([]);
  });

  it('derives the decision from policy hits when missing', () => {
    const v = parseVerdict({ name: 'x', policy_hits: [{ rule: 'deny', severity: 'block', detail: '' }] });
    expect(v.decision).toBe('block');
  });

  it('accepts a wrapped verdict with an id', () => {
    const v = parseVerdict({ id: 'abc', verdict: DESIGN_VERDICT });
    expect(v.id).toBe('abc');
    expect(v.name).toBe('foo');
  });

  it('throws on unusable input', () => {
    expect(() => parseVerdict(null)).toThrow(ParseError);
    expect(() => parseVerdict({ decision: 'block' })).toThrow(ParseError);
  });
});

describe('events', () => {
  const ev = {
    id: 42,
    ts: '2026-10-07T10:00:00Z',
    ecosystem: 'npm',
    name: '@scope/pkg',
    version: '1.0.0',
    client: 'npm/10.8.3',
    kind: 'install',
    decision: 'allow',
    risk: 0.01,
    verdict_id: 'v1',
  };

  it('normalizes numeric ids and timestamps', () => {
    expect(parseEvent(ev)).toEqual({ ...ev, id: '42', ts: '2026-10-07T10:00:00.000Z' });
    expect(parseEvent({ ...ev, ts: 1791367200 })?.ts).toBe(new Date(1791367200 * 1000).toISOString());
    expect(parseTimestamp(1791367200000)).toBe(new Date(1791367200000).toISOString());
    expect(parseTimestamp('nope')).toBeNull();
  });

  it('handles nonexistent package events with null fields', () => {
    const e = parseEvent({ id: 'e1', ts: ev.ts, ecosystem: 'pypi', name: 'huggingface-cli', kind: 'nonexistent_package', decision: 'block', risk: null, verdict_id: null, version: null });
    expect(e).toMatchObject({ kind: 'nonexistent_package', risk: null, verdict_id: null, version: null });
  });

  it('accepts arrays and wrapped lists, skipping invalid rows', () => {
    expect(parseEventList([ev, { id: 1 }])).toHaveLength(1);
    expect(parseEventList({ events: [ev] })).toHaveLength(1);
    expect(parseEventList({ items: [ev, ev] })).toHaveLength(2);
    expect(parseEventList('garbage')).toEqual([]);
  });

  it('maps unknown kinds to install and unknown decisions to null', () => {
    const e = parseEvent({ ...ev, kind: 'weird', decision: 'maybe' });
    expect(e?.kind).toBe('install');
    expect(e?.decision).toBeNull();
  });
});

describe('parseStats', () => {
  it('parses the documented shape', () => {
    const s = parseStats({
      total: 10,
      by_decision: { allow: 7, warn: 1, block: 2 },
      by_ecosystem: { pypi: { allow: 4, warn: 1, block: 1 }, npm: { allow: 3, block: 1 } },
      by_kind: { install: 8, check: 1, nonexistent_package: 1 },
      blocks_per_day: [
        { date: '2026-10-02', count: 1 },
        { date: '2026-10-01', count: 1 },
      ],
      top_reasons: [{ feature: 'inst_proc_exec', label: null, count: 2 }],
    });
    expect(s.total).toBe(10);
    expect(s.by_ecosystem.npm).toEqual({ allow: 3, warn: 0, block: 1 });
    expect(s.blocks_per_day.map((d) => d.date)).toEqual(['2026-10-01', '2026-10-02']);
    expect(s.by_kind.nonexistent_package).toBe(1);
  });

  it('accepts a date map for blocks per day and computes a missing total', () => {
    const s = parseStats({ by_decision: { allow: 1, block: 2 }, blocks_per_day: { '2026-10-01': 2, junk: 4 } });
    expect(s.total).toBe(3);
    expect(s.blocks_per_day).toEqual([{ date: '2026-10-01', count: 2 }]);
    expect(s.top_reasons).toEqual([]);
  });
});

describe('parsePolicy', () => {
  it('parses the customs.toml shape', () => {
    const p = parsePolicy({
      mode: 'monitor',
      warn_threshold: 'model',
      block_threshold: 0.9,
      min_age_days: 3,
      block_nonexistent: false,
      block_install_scripts_from_new: true,
      provenance_dropped: 'block',
      install_script_added: 'off',
      publisher_changed: 'sometimes',
      dormant_days: 730,
      allow: ['pypi:requests', 5],
      deny: ['npm:event-stream@3.3.6'],
      upstream: { npm: 'https://registry.npmjs.org', bad: 1 },
    });
    expect(p).toEqual({
      mode: 'monitor',
      warn_threshold: 'model',
      block_threshold: 0.9,
      min_age_days: 3,
      block_nonexistent: false,
      block_install_scripts_from_new: true,
      provenance_dropped: 'block',
      install_script_added: 'off',
      publisher_changed: 'warn',
      dormant_revival: 'warn',
      dormant_days: 730,
      version_anomaly: 'off',
      allow: ['pypi:requests'],
      deny: ['npm:event-stream@3.3.6'],
      upstream: { npm: 'https://registry.npmjs.org' },
    });
  });

  it('falls back to safe defaults', () => {
    const p = parsePolicy({});
    expect(p.mode).toBe('enforce');
    expect(p.warn_threshold).toBe('model');
    expect(p.allow).toEqual([]);
    expect(p.provenance_dropped).toBe('warn');
    expect(p.version_anomaly).toBe('off');
    expect(p.dormant_days).toBe(365);
  });
});

describe('parseModelInfo', () => {
  it('reads metrics with confidence intervals and the GuardDog baseline', () => {
    const m = parseModelInfo({
      model_version: '2026.10.0',
      feature_schema_version: 1,
      thresholds: { warn: 0.35, block: 0.8, target_fpr_block: 0.001 },
      metrics: {
        split: 'temporal',
        roc_auc: { value: 0.99, ci_low: 0.98, ci_high: 0.995 },
        pr_auc: 0.95,
        'recall_at_fpr_0.001': 0.87,
        baselines: { guarddog: { fpr: 0.03, recall: 0.74, customs_recall_at_matched_fpr: 0.96 } },
      },
    });
    expect(m.thresholds).toEqual({ warn: 0.35, block: 0.8, target_fpr_block: 0.001 });
    expect(m.metrics?.roc_auc).toEqual({ value: 0.99, ci_low: 0.98, ci_high: 0.995 });
    expect(m.metrics?.pr_auc).toEqual({ value: 0.95 });
    expect(m.metrics?.recall_at_fpr_0_001).toEqual({ value: 0.87 });
    expect(m.metrics?.guarddog).toEqual({ fpr: 0.03, recall: 0.74, customs_recall: 0.96 });
  });

  it('accepts a manifest-only response', () => {
    const m = parseModelInfo({ manifest: { model_version: 'x', feature_schema_version: 1 } });
    expect(m.model_version).toBe('x');
    expect(m.metrics).toBeNull();
    expect(m.thresholds).toBeNull();
  });

  it('prefers the temporal split when metrics are keyed by split', () => {
    const m = parseModelInfo({ model_version: 'x', metrics: { temporal: { roc_auc: 0.9 }, random: { roc_auc: 0.99 } } });
    expect(m.metrics?.split).toBe('temporal');
    expect(m.metrics?.roc_auc?.value).toBe(0.9);
  });
});

describe('errorFromBody', () => {
  it('reads field errors from a list', () => {
    const e = errorFromBody(422, { error: 'invalid policy', errors: [{ field: 'min_age_days', message: 'too big' }] });
    expect(e.status).toBe(422);
    expect(e.message).toBe('invalid policy');
    expect(e.fieldErrors).toEqual({ min_age_days: 'too big' });
  });

  it('reads field errors from a map and plain text bodies', () => {
    expect(errorFromBody(400, { errors: { mode: 'bad' } }).message).toBe('bad');
    expect(errorFromBody(500, 'boom').message).toBe('boom');
    expect(errorFromBody(503, null, 'Service Unavailable').message).toBe('Request failed (503 Service Unavailable)');
    expect(errorFromBody(404, { error: 'gone', code: 'nonexistent_package' }).code).toBe('nonexistent_package');
  });
});
