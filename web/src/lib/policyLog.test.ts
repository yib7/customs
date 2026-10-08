import { describe, expect, it } from 'vitest';
import { describeFieldChange, diffPolicies } from './policyLog';

describe('policy change log', () => {
  it('words each kind of change', () => {
    expect(describeFieldChange({ field: 'mode', before: 'enforce', after: 'monitor' })).toBe('mode: enforce -> monitor');
    expect(describeFieldChange({ field: 'block_threshold', before: 'model', after: 0.9 })).toBe('block_threshold: model -> 0.9');
    expect(describeFieldChange({ field: 'hide_young_versions', before: true, after: false })).toBe('hide_young_versions: true -> false');
    expect(describeFieldChange({ field: 'deny', before: ['npm:x', 'npm:y'], after: ['npm:y', 'npm:z'] })).toBe(
      'deny: added npm:z; removed npm:x',
    );
    expect(describeFieldChange({ field: 'allow', before: ['a', 'b'], after: ['b', 'a'] })).toBe('allow: reordered');
  });

  it('diffs nested fields', () => {
    const a = { mode: 'enforce', allow: [], upstream: { npm: 'https://registry.npmjs.org', pypi_simple: 's' } };
    const b = { mode: 'enforce', allow: ['npm:a'], upstream: { npm: 'https://npm.example', pypi_simple: 's' } };
    expect(diffPolicies(a, b)).toEqual([
      { field: 'allow', before: [], after: ['npm:a'] },
      { field: 'upstream.npm', before: 'https://registry.npmjs.org', after: 'https://npm.example' },
    ]);
    expect(diffPolicies(a, a)).toEqual([]);
  });
});
