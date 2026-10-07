import { describe, expect, it } from 'vitest';
import type { Policy } from '../api/types';
import { policyToDraft, validateDraft, validateListEntry } from './policy';

const POLICY: Policy = {
  mode: 'enforce',
  warn_threshold: 'model',
  block_threshold: 'model',
  min_age_days: 3,
  block_nonexistent: true,
  block_install_scripts_from_new: true,
  allow: ['pypi:requests', 'npm:react'],
  deny: ['npm:event-stream@3.3.6'],
  upstream: {},
};

describe('validateListEntry', () => {
  it('accepts ecosystem:name with optional version', () => {
    for (const ok of ['pypi:requests', 'npm:react@18.3.1', 'npm:@types/node', 'npm:@scope/pkg@1.0.0-beta.1', 'pypi:zope.interface@6.0']) {
      expect(validateListEntry(ok), ok).toBeNull();
    }
  });

  it('rejects malformed entries', () => {
    expect(validateListEntry('requests')).toMatch(/ecosystem:name/);
    expect(validateListEntry('cargo:serde')).toMatch(/pypi or npm/);
    expect(validateListEntry('pypi:bad name')).toMatch(/Not a valid/);
    expect(validateListEntry('npm:@scope')).toMatch(/Not a valid/);
    expect(validateListEntry('')).toMatch(/empty/);
  });
});

describe('validateDraft', () => {
  it('round-trips a valid policy', () => {
    const r = validateDraft(policyToDraft(POLICY));
    expect(r.errors).toEqual({});
    expect(r.policy).toEqual({
      mode: 'enforce',
      warn_threshold: 'model',
      block_threshold: 'model',
      min_age_days: 3,
      block_nonexistent: true,
      block_install_scripts_from_new: true,
      allow: ['pypi:requests', 'npm:react'],
      deny: ['npm:event-stream@3.3.6'],
    });
  });

  it('requires thresholds in [0, 1] with warn below block', () => {
    const d = { ...policyToDraft(POLICY), warnModel: false, warnValue: '0.9', blockModel: false, blockValue: '0.5' };
    expect(validateDraft(d).errors.block_threshold).toMatch(/higher than the warn/);
    expect(validateDraft({ ...d, warnValue: '1.5' }).errors.warn_threshold).toMatch(/between 0 and 1/);
    expect(validateDraft({ ...d, warnValue: 'abc' }).errors.warn_threshold).toBeDefined();
    const ok = validateDraft({ ...d, warnValue: '0.3', blockValue: '0.85' });
    expect(ok.policy?.warn_threshold).toBe(0.3);
    expect(ok.policy?.block_threshold).toBe(0.85);
  });

  it('validates min age days', () => {
    const d = policyToDraft(POLICY);
    expect(validateDraft({ ...d, minAgeDays: '-1' }).errors.min_age_days).toBeDefined();
    expect(validateDraft({ ...d, minAgeDays: '2.5' }).errors.min_age_days).toBeDefined();
    expect(validateDraft({ ...d, minAgeDays: '99999' }).errors.min_age_days).toMatch(/at most/);
    expect(validateDraft({ ...d, minAgeDays: '0' }).policy?.min_age_days).toBe(0);
  });

  it('rejects an entry on both lists', () => {
    const d = { ...policyToDraft(POLICY), deny: ['pypi:requests'] };
    expect(validateDraft(d).errors.deny).toMatch(/also on the allow list/);
  });
});
