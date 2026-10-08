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
  provenance_dropped: 'warn',
  install_script_added: 'warn',
  publisher_changed: 'warn',
  dormant_revival: 'warn',
  dormant_days: 365,
  version_anomaly: 'off',
  nonregistry_dependency_added: 'block',
  young_dependency_added: 'block',
  young_dependency_days: 7,
  unread_code: 'block',
  startup_hook: 'block',
  scan_error: 'block',
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
      provenance_dropped: 'warn',
      install_script_added: 'warn',
      publisher_changed: 'warn',
      dormant_revival: 'warn',
      dormant_days: 365,
      version_anomaly: 'off',
      nonregistry_dependency_added: 'block',
      young_dependency_added: 'block',
      young_dependency_days: 7,
      unread_code: 'block',
      startup_hook: 'block',
      scan_error: 'block',
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

  it('validates the dormancy period and passes rule severities through', () => {
    const d = policyToDraft(POLICY);
    expect(validateDraft({ ...d, dormantDays: '0' }).errors.dormant_days).toMatch(/1 to 3650/);
    expect(validateDraft({ ...d, dormantDays: '3651' }).errors.dormant_days).toBeDefined();
    expect(validateDraft({ ...d, dormantDays: 'soon' }).errors.dormant_days).toBeDefined();
    const r = validateDraft({
      ...d,
      dormantDays: ' 730 ',
      history: { ...d.history, provenance_dropped: 'block', version_anomaly: 'warn' },
    });
    expect(r.policy).toMatchObject({ dormant_days: 730, provenance_dropped: 'block', version_anomaly: 'warn', publisher_changed: 'warn' });
  });

  it('validates the new dependency window', () => {
    const d = policyToDraft(POLICY);
    expect(validateDraft({ ...d, youngDependencyDays: '0' }).errors.young_dependency_days).toMatch(/1 to 365/);
    expect(validateDraft({ ...d, youngDependencyDays: '366' }).errors.young_dependency_days).toBeDefined();
    const r = validateDraft({ ...d, youngDependencyDays: '30', history: { ...d.history, young_dependency_added: 'warn' } });
    expect(r.policy).toMatchObject({ young_dependency_days: 30, young_dependency_added: 'warn', nonregistry_dependency_added: 'block' });
  });

  it('rejects an entry on both lists', () => {
    const d = { ...policyToDraft(POLICY), deny: ['pypi:requests'] };
    expect(validateDraft(d).errors.deny).toMatch(/also on the allow list/);
  });
});
