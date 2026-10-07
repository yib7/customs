import { useEffect, useState } from 'react';
import { api } from '../api/client';
import type { ModelInfo, Policy, Thresholds, Verdict } from '../api/types';

/**
 * Effective decision thresholds: numeric policy overrides win over the model's own
 * thresholds (ensemble.json), as described in DESIGN.md section 8.
 */
export function effectiveThresholds(model: ModelInfo | null, policy: Policy | null): Thresholds | null {
  const base = model?.thresholds ?? null;
  const warn = typeof policy?.warn_threshold === 'number' ? policy.warn_threshold : base?.warn;
  const block = typeof policy?.block_threshold === 'number' ? policy.block_threshold : base?.block;
  if (warn === undefined || block === undefined) return null;
  return { warn, block };
}

/** Loads model and policy (both optional) to find the thresholds for gauges. */
export function useThresholds(verdict: Verdict | null): Thresholds | null {
  const [t, setT] = useState<Thresholds | null>(null);
  useEffect(() => {
    const ctrl = new AbortController();
    Promise.allSettled([api.model(ctrl.signal), api.policy(ctrl.signal)]).then(([m, p]) => {
      if (ctrl.signal.aborted) return;
      setT(effectiveThresholds(m.status === 'fulfilled' ? m.value : null, p.status === 'fulfilled' ? p.value : null));
    });
    return () => ctrl.abort();
  }, []);
  return verdict?.thresholds ?? t;
}
