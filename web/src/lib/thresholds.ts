import { useEffect, useState } from 'react';
import { api } from '../api/client';
import type { Thresholds, Verdict } from '../api/types';

/**
 * The thresholds for a verdict's gauges. Verdicts from the server carry them; for one that
 * does not, this asks `/api/model`, whose `thresholds` already have the policy overrides
 * applied. Nothing is fetched while there is no verdict.
 */
export function useThresholds(verdict: Verdict | null): Thresholds | null {
  const [t, setT] = useState<Thresholds | null>(null);
  const need = verdict !== null && verdict.thresholds === null && t === null;
  useEffect(() => {
    if (!need) return;
    const ctrl = new AbortController();
    api.model(ctrl.signal).then(
      (m) => {
        if (!ctrl.signal.aborted) setT(m.thresholds);
      },
      () => undefined,
    );
    return () => ctrl.abort();
  }, [need]);
  return verdict?.thresholds ?? (verdict ? t : null);
}
