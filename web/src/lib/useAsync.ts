import { useCallback, useEffect, useRef, useState } from 'react';

export interface AsyncState<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  reload: () => void;
}

/**
 * Runs `fn` on mount and whenever `key` changes, aborting stale requests. `reload` re-runs
 * it while keeping the previous data visible (no loading flash).
 */
export function useAsync<T>(fn: (signal: AbortSignal) => Promise<T>, key: string): AsyncState<T> {
  const [state, setState] = useState<{ data: T | null; error: Error | null; loading: boolean; key: string }>({
    data: null,
    error: null,
    loading: true,
    key,
  });
  const [tick, setTick] = useState(0);
  const fnRef = useRef(fn);
  useEffect(() => {
    fnRef.current = fn;
  });

  // Reset when the key changes (render-time state adjustment, no effect needed).
  if (state.key !== key) {
    setState({ data: null, error: null, loading: true, key });
  }

  useEffect(() => {
    const ctrl = new AbortController();
    fnRef.current(ctrl.signal).then(
      (data) => {
        if (!ctrl.signal.aborted) setState({ data, error: null, loading: false, key });
      },
      (error: unknown) => {
        if (ctrl.signal.aborted) return;
        if (error instanceof DOMException && error.name === 'AbortError') return;
        setState((s) => ({ ...s, error: error instanceof Error ? error : new Error(String(error)), loading: false }));
      },
    );
    return () => ctrl.abort();
  }, [key, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data: state.data, error: state.error, loading: state.loading, reload };
}
