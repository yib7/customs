import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { api } from '../api/client';
import { LiveConnection, type ConnectionStatus } from '../api/stream';
import type { CustomsEvent } from '../api/types';
import { LiveContext, type LiveValue } from './context';

const MAX_EVENTS = 200;

export function LiveProvider({ children }: { children: ReactNode }) {
  const [events, setEvents] = useState<CustomsEvent[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>('connecting');
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [liveIds, setLiveIds] = useState<ReadonlySet<string>>(() => new Set());
  const [revision, setRevision] = useState(0);
  const listeners = useRef(new Set<(e: CustomsEvent) => void>());

  useEffect(() => {
    let cancelled = false;
    const conn = new LiveConnection({
      fetchEvents: () => api.events({ limit: 50 }),
      onStatus: (s) => {
        if (!cancelled) setStatus(s);
      },
      onEvent: (e) => {
        if (cancelled) return;
        setEvents((prev) => [e, ...prev.filter((p) => p.id !== e.id)].slice(0, MAX_EVENTS));
        setLiveIds((prev) => {
          const next = new Set(prev);
          next.add(e.id);
          return next;
        });
        setRevision((r) => r + 1);
        for (const l of listeners.current) l(e);
      },
    });
    const ctrl = new AbortController();
    api.events({ limit: 50 }, ctrl.signal).then(
      (initial) => {
        if (cancelled) return;
        conn.markSeen(initial.map((e) => e.id));
        setEvents((prev) => {
          const ids = new Set(prev.map((p) => p.id));
          return [...prev, ...initial.filter((e) => !ids.has(e.id))].slice(0, MAX_EVENTS);
        });
        setLoaded(true);
        setError(null);
      },
      (e: unknown) => {
        if (cancelled || (e instanceof DOMException && e.name === 'AbortError')) return;
        setError(e instanceof Error ? e : new Error(String(e)));
        setLoaded(true);
      },
    );
    conn.start();
    return () => {
      cancelled = true;
      ctrl.abort();
      conn.stop();
    };
  }, []);

  const subscribe = useCallback((fn: (e: CustomsEvent) => void) => {
    listeners.current.add(fn);
    return () => {
      listeners.current.delete(fn);
    };
  }, []);

  const value = useMemo<LiveValue>(
    () => ({ events, status, loaded, error, liveIds, revision, subscribe }),
    [events, status, loaded, error, liveIds, revision, subscribe],
  );
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}
