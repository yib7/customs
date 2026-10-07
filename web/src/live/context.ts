import { createContext, useContext, useEffect, useRef } from 'react';
import type { ConnectionStatus } from '../api/stream';
import type { CustomsEvent } from '../api/types';

export interface LiveValue {
  /** Most recent events, newest first. */
  events: CustomsEvent[];
  status: ConnectionStatus;
  loaded: boolean;
  error: Error | null;
  /** Ids of events that arrived live (not from the initial load), for highlighting. */
  liveIds: ReadonlySet<string>;
  /** Increments on every live event; useful to refresh derived data. */
  revision: number;
  subscribe: (fn: (e: CustomsEvent) => void) => () => void;
}

export const LiveContext = createContext<LiveValue | null>(null);

export function useLive(): LiveValue {
  const v = useContext(LiveContext);
  if (!v) throw new Error('useLive must be used inside <LiveProvider>');
  return v;
}

/** Calls `fn` for every new live event. */
export function useLiveEvents(fn: (e: CustomsEvent) => void): void {
  const { subscribe } = useLive();
  const ref = useRef(fn);
  useEffect(() => {
    ref.current = fn;
  });
  useEffect(() => subscribe((e) => ref.current(e)), [subscribe]);
}
