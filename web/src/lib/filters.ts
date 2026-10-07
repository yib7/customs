import type { CustomsEvent, EventQuery } from '../api/types';

/** Client-side event filter, applied even if the server already filtered (it may ignore params). */
export function matchesFilter(e: CustomsEvent, q: EventQuery): boolean {
  if (q.decision && e.decision !== q.decision) return false;
  if (q.ecosystem && e.ecosystem !== q.ecosystem) return false;
  if (q.kind && e.kind !== q.kind) return false;
  if (q.q && !e.name.toLowerCase().includes(q.q.toLowerCase())) return false;
  return true;
}
