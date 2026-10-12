// Live event connection: Server-Sent Events from /api/events/stream with exponential
// backoff, falling back to polling /api/events when SSE keeps failing (for example behind
// a proxy that buffers responses). While polling, SSE is retried periodically.

import { parseEvent } from './parse';
import type { CustomsEvent } from './types';

export type ConnectionStatus = 'connecting' | 'live' | 'reconnecting' | 'polling' | 'offline';

export interface LiveOptions {
  onEvent: (e: CustomsEvent) => void;
  onStatus: (s: ConnectionStatus) => void;
  /** Fetches the newest events (newest first). Used for polling and catch-up. */
  fetchEvents: () => Promise<CustomsEvent[]>;
  /** Called after each successful catch-up or poll: the server answered. */
  onCatchUp?: () => void;
  url?: string;
  pollIntervalMs?: number;
  maxFailuresBeforePolling?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  sseRetryWhilePollingMs?: number;
  EventSourceImpl?: typeof EventSource | undefined;
  random?: () => number;
}

/** Exponential backoff with jitter: the result lies in [delay / 2, delay]. */
export function backoffDelay(attempt: number, baseMs: number, maxMs: number, random: () => number = Math.random): number {
  const exp = Math.min(maxMs, baseMs * 2 ** Math.max(0, attempt));
  return Math.round(exp * (0.5 + random() * 0.5));
}

const MAX_SEEN = 2000;

export class LiveConnection {
  private readonly opts: Required<Omit<LiveOptions, 'EventSourceImpl'>> & { EventSourceImpl: typeof EventSource | undefined };
  private es: EventSource | null = null;
  private failures = 0;
  private hadOpen = false;
  private polling = false;
  private stopped = true;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private pollTimer: ReturnType<typeof setTimeout> | null = null;
  private pollFailures = 0;
  private status: ConnectionStatus | null = null;
  private readonly seen = new Set<string>();

  constructor(options: LiveOptions) {
    this.opts = {
      url: '/api/events/stream',
      pollIntervalMs: 5000,
      maxFailuresBeforePolling: 3,
      baseDelayMs: 1000,
      maxDelayMs: 30000,
      sseRetryWhilePollingMs: 60000,
      random: Math.random,
      onCatchUp: () => undefined,
      ...options,
      EventSourceImpl: 'EventSourceImpl' in options ? options.EventSourceImpl : globalThis.EventSource,
    };
  }

  /** Marks events as already delivered (for example the initial page load). */
  markSeen(ids: Iterable<string>): void {
    for (const id of ids) this.seen.add(id);
    this.trimSeen();
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    if (!this.opts.EventSourceImpl) {
      this.startPolling();
      return;
    }
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    this.closeEs();
    this.clearTimer('reconnect');
    this.clearTimer('poll');
    this.polling = false;
  }

  private setStatus(s: ConnectionStatus): void {
    if (this.status === s) return;
    this.status = s;
    this.opts.onStatus(s);
  }

  private deliver(e: CustomsEvent): void {
    if (this.seen.has(e.id)) return;
    this.seen.add(e.id);
    this.trimSeen();
    this.opts.onEvent(e);
  }

  private trimSeen(): void {
    if (this.seen.size <= MAX_SEEN) return;
    const drop = this.seen.size - MAX_SEEN;
    let i = 0;
    for (const id of this.seen) {
      if (i++ >= drop) break;
      this.seen.delete(id);
    }
  }

  private connect(): void {
    if (this.stopped || !this.opts.EventSourceImpl) return;
    if (!this.polling) this.setStatus(this.failures === 0 && !this.hadOpen ? 'connecting' : 'reconnecting');
    let es: EventSource;
    try {
      es = new this.opts.EventSourceImpl(this.opts.url);
    } catch {
      this.onSseFailure();
      return;
    }
    this.es = es;
    es.onopen = () => {
      this.failures = 0;
      this.hadOpen = true;
      if (this.polling) {
        this.polling = false;
        this.clearTimer('poll');
      }
      this.setStatus('live');
      // Fetch what the stream did not carry: events from before this subscription (on the
      // first open, those between the page's initial load and now) or during an outage.
      // Delivery dedupes ids, so the overlap with events already shown is dropped.
      this.catchUpQuietly();
    };
    es.addEventListener('install', (msg) => {
      const data = (msg as MessageEvent<unknown>).data;
      if (typeof data !== 'string') return;
      try {
        const ev = parseEvent(JSON.parse(data));
        if (ev) this.deliver(ev);
      } catch {
        // Ignore malformed frames.
      }
    });
    // The server dropped events for this slow client; refetch the newest ones.
    es.addEventListener('lagged', () => this.catchUpQuietly());
    es.onerror = () => {
      if (this.es !== es) return;
      this.onSseFailure();
    };
  }

  private onSseFailure(): void {
    this.closeEs();
    if (this.stopped) return;
    this.failures += 1;
    if (!this.polling && this.failures >= this.opts.maxFailuresBeforePolling) {
      this.startPolling();
    }
    const delay = this.polling
      ? this.opts.sseRetryWhilePollingMs
      : backoffDelay(this.failures - 1, this.opts.baseDelayMs, this.opts.maxDelayMs, this.opts.random);
    if (!this.polling) this.setStatus('reconnecting');
    this.clearTimer('reconnect');
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  private startPolling(): void {
    if (this.polling || this.stopped) return;
    this.polling = true;
    this.pollFailures = 0;
    this.setStatus('polling');
    void this.pollOnce();
  }

  private async pollOnce(): Promise<void> {
    if (!this.polling || this.stopped) return;
    try {
      await this.catchUp();
      this.pollFailures = 0;
      if (this.polling) this.setStatus('polling');
    } catch {
      this.pollFailures += 1;
      if (this.polling) this.setStatus('offline');
    }
    if (!this.polling || this.stopped) return;
    const delay =
      this.pollFailures === 0
        ? this.opts.pollIntervalMs
        : backoffDelay(this.pollFailures, this.opts.pollIntervalMs, this.opts.maxDelayMs, this.opts.random);
    this.clearTimer('poll');
    this.pollTimer = setTimeout(() => {
      this.pollTimer = null;
      void this.pollOnce();
    }, delay);
  }

  private async catchUp(): Promise<void> {
    const events = await this.opts.fetchEvents();
    if (this.stopped) return;
    // Deliver oldest first so consumers that prepend end up newest first.
    for (const e of [...events].reverse()) this.deliver(e);
    this.opts.onCatchUp();
  }

  /** A catch-up whose failure is ignored: the stream itself is up, and the next one retries. */
  private catchUpQuietly(): void {
    this.catchUp().catch(() => undefined);
  }

  private closeEs(): void {
    if (this.es) {
      this.es.onopen = null;
      this.es.onerror = null;
      this.es.close();
      this.es = null;
    }
  }

  private clearTimer(which: 'reconnect' | 'poll'): void {
    if (which === 'reconnect' && this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (which === 'poll' && this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
  }
}
