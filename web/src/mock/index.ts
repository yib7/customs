// Wires the in-memory MockServer into the browser: patches window.fetch for same-origin
// /api requests and replaces window.EventSource with a fake stream.
// Exposes window.__customsMock for Playwright to push events or drop the stream.

import { MockServer } from './server';
import { BLOCKED_TYPOSQUAT, type RawEvent } from './fixtures';

export interface MockControls {
  server: MockServer;
  /** Pushes a random event through the stream. */
  emit: () => RawEvent;
  /** Pushes a blocked typosquat event through the stream. */
  emitBlocked: () => RawEvent;
  /** Simulates a dropped SSE connection (the client should reconnect). */
  dropStream: () => void;
  /** Makes the stream fail to connect until re-enabled. */
  setStreamAvailable: (ok: boolean) => void;
}

declare global {
  interface Window {
    __customsMock?: MockControls;
    __CUSTOMS_MOCK_NO_AUTO?: boolean;
    __CUSTOMS_MOCK_LATENCY?: number;
  }
}

const READY = { CONNECTING: 0, OPEN: 1, CLOSED: 2 } as const;

/** The browser's own fetch, kept from the first install so a fresh mock does not wrap an old one. */
let nativeFetch: typeof window.fetch | null = null;

/**
 * Installs the mock API once and returns its controls. `fresh` replaces an installed mock
 * with a new server in its initial state (tests use it so no state leaks between them).
 */
export function installMocks(opts: { latencyMs?: number; autoEmitMs?: number; fresh?: boolean } = {}): MockControls {
  if (window.__customsMock && !opts.fresh) return window.__customsMock;
  const server = new MockServer();
  nativeFetch ??= window.fetch.bind(window);
  const realFetch = nativeFetch;
  const streams = new Set<MockEventSource>();
  let streamAvailable = true;

  const latency = () => window.__CUSTOMS_MOCK_LATENCY ?? opts.latencyMs ?? 120;

  window.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(raw, window.location.origin);
    const isApi = url.origin === window.location.origin && url.pathname.startsWith('/api/');
    if (!isApi) return realFetch(input, init);
    const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
    let body: unknown = null;
    if (typeof init?.body === 'string') {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = init.body;
      }
    }
    await new Promise<void>((resolve, reject) => {
      const signal = init?.signal;
      if (signal?.aborted) {
        reject(new DOMException('Aborted', 'AbortError'));
        return;
      }
      const t = setTimeout(resolve, latency());
      signal?.addEventListener('abort', () => {
        clearTimeout(t);
        reject(new DOMException('Aborted', 'AbortError'));
      });
    });
    const res = server.handle(method, url, body, new Headers(init?.headers));
    const isText = typeof res.body === 'string';
    return new Response(isText ? (res.body as string) : JSON.stringify(res.body), {
      status: res.status,
      headers: { 'Content-Type': res.contentType ?? (isText ? 'text/plain' : 'application/json'), ...res.headers },
    });
  };

  class MockEventSource extends EventTarget {
    static readonly CONNECTING = READY.CONNECTING;
    static readonly OPEN = READY.OPEN;
    static readonly CLOSED = READY.CLOSED;
    readonly CONNECTING = READY.CONNECTING;
    readonly OPEN = READY.OPEN;
    readonly CLOSED = READY.CLOSED;
    readonly url: string;
    readonly withCredentials = false;
    readyState: number = READY.CONNECTING;
    onopen: ((ev: Event) => unknown) | null = null;
    onerror: ((ev: Event) => unknown) | null = null;
    onmessage: ((ev: MessageEvent) => unknown) | null = null;

    constructor(url: string | URL) {
      super();
      this.url = String(url);
      setTimeout(() => {
        if (this.readyState === READY.CLOSED) return;
        if (!streamAvailable) {
          this.fail();
          return;
        }
        this.readyState = READY.OPEN;
        streams.add(this);
        this.onopen?.(new Event('open'));
        this.dispatchEvent(new Event('open'));
      }, 60);
    }

    deliver(e: RawEvent): void {
      if (this.readyState !== READY.OPEN) return;
      this.dispatchEvent(new MessageEvent('install', { data: JSON.stringify(e) }));
    }

    fail(): void {
      streams.delete(this);
      this.readyState = READY.CLOSED;
      this.onerror?.(new Event('error'));
      this.dispatchEvent(new Event('error'));
    }

    close(): void {
      this.readyState = READY.CLOSED;
      streams.delete(this);
    }
  }

  server.subscribe((e) => {
    for (const s of streams) s.deliver(e);
  });

  window.EventSource = MockEventSource as unknown as typeof EventSource;

  const controls: MockControls = {
    server,
    emit: () => server.emitRandom(),
    emitBlocked: () => {
      const v = server.verdicts.get(BLOCKED_TYPOSQUAT.id);
      if (!v) return server.emitRandom();
      return server.record({
        ecosystem: v.ecosystem,
        name: v.name,
        version: v.version,
        client: 'claude-code',
        kind: 'check',
        decision: v.decision,
        risk: v.risk,
        verdict_id: v.id,
      });
    },
    dropStream: () => {
      for (const s of [...streams]) s.fail();
    },
    setStreamAvailable: (ok: boolean) => {
      streamAvailable = ok;
      if (!ok) for (const s of [...streams]) s.fail();
    },
  };
  window.__customsMock = controls;

  const autoMs = opts.autoEmitMs ?? 15000;
  if (autoMs > 0) {
    setInterval(() => {
      if (!window.__CUSTOMS_MOCK_NO_AUTO) server.emitRandom();
    }, autoMs);
  }
  return controls;
}
