import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LiveConnection, backoffDelay, type ConnectionStatus } from './stream';
import type { CustomsEvent } from './types';

class FakeES extends EventTarget {
  static instances: FakeES[] = [];
  onopen: ((e: Event) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  closed = false;
  constructor(public url: string) {
    super();
    FakeES.instances.push(this);
  }
  open() {
    this.onopen?.(new Event('open'));
  }
  fail() {
    this.onerror?.(new Event('error'));
  }
  send(data: unknown) {
    this.dispatchEvent(new MessageEvent('install', { data: JSON.stringify(data) }));
  }
  close() {
    this.closed = true;
  }
}

const ev = (id: number): CustomsEvent => ({
  id: String(id),
  ts: '2026-10-07T10:00:00.000Z',
  ecosystem: 'pypi',
  name: `pkg${id}`,
  version: '1.0',
  client: 'pip',
  kind: 'install',
  decision: 'allow',
  risk: 0.01,
  verdict_id: `v${id}`,
});

describe('backoffDelay', () => {
  it('grows exponentially with jitter and a cap', () => {
    expect(backoffDelay(0, 1000, 30000, () => 1)).toBe(1000);
    expect(backoffDelay(0, 1000, 30000, () => 0)).toBe(500);
    expect(backoffDelay(3, 1000, 30000, () => 1)).toBe(8000);
    expect(backoffDelay(10, 1000, 30000, () => 1)).toBe(30000);
  });
});

describe('LiveConnection', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    FakeES.instances = [];
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  function setup(fetchEvents = vi.fn(async () => [] as CustomsEvent[])) {
    const events: CustomsEvent[] = [];
    const statuses: ConnectionStatus[] = [];
    const conn = new LiveConnection({
      EventSourceImpl: FakeES as unknown as typeof EventSource,
      onEvent: (e) => events.push(e),
      onStatus: (s) => statuses.push(s),
      fetchEvents,
      random: () => 1,
    });
    return { conn, events, statuses, fetchEvents };
  }

  it('delivers parsed install events and dedupes ids', () => {
    const { conn, events, statuses } = setup();
    conn.markSeen(['1']);
    conn.start();
    const es = FakeES.instances[0]!;
    es.open();
    es.send({ ...ev(1), id: 1 });
    es.send({ ...ev(2), id: 2 });
    es.send({ ...ev(2), id: 2 });
    es.dispatchEvent(new MessageEvent('install', { data: '{not json' }));
    expect(events.map((e) => e.id)).toEqual(['2']);
    expect(statuses).toEqual(['connecting', 'live']);
    conn.stop();
    expect(es.closed).toBe(true);
  });

  it('reconnects with backoff and falls back to polling after repeated failures', async () => {
    const fetchEvents = vi.fn(async () => [ev(5), ev(4)]);
    const { conn, events, statuses } = setup(fetchEvents);
    conn.start();
    FakeES.instances[0]!.fail();
    expect(statuses.at(-1)).toBe('reconnecting');
    await vi.advanceTimersByTimeAsync(1000);
    expect(FakeES.instances).toHaveLength(2);
    FakeES.instances[1]!.fail();
    await vi.advanceTimersByTimeAsync(2000);
    expect(FakeES.instances).toHaveLength(3);
    FakeES.instances[2]!.fail();
    expect(statuses.at(-1)).toBe('polling');
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchEvents).toHaveBeenCalled();
    // Oldest first so that consumers prepending end up newest first.
    expect(events.map((e) => e.id)).toEqual(['4', '5']);
    // SSE is retried while polling; when it opens, polling stops.
    await vi.advanceTimersByTimeAsync(60000);
    const latest = FakeES.instances.at(-1)!;
    latest.open();
    expect(statuses.at(-1)).toBe('live');
    conn.stop();
  });

  it('catches up on the first open, so events from before the subscription are not lost', async () => {
    const { conn, events } = setup(vi.fn(async () => [ev(3), ev(2)]));
    conn.markSeen(['2']);
    conn.start();
    FakeES.instances[0]!.open();
    await vi.advanceTimersByTimeAsync(0);
    expect(events.map((e) => e.id)).toEqual(['3']);
    conn.stop();
  });

  it('catches up when the server says the stream lagged', async () => {
    let server: CustomsEvent[] = [];
    const { conn, events } = setup(vi.fn(async () => server));
    conn.start();
    const es = FakeES.instances[0]!;
    es.open();
    await vi.advanceTimersByTimeAsync(0);
    server = [ev(9), ev(8)];
    es.dispatchEvent(new MessageEvent('lagged', { data: '2' }));
    await vi.advanceTimersByTimeAsync(0);
    expect(events.map((e) => e.id)).toEqual(['8', '9']);
    conn.stop();
  });

  it('survives a failed catch-up and reports successful ones', async () => {
    const fetchEvents = vi.fn(async (): Promise<CustomsEvent[]> => {
      throw new Error('down');
    });
    const onCatchUp = vi.fn();
    const conn = new LiveConnection({
      EventSourceImpl: FakeES as unknown as typeof EventSource,
      onEvent: () => undefined,
      onStatus: () => undefined,
      onCatchUp,
      fetchEvents,
    });
    conn.start();
    FakeES.instances[0]!.open();
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchEvents).toHaveBeenCalledTimes(1);
    expect(onCatchUp).not.toHaveBeenCalled();
    fetchEvents.mockResolvedValueOnce([]);
    FakeES.instances[0]!.dispatchEvent(new MessageEvent('lagged', { data: '1' }));
    await vi.advanceTimersByTimeAsync(0);
    expect(onCatchUp).toHaveBeenCalledTimes(1);
    conn.stop();
  });

  it('polls directly when EventSource is unavailable and reports offline on errors', async () => {
    const fetchEvents = vi.fn(async (): Promise<CustomsEvent[]> => {
      throw new Error('down');
    });
    const statuses: ConnectionStatus[] = [];
    const conn = new LiveConnection({
      EventSourceImpl: undefined,
      onEvent: () => undefined,
      onStatus: (s) => statuses.push(s),
      fetchEvents,
    });
    conn.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(statuses).toEqual(['polling', 'offline']);
    conn.stop();
  });
});
