// In-memory mock of the Customs HTTP API (DESIGN.md section 7). Used by `vite --mode mock`,
// the mock-mode build that Playwright runs against, and unit tests. Never bundled into the
// production build: main.tsx imports it only when VITE_MOCK is "1".

import {
  AGENT_CLIENT,
  ALL_VERDICTS,
  ALLOWED,
  BLOCKED_TYPOSQUAT,
  INITIAL_POLICY,
  MODEL_INFO,
  MODEL_VERSION,
  NONEXISTENT,
  buildHistory,
  eventFromVerdict,
  fakeSha,
  mulberry32,
  pick,
  nonexistentEvent,
  type RawEvent,
  type RawVerdict,
} from './fixtures';

export interface MockResponse {
  status: number;
  body: unknown;
  contentType?: string;
}

type Listener = (e: RawEvent) => void;

function json(status: number, body: unknown): MockResponse {
  return { status, body };
}

function isRec(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const ENTRY = /^(pypi|npm):(@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*(@[A-Za-z0-9.+!_-]+)?$/i;

export class MockServer {
  events: RawEvent[];
  verdicts = new Map<string, RawVerdict>();
  policy: Record<string, unknown> = structuredClone(INITIAL_POLICY);
  private nextId: number;
  private listeners = new Set<Listener>();
  private rnd = mulberry32(99);

  constructor(now: number = Date.now()) {
    this.events = buildHistory(now);
    this.nextId = this.events.length + 1;
    for (const v of ALL_VERDICTS) this.verdicts.set(v.id, v);
  }

  subscribe(fn: Listener): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  /** Records an event and pushes it to stream subscribers. */
  record(e: Omit<RawEvent, 'id' | 'ts'> & { ts?: string }): RawEvent {
    const ev: RawEvent = { ...e, id: this.nextId++, ts: e.ts ?? new Date().toISOString() };
    this.events.push(ev);
    for (const l of this.listeners) l(ev);
    return ev;
  }

  /** Emits a plausible random install event. */
  emitRandom(): RawEvent {
    const r = this.rnd();
    if (r < 0.12) {
      return this.record({ ...strip(eventFromVerdict(BLOCKED_TYPOSQUAT, 0, new Date(), AGENT_CLIENT, 'check')) });
    }
    if (r < 0.2) {
      const pkg = pick(NONEXISTENT, this.rnd());
      return this.record(strip(nonexistentEvent(pkg, 0, new Date(), AGENT_CLIENT)));
    }
    const v = pick(ALLOWED, this.rnd());
    const client = v.ecosystem === 'pypi' ? 'pip/24.2' : 'npm/10.8.3';
    return this.record(strip(eventFromVerdict(v, 0, new Date(), client, 'install')));
  }

  handle(method: string, url: URL, body: unknown): MockResponse {
    const path = url.pathname;
    if (method === 'GET' && path === '/api/events') return this.listEvents(url.searchParams);
    if (method === 'GET' && path.startsWith('/api/verdicts/')) {
      const id = decodeURIComponent(path.slice('/api/verdicts/'.length));
      const v = this.verdicts.get(id);
      return v ? json(200, v) : json(404, { error: `no verdict with id ${id}` });
    }
    if (method === 'GET' && path === '/api/stats') return json(200, this.stats());
    if (method === 'GET' && path === '/api/policy') return json(200, this.policy);
    if (method === 'PUT' && path === '/api/policy') return this.putPolicy(body);
    if (method === 'GET' && path === '/api/model') return json(200, MODEL_INFO);
    if (method === 'POST' && path === '/api/check') return this.check(body);
    if (method === 'GET' && path === '/healthz') return { status: 200, body: 'ok', contentType: 'text/plain' };
    if (method === 'GET' && path === '/metrics') {
      return {
        status: 200,
        contentType: 'text/plain; version=0.0.4',
        body: `# TYPE customs_events_total counter\ncustoms_events_total ${this.events.length}\n`,
      };
    }
    return json(404, { error: `not found: ${method} ${path}` });
  }

  private listEvents(q: URLSearchParams): MockResponse {
    const limit = Math.min(500, Math.max(1, Number(q.get('limit') ?? 50) || 50));
    const before = q.get('before');
    const decision = q.get('decision');
    const ecosystem = q.get('ecosystem');
    const kind = q.get('kind');
    const text = (q.get('q') ?? '').toLowerCase();
    const out: RawEvent[] = [];
    for (let i = this.events.length - 1; i >= 0 && out.length < limit; i--) {
      const e = this.events[i];
      if (!e) continue;
      if (before && !(e.id < Number(before))) continue;
      if (decision && e.decision !== decision) continue;
      if (ecosystem && e.ecosystem !== ecosystem) continue;
      if (kind && e.kind !== kind) continue;
      if (text && !e.name.toLowerCase().includes(text)) continue;
      out.push(e);
    }
    return json(200, out);
  }

  stats(now: number = Date.now()) {
    const byDecision = { allow: 0, warn: 0, block: 0 };
    const byEco: Record<string, { allow: number; warn: number; block: number }> = {};
    const byKind = { install: 0, check: 0, nonexistent_package: 0 };
    const days = new Map<string, number>();
    for (let d = 13; d >= 0; d--) days.set(new Date(now - d * 86400000).toISOString().slice(0, 10), 0);
    const reasons = new Map<string, { label: string | null; count: number }>();
    for (const e of this.events) {
      byKind[e.kind] += 1;
      if (!e.decision) continue;
      byDecision[e.decision] += 1;
      const eco = (byEco[e.ecosystem] ??= { allow: 0, warn: 0, block: 0 });
      eco[e.decision] += 1;
      if (e.decision === 'block') {
        const day = e.ts.slice(0, 10);
        if (days.has(day)) days.set(day, (days.get(day) ?? 0) + 1);
      }
      if (e.decision !== 'allow') {
        if (e.kind === 'nonexistent_package') {
          const r = reasons.get('block_nonexistent') ?? { label: 'Package does not exist on the registry', count: 0 };
          r.count += 1;
          reasons.set('block_nonexistent', r);
        }
        const v = e.verdict_id ? this.verdicts.get(e.verdict_id) : undefined;
        if (v) {
          for (const reason of v.reasons.filter((x) => x.contribution > 0).slice(0, 3)) {
            const r = reasons.get(reason.feature) ?? { label: null, count: 0 };
            r.count += 1;
            reasons.set(reason.feature, r);
          }
        }
      }
    }
    return {
      total: this.events.length,
      by_decision: byDecision,
      by_ecosystem: byEco,
      by_kind: byKind,
      blocks_per_day: [...days.entries()].map(([date, count]) => ({ date, count })),
      top_reasons: [...reasons.entries()]
        .map(([feature, r]) => ({ feature, label: r.label, count: r.count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 6),
    };
  }

  private putPolicy(body: unknown): MockResponse {
    if (!isRec(body)) return json(400, { error: 'body must be a JSON object' });
    const errors: { field: string; message: string }[] = [];
    if (body.mode !== 'enforce' && body.mode !== 'monitor') errors.push({ field: 'mode', message: 'mode must be "enforce" or "monitor"' });
    for (const f of ['warn_threshold', 'block_threshold'] as const) {
      const v = body[f];
      if (v !== 'model' && !(typeof v === 'number' && v >= 0 && v <= 1)) {
        errors.push({ field: f, message: `${f} must be "model" or a number between 0 and 1` });
      }
    }
    const age = body.min_age_days;
    if (typeof age !== 'number' || !Number.isInteger(age) || age < 0) {
      errors.push({ field: 'min_age_days', message: 'min_age_days must be a non-negative integer' });
    } else if (age > 365) {
      // A server-side limit the form does not know about, so the UI's handling of server
      // validation errors can be exercised.
      errors.push({ field: 'min_age_days', message: 'min_age_days must be at most 365 (server limit)' });
    }
    for (const f of [
      'provenance_dropped',
      'install_script_added',
      'publisher_changed',
      'dormant_revival',
      'version_anomaly',
      'nonregistry_dependency_added',
      'young_dependency_added',
    ] as const) {
      const v = body[f];
      if (v !== undefined && v !== 'off' && v !== 'warn' && v !== 'block') {
        errors.push({ field: f, message: `${f} must be "off", "warn" or "block"` });
      }
    }
    const dormant = body.dormant_days;
    if (dormant !== undefined && (typeof dormant !== 'number' || !Number.isInteger(dormant) || dormant < 1 || dormant > 3650)) {
      errors.push({ field: 'dormant_days', message: 'dormant_days must be between 1 and 3650' });
    }
    const young = body.young_dependency_days;
    if (young !== undefined && (typeof young !== 'number' || !Number.isInteger(young) || young < 1 || young > 365)) {
      errors.push({ field: 'young_dependency_days', message: 'young_dependency_days must be between 1 and 365' });
    }
    for (const f of ['allow', 'deny'] as const) {
      const list = body[f];
      if (!Array.isArray(list) || list.some((x) => typeof x !== 'string' || !ENTRY.test(x))) {
        errors.push({ field: f, message: `${f} entries must look like "pypi:name" or "npm:name@version"` });
      }
    }
    if (errors.length > 0) return json(422, { error: 'invalid policy', errors });
    this.policy = { ...this.policy, ...body };
    return json(200, this.policy);
  }

  private check(body: unknown): MockResponse {
    if (!isRec(body)) return json(400, { error: 'body must be a JSON object' });
    const eco = body.ecosystem;
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    const version = typeof body.version === 'string' && body.version ? body.version : null;
    if (eco !== 'pypi' && eco !== 'npm') return json(400, { error: 'ecosystem must be "pypi" or "npm"' });
    if (!name) return json(400, { error: 'name is required' });

    const known = ALL_VERDICTS.find((v) => v.ecosystem === eco && v.name.toLowerCase() === name.toLowerCase());
    if (known) {
      this.record(strip(eventFromVerdict(known, 0, new Date(), 'dashboard', 'check')));
      return json(200, known);
    }
    const missing =
      NONEXISTENT.some((n) => n.ecosystem === eco && n.name === name) || /(-pro|-utils-ai|hallucinated)$/.test(name);
    if (missing) {
      this.record(strip(nonexistentEvent({ ecosystem: eco, name }, 0, new Date(), 'dashboard')));
      return json(404, {
        error: `${name} does not exist on ${eco === 'pypi' ? 'PyPI' : 'npm'}`,
        code: 'nonexistent_package',
      });
    }
    // Unknown but plausible package: synthesize a clean verdict.
    const r = mulberry32(name.length * 7919 + name.charCodeAt(0));
    const ver = version ?? `${1 + Math.floor(r() * 4)}.${Math.floor(r() * 12)}.${Math.floor(r() * 9)}`;
    const risk = Math.round((0.002 + r() * 0.05) * 1000) / 1000;
    const id = `v_chk${fakeSha(`${eco}:${name}@${ver}`).slice(0, 6)}`;
    const verdict: RawVerdict = {
      id,
      ecosystem: eco,
      name,
      version: ver,
      artifact: eco === 'pypi' ? `${name.replace(/-/g, '_')}-${ver}-py3-none-any.whl` : `${name.split('/').pop() ?? name}-${ver}.tgz`,
      sha256: fakeSha(`${eco}:${name}@${ver}`),
      decision: 'allow',
      risk,
      scores: { code_gbdt: risk, code_nn: Math.round(r() * 0.06 * 1000) / 1000, name: Math.round(r() * 0.1 * 1000) / 1000 },
      policy_hits: [],
      reasons: [
        { feature: 'meta_has_repo', value: 1, contribution: -0.55, label: 'Links a source repository' },
        { feature: 'inst_proc_exec', value: 0, contribution: -0.31, label: 'No shell commands at install time' },
        { feature: 'all_url', value: 3, contribution: 0.08, label: 'Contains a few URLs (documentation links)' },
      ],
      evidence: [],
      scanned_ms: 11 + Math.floor(r() * 30),
      model_version: MODEL_VERSION,
      cached: false,
    };
    this.verdicts.set(id, verdict);
    this.record(strip(eventFromVerdict(verdict, 0, new Date(), 'dashboard', 'check')));
    return json(200, verdict);
  }
}

function strip(e: RawEvent): Omit<RawEvent, 'id' | 'ts'> {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { id, ts, ...rest } = e;
  return rest;
}
