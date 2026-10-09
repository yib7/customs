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
import type { PolicyChange } from '../api/types';
import { diffPolicies } from '../lib/policyLog';

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
  /** When set, PUT /api/policy needs `Authorization: Bearer <adminToken>`, as with CUSTOMS_ADMIN_TOKEN. */
  adminToken: string | null = null;
  /** Newest last, as GET /api/policy/changes reports them (newest first). */
  policyChanges: PolicyChange[] = [];
  private nextId: number;
  private listeners = new Set<Listener>();
  private rnd = mulberry32(99);

  constructor(now: number = Date.now()) {
    this.events = buildHistory(now);
    this.nextId = this.events.length + 1;
    for (const v of ALL_VERDICTS) this.verdicts.set(v.id, v);
    const day = 86_400_000;
    this.policyChanges = [
      {
        id: 1,
        ts: new Date(now - 6 * day).toISOString(),
        remote: '10.0.4.12',
        client: 'Mozilla/5.0',
        auth: 'token',
        changes: [{ field: 'deny', before: [], after: ['npm:event-stream@3.3.6'] }],
      },
      {
        id: 2,
        ts: new Date(now - 2 * day).toISOString(),
        remote: '10.0.4.12',
        client: 'Mozilla/5.0',
        auth: 'token',
        changes: [
          { field: 'allow', before: ['pypi:requests'], after: ['pypi:requests', 'npm:react'] },
          { field: 'min_age_days', before: 7, after: 3 },
        ],
      },
    ];
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

  handle(method: string, url: URL, body: unknown, headers: Headers = new Headers()): MockResponse {
    const path = url.pathname;
    if (method === 'GET' && path === '/api/events') return this.listEvents(url.searchParams);
    if (method === 'GET' && path.startsWith('/api/verdicts/')) {
      const id = decodeURIComponent(path.slice('/api/verdicts/'.length));
      const v = this.verdicts.get(id);
      return v ? json(200, v) : json(404, { error: `no verdict with id ${id}` });
    }
    if (method === 'GET' && path === '/api/stats') return json(200, this.stats());
    if (method === 'GET' && path === '/api/policy') return json(200, this.policy);
    if (method === 'GET' && path === '/api/policy/changes') {
      const limit = Math.min(500, Math.max(1, Number(url.searchParams.get('limit') ?? 50) || 50));
      return json(200, { changes: this.policyChanges.slice(-limit).reverse() });
    }
    if (method === 'PUT' && path === '/api/policy') {
      if (this.adminToken !== null) {
        const auth = headers.get('Authorization');
        if (!auth) return json(401, { error: 'changing the policy needs the admin token (Authorization: Bearer <token>)', code: 'admin_token_required' });
        if (auth !== `Bearer ${this.adminToken}`) return json(401, { error: 'the admin token is not valid', code: 'admin_token_invalid' });
      }
      return this.putPolicy(body, headers.has('Authorization') ? 'token' : 'none');
    }
    if (method === 'GET' && path === '/api/diff') return this.diff(url.searchParams);
    if (method === 'GET' && path === '/api/model') return json(200, this.model());
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

  /** GET /api/model: `thresholds` has the policy overrides applied, `model_thresholds` is the model's own. */
  private model() {
    const own = MODEL_INFO.thresholds;
    const pick = (t: unknown, m: number) => (typeof t === 'number' ? t : m);
    return {
      ...MODEL_INFO,
      untrained: false,
      thresholds: { ...own, warn: pick(this.policy.warn_threshold, own.warn), block: pick(this.policy.block_threshold, own.block) },
      model_thresholds: own,
    };
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

  private putPolicy(body: unknown, auth: 'token' | 'none' = 'none'): MockResponse {
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
      'unread_code',
      'startup_hook',
      'agent_bypass',
      'scan_error',
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
    const win = body.history_window_days;
    if (win !== undefined && (typeof win !== 'number' || !Number.isInteger(win) || win < 0 || win > 3650)) {
      errors.push({ field: 'history_window_days', message: 'history_window_days must be at most 3650' });
    }
    const young = body.young_dependency_days;
    if (young !== undefined && (typeof young !== 'number' || !Number.isInteger(young) || young < 1 || young > 365)) {
      errors.push({ field: 'young_dependency_days', message: 'young_dependency_days must be between 1 and 365' });
    }
    const est = body.established;
    if (est !== undefined) {
      const e: Record<string, unknown> = isRec(est) ? est : {};
      const top = e.top;
      if (top !== undefined && (typeof top !== 'number' || !Number.isInteger(top) || top < 1)) {
        errors.push({ field: 'established.top', message: 'must be at least 1 (set established.enabled = false to disable)' });
      }
      const days = e.min_age_days;
      if (days !== undefined && (typeof days !== 'number' || !Number.isInteger(days) || days < 1 || days > 3650)) {
        errors.push({ field: 'established.min_age_days', message: 'must be between 1 and 3650' });
      }
    }
    for (const f of ['allow', 'deny'] as const) {
      const list = body[f];
      if (!Array.isArray(list) || list.some((x) => typeof x !== 'string' || !ENTRY.test(x))) {
        errors.push({ field: f, message: `${f} entries must look like "pypi:name" or "npm:name@version"` });
      }
    }
    if (errors.length > 0) return json(422, { error: 'invalid policy', errors });
    const next = { ...this.policy, ...body };
    const changes = diffPolicies(this.policy, next);
    if (changes.length > 0) {
      const id = (this.policyChanges.at(-1)?.id ?? 0) + 1;
      this.policyChanges.push({ id, ts: new Date().toISOString(), remote: '127.0.0.1', client: 'Mozilla/5.0', auth, changes });
    }
    this.policy = next;
    return json(200, this.policy);
  }

  /** GET /api/diff for the fixture verdicts: the release before `x.y.z` is `x.y.(z-1)`. */
  private diff(q: URLSearchParams): MockResponse {
    const eco = q.get('ecosystem');
    const name = q.get('name') ?? '';
    const known = ALL_VERDICTS.find((v) => v.ecosystem === eco && v.name === name);
    if (!known || !known.version) return json(404, { error: `'${name}' does not exist on ${eco === 'pypi' ? 'PyPI' : 'npm'}` });
    const to = q.get('to') || known.version;
    const parts = to.split('.').map(Number);
    const patch = parts[2] ?? NaN;
    const from = q.get('from') || (parts.length === 3 && Number.isInteger(patch) && patch > 0 ? `${parts[0]}.${parts[1]}.${patch - 1}` : null);
    if (!from) return json(422, { error: `${name} ${to} has no earlier release to compare with; pass --from` });
    if (from === to) return json(422, { error: `both sides are ${name} ${to}; name two different versions` });
    const evidence = known.evidence ?? [];
    const day = 86_400_000;
    return json(200, {
      ecosystem: known.ecosystem,
      name,
      from: { version: from, published: new Date(Date.now() - 40 * day).toISOString(), filename: null },
      to: { version: to, published: new Date(Date.now() - day).toISOString(), filename: known.artifact },
      metadata: evidence.length > 0 ? [{ field: 'publisher', before: 'maintainer', after: 'new-account' }] : [],
      dependencies: evidence.length > 0 ? [{ name: 'dotenv-lite', before: null, after: '^0.1.0' }] : [],
      files: {
        added: [],
        modified: [{ path: 'index.js', size: 2048, lines_added: evidence.length * 3 + 1, lines_removed: 1 }],
        removed: [],
        unchanged: 12,
      },
      files_note: null,
      new_evidence: evidence,
      new_install_surface: [],
      verdict: known,
    });
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
