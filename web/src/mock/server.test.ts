// The mock stands in for the Rust server in tests, dev mode and the e2e run, so it must
// answer with the server's shapes and status codes (crates/customs/src/api.rs).
import { describe, expect, it } from 'vitest';
import { MockServer } from './server';

const NOW = Date.parse('2026-10-07T12:00:00Z');

function get(server: MockServer, path: string) {
  return server.handle('GET', new URL(path, 'http://localhost'), null);
}

describe('MockServer matches the server contract', () => {
  it('uses numeric verdict and event ids, as the server does (i64)', () => {
    const server = new MockServer(NOW);
    const events = get(server, '/api/events?limit=500').body as { id: unknown; verdict_id: unknown }[];
    const withVerdict = events.find((e) => e.verdict_id !== null);
    expect(typeof withVerdict?.verdict_id).toBe('number');
    expect(typeof events[0]?.id).toBe('number');
    const verdict = get(server, `/api/verdicts/${String(withVerdict?.verdict_id)}`);
    expect(verdict.status).toBe(200);
    expect(verdict.body).toMatchObject({ id: withVerdict?.verdict_id, mode: 'enforce' });
    expect(verdict.body).toHaveProperty('model_decision');
    expect(verdict.body).toHaveProperty('ts');
    expect(verdict.body).toHaveProperty('thresholds');
  });

  it('rejects a non-numeric verdict id with a plain-text 400, like axum', () => {
    const res = get(new MockServer(NOW), '/api/verdicts/abc');
    expect(res.status).toBe(400);
    expect(typeof res.body).toBe('string');
  });

  it('answers an invalid policy with 400 and field errors', () => {
    const server = new MockServer(NOW);
    const res = server.handle('PUT', new URL('http://localhost/api/policy'), { ...server.policy, min_age_days: -1 });
    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({ errors: [{ field: 'min_age_days' }] });
  });

  it('answers a nonexistent package with code and the verdict', () => {
    const res = new MockServer(NOW).handle('POST', new URL('http://localhost/api/check'), {
      ecosystem: 'pypi',
      name: 'huggingface-cli',
    });
    expect(res.status).toBe(404);
    expect(res.body).toMatchObject({
      code: 'nonexistent_package',
      verdict: { name: 'huggingface-cli', decision: 'block', policy_hits: [{ rule: 'block_nonexistent' }] },
    });
  });

  it('records the client a check names, and "api" when it names none', () => {
    const server = new MockServer(NOW);
    const check = (body: Record<string, unknown>) => server.handle('POST', new URL('http://localhost/api/check'), body);
    check({ ecosystem: 'pypi', name: 'requests', client: 'dashboard' });
    expect(server.events.at(-1)?.client).toBe('dashboard');
    check({ ecosystem: 'pypi', name: 'requests' });
    expect(server.events.at(-1)?.client).toBe('api');
  });

  it('reports 30 days of blocks, like GET /api/stats', () => {
    const stats = new MockServer(NOW).stats(NOW);
    expect(stats.blocks_per_day).toHaveLength(30);
  });

  it('serves only /api routes', () => {
    const server = new MockServer(NOW);
    expect(get(server, '/metrics').status).toBe(404);
    expect(get(server, '/healthz').status).toBe(404);
  });
});
