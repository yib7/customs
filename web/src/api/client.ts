import {
  ParseError,
  isRecord,
  parseEventList,
  parseModelInfo,
  parsePolicy,
  parsePolicyChanges,
  parseReleaseDiff,
  parseStats,
  parseVerdict,
} from './parse';
import type {
  CheckRequest,
  CustomsEvent,
  EventQuery,
  ModelInfo,
  Policy,
  PolicyChange,
  ReleaseDiff,
  Stats,
  Verdict,
} from './types';

export class ApiError extends Error {
  readonly status: number;
  /** Machine-readable error code from the server body, if any. */
  readonly code: string | null;
  /** Field-level validation messages keyed by field name. */
  readonly fieldErrors: Record<string, string>;

  constructor(status: number, message: string, code: string | null = null, fieldErrors: Record<string, string> = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.fieldErrors = fieldErrors;
  }
}

const MAX_ERROR_LEN = 500;
const UNREACHABLE = 'Could not reach the Customs server. Is `customs serve` running?';

/**
 * Builds an ApiError from an error response body. Accepts the shapes
 * `{ error: "msg" }`, `{ message: "msg" }`, `{ errors: [{ field, message }] }`,
 * `{ errors: { field: "msg" } }`, and plain text.
 */
export function errorFromBody(status: number, body: unknown, statusText = ''): ApiError {
  let message = '';
  let code: string | null = null;
  const fieldErrors: Record<string, string> = {};
  if (typeof body === 'string') {
    message = body.trim();
  } else if (isRecord(body)) {
    const err = body.error;
    if (typeof err === 'string') message = err;
    else if (isRecord(err) && typeof err.message === 'string') message = err.message;
    if (!message && typeof body.message === 'string') message = body.message;
    if (typeof body.code === 'string') code = body.code;
    else if (typeof body.kind === 'string') code = body.kind;
    const errors = body.errors;
    if (Array.isArray(errors)) {
      for (const e of errors) {
        if (isRecord(e) && typeof e.message === 'string') {
          const field = typeof e.field === 'string' ? e.field : '_';
          fieldErrors[field] = e.message.slice(0, MAX_ERROR_LEN);
        } else if (typeof e === 'string' && !message) {
          message = e;
        }
      }
    } else if (isRecord(errors)) {
      for (const [field, msg] of Object.entries(errors)) {
        if (typeof msg === 'string') fieldErrors[field] = msg.slice(0, MAX_ERROR_LEN);
      }
    }
  }
  if (!message) {
    const firstField = Object.values(fieldErrors)[0];
    message = firstField ?? `Request failed (${status}${statusText ? ` ${statusText}` : ''})`;
  }
  return new ApiError(status, message.slice(0, MAX_ERROR_LEN), code, fieldErrors);
}

async function readBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  const type = res.headers.get('content-type') ?? '';
  if (type.includes('json') || /^\s*[[{]/.test(text)) {
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return text;
    }
  }
  return text;
}

async function request<T>(path: string, parse: (v: unknown, res: Response) => T, init: RequestInit = {}): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      ...init,
      headers: { Accept: 'application/json', ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...init.headers },
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError(0, UNREACHABLE);
  }
  const body = await readBody(res);
  if (!res.ok) {
    // A dev proxy or load balancer answers 502 to 504 with no body when the server is down.
    if (res.status >= 502 && res.status <= 504 && (body === null || body === '')) throw new ApiError(res.status, UNREACHABLE);
    throw errorFromBody(res.status, body, res.statusText);
  }
  // Every endpoint answers JSON. Anything else (an HTML page from a proxy, plain text) would
  // otherwise parse into a set of defaults that look like real data.
  if (typeof body !== 'object' || body === null) throw new ParseError(`expected JSON from ${path}`);
  return parse(body, res);
}

/**
 * Who may change the policy, from `GET /api/policy`'s `X-Customs-Policy-Changes`: anyone
 * (`open`), the admin token holder (`token`), or nobody over the API (`disabled`). `null`
 * when the server does not say; the page then learns it from a refused save.
 */
export type PolicyChanges = 'open' | 'token' | 'disabled';

function policyChanges(res: Response): PolicyChanges | null {
  const v = res.headers.get('X-Customs-Policy-Changes')?.trim().toLowerCase();
  return v === 'open' || v === 'token' || v === 'disabled' ? v : null;
}

function eventsPath(q: EventQuery = {}): string {
  const params = new URLSearchParams();
  if (q.limit !== undefined) params.set('limit', String(q.limit));
  if (q.before) params.set('before', q.before);
  if (q.decision) params.set('decision', q.decision);
  if (q.ecosystem) params.set('ecosystem', q.ecosystem);
  if (q.kind) params.set('kind', q.kind);
  if (q.q) params.set('q', q.q);
  const s = params.toString();
  return s ? `/api/events?${s}` : '/api/events';
}

export const api = {
  events(q: EventQuery = {}, signal?: AbortSignal): Promise<CustomsEvent[]> {
    return request(eventsPath(q), parseEventList, { signal });
  },
  verdict(id: string, signal?: AbortSignal): Promise<Verdict> {
    return request(`/api/verdicts/${encodeURIComponent(id)}`, parseVerdict, { signal });
  },
  stats(signal?: AbortSignal): Promise<Stats> {
    return request('/api/stats', parseStats, { signal });
  },
  policy(signal?: AbortSignal): Promise<Policy> {
    return request('/api/policy', parsePolicy, { signal });
  },
  /**
   * Saves the policy. `base` is the raw object last received from the server so that
   * fields this client does not know about are sent back unchanged.
   */
  savePolicy(policy: Policy, base: Record<string, unknown> = {}, adminToken?: string): Promise<Policy> {
    return request('/api/policy', parsePolicy, {
      method: 'PUT',
      body: JSON.stringify({ ...base, ...policy }),
      ...(adminToken ? { headers: { Authorization: `Bearer ${adminToken}` } } : {}),
    });
  },
  /**
   * Fetches the policy along with the raw body (used as the merge base when saving) and who
   * may change it.
   */
  async policyWithRaw(
    signal?: AbortSignal,
  ): Promise<{ policy: Policy; raw: Record<string, unknown>; changes: PolicyChanges | null }> {
    return request(
      '/api/policy',
      (v, res) => ({ policy: parsePolicy(v), raw: isRecord(v) ? v : {}, changes: policyChanges(res) }),
      { signal },
    );
  },
  /** Policy changes made through the API, newest first. */
  policyChanges(limit = 20, signal?: AbortSignal): Promise<PolicyChange[]> {
    return request(`/api/policy/changes?limit=${limit}`, parsePolicyChanges, { signal });
  },
  /** What release `to` (default: newest) changes since `from` (default: the one before). */
  diff(q: { ecosystem: string; name: string; from?: string; to?: string }, signal?: AbortSignal): Promise<ReleaseDiff> {
    const params = new URLSearchParams({ ecosystem: q.ecosystem, name: q.name, client: 'dashboard' });
    if (q.from) params.set('from', q.from);
    if (q.to) params.set('to', q.to);
    return request(`/api/diff?${params.toString()}`, parseReleaseDiff, { signal });
  },
  model(signal?: AbortSignal): Promise<ModelInfo> {
    return request('/api/model', parseModelInfo, { signal });
  },
  check(req: CheckRequest, signal?: AbortSignal): Promise<Verdict> {
    return request('/api/check', parseVerdict, {
      method: 'POST',
      // Recorded on the event; without it the server records "api".
      body: JSON.stringify({ ...req, client: 'dashboard' }),
      signal,
    });
  },
};
