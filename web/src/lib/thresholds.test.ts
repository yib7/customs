import { renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseVerdict } from '../api/parse';
import { useThresholds } from './thresholds';

afterEach(() => {
  vi.unstubAllGlobals();
});

function stubFetch() {
  const fetchSpy = vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input);
    const body = path === '/api/model' ? { model_version: 'x', thresholds: { warn: 0.4, block: 0.9 } } : {};
    return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
  });
  vi.stubGlobal('fetch', fetchSpy);
  return fetchSpy;
}

describe('useThresholds', () => {
  it('uses the thresholds a verdict carries without fetching anything', async () => {
    const fetchSpy = stubFetch();
    const verdict = parseVerdict({ name: 'x', decision: 'allow', thresholds: { warn: 0.3, block: 0.7 } });
    const { result } = renderHook(() => useThresholds(verdict));
    expect(result.current).toEqual({ warn: 0.3, block: 0.7 });
    await new Promise((r) => setTimeout(r, 20));
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('asks only /api/model, whose thresholds already include the policy overrides', async () => {
    const fetchSpy = stubFetch();
    const verdict = parseVerdict({ name: 'x', decision: 'allow' });
    const { result } = renderHook(() => useThresholds(verdict));
    await waitFor(() => expect(result.current).toEqual({ warn: 0.4, block: 0.9 }));
    expect(fetchSpy.mock.calls.map((c) => String(c[0]))).toEqual(['/api/model']);
  });

  it('fetches nothing before there is a verdict', async () => {
    const fetchSpy = stubFetch();
    const { result } = renderHook(() => useThresholds(null));
    await new Promise((r) => setTimeout(r, 20));
    expect(result.current).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
