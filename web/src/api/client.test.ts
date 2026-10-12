import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './client';
import { ParseError } from './parse';

afterEach(() => {
  vi.unstubAllGlobals();
});

function serve(body: string, contentType: string) {
  vi.stubGlobal('fetch', async () => new Response(body, { status: 200, headers: { 'Content-Type': contentType } }));
}

describe('request', () => {
  it('rejects a successful response that is not a JSON object or array', async () => {
    // For example an HTML page from a proxy in front of the server.
    serve('<!doctype html><title>Sign in</title>', 'text/html');
    await expect(api.events()).rejects.toThrow(ParseError);
    await expect(api.policy()).rejects.toThrow(ParseError);
    serve('null', 'application/json');
    await expect(api.policy()).rejects.toThrow(ParseError);
  });

  it('accepts JSON arrays and objects', async () => {
    serve('[]', 'application/json');
    await expect(api.events()).resolves.toEqual([]);
  });
});
