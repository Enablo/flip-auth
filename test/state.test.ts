import { describe, expect, it } from 'vitest';
import { decodeLoginState, encodeLoginState, safeReturnTo } from '../src/index.js';

describe('safeReturnTo', () => {
  it.each([
    ['/inbox', '/inbox'],
    ['/s/abc?x=1&y=2', '/s/abc?x=1&y=2'],
    ['//evil.example', '/'],
    ['https://evil.example', '/'],
    ['/\\evil.example', '/'],
    ['/path\r\nSet-Cookie:x', '/'],
    ['javascript:alert(1)', '/'],
    ['', '/'],
    [null, '/'],
    [undefined, '/'],
  ])('%j → %s', (input, expected) => {
    expect(safeReturnTo(input)).toBe(expected);
  });
});

describe('login state', () => {
  const state = { state: 's', codeVerifier: 'v', nonce: 'n', returnTo: '/x', createdAt: 1_000_000 };

  it('round-trips', () => {
    expect(decodeLoginState(encodeLoginState(state), { now: 1_000_000 + 1000 })).toEqual(state);
  });

  it('expires after its maximum age', () => {
    const encoded = encodeLoginState(state);
    expect(decodeLoginState(encoded, { now: 1_000_000 + 599_000 })).not.toBeNull();
    expect(decodeLoginState(encoded, { now: 1_000_000 + 601_000 })).toBeNull();
    expect(decodeLoginState(encoded, { now: 1_000_000 + 30_000, maxAgeSeconds: 10 })).toBeNull();
  });

  it('rejects malformed values and re-checks returnTo', () => {
    expect(decodeLoginState('not-base64-json')).toBeNull();
    expect(decodeLoginState(Buffer.from('{"state":1}').toString('base64url'))).toBeNull();
    const tampered = encodeLoginState({ ...state, returnTo: '//evil.example' });
    expect(decodeLoginState(tampered, { now: 1_000_000 })?.returnTo).toBe('/');
  });
});
