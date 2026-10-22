/**
 * What an app keeps between sending someone to Flip and Flip sending them back: the values the
 * callback must match, and where to return afterwards. Store it in a short-lived, httpOnly cookie
 * (see `encodeLoginState`) or a database row. It isn't signed: it holds only values the callback
 * compares against Flip's response, and a `__Host-` cookie can't be set by another site.
 */
export type FlipLoginState = {
  state: string;
  codeVerifier: string;
  nonce: string;
  /** A same-site path, already checked by `safeReturnTo`. */
  returnTo: string;
  /** Milliseconds since the epoch. */
  createdAt: number;
};

export const DEFAULT_LOGIN_MAX_AGE_SECONDS = 10 * 60;

/**
 * A path on this site to return to after sign-in, or `fallback`. Rejects anything that could
 * leave the site: absolute URLs, protocol-relative `//host`, backslashes (`/\host`, which some
 * browsers treat as `//host`) and control characters.
 */
export function safeReturnTo(value: string | null | undefined, fallback = '/'): string {
  if (!value?.startsWith('/') || value.startsWith('//')) {
    return fallback;
  }
  return /^\/[\w\-./?=&%~+:@]*$/.test(value) ? value : fallback;
}

export function encodeLoginState(state: FlipLoginState): string {
  return Buffer.from(JSON.stringify(state)).toString('base64url');
}

/** Reads a login state, or returns null if it's malformed or older than `maxAgeSeconds`. */
export function decodeLoginState(
  value: string | null | undefined,
  options: { maxAgeSeconds?: number; now?: number } = {},
): FlipLoginState | null {
  if (!value) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(value, 'base64url').toString());
  } catch {
    return null;
  }
  const s = parsed as Partial<FlipLoginState>;
  if (
    typeof s?.state !== 'string' ||
    typeof s.codeVerifier !== 'string' ||
    typeof s.nonce !== 'string' ||
    typeof s.returnTo !== 'string' ||
    typeof s.createdAt !== 'number'
  ) {
    return null;
  }
  const maxAge = (options.maxAgeSeconds ?? DEFAULT_LOGIN_MAX_AGE_SECONDS) * 1000;
  const now = options.now ?? Date.now();
  if (now - s.createdAt > maxAge || s.createdAt > now + 60_000) {
    return null;
  }
  return { ...(s as FlipLoginState), returnTo: safeReturnTo(s.returnTo) };
}
