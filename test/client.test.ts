import { describe, expect, it } from 'vitest';
import { createFlipAuth, FlipAuthError } from '../src/index.js';
import { CLIENT_ID, createFakeFlip, ISSUER } from './fake-flip.js';

const REDIRECT = 'https://app.test/api/auth/flip/callback';
const PERSON = {
  sub: 'f:acme:123',
  email: 'pat@acme.example',
  email_verified: true,
  name: 'Pat Lee',
  preferred_username: 'pat',
  tenant: 'acme',
  roles: ['user', 7],
};

async function setup(options: { requireVerifiedEmail?: boolean; reportedIssuer?: string } = {}) {
  const fake = await createFakeFlip({ reportedIssuer: options.reportedIssuer });
  const flip = createFlipAuth({
    issuer: `${ISSUER}/`,
    clientId: CLIENT_ID,
    fetch: fake.fetch,
    requireVerifiedEmail: options.requireVerifiedEmail,
  });
  return { fake, flip };
}

async function failure(promise: Promise<unknown>): Promise<FlipAuthError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(FlipAuthError);
    return error as FlipAuthError;
  }
  throw new Error('Expected a FlipAuthError');
}

describe('createFlipAuth', () => {
  it('signs someone in end to end, despite Flip leaving `iss` out of the callback', async () => {
    const { fake, flip } = await setup();
    const { url, loginState } = await flip.start({ redirectUri: REDIRECT, returnTo: '/s/abc' });
    const auth = new URL(url);
    expect(auth.origin + auth.pathname).toBe(`${ISSUER}/protocol/openid-connect/auth`);
    expect(auth.searchParams.get('code_challenge_method')).toBe('S256');
    expect(auth.searchParams.get('scope')).toBe('openid profile email');
    expect(loginState.returnTo).toBe('/s/abc');

    const callback = fake.authorize(url, PERSON);
    expect(new URL(callback).searchParams.has('iss')).toBe(false);
    const identity = await flip.finish(callback, loginState);
    expect(identity).toMatchObject({
      sub: 'f:acme:123',
      email: 'pat@acme.example',
      emailVerified: true,
      name: 'Pat Lee',
      username: 'pat',
      tenant: 'acme',
      roles: ['user'],
    });
  });

  it('fetches discovery once and reuses it', async () => {
    const { fake, flip } = await setup();
    await flip.start({ redirectUri: REDIRECT });
    await flip.start({ redirectUri: REDIRECT });
    expect(fake.requests.filter((p) => p.endsWith('openid-configuration'))).toHaveLength(1);
  });

  it('refuses an unverified or unconfirmed email by default', async () => {
    const { fake, flip } = await setup();
    for (const email_verified of [false, undefined]) {
      const { url, loginState } = await flip.start({ redirectUri: REDIRECT });
      const error = await failure(
        flip.finish(fake.authorize(url, { ...PERSON, email_verified }), loginState),
      );
      expect(error.code).toBe('email_not_verified');
    }
  });

  it('can allow unverified emails when the app does not match on email', async () => {
    const { fake, flip } = await setup({ requireVerifiedEmail: false });
    const { url, loginState } = await flip.start({ redirectUri: REDIRECT });
    const identity = await flip.finish(
      fake.authorize(url, { ...PERSON, email_verified: false }),
      loginState,
    );
    expect(identity.emailVerified).toBe(false);
  });

  it('falls back to UserInfo when the ID token has no email', async () => {
    const { fake, flip } = await setup();
    fake.setUserInfo({ sub: PERSON.sub, email: 'pat@acme.example', email_verified: true });
    const { url, loginState } = await flip.start({ redirectUri: REDIRECT });
    const { email: _e, email_verified: _v, ...noEmail } = PERSON;
    const identity = await flip.finish(fake.authorize(url, noEmail), loginState);
    expect(identity.email).toBe('pat@acme.example');
    expect(fake.requests.some((p) => p.endsWith('/userinfo'))).toBe(true);
  });

  it('reports a missing email', async () => {
    const { fake, flip } = await setup();
    fake.setUserInfo({ sub: PERSON.sub });
    const { url, loginState } = await flip.start({ redirectUri: REDIRECT });
    const { email: _e, ...noEmail } = PERSON;
    expect((await failure(flip.finish(fake.authorize(url, noEmail), loginState))).code).toBe(
      'email_missing',
    );
  });

  it('rejects a callback whose state does not match', async () => {
    const { fake, flip } = await setup();
    const { url, loginState } = await flip.start({ redirectUri: REDIRECT });
    const error = await failure(
      flip.finish(fake.authorize(url, PERSON), { ...loginState, state: 'forged' }),
    );
    expect(error.code).toBe('callback_failed');
  });

  it('rejects a callback with the wrong PKCE verifier', async () => {
    const { fake, flip } = await setup();
    const { url, loginState } = await flip.start({ redirectUri: REDIRECT });
    const error = await failure(
      flip.finish(fake.authorize(url, PERSON), { ...loginState, codeVerifier: 'x'.repeat(43) }),
    );
    expect(error.code).toBe('callback_failed');
  });

  it('rejects an ID token whose nonce does not match', async () => {
    const { fake, flip } = await setup();
    const { url, loginState } = await flip.start({ redirectUri: REDIRECT });
    const error = await failure(
      flip.finish(fake.authorize(url, PERSON), { ...loginState, nonce: 'other' }),
    );
    expect(error.code).toBe('callback_failed');
  });

  it('reports a person cancelling at Flip as access_denied', async () => {
    const { flip } = await setup();
    const { loginState } = await flip.start({ redirectUri: REDIRECT });
    const callback = `${REDIRECT}?error=access_denied&state=${loginState.state}`;
    const error = await failure(flip.finish(callback, loginState));
    expect(error.code).toBe('access_denied');
    expect(error.oauthError).toBe('access_denied');
  });

  it('fails clearly when the configured issuer is not the realm Flip reports', async () => {
    const { flip } = await setup({ reportedIssuer: 'https://flip.test/auth/realms/other' });
    expect((await failure(flip.start({ redirectUri: REDIRECT }))).code).toBe('discovery_failed');
  });

  it('only ever returns to paths on the same site', async () => {
    const { flip } = await setup();
    for (const returnTo of ['https://evil.example', '//evil.example', '/\\evil.example']) {
      expect((await flip.start({ redirectUri: REDIRECT, returnTo })).loginState.returnTo).toBe('/');
    }
  });
});
