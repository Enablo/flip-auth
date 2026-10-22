import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { flipAuthRoutes } from '../src/hono.js';
import { createFlipAuth } from '../src/index.js';
import { CLIENT_ID, createFakeFlip, ISSUER } from './fake-flip.js';

const REDIRECT = 'https://app.test/api/auth/flip/callback';

async function setup() {
  const fake = await createFakeFlip();
  const flip = createFlipAuth({ issuer: ISSUER, clientId: CLIENT_ID, fetch: fake.fetch });
  const signedIn: { sub: string; returnTo: string }[] = [];
  const app = new Hono();
  app.route(
    '/api/auth',
    flipAuthRoutes({
      flip,
      redirectUri: REDIRECT,
      onSignIn: (c, identity, returnTo) => {
        signedIn.push({ sub: identity.sub, returnTo });
        c.header('set-cookie', '__Host-session=abc; Path=/; Secure; HttpOnly');
        return c.redirect(returnTo);
      },
    }),
  );
  return { fake, app, signedIn };
}

describe('flipAuthRoutes', () => {
  it('runs the whole sign-in and sets only the app session on the callback', async () => {
    const { fake, app, signedIn } = await setup();
    const start = await app.request('/api/auth/flip?returnTo=/s/abc');
    expect(start.status).toBe(302);
    const loginCookie = start.headers.get('set-cookie') ?? '';
    expect(loginCookie).toMatch(
      /^__Host-flip-login=.+; Max-Age=600; Path=\/; HttpOnly; Secure; SameSite=Lax$/,
    );

    const callback = new URL(
      fake.authorize(start.headers.get('location') ?? '', {
        sub: 'f:acme:1',
        email: 'pat@acme.example',
        email_verified: true,
      }),
    );
    // The browser comes back through a proxy, under another host: the routes rebuild the URL.
    const res = await app.request(`http://internal-host/api/auth/flip/callback${callback.search}`, {
      headers: { cookie: loginCookie.split(';')[0] ?? '' },
    });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/s/abc');
    expect(res.headers.getSetCookie()).toEqual(['__Host-session=abc; Path=/; Secure; HttpOnly']);
    expect(signedIn).toEqual([{ sub: 'f:acme:1', returnTo: '/s/abc' }]);
  });

  it('sends people back to sign-in when the login cookie is missing', async () => {
    const { app } = await setup();
    const res = await app.request('/api/auth/flip/callback?code=x&state=y');
    expect(res.headers.get('location')).toBe('/sign-in?error=login_expired');
  });

  it('reports a forged state as callback_failed without signing in', async () => {
    const { fake, app, signedIn } = await setup();
    const start = await app.request('/api/auth/flip');
    const callback = new URL(
      fake.authorize(start.headers.get('location') ?? '', {
        sub: 'x',
        email: 'a@b.c',
        email_verified: true,
      }),
    );
    callback.searchParams.set('state', 'forged');
    const res = await app.request(`/api/auth/flip/callback${callback.search}`, {
      headers: { cookie: (start.headers.get('set-cookie') ?? '').split(';')[0] ?? '' },
    });
    expect(res.headers.get('location')).toBe('/sign-in?error=callback_failed');
    expect(signedIn).toHaveLength(0);
  });

  it('handles Flip not being configured', async () => {
    const app = new Hono();
    app.route(
      '/auth',
      flipAuthRoutes({
        flip: () => undefined,
        redirectUri: REDIRECT,
        onSignIn: (c) => c.text('no'),
      }),
    );
    const res = await app.request('/auth/flip');
    expect(res.headers.get('location')).toBe('/sign-in?error=discovery_failed');
  });
});
