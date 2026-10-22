# @enablo/flip-auth

Sign people in with [Flip](https://www.getflip.com) from a Node or edge app, using OpenID Connect
(authorisation code + PKCE) against your Flip tenant's Keycloak realm. Built on
[`openid-client`](https://github.com/panva/openid-client), with optional ready-made
[Hono](https://hono.dev) routes.

> **Unofficial.** Made by [Enablo](https://enablo.com), a Flip partner, for the apps we build.
> It isn't made or supported by Flip.

```sh
pnpm add @enablo/flip-auth
```

Requires Node 20 or later (or any runtime with `fetch` and Web Crypto). `hono` is an optional peer
dependency, needed only for `@enablo/flip-auth/hono`.

## What it handles

- **The sign-in flow.** PKCE, state and nonce, ID token validation, and a UserInfo fallback when
  the ID token has no email.
- **Flip's quirks:**
  - Flip's discovery advertises RFC 9207 `iss` in authorisation responses, but its callbacks
    leave it out. `openid-client` would reject every sign-in; this library supplies it.
  - Flip answers discovery for any realm name but always reports its own tenant's issuer, so a
    wrong realm fails with a clear `discovery_failed`.
- **Safe defaults:**
  - `email_verified` must be `true` unless you opt out.
  - `returnTo` only ever points at a path on your own site.
  - The login state expires after 10 minutes.
- **One cookie per response.** Some platforms, including Neon Functions, deliver only the last
  `Set-Cookie` header. The Hono routes never set two.

It deliberately leaves out sessions, user tables and who's allowed in: those differ per app.

## Setup

Ask Flip for a **public** OIDC client (authorisation code + PKCE, no client secret), with your
callback URL as its redirect URI. You need:

- **`issuer`:** your realm, exactly as its discovery document reports it.
  `https://<your-flip-host>/auth/realms/<realm>/.well-known/openid-configuration` shows it.
- **`clientId`:** the client's id, e.g. `external-oidc-my-app`.

## With Hono

```ts
import { createFlipAuth } from '@enablo/flip-auth';
import { flipAuthRoutes } from '@enablo/flip-auth/hono';

const flip = createFlipAuth({ issuer: env.FLIP_ISSUER, clientId: env.FLIP_CLIENT_ID });

app.route(
  '/api/auth',
  flipAuthRoutes({
    flip,
    redirectUri: `${env.APP_URL}/api/auth/flip/callback`,
    onSignIn: async (c, identity, returnTo) => {
      const user = await findOrCreateUser(identity); // see "Matching people" below
      if (!user) return c.redirect('/sign-in?error=not_allowed');
      await startSession(c, user); // set your session cookie here: one cookie only
      return c.redirect(returnTo);
    },
    // Optional. The default redirects to /sign-in?error=<code>.
    onError: (c, error) => c.redirect(`/sign-in?error=${error.code}`),
  }),
);
```

Send people to `GET /api/auth/flip?returnTo=/somewhere`. Flip returns them to
`GET /api/auth/flip/callback`. If a proxy serves your app under a different host, the routes rebuild
the callback URL from `redirectUri`.

## Without Hono

```ts
import { createFlipAuth, decodeLoginState, encodeLoginState, FlipAuthError } from '@enablo/flip-auth';

const flip = createFlipAuth({ issuer, clientId });

// 1. Start: keep loginState (e.g. in a 10-minute httpOnly cookie), redirect to url.
const { url, loginState } = await flip.start({ redirectUri, returnTo: '/inbox' });
setCookie('__Host-flip-login', encodeLoginState(loginState));

// 2. Callback: validate, then decide who this is.
try {
  const state = decodeLoginState(getCookie('__Host-flip-login'));
  if (!state) throw new Error('expired');
  const identity = await flip.finish(requestUrl, state);
  // identity: { sub, email, emailVerified, name, username, tenant, externalId, roles, claims }
} catch (error) {
  if (error instanceof FlipAuthError) {
    // error.code: login_expired | access_denied | callback_failed | email_missing
    //             | email_not_verified | discovery_failed
  }
}
```

## Matching people to your users

Flip's `sub` is the stable identifier; an email address can change or be reused.

1. Look up the user by `sub` first.
2. Only if there's no match, look up by email, and only when `emailVerified` is true (the default
   requires it).
3. **Never re-link** a user that's already linked to one `sub` to a different `sub`, even with the
   same email. Refuse the sign-in instead. Otherwise a Flip account whose email was set to someone
   else's address could take over that person's account.

## API

| Export | What it is |
| --- | --- |
| `createFlipAuth(options)` | The client. Create one per app and reuse it (discovery is cached). |
| `flip.start({ redirectUri, returnTo? })` | Returns `{ url, loginState }`. |
| `flip.finish(callbackUrl, loginState)` | Returns a `FlipIdentity` or throws `FlipAuthError`. |
| `FlipAuthError` | Has a `code`, plus `oauthError` for `access_denied`. |
| `encodeLoginState` / `decodeLoginState` | Cookie-safe login state with an expiry check (default 10 minutes). |
| `safeReturnTo(value, fallback?)` | A same-site path, or the fallback. |
| `toFlipIdentity(claims)` | Normalises raw claims, e.g. from your own token handling. |
| `flipAuthRoutes(options)` (`/hono`) | Start and callback routes for Hono. |

Options for `createFlipAuth`:

- `issuer` and `clientId`: required.
- `scope`: default `openid profile email`.
- `requireVerifiedEmail`: default `true`.
- `fetch`: a custom fetch, for tests and proxies.

## Development

```sh
pnpm install
pnpm check && pnpm typecheck && pnpm test && pnpm build
```

The tests run complete sign-ins against a fake Flip (`test/fake-flip.ts`). It signs real RS256 ID
tokens, checks PKCE, and leaves `iss` out of callbacks the way Flip does.

Releases: bump the version and `CHANGELOG.md`, then publish a GitHub release. The `release`
workflow publishes to npm with provenance, using npm trusted publishing (no npm token stored).

## Security

See [SECURITY.md](SECURITY.md). Please report vulnerabilities privately, not in issues.

## Licence

MIT © Enablo
