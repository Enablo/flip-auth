# Changelog

## 0.1.1

No code changes from 0.1.0. Documentation fixes.

## 0.1.0

First release.

- `createFlipAuth`: Flip sign-in with OIDC authorisation code + PKCE on `openid-client`, with
  cached discovery and the `iss` workaround for Flip's callbacks.
- `FlipIdentity`, normalised from the ID token (with UserInfo fallback), including `tenant`,
  `externalId` and `roles`.
- Verified email required by default (`requireVerifiedEmail`).
- `FlipAuthError` with typed codes.
- Login state helpers with expiry, and `safeReturnTo`.
- `@enablo/flip-auth/hono`: start and callback routes that set at most one cookie per response.
