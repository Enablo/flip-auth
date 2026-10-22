import { createHash, randomBytes } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

export const ISSUER = 'https://flip.test/auth/realms/acme';
export const CLIENT_ID = 'external-oidc-test';

type Pending = {
  challenge: string;
  nonce: string;
  redirectUri: string;
  claims: Record<string, unknown>;
};

/**
 * A Keycloak-shaped stand-in for Flip, reached through a fetch function. Like real Flip, its
 * discovery advertises RFC 9207 `iss`, but `authorize()` returns callbacks without it.
 */
export async function createFakeFlip(options: { issuer?: string; reportedIssuer?: string } = {}) {
  const issuer = options.issuer ?? ISSUER;
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'test-key', use: 'sig', alg: 'RS256' };
  const codes = new Map<string, Pending>();
  let userInfoClaims: Record<string, unknown> = {};
  const requests: string[] = [];

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

  const fetch = async (url: string, init: { body?: unknown; headers: Record<string, string> }) => {
    const u = new URL(url);
    requests.push(u.pathname);
    if (u.pathname.endsWith('/.well-known/openid-configuration')) {
      return json({
        // Flip answers for any realm but reports its own tenant's issuer.
        issuer: options.reportedIssuer ?? issuer,
        authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
        token_endpoint: `${issuer}/protocol/openid-connect/token`,
        userinfo_endpoint: `${issuer}/protocol/openid-connect/userinfo`,
        jwks_uri: `${issuer}/protocol/openid-connect/certs`,
        response_types_supported: ['code'],
        code_challenge_methods_supported: ['S256'],
        id_token_signing_alg_values_supported: ['RS256'],
        authorization_response_iss_parameter_supported: true,
      });
    }
    if (u.pathname.endsWith('/certs')) {
      return json({ keys: [jwk] });
    }
    if (u.pathname.endsWith('/token')) {
      const form = new URLSearchParams(String(init.body));
      const pending = codes.get(form.get('code') ?? '');
      codes.delete(form.get('code') ?? '');
      const verifier = form.get('code_verifier') ?? '';
      const challenge = createHash('sha256').update(verifier).digest('base64url');
      if (
        !pending ||
        pending.challenge !== challenge ||
        pending.redirectUri !== form.get('redirect_uri') ||
        form.get('client_id') !== CLIENT_ID
      ) {
        return json({ error: 'invalid_grant' }, 400);
      }
      const now = Math.floor(Date.now() / 1000);
      const idToken = await new SignJWT({ ...pending.claims, nonce: pending.nonce })
        .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
        .setIssuer(options.reportedIssuer ?? issuer)
        .setAudience(CLIENT_ID)
        .setSubject(String(pending.claims.sub))
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .sign(privateKey);
      return json({
        access_token: 'access-token',
        token_type: 'Bearer',
        expires_in: 300,
        id_token: idToken,
      });
    }
    if (u.pathname.endsWith('/userinfo')) {
      return json(userInfoClaims);
    }
    return json({ error: 'not_found' }, 404);
  };

  return {
    fetch,
    requests,
    setUserInfo(claims: Record<string, unknown>) {
      userInfoClaims = claims;
    },
    /** What Flip does when the person signs in: a callback URL with a code and state (no `iss`). */
    authorize(authorizationUrl: string, claims: Record<string, unknown>) {
      const a = new URL(authorizationUrl);
      const code = randomBytes(16).toString('hex');
      codes.set(code, {
        challenge: a.searchParams.get('code_challenge') ?? '',
        nonce: a.searchParams.get('nonce') ?? '',
        redirectUri: a.searchParams.get('redirect_uri') ?? '',
        claims,
      });
      const callback = new URL(a.searchParams.get('redirect_uri') ?? '');
      callback.searchParams.set('code', code);
      callback.searchParams.set('state', a.searchParams.get('state') ?? '');
      return callback.href;
    },
  };
}
