import * as oidc from 'openid-client';
import { FlipAuthError } from './errors.js';
import { type FlipLoginState, safeReturnTo } from './state.js';

export type FlipAuthOptions = {
  /**
   * The realm's issuer, exactly as its discovery document reports it, e.g.
   * `https://flip.example.com/auth/realms/<organisation>`. Flip answers discovery for any realm
   * name but always reports its own tenant's issuer, and a mismatch is rejected.
   */
  issuer: string;
  /** A public OIDC client (authorisation code + PKCE, no secret) from Flip. */
  clientId: string;
  /** Default `openid profile email`. */
  scope?: string;
  /**
   * Default true: `finish` throws `email_not_verified` unless Flip sends `email_verified: true`.
   * Leave this on if you match people by email.
   */
  requireVerifiedEmail?: boolean;
  /** For tests and proxies: used for discovery, token and UserInfo requests. */
  fetch?: oidc.CustomFetch;
};

/** Who signed in, normalised from the ID token (and UserInfo when the ID token lacks email). */
export type FlipIdentity = {
  /** Flip's stable user id. Match people on this, not on email. */
  sub: string;
  email: string | null;
  /** Flip's `email_verified` claim; null when Flip doesn't send it. */
  emailVerified: boolean | null;
  name: string | null;
  username: string | null;
  /** Flip's `tenant` claim, when present. */
  tenant: string | null;
  /** Flip's `external_id` claim, when present. */
  externalId: string | null;
  roles: string[];
  /** Every claim, for anything not normalised above. */
  claims: Record<string, unknown>;
};

export interface FlipAuth {
  /** Where to send the browser, and the state to keep until it comes back. */
  start(options: { redirectUri: string; returnTo?: string | null }): Promise<{
    url: string;
    loginState: FlipLoginState;
  }>;
  /**
   * Validates Flip's redirect back to `callbackUrl` against the kept state and returns who signed
   * in. Throws `FlipAuthError` on any failure.
   */
  finish(callbackUrl: URL | string, loginState: FlipLoginState): Promise<FlipIdentity>;
}

const DEFAULT_SCOPE = 'openid profile email';
const str = (v: unknown) => (typeof v === 'string' && v ? v : null);
const bool = (v: unknown) => (typeof v === 'boolean' ? v : null);

export function toFlipIdentity(claims: Record<string, unknown>): FlipIdentity {
  return {
    sub: String(claims.sub),
    email: str(claims.email),
    emailVerified: bool(claims.email_verified),
    name: str(claims.name),
    username: str(claims.preferred_username),
    tenant: str(claims.tenant),
    externalId: str(claims.external_id),
    roles: Array.isArray(claims.roles)
      ? claims.roles.filter((r): r is string => typeof r === 'string')
      : [],
    claims,
  };
}

class FlipOidcClient implements FlipAuth {
  private configuration: Promise<oidc.Configuration> | undefined;

  constructor(private readonly options: FlipAuthOptions) {}

  /** Fetched once and reused; a failure is retried on the next call. */
  private discover(): Promise<oidc.Configuration> {
    this.configuration ??= (async () => {
      const { issuer, clientId, fetch } = this.options;
      try {
        const config = await oidc.discovery(
          new URL(issuer),
          clientId,
          undefined,
          oidc.None(),
          fetch ? { [oidc.customFetch]: fetch } : undefined,
        );
        if (fetch) {
          config[oidc.customFetch] = fetch;
        }
        return config;
      } catch (error) {
        throw new FlipAuthError('discovery_failed', `Flip discovery failed for ${issuer}`, {
          cause: error,
        });
      }
    })().catch((error: unknown) => {
      this.configuration = undefined;
      throw error;
    });
    return this.configuration;
  }

  async start({ redirectUri, returnTo }: { redirectUri: string; returnTo?: string | null }) {
    const config = await this.discover();
    const codeVerifier = oidc.randomPKCECodeVerifier();
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();
    const url = oidc.buildAuthorizationUrl(config, {
      redirect_uri: redirectUri,
      scope: this.options.scope ?? DEFAULT_SCOPE,
      code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier),
      code_challenge_method: 'S256',
      state,
      nonce,
    });
    return {
      url: url.href,
      loginState: {
        state,
        codeVerifier,
        nonce,
        returnTo: safeReturnTo(returnTo),
        createdAt: Date.now(),
      },
    };
  }

  async finish(callbackUrl: URL | string, loginState: FlipLoginState): Promise<FlipIdentity> {
    const config = await this.discover();
    const url = new URL(callbackUrl);
    // Flip's discovery advertises RFC 9207 `iss` in authorisation responses, but its callbacks
    // leave it out, so openid-client would reject every sign-in. `iss` guards against mix-ups
    // between identity providers; a client of this library trusts exactly one.
    if (!url.searchParams.has('iss')) {
      url.searchParams.set('iss', config.serverMetadata().issuer);
    }
    let tokens: Awaited<ReturnType<typeof oidc.authorizationCodeGrant>>;
    try {
      tokens = await oidc.authorizationCodeGrant(config, url, {
        pkceCodeVerifier: loginState.codeVerifier,
        expectedState: loginState.state,
        expectedNonce: loginState.nonce,
        idTokenExpected: true,
      });
    } catch (error) {
      if (error instanceof oidc.AuthorizationResponseError) {
        throw new FlipAuthError('access_denied', `Flip returned ${error.error}`, {
          cause: error,
          oauthError: error.error,
        });
      }
      throw new FlipAuthError('callback_failed', 'Flip sign-in could not be completed', {
        cause: error,
      });
    }

    const idClaims = tokens.claims() as Record<string, unknown> | undefined;
    if (!idClaims) {
      throw new FlipAuthError('callback_failed', 'Flip returned no ID token');
    }
    let claims = idClaims;
    if (!str(idClaims.email)) {
      // Not every client gets the email claim in the ID token; UserInfo has it.
      try {
        const info = await oidc.fetchUserInfo(config, tokens.access_token, String(idClaims.sub));
        claims = { ...info, ...idClaims, email: info.email, email_verified: info.email_verified };
      } catch (error) {
        throw new FlipAuthError('callback_failed', 'Flip UserInfo request failed', {
          cause: error,
        });
      }
    }

    const identity = toFlipIdentity(claims);
    if (!identity.email) {
      throw new FlipAuthError('email_missing', 'Flip returned no email address');
    }
    if ((this.options.requireVerifiedEmail ?? true) && identity.emailVerified !== true) {
      throw new FlipAuthError('email_not_verified', 'Flip did not confirm the email is verified');
    }
    return identity;
  }
}

/** A Flip sign-in client. Create one per app (it caches discovery) and reuse it. */
export function createFlipAuth(options: FlipAuthOptions): FlipAuth {
  return new FlipOidcClient({ ...options, issuer: options.issuer.replace(/\/+$/, '') });
}
