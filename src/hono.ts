import type { Context } from 'hono';
import { Hono } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import type { FlipAuth, FlipIdentity } from './client.js';
import { FlipAuthError } from './errors.js';
import { DEFAULT_LOGIN_MAX_AGE_SECONDS, decodeLoginState, encodeLoginState } from './state.js';

export type FlipAuthRoutesOptions = {
  /** The client, or a function returning it (or undefined when Flip isn't configured). */
  flip: FlipAuth | (() => FlipAuth | undefined);
  /** The full callback URL registered with Flip, e.g. `https://app.example.com/api/auth/flip/callback`. */
  redirectUri: string;
  /** Default `/flip` and `/flip/callback`, relative to where the routes are mounted. */
  startPath?: string;
  callbackPath?: string;
  /** Default `__Host-flip-login`. The `__Host-` prefix needs HTTPS (browsers allow it on localhost). */
  cookieName?: string;
  /** Default `Lax`. Use `None` (with partitioned cookies) only inside third-party iframes. */
  sameSite?: 'Lax' | 'None';
  maxAgeSeconds?: number;
  /**
   * Called with a valid identity. Decide whether this person may sign in, start your session and
   * return a redirect (to `returnTo`). Set at most one cookie here: some platforms, including Neon
   * Functions, deliver only the last Set-Cookie header, so the login cookie is left to expire.
   */
  onSignIn: (c: Context, identity: FlipIdentity, returnTo: string) => Response | Promise<Response>;
  /** Default: redirect to `/sign-in?error=<code>`. Never logs the callback URL (it holds the code). */
  onError?: (c: Context, error: FlipAuthError) => Response | Promise<Response>;
};

/** `GET <startPath>?returnTo=/path` and `GET <callbackPath>`, as a Hono app to mount. */
export function flipAuthRoutes(options: FlipAuthRoutesOptions) {
  const app = new Hono();
  const cookieName = options.cookieName ?? '__Host-flip-login';
  const maxAgeSeconds = options.maxAgeSeconds ?? DEFAULT_LOGIN_MAX_AGE_SECONDS;
  const getFlip = () => (typeof options.flip === 'function' ? options.flip() : options.flip);
  const onError =
    options.onError ??
    ((c: Context, error: FlipAuthError) => c.redirect(`/sign-in?error=${error.code}`));

  app.get(options.startPath ?? '/flip', async (c) => {
    const flip = getFlip();
    if (!flip) {
      return onError(c, new FlipAuthError('discovery_failed', 'Flip sign-in is not configured'));
    }
    let started: Awaited<ReturnType<FlipAuth['start']>>;
    try {
      started = await flip.start({
        redirectUri: options.redirectUri,
        returnTo: c.req.query('returnTo'),
      });
    } catch (error) {
      return onError(c, asFlipError(error));
    }
    setCookie(c, cookieName, encodeLoginState(started.loginState), {
      httpOnly: true,
      secure: true,
      sameSite: options.sameSite ?? 'Lax',
      path: '/',
      maxAge: maxAgeSeconds,
    });
    return c.redirect(started.url);
  });

  app.get(options.callbackPath ?? '/flip/callback', async (c) => {
    const flip = getFlip();
    const loginState = decodeLoginState(getCookie(c, cookieName), { maxAgeSeconds });
    if (!flip || !loginState) {
      return onError(
        c,
        new FlipAuthError('login_expired', 'The Flip sign-in expired or was not started here'),
      );
    }
    // Behind a proxy the request URL may name another host, so rebuild the URL Flip redirected to.
    const callbackUrl = new URL(options.redirectUri);
    callbackUrl.search = new URL(c.req.url).search;
    let identity: FlipIdentity;
    try {
      identity = await flip.finish(callbackUrl, loginState);
    } catch (error) {
      return onError(c, asFlipError(error));
    }
    return options.onSignIn(c, identity, loginState.returnTo);
  });

  return app;
}

function asFlipError(error: unknown): FlipAuthError {
  return error instanceof FlipAuthError
    ? error
    : new FlipAuthError('callback_failed', 'Flip sign-in failed', { cause: error });
}
