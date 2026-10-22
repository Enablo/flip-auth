/** Why a Flip sign-in failed. Apps map these to their own messages. */
export type FlipAuthErrorCode =
  /** Flip's discovery document couldn't be fetched or doesn't match the configured issuer. */
  | 'discovery_failed'
  /** The login state is missing, malformed or older than its maximum age. */
  | 'login_expired'
  /** The person cancelled at Flip or Flip returned an error (see `oauthError`). */
  | 'access_denied'
  /** State, PKCE, nonce, token or ID token validation failed. */
  | 'callback_failed'
  /** Flip returned no email address for the account. */
  | 'email_missing'
  /** Flip didn't say the email is verified (and `requireVerifiedEmail` is on). */
  | 'email_not_verified';

export class FlipAuthError extends Error {
  readonly code: FlipAuthErrorCode;
  /** The OAuth `error` from Flip, for `access_denied`. */
  readonly oauthError?: string;

  constructor(
    code: FlipAuthErrorCode,
    message: string,
    options: { cause?: unknown; oauthError?: string } = {},
  ) {
    super(message, { cause: options.cause });
    this.name = 'FlipAuthError';
    this.code = code;
    this.oauthError = options.oauthError;
  }
}
