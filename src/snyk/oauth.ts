/**
 * Snyk authentication: API token, or an OAuth 2.0 service account.
 *
 * Snyk supports three credential types for automation. An API key never
 * expires, which is why Snyk no longer recommends it; an OAuth 2.0 service
 * account exchanges a client id and secret for a short-lived access token
 * (one hour by default) that this module refreshes as needed:
 * https://docs.snyk.io/platform-administration/service-accounts/service-accounts-using-oauth-2.0
 *
 * HOW THE TOKEN REACHES THE WIRE
 *
 * `snyk-request-manager` can send a bearer token itself — it reads
 * `SNYK_OAUTH_TOKEN` — but only once, in its constructor. One manager is
 * created per run and held across discovery, import and polling, so a token
 * that expired mid-run could never be replaced. Instead the header is set
 * per-request (`snykRequest` in http.ts), which the manager supports: a
 * request's own headers are merged over its defaults, so `Authorization` here
 * wins. Every request then gets whatever token is current at that moment.
 *
 * An API token needs none of this — the manager reads `SNYK_TOKEN` per its own
 * rules — so `snykAuthHeaders` returns nothing in that mode and leaves it be.
 */

const DEFAULT_API_ORIGIN = 'https://api.snyk.io';
const TOKEN_PATH = '/oauth2/token';

/**
 * Refresh this far ahead of the stated expiry, so a token cannot lapse between
 * the check and the request arriving at Snyk.
 */
const EXPIRY_SKEW_MS = 60_000;

/** Snyk's own default when a response omits `expires_in`. */
const DEFAULT_TTL_SECONDS = 3600;

/**
 * Cap on how much of an error body is quoted back, to keep failures readable.
 *
 * NOTE on wording, for anyone tidying the strings below: they say
 * "token-exchange endpoint", not "token endpoint", on purpose. Error messages
 * from here are printed through `safeMessage` (http.ts), which redacts
 * anything looking like `token <secret>` — and would otherwise redact the
 * *word* after "token", turning "token endpoint at https://..." into
 * "token <redacted> https://...". The hyphen keeps the message intact.
 */
const MAX_ERROR_DETAIL = 200;

export type SnykAuth =
  /** Client credentials, exchanged here for a short-lived access token. */
  | { mode: 'oauth-client'; clientId: string; clientSecret: string }
  /** An access token minted elsewhere. Used as-is; cannot be refreshed. */
  | { mode: 'oauth-token'; accessToken: string }
  /** A Snyk API key, sent by the request manager rather than by us. */
  | { mode: 'api-token'; token: string };

export type SnykAuthMode = SnykAuth['mode'];

/**
 * Which credential to use, from the environment.
 *
 * Precedence runs most-capable first: client credentials refresh themselves,
 * so they beat a static access token, which in turn is preferred over an API
 * key because setting it is the more deliberate act. In practice the orders
 * rarely collide — `auth login` stores one method and clears the other, so a
 * conflict only arises when env vars are set by hand.
 *
 * Half a client-credentials pair is an error rather than a silent fallback:
 * quietly authenticating as somebody else because a secret failed to reach the
 * environment is exactly the kind of surprise this tool avoids elsewhere.
 */
export function resolveSnykAuth(env: NodeJS.ProcessEnv = process.env): SnykAuth | undefined {
  const clientId = env.SNYK_OAUTH_CLIENT_ID?.trim();
  const clientSecret = env.SNYK_OAUTH_CLIENT_SECRET?.trim();

  if (clientId && clientSecret) {
    return { mode: 'oauth-client', clientId, clientSecret };
  }
  if (clientId || clientSecret) {
    const missing = clientId ? 'SNYK_OAUTH_CLIENT_SECRET' : 'SNYK_OAUTH_CLIENT_ID';
    const present = clientId ? 'SNYK_OAUTH_CLIENT_ID' : 'SNYK_OAUTH_CLIENT_SECRET';
    throw new Error(
      `${present} is set but ${missing} is not — an OAuth 2.0 client-credentials ` +
        'grant needs both. Set both, or neither.',
    );
  }

  const accessToken = env.SNYK_OAUTH_TOKEN?.trim();
  if (accessToken) return { mode: 'oauth-token', accessToken };

  const token = env.SNYK_TOKEN?.trim();
  if (token) return { mode: 'api-token', token };

  return undefined;
}

/** One line naming the credential in use. Never includes a secret. */
export function describeSnykAuth(auth: SnykAuth): string {
  switch (auth.mode) {
    case 'oauth-client':
      return `OAuth 2.0 service account (client ${auth.clientId})`;
    case 'oauth-token':
      return 'OAuth 2.0 access token (SNYK_OAUTH_TOKEN)';
    case 'api-token':
      return 'Snyk API token';
  }
}

/**
 * The token endpoint for whichever region is configured.
 *
 * Derived from `SNYK_API` rather than kept in its own table: that variable is
 * already the single place the region lands (see regions.ts), so a token
 * minted here can never be from a different region than the API calls that
 * follow. Only the origin is taken — `SNYK_API` carries a `/v1` suffix, while
 * `/oauth2/token` is served from the root.
 */
export function snykOauthTokenUrl(apiBase = process.env.SNYK_API): string {
  if (!apiBase) return `${DEFAULT_API_ORIGIN}${TOKEN_PATH}`;
  try {
    return `${new URL(apiBase).origin}${TOKEN_PATH}`;
  } catch {
    throw new Error(
      `SNYK_API is not a valid URL ("${apiBase}"), so the OAuth token-exchange endpoint ` +
        'cannot be derived from it. Expected something like https://api.snyk.io.',
    );
  }
}

interface TokenResponse {
  access_token?: string;
  token_type?: string;
  expires_in?: number;
}

interface CachedToken {
  /** Token url + client id: a change to either must not reuse a token. */
  key: string;
  token: string;
  /** Already includes the skew, so this is simply "good until". */
  expiresAt: number;
}

let cached: CachedToken | undefined;

/** Drop any cached access token. For tests, and for re-verifying at login. */
export function resetSnykOauthCache(): void {
  cached = undefined;
}

/**
 * Quote just enough of a failed exchange to be actionable.
 *
 * OAuth errors are a machine-readable code plus an optional description
 * (RFC 6749 §5.2), which is far more useful than a status alone —
 * `invalid_client` says the credentials are wrong, `invalid_scope` says they
 * are right but insufficient. The request body is never echoed, so the client
 * secret cannot come back out this way.
 */
async function errorDetail(res: Response): Promise<string> {
  let raw: string;
  try {
    raw = await res.text();
  } catch {
    return '';
  }
  try {
    const parsed = JSON.parse(raw) as { error?: string; error_description?: string };
    const code = parsed.error;
    const description = parsed.error_description;
    if (code && description) return `${code} — ${description}`;
    if (code || description) return String(code ?? description);
  } catch {
    // Not JSON; fall through to the raw text.
  }
  return raw.trim().split('\n')[0].slice(0, MAX_ERROR_DETAIL);
}

/**
 * Exchange client credentials for an access token.
 *
 * Snyk takes the client id and secret as form-urlencoded body parameters
 * (`client_secret_post`), which is what its own CLI sends; the Basic-auth form
 * RFC 6749 also allows is deliberately not attempted, since a second try would
 * only turn a clear "your secret is wrong" into a confusing pair of failures.
 */
async function exchangeClientCredentials(
  clientId: string,
  clientSecret: string,
  url: string,
): Promise<{ token: string; ttlSeconds: number }> {
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: clientId,
    client_secret: clientSecret,
  });

  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      body: body.toString(),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Could not reach the Snyk OAuth token-exchange endpoint at ${url}: ${message}`);
  }

  if (!res.ok) {
    const detail = await errorDetail(res);
    throw new Error(
      `Snyk rejected the OAuth client credentials (${res.status}` +
        `${detail ? `: ${detail}` : ''}). Check SNYK_OAUTH_CLIENT_ID and ` +
        `SNYK_OAUTH_CLIENT_SECRET, and that the service account belongs to ` +
        `${new URL(url).origin}.`,
    );
  }

  let parsed: TokenResponse;
  try {
    parsed = (await res.json()) as TokenResponse;
  } catch {
    throw new Error(`The Snyk OAuth token-exchange endpoint at ${url} did not return JSON.`);
  }

  if (!parsed.access_token) {
    throw new Error(
      `The Snyk OAuth token-exchange endpoint at ${url} returned no access_token. ` +
        'Check that the service account is an OAuth 2.0 one.',
    );
  }

  return {
    token: parsed.access_token,
    ttlSeconds:
      typeof parsed.expires_in === 'number' && parsed.expires_in > 0
        ? parsed.expires_in
        : DEFAULT_TTL_SECONDS,
  };
}

/** A currently-valid access token, minting a new one when the last has aged out. */
async function currentAccessToken(clientId: string, clientSecret: string): Promise<string> {
  const url = snykOauthTokenUrl();
  const key = `${url}|${clientId}`;

  if (cached && cached.key === key && cached.expiresAt > Date.now()) {
    return cached.token;
  }

  const { token, ttlSeconds } = await exchangeClientCredentials(clientId, clientSecret, url);
  cached = {
    key,
    token,
    // A TTL shorter than the skew leaves expiresAt at "now", so the next
    // request mints a fresh token rather than sending one about to lapse.
    expiresAt: Date.now() + Math.max(ttlSeconds * 1000 - EXPIRY_SKEW_MS, 0),
  };
  return token;
}

/**
 * The `Authorization` header for the current credential, or undefined when the
 * request manager should supply it (API token mode) or nothing is configured —
 * in which case the request fails on its own, with Snyk's 401 rather than a
 * second, redundant error from here.
 */
export async function snykAuthHeaders(): Promise<Record<string, string> | undefined> {
  const auth = resolveSnykAuth();
  if (!auth || auth.mode === 'api-token') return undefined;
  const token =
    auth.mode === 'oauth-token'
      ? auth.accessToken
      : await currentAccessToken(auth.clientId, auth.clientSecret);
  return { Authorization: `Bearer ${token}` };
}
