/**
 * Shared HTTP for SCM discovery.
 *
 * Uses the runtime's built-in fetch (Node 18+; this package requires 20), so
 * discovering repos across five providers adds no dependency. `snyk-api-import`
 * reached for @octokit/rest, @gitbeaker/node, needle and bottleneck to do the
 * same work.
 *
 * Every provider paginates sequentially — one request in flight per provider —
 * so pacing falls out of the traversal and no rate limiter is needed. What is
 * needed is surviving a throttle, which is what the retry below is for.
 */

const MAX_ATTEMPTS = 5;
const BASE_BACKOFF_MS = 2_000;
const MAX_BACKOFF_MS = 120_000;

export interface ScmResponse<T> {
  status: number;
  body: T;
  headers: Headers;
}

export class ScmError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly url: string,
  ) {
    super(message);
    this.name = 'ScmError';
  }
}

/** Seconds from a Retry-After header, if the server sent a usable one. */
function retryAfterMs(headers: Headers): number | undefined {
  const raw = headers.get('retry-after');
  if (!raw) return undefined;
  const seconds = Number.parseInt(raw, 10);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds * 1000 : undefined;
}

/**
 * GitHub reports secondary rate limits as 403 with a marker header, which is
 * retryable — unlike a plain 403 for a repo the token cannot see, which is not.
 */
function isThrottled(status: number, headers: Headers): boolean {
  if (status === 429) return true;
  return (
    status === 403 &&
    (headers.has('retry-after') || headers.get('x-ratelimit-remaining') === '0')
  );
}

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

export interface RetryOptions {
  maxAttempts?: number;
  baseBackoffMs?: number;
}

/**
 * GET and parse JSON, retrying throttles and transient server errors.
 *
 * `label` names the resource for error messages ("GitHub repos for acme").
 * The URL is included but never the response body, which can echo back the
 * request — and with it the token.
 *
 * `retry` exists so tests can exercise the backoff without waiting on it.
 */
export async function scmGet<T>(
  url: string,
  headers: Record<string, string>,
  label: string,
  retry: RetryOptions = {},
): Promise<ScmResponse<T>> {
  const maxAttempts = retry.maxAttempts ?? MAX_ATTEMPTS;
  const base = retry.baseBackoffMs ?? BASE_BACKOFF_MS;
  const backoff = (attempt: number, h: Headers): number =>
    Math.min(retryAfterMs(h) ?? base * 2 ** attempt, MAX_BACKOFF_MS);
  let lastError: string = 'unknown error';

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    let res: Response;
    try {
      res = await fetch(url, { headers: { accept: 'application/json', ...headers } });
    } catch (err) {
      // Network-level failure (DNS, TLS, connection reset) — worth a retry.
      lastError = err instanceof Error ? err.message : 'network error';
      if (attempt === maxAttempts - 1) break;
      await sleep(backoff(attempt, new Headers()));
      continue;
    }

    if (isThrottled(res.status, res.headers)) {
      if (attempt === maxAttempts - 1) {
        throw new ScmError(`${label}: rate limited and out of retries.`, res.status, url);
      }
      await sleep(backoff(attempt, res.headers));
      continue;
    }

    if (res.status >= 500) {
      lastError = `server error ${res.status}`;
      if (attempt === maxAttempts - 1) break;
      await sleep(backoff(attempt, res.headers));
      continue;
    }

    if (!res.ok) {
      throw new ScmError(
        `${label}: request failed with ${res.status}.`,
        res.status,
        url,
      );
    }

    return {
      status: res.status,
      body: (await res.json()) as T,
      headers: res.headers,
    };
  }

  throw new ScmError(`${label}: ${lastError}.`, 0, url);
}

/** Basic auth header value, for the providers that expect one. */
export function basicAuth(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
}

/** Read a required token from the environment, or explain what to set. */
export function requireEnv(name: string, source: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is not set — required to discover ${source} repos.`);
  }
  return value;
}
