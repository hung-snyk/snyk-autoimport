/**
 * The HTTP client for Snyk's API, on the runtime's built-in fetch.
 *
 * This replaces `snyk-request-manager`, the last piece of borrowed
 * infrastructure in the project. The SCM side already talks to five providers
 * through ~140 lines of `scm/http.ts` with no dependency at all, and this is
 * the same shape for the Snyk side. Removing it also removes three separate
 * hazards that each cost real debugging time:
 *
 *  1. **Errors that carried the token.** The manager wrapped failures in an
 *     error whose `message` was the *inspected* axios error — request headers
 *     included, so `Authorization: token <the live token>`. Printing that put
 *     a credential in terminals and CI logs. `SnykApiError` below carries a
 *     status, a short detail and a request id, and nothing else. (The
 *     redaction in `safeMessage` stays as defence in depth; nothing should
 *     depend on it any more.)
 *  2. **OAuth read once, at construction.** It read `SNYK_OAUTH_TOKEN` in its
 *     constructor, so a token refreshed mid-run could never reach the wire.
 *     Here every request resolves the credential as it is sent.
 *  3. **A pinned `axios` override** in package.json, to keep a transitive
 *     dependency patched. Gone with the dependency.
 *
 * WHAT IS KEPT
 *
 * Pacing and retries, because the manager did provide those. Call sites bound
 * their own concurrency (CONCURRENT_IMPORTS for kickoff, POLL_CONCURRENCY for
 * polling), so what is needed here is a ceiling on how fast requests *start* —
 * the same job the manager's leaky bucket did, with the same numbers.
 *
 * A NOTE ON RETRYING POSTS
 *
 * The retry below applies to `POST .../import` as well as to reads, and that
 * is not idempotent in principle: a 5xx returned *after* Snyk created the job
 * means the retry submits the same target twice. It is kept anyway, for two
 * reasons. The previous client behaved identically, so this is not a new
 * exposure. And the consequence is bounded: Snyk deduplicates projects
 * server-side (verified live — re-importing an imported repo creates nothing),
 * so the visible effect is two job URLs for one repo, which inflates
 * `reposImported` in the summary rather than creating anything twice. Dropping
 * the retry would trade that rare miscount for real lost imports on every
 * transient 502, which is the worse deal.
 */
import { snykAuthHeaders } from './oauth';

/** Matches the manager's configured burst and period: 10 requests a second. */
const BURST = 10;
const PERIOD_MS = 1_000;

/** Matches the manager's `maxRetryCount: 3`. */
const MAX_ATTEMPTS = 3;
const BASE_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 60_000;

/** Cap on how much of an error body is quoted back. */
const MAX_DETAIL = 300;

export interface SnykResponse<T> {
  data: T;
  status?: number;
  /** Alias the manager used; kept so `statusOf` works for both. */
  statusCode?: number;
  headers?: Record<string, string | string[] | undefined>;
}

/**
 * One Snyk API call.
 *
 * Deliberately has no per-request `headers`: the previous client accepted them
 * and nothing set them, and a caller passing a lowercase `authorization`
 * alongside the `Authorization` set below would have produced two keys, one of
 * which silently wins. Authentication belongs to the client alone.
 */
export interface SnykRequestSpec {
  verb: 'get' | 'post';
  /** Path relative to the version base, e.g. `/orgs` or `/org/{id}/import`. */
  url: string;
  /** Pre-serialised JSON, as the previous client expected. */
  body?: string;
  /** Use the REST base (`/rest`) rather than v1. */
  useRESTApi?: boolean;
}

/**
 * The seam the rest of the tool depends on.
 *
 * An interface rather than the class, so a test can hand any object with a
 * `request` method to code that takes a client — which is how every Snyk test
 * in this project already works.
 */
export interface SnykClient {
  request(spec: SnykRequestSpec): Promise<SnykResponse<unknown>>;
}

/** A Snyk API failure, with only the fields that are safe to print. */
export class SnykApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = 'SnykApiError';
  }
}

/**
 * Both API bases, from the one configured host.
 *
 * `SNYK_API` is normalised to end in `/v1` rather than trusted as given. Snyk's
 * own docs tell people to set it to the bare host (`https://api.eu.snyk.io`)
 * for the CLI, and the previous client used whatever it found verbatim — so a
 * user following those docs sent every v1 call to a path that 404s. The REST
 * base is taken from the origin, since `/rest` is served from the root.
 */
export function snykApiBases(apiBase = process.env.SNYK_API): {
  v1: string;
  rest: string;
} {
  const raw = apiBase?.trim() || 'https://api.snyk.io/v1';
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(
      `SNYK_API is not a valid URL ("${raw}"). Expected something like https://api.snyk.io.`,
    );
  }
  const path = url.pathname.replace(/\/+$/, '');
  const v1 = /\/v1$/.test(path) ? `${url.origin}${path}` : `${url.origin}${path}/v1`;
  return { v1, rest: `${url.origin}/rest` };
}

/**
 * Allow at most `BURST` request starts per `PERIOD_MS`.
 *
 * Start times are recorded and the window is trimmed on each call, so a caller
 * only waits when the window is genuinely full. Deliberately not a token
 * bucket with a background timer: nothing here should keep the process alive.
 */
class RateLimiter {
  private readonly starts: number[] = [];

  constructor(
    private readonly burst = BURST,
    private readonly periodMs = PERIOD_MS,
  ) {}

  async take(): Promise<void> {
    for (;;) {
      const now = Date.now();
      while (this.starts.length > 0 && now - this.starts[0] >= this.periodMs) {
        this.starts.shift();
      }
      if (this.starts.length < this.burst) {
        this.starts.push(now);
        return;
      }
      await sleep(this.periodMs - (now - this.starts[0]));
    }
  }
}

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, Math.max(ms, 0)));

function retryAfterMs(headers: Headers): number | undefined {
  const raw = headers.get('retry-after');
  if (!raw) return undefined;
  const seconds = Number.parseInt(raw, 10);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds * 1000 : undefined;
}

function headersToObject(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key] = value;
  });
  return out;
}

/** A JSON:API error entry, which is how Snyk reports a failure's detail. */
interface JsonApiError {
  status?: string | number;
  detail?: string;
  title?: string;
}

/**
 * The most useful one-line description of a failure, from the body.
 *
 * Snyk answers v1 with `{message}` and REST with JSON:API `{errors: [...]}`.
 * Only those named fields are read — never the whole body, which is what used
 * to echo the request (and the token) back into a printed message.
 */
function describeFailureBody(raw: string): { detail: string; status?: number } {
  try {
    const parsed = JSON.parse(raw) as {
      message?: string;
      error?: string;
      errors?: JsonApiError[];
    };
    const first = parsed.errors?.[0];
    const detail =
      parsed.message ?? parsed.error ?? first?.detail ?? first?.title ?? '';
    const status = first?.status === undefined ? undefined : Number(first.status);
    return {
      detail: detail.slice(0, MAX_DETAIL),
      status: Number.isFinite(status) ? status : undefined,
    };
  } catch {
    return { detail: raw.trim().split('\n')[0].slice(0, MAX_DETAIL) };
  }
}

export interface SnykClientOptions {
  userAgentPrefix?: string;
  maxAttempts?: number;
  baseBackoffMs?: number;
  /** Requests per period; 0 disables pacing. For tests. */
  burst?: number;
  periodMs?: number;
}

class HttpSnykClient implements SnykClient {
  private readonly limiter: RateLimiter;
  private readonly maxAttempts: number;
  private readonly baseBackoff: number;
  private readonly userAgent: string;

  constructor(options: SnykClientOptions = {}) {
    this.limiter = new RateLimiter(options.burst ?? BURST, options.periodMs ?? PERIOD_MS);
    this.maxAttempts = options.maxAttempts ?? MAX_ATTEMPTS;
    this.baseBackoff = options.baseBackoffMs ?? BASE_BACKOFF_MS;
    this.userAgent = `${options.userAgentPrefix ?? 'snyk-autoimport'}/snyk-autoimport`;
  }

  async request(spec: SnykRequestSpec): Promise<SnykResponse<unknown>> {
    const bases = snykApiBases();
    const base = spec.useRESTApi ? bases.rest : bases.v1;
    const url = `${base}/${spec.url.replace(/^\/+/, '')}`;

    // Resolved per request, not per client: an OAuth access token is
    // short-lived and may be refreshed part-way through a long run.
    const auth = await snykAuthHeaders();
    const token = process.env.SNYK_TOKEN?.trim();
    const headers: Record<string, string> = {
      accept: 'application/json',
      'content-type':
        spec.useRESTApi && spec.body ? 'application/vnd.api+json' : 'application/json',
      'user-agent': this.userAgent,
      ...(auth ?? (token ? { Authorization: `token ${token}` } : {})),
    };

    let lastError = 'unknown error';
    for (let attempt = 0; attempt < this.maxAttempts; attempt++) {
      await this.limiter.take();

      let res: Response;
      try {
        res = await fetch(url, {
          method: spec.verb.toUpperCase(),
          headers,
          ...(spec.body !== undefined && spec.verb === 'post' ? { body: spec.body } : {}),
        });
      } catch (error) {
        // DNS, TLS, connection reset — worth another attempt.
        lastError = error instanceof Error ? error.message : 'network error';
        if (attempt === this.maxAttempts - 1) break;
        await sleep(Math.min(this.baseBackoff * 2 ** attempt, MAX_BACKOFF_MS));
        continue;
      }

      const requestId =
        res.headers.get('snyk-request-id') ?? res.headers.get('x-request-id') ?? undefined;

      if (res.status === 429 || res.status >= 500) {
        const body = await res.text().catch(() => '');
        lastError = describeFailureBody(body).detail || `HTTP ${res.status}`;
        if (attempt === this.maxAttempts - 1) {
          throw new SnykApiError(lastError, res.status, requestId);
        }
        await sleep(
          Math.min(
            retryAfterMs(res.headers) ?? this.baseBackoff * 2 ** attempt,
            MAX_BACKOFF_MS,
          ),
        );
        continue;
      }

      const text = await res.text();
      if (!res.ok) {
        const { detail } = describeFailureBody(text);
        throw new SnykApiError(detail || `HTTP ${res.status}`, res.status, requestId);
      }

      // A 201 from the import endpoint has no body worth parsing; its result
      // is the Location header. An empty body is therefore not an error.
      let data: unknown = undefined;
      if (text.length > 0) {
        try {
          data = JSON.parse(text);
        } catch {
          throw new SnykApiError(
            `Expected JSON from ${spec.url} but the response was not parseable.`,
            res.status,
            requestId,
          );
        }
      }

      return { data, status: res.status, headers: headersToObject(res.headers) };
    }

    throw new SnykApiError(lastError, 0);
  }
}

/**
 * The client every command uses. `userAgentPrefix` is carried over from the
 * previous implementation so Snyk-side request logs stay attributable.
 */
export function makeSnykClient(
  userAgentPrefix = 'snyk-autoimport',
  options: SnykClientOptions = {},
): SnykClient {
  return new HttpSnykClient({ ...options, userAgentPrefix });
}
