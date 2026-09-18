/**
 * Response helpers and error description for Snyk calls.
 *
 * The client itself lives in client.ts. This is the layer above it: reading a
 * status or header off a response whose shape varies between the real client
 * and a test double, and turning a thrown request error into a short,
 * credential-free description.
 */
import type { SnykClient, SnykResponse } from './client';

export type { SnykResponse };

/**
 * Every Snyk call in this tool goes through here.
 *
 * `useRest` switches from the v1 base to the REST base (`/rest`), which the
 * client derives from the same configured host — so the region stays correct
 * either way. Authentication is resolved inside the client, per request, so a
 * short-lived OAuth token can be refreshed mid-run (see oauth.ts).
 */
export async function snykRequest<T>(
  client: SnykClient,
  verb: 'get' | 'post',
  url: string,
  body: unknown = {},
  useRest = false,
): Promise<SnykResponse<T>> {
  return (await client.request({
    verb,
    url,
    body: JSON.stringify(body),
    ...(useRest ? { useRESTApi: true } : {}),
  })) as SnykResponse<T>;
}

export function statusOf(res: SnykResponse<unknown>): number | undefined {
  return res.status ?? res.statusCode;
}

/** Case-insensitive header lookup — casing differs between HTTP clients. */
export function headerOf(
  res: SnykResponse<unknown>,
  name: string,
): string | undefined {
  const headers = res.headers ?? {};
  const key = Object.keys(headers).find(
    (k) => k.toLowerCase() === name.toLowerCase(),
  );
  const value = key ? headers[key] : undefined;
  return Array.isArray(value) ? value[0] : value;
}

export interface ErrorDetail {
  status?: number;
  message: string;
  requestId?: string;
}

/**
 * Reduce an error message to something safe and short to print.
 *
 * First line only, then redact anything credential-shaped. Kept after the
 * client that made it necessary was replaced: an error message is the one
 * place a secret has actually leaked in this project's history (the previous
 * HTTP client inspected the axios error into its message, request headers and
 * all), and the cost of keeping the guard is two regexes.
 */
function safeMessage(raw: string): string {
  const firstLine = raw.split('\n')[0].trim();
  return (
    firstLine
      // A header value runs to the end of the line (or its closing quote), and
      // can itself contain a space — "token abc", "Bearer abc". Matching only
      // the next word would redact the scheme and leave the secret.
      .replace(
        /((?:authorization|private-token|x-api-key)\s*[:=]\s*['"]?)[^\n'"]*/gi,
        '$1<redacted>',
      )
      // A scheme-prefixed credential with no header name around it.
      .replace(/\b(token|bearer|basic)\s+[A-Za-z0-9._~+/=-]+/gi, '$1 <redacted>')
  );
}

/**
 * Extract status, a printable message, and the Snyk request id from a thrown
 * error.
 *
 * Every error this can now see is one of three shapes, all of them ours:
 * `SnykApiError` (status + detail + request id, from client.ts), `ScmError`
 * (status + message, from scm/http.ts), or a plain `Error`. This used to also
 * unpick axios-shaped errors — `err.response.data`, and a JSON:API errors
 * array on `err.data` whose status was a *string* — because that is what
 * `snyk-request-manager` threw. Nothing produces those shapes any more, and
 * carrying the code to parse them implied a hazard that no longer exists.
 *
 * `safeMessage` stays, as defence in depth rather than as the load-bearing
 * protection it once was: the reason this function never touches a response
 * body is that the old client's error messages embedded the request headers,
 * token included. Ours never do.
 */
export function describeError(error: unknown): ErrorDetail {
  const err = error as {
    message?: string;
    status?: number;
    statusCode?: number;
    requestId?: string;
  };

  const status = err?.status ?? err?.statusCode;
  // A network failure is reported as status 0 (see client.ts), which is not a
  // status worth printing — `formatError` would render it as "0: ...".
  return {
    status: status === 0 ? undefined : status,
    message: safeMessage(err?.message ?? 'Unknown error'),
    requestId: err?.requestId,
  };
}

/** One-line summary suitable for showing a user, e.g. "401: Invalid auth". */
export function formatError(detail: ErrorDetail): string {
  return detail.status ? `${detail.status}: ${detail.message}` : detail.message;
}
