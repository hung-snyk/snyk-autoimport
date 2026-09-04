/**
 * Thin, typed layer over `snyk-request-manager`.
 *
 * The request manager already handles queueing, pacing and retries, so this
 * only normalises the two things its callers actually need: reading a status
 * code / header off a response whose shape varies by client, and turning a
 * thrown request error into a short, credential-free description.
 */
import type { requestsManager } from 'snyk-request-manager';
import { snykAuthHeaders } from './oauth';

/** Axios-shaped response, with the field aliases the manager can return. */
export interface SnykResponse<T> {
  data: T;
  status?: number;
  statusCode?: number;
  headers?: Record<string, string | string[] | undefined>;
}

/**
 * `useRest` switches the request manager from the v1 base to the REST base
 * (`/rest/`), which it derives from the same configured host — so the region
 * stays correct either way.
 *
 * Every Snyk call in this tool goes through here, which is what makes it the
 * right place to attach an OAuth bearer token: the manager merges a request's
 * own headers over its defaults, so this overrides whatever it would have
 * sent, and a token refreshed mid-run takes effect on the next request rather
 * than being pinned at construction. In API-token mode nothing is attached and
 * the manager's own `SNYK_TOKEN` handling applies — see oauth.ts.
 */
export async function snykRequest<T>(
  rm: requestsManager,
  verb: 'get' | 'post',
  url: string,
  body: unknown = {},
  useRest = false,
): Promise<SnykResponse<T>> {
  const headers = await snykAuthHeaders();
  return (await rm.request({
    verb,
    url,
    body: JSON.stringify(body),
    ...(headers ? { headers } : {}),
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
 * `snyk-request-manager` wraps failures in an error whose `message` is the
 * *inspected* underlying axios error — which includes the outgoing request
 * headers, and therefore `Authorization: token <the real token>`. Printing
 * that message verbatim would leak the credential into a terminal, a CI log,
 * or a pasted bug report.
 *
 * So: first line only, then redact anything that looks like a credential even
 * if it appears there.
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

/** A JSON:API error entry, which is how Snyk reports the status on a failure. */
interface JsonApiError {
  status?: string | number;
  detail?: string;
  details?: string;
  title?: string;
}

/**
 * Extract status, a human-meaningful message, and the Snyk request id from a
 * thrown error.
 *
 * Deliberately never includes the full response body: it can echo back request
 * headers, and those carry the API token.
 */
export function describeError(error: unknown): ErrorDetail {
  const err = error as {
    message?: string;
    status?: number;
    statusCode?: number;
    data?: { message?: string; code?: number; errors?: JsonApiError[] };
    response?: {
      status?: number;
      statusCode?: number;
      headers?: Record<string, string | undefined>;
      data?: { message?: string; errors?: JsonApiError[] } | string;
    };
  };

  const res = err?.response;
  // The wrapped request-manager error carries neither `status` nor `response`;
  // its only structured signal is a JSON:API errors array on `data`, whose
  // status is a *string*.
  const jsonApi =
    err?.data?.errors?.[0] ??
    (typeof res?.data === 'object' ? res?.data?.errors?.[0] : undefined);
  const jsonApiStatus =
    jsonApi?.status === undefined ? undefined : Number(jsonApi.status);

  const status =
    err?.data?.code ??
    err?.status ??
    err?.statusCode ??
    res?.status ??
    res?.statusCode ??
    (Number.isFinite(jsonApiStatus) ? jsonApiStatus : undefined);

  const headers = res?.headers ?? {};
  const requestId =
    headers['snyk-request-id'] ?? headers['x-request-id'] ?? headers['request-id'];

  const bodyMessage =
    (typeof res?.data === 'object' ? res?.data?.message : undefined) ??
    (typeof res?.data === 'string' ? res.data : undefined);

  const raw =
    err?.data?.message ??
    jsonApi?.detail ??
    jsonApi?.details ??
    jsonApi?.title ??
    bodyMessage ??
    err?.message ??
    'Unknown error';

  return { status, message: safeMessage(raw), requestId };
}

/** One-line summary suitable for showing a user, e.g. "401: Invalid auth". */
export function formatError(detail: ErrorDetail): string {
  return detail.status ? `${detail.status}: ${detail.message}` : detail.message;
}
