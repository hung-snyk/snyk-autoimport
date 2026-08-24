/**
 * Thin, typed layer over `snyk-request-manager`.
 *
 * The request manager already handles queueing, pacing and retries, so this
 * only normalises the two things its callers actually need: reading a status
 * code / header off a response whose shape varies by client, and turning a
 * thrown request error into a short, credential-free description.
 */
import type { requestsManager } from 'snyk-request-manager';

/** Axios-shaped response, with the field aliases the manager can return. */
export interface SnykResponse<T> {
  data: T;
  status?: number;
  statusCode?: number;
  headers?: Record<string, string | string[] | undefined>;
}

export async function snykRequest<T>(
  rm: requestsManager,
  verb: 'get' | 'post',
  url: string,
  body: unknown = {},
): Promise<SnykResponse<T>> {
  return (await rm.request({
    verb,
    url,
    body: JSON.stringify(body),
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
    data?: { message?: string; code?: number };
    response?: {
      status?: number;
      statusCode?: number;
      headers?: Record<string, string | undefined>;
      data?: { message?: string } | string;
    };
  };

  const res = err?.response;
  const status =
    err?.data?.code ?? err?.status ?? err?.statusCode ?? res?.status ?? res?.statusCode;

  const headers = res?.headers ?? {};
  const requestId =
    headers['snyk-request-id'] ?? headers['x-request-id'] ?? headers['request-id'];

  const bodyMessage =
    (typeof res?.data === 'object' ? res?.data?.message : undefined) ??
    (typeof res?.data === 'string' ? res.data : undefined);

  const message =
    err?.data?.message ?? bodyMessage ?? err?.message ?? 'Unknown error';

  return { status, message, requestId };
}

/** One-line summary suitable for showing a user, e.g. "401: Invalid auth". */
export function formatError(detail: ErrorDetail): string {
  return detail.status ? `${detail.status}: ${detail.message}` : detail.message;
}
