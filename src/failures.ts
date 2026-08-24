/**
 * Classify why a target could not be started, so the summary can offer the
 * right fix (401 wrong-integration vs. 404 not-shared-with-the-GitHub-App).
 *
 * These used to be recovered by re-reading `snyk-api-import`'s bunyan log at
 * `<LOG_DIR>/<orgId>.failed-imports.log`, snapshotting the file size before
 * each run to read only new bytes. Now that this tool owns the import call,
 * failures come back from it as data and the log round-trip is gone.
 */
import type { TargetLike } from './target-format';

export interface FailureEntry {
  target?: TargetLike;
  errorMessage?: string;
  /** HTTP status, when the failure came back as an HTTP response. */
  status?: number;
}

/**
 * Prefer the status code; fall back to scanning the message for failures that
 * never carried one (a socket error, or a message that only embeds the code).
 */
function matches(entry: FailureEntry, code: number, pattern: RegExp): boolean {
  if (entry.status === code) return true;
  if (entry.status !== undefined) return false;
  return pattern.test(entry.errorMessage ?? '');
}

export function isAuthFailure(entry: FailureEntry): boolean {
  return matches(entry, 401, /401|ApiAuthenticationError|Invalid credentials/i);
}

export function isNotFoundFailure(entry: FailureEntry): boolean {
  return matches(entry, 404, /404|NotFoundError|Not found/i);
}
