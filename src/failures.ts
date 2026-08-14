/**
 * Read and classify the underlying library's failed-imports log.
 *
 * `snyk-api-import` swallows per-target kickoff errors, logs them to
 * `<LOG_DIR>/<orgId>.failed-imports.log` (bunyan JSON lines), and returns
 * fewer polling URLs. To surface the real reason (instead of a generic
 * "permission/config" line) we read that log. The file is appended across
 * runs, so we snapshot its size before the import and read only new bytes.
 */
import * as fs from 'fs';
import * as path from 'path';
import { LOG_DIR } from './config';
import { ORG_ID_PATTERN } from './org-id';
import type { TargetLike } from './target-format';

const FAILED_LOG_NAME = 'failed-imports.log';

export interface FailureEntry {
  target?: TargetLike;
  errorMessage?: string;
  innerError?: string;
}

/**
 * orgId reaches the filesystem here and originates from the Snyk API (or from
 * `--snyk-org-id`), so it is treated as untrusted: anything that is not a bare
 * UUID is rejected outright rather than sanitized, since stripping separators
 * out of a bad value would quietly read a *different* file. basename() then
 * pins the result to a single path segment inside LOG_DIR — a no-op for a
 * validated UUID, and a backstop if that pattern is ever loosened.
 *
 * Both readers below treat a throw as "no failure details available", so a bad
 * value degrades to a generic summary instead of escaping LOG_DIR.
 */
function logPathFor(orgId: string): string {
  if (!ORG_ID_PATTERN.test(orgId)) {
    throw new Error(`Refusing to build a log path from non-UUID org id "${orgId}".`);
  }
  return path.join(LOG_DIR, path.basename(`${orgId}.${FAILED_LOG_NAME}`));
}

/** Byte offset to read from after the next import (current end of file). */
export function snapshotOffset(orgId: string): number {
  try {
    return fs.statSync(logPathFor(orgId)).size;
  } catch {
    return 0;
  }
}

/** Parse failure entries appended since the given offset. */
export function readFailuresSince(orgId: string, offset: number): FailureEntry[] {
  let content = '';
  try {
    const fd = fs.openSync(logPathFor(orgId), 'r');
    try {
      const size = fs.fstatSync(fd).size;
      if (size <= offset) return [];
      const buf = Buffer.alloc(size - offset);
      fs.readSync(fd, buf, 0, buf.length, offset);
      content = buf.toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return [];
  }

  const entries: FailureEntry[] = [];
  for (const line of content.split('\n')) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line);
      entries.push({
        target: parsed.target,
        errorMessage: parsed.errorData?.errorMessage,
        innerError: parsed.errorData?.innerError,
      });
    } catch {
      // ignore malformed lines
    }
  }
  return entries;
}

export function isAuthFailure(entry: FailureEntry): boolean {
  const blob = `${entry.errorMessage ?? ''} ${entry.innerError ?? ''}`;
  return /401|ApiAuthenticationError|Invalid credentials/i.test(blob);
}

export function isNotFoundFailure(entry: FailureEntry): boolean {
  const blob = `${entry.errorMessage ?? ''} ${entry.innerError ?? ''}`;
  return /404|NotFoundError|Not found/i.test(blob);
}
