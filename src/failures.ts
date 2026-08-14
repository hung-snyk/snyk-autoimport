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
import type { TargetLike } from './target-format';

const FAILED_LOG_NAME = 'failed-imports.log';

export interface FailureEntry {
  target?: TargetLike;
  errorMessage?: string;
  innerError?: string;
}

function logPathFor(orgId: string): string {
  return path.join(LOG_DIR, `${orgId}.${FAILED_LOG_NAME}`);
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
