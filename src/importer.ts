/**
 * Run the import: kick off targets, then poll to completion.
 *
 * `importTargets` paces requests internally (CONCURRENT_IMPORTS, default 15)
 * and logs+skips individual kickoff failures rather than aborting the batch.
 * `pollImportUrls` waits for each job and returns the per-project results.
 * We snapshot the failed-imports log around the run to surface real reasons.
 */
import type { requestsManager } from 'snyk-request-manager';
import { importTargets, pollImportUrls, type ImportTarget } from './api';
import {
  snapshotOffset,
  readFailuresSince,
  type FailureEntry,
} from './failures';
import { withQuietConsole } from './quiet';

export interface ImportOutcome {
  createdProjects: Array<{ projectUrl: string; targetFile?: string }>;
  failedProjects: Array<{ projectUrl?: string; targetFile?: string; locationUrl?: string }>;
  /** Targets that never produced a polling URL (kickoff itself failed). */
  kickoffFailures: number;
  /** Parsed reasons for the kickoff failures, read from the library's log. */
  kickoffFailureDetails: FailureEntry[];
  submittedTargets: number;
}

export async function runImport(
  rm: requestsManager,
  orgId: string,
  targets: ImportTarget[],
): Promise<ImportOutcome> {
  const offset = snapshotOffset(orgId);

  const { pollingUrls, projects, failed } = await withQuietConsole(async () => {
    const urls = await importTargets(rm, targets);
    const res = await pollImportUrls(rm, urls);
    return { pollingUrls: urls, projects: res.projects, failed: res.failed };
  });

  const created = projects.filter((p) => p.success);
  const kickoffFailures = Math.max(0, targets.length - pollingUrls.length);
  const kickoffFailureDetails =
    kickoffFailures > 0 ? readFailuresSince(orgId, offset) : [];

  return {
    createdProjects: created.map((p) => ({
      projectUrl: p.projectUrl,
      targetFile: p.targetFile,
    })),
    failedProjects: failed.map((f) => ({
      projectUrl: f.projectUrl,
      targetFile: f.targetFile,
      locationUrl: (f as { locationUrl?: string }).locationUrl,
    })),
    kickoffFailures,
    kickoffFailureDetails,
    submittedTargets: targets.length,
  };
}

/** Combine two outcomes from separate runImport calls into one summary. */
export function mergeOutcomes(a: ImportOutcome, b: ImportOutcome): ImportOutcome {
  return {
    createdProjects: [...a.createdProjects, ...b.createdProjects],
    failedProjects: [...a.failedProjects, ...b.failedProjects],
    kickoffFailures: a.kickoffFailures + b.kickoffFailures,
    kickoffFailureDetails: [...a.kickoffFailureDetails, ...b.kickoffFailureDetails],
    submittedTargets: a.submittedTargets + b.submittedTargets,
  };
}
