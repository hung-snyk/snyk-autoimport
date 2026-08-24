/**
 * Run the import: kick off targets, then poll to completion.
 *
 * `importTargets` paces requests internally (CONCURRENT_IMPORTS, default 15)
 * and returns per-target kickoff failures rather than aborting the batch.
 * `pollImportUrls` then waits for each job and returns the project results.
 */
import type { requestsManager } from 'snyk-request-manager';
import { importTargets, pollImportUrls, type ImportTarget } from './api';
import type { FailureEntry } from './failures';

export interface ImportOutcome {
  createdProjects: Array<{ projectUrl: string; targetFile?: string }>;
  failedProjects: Array<{ projectUrl?: string; targetFile?: string; locationUrl?: string }>;
  /** Targets that never produced a polling URL (kickoff itself failed). */
  kickoffFailures: number;
  /** Why each of those kickoffs failed. */
  kickoffFailureDetails: FailureEntry[];
  submittedTargets: number;
}

export async function runImport(
  rm: requestsManager,
  targets: ImportTarget[],
): Promise<ImportOutcome> {
  const { pollingUrls, failures } = await importTargets(rm, targets);
  const { projects, failed, pollFailures } = await pollImportUrls(rm, pollingUrls);

  return {
    createdProjects: projects.map((p) => ({
      projectUrl: p.projectUrl,
      targetFile: p.targetFile,
    })),
    failedProjects: [
      ...failed.map((f) => ({
        projectUrl: f.projectUrl,
        targetFile: f.targetFile,
        locationUrl: f.locationUrl,
      })),
      // A job whose status could never be read is reported here rather than
      // dropped: its projects may well have been created, so claiming success
      // would be wrong and claiming nothing would hide it.
      ...pollFailures.map((f) => ({ locationUrl: f.locationUrl })),
    ],
    kickoffFailures: failures.length,
    kickoffFailureDetails: failures.map((f) => ({
      target: f.target,
      errorMessage: f.errorMessage,
      status: f.status,
    })),
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
