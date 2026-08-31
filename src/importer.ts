/**
 * Run the import: kick off targets, then poll to completion.
 *
 * `importTargets` paces requests internally (CONCURRENT_IMPORTS, default 15)
 * and returns per-target kickoff failures rather than aborting the batch.
 * `pollImportUrls` then waits for each job and returns the project results.
 */
import type { requestsManager } from 'snyk-request-manager';
import { importTargets, pollImportUrls, type ImportTarget, type PollProgress } from './api';
import type { FailureEntry } from './failures';

export interface ImportOutcome {
  createdProjects: Array<{ projectUrl: string; targetFile?: string }>;
  failedProjects: Array<{ projectUrl?: string; targetFile?: string; locationUrl?: string }>;
  /** Targets that never produced a polling URL (kickoff itself failed). */
  kickoffFailures: number;
  /** Why each of those kickoffs failed. */
  kickoffFailureDetails: FailureEntry[];
  submittedTargets: number;
  /** Repos whose import job ran to completion, whatever it produced. */
  reposImported: number;
  /**
   * Of those, ones that produced no projects at all. A successful import of a
   * repo with no supported manifests — worth naming, because nothing is being
   * scanned there and the repo count alone would imply otherwise.
   */
  reposWithoutProjects: number;
}

export interface RunOptions {
  /**
   * Called while Snyk is still scanning. Without this the CLI prints
   * "Importing..." and then nothing for as long as the scan takes — which
   * on a real repo is minutes, and reads as a hung process.
   */
  onProgress?: (progress: PollProgress) => void;
}

export async function runImport(
  rm: requestsManager,
  targets: ImportTarget[],
  options: RunOptions = {},
): Promise<ImportOutcome> {
  const { pollingUrls, failures } = await importTargets(rm, targets);
  const { projects, failed, pollFailures, perJob } = await pollImportUrls(rm, pollingUrls, {
    onProgress: options.onProgress,
  });

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
    reposImported: perJob.length,
    reposWithoutProjects: perJob.filter((j) => j.created === 0 && j.failed === 0).length,
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
    reposImported: a.reposImported + b.reposImported,
    reposWithoutProjects: a.reposWithoutProjects + b.reposWithoutProjects,
  };
}
