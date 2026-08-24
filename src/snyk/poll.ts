/**
 * Poll import jobs to completion: GET on each job's polling URL.
 *
 * An import job is asynchronous — Snyk clones the repo, detects manifests and
 * creates a project per manifest. The job reports `pending` until all of that
 * finishes, so each URL is re-checked on an interval until it reads `complete`.
 *
 * A target that produces no projects (a repo with no supported manifests)
 * completes normally with an empty project list. That is a success, not an
 * error, and is why the summary counts projects rather than targets.
 */
import type { requestsManager } from 'snyk-request-manager';
import { mapWithConcurrency, sleep } from './async';
import { describeError, formatError, snykRequest, statusOf } from './http';
import { toPollingPath } from './import';
import type { PollImportResponse, Project } from './types';

const POLL_INTERVAL_MS = 20_000;
const MAX_POLL_ATTEMPTS = 1_000;
const POLL_CONCURRENCY = 10;

export interface FailedProject extends Project {
  locationUrl: string;
}

export interface PollFailure {
  locationUrl: string;
  errorMessage: string;
}

export interface PollResult {
  /** Projects Snyk successfully created. */
  projects: Project[];
  /** Projects the job attempted but could not create. */
  failed: FailedProject[];
  /** Jobs whose status could never be read (the import may still be running). */
  pollFailures: PollFailure[];
}

export interface PollOptions {
  intervalMs?: number;
  maxAttempts?: number;
}

/** Poll one job until it reports `complete`, then return its projects. */
export async function pollImportUrl(
  rm: requestsManager,
  locationUrl: string,
  options: PollOptions = {},
): Promise<Project[]> {
  if (!locationUrl) {
    throw new Error('Missing required parameter: location url.');
  }
  const intervalMs = options.intervalMs ?? POLL_INTERVAL_MS;
  const maxAttempts = options.maxAttempts ?? MAX_POLL_ATTEMPTS;
  const path = toPollingPath(locationUrl);

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const res = await snykRequest<PollImportResponse>(rm, 'get', path);

    const status = statusOf(res);
    if (status && status !== 200) {
      throw new Error(`Expected a 200 response, instead received: ${status}.`);
    }

    const job = res.data;
    if (job?.status && job.status !== 'complete') {
      await sleep(intervalMs);
      continue;
    }
    return (job?.logs ?? []).flatMap((log) => log.projects ?? []);
  }

  throw new Error(
    `Import job did not complete after ${maxAttempts} checks. It may still be running.`,
  );
}

/**
 * Poll every job. A job that cannot be read is recorded rather than thrown, so
 * one unreachable job does not discard results already collected from others.
 */
export async function pollImportUrls(
  rm: requestsManager,
  locationUrls: readonly string[],
  options: PollOptions = {},
): Promise<PollResult> {
  const projects: Project[] = [];
  const failed: FailedProject[] = [];
  const pollFailures: PollFailure[] = [];

  await mapWithConcurrency(
    [...new Set(locationUrls)],
    POLL_CONCURRENCY,
    async (locationUrl) => {
      try {
        for (const project of await pollImportUrl(rm, locationUrl, options)) {
          if (project.success) projects.push(project);
          else failed.push({ ...project, locationUrl });
        }
      } catch (error) {
        pollFailures.push({
          locationUrl,
          errorMessage: formatError(describeError(error)),
        });
      }
    },
  );

  return { projects, failed, pollFailures };
}
