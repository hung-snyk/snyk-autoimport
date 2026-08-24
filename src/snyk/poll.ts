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

/**
 * Polling starts fast and backs off to a steady interval.
 *
 * A fixed 20s interval made every import take at least 20s to report, even
 * one Snyk had already finished — a repo with no manifests completes almost
 * immediately server-side. Starting at 2s and doubling to the same 20s cap
 * keeps long imports just as cheap (a 2-minute job costs one extra request)
 * while making short ones feel immediate.
 */
const FIRST_POLL_INTERVAL_MS = 2_000;
const MAX_POLL_INTERVAL_MS = 20_000;
const MAX_POLL_ATTEMPTS = 1_000;
const POLL_CONCURRENCY = 10;
/** How often to report that a long import is still running. */
const PROGRESS_INTERVAL_MS = 15_000;

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

export interface PollProgress {
  /** Import jobs finished so far. */
  completed: number;
  total: number;
  elapsedMs: number;
}

export interface PollOptions {
  /** Fixed interval; omit to use the backoff described above. */
  intervalMs?: number;
  maxAttempts?: number;
  /**
   * Called periodically while jobs are still running, so a caller can show
   * that a slow import is alive rather than hung. Driven by its own timer,
   * not by poll timing, so the cadence stays predictable.
   */
  onProgress?: (progress: PollProgress) => void;
  /** Heartbeat cadence; exists so tests can assert it without waiting 15s. */
  progressIntervalMs?: number;
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
  const maxAttempts = options.maxAttempts ?? MAX_POLL_ATTEMPTS;
  const path = toPollingPath(locationUrl);
  let wait = options.intervalMs ?? FIRST_POLL_INTERVAL_MS;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const res = await snykRequest<PollImportResponse>(rm, 'get', path);

    const status = statusOf(res);
    if (status && status !== 200) {
      throw new Error(`Expected a 200 response, instead received: ${status}.`);
    }

    const job = res.data;
    if (job?.status && job.status !== 'complete') {
      await sleep(wait);
      // A caller-supplied interval is honoured as-is; otherwise back off.
      if (options.intervalMs === undefined) {
        wait = Math.min(wait * 2, MAX_POLL_INTERVAL_MS);
      }
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

  const jobs = [...new Set(locationUrls)];
  const startedAt = Date.now();
  let completed = 0;

  // Reporting runs on its own timer rather than per poll, so the cadence a
  // user sees does not change as the backoff grows. unref() keeps it from
  // holding the process open if everything else has finished.
  const ticker = options.onProgress
    ? setInterval(() => {
        options.onProgress?.({
          completed,
          total: jobs.length,
          elapsedMs: Date.now() - startedAt,
        });
      }, options.progressIntervalMs ?? PROGRESS_INTERVAL_MS)
    : undefined;
  ticker?.unref?.();

  try {
    await mapWithConcurrency(jobs, POLL_CONCURRENCY, async (locationUrl) => {
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
      } finally {
        completed++;
      }
    });
  } finally {
    if (ticker) clearInterval(ticker);
  }

  return { projects, failed, pollFailures };
}
