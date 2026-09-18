/**
 * Poll import jobs to completion: GET on each job's polling URL.
 *
 * An import job is asynchronous — Snyk clones the repo, detects manifests and
 * creates a project per manifest. The job reports `pending` until all of that
 * finishes, so each URL is re-checked on an interval until it reads `complete`.
 *
 * A target that produces no projects (a repo with no supported manifests)
 * completes normally with an empty project list. That is a success, not an
 * error — so results are reported per job as well as per project, letting the
 * summary count repositories and still call out the ones that yielded nothing.
 */
import type { SnykClient } from './client';
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
/**
 * Give up on a single job after this long.
 *
 * The attempt count alone was not a usable ceiling: 1,000 attempts at the 20s
 * cap is about five and a half hours, so a job Snyk never finishes held the
 * command open until whatever timeout wrapped it — a CI job's, or none. Two
 * hours is well beyond any import observed (minutes), and expressed in
 * wall-clock time because that is the thing a caller is actually budgeting.
 *
 * Reaching it is reported as a poll failure, not a success: the job may still
 * be running server-side, and its projects may yet appear.
 */
const MAX_POLL_DURATION_MS = 2 * 60 * 60 * 1_000;
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

/** What one import job produced. One job is one submitted repository. */
export interface JobResult {
  locationUrl: string;
  created: number;
  failed: number;
}

export interface PollResult {
  /** Projects Snyk successfully created. */
  projects: Project[];
  /** Projects the job attempted but could not create. */
  failed: FailedProject[];
  /** Jobs whose status could never be read (the import may still be running). */
  pollFailures: PollFailure[];
  /**
   * One entry per job that completed, so results can be counted per repository
   * as well as per project. Without this the summary can only report projects,
   * which is a different unit from the repositories the user asked to import.
   */
  perJob: JobResult[];
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
  /** Wall-clock ceiling for one job. Tests use a tiny value. */
  maxDurationMs?: number;
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
  client: SnykClient,
  locationUrl: string,
  options: PollOptions = {},
): Promise<Project[]> {
  if (!locationUrl) {
    throw new Error('Missing required parameter: location url.');
  }
  const maxAttempts = options.maxAttempts ?? MAX_POLL_ATTEMPTS;
  const maxDuration = options.maxDurationMs ?? MAX_POLL_DURATION_MS;
  const path = toPollingPath(locationUrl);
  const startedAt = Date.now();
  let wait = options.intervalMs ?? FIRST_POLL_INTERVAL_MS;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const elapsed = Date.now() - startedAt;
    if (elapsed >= maxDuration) {
      throw new Error(
        `Import job did not complete within ${Math.round(elapsed / 60_000)} minute(s). ` +
          'It may still be running — re-run to pick up whatever it created.',
      );
    }

    const res = await snykRequest<PollImportResponse>(client, 'get', path);

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
  client: SnykClient,
  locationUrls: readonly string[],
  options: PollOptions = {},
): Promise<PollResult> {
  const projects: Project[] = [];
  const failed: FailedProject[] = [];
  const pollFailures: PollFailure[] = [];
  const perJob: JobResult[] = [];

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
        let jobCreated = 0;
        let jobFailed = 0;
        for (const project of await pollImportUrl(client, locationUrl, options)) {
          if (project.success) {
            projects.push(project);
            jobCreated++;
          } else {
            failed.push({ ...project, locationUrl });
            jobFailed++;
          }
        }
        perJob.push({ locationUrl, created: jobCreated, failed: jobFailed });
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

  return { projects, failed, pollFailures, perJob };
}
