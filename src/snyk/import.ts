/**
 * Kick off imports: POST /org/{orgId}/integrations/{integrationId}/import
 *
 * Snyk answers 201 with a `Location` header pointing at an import job; the
 * actual projects only exist once that job is polled to completion (see
 * poll.ts). One target can yield many projects, or none.
 *
 * Difference from `snyk-api-import`, which this replaces: failures are
 * returned to the caller as data. The original wrote each failure to a bunyan
 * log under SNYK_LOG_PATH and returned only the successful polling URLs, so
 * the reason for a failure had to be recovered by re-reading and parsing that
 * file. It also called `process.exit(1)` when a run of targets all failed,
 * which is not a decision a library should make for its caller.
 */
import type { requestsManager } from 'snyk-request-manager';
import { mapWithConcurrency } from './async';
import { describeError, formatError, headerOf, snykRequest, statusOf } from './http';
import type { ImportTarget, Target } from './types';

/** Matches `snyk-api-import`'s default and env var, so tuning carries over. */
const DEFAULT_CONCURRENT_IMPORTS = 15;

export function concurrentImports(): number {
  const raw = process.env.CONCURRENT_IMPORTS;
  const parsed = raw ? Number.parseInt(raw, 10) : NaN;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_CONCURRENT_IMPORTS;
}

export interface ImportKickoffFailure {
  target: Target;
  orgId: string;
  integrationId: string;
  status?: number;
  errorMessage: string;
  requestId?: string;
}

export interface ImportKickoffResult {
  /** Polling URLs for targets Snyk accepted, deduplicated. */
  pollingUrls: string[];
  failures: ImportKickoffFailure[];
}

/**
 * A GitLab target is `{id, branch}` and nothing else — sending the extra keys
 * the other SCMs use makes the API reject it. GitLab is the only source whose
 * target carries a numeric `id`, so that is how it is detected.
 */
function requestTarget(target: Target): Target {
  if (typeof target.id === 'number') {
    return { id: target.id, ...(target.branch ? { branch: target.branch } : {}) };
  }
  const { id: _ignored, ...rest } = target;
  return rest;
}

/**
 * Turn the `Location` header into a path the request manager can re-request.
 *
 * It returns an absolute URL (`https://api.snyk.io/api/v1/org/...`) while the
 * manager prepends its own configured base (`.../v1`), so the version prefix
 * has to come off. Failing loudly here beats silently polling a wrong path.
 */
export function toPollingPath(locationUrl: string): string {
  const pathname = (() => {
    try {
      return new URL(locationUrl).pathname;
    } catch {
      return locationUrl;
    }
  })();

  const stripped = pathname.replace(/^\/(?:api\/)?v1\//, '');
  if (stripped === pathname && pathname.startsWith('/')) {
    throw new Error(
      `Could not derive a polling path from import location "${locationUrl}".`,
    );
  }
  return stripped;
}

export async function importTarget(
  rm: requestsManager,
  { orgId, integrationId, target, files, exclusionGlobs }: ImportTarget,
): Promise<string> {
  if (!orgId || !integrationId || Object.keys(target).length === 0) {
    throw new Error(
      'Missing required parameters. Please ensure you have set: orgId, integrationId, target.',
    );
  }

  const res = await snykRequest<{ location?: string; pollingUrl?: string }>(
    rm,
    'post',
    `/org/${orgId.trim()}/integrations/${integrationId}/import`,
    { target: requestTarget(target), files, exclusionGlobs },
  );

  const status = statusOf(res);
  if (status !== 201) {
    throw new Error(`Expected a 201 response, instead received: ${status}.`);
  }

  // Snyk returns this in the header; the body fallbacks keep the contract
  // honest if a client surfaces it differently.
  const location =
    headerOf(res, 'location') ?? res.data?.location ?? res.data?.pollingUrl;
  if (!location) {
    throw new Error('No import location url returned. Please re-try the import.');
  }
  return location;
}

/**
 * Submit every target, pacing requests so a large batch does not stampede the
 * SCM behind Snyk. Individual failures are collected, never thrown — one
 * unreachable repo should not abandon the rest of the batch.
 */
export async function importTargets(
  rm: requestsManager,
  targets: readonly ImportTarget[],
): Promise<ImportKickoffResult> {
  const pollingUrls: string[] = [];
  const failures: ImportKickoffFailure[] = [];

  await mapWithConcurrency(targets, concurrentImports(), async (t) => {
    try {
      pollingUrls.push(await importTarget(rm, t));
    } catch (error) {
      const detail = describeError(error);
      failures.push({
        target: t.target,
        orgId: t.orgId,
        integrationId: t.integrationId,
        status: detail.status,
        errorMessage: formatError(detail),
        requestId: detail.requestId,
      });
    }
  });

  return { pollingUrls: [...new Set(pollingUrls)], failures };
}
