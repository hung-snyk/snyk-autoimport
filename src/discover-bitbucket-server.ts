/**
 * Bitbucket Server (self-hosted) discovery. Unlike every other source, its
 * target shape has no `branch` field at all — Bitbucket Server targets are
 * just `{projectKey, repoSlug}`, matching Snyk's
 * `bitbucketServerProjectToTarget` dedup generator exactly. Import defaults to
 * each repo's default branch.
 *
 * Host is mandatory here — there is no public default host for a self-hosted
 * product, and discovery throws if it's missing (`sources.ts`'s
 * REQUIRES_SOURCE_URL also enforces this upfront, before any token check).
 */
import { listBitbucketServerRepos, type ImportTarget } from './api';

export interface DiscoverBitbucketServerOptions {
  projectName: string;
  orgId: string;
  integrationId: string;
  host: string;
}

export async function discoverBitbucketServerTargets(
  opts: DiscoverBitbucketServerOptions,
): Promise<ImportTarget[]> {
  const repos = await listBitbucketServerRepos(opts.projectName, opts.host);
  return repos.map((repo) => ({
    orgId: opts.orgId,
    integrationId: opts.integrationId,
    target: {
      projectKey: repo.projectKey,
      repoSlug: repo.repoSlug,
    },
  }));
}
