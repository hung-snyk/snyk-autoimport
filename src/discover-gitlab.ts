/**
 * GitLab repo discovery via snyk-api-import's `listGitlabRepos`.
 *
 * The `name` field matters beyond display: `listGitlabRepos` returns
 * `path_with_namespace` (e.g. "group/repo") as `name`, which is exactly the
 * format Snyk's own dedup (`gitlabProjectToImportLogTarget`) derives from
 * existing project names. GitLab import targets are `{id, branch}` on the
 * wire (numeric project id — `snyk-api-import` detects a GitLab target by
 * the presence of both `id` and `branch` keys), but dedup never uses `id`
 * (Snyk's project API never returns it) — so `name` must be carried too,
 * even though the wire call itself drops it.
 */
import { listGitlabRepos, type ImportTarget } from './api';

export interface DiscoverGitlabOptions {
  /** GitLab group name (not a personal namespace — unverified whether that distinction matters here, unlike the confirmed GitHub org-only limitation). */
  groupName: string;
  orgId: string;
  integrationId: string;
  /** Optional self-hosted GitLab host. Defaults safely to gitlab.com. */
  host?: string;
}

export async function discoverGitlabTargets(
  opts: DiscoverGitlabOptions,
): Promise<ImportTarget[]> {
  const repos = await listGitlabRepos(opts.groupName, opts.host);
  return repos.map((repo) => ({
    orgId: opts.orgId,
    integrationId: opts.integrationId,
    target: {
      id: repo.id,
      name: repo.name,
      branch: repo.branch,
    },
  }));
}
