/**
 * Azure Repos discovery. `listAzureRepos` enumerates every Azure DevOps
 * project within the org and flattens their repos into one list. Target shape
 * is `{owner, name, branch}` — identical to the GitHub family, and matches
 * Snyk's own `projectToTarget` dedup generator for the azure-repos origin.
 *
 * The branch is always the repo's default branch, read from Azure's
 * `defaultBranch`; there is no per-repo override, so nothing here chooses a
 * branch. Repos with no default branch (empty repos) are dropped by
 * `listAzureRepos`; disabled repos — Azure's equivalent of archived — are set
 * aside by `toDiscovery` and reported.
 */
import { listAzureRepos } from './api';
import { toDiscovery, type Discovery } from './discovery';

export interface DiscoverAzureOptions {
  orgName: string;
  orgId: string;
  integrationId: string;
  /** Optional self-hosted Azure DevOps Server host. Defaults safely to dev.azure.com. */
  host?: string;
}

const REFS_HEADS = 'refs/heads/';

/**
 * Azure DevOps reports a repo's default branch as a fully-qualified ref
 * ("refs/heads/main"), unlike every other source we support, which return the
 * short name. Snyk stores and matches on the short name, so the prefix has to
 * go: left in place it is submitted as the branch at import time, and it also
 * breaks dedup, since `branch` is part of the target identity that
 * `filterAlreadyImported` compares against live Snyk state — "refs/heads/main"
 * never matches Snyk's "main", so every repo looks new on every run.
 *
 * Trimmed by prefix length rather than by splitting on "/", so a branch that
 * legitimately contains slashes ("refs/heads/feature/login" -> "feature/login")
 * survives intact.
 */
export function shortBranchName(ref: string | undefined): string | undefined {
  if (!ref) return undefined;
  const short = ref.startsWith(REFS_HEADS) ? ref.slice(REFS_HEADS.length) : ref;
  return short || undefined;
}

export async function discoverAzureTargets(
  opts: DiscoverAzureOptions,
): Promise<Discovery> {
  const repos = await listAzureRepos(opts.orgName, opts.host);
  return toDiscovery(repos, (repo) => ({
    orgId: opts.orgId,
    integrationId: opts.integrationId,
    target: {
      owner: repo.owner,
      name: repo.name,
      branch: shortBranchName(repo.branch),
    },
  }));
}
