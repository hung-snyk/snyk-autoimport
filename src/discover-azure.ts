/**
 * Azure Repos discovery via snyk-api-import's `listAzureRepos`, which
 * internally enumerates every Azure DevOps project within the org and
 * flattens their repos into one list. Target shape is `{owner, name,
 * branch}` — identical to the GitHub family, and matches Snyk's own
 * `projectToTarget` dedup generator for the azure-repos origin.
 */
import { listAzureRepos, type ImportTarget } from './api';

export interface DiscoverAzureOptions {
  orgName: string;
  orgId: string;
  integrationId: string;
  /** Optional self-hosted Azure DevOps Server host. Defaults safely to dev.azure.com. */
  host?: string;
}

export async function discoverAzureTargets(
  opts: DiscoverAzureOptions,
): Promise<ImportTarget[]> {
  const repos = await listAzureRepos(opts.orgName, opts.host);
  return repos.map((repo) => ({
    orgId: opts.orgId,
    integrationId: opts.integrationId,
    target: {
      owner: repo.owner,
      name: repo.name,
      branch: repo.branch,
    },
  }));
}
