/**
 * Bitbucket Cloud discovery.
 *
 * Unlike every other source this one has three auth methods across four env
 * vars, resolved by `getBitbucketCloudAuth()` (precedence: username/app
 * password -> API token -> OAuth token), which throws a clear error if none
 * are set.
 *
 * Deliberately NOT wired into `auth login` / the credential store: three auth
 * methods is real complexity that would clutter the login prompt for a source
 * not yet verified against a live account. Env vars only for now — see README.
 */
import {
  listBitbucketCloudRepos,
  getBitbucketCloudAuth,
  type ImportTarget,
} from './api';

export interface DiscoverBitbucketCloudOptions {
  workspace: string;
  orgId: string;
  integrationId: string;
}

export async function discoverBitbucketCloudTargets(
  opts: DiscoverBitbucketCloudOptions,
): Promise<ImportTarget[]> {
  const repos = await listBitbucketCloudRepos(getBitbucketCloudAuth(), opts.workspace);
  return repos.map((repo) => ({
    orgId: opts.orgId,
    integrationId: opts.integrationId,
    target: {
      owner: repo.owner,
      name: repo.name,
      // May be undefined when Bitbucket reports no main branch; Snyk then
      // imports the repo's actual default branch.
      branch: repo.branch,
    },
  }));
}
