/**
 * Bitbucket Cloud discovery, shared by `bitbucket-cloud` and
 * `bitbucket-connect-app` — how Snyk connects to Bitbucket does not change
 * how Bitbucket lists repositories.
 *
 * Auth is resolved by `getBitbucketCloudAuth()` from env vars, with precedence
 * username/app-password -> API token -> OAuth token, overridable via
 * `BITBUCKET_CLOUD_AUTH_METHOD`. It throws a clear error if none are set.
 *
 * The Basic-auth pair (email or username + API token or app password) is the
 * form `auth login` stores and `env.ts` publishes as
 * `BITBUCKET_CLOUD_USERNAME` / `BITBUCKET_CLOUD_PASSWORD`. The Bearer methods
 * are env-var only — see the Credentials type in config.ts for why.
 */
import { listBitbucketCloudRepos, getBitbucketCloudAuth } from './api';
import { toDiscovery, type Discovery } from './discovery';

export interface DiscoverBitbucketCloudOptions {
  workspace: string;
  orgId: string;
  integrationId: string;
}

export async function discoverBitbucketCloudTargets(
  opts: DiscoverBitbucketCloudOptions,
): Promise<Discovery> {
  const repos = await listBitbucketCloudRepos(getBitbucketCloudAuth(), opts.workspace);
  // Bitbucket Cloud cannot archive a repo, so the archived count here is
  // always zero — the shared helper is used for the uniform return shape.
  return toDiscovery(repos, (repo) => ({
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
