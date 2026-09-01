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
