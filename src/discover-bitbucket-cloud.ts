/**
 * Bitbucket Cloud discovery via snyk-api-import's `listRepos`, which — unlike
 * every other source — takes an explicit auth config object rather than
 * reading a single env var itself. `getBitbucketCloudAuth()` resolves one of
 * three methods from env vars (precedence: username/app-password -> API
 * token -> OAuth token) and throws a clear error if none are set.
 *
 * Its return type (`BitbucketCloudAuthMethod`, `{username, appPassword,
 * password?}`) doesn't exactly match what `listRepos` expects
 * (`BitbucketCloudAuthConfig`, `{username, password}`) for the username case
 * — verified the library actually populates both fields with the same value
 * already, but map explicitly rather than rely on that implementation detail.
 *
 * Deliberately NOT wired into `auth login` / the credential store: three
 * auth methods across four env vars is real complexity that would clutter
 * the login prompt for a source not yet verified against a live account.
 * Supported via env vars only for now — see README.
 */
import {
  listBitbucketCloudRepos,
  getBitbucketCloudAuth,
  type ImportTarget,
  type BitbucketCloudAuthConfig,
} from './api';

export interface DiscoverBitbucketCloudOptions {
  workspace: string;
  orgId: string;
  integrationId: string;
}

function toAuthConfig(): BitbucketCloudAuthConfig {
  const method = getBitbucketCloudAuth();
  if (method.type === 'user') {
    return {
      type: 'user',
      username: method.username,
      password: method.password ?? method.appPassword,
    };
  }
  return method;
}

export async function discoverBitbucketCloudTargets(
  opts: DiscoverBitbucketCloudOptions,
): Promise<ImportTarget[]> {
  const config = toAuthConfig();
  const repos = await listBitbucketCloudRepos(config, opts.workspace);
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
