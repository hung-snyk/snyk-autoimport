/**
 * Bitbucket Cloud repo discovery.
 *
 * Unlike the other providers this one has three auth methods across four env
 * vars, resolved here rather than by a single token lookup. It is also the one
 * provider whose credentials are deliberately not in the credential store —
 * see discover-bitbucket-cloud.ts.
 */
import { basicAuth, scmGet } from './http';
import type { BitbucketCloudRepoData } from './types';

const API_ROOT = 'https://api.bitbucket.org/2.0';

export type BitbucketCloudAuthConfig =
  | { type: 'user'; username: string; password: string }
  | { type: 'api'; token: string }
  | { type: 'oauth'; token: string };

interface BitbucketCloudApiRepo {
  slug?: string;
  name: string;
  workspace?: { slug?: string; uuid?: string };
  mainbranch?: { name?: string } | null;
}

interface BitbucketCloudPage {
  values: BitbucketCloudApiRepo[];
  next?: string;
}

function envValue(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

/**
 * Resolve one auth method from the environment.
 *
 * Precedence matches `snyk-api-import`: username/app-password first, because
 * some Bitbucket Cloud endpoints only accept Basic auth, then API token, then
 * OAuth. BITBUCKET_CLOUD_AUTH_METHOD forces a specific one.
 */
export function getBitbucketCloudAuth(): BitbucketCloudAuthConfig {
  const api = envValue('BITBUCKET_CLOUD_API_TOKEN');
  const oauth = envValue('BITBUCKET_CLOUD_OAUTH_TOKEN');
  const username = envValue('BITBUCKET_CLOUD_USERNAME');
  const password = envValue('BITBUCKET_CLOUD_PASSWORD');
  const user =
    username && password
      ? ({ type: 'user', username, password } as const)
      : undefined;

  const override = envValue('BITBUCKET_CLOUD_AUTH_METHOD')?.toLowerCase();
  if (override) {
    let requested: BitbucketCloudAuthConfig | undefined;
    switch (override) {
      case 'user':
        requested = user;
        break;
      case 'api':
        requested = api ? { type: 'api', token: api } : undefined;
        break;
      case 'oauth':
        requested = oauth ? { type: 'oauth', token: oauth } : undefined;
        break;
      default:
        throw new Error(
          `BITBUCKET_CLOUD_AUTH_METHOD is "${override}" — allowed values are: api, oauth, user.`,
        );
    }
    if (!requested) {
      throw new Error(
        `BITBUCKET_CLOUD_AUTH_METHOD is "${override}" but its credentials are not set.`,
      );
    }
    return requested;
  }

  if (user) return user;
  if (api) return { type: 'api', token: api };
  if (oauth) return { type: 'oauth', token: oauth };

  throw new Error(
    'No Bitbucket Cloud authentication found. Set BITBUCKET_CLOUD_USERNAME and ' +
      'BITBUCKET_CLOUD_PASSWORD, or BITBUCKET_CLOUD_API_TOKEN, or BITBUCKET_CLOUD_OAUTH_TOKEN.',
  );
}

function authHeader(config: BitbucketCloudAuthConfig): Record<string, string> {
  return config.type === 'user'
    ? { authorization: basicAuth(config.username, config.password) }
    : { authorization: `Bearer ${config.token}` };
}

export async function listBitbucketCloudRepos(
  config: BitbucketCloudAuthConfig,
  workspace: string,
): Promise<BitbucketCloudRepoData[]> {
  const repos: BitbucketCloudRepoData[] = [];
  const headers = authHeader(config);
  // Bitbucket returns an absolute `next` url, so paging is following links.
  let url: string | undefined = `${API_ROOT}/repositories/${encodeURIComponent(workspace)}`;

  while (url) {
    const { body }: { body: BitbucketCloudPage } = await scmGet<BitbucketCloudPage>(
      url,
      headers,
      `Bitbucket Cloud repos for "${workspace}"`,
    );

    for (const repo of body.values ?? []) {
      repos.push({
        name: repo.slug ?? repo.name,
        owner: repo.workspace?.slug ?? repo.workspace?.uuid ?? workspace,
        // Left undefined when Bitbucket reports no main branch, so Snyk picks
        // the repo's real default. snyk-api-import hardcoded "main" here,
        // which fails the import outright on a repo whose default is "master".
        branch: repo.mainbranch?.name,
      });
    }

    url = body.next;
  }

  return repos;
}
