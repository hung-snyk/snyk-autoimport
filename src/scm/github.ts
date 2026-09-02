/**
 * GitHub repo discovery — covers github, github-enterprise and
 * github-cloud-app, which all read the same GitHub REST API with a PAT.
 *
 * Organization repos only. GitHub's /orgs/{org}/repos 404s for a personal
 * account, and there is no equivalent listing that would let a personal
 * account work here; discover.ts turns that 404 into an explanation.
 */
import { requireEnv, scmGet } from './http';
import type { GithubRepoData } from './types';

const PER_PAGE = 100;

interface GithubApiRepo {
  name: string;
  owner: { login: string } | null;
  default_branch: string;
  archived: boolean;
  fork: boolean;
}

/**
 * GitHub Enterprise Server serves its API under /api/v3.
 *
 * Appended to the host rather than resolved through `new URL('/api/v3', host)`.
 * That form takes `/api/v3` as root-relative and drops any path the host
 * carries, so a server behind a context path (`https://ghe.example.com/github`)
 * was silently queried at `https://ghe.example.com/api/v3` — the wrong host,
 * with no error, which is the outcome REQUIRES_SOURCE_URL exists to prevent.
 * `gitlabBaseUrl`, `azureBaseUrl` and Bitbucket Server all append, so this was
 * also the one helper that behaved differently.
 *
 * Hosts reaching here are validated and normalised by `source-url.ts`, at both
 * the `auth login` prompt and `--source-url`; the trailing-slash strip is kept
 * as defence in depth for a value stored before that existed.
 */
export function githubBaseUrl(host?: string): string {
  if (!host) return 'https://api.github.com';
  return `${host.replace(/\/+$/, '')}/api/v3`;
}

export async function listGithubRepos(
  orgName: string,
  host?: string,
): Promise<GithubRepoData[]> {
  const token = requireEnv('GITHUB_TOKEN', 'GitHub');
  const baseUrl = githubBaseUrl(host);
  const repos: GithubRepoData[] = [];

  for (let page = 1; ; page++) {
    const url = `${baseUrl}/orgs/${encodeURIComponent(orgName)}/repos?per_page=${PER_PAGE}&page=${page}`;
    const { body } = await scmGet<GithubApiRepo[]>(
      url,
      {
        authorization: `token ${token}`,
        'x-github-api-version': '2022-11-28',
      },
      `GitHub repos for "${orgName}"`,
    );

    for (const repo of body) {
      // No default branch means an empty repo — nothing to scan.
      if (!repo.owner?.login || !repo.default_branch) continue;
      repos.push({
        name: repo.name,
        owner: repo.owner.login,
        branch: repo.default_branch,
        fork: repo.fork,
        archived: repo.archived,
      });
    }

    if (body.length < PER_PAGE) return repos;
  }
}
