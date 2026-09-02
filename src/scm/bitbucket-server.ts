/**
 * Bitbucket Server (self-hosted) repo discovery.
 *
 * The target here is `{projectKey, repoSlug}` with no branch — Bitbucket
 * Server imports always use the repo's default branch.
 *
 * Note the query filters by project *name* while the target carries the
 * project *key*; they are different strings ("My Project" vs "MYPROJ"), which
 * is why the key is read back off each repo rather than assumed.
 */
import { basicAuth, requireEnv, scmGet } from './http';
import type { BitbucketServerRepoData } from './types';

const PAGE_LIMIT = 100;

interface BitbucketServerApiRepo {
  name: string;
  slug?: string;
  project: { key: string; name?: string };
  /**
   * Present on Bitbucket Data Center 8.0+, absent before archiving existed.
   * Read from the documented field shape; not yet seen from a live server.
   */
  archived?: boolean;
}

interface BitbucketServerPage {
  values: BitbucketServerApiRepo[];
  isLastPage: boolean;
  nextPageStart?: number;
}

/**
 * Bitbucket Server accepts either an HTTP access token as Bearer, or a
 * username and password over Basic. Basic wins when a username is present,
 * since setting one is an explicit choice; the token path stays the default so
 * existing setups keep working.
 */
export function bitbucketServerAuthHeader(): Record<string, string> {
  const username = process.env.BITBUCKET_SERVER_USERNAME?.trim();
  if (username) {
    const password = requireEnv('BITBUCKET_SERVER_PASSWORD', 'Bitbucket Server');
    return { authorization: basicAuth(username, password) };
  }
  const token = requireEnv('BITBUCKET_SERVER_TOKEN', 'Bitbucket Server');
  return { authorization: `Bearer ${token}` };
}

export async function listBitbucketServerRepos(
  projectName: string,
  host: string,
): Promise<BitbucketServerRepoData[]> {
  if (!host) {
    throw new Error(
      'Bitbucket Server needs --source-url — there is no default host for a self-hosted server.',
    );
  }
  const headers = bitbucketServerAuthHeader();
  const baseUrl = host.replace(/\/$/, '');
  const repos: BitbucketServerRepoData[] = [];
  let start = 0;

  for (;;) {
    const query = new URLSearchParams({
      projectname: projectName,
      state: 'AVAILABLE',
      start: String(start),
      limit: String(PAGE_LIMIT),
    });

    const { body } = await scmGet<BitbucketServerPage>(
      `${baseUrl}/rest/api/1.0/repos?${query}`,
      headers,
      `Bitbucket Server repos for "${projectName}"`,
    );

    for (const repo of body.values ?? []) {
      // `projectname` is a substring filter, so "Web" would also return repos
      // from "Web Legacy". Only exact project matches belong to this import.
      if (repo.project?.name !== projectName) continue;
      // Prefer `slug` over `name`: Bitbucket's slug is the url-safe identifier
      // ("my-repo"), while name is the display form ("My Repo"). NOTE this
      // differs from snyk-api-import, which sent `name` as the repoSlug —
      // verify against a live Bitbucket Server before relying on it.
      repos.push({
        projectKey: repo.project.key,
        repoSlug: repo.slug ?? repo.name,
        archived: repo.archived ?? false,
      });
    }

    if (body.isLastPage || !body.nextPageStart) return repos;
    start = body.nextPageStart;
  }
}
