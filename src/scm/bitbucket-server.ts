/**
 * Bitbucket Server (self-hosted) repo discovery.
 *
 * The target here is `{projectKey, repoSlug}` with no branch — Bitbucket
 * Server imports always use the repo's default branch.
 *
 * Note the query filters by project *name* while the target carries the
 * project *key*; they are different strings ("My Project" vs "MYPROJ"), which
 * is why the key is read back off each repo rather than assumed.
 *
 * The exact-match check below is case-insensitive, and a result where every
 * repo was filtered out is an error rather than an empty list. Both come from
 * the same bug found in GitLab and reproduced live (2026-09-18): the server
 * resolves the name loosely, the client-side filter then drops everything, and
 * the run reports "Found 0 repo(s)" and exits 0. This provider has no live
 * instance to test against, so the shape is fixed here by inspection.
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
  const dropped = new Set<string>();
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
      // from "Web Legacy". Only exact project matches belong to this import —
      // compared without case, since the name came from a human.
      if (repo.project?.name?.toLowerCase() !== projectName.trim().toLowerCase()) {
        if (repo.project?.name) dropped.add(repo.project.name);
        continue;
      }
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

    if (body.isLastPage || !body.nextPageStart) break;
    start = body.nextPageStart;
  }

  // Every repo belonged to a different project. An empty list here would read
  // as "that project has no repositories", which is a different problem.
  if (repos.length === 0 && dropped.size > 0) {
    const seen = [...dropped].sort().slice(0, 5).join(', ');
    throw new Error(
      `Bitbucket Server returned repositories for "${projectName}", but none are in ` +
        `a project of that name — they are in: ${seen}.\n` +
        'Check the name: the server matches it as a substring, so a partial or ' +
        'differently-spelled name finds other projects instead.',
    );
  }

  return repos;
}
