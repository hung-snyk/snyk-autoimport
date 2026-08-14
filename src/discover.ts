/**
 * SCM repo discovery. GitHub only for now — reuses `snyk-api-import`'s
 * `listGithubRepos`, which walks the GitHub API (auth via GITHUB_TOKEN) and
 * returns every non-archived repo in an org.
 *
 * Deliberately org-only: `listGithubRepos` calls GitHub's *organization*
 * repos endpoint, which 404s for a personal account (github.com/<user> is
 * not an org). This is a real, cross-cutting limitation of all three
 * GitHub-family sources (github, github-cloud-app, github-enterprise), not
 * something specific to one integration type — see README. We surface it
 * as a clear, actionable error rather than let GitHub's raw 404 through.
 */
import { listGithubRepos, type ImportTarget } from './api';

export interface DiscoverOptions {
  /** GitHub organization login. Personal accounts are not supported. */
  githubOrg: string;
  orgId: string;
  integrationId: string;
  /** Optional GitHub Enterprise host, e.g. https://ghe.example.com. */
  host?: string;
}

/** Discover repos and shape them into import targets ready for the API. */
export async function discoverGithubTargets(
  opts: DiscoverOptions,
): Promise<ImportTarget[]> {
  let repos;
  try {
    repos = await listGithubRepos(opts.githubOrg, opts.host);
  } catch (err) {
    const status = (err as { status?: number }).status;
    if (status === 404) {
      throw new Error(
        `GitHub org "${opts.githubOrg}" not found (404). This tool only discovers ` +
          `repos in a GitHub *organization* — personal accounts (github.com/${opts.githubOrg}) ` +
          `are not supported, since GitHub's org-repos API 404s for them. ` +
          `If "${opts.githubOrg}" is your personal account, this source can't import from it.`,
      );
    }
    throw err;
  }
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
