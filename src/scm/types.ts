/**
 * What each provider's discovery returns.
 *
 * These are deliberately per-provider rather than one shared shape: the fields
 * differ because Snyk's import targets differ (Bitbucket Server has no branch,
 * GitLab needs a numeric id), and collapsing them would hide that.
 */

/** GitHub.com, GitHub Enterprise, and the GitHub Cloud App all use this. */
export interface GithubRepoData {
  name: string;
  owner: string;
  branch: string;
  fork: boolean;
}

export interface GitlabRepoData {
  /** Numeric project id — the only identifier GitLab's import accepts. */
  id: number;
  /** "group/repo" path, carried for dedup (Snyk never returns the id). */
  name: string;
  branch: string;
  fork: boolean;
}

export interface AzureRepoData {
  name: string;
  /** The Azure DevOps *project* name, which Snyk treats as the owner. */
  owner: string;
  branch: string;
}

export interface BitbucketServerRepoData {
  projectKey: string;
  repoSlug: string;
}

export interface BitbucketCloudRepoData {
  name: string;
  owner: string;
  /** Undefined when Bitbucket reports no main branch; Snyk then picks it. */
  branch?: string;
}
