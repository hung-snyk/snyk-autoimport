/**
 * What each provider's discovery returns.
 *
 * These are deliberately per-provider rather than one shared shape: the fields
 * differ because Snyk's import targets differ (Bitbucket Server has no branch,
 * GitLab needs a numeric id), and collapsing them would hide that.
 *
 * `archived` and `fork` are reported, not acted on. Whether to import such a
 * repo is a policy question, and the answer lives in one place (discovery.ts)
 * rather than being re-decided per provider, where it drifted: three providers
 * dropped archived repos silently and two did not.
 */

/** GitHub.com, GitHub Enterprise, and the GitHub Cloud App all use this. */
export interface GithubRepoData {
  name: string;
  owner: string;
  branch: string;
  fork: boolean;
  archived: boolean;
}

export interface GitlabRepoData {
  /** Numeric project id — the only identifier GitLab's import accepts. */
  id: number;
  /** "group/repo" path, carried for dedup (Snyk never returns the id). */
  name: string;
  branch: string;
  fork: boolean;
  archived: boolean;
}

export interface AzureRepoData {
  name: string;
  /** The Azure DevOps *project* name, which Snyk treats as the owner. */
  owner: string;
  branch: string;
  /** Azure has no archive state; a disabled repo is its equivalent, and cannot be read. */
  archived: boolean;
}

export interface BitbucketServerRepoData {
  projectKey: string;
  repoSlug: string;
  /** Bitbucket Data Center 8.0+ can archive a repo; older servers omit the field. */
  archived: boolean;
}

export interface BitbucketCloudRepoData {
  name: string;
  owner: string;
  /** Undefined when Bitbucket reports no main branch; Snyk then picks it. */
  branch?: string;
  /** Bitbucket Cloud has no archive concept; typed so it can never be reported as one. */
  archived?: false;
}
