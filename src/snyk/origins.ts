/**
 * Snyk's `origin` values for projects that came from a supported source.
 *
 * These are what a Snyk project reports about where it was imported from, and
 * they are how dedup finds the projects that correspond to a given `--source`.
 *
 * Was `SupportedIntegrationTypesToListSnykTargets` in snyk-api-import; the
 * values are unchanged, since they are Snyk's own strings.
 */
export enum SnykProjectOrigin {
  GITHUB = 'github',
  GITHUB_CLOUD_APP = 'github-cloud-app',
  GHE = 'github-enterprise',
  GITLAB = 'gitlab',
  AZURE_REPOS = 'azure-repos',
  BITBUCKET_SERVER = 'bitbucket-server',
  BITBUCKET_CLOUD = 'bitbucket-cloud',
  BITBUCKET_CLOUD_APP = 'bitbucket-cloud-app',
  /**
   * Bitbucket Cloud connected through Snyk's Connect App — the current way to
   * link Bitbucket Cloud, and a different integration key from the legacy
   * username/app-password `bitbucket-cloud`. Verified against a live org: both
   * the integration key and the project origin are this same string, and its
   * projects are named `owner/repo(branch):manifest` like the GitHub family.
   */
  BITBUCKET_CONNECT_APP = 'bitbucket-connect-app',
}
