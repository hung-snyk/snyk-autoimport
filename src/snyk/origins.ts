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
}
