/**
 * Single import surface for everything we borrow from `snyk-api-import`.
 *
 * IMPORTANT: we import from deep paths, never the package root.
 * `snyk-api-import`'s entry (`dist/index.js`) runs `yargs(...).parse()` at
 * module top level, so `require`-ing it self-executes the CLI. The `dist/lib`
 * barrel and the individual script files below have no such side effect.
 */

// The library barrel — side-effect free.
export {
  importTargets,
  pollImportUrls,
  listGithubRepos,
  listGitlabRepos,
  listAzureRepos,
  listBitbucketServerRepos,
  listIntegrations,
} from 'snyk-api-import/dist/lib';

// Bitbucket Cloud isn't re-exported from the lib barrel (its list-repos takes
// an explicit auth config rather than reading an env var itself, unlike the
// others) — reachable only via its own files.
export { listRepos as listBitbucketCloudRepos } from 'snyk-api-import/dist/lib/source-handlers/bitbucket-cloud/list-repos';
export { getBitbucketCloudAuth } from 'snyk-api-import/dist/lib/source-handlers/bitbucket-cloud/get-bitbucket-cloud-auth';
export type { BitbucketCloudAuthConfig } from 'snyk-api-import/dist/lib/source-handlers/bitbucket-cloud/types';

// Not re-exported from the lib barrel; only reachable via their own files.
export { generateTargetId } from 'snyk-api-import/dist/generate-target-id';
export { generateSnykImportedTargets } from 'snyk-api-import/dist/scripts/generate-imported-targets-from-snyk';

export type {
  Target,
  ImportTarget,
  FilePath,
} from 'snyk-api-import/dist/lib/types';

export { SupportedIntegrationTypesToListSnykTargets } from 'snyk-api-import/dist/lib/types';
