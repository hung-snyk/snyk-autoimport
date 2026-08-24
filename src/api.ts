/**
 * Single import surface for everything still borrowed from `snyk-api-import`.
 *
 * That package is in maintenance mode and slated for replacement, so this file
 * exists to keep the borrowed surface in one reviewable place. It is shrinking:
 * the Snyk Import API calls (import, poll, integrations) are now ours, in
 * ./snyk. What remains is SCM repo discovery and the dedup helper.
 *
 * IMPORTANT: import from deep paths, never the package root.
 * `snyk-api-import`'s entry (`dist/index.js`) runs `yargs(...).parse()` at
 * module top level, so `require`-ing it self-executes the CLI. The `dist/lib`
 * barrel and the individual script files below have no such side effect.
 */

// ---------------------------------------------------------------------------
// Ours — talks to Snyk's documented v1 Import API directly.
// ---------------------------------------------------------------------------
export { importTarget, importTargets } from './snyk/import';
export type { ImportKickoffFailure, ImportKickoffResult } from './snyk/import';
export { pollImportUrl, pollImportUrls } from './snyk/poll';
export type { FailedProject, PollFailure, PollResult } from './snyk/poll';
export { listIntegrations } from './snyk/integrations';
export type { IntegrationsMap } from './snyk/integrations';
export { generateTargetId } from './snyk/target-id';
export type { Target, ImportTarget, FilePath, Project } from './snyk/types';

// ---------------------------------------------------------------------------
// Still borrowed — SCM repo discovery.
// ---------------------------------------------------------------------------
export {
  listGithubRepos,
  listGitlabRepos,
  listAzureRepos,
  listBitbucketServerRepos,
} from 'snyk-api-import/dist/lib';

// Bitbucket Cloud isn't re-exported from the lib barrel (its list-repos takes
// an explicit auth config rather than reading an env var itself, unlike the
// others) — reachable only via its own files.
export { listRepos as listBitbucketCloudRepos } from 'snyk-api-import/dist/lib/source-handlers/bitbucket-cloud/list-repos';
export { getBitbucketCloudAuth } from 'snyk-api-import/dist/lib/source-handlers/bitbucket-cloud/get-bitbucket-cloud-auth';
export type { BitbucketCloudAuthConfig } from 'snyk-api-import/dist/lib/source-handlers/bitbucket-cloud/types';

// ---------------------------------------------------------------------------
// Still borrowed — dedup against existing Snyk state.
// ---------------------------------------------------------------------------
export { generateSnykImportedTargets } from 'snyk-api-import/dist/scripts/generate-imported-targets-from-snyk';
export { SupportedIntegrationTypesToListSnykTargets } from 'snyk-api-import/dist/lib/types';
