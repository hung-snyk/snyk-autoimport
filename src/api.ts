/**
 * Single import surface for everything still borrowed from `snyk-api-import`.
 *
 * That package is in maintenance mode and slated for replacement, so this file
 * keeps the borrowed surface in one reviewable place. It is nearly empty now:
 * the Snyk Import API calls live in ./snyk and SCM repo discovery in ./scm.
 * What remains is the dedup helper, which reads existing Snyk projects and
 * reconstructs targets from their names.
 *
 * IMPORTANT: import from deep paths, never the package root.
 * `snyk-api-import`'s entry (`dist/index.js`) runs `yargs(...).parse()` at
 * module top level, so `require`-ing it self-executes the CLI.
 */

// ---------------------------------------------------------------------------
// Ours — Snyk's documented v1 Import API.
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
// Ours — SCM repo discovery, over the providers' public REST APIs.
// ---------------------------------------------------------------------------
export { listGithubRepos } from './scm/github';
export { listGitlabRepos } from './scm/gitlab';
export { listAzureRepos } from './scm/azure';
export { listBitbucketServerRepos } from './scm/bitbucket-server';
export {
  listBitbucketCloudRepos,
  getBitbucketCloudAuth,
} from './scm/bitbucket-cloud';
export type { BitbucketCloudAuthConfig } from './scm/bitbucket-cloud';
export { ScmError } from './scm/http';

// ---------------------------------------------------------------------------
// Still borrowed — dedup against existing Snyk state.
// ---------------------------------------------------------------------------
export { generateSnykImportedTargets } from 'snyk-api-import/dist/scripts/generate-imported-targets-from-snyk';
export { SupportedIntegrationTypesToListSnykTargets } from 'snyk-api-import/dist/lib/types';
