/**
 * The tool's own API surface: everything it does against Snyk and the SCMs.
 *
 * This file used to re-export borrowed pieces of `snyk-api-import` and exists
 * to keep that surface reviewable in one place. Nothing is borrowed any more —
 * ./snyk talks to Snyk's documented APIs and ./scm to each provider's public
 * REST API — so it is now just the tool's internal barrel.
 */

// --- Snyk: import, poll, integrations ---------------------------------------
export { importTarget, importTargets } from './snyk/import';
export type { ImportKickoffFailure, ImportKickoffResult } from './snyk/import';
export { pollImportUrl, pollImportUrls } from './snyk/poll';
export type {
  FailedProject,
  PollFailure,
  PollProgress,
  PollResult,
} from './snyk/poll';
export { describeError, formatError, snykRequest, statusOf } from './snyk/http';
export { listIntegrations } from './snyk/integrations';
export type { IntegrationsMap } from './snyk/integrations';
export type { Target, ImportTarget, FilePath, Project } from './snyk/types';

// --- Snyk: what is already imported, for dedup ------------------------------
export { generateTargetId } from './snyk/target-id';
export {
  listImportedTargets,
  listSnykProjects,
  projectToTarget,
} from './snyk/imported-targets';
export type { SnykProject } from './snyk/imported-targets';
export { SnykProjectOrigin } from './snyk/origins';

// --- Snyk: authentication ---------------------------------------------------
export {
  describeSnykAuth,
  resetSnykOauthCache,
  resolveSnykAuth,
  snykAuthHeaders,
  snykOauthTokenUrl,
} from './snyk/oauth';
export type { SnykAuth, SnykAuthMode } from './snyk/oauth';

// --- SCM: repo discovery ----------------------------------------------------
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
