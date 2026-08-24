/**
 * Types for Snyk's v1 Import API.
 *
 * Declared here rather than borrowed from `snyk-api-import` so this tool owns
 * its contract directly with the documented API:
 * https://docs.snyk.io/developer-tools/snyk-api/reference/import-projects-v1
 *
 * Only the SCM sources this tool supports are modelled. `snyk-api-import`'s
 * Target also carries Heroku/Lambda/CloudFoundry fields (appId, functionId,
 * slugId); those are deliberately omitted — nothing here can produce them.
 */

/**
 * Identifies *what* to import. The shape varies by SCM:
 *   GitHub / GHE / Azure Repos / Bitbucket Cloud -> owner + name + branch
 *   Bitbucket Server                             -> projectKey + repoSlug
 *   GitLab                                       -> id + branch
 */
export interface Target {
  name?: string;
  owner?: string;
  /** Omit to let Snyk pick the repo's default branch. */
  branch?: string;
  projectKey?: string;
  repoSlug?: string;
  /** GitLab only, and numeric — a path string is not accepted by the API. */
  id?: number;
}

export interface FilePath {
  path: string;
}

export interface ImportTarget {
  orgId: string;
  integrationId: string;
  target: Target;
  /** Import only these paths, relative to the repo root, instead of scanning. */
  files?: FilePath[];
  /** Comma-separated folder names to skip (max 10). Empty string = skip none. */
  exclusionGlobs?: string;
}

/** One project Snyk created — or failed to create — from a target. */
export interface Project {
  targetFile?: string;
  success: boolean;
  projectUrl: string;
}

export type ImportJobStatus = 'pending' | 'failed' | 'complete';

export interface ImportJobLog {
  name: string;
  created: string;
  status: ImportJobStatus;
  projects: Project[];
}

/** Body of a GET against an import job's polling URL. */
export interface PollImportResponse {
  id: string;
  status: ImportJobStatus;
  created: string;
  logs: ImportJobLog[];
}
