/**
 * Source config — shared between the CLI (arg validation, integration
 * resolution) and reporting (source-aware failure hints), so identifiers and
 * per-source rules live in exactly one place.
 *
 * Each entry maps a --source value to: the Snyk dedup origin type, whether
 * --source-url is mandatory (SCMs with a real public-cloud default host are
 * safe to leave optional — GitHub.com, GitLab.com, dev.azure.com; self-hosted
 * variants with NO safe default, like GitHub Enterprise and Bitbucket Server,
 * must be forced so discovery never silently queries the wrong host), and
 * which credential the discovery step needs.
 *
 * NOTE: "github-server-app" (the GitHub App variant for self-hosted GitHub
 * Enterprise Server) is intentionally NOT included. Its project origin has no
 * verified dedup mapping, so wiring it up would either skip dedup or match on
 * the wrong rules — unsafe without a live org to verify against. Revisit if
 * that becomes a real need.
 */
import { SnykProjectOrigin } from './api';

export const GITHUB_CLOUD_APP_SOURCE = 'github-cloud-app';

/** Single-env-var credential requirement. Bitbucket Cloud has its own
 * multi-method check (see cli.ts) since it isn't a single fixed var. */
export type TokenRequirement = { envVar: string } | { special: 'bitbucket-cloud' };

export interface SourceDef {
  /**
   * How Snyk names this integration in its own UI. Shown wherever a human
   * reads the list, while the key stays the value passed to --source and sent
   * on the wire — "bitbucket-connect-app" is presented as "Bitbucket Cloud
   * App", which is what someone looking at the Snyk platform will be trying to
   * match up.
   */
  label: string;
  dedupType: SnykProjectOrigin;
  requiresSourceUrl: boolean;
  token: TokenRequirement;
}

export const SOURCES: Record<string, SourceDef> = {
  github: {
    label: 'GitHub',
    dedupType: SnykProjectOrigin.GITHUB,
    requiresSourceUrl: false,
    token: { envVar: 'GITHUB_TOKEN' },
  },
  [GITHUB_CLOUD_APP_SOURCE]: {
    label: 'GitHub Cloud App',
    dedupType: SnykProjectOrigin.GITHUB_CLOUD_APP,
    requiresSourceUrl: false,
    token: { envVar: 'GITHUB_TOKEN' },
  },
  'github-enterprise': {
    label: 'GitHub Enterprise',
    dedupType: SnykProjectOrigin.GHE,
    requiresSourceUrl: true, // getGithubBaseUrl silently defaults to public GitHub otherwise
    token: { envVar: 'GITHUB_TOKEN' },
  },
  gitlab: {
    label: 'GitLab',
    dedupType: SnykProjectOrigin.GITLAB,
    requiresSourceUrl: false, // safe default: gitlab.com
    token: { envVar: 'GITLAB_TOKEN' },
  },
  'azure-repos': {
    label: 'Azure Repos',
    dedupType: SnykProjectOrigin.AZURE_REPOS,
    requiresSourceUrl: false, // safe default: dev.azure.com
    token: { envVar: 'AZURE_TOKEN' },
  },
  'bitbucket-server': {
    label: 'Bitbucket Server',
    dedupType: SnykProjectOrigin.BITBUCKET_SERVER,
    requiresSourceUrl: true, // no public default host exists for self-hosted Bitbucket Server
    token: { envVar: 'BITBUCKET_SERVER_TOKEN' },
  },
  'bitbucket-cloud': {
    label: 'Bitbucket Cloud',
    dedupType: SnykProjectOrigin.BITBUCKET_CLOUD,
    requiresSourceUrl: false, // fixed host: api.bitbucket.org
    token: { special: 'bitbucket-cloud' },
  },
  /**
   * Bitbucket Cloud via Snyk's Connect App. Discovery is identical to
   * `bitbucket-cloud` — the same Bitbucket Cloud API, addressed the same way —
   * because how Snyk connects to Bitbucket does not change how repos are
   * listed. Only the Snyk-side integration key and project origin differ.
   */
  'bitbucket-connect-app': {
    label: 'Bitbucket Cloud App',
    dedupType: SnykProjectOrigin.BITBUCKET_CONNECT_APP,
    requiresSourceUrl: false,
    token: { special: 'bitbucket-cloud' },
  },
};

export const REQUIRES_SOURCE_URL = new Set(
  Object.entries(SOURCES)
    .filter(([, def]) => def.requiresSourceUrl)
    .map(([source]) => source),
);

/**
 * Sources that are deliberately unsupported (not just "not built yet"),
 * with the reason surfaced directly in the error so it doesn't read the
 * same as a plain gap like a source we simply haven't ported yet.
 */
export const KNOWN_UNSUPPORTED: Record<string, string> = {
  'github-server-app':
    'no dedup mapping exists for this integration\'s project origin, and there is ' +
    'no verified org to test one against — wiring it up blind risks silently skipping repos. See README.',
};
