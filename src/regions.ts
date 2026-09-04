/**
 * Snyk regional hosting.
 *
 * Region names and API hosts mirror the `snyk config environment` aliases
 * exactly, so a value that works with the Snyk CLI works here too:
 * https://docs.snyk.io/developer-tools/snyk-cli/snyk-cli/commands/config-environment
 *
 * SNYK-GOV-01 is included, but is the one region with a credential rule of its
 * own: the FedRAMP environment does not issue API keys at all, so it accepts
 * only an OAuth 2.0 service account. That rule is enforced here rather than
 * left to fail as a 401 — see `assertAuthAllowedForRegion`.
 */

export type Region =
  | 'snyk-us-01'
  | 'snyk-us-02'
  | 'snyk-eu-01'
  | 'snyk-au-01'
  | 'snyk-gov-01';

export const DEFAULT_REGION: Region = 'snyk-us-01';

/** Snyk for Government (US). Called out because its auth rules differ. */
export const GOV_REGION: Region = 'snyk-gov-01';

/**
 * v1 API base per region, published as SNYK_API for `snyk-request-manager` to
 * read. The `/v1` suffix is ours; the docs list the bare host.
 */
export const REGION_API_HOSTS: Record<Region, string> = {
  'snyk-us-01': 'https://api.snyk.io/v1',
  'snyk-us-02': 'https://api.us.snyk.io/v1',
  'snyk-eu-01': 'https://api.eu.snyk.io/v1',
  'snyk-au-01': 'https://api.au.snyk.io/v1',
  'snyk-gov-01': 'https://api.snykgov.io/v1',
};

export const REGIONS = Object.keys(REGION_API_HOSTS) as Region[];

/** Shown next to a region in a picker, where one needs explaining. */
export const REGION_NOTES: Partial<Record<Region, string>> = {
  'snyk-gov-01': 'Snyk for Government (US) — OAuth service account only',
};

export function isRegion(value: string): value is Region {
  return Object.prototype.hasOwnProperty.call(REGION_API_HOSTS, value);
}

/**
 * Parse a user-supplied region. Case-insensitive so the uppercase spelling
 * used throughout the Snyk docs (`SNYK-EU-01`) can be pasted in directly.
 */
export function parseRegion(input: string): Region {
  const normalized = input.trim().toLowerCase();
  if (!isRegion(normalized)) {
    throw new Error(
      `Invalid region "${input}". Must be one of: ${REGIONS.join(', ')}.`,
    );
  }
  return normalized;
}

/**
 * Is this API base the FedRAMP environment?
 *
 * Matches on the resolved host rather than the region name because `SNYK_API`
 * can be set directly, bypassing the region entirely. Checking the name alone
 * would let `SNYK_API=https://api.snykgov.io` through with an API key that the
 * environment cannot issue.
 */
export function isGovApiHost(apiBase: string | undefined): boolean {
  if (!apiBase) return false;
  try {
    return new URL(apiBase).hostname === new URL(REGION_API_HOSTS[GOV_REGION]).hostname;
  } catch {
    return false;
  }
}

/**
 * Refuse an API key against SNYK-GOV-01, where one cannot exist.
 *
 * Snyk for Government does not issue API keys — a service account with
 * `auth_type: apikey` is rejected at creation, and Snyk's own CLI must run in
 * OAuth mode there. So a token presented against this host is either from a
 * different region or something that was never valid; either way the 401 it
 * would earn says nothing useful. Failing here names the actual rule.
 *
 * `mode` is the string form of SnykAuthMode, taken loosely to keep this file
 * free of a dependency on the auth layer.
 */
export function assertAuthAllowedForRegion(
  mode: string,
  apiBase: string | undefined,
): void {
  if (mode !== 'api-token' || !isGovApiHost(apiBase)) return;
  throw new Error(
    'SNYK-GOV-01 does not accept Snyk API tokens — the FedRAMP environment ' +
      'issues none.\nUse an OAuth 2.0 service account instead: run ' +
      '`snyk-autoimport auth login` and choose it, or set SNYK_OAUTH_CLIENT_ID ' +
      'and SNYK_OAUTH_CLIENT_SECRET.',
  );
}
