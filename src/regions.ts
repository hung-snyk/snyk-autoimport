/**
 * Snyk regional hosting.
 *
 * Region names and API hosts mirror the `snyk config environment` aliases
 * exactly, so a value that works with the Snyk CLI works here too:
 * https://docs.snyk.io/developer-tools/snyk-cli/snyk-cli/commands/config-environment
 *
 * SNYK-GOV-01 is deliberately absent. It does not accept API keys at all
 * (OAuth 2.0 only), and this wrapper authenticates with a SNYK_TOKEN API key,
 * so offering it would only produce confusing 401s.
 */

export type Region = 'snyk-us-01' | 'snyk-us-02' | 'snyk-eu-01' | 'snyk-au-01';

export const DEFAULT_REGION: Region = 'snyk-us-01';

/**
 * v1 API base per region, published as SNYK_API for `snyk-request-manager` to
 * read. The `/v1` suffix is ours; the docs list the bare host.
 */
export const REGION_API_HOSTS: Record<Region, string> = {
  'snyk-us-01': 'https://api.snyk.io/v1',
  'snyk-us-02': 'https://api.us.snyk.io/v1',
  'snyk-eu-01': 'https://api.eu.snyk.io/v1',
  'snyk-au-01': 'https://api.au.snyk.io/v1',
};

export const REGIONS = Object.keys(REGION_API_HOSTS) as Region[];

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
