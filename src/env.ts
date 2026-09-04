/**
 * Bridge stored config -> process.env.
 *
 * Everything downstream reads its configuration from env vars: each `scm/`
 * module reads its provider's credential vars, `snyk-request-manager` takes
 * `SNYK_TOKEN` and `SNYK_API`, and the import paces itself with
 * `CONCURRENT_IMPORTS`. The whole point of this tool is that the user never
 * sets those by hand — we publish them here from the credential store.
 *
 * Which vars get published is not listed here on purpose: it is exactly
 * `CREDENTIAL_ENV_VARS` in config.ts, and every stored credential — including
 * the Bitbucket Cloud and Bitbucket Server username/password pairs — goes
 * through the same loop. Bitbucket Cloud's Bearer methods (OAuth and workspace
 * access tokens) are the only credentials with no stored form; those are
 * env-var only and read directly by `scm/bitbucket-cloud.ts`.
 *
 * Precedence: a value already present in the real environment always wins,
 * so CI pipelines can inject secrets the normal way and ignore the store.
 */
import { loadConfig, CREDENTIAL_ENV_VARS, CREDENTIAL_KEYS } from './config';
import { resolveSnykAuth, type SnykAuthMode } from './snyk/oauth';
import {
  DEFAULT_REGION,
  REGION_API_HOSTS,
  REGIONS,
  isRegion,
  type Region,
} from './regions';

/**
 * Resolve the stored region, refusing to guess. Region names changed to match
 * the Snyk docs, so a config written by an older version may hold a retired
 * name — falling back to the default there would silently send an EU or AU
 * customer's requests to the US host, so this fails with migration steps.
 */
function storedRegion(value: string | undefined): Region {
  if (!value) return DEFAULT_REGION;
  if (isRegion(value)) return value;
  throw new Error(
    `Stored region "${value}" is no longer a valid name. Region names now match ` +
      `the Snyk docs: ${REGIONS.join(', ')}. ` +
      'Run `snyk-autoimport auth login` to set it again, or pass --region.',
  );
}

function setIfAbsent(key: string, value: string | undefined): void {
  if (value && !process.env[key]) {
    process.env[key] = value;
  }
}

export interface PreparedEnv {
  /** Which Snyk credential the run will authenticate with. */
  authMode: SnykAuthMode;
}

/**
 * Publish the store + region into process.env. Throws if there is no Snyk
 * credential at all, since nothing downstream can work without one. SCM
 * credentials are not returned: discovery and verification read them from
 * process.env, and a per-provider return here would be one more list to keep
 * in step with `CREDENTIAL_ENV_VARS`.
 *
 * Either Snyk auth method satisfies this — an API token or an OAuth 2.0
 * service account. The token itself is not returned because nothing sends it
 * from here: every Snyk request goes through `snykRequest`, which resolves the
 * credential per call so a short-lived OAuth token can be refreshed mid-run.
 */
export function prepareEnv(region?: Region): PreparedEnv {
  const config = loadConfig();
  const creds = config.credentials ?? {};
  const effectiveRegion = region ?? storedRegion(config.defaults?.region);

  for (const key of CREDENTIAL_KEYS) {
    setIfAbsent(CREDENTIAL_ENV_VARS[key], creds[key]);
  }
  setIfAbsent('SNYK_API', REGION_API_HOSTS[effectiveRegion]);

  const auth = resolveSnykAuth();
  if (!auth) {
    throw new Error(
      'No Snyk credentials found. Run `snyk-autoimport auth login`, or set ' +
        'SNYK_TOKEN (API token), or SNYK_OAUTH_CLIENT_ID and ' +
        'SNYK_OAUTH_CLIENT_SECRET (OAuth 2.0 service account).',
    );
  }

  return { authMode: auth.mode };
}
