/**
 * Bridge stored config -> process.env.
 *
 * The underlying `snyk-api-import` library reads everything from env vars
 * (`SNYK_TOKEN`, `SNYK_LOG_PATH`, `SNYK_API`, `GITHUB_TOKEN`, `GITLAB_TOKEN`,
 * `AZURE_TOKEN`, `BITBUCKET_SERVER_TOKEN`, `CONCURRENT_IMPORTS`). The whole
 * point of this wrapper is that the user never sets those by hand — we
 * populate them here from the credential store.
 *
 * Precedence: a value already present in the real environment always wins,
 * so CI pipelines can inject secrets the normal way and ignore the store.
 *
 * Bitbucket Cloud is NOT bridged here — its 3-method auth is read directly
 * from its own 4 env vars by `discover-bitbucket-cloud.ts`, never persisted
 * through this store. See config.ts's Credentials type for why.
 */
import * as fs from 'fs';
import { loadConfig, LOG_DIR, type Region } from './config';

const REGION_HOSTS: Record<Region, string> = {
  global: 'https://api.snyk.io/v1',
  eu: 'https://api.eu.snyk.io/v1',
  au: 'https://api.au.snyk.io/v1',
};

function setIfAbsent(key: string, value: string | undefined): void {
  if (value && !process.env[key]) {
    process.env[key] = value;
  }
}

export interface PreparedEnv {
  snykToken: string;
  githubToken?: string;
  gitlabToken?: string;
  azureToken?: string;
  bitbucketServerToken?: string;
}

/**
 * Populate process.env from the store + region, creating the scratch log
 * directory the library requires. Throws if the Snyk token is missing, since
 * nothing downstream can work without it.
 */
export function prepareEnv(region?: Region): PreparedEnv {
  const config = loadConfig();
  const creds = config.credentials ?? {};
  const effectiveRegion = region ?? config.defaults?.region ?? 'global';

  setIfAbsent('SNYK_TOKEN', creds.snykToken);
  setIfAbsent('GITHUB_TOKEN', creds.githubToken);
  setIfAbsent('GITLAB_TOKEN', creds.gitlabToken);
  setIfAbsent('AZURE_TOKEN', creds.azureToken);
  setIfAbsent('BITBUCKET_SERVER_TOKEN', creds.bitbucketServerToken);
  setIfAbsent('SNYK_API', REGION_HOSTS[effectiveRegion]);

  // getLoggingPath() throws if SNYK_LOG_PATH is unset; the library writes
  // per-target logs there. We read results from return values, not the logs,
  // so this is just scratch space.
  if (!process.env.SNYK_LOG_PATH) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    process.env.SNYK_LOG_PATH = LOG_DIR;
  }

  const snykToken = process.env.SNYK_TOKEN;
  if (!snykToken) {
    throw new Error(
      'No Snyk API token found. Run `snyk-autoimport auth login`, or set SNYK_TOKEN.',
    );
  }

  return {
    snykToken,
    githubToken: process.env.GITHUB_TOKEN,
    gitlabToken: process.env.GITLAB_TOKEN,
    azureToken: process.env.AZURE_TOKEN,
    bitbucketServerToken: process.env.BITBUCKET_SERVER_TOKEN,
  };
}
