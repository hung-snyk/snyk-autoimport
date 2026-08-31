/**
 * Credential + defaults store.
 *
 * Persisted to `.snyk-autoimport.json` in the installed package's own root, so
 * the path is identical on macOS, Linux, and Windows rather than varying with
 * each OS's config convention. It is resolved from the package location, not
 * the working directory, so "log in once" still holds wherever the command is
 * run from. The file is written with 0600 permissions since it holds API
 * tokens.
 *
 * TRADE-OFF: this puts secrets inside a git working tree, so the .gitignore
 * entry for it is load-bearing — without it, a `git add .` would commit live
 * tokens. Prefer environment variables in CI, which bypass this file entirely.
 */
import envPaths from 'env-paths';
import * as fs from 'fs';
import * as path from 'path';
import type { Region } from './regions';

/**
 * Bitbucket Cloud is the one source needing two fields rather than one: it
 * authenticates over HTTP Basic, with an Atlassian account email (or Bitbucket
 * username) as the user and an API token (or app password) as the secret.
 *
 * Only that Basic-auth pair is stored. The other two methods Bitbucket
 * accepts — OAuth tokens and workspace access tokens, which are Bearer rather
 * than Basic — remain env-var only, since they are short-lived or narrowly
 * scoped and not worth persisting.
 */
export interface Credentials {
  snykToken?: string;
  githubToken?: string;
  gitlabToken?: string;
  azureToken?: string;
  /** Bitbucket Server HTTP access token, used as Bearer. */
  bitbucketServerToken?: string;
  /** Bitbucket Server username + password, used as HTTP Basic. */
  bitbucketServerUsername?: string;
  bitbucketServerPassword?: string;
  bitbucketCloudUsername?: string;
  bitbucketCloudPassword?: string;
}

/** The env var each stored credential is published to for discovery/import. */
export const CREDENTIAL_ENV_VARS: Record<keyof Credentials, string> = {
  snykToken: 'SNYK_TOKEN',
  githubToken: 'GITHUB_TOKEN',
  gitlabToken: 'GITLAB_TOKEN',
  azureToken: 'AZURE_TOKEN',
  bitbucketServerToken: 'BITBUCKET_SERVER_TOKEN',
  bitbucketServerUsername: 'BITBUCKET_SERVER_USERNAME',
  bitbucketServerPassword: 'BITBUCKET_SERVER_PASSWORD',
  bitbucketCloudUsername: 'BITBUCKET_CLOUD_USERNAME',
  bitbucketCloudPassword: 'BITBUCKET_CLOUD_PASSWORD',
};

/** Human-readable name for each credential, used in prompts and summaries. */
export const CREDENTIAL_LABELS: Record<keyof Credentials, string> = {
  snykToken: 'Snyk API token',
  githubToken: 'GitHub token',
  gitlabToken: 'GitLab token',
  azureToken: 'Azure DevOps token',
  bitbucketServerToken: 'Bitbucket Server HTTP access token',
  bitbucketServerUsername: 'Bitbucket Server username',
  bitbucketServerPassword: 'Bitbucket Server password',
  bitbucketCloudUsername: 'Bitbucket Cloud email or username',
  bitbucketCloudPassword: 'Bitbucket Cloud API token or app password',
};

export const CREDENTIAL_KEYS = Object.keys(CREDENTIAL_ENV_VARS) as Array<
  keyof Credentials
>;

/** Reverse of CREDENTIAL_ENV_VARS, for going from a source's token to storage. */
export function credentialKeyForEnvVar(
  envVar: string,
): keyof Credentials | undefined {
  return CREDENTIAL_KEYS.find((key) => CREDENTIAL_ENV_VARS[key] === envVar);
}

export interface StoredConfig {
  credentials?: Credentials;
  defaults?: {
    /**
     * Host per source, for the self-hosted ones. A customer's Bitbucket Server
     * or GitHub Enterprise URL never changes, so making it a required flag on
     * every import was friction for no safety benefit — a wrong host fails
     * loudly at discovery either way.
     */
    sourceUrls?: Record<string, string>;
    /**
     * Held as a plain string, not a Region: a file written by an older version
     * can contain a name that is no longer valid, so readers validate it.
     */
    region?: string;
  };
}

const paths = envPaths('snyk-autoimport', { suffix: '' });

/**
 * The installed package's own directory, found by walking up to the nearest
 * package.json. Deliberately not `process.cwd()`: keying off the working
 * directory would scatter a separate credential file through every folder the
 * command happens to be run from.
 */
function findProjectRoot(): string {
  let dir = __dirname;
  for (;;) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return path.resolve(__dirname, '..');
    dir = parent;
  }
}

export const PROJECT_ROOT = findProjectRoot();

/**
 * A dotfile rather than `config.json` so the .gitignore entry is unambiguous
 * and cannot collide with unrelated config a customer adds to the repo.
 */
const CONFIG_FILE = path.join(PROJECT_ROOT, '.snyk-autoimport.json');

/** Where releases before this change stored credentials; still readable. */
const LEGACY_CONFIG_FILE = path.join(paths.config, 'config.json');

/**
 * Scratch directory for the underlying library's SNYK_LOG_PATH output. Left in
 * the OS cache directory: it is transient churn, not configuration, and does
 * not belong in a git working tree.
 */
export const LOG_DIR = path.join(paths.cache, 'logs');

export function configFilePath(): string {
  return CONFIG_FILE;
}

export function legacyConfigFilePath(): string {
  return LEGACY_CONFIG_FILE;
}

/** True while credentials are only in the old per-user location. */
export function usingLegacyConfig(): boolean {
  return !fs.existsSync(CONFIG_FILE) && fs.existsSync(LEGACY_CONFIG_FILE);
}

function readConfigFile(file: string): StoredConfig | undefined {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8')) as StoredConfig;
  } catch {
    return undefined;
  }
}

/**
 * Reads the project-root file, falling back to the legacy location so an
 * existing install keeps working. Nothing is copied across automatically —
 * writing credentials into a git working tree should be an explicit act, so
 * the move happens on the next `auth login`.
 */
export function loadConfig(): StoredConfig {
  return readConfigFile(CONFIG_FILE) ?? readConfigFile(LEGACY_CONFIG_FILE) ?? {};
}

export function saveConfig(config: StoredConfig): void {
  fs.mkdirSync(path.dirname(CONFIG_FILE), { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
  // Ensure perms even if the file already existed with looser bits.
  fs.chmodSync(CONFIG_FILE, 0o600);
}

export function setCredentials(creds: Credentials): void {
  const config = loadConfig();
  config.credentials = { ...config.credentials, ...creds };
  saveConfig(config);
}

/**
 * Logout is a clean slate, not just a credential wipe.
 *
 * The region and any stored self-hosted URLs are account-specific too: leaving
 * a customer's internal Bitbucket Server host, or a non-default region, behind
 * for whoever logs in next is both surprising and a small information leak.
 *
 * Writes an empty config rather than deleting the file, so a leftover legacy
 * config cannot quietly become the active one again after a logout.
 */
export function clearStoredConfig(): void {
  saveConfig({});
}

export function setRegion(region: Region): void {
  const config = loadConfig();
  config.defaults = { ...config.defaults, region };
  saveConfig(config);
}

export function setSourceUrl(source: string, url: string): void {
  const config = loadConfig();
  config.defaults = {
    ...config.defaults,
    sourceUrls: { ...config.defaults?.sourceUrls, [source]: url },
  };
  saveConfig(config);
}

export function storedSourceUrl(source: string): string | undefined {
  return loadConfig().defaults?.sourceUrls?.[source];
}
