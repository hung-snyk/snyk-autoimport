/**
 * Credential + defaults store.
 *
 * Persisted to a fixed per-user OS config directory (resolved by `env-paths`,
 * not the current working directory) so that "log in once" holds no matter
 * which folder the command is run from — the same behaviour as gh/aws/docker.
 * The file is written with 0600 permissions since it holds API tokens.
 */
import envPaths from 'env-paths';
import * as fs from 'fs';
import * as path from 'path';

export type Region = 'global' | 'eu' | 'au';

/**
 * Bitbucket Cloud is deliberately excluded here — its 3-method auth (API
 * token / OAuth token / username+app-password across 4 env vars) is real
 * complexity that would clutter this simple one-token-per-source model.
 * Supported via env vars only for now, not persisted through auth login.
 */
export interface Credentials {
  snykToken?: string;
  githubToken?: string;
  gitlabToken?: string;
  azureToken?: string;
  bitbucketServerToken?: string;
}

export interface StoredConfig {
  credentials?: Credentials;
  defaults?: {
    region?: Region;
  };
}

const paths = envPaths('snyk-autoimport', { suffix: '' });
const CONFIG_FILE = path.join(paths.config, 'config.json');
/** Scratch directory for the underlying library's SNYK_LOG_PATH output. */
export const LOG_DIR = path.join(paths.cache, 'logs');

export function configFilePath(): string {
  return CONFIG_FILE;
}

export function loadConfig(): StoredConfig {
  try {
    const raw = fs.readFileSync(CONFIG_FILE, 'utf8');
    return JSON.parse(raw) as StoredConfig;
  } catch {
    return {};
  }
}

export function saveConfig(config: StoredConfig): void {
  fs.mkdirSync(paths.config, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
  // Ensure perms even if the file already existed with looser bits.
  fs.chmodSync(CONFIG_FILE, 0o600);
}

export function setCredentials(creds: Credentials): void {
  const config = loadConfig();
  config.credentials = { ...config.credentials, ...creds };
  saveConfig(config);
}

export function clearCredentials(): void {
  const config = loadConfig();
  delete config.credentials;
  saveConfig(config);
}

export function setRegion(region: Region): void {
  const config = loadConfig();
  config.defaults = { ...config.defaults, region };
  saveConfig(config);
}
