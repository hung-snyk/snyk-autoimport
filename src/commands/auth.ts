/**
 * The `auth` commands — login, status — and every interactive prompt they use.
 *
 * Extracted from cli.ts so it can be imported by a test: cli.ts self-executes,
 * so nothing left in it can be reached from a test file.
 */
import { describeError, formatError, resetSnykOauthCache } from '../api';
import { CREDENTIAL_ENV_VARS, CREDENTIAL_KEYS, CREDENTIAL_LABELS, configFilePath, credentialKeyForEnvVar, legacyConfigFilePath, loadConfig, removeCredentials, setCredentials, setRegion, setSourceUrl, storedSourceUrl, usingLegacyConfig } from '../config';
import type { Credentials, StoredConfig } from '../config';
import type { Discovery } from '../discovery';
import { ask, askSecret, confirm, isInteractive } from '../prompt';
import { DEFAULT_REGION, GOV_REGION, REGIONS, REGION_API_HOSTS, REGION_NOTES, isRegion, parseRegion } from '../regions';
import type { Region } from '../regions';
import { listAllOrgs, makeSnykApiClient } from '../snyk';
import type { OrgSummary } from '../snyk';
import { normalizeSourceUrl } from '../source-url';
import { ACCEPTS_SOURCE_URL, SOURCES } from '../sources';
import { verifyScmCredential } from '../verify';
import type { VerifyResult } from '../verify';

/** `Label: `, noting when a value already exists so blank is a real choice. */
function secretPrompt(key: keyof Credentials, existing: Credentials): string {
  const suffix = existing[key] ? ' [already set — blank keeps it]' : '';
  return `${CREDENTIAL_LABELS[key]}${suffix}: `;
}

/**
 * Which stored credential a source's token belongs in. Undefined for the
 * Bitbucket Cloud sources, which need a two-field Basic-auth pair instead of a
 * single token — see bitbucketCloudPrompt below.
 */
function credentialForSource(source: string): keyof Credentials | undefined {
  const token = SOURCES[source].token;
  return 'special' in token ? undefined : credentialKeyForEnvVar(token.envVar);
}

/** True for the sources authenticating with the Bitbucket Cloud email/token pair. */
function usesBitbucketCloudAuth(source: string): boolean {
  const token = SOURCES[source].token;
  return 'special' in token && token.special === 'bitbucket-cloud';
}

function usesBitbucketServerAuth(source: string): boolean {
  const token = SOURCES[source].token;
  return 'special' in token && token.special === 'bitbucket-server';
}

/** Example host shown when a self-hostable source has no URL stored yet. */
const URL_EXAMPLES: Record<string, string> = {
  'github-enterprise': 'https://github.example.com',
  'bitbucket-server': 'https://bitbucket.example.com',
  gitlab: 'https://gitlab.example.com',
};

/**
 * The public host used when a source that allows one is left blank. Display
 * only — the real defaults live in each scm/ module's base-url helper, and
 * this must not become a second place they are decided.
 */
const DEFAULT_HOST_LABELS: Record<string, string> = {
  gitlab: 'gitlab.com',
};

/**
 * Ask for and store a self-hostable source's URL.
 *
 * Stored rather than passed every time: a customer's host never changes, and
 * requiring --source-url on every import was friction with no safety benefit —
 * a wrong host fails loudly at discovery either way. The flag still overrides
 * this for a one-off run.
 *
 * A source with a real public default (GitLab) may be left blank, and that is
 * a valid answer rather than a skipped step. One with no default (GitHub
 * Enterprise, Bitbucket Server) may not, since there would be nothing to fall
 * back on.
 */
async function promptSourceUrl(source: string): Promise<void> {
  const { label, requiresSourceUrl } = SOURCES[source];
  const current = storedSourceUrl(source);
  const example = URL_EXAMPLES[source] ?? 'https://scm.example.com';
  const fallback = DEFAULT_HOST_LABELS[source];

  const hint = current
    ? `[current: ${current} — blank keeps it]`
    : requiresSourceUrl
      ? `(e.g. ${example})`
      : `(e.g. ${example}) [blank for ${fallback ?? 'the public host'}]`;

  for (;;) {
    const url = await ask(`\n${label} URL ${hint}: `);
    if (!url) {
      if (!current && requiresSourceUrl) {
        throw new Error(
          `${label} is self-hosted, so it needs its URL — there is no default host to fall back on.`,
        );
      }
      return;
    }

    // Checked here, where a typo can be retyped, rather than stored as typed
    // and left to fail at the credential check under the wrong heading.
    let normalized: string;
    try {
      normalized = normalizeSourceUrl(url, `${label} URL`);
    } catch (error) {
      console.log(`  ✗ ${error instanceof Error ? error.message : String(error)}`);
      continue;
    }
    setSourceUrl(source, normalized);
    return;
  }
}

/**
 * Bitbucket Server takes either a username and password, or an HTTP access
 * token. Its URL is collected separately, by promptSourceUrl.
 */
async function promptBitbucketServer(existing: Credentials): Promise<Credentials> {
  const creds: Credentials = {};

  console.log(
    '\nAuthenticate with a username and password, or leave the username blank\n' +
      'to use an HTTP access token instead.',
  );
  const userSuffix = existing.bitbucketServerUsername
    ? ` [current: ${existing.bitbucketServerUsername}]`
    : '';
  const username = await ask(`${CREDENTIAL_LABELS.bitbucketServerUsername}${userSuffix}: `);
  if (username) creds.bitbucketServerUsername = username;

  if (username || existing.bitbucketServerUsername) {
    const password = await askSecret(secretPrompt('bitbucketServerPassword', existing));
    if (password) creds.bitbucketServerPassword = password;
  } else {
    const token = await askSecret(secretPrompt('bitbucketServerToken', existing));
    if (token) creds.bitbucketServerToken = token;
  }
  return creds;
}

/** Require one of the supported sources, re-prompting until a valid pick. */
async function promptForSource(): Promise<string> {
  const names = Object.keys(SOURCES);
  // Width comes from the longest label, not a constant: a hardcoded 18 was
  // silently outgrown by "Bitbucket Cloud App" and broke the column.
  const labelWidth = Math.max(...names.map((name) => SOURCES[name].label.length));
  console.log('\nWhich source will you import from?');
  names.forEach((name, i) => {
    // Snyk's own name for it, then the --source value, since the two differ
    // for the App integrations and users are matching against the Snyk UI.
    // No --source-url note: login asks self-hosted sources for their URL.
    const label = SOURCES[name].label.padEnd(labelWidth);
    console.log(`  [${String(i + 1).padStart(names.length >= 10 ? 2 : 1)}] ${label}  --source ${name}`);
  });

  for (;;) {
    const answer = await ask(`Pick one (1-${names.length} or name): `);
    const byNumber = names[Number(answer) - 1];
    const byName = SOURCES[answer.toLowerCase()] ? answer.toLowerCase() : undefined;
    const picked = byNumber ?? byName;
    if (picked) return picked;
    console.log(
      `  "${answer}" is not a supported source — enter a number from 1 to ` +
        `${names.length}, or an exact name from the list.`,
    );
  }
}

/**
 * Confirm the Snyk credential in the environment actually works, by listing
 * the organizations it can see. Done before asking anything else, so a wrong
 * or expired credential is caught here rather than after the user has picked a
 * source and pasted a second secret — and rather than at the start of a real
 * import.
 *
 * For an OAuth service account this exercises the whole chain: the client
 * credentials are exchanged for an access token, and that token is used
 * against the API. A bad secret fails at the exchange, with the reason Snyk
 * gave; a good secret with no organization access fails at the call.
 */
async function verifySnykCredential(): Promise<
  { ok: true; orgs: OrgSummary[] } | { ok: false; reason: string }
> {
  try {
    // A retyped secret must be exchanged afresh rather than checked against
    // the token the previous attempt already minted.
    resetSnykOauthCache();
    const orgs = await listAllOrgs(makeSnykApiClient('snyk-autoimport:auth'));
    return { ok: true, orgs };
  } catch (error) {
    const detail = describeError(error);
    const reason =
      detail.status === 401
        ? 'the credential was rejected (401). Check you pasted it whole, and that it matches the region above.'
        : formatError(detail);
    return { ok: false, reason };
  }
}

/**
 * Region first, then the Snyk token — in that order because verifying the
 * token requires knowing which regional API to verify it against. A token
 * valid in SNYK-EU-01 returns 401 against the US host, so asking for the
 * region afterwards would make a correct token look broken.
 *
 * Numbered like the source picker, so both selections work the same way.
 */
async function promptRegion(config: StoredConfig): Promise<Region | undefined> {
  const current = (config.defaults?.region as Region | undefined) ?? DEFAULT_REGION;
  console.log('Which Snyk region is your account on?');
  REGIONS.forEach((name, i) => {
    const notes = [
      name === DEFAULT_REGION ? 'default' : undefined,
      name === current ? 'current' : undefined,
      REGION_NOTES[name],
    ].filter(Boolean);
    console.log(`  [${i + 1}] ${name}${notes.length ? `  (${notes.join(', ')})` : ''}`);
  });

  for (;;) {
    const answer = await ask(`Pick one (1-${REGIONS.length} or name) [blank keeps ${current}]: `);
    if (!answer) return undefined;

    const byNumber = REGIONS[Number(answer) - 1];
    if (byNumber) return byNumber;
    try {
      return parseRegion(answer);
    } catch {
      console.log(
        `  "${answer}" is not a region — enter a number from 1 to ${REGIONS.length}, ` +
          'or an exact name from the list.',
      );
    }
  }
}

/** The two Snyk credential types `auth login` can store. */
const SNYK_AUTH_METHODS = [
  {
    key: 'token' as const,
    label: 'Snyk API token',
    note: 'from app.snyk.io/account — one value, and it never expires',
  },
  {
    key: 'oauth' as const,
    label: 'OAuth 2.0 service account',
    note: 'a client ID and secret, exchanged here for a short-lived token',
  },
];

type SnykAuthChoice = (typeof SNYK_AUTH_METHODS)[number]['key'];

/**
 * Which Snyk credential to use. Numbered like the region and source pickers.
 *
 * Asked rather than inferred from what happens to be stored: only one method
 * ends up stored (the other is cleared below), so this is the step that
 * decides it, and an OAuth service account is not something to fall into by
 * accident when a plain token was meant.
 */
async function promptSnykAuthMethod(
  existing: Credentials,
  region: Region,
): Promise<SnykAuthChoice> {
  // SNYK-GOV-01 issues no API keys at all, so there is nothing to choose
  // between. Asking anyway and then rejecting the answer would be a worse
  // version of simply saying so.
  if (region === GOV_REGION) {
    console.log(
      `\n${GOV_REGION} issues no API tokens, so this uses an OAuth 2.0 service account.`,
    );
    return 'oauth';
  }

  const current: SnykAuthChoice | undefined = existing.snykOauthClientId
    ? 'oauth'
    : existing.snykToken
      ? 'token'
      : undefined;

  console.log('\nHow will you authenticate to Snyk?');
  SNYK_AUTH_METHODS.forEach((method, i) => {
    const mark = method.key === current ? '  (current)' : '';
    console.log(`  [${i + 1}] ${method.label}${mark}`);
    console.log(`      ${method.note}`);
  });

  const currentLabel = SNYK_AUTH_METHODS.find((m) => m.key === current)?.label;
  for (;;) {
    const suffix = currentLabel ? ` [blank keeps ${currentLabel}]` : '';
    const answer = await ask(`Pick one (1-${SNYK_AUTH_METHODS.length})${suffix}: `);
    if (!answer && current) return current;
    const picked = SNYK_AUTH_METHODS[Number(answer) - 1];
    if (picked) return picked.key;
    console.log(
      `  "${answer}" is not one of the options — enter a number from 1 to ` +
        `${SNYK_AUTH_METHODS.length}.`,
    );
  }
}

/** What a Snyk login produced: what to store, and what it replaces. */
interface SnykAuthEntry {
  /** Newly entered values, to store. Empty when the stored ones were kept. */
  creds: Credentials;
  /** Stored credentials belonging to the method NOT chosen. */
  obsolete: Array<keyof Credentials>;
  /** Human-readable name of the method chosen, for the summary. */
  label: string;
}

/**
 * Prompt for a Snyk credential and verify it, re-prompting while it fails.
 *
 * Both methods publish to `process.env` before the check, so what gets
 * verified is exactly what the next import will use. The unchosen method's
 * variables are cleared from the environment too: leaving them set would let
 * the precedence rule in snyk/oauth.ts verify a credential the user did not
 * just type.
 */
async function promptAndVerifySnykAuth(
  existing: Credentials,
  region: Region,
): Promise<SnykAuthEntry> {
  const method = await promptSnykAuthMethod(existing, region);
  const label = SNYK_AUTH_METHODS.find((m) => m.key === method)?.label ?? method;
  console.log('');

  for (;;) {
    const creds: Credentials = {};

    if (method === 'token') {
      const entered = await askSecret(secretPrompt('snykToken', existing));
      const effective = entered || existing.snykToken;
      if (!effective) {
        throw new Error(
          'A Snyk API token is required. Get one from https://app.snyk.io/account',
        );
      }
      if (entered) creds.snykToken = entered;
      process.env.SNYK_TOKEN = effective;
      delete process.env.SNYK_OAUTH_CLIENT_ID;
      delete process.env.SNYK_OAUTH_CLIENT_SECRET;
      delete process.env.SNYK_OAUTH_TOKEN;
    } else {
      const idSuffix = existing.snykOauthClientId
        ? ` [current: ${existing.snykOauthClientId} — blank keeps it]`
        : '';
      // The client id is an identifier, not a secret, so it is echoed —
      // seeing it is how a wrong service account gets spotted.
      const id = await ask(`${CREDENTIAL_LABELS.snykOauthClientId}${idSuffix}: `);
      const secret = await askSecret(secretPrompt('snykOauthClientSecret', existing));
      const effectiveId = id || existing.snykOauthClientId;
      const effectiveSecret = secret || existing.snykOauthClientSecret;
      if (!effectiveId || !effectiveSecret) {
        throw new Error(
          'An OAuth 2.0 service account needs both a client ID and a client secret.\n' +
            'Create one in Snyk under Settings → Service accounts (Enterprise plans), ' +
            'and copy the secret then — it cannot be shown again.',
        );
      }
      if (id) creds.snykOauthClientId = id;
      if (secret) creds.snykOauthClientSecret = secret;
      process.env.SNYK_OAUTH_CLIENT_ID = effectiveId;
      process.env.SNYK_OAUTH_CLIENT_SECRET = effectiveSecret;
      delete process.env.SNYK_TOKEN;
    }

    process.stdout.write('  Checking credentials... ');
    const result = await verifySnykCredential();
    if (result.ok) {
      const n = result.orgs.length;
      console.log(`✓ valid (${n} organization${n === 1 ? '' : 's'} visible)`);
      return {
        creds,
        obsolete:
          method === 'token'
            ? ['snykOauthClientId', 'snykOauthClientSecret']
            : ['snykToken'],
        label,
      };
    }

    console.log(`✗ ${result.reason}`);
    const retry = await confirm('  Try again?');
    if (!retry) {
      throw new Error('Stopped without a working Snyk credential — nothing was saved.');
    }
  }
}

/**
 * Bitbucket Cloud needs two values rather than one. The email is not a secret,
 * so it is echoed normally; only the token is masked.
 */
async function promptBitbucketCloud(existing: Credentials): Promise<Credentials> {
  const creds: Credentials = {};
  console.log(
    '\nBitbucket Cloud authenticates over HTTP Basic: your Atlassian account\n' +
      'email with an API token, or your Bitbucket username with an app password.',
  );

  const userSuffix = existing.bitbucketCloudUsername
    ? ` [current: ${existing.bitbucketCloudUsername}]`
    : '';
  const username = await ask(
    `${CREDENTIAL_LABELS.bitbucketCloudUsername}${userSuffix}: `,
  );
  if (username) creds.bitbucketCloudUsername = username;

  const token = await askSecret(secretPrompt('bitbucketCloudPassword', existing));
  if (token) creds.bitbucketCloudPassword = token;

  const haveUser = creds.bitbucketCloudUsername ?? existing.bitbucketCloudUsername;
  const haveToken = creds.bitbucketCloudPassword ?? existing.bitbucketCloudPassword;
  if (!haveUser || !haveToken) {
    console.log(
      '\n  ⚠ Both values are needed for Basic auth. Discovery will fail until\n' +
        '    the missing one is set — re-run `auth login` to finish.',
    );
  }
  return creds;
}

/** Print the outcome of a credential check as one indented status line. */
function printVerifyResult(result: VerifyResult): void {
  if (result.status === 'ok') console.log(`  ✓ ${result.detail}`);
  else if (result.status === 'failed') console.log(`  ✗ ${result.reason}`);
  else console.log(`  – not checked: ${result.reason}`);
}

export async function authLogin(): Promise<void> {
  if (!isInteractive()) {
    throw new Error('auth login requires an interactive terminal.');
  }
  const config = loadConfig();
  const existing = config.credentials ?? {};

  // 1. Region, before the token: the token is verified against this region.
  const region = await promptRegion(config);
  const effectiveRegion =
    region ?? (config.defaults?.region as Region | undefined) ?? DEFAULT_REGION;
  process.env.SNYK_API = REGION_API_HOSTS[effectiveRegion];
  if (region) setRegion(region);

  // 2. The Snyk credential — API token or OAuth service account — verified
  //    before going any further.
  const creds: Credentials = {};
  const snykAuth = await promptAndVerifySnykAuth(existing, effectiveRegion);
  Object.assign(creds, snykAuth.creds);
  // Only what is actually stored needs clearing; listing the rest would report
  // deletions that never happened.
  const obsolete = snykAuth.obsolete.filter((key) => existing[key] !== undefined);

  // 3. Which source.
  //    Deliberately NOT checked against Snyk here: integrations are
  //    per-organization and login never asks for one, so any check would
  //    either need a prompt it does not have or a scan of every visible
  //    organization — which is slow, and can only ever return an inconclusive
  //    answer once capped. `import` knows the target organization and checks
  //    it exactly; that is where a missing integration should fail.
  const source = await promptForSource();

  // 4. A self-hostable source is asked for its host before its credential,
  //    because the credential check below is run against that host: a token
  //    issued by a self-managed instance is rejected by the vendor's public
  //    one, so checking the wrong server would fail a working credential.
  if (ACCEPTS_SOURCE_URL.has(source)) {
    await promptSourceUrl(source);
  }

  // 5. That source's credential(s), verified.
  if (usesBitbucketCloudAuth(source)) {
    Object.assign(creds, await promptBitbucketCloud(existing));
  } else if (usesBitbucketServerAuth(source)) {
    Object.assign(creds, await promptBitbucketServer(existing));
  } else {
    const key = credentialForSource(source);
    if (key) {
      console.log('');
      const token = await askSecret(secretPrompt(key, existing));
      if (token) creds[key] = token;
    }
  }

  // Publish what was just entered (falling back to what was already stored) so
  // the check below tests the credential the user will actually import with.
  // The unchosen Snyk method is skipped: it is about to be deleted from the
  // store, and re-publishing it here would put back the very variables
  // promptAndVerifySnykAuth cleared from the environment.
  for (const key of CREDENTIAL_KEYS) {
    if (snykAuth.obsolete.includes(key)) continue;
    const value = creds[key] ?? existing[key];
    if (value) process.env[CREDENTIAL_ENV_VARS[key]] = value;
  }
  process.stdout.write(`\nChecking ${source} credentials...\n`);
  const scmResult = await verifyScmCredential(source);
  printVerifyResult(scmResult);

  const saved = Object.keys(creds) as Array<keyof Credentials>;
  if (saved.length === 0 && !region) {
    console.log('\nNothing entered — no changes.');
    return;
  }
  if (saved.length > 0) setCredentials(creds);
  if (obsolete.length > 0) removeCredentials(obsolete);

  // 6. Everything is entered and checked — now say what happened and where it
  //    went. Leading with a file path told the user nothing they could act on.
  console.log('');
  if (region) console.log(`✓ Region set to ${region}.`);
  console.log(`✓ Snyk auth: ${snykAuth.label}.`);
  if (obsolete.length > 0) {
    console.log('  The credentials for the other Snyk auth method were removed.');
  }
  if (saved.length > 0) {
    console.log(`✓ Stored ${saved.length} credential(s), chmod 600:`);
    console.log(`    ${configFilePath()}`);
    console.log(
      '    Environment variables override this file, so CI never needs it.',
    );
  }

  if (scmResult.status === 'failed') {
    console.log(
      `\n⚠ The ${source} credential did not pass its check, so an import will ` +
        'likely fail.\n  Re-run `auth login` once you have a working one.',
    );
    return;
  }
  console.log(
    `\nNext: snyk-autoimport import --snyk-org "<name>" --source ${source} ` +
      '--source-org <org>',
  );
}

export function authStatus(): void {
  const config = loadConfig();
  const creds = config.credentials ?? {};
  console.log('Config file: ' + configFilePath());
  if (usingLegacyConfig()) {
    console.log(
      '  ⚠ Still reading the previous location, ' + legacyConfigFilePath() + '.\n' +
        '    Run `auth login` to store them at the path above, then delete the old file.',
    );
  }
  // One line, not one per field: what matters is which method will be used,
  // and a half-entered OAuth pair authenticates as nothing at all.
  const oauthComplete = creds.snykOauthClientId && creds.snykOauthClientSecret;
  const snykAuth = oauthComplete
    ? `OAuth 2.0 service account (client ${creds.snykOauthClientId})` +
      (creds.snykToken ? ' — an API token is also stored, but this wins' : '')
    : creds.snykOauthClientId || creds.snykOauthClientSecret
      ? 'INCOMPLETE — an OAuth service account needs both client ID and secret'
      : creds.snykToken
        ? 'API token'
        : 'not set';
  console.log('  ' + 'Snyk auth:'.padEnd(25) + snykAuth);
  console.log('  GitHub token:            ' + (creds.githubToken ? 'set' : 'not set'));
  console.log('  GitLab token:            ' + (creds.gitlabToken ? 'set' : 'not set'));
  console.log('  Azure DevOps token:      ' + (creds.azureToken ? 'set' : 'not set'));
  console.log('  Bitbucket Server token:  ' + (creds.bitbucketServerToken ? 'set' : 'not set'));
  // Shown as one line: Basic auth needs both halves, so one alone is useless.
  const bbUser = creds.bitbucketCloudUsername;
  const bbToken = creds.bitbucketCloudPassword;
  const bbState = bbUser && bbToken
    ? `set (${bbUser})`
    : bbUser || bbToken
      ? 'INCOMPLETE — needs both email and token'
      : 'not set';
  console.log('  Bitbucket Cloud auth:    ' + bbState);
  // Reports rather than throws on a retired name — status should still be
  // readable when the stored region is what needs fixing.
  const stored = config.defaults?.region;
  const region = !stored
    ? `${DEFAULT_REGION} (default)`
    : isRegion(stored)
      ? stored
      : `${stored} (no longer valid — re-run \`auth login\`)`;
  console.log('  Region:                  ' + region);
}
