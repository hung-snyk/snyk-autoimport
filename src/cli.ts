#!/usr/bin/env node
/**
 * snyk-autoimport — one-command bulk repo import into Snyk.
 *
 * Commands:
 *   auth login | logout | status
 *   integrations  --snyk-org <name>
 *   import  --snyk-org <name> | --snyk-org-id <uuid>
 *           --source github|github-cloud-app|github-enterprise|gitlab|
 *                     azure-repos|bitbucket-server|bitbucket-cloud|
 *                     bitbucket-connect-app
 *           --source-org <org-or-group-or-project-or-workspace>
 *           [--source-url <self-hosted-host>]  [--dry-run]  [--yes]
 */
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

import {
  configFilePath,
  setCredentials,
  clearCredentials,
  loadConfig,
  setRegion,
  credentialKeyForEnvVar,
  legacyConfigFilePath,
  usingLegacyConfig,
  CREDENTIAL_LABELS,
  CREDENTIAL_KEYS,
  CREDENTIAL_ENV_VARS,
  type Credentials,
  type StoredConfig,
} from './config';
import {
  DEFAULT_REGION,
  REGION_API_HOSTS,
  REGIONS,
  isRegion,
  parseRegion,
  type Region,
} from './regions';
import { prepareEnv } from './env';
import {
  makeRequestManager,
  listAllOrgs,
  resolveOrg,
  resolveIntegration,
  listIntegrationsMap,
  formatOrgMatch,
  type OrgSummary,
} from './snyk';
import { assertValidOrgId } from './org-id';
import { discoverGithubTargets } from './discover';
import { discoverGitlabTargets } from './discover-gitlab';
import { discoverAzureTargets } from './discover-azure';
import { discoverBitbucketServerTargets } from './discover-bitbucket-server';
import { discoverBitbucketCloudTargets } from './discover-bitbucket-cloud';
import { filterAlreadyImported } from './dedup';
import { runImport, mergeOutcomes } from './importer';
import { SOURCES, REQUIRES_SOURCE_URL, KNOWN_UNSUPPORTED, GITHUB_CLOUD_APP_SOURCE } from './sources';
import { printSummary } from './report';
import { describeTarget } from './target-format';
import { ask, askSecret, confirm, isInteractive } from './prompt';
import { verifyScmCredential, type VerifyResult } from './verify';
import {
  getBitbucketCloudAuth,
  describeError,
  formatError,
  type ImportTarget,
  type PollProgress,
} from './api';

/** "1m 30s" / "45s" — short enough to sit inside a status line. */
function formatElapsed(ms: number): string {
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${String(seconds % 60).padStart(2, '0')}s`;
}

/**
 * Heartbeat while Snyk scans. Without it the CLI prints "Importing..." and
 * then nothing for minutes, which is indistinguishable from a hung process.
 * Plain appended lines rather than an in-place spinner, so piped output and
 * CI logs stay readable.
 */
function reportProgress({ completed, total, elapsedMs }: PollProgress): void {
  const scope = total > 1 ? ` — ${completed}/${total} repos done` : '';
  console.log(`  … still scanning (${formatElapsed(elapsedMs)})${scope}`);
}

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

/** Require one of the supported sources, re-prompting until a valid pick. */
async function promptForSource(): Promise<string> {
  const names = Object.keys(SOURCES);
  console.log('\nWhich source will you import from?');
  names.forEach((name, i) => {
    const note = REQUIRES_SOURCE_URL.has(name) ? '  (needs --source-url)' : '';
    console.log(`  [${i + 1}] ${name}${note}`);
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
 * Confirm a Snyk token actually works, by listing the organizations it can
 * see. Done before asking anything else, so a wrong or expired token is caught
 * here rather than after the user has picked a source and pasted a second
 * secret — and rather than at the start of a real import.
 */
async function verifySnykToken(): Promise<
  { ok: true; orgCount: number } | { ok: false; reason: string }
> {
  try {
    const orgs = await listAllOrgs(makeRequestManager('snyk-autoimport:auth'));
    return { ok: true, orgCount: orgs.length };
  } catch (error) {
    const detail = describeError(error);
    const reason =
      detail.status === 401
        ? 'the token was rejected (401). Check you pasted it whole, and that it matches the region above.'
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

/** Prompt for a Snyk token and verify it, re-prompting while it fails. */
async function promptAndVerifySnykToken(
  existing: Credentials,
): Promise<string | undefined> {
  for (;;) {
    const entered = await askSecret(secretPrompt('snykToken', existing));
    const effective = entered || existing.snykToken;
    if (!effective) {
      throw new Error(
        'A Snyk API token is required. Get one from https://app.snyk.io/account',
      );
    }

    // Publish it for the check below; prepareEnv would otherwise read the old
    // stored value, which is exactly what we are trying to replace.
    process.env.SNYK_TOKEN = effective;

    process.stdout.write('  Checking token... ');
    const result = await verifySnykToken();
    if (result.ok) {
      console.log(
        `✓ valid (${result.orgCount} organization${result.orgCount === 1 ? '' : 's'} visible)`,
      );
      return entered || undefined;
    }

    console.log(`✗ ${result.reason}`);
    const retry = await confirm('  Enter a different token?');
    if (!retry) {
      throw new Error('Stopped without a working Snyk token — nothing was saved.');
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

async function authLogin(): Promise<void> {
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

  // 2. Snyk token, verified before going any further.
  console.log('');
  const creds: Credentials = {};
  const snykToken = await promptAndVerifySnykToken(existing);
  if (snykToken) creds.snykToken = snykToken;

  // 3. Which source, and its credential(s), also verified.
  const source = await promptForSource();
  if (usesBitbucketCloudAuth(source)) {
    Object.assign(creds, await promptBitbucketCloud(existing));
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
  for (const key of CREDENTIAL_KEYS) {
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

  // 4. Everything is entered and checked — now say what happened and where it
  //    went. Leading with a file path told the user nothing they could act on.
  console.log('');
  if (region) console.log(`✓ Region set to ${region}.`);
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

function authStatus(): void {
  const config = loadConfig();
  const creds = config.credentials ?? {};
  console.log('Config file: ' + configFilePath());
  if (usingLegacyConfig()) {
    console.log(
      '  ⚠ Still reading the previous location, ' + legacyConfigFilePath() + '.\n' +
        '    Run `auth login` to store them at the path above, then delete the old file.',
    );
  }
  console.log('  Snyk token:              ' + (creds.snykToken ? 'set' : 'not set'));
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

/**
 * Resolve the Snyk org. --snyk-org-id skips lookup entirely; --snyk-org always
 * re-resolves against the current token's live org list (no caching) so a
 * stale mapping can never silently override current access or a genuinely
 * new ambiguity.
 */
async function resolveTargetOrg(args: {
  snykOrgId?: string;
  snykOrg?: string;
  yes: boolean;
}): Promise<OrgSummary> {
  if (args.snykOrgId) {
    assertValidOrgId(args.snykOrgId, '--snyk-org-id');
    return { id: args.snykOrgId, name: args.snykOrgId };
  }
  if (!args.snykOrg) {
    throw new Error('Provide --snyk-org "<name>" or --snyk-org-id <uuid>.');
  }

  const rm = makeRequestManager();
  const result = await resolveOrg(rm, args.snykOrg);

  if (result.status === 'resolved' && result.org) {
    console.log(
      `✓ Resolved "${args.snykOrg}" → ${result.org.id}` +
        (result.org.groupName ? ` (group: ${result.org.groupName})` : ''),
    );
    return result.org;
  }

  if (result.status === 'not_found') {
    throw new Error(
      `No Snyk org matched "${args.snykOrg}". Check the name/slug, or pass --snyk-org-id.`,
    );
  }

  // Ambiguous — never guess.
  const matches = result.matches ?? [];
  if (args.yes || !isInteractive()) {
    const lines = matches.map((m) => `    ${formatOrgMatch(m)}`).join('\n');
    throw new Error(
      `Ambiguous org name "${args.snykOrg}" — ${matches.length} matches. ` +
        `Re-run with --snyk-org-id:\n${lines}`,
    );
  }

  console.log(`Multiple orgs named "${args.snykOrg}":`);
  matches.forEach((m, i) => {
    console.log(`  [${i + 1}] ${formatOrgMatch(m)}`);
  });
  const choice = parseInt(await ask('Pick one (number): '), 10);
  const picked = matches[choice - 1];
  if (!picked) throw new Error('Invalid selection.');
  return picked;
}

interface ImportArgs {
  source?: string;
  snykOrg?: string;
  snykOrgId?: string;
  sourceOrg?: string;
  region?: Region;
  sourceUrl?: string;
  yes: boolean;
  dryRun: boolean;
}

/**
 * Discover repos for whichever --source was selected. Each SCM has its own
 * discovery function (different auth, different target shape — see the
 * discover-*.ts files); this just routes to the right one. `sourceUrl` is
 * guaranteed present for sources that require it (checked earlier).
 */
async function discoverForSource(
  source: string,
  sourceOrg: string,
  orgId: string,
  integrationId: string,
  sourceUrl: string | undefined,
): Promise<ImportTarget[]> {
  switch (source) {
    case 'github':
    case GITHUB_CLOUD_APP_SOURCE:
    case 'github-enterprise':
      return discoverGithubTargets({ githubOrg: sourceOrg, orgId, integrationId, host: sourceUrl });
    case 'gitlab':
      return discoverGitlabTargets({ groupName: sourceOrg, orgId, integrationId, host: sourceUrl });
    case 'azure-repos':
      return discoverAzureTargets({ orgName: sourceOrg, orgId, integrationId, host: sourceUrl });
    case 'bitbucket-server':
      return discoverBitbucketServerTargets({ projectName: sourceOrg, orgId, integrationId, host: sourceUrl! });
    case 'bitbucket-cloud':
    case 'bitbucket-connect-app':
      // Same Bitbucket Cloud API either way; only the Snyk integration differs.
      return discoverBitbucketCloudTargets({ workspace: sourceOrg, orgId, integrationId });
    default:
      // Unreachable: importCmd validates args.source against SOURCES first.
      throw new Error(`No discovery wired up for source "${source}".`);
  }
}

/** Verify the credential this source's discovery needs is actually present. */
function checkSourceCredential(source: string): void {
  const token = SOURCES[source].token;
  if ('special' in token) {
    // Bitbucket Cloud: multi-method, checked by trying to resolve it —
    // getBitbucketCloudAuth() already throws a clear, specific message
    // naming exactly which env vars are missing.
    getBitbucketCloudAuth();
    return;
  }
  if (!process.env[token.envVar]) {
    throw new Error(
      `No ${token.envVar} found. Run \`snyk-autoimport auth login\`, or set ${token.envVar}.`,
    );
  }
}

async function importCmd(args: ImportArgs): Promise<void> {
  if (!args.source) {
    throw new Error(
      `Provide --source (${Object.keys(SOURCES).join(' | ')}). ` +
        `Not sure which? Run 'snyk-autoimport integrations --snyk-org "<name>"' first ` +
        `to see what's configured on the org — never guessed automatically, since an ` +
        `org can have more than one integration of the same family configured at once.`,
    );
  }
  const sourceDef = SOURCES[args.source];
  if (!sourceDef) {
    if (KNOWN_UNSUPPORTED[args.source]) {
      throw new Error(`Source "${args.source}" is not supported: ${KNOWN_UNSUPPORTED[args.source]}`);
    }
    throw new Error(
      `Source "${args.source}" is not supported yet. Available: ${Object.keys(SOURCES).join(', ')}.`,
    );
  }
  if (!args.sourceOrg) {
    throw new Error('Provide --source-org <org-or-group-or-project-or-workspace>.');
  }
  if (REQUIRES_SOURCE_URL.has(args.source) && !args.sourceUrl) {
    throw new Error(
      `--source-url is required for --source ${args.source} (e.g. https://ghe.example.com). ` +
        'Without it, discovery would either fail outright or silently query the wrong public host.',
    );
  }

  prepareEnv(args.region);
  checkSourceCredential(args.source);

  const org = await resolveTargetOrg(args);

  const rm = makeRequestManager('snyk-autoimport:import');
  const { id: integrationId, available } = await resolveIntegration(
    rm,
    org.id,
    args.source,
  );
  if (!integrationId) {
    const configured = Object.keys(available);
    throw new Error(
      `Org ${org.id} has no "${args.source}" integration.\n` +
        `Configured integrations: ${configured.length ? configured.join(', ') : '(none)'}.\n` +
        `Set --source to one of those (e.g. --source github-cloud-app), or configure it in Snyk.`,
    );
  }
  console.log(`✓ Using ${args.source} integration ${integrationId}`);

  console.log(`Discovering repos in ${args.sourceOrg}...`);
  const candidates = await discoverForSource(
    args.source,
    args.sourceOrg,
    org.id,
    integrationId,
    args.sourceUrl,
  );
  console.log(`✓ Found ${candidates.length} repo(s)`);

  const { toImport, alreadyImported } = await filterAlreadyImported(
    rm,
    org.id,
    candidates,
    sourceDef.dedupType,
  );
  console.log(
    `✓ ${alreadyImported} already imported — ${toImport.length} new to import`,
  );

  if (toImport.length === 0) {
    console.log('\nNothing to import. All discovered repos are already in Snyk.');
    return;
  }

  if (args.dryRun) {
    console.log(`\nDry run — would import ${toImport.length} repo(s) into ${org.name}:`);
    for (const t of toImport.slice(0, 50)) {
      console.log(`  - ${describeTarget(t.target)}`);
    }
    if (toImport.length > 50) console.log(`  ... and ${toImport.length - 50} more`);
    console.log('\nNo changes made. Re-run without --dry-run to import.');
    return;
  }

  if (!args.yes) {
    if (!isInteractive()) {
      throw new Error('Refusing to import without confirmation. Pass --yes in non-interactive use.');
    }
    const ok = await confirm(
      `Import ${toImport.length} repo(s) into ${org.name}?`,
    );
    if (!ok) {
      console.log('Aborted.');
      return;
    }
  }

  console.log(
    '\nImporting... Snyk clones each repo and scans it for manifests, which ' +
      'usually takes a few minutes.',
  );

  // Canary: submit the first target alone before the rest. A failure on the
  // very first repo is almost always systemic (wrong token or integration) and
  // would repeat for every remaining repo, so stopping here turns a long run of
  // identical failures into one clear message.
  const [canaryTarget, ...restTargets] = toImport;
  const canaryOutcome = await runImport(rm, [canaryTarget], {
    onProgress: reportProgress,
  });

  if (canaryOutcome.kickoffFailures > 0) {
    printSummary(canaryOutcome, { source: args.source });
    console.log(
      `\n⚠ The first repo failed to import — stopping before attempting the ` +
        `remaining ${restTargets.length}. A failure this early usually means something ` +
        `systemic (wrong token or integration), which would likely repeat for every repo.\n` +
        `Fix the issue above, then re-run — already-imported repos are skipped automatically.`,
    );
    return;
  }

  let outcome = canaryOutcome;
  if (restTargets.length > 0) {
    const restOutcome = await runImport(rm, restTargets, {
      onProgress: reportProgress,
    });
    outcome = mergeOutcomes(canaryOutcome, restOutcome);
  }
  printSummary(outcome, { source: args.source });
}

async function integrationsCmd(args: {
  snykOrg?: string;
  snykOrgId?: string;
  region?: Region;
}): Promise<void> {
  prepareEnv(args.region); // needs SNYK_TOKEN only
  const org = await resolveTargetOrg({ ...args, yes: false });
  const rm = makeRequestManager('snyk-autoimport:integrations');
  const map = await listIntegrationsMap(rm, org.id);
  const entries = Object.entries(map);
  console.log(`Integrations configured on ${org.name} (${org.id}):`);
  if (entries.length === 0) {
    console.log('  (none)');
    return;
  }
  for (const [type, id] of entries) {
    const usable = SOURCES[type] ? '  ← usable as --source ' + type : '';
    console.log(`  ${type}: ${id}${usable}`);
  }
}

const REGION_DESCRIBE = `Snyk region: ${REGIONS.join(' | ')} (default ${DEFAULT_REGION})`;

/** Validate --region eagerly so a typo fails before any API call. */
function optionalRegion(value: string | undefined): Region | undefined {
  return value === undefined ? undefined : parseRegion(value);
}

async function main(): Promise<void> {
  // yargs 16 has no parseAsync; capture the handler's promise and await it
  // after parse() so errors propagate to the top-level catch.
  let pending: Promise<void> | undefined;

  yargs(hideBin(process.argv))
    .scriptName('snyk-autoimport')
    .command(
      'auth <action>',
      'Manage stored credentials',
      (y) =>
        y.positional('action', {
          choices: ['login', 'logout', 'status'] as const,
          demandOption: true,
        }),
      (a) => {
        pending = (async () => {
          const action = a.action as string;
          if (action === 'login') await authLogin();
          else if (action === 'logout') {
            clearCredentials();
            console.log('✓ Credentials cleared.');
          } else authStatus();
        })();
      },
    )
    .command(
      'integrations',
      'List the integrations configured on a Snyk org (diagnostic)',
      (y) =>
        y
          .option('snyk-org', { type: 'string', describe: 'Snyk org name or slug' })
          .option('snyk-org-id', { type: 'string', describe: 'Snyk org UUID' })
          .option('region', { type: 'string', describe: REGION_DESCRIBE }),
      (a) => {
        pending = (async () =>
          integrationsCmd({
            snykOrg: a['snyk-org'] as string | undefined,
            snykOrgId: a['snyk-org-id'] as string | undefined,
            region: optionalRegion(a.region as string | undefined),
          }))();
      },
    )
    .command(
      'import',
      'Discover, dedup, and import repos into a Snyk org',
      (y) =>
        y
          .option('source', {
            type: 'string',
            describe:
              'SCM source: github | github-cloud-app | github-enterprise | gitlab | ' +
              'azure-repos | bitbucket-server | bitbucket-cloud. ' +
              'Required — never guessed, since an org may have more than one configured. ' +
              'Run the `integrations` command first if unsure.',
          })
          .option('snyk-org', { type: 'string', describe: 'Snyk org name or slug' })
          .option('snyk-org-id', { type: 'string', describe: 'Snyk org UUID (skips name lookup)' })
          .option('source-org', {
            type: 'string',
            alias: 'github-org',
            describe: 'Org/group/project/workspace to import from, within --source',
          })
          .option('region', { type: 'string', describe: REGION_DESCRIBE })
          .option('source-url', { type: 'string', describe: 'Self-hosted host URL (required for github-enterprise and bitbucket-server)' })
          .option('yes', { type: 'boolean', default: false, describe: 'Skip confirmation (for CI)' })
          .option('dry-run', { type: 'boolean', default: false, describe: 'Show the plan; create nothing' }),
      (a) => {
        pending = (async () =>
          importCmd({
            source: a.source as string | undefined,
            snykOrg: a['snyk-org'] as string | undefined,
            snykOrgId: a['snyk-org-id'] as string | undefined,
            sourceOrg: a['source-org'] as string | undefined,
            region: optionalRegion(a.region as string | undefined),
            sourceUrl: a['source-url'] as string | undefined,
            yes: a.yes as boolean,
            dryRun: a['dry-run'] as boolean,
          }))();
      },
    )
    .demandCommand(1, 'Specify a command: auth or import')
    .strict()
    .help()
    .parse();

  await pending;
}

main().catch((err: Error) => {
  console.error(`\nError: ${err.message}`);
  process.exit(1);
});
