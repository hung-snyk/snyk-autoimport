#!/usr/bin/env node
/**
 * snyk-autoimport — one-command bulk repo import into Snyk.
 *
 * Commands:
 *   auth login | logout | status
 *   integrations  --snyk-org <name>
 *   import  --snyk-org <name> | --snyk-org-id <uuid>
 *           --source github|github-cloud-app|github-enterprise|gitlab|
 *                     azure-repos|bitbucket-server|bitbucket-cloud
 *           --source-org <org-or-group-or-project-or-workspace>
 *           [--source-url <self-hosted-host>]  [--dry-run]  [--yes]
 */
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

// Silence Node deprecation warnings (e.g. url.parse) emitted from deep inside
// snyk-api-import's poller — not actionable for our users.
(process as { noDeprecation?: boolean }).noDeprecation = true;

import {
  configFilePath,
  setCredentials,
  clearCredentials,
  loadConfig,
  setRegion,
  type Region,
  type Credentials,
} from './config';
import { prepareEnv } from './env';
import {
  makeRequestManager,
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
import { getBitbucketCloudAuth, type ImportTarget } from './api';

async function authLogin(): Promise<void> {
  if (!isInteractive()) {
    throw new Error('auth login requires an interactive terminal.');
  }
  console.log('Enter credentials (stored at ' + configFilePath() + ', chmod 600).');
  console.log('Leave blank to keep an existing value.\n');

  const snykToken = await askSecret('Snyk API token: ');
  const githubToken = await askSecret('GitHub token (optional, for github/github-cloud-app/github-enterprise): ');
  const gitlabToken = await askSecret('GitLab token (optional, for gitlab): ');
  const azureToken = await askSecret('Azure DevOps token (optional, for azure-repos): ');
  const bitbucketServerToken = await askSecret('Bitbucket Server token (optional, for bitbucket-server): ');
  const currentRegion = loadConfig().defaults?.region ?? 'global';
  const regionInput = (await ask(`Region — global/eu/au [current: ${currentRegion}]: `))
    .trim()
    .toLowerCase();

  const creds: Credentials = {};
  if (snykToken) creds.snykToken = snykToken;
  if (githubToken) creds.githubToken = githubToken;
  if (gitlabToken) creds.gitlabToken = gitlabToken;
  if (azureToken) creds.azureToken = azureToken;
  if (bitbucketServerToken) creds.bitbucketServerToken = bitbucketServerToken;

  let regionChanged = false;
  if (regionInput) {
    if (regionInput !== 'global' && regionInput !== 'eu' && regionInput !== 'au') {
      throw new Error(`Invalid region "${regionInput}". Must be global, eu, or au.`);
    }
    setRegion(regionInput as Region);
    regionChanged = true;
  }

  if (Object.keys(creds).length === 0 && !regionChanged) {
    console.log('Nothing entered — no changes.');
    return;
  }
  if (Object.keys(creds).length > 0) {
    setCredentials(creds);
  }
  console.log(
    '\n✓ Saved. (bitbucket-cloud auth is env-var only — see README — not part of this prompt.)',
  );
}

function authStatus(): void {
  const config = loadConfig();
  const creds = config.credentials ?? {};
  console.log('Config file: ' + configFilePath());
  console.log('  Snyk token:              ' + (creds.snykToken ? 'set' : 'not set'));
  console.log('  GitHub token:            ' + (creds.githubToken ? 'set' : 'not set'));
  console.log('  GitLab token:            ' + (creds.gitlabToken ? 'set' : 'not set'));
  console.log('  Azure DevOps token:      ' + (creds.azureToken ? 'set' : 'not set'));
  console.log('  Bitbucket Server token:  ' + (creds.bitbucketServerToken ? 'set' : 'not set'));
  console.log('  Bitbucket Cloud auth:    env vars only, not shown here (see README)');
  console.log('  Region:                  ' + (config.defaults?.region ?? 'global'));
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

  console.log('\nImporting...');

  // Canary: submit the first target alone before the rest. snyk-api-import
  // kills its own process (process.exit(1), no summary) after ~30 kickoff
  // failures in a row — a scenario that's almost always systemic (wrong
  // token/integration), which a single early failure already reveals. This
  // converts "might die unexplained mid-batch" into "fails fast and clearly."
  const [canaryTarget, ...restTargets] = toImport;
  const canaryOutcome = await runImport(rm, org.id, [canaryTarget]);

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
    const restOutcome = await runImport(rm, org.id, restTargets);
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
          .option('region', { choices: ['global', 'eu', 'au'] as const, describe: 'Snyk region' }),
      (a) => {
        pending = integrationsCmd({
          snykOrg: a['snyk-org'] as string | undefined,
          snykOrgId: a['snyk-org-id'] as string | undefined,
          region: a.region as Region | undefined,
        });
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
          .option('region', { choices: ['global', 'eu', 'au'] as const, describe: 'Snyk region' })
          .option('source-url', { type: 'string', describe: 'Self-hosted host URL (required for github-enterprise and bitbucket-server)' })
          .option('yes', { type: 'boolean', default: false, describe: 'Skip confirmation (for CI)' })
          .option('dry-run', { type: 'boolean', default: false, describe: 'Show the plan; create nothing' }),
      (a) => {
        pending = importCmd({
          source: a.source as string | undefined,
          snykOrg: a['snyk-org'] as string | undefined,
          snykOrgId: a['snyk-org-id'] as string | undefined,
          sourceOrg: a['source-org'] as string | undefined,
          region: a.region as Region | undefined,
          sourceUrl: a['source-url'] as string | undefined,
          yes: a.yes as boolean,
          dryRun: a['dry-run'] as boolean,
        });
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
