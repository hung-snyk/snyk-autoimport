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
 *           [--source-url <self-hosted-host>]  [--branch <name>]
 *           [--exclude <glob,...>]  [--dry-run]  [--yes]
 *
 * This file is the yargs wiring and nothing else. Each command's behaviour
 * lives in src/commands/, because this module calls `main()` at top level:
 * anything defined here is unreachable from a test, since importing it would
 * execute the real CLI as a side effect (NOTES §7, landmine 1).
 */
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

import { clearStoredConfig, configFilePath } from './config';
import { DEFAULT_REGION, REGIONS, parseRegion, type Region } from './regions';
import { authLogin, authStatus } from './commands/auth';
import { importCmd } from './commands/import';
import { integrationsCmd } from './commands/integrations';
import { BRANCH_UNSUPPORTED, REQUIRES_SOURCE_URL, SOURCES } from './sources';
import { parseExcludePatterns } from './filters';

/** "a", "a and b", "a, b and c" — for prose that lists a derived set. */
function listInProse(items: readonly string[]): string {
  if (items.length <= 2) return items.join(' and ');
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
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
            clearStoredConfig();
            console.log('✓ Cleared stored credentials, region and server URLs.');
            console.log(`  ${configFilePath()}`);
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
              `SCM source: ${Object.keys(SOURCES).join(' | ')}. ` +
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
          .option('source-url', {
            type: 'string',
            describe: `Self-hosted host URL (required for ${listInProse([...REQUIRES_SOURCE_URL])})`,
          })
          .option('branch', {
            type: 'string',
            describe:
              "Import this branch instead of each repo's default. A repo without " +
              'the branch is not rejected by Snyk — it imports as zero projects, ' +
              'so check the summary. Not available for ' +
              `${listInProse(Object.keys(BRANCH_UNSUPPORTED))}.`,
          })
          .option('exclude', {
            type: 'string',
            array: true,
            describe:
              "Repos to leave alone: glob patterns where '*' matches anything. " +
              "A pattern without '/' matches the repo name, one with '/' the full " +
              "owner/repo path. Repeatable, or comma-separated.",
          })
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
            branch: (a.branch as string | undefined)?.trim() || undefined,
            exclude: parseExcludePatterns(a.exclude as string[] | undefined),
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
