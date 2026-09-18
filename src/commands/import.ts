/**
 * The `import` command: resolve, discover, dedup, submit, report.
 *
 * Extracted from cli.ts so it can be imported by a test. cli.ts calls
 * `main()` at module top level, so anything left in it is unreachable from a
 * test file — importing it would run the real CLI as a side effect.
 */
import { getBitbucketCloudAuth } from '../api';
import type { PollProgress } from '../api';
import { storedSourceUrl } from '../config';
import { filterAlreadyImported } from '../dedup';
import { discoverGithubTargets } from '../discover';
import { discoverAzureTargets } from '../discover-azure';
import { discoverBitbucketCloudTargets } from '../discover-bitbucket-cloud';
import { discoverBitbucketServerTargets } from '../discover-bitbucket-server';
import { discoverGitlabTargets } from '../discover-gitlab';
import { describeDiscovery } from '../discovery';
import type { Discovery } from '../discovery';
import { prepareEnv } from '../env';
import { applyTargetFilters } from '../filters';
import { mergeOutcomes, runImport } from '../importer';
import { confirm, isInteractive } from '../prompt';
import type { Region } from '../regions';
import { hasFailures, printSummary } from '../report';
import { describeMissingIntegration, makeSnykApiClient, resolveIntegration } from '../snyk';
import { normalizeSourceUrl, normalizeStoredSourceUrl } from '../source-url';
import { BRANCH_UNSUPPORTED, GITHUB_CLOUD_APP_SOURCE, KNOWN_UNSUPPORTED, REQUIRES_SOURCE_URL, SOURCES } from '../sources';
import { describeTarget } from '../target-format';
import { resolveTargetOrg } from './org';

/** "1m 30s" / "45s" — short enough to sit inside a status line. */
export function formatElapsed(ms: number): string {
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
export function reportProgress({ completed, total, elapsedMs }: PollProgress): void {
  const scope = total > 1 ? ` — ${completed}/${total} repos done` : '';
  console.log(`  … still scanning (${formatElapsed(elapsedMs)})${scope}`);
}

/** Excluded repos, capped: the point is to spot a greedy glob, not to page. */
export function listExcluded(paths: readonly string[], cap = 10): string {
  const shown = paths.slice(0, cap).join(', ');
  return paths.length > cap ? `${shown} … and ${paths.length - cap} more` : shown;
}

export interface ImportArgs {
  source?: string;
  snykOrg?: string;
  snykOrgId?: string;
  sourceOrg?: string;
  region?: Region;
  sourceUrl?: string;
  /** Import this branch instead of each repo's default. */
  branch?: string;
  /** Glob patterns for repos to leave alone; already flattened and trimmed. */
  exclude?: string[];
  yes: boolean;
  dryRun: boolean;
}

/**
 * Discover repos for whichever --source was selected. Each SCM has its own
 * discovery function (different auth, different target shape — see the
 * discover-*.ts files); this just routes to the right one. `sourceUrl` is
 * guaranteed present for sources that require it (checked earlier).
 */
export async function discoverForSource(
  source: string,
  sourceOrg: string,
  orgId: string,
  integrationId: string,
  sourceUrl: string | undefined,
): Promise<Discovery> {
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
export function checkSourceCredential(source: string): void {
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

export async function importCmd(args: ImportArgs): Promise<void> {
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
  // A host stored by `auth login` stands in for the flag, since a self-hosted
  // URL never changes. The flag still wins, so a one-off run can override it.
  // Both are validated: the flag as typed, and the stored value because a
  // config written before URLs were checked can still hold a bad one.
  const stored = storedSourceUrl(args.source);
  const sourceUrl =
    args.sourceUrl !== undefined
      ? normalizeSourceUrl(args.sourceUrl, '--source-url')
      : stored === undefined
        ? undefined
        : normalizeStoredSourceUrl(stored, args.source);
  if (REQUIRES_SOURCE_URL.has(args.source) && !sourceUrl) {
    throw new Error(
      `--source-url is required for --source ${args.source} (e.g. https://ghe.example.com), ` +
        'or store it once with `auth login`.\n' +
        'Without it, discovery would either fail outright or silently query the wrong public host.',
    );
  }

  // Checked before anything is resolved or discovered: a flag this source can
  // never honour should cost nothing to find out about.
  const branchProblem = args.branch ? BRANCH_UNSUPPORTED[args.source] : undefined;
  if (branchProblem) {
    throw new Error(
      `--branch is not supported for --source ${args.source}: ${branchProblem}.\n` +
        'Re-run without --branch to import the default branch of each repository.',
    );
  }

  prepareEnv(args.region);
  checkSourceCredential(args.source);

  // One client for the whole run: org resolution, the integration lookup,
  // dedup, the import and the polling all share its pacing budget.
  const rm = makeSnykApiClient('snyk-autoimport:import');
  const org = await resolveTargetOrg(rm, args);
  const { id: integrationId } = await resolveIntegration(
    rm,
    org.id,
    args.source,
  );
  if (!integrationId) {
    // Two different problems with two different fixes: an org with other
    // integrations usually means the wrong --source was passed, while an org
    // with none needs a setup step in Snyk that this tool cannot perform.
    const label = org.name === org.id ? org.id : `"${org.name}"`;
    throw new Error(
      describeMissingIntegration(label, args.source, SOURCES[args.source].label),
    );
  }
  console.log(`✓ Using ${args.source} integration ${integrationId}`);

  console.log(`Discovering repos in ${args.sourceOrg}...`);
  const discovered = await discoverForSource(
    args.source,
    args.sourceOrg,
    org.id,
    integrationId,
    sourceUrl,
  );
  // --exclude and --branch are applied here, to every source's discovery at
  // once, rather than inside each discover*.ts — see filters.ts.
  const discovery = applyTargetFilters(discovered, {
    branch: args.branch,
    exclude: args.exclude,
  });
  const candidates = discovery.targets;
  console.log(`✓ ${describeDiscovery(discovery)}`);
  if (discovery.excluded.length > 0) {
    // Listed, not just counted: a glob that matched more than intended is
    // invisible in a count, and this is the moment to catch it.
    console.log(`  Excluded by --exclude: ${listExcluded(discovery.excluded)}`);
  }
  if (args.branch) {
    console.log(`  Importing branch "${args.branch}" rather than each default branch.`);
  }

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
    printSummary(canaryOutcome, { source: args.source, branch: args.branch });
    // A stopped run is a failed run: exiting 0 here told CI everything worked.
    process.exitCode = 1;
    console.log(
      `\n⚠ The first repo failed to import — stopping before attempting the ` +
        `remaining ${restTargets.length}. A failure this early usually means something ` +
        `systemic (wrong token or integration), which would likely repeat for every repo.\n` +
        (args.branch
          ? `It can also mean just this repo has no "${args.branch}" branch, in which ` +
            `case the rest may import fine — re-run without --branch, or with a branch ` +
            `they all have.\n`
          : '') +
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
  printSummary(outcome, { source: args.source, branch: args.branch });

  // Exit non-zero when anything failed, so a scheduled run cannot report
  // success while the summary above lists repos that never imported. Set
  // rather than thrown: the summary has already been printed, and re-raising
  // it as an error would print a second, redundant message.
  if (hasFailures(outcome)) {
    process.exitCode = 1;
    console.log(
      '\nExiting 1 because some repos did not import. Re-run to retry just those —\n' +
        'the ones that succeeded are skipped automatically.',
    );
  }
}
