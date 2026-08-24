/**
 * Human-readable summaries — the replacement for jq-ing log files.
 */
import type { ImportOutcome } from './importer';
import { isAuthFailure, isNotFoundFailure, type FailureEntry } from './failures';
import { GITHUB_CLOUD_APP_SOURCE } from './sources';
import { describeTarget } from './target-format';

export interface ReportContext {
  /** The --source used, so cloud-app 404s can be explained precisely. */
  source: string;
}

export function printSummary(outcome: ImportOutcome, ctx: ReportContext): void {
  const created = outcome.createdProjects.length;
  const failed = outcome.failedProjects.length;
  const isCloudApp = ctx.source === GITHUB_CLOUD_APP_SOURCE;

  console.log('');
  console.log('Done.');
  console.log(`  ${created} project(s) created`);

  if (outcome.kickoffFailures > 0) {
    const details = outcome.kickoffFailureDetails;
    console.log(`  ${outcome.kickoffFailures} target(s) could not be started:`);
    for (const d of details.slice(0, 25)) {
      console.log(`    - ${describeFailure(d, isCloudApp)}`);
    }
    if (details.length > 25) console.log(`    ... and ${details.length - 25} more`);

    // Consolidated, actionable hints keyed on what actually failed.
    if (isCloudApp && details.some(isNotFoundFailure)) {
      console.log('');
      console.log('  ⚠ 404 on a Cloud App import means the repo is not shared with the');
      console.log('    Snyk GitHub App. In GitHub → org Settings → GitHub Apps → Snyk →');
      console.log('    Configure, grant it access to those repos, then re-run.');
    }
    if (details.some(isAuthFailure)) {
      console.log('');
      console.log('  ⚠ 401 / invalid credentials on import. Common causes:');
      console.log('    • Wrong integration type — run `snyk-autoimport integrations --snyk-org <name>`');
      console.log('      to confirm, and set --source to match (e.g. github-cloud-app).');
      console.log('    • Classic `github` integration needs a PERSONAL Snyk token, not a');
      console.log('      service account. (github-cloud-app works with a service account.)');
    }
  }

  if (failed > 0) {
    console.log(`  ${failed} project(s) failed during import:`);
    for (const f of outcome.failedProjects.slice(0, 25)) {
      const label = f.targetFile || f.projectUrl || f.locationUrl || 'unknown';
      console.log(`    - ${label}`);
    }
    if (failed > 25) console.log(`    ... and ${failed - 25} more`);
  }

  console.log('');
  console.log(
    'Re-run the same command any time — already-imported repos are skipped automatically.',
  );
}

/** One-line per-repo failure description, specialised for the cloud-app 404. */
function describeFailure(d: FailureEntry, isCloudApp: boolean): string {
  const repo = describeTarget(d.target);
  if (isCloudApp && isNotFoundFailure(d)) {
    return `${repo}: not accessible to the Snyk GitHub App (grant it access, then re-run)`;
  }
  return `${repo}: ${d.errorMessage || 'unknown error'}`;
}
