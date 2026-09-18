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
  /**
   * The `--branch` override, when one was given.
   *
   * Needed because Snyk does NOT reject a target whose branch does not exist:
   * verified live on 2026-09-15, the import job completes and creates zero
   * projects, exactly as a repo with no manifests does. Without knowing a
   * branch was forced, the summary confidently reports the wrong cause.
   */
  branch?: string;
}

/**
 * Did anything in this run fail?
 *
 * Separate from printing, because the exit code depends on it and the two must
 * agree: a summary that lists failures while the process exits 0 tells a CI
 * pipeline the run succeeded. A repo that imported but produced no projects is
 * deliberately NOT a failure — that is a legitimate outcome for a repo with no
 * manifests, and treating it as one would fail most real runs. The zero-project
 * case is surfaced in the summary text instead (and with --branch, warned about
 * loudly), which is the right place for something ambiguous.
 */
export function hasFailures(outcome: ImportOutcome): boolean {
  return outcome.kickoffFailures > 0 || outcome.failedProjects.length > 0;
}

export function printSummary(outcome: ImportOutcome, ctx: ReportContext): void {
  const created = outcome.createdProjects.length;
  const failed = outcome.failedProjects.length;
  const isCloudApp = ctx.source === GITHUB_CLOUD_APP_SOURCE;

  console.log('');
  console.log('Done.');
  // Repos first: that is the unit the user asked in. Projects second, because
  // one repo yields one per manifest, so the two counts rarely match.
  console.log(
    `  ${outcome.reposImported} of ${outcome.submittedTargets} repo(s) imported` +
      ` — ${created} project(s) created`,
  );
  if (outcome.reposWithoutProjects > 0) {
    // Two indistinguishable causes once --branch is in play, so say both
    // rather than assert the wrong one. Snyk reports a missing branch as a
    // clean import of nothing, not as a failure.
    const cause = ctx.branch
      ? `had no "${ctx.branch}" branch, or no supported manifests on it`
      : 'had no supported manifests';
    console.log(
      `  ${outcome.reposWithoutProjects} of those ${cause}, so produced no projects`,
    );
    if (ctx.branch && outcome.reposWithoutProjects === outcome.reposImported) {
      console.log(
        `  ⚠ Every repo produced nothing, which usually means "${ctx.branch}" does not ` +
          'exist in them.\n' +
          '    Snyk accepts an import for a branch that is missing and creates no ' +
          'projects, so this\n    does not show up as a failure. Check the branch name.',
      );
    }
  }

  if (outcome.kickoffFailures > 0) {
    const details = outcome.kickoffFailureDetails;
    console.log(`  ${outcome.kickoffFailures} repo(s) could not be started:`);
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
