/**
 * What discovery hands to the import: the targets to submit, plus what it
 * chose *not* to submit and why, so the CLI can say so.
 *
 * Archived repos are skipped. An archived repo is read-only upstream, so any
 * finding Snyk raised against it is one nobody can fix in place — and Snyk
 * would keep re-scanning it on every schedule. That is a reasonable default,
 * but it is a decision the tool is making on the user's behalf, so it must be
 * visible: `✓ Found 24 repo(s) (6 more archived, skipped)` rather than a count
 * that quietly omits six. Reporting what was inferred is design principle 1.
 *
 * This is the only place the rule is applied. Each provider reports
 * `archived` as data (Azure's equivalent is a disabled repo; Bitbucket Cloud
 * has no such state) and the decision is made here once, so a new provider
 * cannot silently drop or silently include them, and an `--include-archived`
 * flag, should anyone need one, is a one-line change.
 *
 * ---
 *
 * TWO TIERS OF FILTERING, and why only one of them is reported.
 *
 * `scm/` still drops some records before they ever reach here, and that is
 * deliberate rather than a leftover of the drift this module fixed. The line
 * between the two:
 *
 *  - **`scm/` drops what is not importable at all.** A repo with no default
 *    branch is an empty repo: there is no tree for Snyk to clone, so there is
 *    no import to skip. A record missing an owner or a project is a malformed
 *    response. GitLab and Bitbucket Server also drop repos outside the
 *    requested namespace or project — those were never in scope, so counting
 *    them as "skipped" would misreport the scope the user asked for.
 *  - **`discovery.ts` sets aside what IS importable but that we choose not to
 *    import.** Only this is a decision made on the user's behalf, and only
 *    this needs surfacing.
 *
 * So `Found N` is "repos that could be imported", not "repos that exist" —
 * documented in the README, because a GitHub org showing 27 repos and a
 * `Found 24` line is otherwise a discrepancy the user cannot account for.
 *
 * Deliberately NOT unified by having `toDiscovery` filter on a missing branch:
 * an undefined branch means "empty repo" for GitHub, GitLab and Azure, but for
 * Bitbucket Cloud it legitimately means "Snyk picks the repo's default", which
 * is a real and previously-broken case. One shared branch test would silently
 * drop every Bitbucket Cloud repo without a `mainbranch`.
 */
import type { ImportTarget } from './api';

export interface Discovery {
  targets: ImportTarget[];
  /** Repos discovered but not offered for import because they are archived. */
  archived: number;
}

/** Shape discovered repos into import targets, setting archived ones aside. */
export function toDiscovery<R extends { archived?: boolean }>(
  repos: R[],
  toTarget: (repo: R) => ImportTarget,
): Discovery {
  const active = repos.filter((repo) => !repo.archived);
  return {
    targets: active.map(toTarget),
    archived: repos.length - active.length,
  };
}

/**
 * The `✓ Found …` line, with the skipped count only when there is one.
 *
 * "N more" is load-bearing. The count before the parenthetical is what will be
 * considered for import, so the archived ones are *in addition* to it — but
 * `Found 24 repo(s) (2 archived, skipped)` reads just as naturally as "2 of
 * those 24", which would be wrong. `printSummary` has the same problem and
 * solves it the same way, with "N of those".
 */
export function describeDiscovery(discovery: Discovery): string {
  const found = `Found ${discovery.targets.length} repo(s)`;
  return discovery.archived > 0
    ? `${found} (${discovery.archived} more archived, skipped)`
    : found;
}
