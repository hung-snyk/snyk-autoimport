/**
 * What discovery hands to the import: the targets to submit, plus what it
 * chose *not* to submit and why, so the CLI can say so.
 *
 * Archived repos are skipped. An archived repo is read-only upstream, so any
 * finding Snyk raised against it is one nobody can fix in place — and Snyk
 * would keep re-scanning it on every schedule. That is a reasonable default,
 * but it is a decision the tool is making on the user's behalf, so it must be
 * visible: `✓ Found 24 repo(s) (6 archived, skipped)` rather than a count that
 * quietly omits six. Reporting what was inferred is design principle 1.
 *
 * This is the only place the rule is applied. Each provider reports
 * `archived` as data (Azure's equivalent is a disabled repo; Bitbucket Cloud
 * has no such state) and the decision is made here once, so a new provider
 * cannot silently drop or silently include them, and an `--include-archived`
 * flag, should anyone need one, is a one-line change.
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

/** The `✓ Found …` line, with the skipped count only when there is one. */
export function describeDiscovery(discovery: Discovery): string {
  const found = `Found ${discovery.targets.length} repo(s)`;
  return discovery.archived > 0
    ? `${found} (${discovery.archived} archived, skipped)`
    : found;
}
