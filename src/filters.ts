/**
 * The two things a user can say about *which* repos and *what* to import:
 * `--exclude` and `--branch`.
 *
 * Applied here, once, to the `Discovery` every provider returns — for the same
 * reason the archived rule lives in discovery.ts rather than in each of the
 * five `discover*.ts` files. A filter implemented per provider drifts, and the
 * failure mode is silent: one source honouring `--exclude` and another
 * ignoring it imports repositories the user asked to leave alone.
 *
 * WHAT `--exclude` MATCHES
 *
 * Two strings are derived per target, because a target's shape differs by SCM
 * (see target-format.ts) and both halves are things people name:
 *
 *   github / azure / bitbucket cloud   path "acme/web"        name "web"
 *   gitlab                             path "acme/team/web"   name "web"
 *   bitbucket server                   path "PROJ/web"        name "web"
 *
 * A pattern containing `/` is matched against the path, one without it against
 * the repo name. That asymmetry is deliberate: matching a bare pattern against
 * the path too would make `--exclude acme` — an organization name — silently
 * exclude every repository in it.
 *
 * `*` is the only metacharacter, and it matches anything including `/`.
 * Everything else is literal, so a repo named `my.repo` needs no escaping and
 * cannot accidentally match `my-repo`.
 *
 * WHAT `--branch` DOES NOT DO
 *
 * It does not check that the branch exists. Verifying would cost one SCM call
 * per repository, and the repos that lack it are reported anyway — Snyk
 * rejects the target and it lands in the failure summary. See NOTES §5.
 */
import type { ImportTarget } from './api';
import type { Discovery } from './discovery';
import type { TargetLike } from './target-format';

export interface TargetFilters {
  /** Import this branch rather than each repo's default. */
  branch?: string;
  /** Glob patterns; a repo matching any one of them is not imported. */
  exclude?: readonly string[];
}

/**
 * Flatten repeated flags and comma-separated lists into one pattern list.
 *
 * Both spellings work because both get used: `--exclude a --exclude b` reads
 * better in a shell, `--exclude a,b` in a CI variable. Empty entries are
 * dropped rather than kept as a pattern that would match nothing — a trailing
 * comma is a typo, not an instruction.
 */
export function parseExcludePatterns(
  values: readonly string[] | string | undefined,
): string[] {
  if (values === undefined) return [];
  const raw = typeof values === 'string' ? [values] : values;
  return raw
    .flatMap((value) => value.split(','))
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
}

/**
 * A glob with `*` as its only metacharacter, anchored and case-insensitive.
 *
 * Split on `*` first, then escape each literal piece. The obvious alternative —
 * one pass that escapes everything and swaps `*` for a placeholder — needs a
 * placeholder no pattern could contain, and the NUL character that seems
 * perfect for the job makes this file binary as far as git is concerned.
 */
export function globToRegExp(pattern: string): RegExp {
  const escaped = pattern
    .split('*')
    .map((literal) => literal.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
    .join('.*');
  return new RegExp(`^${escaped}$`, 'i');
}

/** The path and bare name a pattern can match against, per target shape. */
export function matchStrings(target: TargetLike): { path: string; name: string } {
  if (target.owner && target.name) {
    return { path: `${target.owner}/${target.name}`, name: target.name };
  }
  if (target.projectKey && target.repoSlug) {
    return { path: `${target.projectKey}/${target.repoSlug}`, name: target.repoSlug };
  }
  // GitLab: the name is already the full "group/sub/repo" path.
  const path = target.name ?? '';
  const slash = path.lastIndexOf('/');
  return { path, name: slash === -1 ? path : path.slice(slash + 1) };
}

/** Does this target match any exclude pattern? */
export function isExcluded(
  target: TargetLike,
  patterns: readonly string[],
): boolean {
  if (patterns.length === 0) return false;
  const { path, name } = matchStrings(target);
  return patterns.some((pattern) =>
    globToRegExp(pattern).test(pattern.includes('/') ? path : name),
  );
}

/**
 * Apply `--exclude` and `--branch` to a discovery.
 *
 * Exclusion runs over what is left after archived repos are set aside, so a
 * repo that is both is counted once, as archived. The branch override is
 * applied only to what survives, so nothing is spent describing repos that are
 * not being imported.
 */
export function applyTargetFilters(
  discovery: Discovery,
  filters: TargetFilters,
): Discovery {
  const patterns = filters.exclude ?? [];
  const excluded: string[] = [];
  const kept: ImportTarget[] = [];

  for (const target of discovery.targets) {
    if (isExcluded(target.target, patterns)) {
      excluded.push(matchStrings(target.target).path);
      continue;
    }
    kept.push(
      filters.branch
        ? { ...target, target: { ...target.target, branch: filters.branch } }
        : target,
    );
  }

  return { ...discovery, targets: kept, excluded };
}
