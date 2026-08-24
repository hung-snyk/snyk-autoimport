/**
 * Deterministic identity for an import target, used to match discovered repos
 * against what already exists in Snyk (see dedup.ts).
 *
 * The key is compared only in memory, between two lists built in the same run,
 * so its exact format is private to this tool — it is never persisted or sent
 * anywhere.
 *
 * GitLab's numeric `id` is deliberately excluded: Snyk's project APIs never
 * return it, so any key including it could never match existing Snyk state.
 * GitLab targets are matched on name + branch instead.
 */
import type { Target } from './types';

const TARGET_PROPS = ['name', 'projectKey', 'repoSlug', 'owner', 'branch'] as const;

export function generateTargetId(
  orgId: string,
  integrationId: string,
  target: Target,
): string {
  const values = TARGET_PROPS.map((prop) => target[prop] ?? '');
  return `${orgId}:${integrationId}:${values.join(':')}`;
}
