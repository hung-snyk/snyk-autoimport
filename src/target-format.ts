/**
 * Human-readable label for an import target, whose shape varies by SCM:
 * GitHub-family/Azure/Bitbucket Cloud use {owner, name}, GitLab uses {name}
 * (already "group/repo" formatted) + a separate numeric {id}, Bitbucket
 * Server uses {projectKey, repoSlug}. Shared between the dry-run preview
 * (cli.ts) and failure descriptions (report.ts) so formatting stays in sync.
 */
export interface TargetLike {
  owner?: string;
  name?: string;
  projectKey?: string;
  repoSlug?: string;
  branch?: string;
}

export function describeTarget(target: TargetLike | undefined): string {
  if (!target) return 'unknown';
  const withBranch = (label: string): string =>
    target.branch ? `${label} (${target.branch})` : label;

  if (target.owner && target.name) return withBranch(`${target.owner}/${target.name}`);
  if (target.projectKey && target.repoSlug) return `${target.projectKey}/${target.repoSlug}`;
  if (target.name) return withBranch(target.name);
  return JSON.stringify(target);
}
