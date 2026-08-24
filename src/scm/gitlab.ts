/**
 * GitLab project discovery.
 *
 * Two GitLab-specific details drive the shape of a target:
 *  - the import API accepts only the numeric project id, not a path;
 *  - Snyk's APIs never return that id, so dedup has to match on the
 *    "group/repo" path instead. Both are carried (see discover-gitlab.ts).
 */
import { requireEnv, scmGet } from './http';
import type { GitlabRepoData } from './types';

const PER_PAGE = 100;

interface GitlabApiProject {
  id: number;
  path_with_namespace: string;
  default_branch: string | null;
  archived: boolean;
  namespace: { full_path: string };
  forked_from_project?: unknown;
}

export function gitlabBaseUrl(host?: string): string {
  return (host ?? 'https://gitlab.com').replace(/\/$/, '');
}

export async function listGitlabRepos(
  groupName: string,
  host?: string,
): Promise<GitlabRepoData[]> {
  const token = requireEnv('GITLAB_TOKEN', 'GitLab');
  const baseUrl = gitlabBaseUrl(host);
  const repos: GitlabRepoData[] = [];

  for (let page = 1; ; page++) {
    // The group id may be a nested path ("group/subgroup"), which has to be
    // encoded whole — slashes included — to address a single group.
    const url =
      `${baseUrl}/api/v4/groups/${encodeURIComponent(groupName)}/projects` +
      `?per_page=${PER_PAGE}&page=${page}&with_shared=false`;

    const { body } = await scmGet<GitlabApiProject[]>(
      url,
      { 'private-token': token },
      `GitLab projects for "${groupName}"`,
    );

    for (const project of body) {
      // with_shared=false still returns projects shared *into* the group on
      // some versions; comparing the namespace keeps discovery to this group.
      if (project.namespace?.full_path !== groupName) continue;
      // No default branch means an empty project — nothing to scan.
      if (project.archived || !project.default_branch) continue;
      repos.push({
        id: project.id,
        name: project.path_with_namespace,
        branch: project.default_branch,
        fork: Boolean(project.forked_from_project),
      });
    }

    if (body.length < PER_PAGE) return repos;
  }
}
