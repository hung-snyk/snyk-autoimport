/**
 * GitLab project discovery.
 *
 * Two GitLab-specific details drive the shape of a target:
 *  - the import API accepts only the numeric project id, not a path;
 *  - Snyk's APIs never return that id, so dedup has to match on the
 *    "group/repo" path instead. Both are carried (see discover-gitlab.ts).
 *
 * A third shapes discovery itself: a GitLab namespace is either a *group* or a
 * *user*, and they are different endpoints. `/groups/{name}` 404s for a
 * personal namespace, so both are tried. This is unlike GitHub, which has no
 * equivalent listing for a personal account and therefore genuinely cannot
 * support one.
 */
import { requireEnv, scmGet, ScmError } from './http';
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

/** GitLab keeps group and user namespaces behind different collections. */
type NamespaceKind = 'groups' | 'users';

async function collectProjects(
  baseUrl: string,
  kind: NamespaceKind,
  namespace: string,
  token: string,
): Promise<GitlabRepoData[]> {
  const repos: GitlabRepoData[] = [];

  for (let page = 1; ; page++) {
    // The namespace may be a nested path ("group/subgroup"), which has to be
    // encoded whole — slashes included — to address a single namespace.
    const query = new URLSearchParams({
      per_page: String(PER_PAGE),
      page: String(page),
      // Groups-only: it has no meaning for a user namespace.
      ...(kind === 'groups' ? { with_shared: 'false' } : {}),
    });
    const url = `${baseUrl}/api/v4/${kind}/${encodeURIComponent(namespace)}/projects?${query}`;

    const { body } = await scmGet<GitlabApiProject[]>(
      url,
      { 'private-token': token },
      `GitLab projects for "${namespace}"`,
    );

    for (const project of body) {
      // Keeps discovery to this namespace: the group endpoint can still return
      // projects shared *into* it on some versions, and the user endpoint
      // returns projects the user owns elsewhere too.
      if (project.namespace?.full_path !== namespace) continue;
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

/**
 * Discover a namespace's projects, whether it is a group or a user.
 *
 * Groups are tried first because that is the common case for an organization;
 * a 404 there means the name is not a group, and personal projects live under
 * `/users/{name}/projects` instead.
 */
export async function listGitlabRepos(
  namespace: string,
  host?: string,
): Promise<GitlabRepoData[]> {
  const token = requireEnv('GITLAB_TOKEN', 'GitLab');
  const baseUrl = gitlabBaseUrl(host);

  try {
    return await collectProjects(baseUrl, 'groups', namespace, token);
  } catch (error) {
    if (!(error instanceof ScmError) || error.status !== 404) throw error;
  }

  try {
    return await collectProjects(baseUrl, 'users', namespace, token);
  } catch (error) {
    if (error instanceof ScmError && error.status === 404) {
      throw new Error(
        `GitLab namespace "${namespace}" was not found as either a group or a ` +
          'user. Check the spelling, and that your GITLAB_TOKEN can see it.',
      );
    }
    throw error;
  }
}
