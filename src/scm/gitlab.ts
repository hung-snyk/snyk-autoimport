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
 *
 * SUBGROUPS ARE INCLUDED, AND MATCHING IGNORES CASE
 *
 * Both were silent-zero bugs, and they compounded. GitLab resolves a namespace
 * case-insensitively, so `--source-org MyGroup` returned 200 with every
 * project — and the exact-match filter below then dropped all of them, giving
 * "Found 0 repo(s)" and exit 0 (reproduced live 2026-09-18). Separately,
 * `/groups/{id}/projects` omits subgroup projects unless asked, so the normal
 * enterprise layout — `acme/team-a`, `acme/team-b` under `acme` — also
 * discovered nothing.
 *
 * So: `include_subgroups` is on, and a project counts as in-namespace when its
 * path equals the requested one or sits beneath it, compared case-insensitively.
 * Shared projects are still excluded, by `with_shared=false` and by the same
 * test — a project shared into `acme` from `other/thing` is neither.
 */
import { requireEnv, scmGet, ScmError } from './http';
import type { GitlabRepoData } from './types';

const PER_PAGE = 100;
/** A ceiling on paging, so a server that never returns a short page cannot spin. */
const MAX_PAGES = 200;

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

/**
 * Is this project inside the namespace that was asked for?
 *
 * Case-insensitive because GitLab addresses namespaces that way, and prefix
 * aware so a subgroup counts. The `/` guard matters: without it, namespace
 * "acme" would also match "acme-archive".
 */
export function inNamespace(fullPath: string | undefined, namespace: string): boolean {
  if (!fullPath) return false;
  const path = fullPath.toLowerCase();
  const wanted = namespace.toLowerCase().replace(/^\/+|\/+$/g, '');
  return path === wanted || path.startsWith(`${wanted}/`);
}

interface Collected {
  repos: GitlabRepoData[];
  /**
   * Namespaces of projects that were returned but not kept. Empty in the
   * ordinary case; non-empty with no repos means the name matched something
   * other than what the user meant, which is worth saying out loud.
   */
  dropped: Set<string>;
}

async function collectProjects(
  baseUrl: string,
  kind: NamespaceKind,
  namespace: string,
  token: string,
): Promise<Collected> {
  const repos: GitlabRepoData[] = [];
  const dropped = new Set<string>();

  for (let page = 1; page <= MAX_PAGES; page++) {
    // The namespace may be a nested path ("group/subgroup"), which has to be
    // encoded whole — slashes included — to address a single namespace.
    const query = new URLSearchParams({
      per_page: String(PER_PAGE),
      page: String(page),
      // Groups-only: neither has meaning for a user namespace.
      ...(kind === 'groups'
        ? { with_shared: 'false', include_subgroups: 'true' }
        : {}),
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
      if (!inNamespace(project.namespace?.full_path, namespace)) {
        if (project.namespace?.full_path) dropped.add(project.namespace.full_path);
        continue;
      }
      // No default branch means an empty project — nothing to scan.
      if (!project.default_branch) continue;
      repos.push({
        id: project.id,
        name: project.path_with_namespace,
        branch: project.default_branch,
        fork: Boolean(project.forked_from_project),
        archived: project.archived,
      });
    }

    if (body.length < PER_PAGE) return { repos, dropped };
  }

  throw new Error(
    `GitLab returned more than ${MAX_PAGES * PER_PAGE} projects for "${namespace}" ` +
      'without reaching the end, which should not happen. Stopping rather than ' +
      'paging forever.',
  );
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

  let collected: Collected | undefined;
  try {
    collected = await collectProjects(baseUrl, 'groups', namespace, token);
  } catch (error) {
    if (!(error instanceof ScmError) || error.status !== 404) throw error;
  }

  if (!collected) {
    try {
      collected = await collectProjects(baseUrl, 'users', namespace, token);
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

  // Everything GitLab returned belonged somewhere else. Reporting this as an
  // empty result would be indistinguishable from an empty namespace, which is
  // how the case-sensitivity bug stayed invisible.
  if (collected.repos.length === 0 && collected.dropped.size > 0) {
    const seen = [...collected.dropped].sort().slice(0, 5).join(', ');
    throw new Error(
      `GitLab returned projects for "${namespace}", but none of them are in that ` +
        `namespace — they are in: ${seen}.\n` +
        'Check the name: this is what happens when a project path is passed where ' +
        'a group or user namespace was expected.',
    );
  }

  return collected.repos;
}
