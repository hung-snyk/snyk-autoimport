/**
 * What is already imported into a Snyk org, expressed as import targets, so a
 * re-run can skip it (see dedup.ts).
 *
 * Snyk has no API that returns "the targets you imported". What it has is a
 * list of *projects*, each of which encodes its repo in its name:
 *
 *   owner/repo:package.json            -> one manifest in a repo
 *   owner/repo(develop):package.json   -> the same, on a non-default branch
 *   group/sub/repo:package.json        -> GitLab keeps its full path
 *
 * So the repo has to be parsed back out of the project name, per origin. This
 * is what `snyk-api-import` did, and the parsing is ported as-is deliberately:
 * a mismatch that makes a repo look *new* is harmless (the re-import creates
 * no duplicates), while one that makes a repo look *already imported* silently
 * skips a repo the user asked for. Faithful beats clever here.
 */
import type { requestsManager } from 'snyk-request-manager';
import { snykRequest, statusOf, type SnykResponse } from './http';
import { SnykProjectOrigin } from './origins';
import type { Target } from './types';

/**
 * Pinned to the version `snyk-api-import` used, which is known to return the
 * attribute names read below. Worth revisiting once this is live-verified.
 */
const PROJECTS_API_VERSION = '2022-09-15~beta';
const PAGE_LIMIT = 100;

interface RestProject {
  id: string;
  attributes: {
    name: string;
    origin: string;
    targetReference: string | null;
    status: string;
  };
}

interface RestProjectsPage {
  data: RestProject[];
  links?: { next?: string };
}

export interface SnykProject {
  name: string;
  origin: string;
  branch: string | null;
}

/**
 * Normalise a pagination link into something the request manager can re-request.
 *
 * Snyk returns `links.next` inconsistently across endpoints — sometimes a bare
 * path, sometimes one already prefixed with `/rest`, sometimes absolute. The
 * manager prepends its own REST base, so any `/rest` prefix here would produce
 * `/rest/rest/...` and 404.
 */
export function restPathFrom(next: string): string {
  let path = next;
  if (/^https?:\/\//i.test(next)) {
    const url = new URL(next);
    path = `${url.pathname}${url.search}`;
  }
  return path.replace(/^\/?rest\//, '/');
}

/** Every project in an org, optionally narrowed to one origin. */
export async function listSnykProjects(
  rm: requestsManager,
  orgId: string,
  origin?: string,
): Promise<SnykProject[]> {
  const query = new URLSearchParams({
    version: PROJECTS_API_VERSION,
    limit: String(PAGE_LIMIT),
  });
  if (origin) query.set('origin', origin);

  const projects: SnykProject[] = [];
  let path: string | undefined = `/orgs/${orgId.trim()}/projects?${query}`;

  while (path) {
    const res: SnykResponse<RestProjectsPage> = await snykRequest<RestProjectsPage>(
      rm,
      'get',
      path,
      {},
      true,
    );
    const status = statusOf(res);
    if (status && status !== 200) {
      throw new Error(`Expected 200 listing projects, got ${status}.`);
    }

    for (const project of res.data?.data ?? []) {
      projects.push({
        name: project.attributes.name,
        origin: project.attributes.origin,
        branch: project.attributes.targetReference,
      });
    }

    const next: string | undefined = res.data?.links?.next;
    path = next ? restPathFrom(next) : undefined;
  }

  return projects;
}

/** Strip the ":manifest/path" suffix, leaving the repo portion of a name. */
function repoPart(projectName: string): string {
  return projectName.split(':')[0];
}

/** Strip a "(branch)" suffix from the repo segment of a name. */
function withoutBranchSuffix(segment: string): string {
  return segment.split('(')[0];
}

/** owner/repo — GitHub family, Azure Repos, Bitbucket Cloud. */
function ownerNameTarget(project: SnykProject): Target | undefined {
  const [owner, name] = repoPart(project.name).split('/');
  if (!owner || !name) return undefined;
  return {
    owner,
    name: withoutBranchSuffix(name),
    branch: project.branch || undefined,
  };
}

/** projectKey/repoSlug, and no branch — Bitbucket Server. */
function bitbucketServerTarget(project: SnykProject): Target | undefined {
  const [projectKey, repoSlug] = repoPart(project.name).split('/');
  if (!projectKey || !repoSlug) return undefined;
  return { projectKey, repoSlug: withoutBranchSuffix(repoSlug) };
}

/**
 * GitLab keeps its whole "group/sub/repo" path as the name, and dedup matches
 * on that path rather than the numeric id Snyk never returns.
 */
function gitlabTarget(project: SnykProject): Target | undefined {
  const name = repoPart(project.name);
  if (!name) return undefined;
  return { name, branch: project.branch || undefined };
}

const TARGET_FROM_PROJECT: Record<SnykProjectOrigin, (p: SnykProject) => Target | undefined> = {
  [SnykProjectOrigin.GITHUB]: ownerNameTarget,
  [SnykProjectOrigin.GITHUB_CLOUD_APP]: ownerNameTarget,
  [SnykProjectOrigin.GHE]: ownerNameTarget,
  [SnykProjectOrigin.AZURE_REPOS]: ownerNameTarget,
  [SnykProjectOrigin.BITBUCKET_CLOUD]: ownerNameTarget,
  [SnykProjectOrigin.BITBUCKET_CLOUD_APP]: ownerNameTarget,
  [SnykProjectOrigin.BITBUCKET_SERVER]: bitbucketServerTarget,
  [SnykProjectOrigin.GITLAB]: gitlabTarget,
};

/** Reconstruct the target a project came from, or undefined if unparseable. */
export function projectToTarget(project: SnykProject): Target | undefined {
  const convert = TARGET_FROM_PROJECT[project.origin as SnykProjectOrigin];
  return convert ? convert(project) : undefined;
}

/**
 * The distinct targets already imported into `orgId` for the given origins.
 *
 * Many projects collapse to one target — a repo with five manifests is five
 * projects and one target — so the result is deduplicated by the caller's key.
 */
export async function listImportedTargets(
  rm: requestsManager,
  orgId: string,
  origins: readonly SnykProjectOrigin[],
): Promise<Target[]> {
  // The API filters by a single origin only, so one call per origin. In
  // practice dedup passes exactly one.
  const wanted = new Set<string>(origins);
  const pages = await Promise.all(
    origins.map((origin) => listSnykProjects(rm, orgId, origin)),
  );

  const targets: Target[] = [];
  for (const project of pages.flat()) {
    // The origin filter is applied server-side, but re-check: an unfiltered
    // response would otherwise be parsed with the wrong origin's rules.
    if (!wanted.has(project.origin)) continue;
    const target = projectToTarget(project);
    if (target) targets.push(target);
  }
  return targets;
}
