/**
 * Azure DevOps repo discovery.
 *
 * Azure nests repos under projects, so one "org" is two levels: list the
 * org's projects, then each project's repos. Snyk's target treats the Azure
 * *project* name as the owner.
 *
 * API version 4.1 is pinned to match what Snyk's integration expects.
 */
import { basicAuth, requireEnv, scmGet } from './http';
import type { AzureRepoData } from './types';

const API_VERSION = '4.1';

interface AzureProject {
  id: string;
  name: string;
}

interface AzureListResponse<T> {
  value: T[];
}

interface AzureRepo {
  name: string;
  project: { name: string } | null;
  defaultBranch: string | null;
  isDisabled: boolean;
}

export function azureBaseUrl(host?: string): string {
  return (host ?? 'https://dev.azure.com').replace(/\/$/, '');
}

/** Azure authenticates a PAT as the password of an empty username. */
function authHeaders(token: string): Record<string, string> {
  return { authorization: basicAuth('', token) };
}

export async function listAzureProjects(
  orgName: string,
  host?: string,
): Promise<AzureProject[]> {
  const token = requireEnv('AZURE_TOKEN', 'Azure Repos');
  const baseUrl = azureBaseUrl(host);
  const projects: AzureProject[] = [];
  let continuationToken: string | undefined;

  for (;;) {
    const query = new URLSearchParams({
      stateFilter: 'wellFormed',
      'api-version': API_VERSION,
    });
    if (continuationToken) query.set('continuationToken', continuationToken);

    const { body, headers } = await scmGet<AzureListResponse<AzureProject>>(
      `${baseUrl}/${encodeURIComponent(orgName)}/_apis/projects?${query}`,
      authHeaders(token),
      `Azure projects for "${orgName}"`,
    );

    projects.push(...(body.value ?? []).filter((p) => p.id && p.name));

    // Azure paginates by echoing a continuation token in a response header.
    continuationToken = headers.get('x-ms-continuationtoken') ?? undefined;
    if (!continuationToken || !body.value?.length) return projects;
  }
}

export async function listAzureRepos(
  orgName: string,
  host?: string,
): Promise<AzureRepoData[]> {
  const token = requireEnv('AZURE_TOKEN', 'Azure Repos');
  const baseUrl = azureBaseUrl(host);
  const repos: AzureRepoData[] = [];

  // Sequential on purpose: one org can hold many projects, and this keeps a
  // large discovery from opening a burst of connections against the server.
  for (const project of await listAzureProjects(orgName, host)) {
    const { body } = await scmGet<AzureListResponse<AzureRepo>>(
      `${baseUrl}/${encodeURIComponent(orgName)}/${project.id}/_apis/git/repositories?api-version=${API_VERSION}`,
      authHeaders(token),
      `Azure repos for project "${project.name}"`,
    );

    for (const repo of body.value ?? []) {
      // No default branch means an empty repo; disabled repos cannot be read.
      if (!repo.name || !repo.project?.name || !repo.defaultBranch) continue;
      if (repo.isDisabled) continue;
      repos.push({
        name: repo.name,
        owner: repo.project.name,
        branch: repo.defaultBranch,
      });
    }
  }

  return repos;
}
