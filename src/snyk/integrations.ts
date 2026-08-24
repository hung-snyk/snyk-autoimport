/**
 * Integration lookup: GET /org/{orgId}/integrations
 *
 * Returns a map of integration type -> integration id, e.g.
 * `{ github: "<uuid>", "github-cloud-app": "<uuid>" }`. An org can have more
 * than one SCM integration configured, which is why callers must say which
 * `--source` they mean rather than the tool guessing.
 */
import type { requestsManager } from 'snyk-request-manager';
import { snykRequest, statusOf } from './http';

export type IntegrationsMap = Record<string, string>;

export async function listIntegrations(
  rm: requestsManager,
  orgId: string,
): Promise<IntegrationsMap> {
  if (!orgId) {
    throw new Error('Missing required parameter: orgId.');
  }

  const res = await snykRequest<IntegrationsMap>(
    rm,
    'get',
    `/org/${orgId.trim()}/integrations`,
  );

  const status = statusOf(res);
  if (status && status !== 200) {
    throw new Error(`Expected 200 listing integrations, got ${status}.`);
  }
  return res.data ?? {};
}
