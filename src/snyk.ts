/**
 * Thin adapters over Snyk APIs: a shared requestsManager, org resolution
 * (name/slug -> UUID, failing closed on ambiguity), and integration lookup.
 */
import { requestsManager } from 'snyk-request-manager';
import { listIntegrations, snykRequest, statusOf } from './api';

export interface OrgSummary {
  id: string;
  name: string;
  slug?: string;
  groupName?: string;
}

interface V1OrgsResponse {
  orgs: Array<{
    id: string;
    name: string;
    slug?: string;
    group?: { name?: string } | null;
  }>;
}

export function makeRequestManager(userAgentPrefix = 'snyk-autoimport'): requestsManager {
  return new requestsManager({ userAgentPrefix, period: 1000, maxRetryCount: 3 });
}

/**
 * List every org the credential can see, across all groups (v1 GET /orgs).
 *
 * Goes through `snykRequest` rather than calling the manager directly so that
 * OAuth bearer tokens are attached here too — this is the call `auth login`
 * uses to verify a credential, so a bypass would verify the wrong one.
 */
export async function listAllOrgs(rm: requestsManager): Promise<OrgSummary[]> {
  const res = await snykRequest<V1OrgsResponse>(rm, 'get', '/orgs');

  const statusCode = statusOf(res);
  if (statusCode && statusCode !== 200) {
    throw new Error(`Expected 200 listing orgs, got ${statusCode}`);
  }
  return (res.data?.orgs ?? []).map((o) => ({
    id: o.id,
    name: o.name,
    slug: o.slug,
    groupName: o.group?.name ?? undefined,
  }));
}

export interface OrgResolution {
  status: 'resolved' | 'not_found' | 'ambiguous';
  org?: OrgSummary;
  matches?: OrgSummary[];
}

/** Shared formatting for one ambiguous-org candidate. */
export function formatOrgMatch(m: OrgSummary): string {
  return `${m.id}  (group: ${m.groupName ?? 'none'})`;
}

/**
 * Resolve an org from a name or slug. Never guesses: an exact-name collision
 * (Snyk names are not unique) returns `ambiguous` with all candidates so the
 * caller can prompt or hard-fail. A slug match is treated as unique.
 */
export async function resolveOrg(
  rm: requestsManager,
  query: string,
): Promise<OrgResolution> {
  const orgs = await listAllOrgs(rm);

  const bySlug = orgs.filter((o) => o.slug && o.slug === query);
  if (bySlug.length === 1) return { status: 'resolved', org: bySlug[0] };

  const byName = orgs.filter(
    (o) => o.name.toLowerCase() === query.toLowerCase(),
  );
  if (byName.length === 1) return { status: 'resolved', org: byName[0] };
  if (byName.length > 1) return { status: 'ambiguous', matches: byName };

  return { status: 'not_found' };
}

/** Full map of integration type -> id configured on an org. */
export async function listIntegrationsMap(
  rm: requestsManager,
  orgId: string,
): Promise<Record<string, string>> {
  return (await listIntegrations(rm, orgId)) as Record<string, string>;
}

/**
 * Explain a missing integration, for the org the user actually named.
 *
 * Deliberately does NOT list the org's other integrations or suggest one.
 * Someone running this has a source in mind; offering to import from a
 * different one instead invites importing the wrong repositories into the
 * wrong place. The fix is always the same — connect it in Snyk — so the
 * message says only that.
 *
 * `sourceLabel` is passed in rather than looked up, keeping this free of a
 * dependency on the source registry.
 */
export function describeMissingIntegration(
  orgLabel: string,
  source: string,
  sourceLabel: string,
): string {
  return (
    `Org ${orgLabel} has no "${source}" (${sourceLabel}) integration configured.\n` +
    'Configure it in Snyk for this organization, then try again.'
  );
}

/**
 * Find the integration id for a given source type on an org, e.g. "github"
 * or "github-cloud-app". Returns the id plus the full map (so callers can
 * show what *is* configured when the requested type is missing).
 */
export async function resolveIntegration(
  rm: requestsManager,
  orgId: string,
  source: string,
): Promise<{ id?: string; available: Record<string, string> }> {
  const available = await listIntegrationsMap(rm, orgId);
  return { id: available[source], available };
}
