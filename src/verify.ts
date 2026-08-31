/**
 * Confirm an SCM credential works, at the end of `auth login`.
 *
 * The point is to fail here rather than at the start of a real import. Each
 * check hits the lightest endpoint that proves the credential is accepted, and
 * where possible one that exercises the same permission discovery needs.
 *
 * Some sources genuinely cannot be checked at this stage, and say so rather
 * than guessing: the self-hosted ones need a host that is only supplied at
 * import time (`--source-url`), and an Azure PAT scoped to Code alone is
 * rejected by every account-level endpoint, so a failure there would say
 * nothing about whether discovery will work.
 */
import type { requestsManager } from 'snyk-request-manager';
import { getBitbucketCloudAuth } from './scm/bitbucket-cloud';
import { basicAuth, scmGet, ScmError } from './scm/http';
import { mapWithConcurrency } from './snyk/async';
import { listIntegrationsMap, type OrgSummary } from './snyk';

export type VerifyResult =
  | { status: 'ok'; detail: string }
  | { status: 'failed'; reason: string }
  | { status: 'skipped'; reason: string };

/** Why a given source cannot be verified without more input than login has. */
const UNVERIFIABLE: Record<string, string> = {
  'github-enterprise':
    'verifying needs your GitHub Enterprise host, which is supplied at import time via --source-url',
  'bitbucket-server':
    'verifying needs your Bitbucket Server host, which is supplied at import time via --source-url',
  'azure-repos':
    'an Azure PAT scoped to Code only is rejected by account-level endpoints, so a check here would prove nothing',
};

function describeScmFailure(error: unknown): string {
  if (error instanceof ScmError) {
    if (error.status === 401) return 'the credential was rejected (401)';
    if (error.status === 403) return 'authenticated, but access was denied (403) — check the token scopes';
    return error.message;
  }
  return error instanceof Error ? error.message : 'unknown error';
}

async function verifyGithub(token: string): Promise<VerifyResult> {
  const { body } = await scmGet<{ login?: string }>(
    'https://api.github.com/user',
    { authorization: `token ${token}`, 'x-github-api-version': '2022-11-28' },
    'GitHub credential check',
    { maxAttempts: 2 },
  );
  return { status: 'ok', detail: body.login ? `authenticated as ${body.login}` : 'accepted' };
}

async function verifyGitlab(token: string): Promise<VerifyResult> {
  const { body } = await scmGet<{ username?: string }>(
    'https://gitlab.com/api/v4/user',
    { 'private-token': token },
    'GitLab credential check',
    { maxAttempts: 2 },
  );
  return {
    status: 'ok',
    detail: body.username ? `authenticated as ${body.username}` : 'accepted',
  };
}

/**
 * Reads the account rather than listing repositories.
 *
 * Listing would be the better test — it is the permission discovery needs —
 * but Bitbucket has retired every workspace-agnostic form of it: both
 * `/2.0/repositories?role=member` and plain `/2.0/repositories` now answer
 * **410 Gone** (verified live), and the surviving form needs a workspace name,
 * which login does not ask for.
 *
 * `/2.0/user` still works and distinguishes the case that matters: Bitbucket
 * answers 401 for a bad credential and 403 for a good one whose scopes are
 * narrow. Only the first is a real failure — discovery does not need `account`.
 */
async function verifyBitbucketCloud(): Promise<VerifyResult> {
  const config = getBitbucketCloudAuth();
  const headers =
    config.type === 'user'
      ? { authorization: basicAuth(config.username, config.password) }
      : { authorization: `Bearer ${config.token}` };

  try {
    const { body } = await scmGet<{ display_name?: string; username?: string }>(
      'https://api.bitbucket.org/2.0/user',
      headers,
      'Bitbucket Cloud credential check',
      { maxAttempts: 2 },
    );
    const who = body.display_name ?? body.username;
    return { status: 'ok', detail: who ? `authenticated as ${who}` : 'accepted' };
  } catch (error) {
    if (error instanceof ScmError && error.status === 403) {
      return {
        status: 'ok',
        detail: 'accepted (no account scope, which discovery does not need)',
      };
    }
    throw error;
  }
}

export async function verifyScmCredential(source: string): Promise<VerifyResult> {
  const skip = UNVERIFIABLE[source];
  if (skip) return { status: 'skipped', reason: skip };

  try {
    switch (source) {
      case 'github':
      case 'github-cloud-app':
        return await verifyGithub(process.env.GITHUB_TOKEN ?? '');
      case 'gitlab':
        return await verifyGitlab(process.env.GITLAB_TOKEN ?? '');
      case 'bitbucket-cloud':
      case 'bitbucket-connect-app':
        return await verifyBitbucketCloud();
      default:
        return { status: 'skipped', reason: 'no check implemented for this source' };
    }
  } catch (error) {
    return { status: 'failed', reason: describeScmFailure(error) };
  }
}

/**
 * How many organizations to inspect when looking for an integration.
 *
 * Measured cost: ~166 ms per organization with requests in flight together, so
 * 25 lands around 4-8 seconds — acceptable for something blocking a prompt,
 * where 200 organizations would be over 30 seconds.
 *
 * The cap makes a "found nothing" answer INCONCLUSIVE rather than negative,
 * which callers must respect: `exhaustive` below is false when there were more
 * organizations than were checked, and finding nothing in that case is not
 * evidence that the integration is missing.
 */
const MAX_ORGS_TO_CHECK = 25;

export interface IntegrationCheck {
  /** Organizations that have this source's integration configured. */
  configuredIn: OrgSummary[];
  orgsChecked: number;
  orgsTotal: number;
  /**
   * True when every organization was checked. When false, an empty
   * `configuredIn` means "not found in the ones we looked at" — NOT "not
   * configured". Treating those the same would block a user whose
   * organization simply sorted past the cap.
   */
  exhaustive: boolean;
}

/**
 * Find which organizations have a given source configured.
 *
 * `auth login` collects credentials, not a target organization, and
 * integrations are per-organization — so rather than asking for one, this
 * looks across everything the token can see. The result doubles as useful
 * information: it names the organizations the chosen source can import into.
 *
 * An organization that cannot be read is skipped rather than failing the whole
 * check; a token with partial access is normal.
 */
export async function findOrgsWithIntegration(
  rm: requestsManager,
  source: string,
  orgs: readonly OrgSummary[],
): Promise<IntegrationCheck> {
  const toCheck = orgs.slice(0, MAX_ORGS_TO_CHECK);
  const configuredIn: OrgSummary[] = [];

  await mapWithConcurrency(toCheck, 5, async (org) => {
    try {
      const integrations = await listIntegrationsMap(rm, org.id);
      if (integrations[source]) configuredIn.push(org);
    } catch {
      // No access to this org's settings — not evidence either way.
    }
  });

  return {
    configuredIn,
    orgsChecked: toCheck.length,
    orgsTotal: orgs.length,
    exhaustive: toCheck.length === orgs.length,
  };
}
