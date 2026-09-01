/**
 * Confirm an SCM credential works, at the end of `auth login`.
 *
 * The point is to fail here rather than at the start of a real import. Each
 * check hits the lightest endpoint that proves the credential is accepted, and
 * where possible one that exercises the same permission discovery needs.
 *
 * A self-hostable source is checked against the host `auth login` stored for
 * it, never a guessed one. Which server answers is part of what is being
 * tested: a token is only valid on the instance that issued it, so checking a
 * self-managed credential against the vendor's public host reports a working
 * token as rejected.
 *
 * Some sources genuinely cannot be checked at this stage, and say so rather
 * than guessing: the ones with no default host are skipped until a URL is
 * stored, and an Azure PAT scoped to Code alone is rejected by every
 * account-level endpoint, so a failure there would say nothing about whether
 * discovery will work.
 */
import { githubBaseUrl } from './scm/github';
import { gitlabBaseUrl } from './scm/gitlab';
import { getBitbucketCloudAuth } from './scm/bitbucket-cloud';
import { bitbucketServerAuthHeader } from './scm/bitbucket-server';
import { basicAuth, scmGet, ScmError } from './scm/http';
import { storedSourceUrl } from './config';

export type VerifyResult =
  | { status: 'ok'; detail: string }
  | { status: 'failed'; reason: string }
  | { status: 'skipped'; reason: string };

/** Why a given source cannot be verified without more input than login has. */
const UNVERIFIABLE: Record<string, string> = {
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

async function verifyGithub(token: string, host?: string): Promise<VerifyResult> {
  const { body } = await scmGet<{ login?: string }>(
    `${githubBaseUrl(host)}/user`,
    { authorization: `token ${token}`, 'x-github-api-version': '2022-11-28' },
    'GitHub credential check',
    { maxAttempts: 2 },
  );
  return { status: 'ok', detail: body.login ? `authenticated as ${body.login}` : 'accepted' };
}

/**
 * Checked against the host the token actually belongs to.
 *
 * GitLab defaults safely to gitlab.com, but self-managed instances are common,
 * and a token issued by one is meaningless to the other. Hardcoding gitlab.com
 * here reported a perfectly good self-managed token as rejected (401) and told
 * the user to go find a different one — the same wrong-turn this file's
 * 401-versus-403 rule exists to prevent, arriving by a different route.
 *
 * The host is echoed back in the detail line so it is visible which server
 * answered, rather than left to be assumed.
 */
async function verifyGitlab(token: string, host?: string): Promise<VerifyResult> {
  const baseUrl = gitlabBaseUrl(host);
  const { body } = await scmGet<{ username?: string }>(
    `${baseUrl}/api/v4/user`,
    { 'private-token': token },
    'GitLab credential check',
    { maxAttempts: 2 },
  );
  const who = body.username ? `authenticated as ${body.username}` : 'accepted';
  return { status: 'ok', detail: host ? `${who} at ${baseUrl}` : who };
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

/**
 * Lists projects, which is the permission discovery needs, against the host
 * stored during login. Unlike the cloud providers there is no fixed endpoint
 * to fall back on, so without a stored host this is skipped rather than
 * guessed at.
 */
async function verifyBitbucketServer(host?: string): Promise<VerifyResult> {
  if (!host) {
    return {
      status: 'skipped',
      reason: 'no Bitbucket Server URL is stored yet — re-run `auth login` to add one',
    };
  }
  const { body } = await scmGet<{ size?: number }>(
    `${host.replace(/\/$/, '')}/rest/api/1.0/projects?limit=1`,
    bitbucketServerAuthHeader(),
    'Bitbucket Server credential check',
    { maxAttempts: 2 },
  );
  return {
    status: 'ok',
    detail:
      typeof body.size === 'number'
        ? `accepted (${body.size} project(s) visible)`
        : 'accepted',
  };
}

/**
 * `hostOverride` stands in for the stored host. It exists so tests can exercise
 * the self-hosted paths without calling `setSourceUrl`, which would write a
 * fake host into the real credential file — see the note in config.ts. Callers
 * in normal use omit it and get whatever `auth login` stored.
 */
export async function verifyScmCredential(
  source: string,
  hostOverride?: string,
): Promise<VerifyResult> {
  const skip = UNVERIFIABLE[source];
  if (skip) return { status: 'skipped', reason: skip };

  // Only consulted by the sources that can be self-hosted. github.com and
  // api.bitbucket.org are single-host, so they deliberately ignore it: a host
  // stored against those could only ever be wrong.
  const host = hostOverride ?? storedSourceUrl(source);

  try {
    switch (source) {
      case 'github':
      case 'github-cloud-app':
        return await verifyGithub(process.env.GITHUB_TOKEN ?? '');
      case 'github-enterprise': {
        // Self-hosted, so there is no endpoint to fall back on: without a
        // stored host, guessing one would test the wrong server entirely.
        if (!host) {
          return {
            status: 'skipped',
            reason:
              'no GitHub Enterprise URL is stored yet — re-run `auth login` to add one',
          };
        }
        return await verifyGithub(process.env.GITHUB_TOKEN ?? '', host);
      }
      case 'gitlab':
        // Unlike the two above, a missing host is not a gap — gitlab.com is a
        // real default — so this checks rather than skips.
        return await verifyGitlab(process.env.GITLAB_TOKEN ?? '', host);
      case 'bitbucket-cloud':
      case 'bitbucket-connect-app':
        return await verifyBitbucketCloud();
      case 'bitbucket-server':
        return await verifyBitbucketServer(host);
      default:
        return { status: 'skipped', reason: 'no check implemented for this source' };
    }
  } catch (error) {
    return { status: 'failed', reason: describeScmFailure(error) };
  }
}
