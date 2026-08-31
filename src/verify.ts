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
  'github-enterprise':
    'verifying needs your GitHub Enterprise host, which is supplied at import time via --source-url',
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

/**
 * Lists projects, which is the permission discovery needs, against the host
 * stored during login. Unlike the cloud providers there is no fixed endpoint
 * to fall back on, so without a stored host this is skipped rather than
 * guessed at.
 */
async function verifyBitbucketServer(): Promise<VerifyResult> {
  const host = storedSourceUrl('bitbucket-server');
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
      case 'bitbucket-server':
        return await verifyBitbucketServer();
      default:
        return { status: 'skipped', reason: 'no check implemented for this source' };
    }
  } catch (error) {
    return { status: 'failed', reason: describeScmFailure(error) };
  }
}
