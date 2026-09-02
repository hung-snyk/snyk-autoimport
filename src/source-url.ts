/**
 * Self-hosted source URL validation.
 *
 * A host is typed once at `auth login` (or passed as `--source-url`) and then
 * interpolated into every SCM request for that source. Nothing between the
 * prompt and the first request used to check it, so a schemeless
 * `gitlab.acme.internal` was stored as typed and only failed later — as
 * `Failed to parse URL` or a bare `Invalid URL` out of `new URL('/api/v3',
 * host)` — under the heading "the credential did not pass its check", pointing
 * at the token rather than the host. Validating here, where the user can
 * retype it, is the same trust-boundary rule org-id.ts and regions.ts follow.
 *
 * A missing scheme is rejected rather than guessed. Prefixing `https://` would
 * be inferring something the user did not state (design principle 1), and a
 * wrong guess about an on-prem `http://` server would surface as yet another
 * failure attributed to the wrong thing.
 */

function invalid(
  raw: string,
  label: string,
  why: string,
  hint = 'Expected a full URL such as https://scm.example.com.',
): Error {
  return new Error(`Invalid ${label} "${raw}": ${why}. ${hint}`);
}

/**
 * Validate and canonicalise a self-hosted URL, or throw an error that says
 * what is wrong with it. `label` names the input so the message is actionable
 * (`GitLab URL`, `--source-url`).
 *
 * The result keeps any path — Bitbucket Server and Azure DevOps Server can
 * live under a context path — and drops trailing slashes so every consumer
 * can append `/api/...` without checking.
 */
export function normalizeSourceUrl(input: string, label: string): string {
  const raw = input.trim();
  if (!raw) throw invalid(raw, label, 'it is empty');

  // The common mistake, and the one that produced the confusing downstream
  // errors. Diagnosed up front because a bare host fails two different ways:
  // `gitlab.acme.internal` does not parse at all, while `gitlab.acme.internal:8443`
  // parses with `gitlab.acme.internal:` as its scheme.
  if (!raw.includes('://')) {
    throw invalid(raw, label, 'it has no scheme', `Did you mean https://${raw}?`);
  }

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw invalid(raw, label, 'it is not a valid URL');
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw invalid(raw, label, 'only https:// and http:// are supported');
  }
  if (!url.hostname) throw invalid(raw, label, 'it has no host');
  if (url.username || url.password) {
    throw invalid(raw, label, 'it must not embed a username or password — the credential is stored separately');
  }
  if (url.search || url.hash) {
    throw invalid(raw, label, 'it must not include a query string or fragment');
  }

  return url.href.replace(/\/+$/, '');
}

/**
 * Validate a URL that came out of the config file rather than from the user
 * just now.
 *
 * A file written before `normalizeSourceUrl` existed can hold a schemeless
 * host, and using it produces exactly the misattributed failure this module
 * was added to stop. This mirrors `storedRegion()` in env.ts: a stale stored
 * value is a migration problem, and saying so — with the command that fixes
 * it — beats failing later under an unrelated heading.
 *
 * Deliberately NOT called from the `auth login` prompt, which shows the
 * current value only so the user can replace it. Throwing there would block
 * the one command that can fix the bad value.
 */
export function normalizeStoredSourceUrl(url: string, source: string): string {
  try {
    return normalizeSourceUrl(url, `stored ${source} URL`);
  } catch (error) {
    const why = error instanceof Error ? error.message : String(error);
    throw new Error(
      `${why}\nIt was stored by an earlier version, before URLs were checked. ` +
        'Run `snyk-autoimport auth login` to set it again, or pass --source-url.',
    );
  }
}
