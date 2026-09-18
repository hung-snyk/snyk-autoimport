/**
 * Resolving the Snyk org named on the command line, shared by `import` and
 * `integrations`.
 *
 * Takes the run's client rather than building its own: pacing is per client
 * (see client.ts), so a second client means a second rate-limit budget, and
 * two of them would quietly double the request rate this tool promises.
 *
 * Kept in its own module because both commands need it and neither owns it.
 * The fail-closed behaviour it implements — never guess between two orgs with
 * the same name — is the core safety property of the tool (NOTES §5).
 */
import { assertValidOrgId } from '../org-id';
import { ask, isInteractive } from '../prompt';
import { formatOrgMatch, resolveOrg } from '../snyk';
import type { SnykClient } from '../snyk/client';
import type { OrgSummary } from '../snyk';

/**
 * Resolve the Snyk org. --snyk-org-id skips lookup entirely; --snyk-org always
 * re-resolves against the current token's live org list (no caching) so a
 * stale mapping can never silently override current access or a genuinely
 * new ambiguity.
 */
export async function resolveTargetOrg(
  client: SnykClient,
  args: {
    snykOrgId?: string;
    snykOrg?: string;
    yes: boolean;
  },
): Promise<OrgSummary> {
  if (args.snykOrgId) {
    assertValidOrgId(args.snykOrgId, '--snyk-org-id');
    return { id: args.snykOrgId, name: args.snykOrgId };
  }
  if (!args.snykOrg) {
    throw new Error('Provide --snyk-org "<name>" or --snyk-org-id <uuid>.');
  }

  const result = await resolveOrg(client, args.snykOrg);

  if (result.status === 'resolved' && result.org) {
    console.log(
      `✓ Resolved "${args.snykOrg}" → ${result.org.id}` +
        (result.org.groupName ? ` (group: ${result.org.groupName})` : ''),
    );
    return result.org;
  }

  if (result.status === 'not_found') {
    throw new Error(
      `No Snyk org matched "${args.snykOrg}". Check the name/slug, or pass --snyk-org-id.`,
    );
  }

  // Ambiguous — never guess.
  const matches = result.matches ?? [];
  if (args.yes || !isInteractive()) {
    const lines = matches.map((m) => `    ${formatOrgMatch(m)}`).join('\n');
    throw new Error(
      `Ambiguous org name "${args.snykOrg}" — ${matches.length} matches. ` +
        `Re-run with --snyk-org-id:\n${lines}`,
    );
  }

  console.log(`Multiple orgs named "${args.snykOrg}":`);
  matches.forEach((m, i) => {
    console.log(`  [${i + 1}] ${formatOrgMatch(m)}`);
  });
  const choice = parseInt(await ask('Pick one (number): '), 10);
  const picked = matches[choice - 1];
  if (!picked) throw new Error('Invalid selection.');
  return picked;
}
