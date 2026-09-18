/**
 * The `integrations` command: what SCM integrations an org actually has.
 *
 * Diagnostic only. It exists because `--source` is never guessed, and an org
 * can have several integrations from the same family configured at once.
 */
import { prepareEnv } from '../env';
import type { Region } from '../regions';
import { listIntegrationsMap, makeSnykApiClient } from '../snyk';
import { SOURCES } from '../sources';
import { resolveTargetOrg } from './org';

export async function integrationsCmd(args: {
  snykOrg?: string;
  snykOrgId?: string;
  region?: Region;
}): Promise<void> {
  prepareEnv(args.region); // needs SNYK_TOKEN only
  const org = await resolveTargetOrg({ ...args, yes: false });
  const rm = makeSnykApiClient('snyk-autoimport:integrations');
  const map = await listIntegrationsMap(rm, org.id);
  const entries = Object.entries(map);
  console.log(`Integrations configured on ${org.name} (${org.id}):`);
  if (entries.length === 0) {
    console.log('  (none)');
    return;
  }
  for (const [type, id] of entries) {
    const def = SOURCES[type];
    const usable = def ? `  ← ${def.label}, usable as --source ${type}` : '';
    console.log(`  ${type}: ${id}${usable}`);
  }
}
