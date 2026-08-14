/**
 * Dedup discovered targets against what already exists in Snyk.
 *
 * Rather than a local log file (how the raw CLI's `list:imported` works), we
 * query live Snyk state via `generateSnykImportedTargets`, then match on the
 * same deterministic `generateTargetId` key the importer uses. Re-running is
 * therefore always safe — anything already imported is skipped automatically.
 */
import {
  generateSnykImportedTargets,
  generateTargetId,
  SupportedIntegrationTypesToListSnykTargets,
  type ImportTarget,
} from './api';
import { withQuietConsole } from './quiet';

export interface DedupResult {
  toImport: ImportTarget[];
  alreadyImported: number;
}

export async function filterAlreadyImported(
  orgId: string,
  candidates: ImportTarget[],
  integrationType: SupportedIntegrationTypesToListSnykTargets,
): Promise<DedupResult> {
  const { targets: existing } = await withQuietConsole(() =>
    generateSnykImportedTargets({ orgId }, [integrationType]),
  );

  const existingIds = new Set(
    existing.map((t) => generateTargetId(t.orgId, t.integrationId, t.target)),
  );

  const toImport = candidates.filter(
    (c) => !existingIds.has(generateTargetId(c.orgId, c.integrationId, c.target)),
  );

  return { toImport, alreadyImported: candidates.length - toImport.length };
}
