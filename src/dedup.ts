/**
 * Dedup discovered targets against what already exists in Snyk.
 *
 * Rather than a local log file (how the raw CLI's `list:imported` works), we
 * query live Snyk state, then match on the same deterministic
 * `generateTargetId` key the importer uses. Re-running is therefore always
 * safe — anything already imported is skipped automatically.
 *
 * Known gap, verified against a live org: a repo that imports with zero
 * manifests produces no projects, and Snyk exposes no record of it anywhere.
 * Such a repo cannot be deduped and will be re-attempted on every run. That is
 * harmless — the re-import creates nothing — and is accepted rather than
 * worked around with a machine-local log, which would be useless in CI.
 */
import type { requestsManager } from 'snyk-request-manager';
import {
  generateTargetId,
  listImportedTargets,
  SnykProjectOrigin,
  type ImportTarget,
} from './api';

export interface DedupResult {
  toImport: ImportTarget[];
  alreadyImported: number;
}

export async function filterAlreadyImported(
  rm: requestsManager,
  orgId: string,
  candidates: ImportTarget[],
  origin: SnykProjectOrigin,
): Promise<DedupResult> {
  const existing = await listImportedTargets(rm, orgId, [origin]);

  // The integration id is constant across this run, so it cancels out of both
  // sides of the comparison; what matters is the org plus the target itself.
  const existingIds = new Set(
    existing.map((target) => generateTargetId(orgId, origin, target)),
  );

  const toImport = candidates.filter(
    (c) => !existingIds.has(generateTargetId(orgId, origin, c.target)),
  );

  return { toImport, alreadyImported: candidates.length - toImport.length };
}
