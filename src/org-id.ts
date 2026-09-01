/**
 * Org ID validation.
 *
 * An org ID is not an opaque label: it is interpolated into API request paths
 * (`/org/${orgId}/integrations` in snyk/integrations.ts and snyk/import.ts),
 * and `--snyk-org-id` is user input. A value containing `/`, `..`, or `?`
 * would change which endpoint the request reaches, with a live token attached.
 * Requiring a UUID closes that off entirely.
 *
 * Rejecting is deliberate rather than sanitizing: stripping the offending
 * characters out of a bad value would silently send the request somewhere the
 * user did not name, instead of refusing.
 *
 * (This originally guarded a filesystem path — the borrowed library named a
 * log file after the org ID. That path is gone; the request-path reason is the
 * stronger one and was always there.)
 */

/** Snyk org IDs are UUIDs, both from the API and from `--snyk-org-id`. */
export const ORG_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isValidOrgId(value: string): boolean {
  return ORG_ID_PATTERN.test(value);
}

/** Validate at a trust boundary, naming `label` so the error is actionable. */
export function assertValidOrgId(value: string, label: string): string {
  if (!isValidOrgId(value)) {
    throw new Error(
      `Invalid ${label}: "${value}" is not a UUID ` +
        '(expected e.g. 8fa1e6c9-3b0d-4f7a-9c21-5de40b7a1f83). ' +
        'Pass --snyk-org "<name>" to look the org up by name instead.',
    );
  }
  return value;
}
