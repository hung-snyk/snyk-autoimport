/**
 * Org ID validation.
 *
 * An org ID is not just an opaque label: it becomes part of a filesystem path
 * (the failed-imports log is named `<orgId>.failed-imports.log`), so a value
 * containing path separators would escape LOG_DIR. Rejecting non-UUIDs is
 * deliberate rather than sanitizing them — stripping separators out of a bad
 * value would silently read a *different* file instead of refusing.
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
