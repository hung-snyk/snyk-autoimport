/**
 * Tests for the org-resolution safety property: never guess. These cover the
 * exact bug class the project has hit twice already (silent wrong defaults),
 * so they're the highest-value tests to have before handing this to anyone
 * who isn't sitting next to a developer who can debug a bad guess live.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { requestsManager } from 'snyk-request-manager';
import { resolveOrg, formatOrgMatch, type OrgSummary } from '../src/snyk';

/** Stub a requestsManager whose /orgs call returns a fixed org list. */
function stubRequestManager(orgs: Array<Partial<OrgSummary> & { id: string; name: string }>): requestsManager {
  return {
    request: async () => ({
      statusCode: 200,
      data: { orgs: orgs.map((o) => ({ ...o, group: o.groupName ? { name: o.groupName } : null } as unknown)) },
    }),
  } as unknown as requestsManager;
}

test('resolveOrg: unique name match resolves', async () => {
  const rm = stubRequestManager([{ id: '1', name: 'Acme Corp' }]);
  const result = await resolveOrg(rm, 'Acme Corp');
  assert.equal(result.status, 'resolved');
  assert.equal(result.org?.id, '1');
});

test('resolveOrg: name match is case-insensitive', async () => {
  const rm = stubRequestManager([{ id: '1', name: 'Acme Corp' }]);
  const result = await resolveOrg(rm, 'acme corp');
  assert.equal(result.status, 'resolved');
  assert.equal(result.org?.id, '1');
});

test('resolveOrg: two orgs with the same name -> ambiguous, never guesses', async () => {
  const rm = stubRequestManager([
    { id: '1', name: 'Acme Corp', groupName: 'Engineering' },
    { id: '2', name: 'Acme Corp', groupName: 'Sales' },
  ]);
  const result = await resolveOrg(rm, 'Acme Corp');
  assert.equal(result.status, 'ambiguous');
  assert.equal(result.matches?.length, 2);
  // Must never silently pick one — no `org` field on an ambiguous result.
  assert.equal(result.org, undefined);
});

test('resolveOrg: no match -> not_found, never guesses a near match', async () => {
  const rm = stubRequestManager([{ id: '1', name: 'Acme Corp' }]);
  const result = await resolveOrg(rm, 'Acme Corpp');
  assert.equal(result.status, 'not_found');
});

test('resolveOrg: exact slug match resolves even if name collides elsewhere', async () => {
  const rm = stubRequestManager([
    { id: '1', name: 'Acme Corp', slug: 'acme-corp' },
    { id: '2', name: 'Acme Corp', slug: 'acme-corp-eu' },
  ]);
  const result = await resolveOrg(rm, 'acme-corp');
  assert.equal(result.status, 'resolved');
  assert.equal(result.org?.id, '1');
});

test('resolveOrg: non-200 response throws rather than silently resolving', async () => {
  const rm = {
    request: async () => ({ statusCode: 500, data: { orgs: [] } }),
  } as unknown as requestsManager;
  await assert.rejects(() => resolveOrg(rm, 'Acme Corp'));
});

test('formatOrgMatch: includes id and group, falls back to "none"', () => {
  assert.equal(
    formatOrgMatch({ id: '1', name: 'x', groupName: 'Engineering' }),
    '1  (group: Engineering)',
  );
  assert.equal(formatOrgMatch({ id: '1', name: 'x' }), '1  (group: none)');
});
