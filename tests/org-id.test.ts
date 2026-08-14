/**
 * Tests for org ID validation — this guards a value that becomes part of a
 * filesystem path, so the traversal cases below are the ones that matter most.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isValidOrgId, assertValidOrgId } from '../src/org-id';

test('accepts a real Snyk org UUID, in either case', () => {
  assert.equal(isValidOrgId('8fa1e6c9-3b0d-4f7a-9c21-5de40b7a1f83'), true);
  assert.equal(isValidOrgId('8FA1E6C9-3B0D-4F7A-9C21-5DE40B7A1F83'), true);
});

test('rejects path traversal attempts', () => {
  assert.equal(isValidOrgId('../../../../etc/passwd'), false);
  assert.equal(isValidOrgId('8fa1e6c9-3b0d-4f7a-9c21-5de40b7a1f83/../../secret'), false);
  assert.equal(isValidOrgId('../8fa1e6c9-3b0d-4f7a-9c21-5de40b7a1f83'), false);
});

test('rejects separators and traversal even when otherwise UUID-shaped', () => {
  assert.equal(isValidOrgId('8fa1e6c9-3b0d-4f7a-9c21-5de40b7a1f8/'), false);
  assert.equal(isValidOrgId('8fa1e6c9-3b0d-4f7a-9c21-5de40b7a1f83\\..'), false);
  assert.equal(isValidOrgId('8fa1e6c9-3b0d-4f7a-9c21-5de40b7a1f83\0'), false);
});

test('rejects the empty string and near-miss shapes', () => {
  assert.equal(isValidOrgId(''), false);
  assert.equal(isValidOrgId('not-a-uuid'), false);
  // Too short in the final group, and a non-hex character.
  assert.equal(isValidOrgId('8fa1e6c9-3b0d-4f7a-9c21-5de40b7a1f8'), false);
  assert.equal(isValidOrgId('8fa1e6c9-3b0d-4f7a-9c21-5de40b7a1f8z'), false);
});

test('assertValidOrgId returns the value untouched when valid', () => {
  const id = '8fa1e6c9-3b0d-4f7a-9c21-5de40b7a1f83';
  assert.equal(assertValidOrgId(id, '--snyk-org-id'), id);
});

test('assertValidOrgId throws an actionable error naming the flag', () => {
  assert.throws(() => assertValidOrgId('../../etc', '--snyk-org-id'), {
    message: /--snyk-org-id/,
  });
  assert.throws(() => assertValidOrgId('../../etc', '--snyk-org-id'), {
    message: /--snyk-org/,
  });
});
