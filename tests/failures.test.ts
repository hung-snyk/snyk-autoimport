/**
 * Tests for failure classification — these drive which actionable hint (401
 * wrong-integration vs. 404 not-shared-with-app) gets shown in the summary,
 * so a misclassification would point a real user at the wrong fix.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isAuthFailure, isNotFoundFailure, type FailureEntry } from '../src/failures';

test('isAuthFailure: matches the actual 401 shape seen in live testing', () => {
  const entry: FailureEntry = {
    errorMessage: 'Could not complete API import',
    innerError:
      "{\n  name: 'ApiAuthenticationError',\n  message: AxiosError: Request failed with status code 401",
  };
  assert.equal(isAuthFailure(entry), true);
  assert.equal(isNotFoundFailure(entry), false);
});

test('isNotFoundFailure: matches the actual 404 shape seen in live testing (cloud-app not-shared)', () => {
  const entry: FailureEntry = {
    errorMessage: 'Could not complete API import',
    innerError: "{\n  name: 'NotFoundError',\n  message: AxiosError: Request failed with status code 404",
  };
  assert.equal(isNotFoundFailure(entry), true);
  assert.equal(isAuthFailure(entry), false);
});

test('classifiers do not cross-match an unrelated error', () => {
  const entry: FailureEntry = { errorMessage: 'socket hang up' };
  assert.equal(isAuthFailure(entry), false);
  assert.equal(isNotFoundFailure(entry), false);
});

test('classifiers handle a missing innerError without throwing', () => {
  const entry: FailureEntry = {};
  assert.equal(isAuthFailure(entry), false);
  assert.equal(isNotFoundFailure(entry), false);
});
