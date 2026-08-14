/**
 * mergeOutcomes backs the canary-check flow (submit one target, then the
 * rest, then combine into one summary) — a merge bug here would silently
 * drop or double-count results in the final report.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mergeOutcomes, type ImportOutcome } from './importer';

function outcome(partial: Partial<ImportOutcome>): ImportOutcome {
  return {
    createdProjects: [],
    failedProjects: [],
    kickoffFailures: 0,
    kickoffFailureDetails: [],
    submittedTargets: 0,
    ...partial,
  };
}

test('mergeOutcomes concatenates lists and sums counts', () => {
  const a = outcome({
    createdProjects: [{ projectUrl: 'p1' }],
    kickoffFailures: 1,
    kickoffFailureDetails: [{ errorMessage: 'canary failed' }],
    submittedTargets: 1,
  });
  const b = outcome({
    createdProjects: [{ projectUrl: 'p2' }, { projectUrl: 'p3' }],
    failedProjects: [{ projectUrl: 'p4' }],
    submittedTargets: 2,
  });

  const merged = mergeOutcomes(a, b);
  assert.equal(merged.createdProjects.length, 3);
  assert.equal(merged.failedProjects.length, 1);
  assert.equal(merged.kickoffFailures, 1);
  assert.equal(merged.kickoffFailureDetails.length, 1);
  assert.equal(merged.submittedTargets, 3);
});

test('mergeOutcomes with two empty outcomes stays empty, not undefined', () => {
  const merged = mergeOutcomes(outcome({}), outcome({}));
  assert.deepEqual(merged.createdProjects, []);
  assert.equal(merged.kickoffFailures, 0);
});
