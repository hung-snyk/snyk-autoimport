/**
 * Data-integrity checks for the source config — guards against someone
 * silently removing/changing an entry (e.g. re-adding github-server-app
 * without the dedup work that made it unsafe, or dropping a required
 * --source-url guard) without noticing.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SOURCES, REQUIRES_SOURCE_URL, KNOWN_UNSUPPORTED, GITHUB_CLOUD_APP_SOURCE } from '../src/sources';

test('exactly the seven supported sources are present', () => {
  assert.deepEqual(
    Object.keys(SOURCES).sort(),
    [
      'azure-repos',
      'bitbucket-cloud',
      'bitbucket-server',
      'github',
      'github-cloud-app',
      'github-enterprise',
      'gitlab',
    ],
  );
});

test('only sources with no safe public-cloud default host require --source-url', () => {
  // github-enterprise and bitbucket-server: no safe default, must be forced.
  assert.equal(REQUIRES_SOURCE_URL.has('github-enterprise'), true);
  assert.equal(REQUIRES_SOURCE_URL.has('bitbucket-server'), true);
  // Everything else has a real, safe public default (github.com, gitlab.com,
  // dev.azure.com, api.bitbucket.org) and must NOT be forced.
  for (const source of ['github', 'github-cloud-app', 'gitlab', 'azure-repos', 'bitbucket-cloud']) {
    assert.equal(REQUIRES_SOURCE_URL.has(source), false, `${source} should not require --source-url`);
  }
});

test('github-server-app is explicitly, deliberately unsupported', () => {
  assert.ok(KNOWN_UNSUPPORTED['github-server-app']);
});

test('GITHUB_CLOUD_APP_SOURCE matches the actual key used in SOURCES', () => {
  assert.ok(SOURCES[GITHUB_CLOUD_APP_SOURCE]);
});

test('bitbucket-cloud uses the special multi-method token check, everything else a single env var', () => {
  assert.deepEqual(SOURCES['bitbucket-cloud'].token, { special: 'bitbucket-cloud' });
  for (const source of ['github', 'github-cloud-app', 'github-enterprise', 'gitlab', 'azure-repos', 'bitbucket-server']) {
    const token = SOURCES[source].token;
    assert.ok('envVar' in token, `${source} should have a single envVar token requirement`);
  }
});

test('each source has a distinct dedup origin type', () => {
  const dedupTypes = Object.values(SOURCES).map((def) => def.dedupType);
  assert.equal(new Set(dedupTypes).size, dedupTypes.length, 'dedup types must not collide across sources');
});
