import test from 'node:test';
import assert from 'node:assert/strict';
import {
  verifiedCandidates,
  supersededEvidence,
  trackedActivePRs,
  eligibleForDeletion,
  verifySupersededEvidence,
  pruneVerifiedBranches,
} from './prune-verified-branches.mjs';

const repo = 'GavinDu/security-agent-desktop-mac';
const merged = verifiedCandidates.find(candidate => candidate.status === 'merged');
const superseded = verifiedCandidates.find(candidate => candidate.status === 'superseded');
const branch = candidate => ({
  name: candidate.name,
  protected: false,
  commit: { sha: candidate.sha },
});
const pr = (candidate, mergedAt = '2026-11-21T00:00:00Z') => ({
  state: 'closed',
  merged_at: mergedAt,
  head: { ref: candidate.name, sha: candidate.sha, repo: { full_name: repo } },
});

test('explicit inventory preserves main and both active work branches (#162)', () => {
  assert.deepEqual(trackedActivePRs.map(entry => entry.pr), [161, 163]);
  assert.equal(verifiedCandidates.length, 48);
  assert.equal(new Set(verifiedCandidates.map(candidate => candidate.name)).size, 48);
  assert.ok(verifiedCandidates.every(candidate => /^[0-9a-f]{40}$/.test(candidate.sha)));
  assert.ok(!verifiedCandidates.some(candidate => [
    'main', 'security/158-stale-root-snapshot-fence', 'security/156-native-root-mutation-order',
  ].includes(candidate.name)));
  assert.equal(verifiedCandidates.filter(candidate => candidate.status === 'merged').length, 43);
  assert.equal(verifiedCandidates.filter(candidate => candidate.status === 'superseded').length, 5);
});

test('only a closed merged PR with the exact current head may be deleted', () => {
  assert.equal(eligibleForDeletion(merged, branch(merged), pr(merged), new Set(), true), true);
  assert.equal(eligibleForDeletion(merged, branch(merged), { ...pr(merged), merged_at: null }, new Set(), true), false);
  assert.equal(eligibleForDeletion(merged, { ...branch(merged), commit: { sha: 'f'.repeat(40) } }, pr(merged), new Set(), true), false);
  assert.equal(eligibleForDeletion(merged, { ...branch(merged), protected: true }, pr(merged), new Set(), true), false);
  assert.equal(eligibleForDeletion(merged, branch(merged), pr(merged), new Set([merged.name]), true), false);
  assert.equal(eligibleForDeletion(merged, branch(merged), { ...pr(merged), head: { ...pr(merged).head, repo: { full_name: 'untrusted/fork' } } }, new Set(), true), false);
});

test('closed-unmerged candidate requires verified consolidated code and cannot be active', () => {
  assert.ok(Object.hasOwn(supersededEvidence, String(superseded.pr)));
  assert.equal(eligibleForDeletion(superseded, branch(superseded), pr(superseded, null), new Set(), false), false);
  assert.equal(eligibleForDeletion(superseded, branch(superseded), pr(superseded, null), new Set(), true), true);
  assert.equal(eligibleForDeletion(superseded, branch(superseded), pr(superseded), new Set(), true), false);
  assert.equal(eligibleForDeletion(superseded, branch(superseded), pr(superseded, null), new Set([superseded.name]), true), false);
});

test('all five superseded candidates have concrete evidence already represented in current main', async () => {
  const outdated = verifiedCandidates.filter(candidate => candidate.status === 'superseded');
  assert.deepEqual(outdated.map(candidate => candidate.pr).sort((a, b) => a - b),
    [69, 82, 97, 103, 105]);
  for (const candidate of outdated) {
    assert.equal(await verifySupersededEvidence(candidate), true,
      'Cannot prune unresolved unique work for PR #' + candidate.pr);
  }
  const first = outdated[0];
  assert.equal(await verifySupersededEvidence(first, async () => 'not merged'), false);
});

test('an untrusted runner context cannot reach the GitHub API', async () => {
  await assert.rejects(pruneVerifiedBranches({ GITHUB_REPOSITORY: 'wrong/repo', GITHUB_REF: 'refs/heads/main', GITHUB_TOKEN: 'test' }), /restricted to this repository/);
  await assert.rejects(pruneVerifiedBranches({ GITHUB_REPOSITORY: repo, GITHUB_REF: 'refs/heads/feature', GITHUB_TOKEN: 'test' }), /restricted to this repository/);
  await assert.rejects(pruneVerifiedBranches({ GITHUB_REPOSITORY: repo, GITHUB_REF: 'refs/heads/main' }), /Missing narrowly scoped/);
});
