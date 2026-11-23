import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  verifiedCandidates,
  supersededEvidence,
  trackedActivePRs,
  eligibleForDeletion,
  verifySupersededEvidence,
  pruneVerifiedBranches,
  eligibleMergedRecentBranch,
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


function mockGitHub(initial, { open = [], refDrift = {}, prOverrides = {} } = {}) {
  const current = new Map([['main', { name: 'main', protected: true, commit: { sha: 'a'.repeat(40) } }],
    ...initial.map(candidate => [candidate.name, branch(candidate)])]);
  const original = new Map(initial.map(candidate => [candidate.pr, candidate]));
  const deleted = [];
  const calls = [];
  const api = async (seenRepo, token, path, method = 'GET') => {
    assert.equal(seenRepo, repo);
    assert.equal(token, 'test-only-no-credentials');
    calls.push({ path, method });
    if (path === '/branches?per_page=100') return [...current.values()];
    if (path === '/pulls?state=open&per_page=100') return open;
    if (path.startsWith('/pulls/')) {
      const n = Number(path.slice('/pulls/'.length));
      const candidate = original.get(n);
      const inFlight = [
        { name: 'security/158-stale-root-snapshot-fence', pr: 161 },
        { name: 'security/156-native-root-mutation-order', pr: 163 },
      ].find(item => item.pr === n);
      if (!candidate && !inFlight) throw new Error('unexpected pull request fetch');
      const mock = candidate || {
        name: inFlight.name, pr: n, sha: current.get(inFlight.name)?.commit.sha,
      };
      return { ...pr(mock, mock.status === 'superseded' ? null : '2026-11-21T00:00:00Z'), ...prOverrides[n] };
    }
    const getRef = '/git/ref/heads/';
    const deleteRef = '/git/refs/heads/';
    if (path.startsWith(getRef)) {
      const name = path.slice(getRef.length);
      return { object: { sha: refDrift[name] || current.get(name)?.commit.sha } };
    }
    if (path.startsWith(deleteRef) && method === 'DELETE') {
      const name = path.slice(deleteRef.length);
      assert.ok(current.has(name), 'cannot delete missing branch');
      current.delete(name);
      deleted.push(name);
      return null;
    }
    throw new Error('unexpected REST action ' + method + ' ' + path);
  };
  return { api, current, deleted, calls };
}

test('full janitor integration deletes only two audited current refs with real REST paths', async () => {
  const mock = mockGitHub([merged, superseded]);
  const result = await pruneVerifiedBranches({
    GITHUB_REPOSITORY: repo, GITHUB_REF: 'refs/heads/main', GITHUB_TOKEN: 'test-only-no-credentials',
  }, mock.api);
  assert.deepEqual(result, { deleted: 2, skipped: 46, featureCount: 0 });
  assert.deepEqual(mock.deleted, [merged.name, superseded.name]);
  for (const candidate of [merged, superseded]) {
    assert.ok(mock.calls.some(call =>
      call.path === '/git/ref/heads/' + candidate.name && call.method === 'GET'));
    assert.ok(mock.calls.some(call =>
      call.path === '/git/refs/heads/' + candidate.name && call.method === 'DELETE'));
  }
  assert.ok(mock.current.has('main'), 'the main ref must survive');
});

test('changed ref or live PR never causes deletion, even with matching historic PR', async () => {
  const changed = { ...merged, sha: '0'.repeat(40) };
  const openPR = { head: { ref: superseded.name, repo: { full_name: repo } } };
  const mock = mockGitHub([changed, superseded], { open: [openPR],
    prOverrides: { [merged.pr]: { head: { ...pr(merged).head, sha: 'f'.repeat(40) } } },
  });
  const result = await pruneVerifiedBranches({
    GITHUB_REPOSITORY: repo, GITHUB_REF: 'refs/heads/main', GITHUB_TOKEN: 'test-only-no-credentials',
  }, mock.api);
  assert.equal(result.deleted, 0);
  assert.equal(result.featureCount, 2);
  assert.deepEqual(mock.deleted, []);
});

test('last-moment ref drift fails closed and never issues DELETE', async () => {
  const mock = mockGitHub([merged], { refDrift: { [merged.name]: 'c'.repeat(40) } });
  const result = await pruneVerifiedBranches({
    GITHUB_REPOSITORY: repo, GITHUB_REF: 'refs/heads/main', GITHUB_TOKEN: 'test-only-no-credentials',
  }, mock.api);
  assert.equal(result.deleted, 0);
  assert.equal(result.featureCount, 1);
  assert.equal(mock.calls.filter(c => c.method === 'DELETE').length, 0);
});

test('a closed-but-unmerged PR is never deleted if consolidated evidence is absent', async () => {
  const mock = mockGitHub([superseded]);
  const result = await pruneVerifiedBranches({
    GITHUB_REPOSITORY: repo, GITHUB_REF: 'refs/heads/main', GITHUB_TOKEN: 'test-only-no-credentials',
  }, mock.api, async () => '');
  assert.equal(result.deleted, 0);
  assert.equal(result.featureCount, 1);
  assert.deepEqual(mock.deleted, []);
});

test('two tracked active PR source refs retire only after merged status is proven', async () => {
  const tracked = [
    { name: 'security/158-stale-root-snapshot-fence', pr: 161, sha: '1'.repeat(40) },
    { name: 'security/156-native-root-mutation-order', pr: 163, sha: '2'.repeat(40) },
  ];
  const mock = mockGitHub(tracked, {
    prOverrides: {
      161: { merged_at: null },
      163: { merged_at: '2026-11-22T20:00:00Z' },
    },
  });
  const result = await pruneVerifiedBranches({
    GITHUB_REPOSITORY: repo, GITHUB_REF: 'refs/heads/main', GITHUB_TOKEN: 'test-only-no-credentials',
  }, mock.api);
  assert.equal(result.deleted, 1);
  assert.equal(result.featureCount, 1);
  assert.deepEqual(mock.deleted, [tracked[1].name]);
});

function recentMergedPr(overrides = {}) {
  const base = {
    number: 1001,
    state: 'closed',
    merged_at: '2026-11-22T20:00:00Z',
    merge_commit_sha: 'b'.repeat(40),
    base: { ref: 'main' },
    head: { ref: 'feature/future-success', sha: 'c'.repeat(40), repo: { full_name: repo } },
  };
  return {
    ...base, ...overrides,
    head: overrides.head ? { ...base.head, ...overrides.head } : base.head,
  };
}

function recentMergedMock(prs, {
  open = [], refDrift = {}, ancestors = {}, branchOverrides = {},
} = {}) {
  const current = new Map([
    ['main', { name: 'main', protected: true, commit: { sha: 'a'.repeat(40) } }],
    ...prs.map(p => [p.head.ref, {
      name: p.head.ref, protected: false, commit: { sha: p.head.sha },
      ...branchOverrides[p.head.ref],
    }]),
  ]);
  const calls = [];
  const deleted = [];
  const api = async (seenRepo, token, path, method = 'GET') => {
    assert.equal(seenRepo, repo);
    assert.equal(token, 'test-only-no-credentials');
    calls.push({ path, method });
    if (path === '/branches?per_page=100') return [...current.values()];
    if (path === '/pulls?state=open&per_page=100') return open;
    if (path === '/pulls?state=closed&sort=updated&direction=desc&per_page=100') return prs;
    if (path.startsWith('/compare/')) {
      const sha = path.slice('/compare/'.length).split('...')[0];
      return { status: ancestors[sha] || 'ahead' };
    }
    if (path.startsWith('/git/ref/heads/')) {
      const name = path.slice('/git/ref/heads/'.length);
      return { object: { sha: refDrift[name] || current.get(name)?.commit.sha } };
    }
    if (path.startsWith('/git/refs/heads/') && method === 'DELETE') {
      const name = path.slice('/git/refs/heads/'.length);
      assert.ok(current.has(name));
      current.delete(name);
      deleted.push(name);
      return null;
    }
    throw new Error('Unexpected future ref cleanup request ' + method + ' ' + path);
  };
  return { api, deleted, current, calls };
}

const futureEnv = {
  GITHUB_REPOSITORY: repo, GITHUB_REF: 'refs/heads/main',
  GITHUB_SHA: 'a'.repeat(40), GITHUB_TOKEN: 'test-only-no-credentials',
};

test('future main-merged PR needs same-repo exact head, main base and merged SHA (#167)', () => {
  const candidate = recentMergedPr();
  const current = { name: candidate.head.ref, protected: false,
    commit: { sha: candidate.head.sha } };
  assert.equal(eligibleMergedRecentBranch(candidate, current, new Set()), true);
  for (const changed of [
    { state: 'open' }, { merged_at: null }, { merge_commit_sha: null },
    { merge_commit_sha: 'invalid' }, { base: { ref: 'develop' } },
    { head: { repo: { full_name: 'untrusted/fork' } } },
  ]) {
    assert.equal(eligibleMergedRecentBranch(recentMergedPr(changed), current, new Set()), false,
      'bad PR metadata must not authorize deletion: ' + JSON.stringify(changed));
  }
  assert.equal(eligibleMergedRecentBranch(candidate,
    { ...current, protected: true }, new Set()), false);
  assert.equal(eligibleMergedRecentBranch(candidate,
    { ...current, commit: { sha: 'd'.repeat(40) } }, new Set()), false);
  assert.equal(eligibleMergedRecentBranch(candidate, current,
    new Set([candidate.head.ref])), false);
});

test('future merged PR branch is deleted only after verified merge ancestry, then cleanup is idempotent (#167)', async () => {
  const candidate = recentMergedPr();
  const mock = recentMergedMock([candidate]);
  const first = await pruneVerifiedBranches(futureEnv, mock.api);
  assert.deepEqual(first, { deleted: 1, skipped: 48, featureCount: 0 });
  assert.deepEqual(mock.deleted, [candidate.head.ref]);
  assert.ok(mock.calls.some(call => call.path === '/compare/' +
    candidate.merge_commit_sha + '...' + futureEnv.GITHUB_SHA));
  assert.ok(mock.calls.some(call => call.method === 'GET' &&
    call.path === '/git/ref/heads/' + candidate.head.ref));
  assert.ok(mock.calls.some(call => call.method === 'DELETE' &&
    call.path === '/git/refs/heads/' + candidate.head.ref));
  const second = await pruneVerifiedBranches(futureEnv, mock.api);
  assert.deepEqual(second, { deleted: 0, skipped: 48, featureCount: 0 });
  assert.ok(mock.current.has('main'));
});

test('future branch cleanup preserves non-ancestor, open, protected and last-moment drifted refs (#167)', async () => {
  const candidate = recentMergedPr();
  for (const modifiers of [
    { ancestors: { [candidate.merge_commit_sha]: 'diverged' } },
    { ancestors: { [candidate.merge_commit_sha]: 'behind' } },
    { open: [{ head: { ref: candidate.head.ref, repo: { full_name: repo } } }] },
    // Open dependent PRs must retain their base even after a parent merges.
    { open: [{ base: { ref: candidate.head.ref, repo: { full_name: repo } },
      head: { ref: 'feature/stacked-child', repo: { full_name: repo } } }] },
    // A fork PR can also use a same-repository feature branch as its base.
    { open: [{ base: { ref: candidate.head.ref, repo: { full_name: repo } },
      head: { ref: 'feature/fork-child', repo: { full_name: 'example/fork' } } }] },
    { branchOverrides: { [candidate.head.ref]: { protected: true } } },
    { refDrift: { [candidate.head.ref]: 'f'.repeat(40) } },
  ]) {
    const mock = recentMergedMock([candidate], modifiers);
    const result = await pruneVerifiedBranches(futureEnv, mock.api);
    assert.equal(result.deleted, 0);
    assert.equal(result.featureCount, 1);
    assert.deepEqual(mock.deleted, []);
  }
});

test('future branch cleanup refuses unidentified main checkout and ignores closed but unmerged PR (#167)', async () => {
  const candidate = recentMergedPr();
  const invalid = recentMergedMock([candidate]);
  await assert.rejects(
    pruneVerifiedBranches({ ...futureEnv, GITHUB_SHA: 'invalid' }, invalid.api),
    /Cannot attest checked-out main commit/,
  );
  assert.deepEqual(invalid.deleted, []);
  const closedNotMerged = recentMergedPr({ merged_at: null });
  const unmerged = recentMergedMock([closedNotMerged]);
  const result = await pruneVerifiedBranches(futureEnv, unmerged.api);
  assert.equal(result.deleted, 0);
  assert.equal(result.featureCount, 1);
  assert.deepEqual(unmerged.deleted, []);
});

test('active branch inventory includes open PR base refs, including forked child PRs (#167)', async () => {
  const source = await readFile('scripts/prune-verified-branches.mjs', 'utf8');
  assert.match(source, /openPRs\.flatMap\(pr => \[/);
  assert.match(source, /pr\.base\?\.ref/);
  assert.match(source, /pr\.head\?\.repo\?\.full_name === repo/);
});
