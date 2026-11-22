import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  measureQueue, renderQueueSummary, reportQueue,
} from './report-macos-queue.mjs';

const job = {
  id: 123,
  name: 'macos',
  created_at: '2026-11-20T13:50:53Z',
  started_at: '2026-11-20T15:59:27Z',
  runner_name: 'hosted',
};
const sha = 'f797a55adb3d0953e4fd2f6b873b8db8acdecfdb';
const syntheticMergeSha = '9f513d181d3f887bc16797d3a4026d859ee60fa9';

test('reports per-job queue time on an exact attempt, not test execution duration', () => {
  const result = measureQueue([
    { id: 555, name: 'frontend', created_at: job.created_at, started_at: job.created_at },
    job,
  ]);
  assert.equal(result.queueSeconds, 7714);
  assert.equal(result.jobId, 123);
  assert.equal(result.queuedAt, '2026-11-20T13:50:53.000Z');
  assert.equal(result.startedAt, '2026-11-20T15:59:27.000Z');
  const summary = renderQueueSummary(result, { runId: '44747917651', attempt: '2', headSha: sha, checkoutSha: syntheticMergeSha });
  assert.match(summary, /128\.6 minutes/);
  assert.match(summary, /attempt 2/);
  assert.match(summary, /macOS 15\+ ARM64/);
  assert.ok(!summary.includes('Bearer'));
});

test('missing, duplicated and inconsistent job timestamps fail closed', () => {
  assert.throws(() => measureQueue(undefined), /not an array/);
  assert.throws(() => measureQueue([]), /exactly one/);
  assert.throws(() => measureQueue([job, job]), /exactly one/);
  assert.throws(() => measureQueue([{ ...job, started_at: null }]), /unavailable/);
  assert.throws(() => measureQueue([{ ...job, started_at: '2026-11-20T13:40:00Z' }]), /inconsistent/);
  assert.throws(() => renderQueueSummary(measureQueue([job]), {
    runId: 'not-a-number', attempt: '1', headSha: sha, checkoutSha: sha,
  }), /Invalid/);
});

test('API integration is read-only, attempt-scoped and keeps tokens out of summary', async () => {
  const env = {
    GITHUB_REPOSITORY: 'GavinDu/security-agent-desktop-mac',
    GITHUB_RUN_ID: '44747917651',
    GITHUB_RUN_ATTEMPT: '2',
    GITHUB_TOKEN: 'secret-canary-never-print',
    GITHUB_SHA: syntheticMergeSha,
    SOURCE_HEAD_SHA: sha,
    GITHUB_STEP_SUMMARY: '/tmp/fake-summary',
  };
  let endpoint, headers, stored;
  const request = async (url, opts) => {
    endpoint = url;
    headers = opts.headers;
    return { ok: true, json: async () => ({ jobs: [job] }) };
  };
  const append = async (path, value) => {
    assert.equal(path, env.GITHUB_STEP_SUMMARY);
    stored = value;
  };
  const metrics = await reportQueue(env, request, append);
  assert.equal(metrics.jobId, 123);
  assert.match(endpoint, /\/runs\/44747917651\/attempts\/2\/jobs\?per_page=100$/);
  assert.equal(headers.Authorization, 'Bearer ' + env.GITHUB_TOKEN);
  assert.ok(!stored.includes(env.GITHUB_TOKEN));
  assert.match(stored, /Source head commit/);
  assert.match(stored, /Workflow checkout commit/);
  assert.match(stored, /9f513d18/);
  assert.match(stored, /f797a55a/);
});

test('bad identity or API permission failures never produce fake success', async () => {
  const env = {
    GITHUB_REPOSITORY: 'GavinDu/security-agent-desktop-mac',
    GITHUB_RUN_ID: '44747917651',
    GITHUB_RUN_ATTEMPT: '2',
    GITHUB_TOKEN: 'token',
    GITHUB_SHA: sha,
    GITHUB_STEP_SUMMARY: '/tmp/fake-summary',
  };
  await assert.rejects(reportQueue(env, async () => ({ ok: false, status: 403 })),
    /HTTP 403/);
  await assert.rejects(reportQueue({ ...env, GITHUB_REPOSITORY: 'bad/repo/extra' }),
    /environment is unavailable/);
});

test('reporter runs only in approved macOS 15+ ARM64 job; native verification remains required', async () => {
  const ci = await readFile('.github/workflows/ci.yml', 'utf8');
  const [beforeMacos, native] = ci.split(/^  macos:$/m);
  assert.ok(native, 'macOS job must exist');
  assert.doesNotMatch(beforeMacos, /node scripts\/report-macos-queue\.mjs/);
  assert.match(native, /runs-on: \$\{\{ vars\.MACOS_RUNNER_LABEL \|\| 'macos-latest' \}\}/);
  assert.match(native, /run: node scripts\/check-macos-runner\.mjs/);
  assert.match(native, /actions: read/);
  assert.ok(native.includes('SOURCE_HEAD_SHA: ${{ github.event.pull_request.head.sha || github.sha }}'));

  assert.match(native, /continue-on-error: true[\s\S]*node scripts\/report-macos-queue\.mjs/);
  assert.match(native, /cargo test --locked/);
  assert.match(native, /bash scripts\/verify-macos-bundle\.sh/);
  assert.match(native, /actions\/upload-artifact@v4/);
  assert.ok(native.indexOf('node scripts/report-macos-queue.mjs') <
    native.indexOf('cargo test --locked'), 'report must run before native checks');
});

test('PR source and synthetic checkout identities are explicit and individually validated', () => {
  const summary = renderQueueSummary(measureQueue([job]), {
    runId: '44747917651', attempt: '1', headSha: sha, checkoutSha: syntheticMergeSha,
  });
  assert.match(summary, new RegExp('Source head commit \\| ' + sha));
  assert.match(summary, new RegExp('Workflow checkout commit \\| ' + syntheticMergeSha));
  assert.match(summary, /synthetic merge commit/);
  assert.throws(() => renderQueueSummary(measureQueue([job]), {
    runId: '44747917651', attempt: '1', headSha: sha, checkoutSha: 'invalid',
  }), /Invalid Actions run identity/);
});
