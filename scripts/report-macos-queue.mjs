/**
 * Read-only queue evidence for the exact GitHub Actions run attempt.
 * Does not retry, skip, approve, or change the native macOS release gate.
 * Never print the Actions token, request bodies, or environment contents.
 */
import { appendFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

export function measureQueue(jobs, expectedName = 'macos') {
  if (!Array.isArray(jobs)) throw new Error('Actions jobs payload is not an array');
  const matches = jobs.filter((job) => job?.name === expectedName);
  if (matches.length !== 1) throw new Error('Expected exactly one native macOS job');
  const job = matches[0];
  const queuedAt = Date.parse(job.created_at);
  const startedAt = Date.parse(job.started_at);
  if (!Number.isFinite(queuedAt) || !Number.isFinite(startedAt) || startedAt < queuedAt) {
    throw new Error('Native macOS queue timestamps are unavailable or inconsistent');
  }
  return {
    queueSeconds: Math.round((startedAt - queuedAt) / 1000),
    queuedAt: new Date(queuedAt).toISOString(),
    startedAt: new Date(startedAt).toISOString(),
    jobId: job.id,
    runner: job.runner_name || 'GitHub-hosted macOS',
  };
}

export function renderQueueSummary(metric, { runId, attempt, headSha }) {
  if (!/^[0-9]+$/.test(String(runId)) || !/^[0-9]+$/.test(String(attempt))
      || !/^[0-9a-f]{40}$/.test(headSha)) {
    throw new Error('Invalid Actions run identity');
  }
  const minutes = (metric.queueSeconds / 60).toFixed(1);
  return [
    '### Native macOS CI queue evidence (#70)',
    '',
    '| Evidence | Value |',
    '| --- | --- |',
    '| Workflow run | ' + runId + ' (attempt ' + attempt + ') |',
    '| Tested commit | ' + headSha + ' |',
    '| Job ID | ' + metric.jobId + ' |',
    '| Job created UTC | ' + metric.queuedAt + ' |',
    '| Native runner started UTC | ' + metric.startedAt + ' |',
    '| Queue wait | ' + minutes + ' minutes |',
    '',
    'Queue wait does not establish a capacity or billing root cause. The exact-head',
    'macos-15 Rust tests, mounted-DMG verification and artifact upload remain mandatory.',
    '',
  ].join('\n');
}

export async function reportQueue(env = process.env, fetchImpl = fetch,
                                  append = appendFile) {
  const repo = env.GITHUB_REPOSITORY;
  const runId = env.GITHUB_RUN_ID;
  const attempt = env.GITHUB_RUN_ATTEMPT;
  const token = env.GITHUB_TOKEN;
  const headSha = env.GITHUB_SHA;
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo || '') ||
      !/^[0-9]+$/.test(runId || '') || !/^[0-9]+$/.test(attempt || '') ||
      !token || !env.GITHUB_STEP_SUMMARY) {
    throw new Error('Required GitHub Actions queue-report environment is unavailable');
  }
  const endpoint = 'https://api.github.com/repos/' + repo +
    '/actions/runs/' + runId + '/attempts/' + attempt + '/jobs?per_page=100';
  const response = await fetchImpl(endpoint, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: 'Bearer ' + token,
      'X-GitHub-Api-Version': '2022-11-28',
    },
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error('Actions jobs API returned HTTP ' + response.status);
  const payload = await response.json();
  const metrics = measureQueue(payload.jobs);
  await append(env.GITHUB_STEP_SUMMARY,
    renderQueueSummary(metrics, { runId, attempt, headSha }), 'utf8');
  process.stdout.write('Native macOS runner queue: ' +
    (metrics.queueSeconds / 60).toFixed(1) + ' minutes (run ' + runId + ').\n');
  return metrics;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  reportQueue().catch(() => {
    // Telemetry is best effort. The workflow keeps its separate strict native
    // test, bundle-seal and DMG-upload gates, even if the API is unavailable.
    process.stderr.write('macOS queue metadata unavailable; native gates unchanged.\n');
    process.exitCode = 1;
  });
}
