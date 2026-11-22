import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';

const head = execFileSync('/usr/bin/git', ['rev-parse', '--verify', 'HEAD'],
  { encoding: 'utf8', timeout: 5000, maxBuffer: 128 }).trim();

function check(sha, extra = {}) {
  const env = { ...process.env, GITHUB_ACTIONS: 'true', GITHUB_SHA: sha, ...extra };
  if (sha === undefined) delete env.GITHUB_SHA;
  return spawnSync('bash', ['scripts/check-ci-checkout.sh'], {
    env, encoding: 'utf8', timeout: 5000, maxBuffer: 2048,
  });
}

test('checked-out synthetic merge SHA is the required identity, not source PR head', () => {
  const other = head === 'a'.repeat(40) ? 'b'.repeat(40) : 'a'.repeat(40);
  const result = check(head, { SOURCE_HEAD_SHA: other });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /PASS: workflow checkout commit matches tested Git HEAD/);
  assert.ok(!result.stdout.includes(head), 'avoid printing commit identity unnecessarily');
});

test('mismatched, missing and malformed expected SHA fail closed and do not reveal data', () => {
  const cases = [undefined, '', 'short', 'A'.repeat(40), '0'.repeat(40),
    'a'.repeat(40) + '\nmalicious-output'];
  for (const sha of cases) {
    if (sha === head) continue;
    const result = check(sha);
    assert.notEqual(result.status, 0, 'invalid checkout identity must fail');
    assert.doesNotMatch(result.stderr, /malicious-output|GITHUB_TOKEN|Authorization:/);
    assert.doesNotMatch(result.stdout, /PASS:/);
  }
});

test('checkpoint validation requires GitHub Actions context', () => {
  const result = check(head, { GITHUB_ACTIONS: 'false' });
  assert.notEqual(result.status, 0);
});

test('five required CI jobs each check the GitHub checkout SHA before building', async () => {
  const workflow = await readFile('.github/workflows/ci.yml', 'utf8');
  const invocations = workflow.match(/- name: Assert checked-out Git revision/g) || [];
  const checkouts = workflow.match(/- uses: actions\/checkout@v4/g) || [];
  assert.equal(checkouts.length, 5);
  assert.equal(invocations.length, 5);
  // Split only on top-level two-space job headers, never indented steps.
  const sections = workflow.split(/\n(?=  (?:rustfmt|frontend|rust-linux|macos|required-gates):\r?\n)/);
  for (const job of ['rustfmt:', 'frontend:', 'rust-linux:', 'macos:', 'required-gates:']) {
    const scope = sections.find((section) => section.startsWith('  ' + job + '\n'));
    assert.ok(scope, 'missing required CI job: ' + job);
    const checkout = scope.indexOf('actions/checkout@v4');
    const identity = scope.indexOf('bash scripts/check-ci-checkout.sh');
    assert.ok(checkout >= 0 && identity > checkout, 'identity must run after checkout');
    assert.match(scope, /Assert checked-out Git revision[\s\S]*bash scripts\/check-ci-checkout\.sh/);
  }
  const guard = await readFile('scripts/check-ci-checkout.sh', 'utf8');
  assert.match(guard, /\/usr\/bin\/git rev-parse --verify HEAD/);
  assert.match(guard, /\$GITHUB_SHA/);
  assert.doesNotMatch(guard, /SOURCE_HEAD_SHA|git checkout|git reset|git fetch/);
  assert.match(workflow, /runs-on: \$\{\{ vars\.MACOS_RUNNER_LABEL \|\| 'macos-latest' \}\}/);
  assert.match(workflow, /node scripts\/check-macos-runner\.mjs/);
  assert.match(workflow, /bash scripts\/verify-macos-bundle\.sh/);
  assert.match(workflow, /actions\/upload-artifact@v4/);
});
