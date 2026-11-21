import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const filename = 'scripts/check-required-gates.sh';
const ci = readFileSync('.github/workflows/ci.yml', 'utf8');
const run = (overrides = {}) => spawnSync('bash', [filename], {
  encoding: 'utf8',
  env: {
    PATH: process.env.PATH,
    FRONTEND_RESULT: 'success',
    RUSTFMT_RESULT: 'success',
    RUST_LINUX_RESULT: 'success',
    MACOS_RESULT: 'success',
    ...overrides,
  },
});

test('required-gates job runs even if native was skipped and reads all four needs', () => {
  assert.match(ci, /^  required-gates:\n    needs: \[frontend, rustfmt, rust-linux, macos\]\n    if: \$\{\{ always\(\) \}\}/m);
  for (const name of [
    'FRONTEND_RESULT: ${{ needs.frontend.result }}',
    'RUSTFMT_RESULT: ${{ needs.rustfmt.result }}',
    "RUST_LINUX_RESULT: ${{ needs['rust-linux'].result }}",
    'MACOS_RESULT: ${{ needs.macos.result }}',
    'run: bash scripts/check-required-gates.sh',
  ]) {
    assert.ok(ci.includes(name), 'required-gates missing ' + name);
  }
  assert.doesNotMatch(ci, /  required-gates:[\s\S]*?continue-on-error: true/);
});

test('required-gates accepts only four actual successes', () => {
  const yes = run();
  assert.equal(yes.status, 0, yes.stderr);
  assert.match(yes.stdout, /All four required CI jobs completed successfully/);

  for (const key of ['FRONTEND_RESULT', 'RUSTFMT_RESULT', 'RUST_LINUX_RESULT', 'MACOS_RESULT']) {
    for (const bad of ['skipped', 'neutral', 'failure', 'cancelled', '', 'SECRET_NEVER_PRINT']) {
      const no = run({ [key]: bad });
      assert.equal(no.status, 1, key + ' ' + bad);
      assert.match(no.stderr, new RegExp(key + ' did not complete with success'));
      assert.doesNotMatch(no.stderr + no.stdout, /SECRET_NEVER_PRINT/);
    }
  }
});
