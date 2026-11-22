import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { validateMacosRunner } from './check-macos-runner.mjs';

const host = { label: 'macos-latest', runnerOs: 'macOS',
  runnerArch: 'ARM64', version: '26.1.0' };

test('approved Apple Silicon macOS 15+ runner labels are accepted', () => {
  for (const label of ['macos-latest', 'macos-15', 'macos-26', 'xcode-27']) {
    for (const version of ['15.0', '15.7.2', '26.0', '26.1.0']) {
      assert.equal(validateMacosRunner({ ...host, label, version }).architecture, 'ARM64');
    }
  }
});

test('wrong architecture, stale OS and unsupported runner labels fail closed', () => {
  for (const label of ['macos-15-intel', 'macos-26-intel', 'ubuntu-latest',
    'macos-14', '', undefined, 'macos-26-xlarge']) {
    assert.throws(() => validateMacosRunner({ ...host, label }), /Unsupported/);
  }
  for (const runnerOs of ['Linux', 'Windows', '', undefined]) {
    assert.throws(() => validateMacosRunner({ ...host, runnerOs }), /Apple Silicon/);
  }
  for (const runnerArch of ['X64', 'ARM', '', undefined]) {
    assert.throws(() => validateMacosRunner({ ...host, runnerArch }), /Apple Silicon/);
  }
  for (const version of ['14.7', '13.0', '', 'unknown', '26', '14.7-beta', undefined]) {
    assert.throws(() => validateMacosRunner({ ...host, version }), /macOS 15/);
  }
});

test('CI validates actual runtime before Rust/DMG with no bypass', async () => {
  const ci = await readFile('.github/workflows/ci.yml', 'utf8');
  const native = ci.split(/^  macos:$/m)[1].split(/^  required-gates:$/m)[0];
  assert.match(native, /runs-on: \$\{\{ vars\.MACOS_RUNNER_LABEL \|\| 'macos-latest' \}\}/);
  assert.match(native, /SELECTED_MACOS_RUNNER: \$\{\{ vars\.MACOS_RUNNER_LABEL \|\| 'macos-latest' \}\}/);
  assert.ok(native.indexOf('node scripts/check-macos-runner.mjs') >
    native.indexOf("node-version: '22'"));
  assert.ok(native.indexOf('node scripts/check-macos-runner.mjs') <
    native.indexOf('cargo test --locked'));
  assert.match(native, /bash scripts\/verify-macos-bundle\.sh/);
  assert.match(native, /actions\/upload-artifact@v4/);
});
