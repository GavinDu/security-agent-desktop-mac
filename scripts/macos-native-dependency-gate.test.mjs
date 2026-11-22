import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('native macOS job depends on all three required successful source gates (#143)', async () => {
  const code = await readFile('.github/workflows/ci.yml', 'utf8');
  const split = code.split(/^  macos:$/m);
  assert.equal(split.length, 2, 'exactly one named native job is required');
  const before = split[0];
  const native = split[1].split(/^  required-gates:$/m)[0];
  for (const name of ['frontend', 'rustfmt', 'rust-linux']) {
    assert.match(before, new RegExp('^  ' + name + ':', 'm'));
  }
  assert.match(native, /^    needs: \[frontend, rustfmt, rust-linux\]$/m);
  assert.match(native, /^    runs-on: \$\{\{ vars\.MACOS_RUNNER_LABEL \|\| 'macos-latest' \}\}$/m);
  assert.match(native, /SELECTED_MACOS_RUNNER: \$\{\{ vars\.MACOS_RUNNER_LABEL \|\| 'macos-latest' \}\}/);
  assert.match(native, /run: node scripts\/check-macos-runner\.mjs/);
  assert.ok(native.indexOf('node scripts/check-macos-runner.mjs') < native.indexOf('cargo test --locked'));
  assert.match(native, /^    timeout-minutes: 50$/m);
  assert.doesNotMatch(native, /^    if:.*always\(/m);
  assert.doesNotMatch(native, /^    continue-on-error:/m);
  assert.match(code, /cancel-in-progress: true/);
});

test('native verification and DMG artifact remain mandatory rather than bypassed (#143)', async () => {
  const ci = await readFile('.github/workflows/ci.yml', 'utf8');
  const native = ci.split(/^  macos:$/m)[1].split(/^  required-gates:$/m)[0];
  const required = [
    'Assert checked-out Git revision',
    'npm ci --no-audit --no-fund',
    'npm run typecheck',
    'npm run build:webview',
    'npm run test:foundation',
    'cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check',
    'cargo test --locked --manifest-path src-tauri/Cargo.toml',
    'npm run build',
    'bash scripts/verify-macos-bundle.sh',
    'actions/upload-artifact@v6',
    'name: unsigned-security-agent-mac',
    'if-no-files-found: error',
  ];
  for (const command of required) {
    assert.ok(native.includes(command), 'missing native security gate ' + command);
  }
  assert.match(native, /- name: Record native macOS queue wait \(telemetry only\)\s+continue-on-error: true/);
  // Match the standalone Tauri build step, not the earlier WebView
  // prerequisite "npm run build:webview".
  const dmgBuild = native.indexOf('\n        run: npm run build\n');
  assert.ok(dmgBuild > 0, 'required standalone Tauri DMG build step');
  assert.ok(native.indexOf('cargo test --locked') < dmgBuild);
  assert.ok(dmgBuild < native.indexOf('bash scripts/verify-macos-bundle.sh'));
  assert.ok(native.indexOf('bash scripts/verify-macos-bundle.sh') < native.indexOf('actions/upload-artifact@v6'));
});
