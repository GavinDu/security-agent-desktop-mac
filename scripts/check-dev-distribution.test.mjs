import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  auditRepositoryDistribution,
  auditDevelopmentDistribution,
} from './check-dev-distribution.mjs';

const source = async (path) => readFile(path, 'utf8');
const baseline = async () => ({
  config: JSON.parse(await source('src-tauri/tauri.conf.json')),
  capabilities: JSON.parse(await source('src-tauri/capabilities/default.json')),
  workflows: [{ name: 'ci.yml', content: await source('.github/workflows/ci.yml') }],
  cargo: await source('src-tauri/Cargo.toml'),
});
const check = (f) => auditDevelopmentDistribution(
  f.config, f.capabilities, f.workflows, f.cargo
);

test('shipped developer DMG policy requires strict macOS gate and never claims notarization', async () => {
  const result = await auditRepositoryDistribution();
  assert.deepEqual(result, { distribution: 'ad-hoc-development-only', publicReleaseEnabled: false });
});

test('no Developer ID / updater / remote WebView permissions in unsigned CI', async () => {
  const base = await baseline();
  for (const mutation of [
    (f) => { f.config.bundle.macOS.signingIdentity = 'Developer ID Application: Fake'; },
    (f) => { delete f.config.bundle.macOS.signingIdentity; },
    (f) => { f.config.bundle.macOS.entitlements = 'Privileged.plist'; },
    (f) => { f.config.bundle.targets.push('app'); },
    (f) => { f.config.app.withGlobalTauri = true; },
    (f) => { f.config.app.windows[0].create = true; },
    (f) => { f.capabilities.remote = { urls: ['https://attacker.invalid'] }; },
    (f) => { f.capabilities.permissions.push('updater:default'); },
    (f) => { f.cargo += '\ntauri-plugin-updater = "2"\n'; },
  ]) {
    const fixture = structuredClone(base);
    mutation(fixture);
    assert.throws(() => check(fixture), /Development|Unsigned/);
  }
});

test('reject release publication, high privilege Actions and alternate publish routes', async () => {
  const base = await baseline();
  const dangerous = [
    'on:\n  release:\n    types: [published]',
    '- uses: softprops/action-gh-release@v2',
    '- uses: actions/create-release@v1',
    '- uses: ncipollo/release-action@v1',
    'run: gh release create v1.0 dist/app.dmg',
    'run: gh release upload v1.0 artifact.dmg',
    'run: npm publish',
    'run: cargo publish',
    'uses: tauri-apps/tauri-action@v0',
    'permissions:\n  contents: write',
    'permissions:\n  packages: write',
    'run: goreleaser release',
    'run: electron-builder publish',
  ];
  for (const payload of dangerous) {
    const fixture = structuredClone(base);
    fixture.workflows[0].content += '\n' + payload + '\n';
    assert.throws(() => check(fixture), /Release\/publish/);
  }
});

test('strict mounted DMG verification, upload and workflow discovery are required', async () => {
  const base = await baseline();
  for (const target of [
    "runs-on: ${{ vars.MACOS_RUNNER_LABEL || 'macos-latest' }}",
    "SELECTED_MACOS_RUNNER: ${{ vars.MACOS_RUNNER_LABEL || 'macos-latest' }}",
    'run: node scripts/check-macos-runner.mjs',
    'bash scripts/verify-macos-bundle.sh',
    'actions/upload-artifact@v6', 'name: unsigned-security-agent-mac',
  ]) {
    const f = structuredClone(base);
    f.workflows[0].content = f.workflows[0].content.replace(target, 'REMOVED');
    assert.throws(() => check(f), /Required strict/);
  }
  assert.throws(() => check({ ...base, workflows: [] }), /No workflow/);
  assert.throws(() => check({ ...base, workflows: [{ name: 'ci.yml', content: null }] }),
    /Cannot audit/);
});

test('Node 20 actions are rejected independently of the app Node 22 version', async () => {
  const base = await baseline();
  const workflow = base.workflows[0].content;
  assert.equal((workflow.match(/actions\/checkout@v6/g) || []).length, 5);
  assert.equal((workflow.match(/actions\/setup-node@v6/g) || []).length, 3);
  assert.equal((workflow.match(/actions\/upload-artifact@v6/g) || []).length, 1);
  assert.equal((workflow.match(/package-manager-cache: false/g) || []).length, 3);
  for (const legacy of [
    'actions/checkout@v4', 'actions/setup-node@v4', 'actions/upload-artifact@v4',
    'actions/upload-artifact@v5',
  ]) {
    const fixture = structuredClone(base);
    fixture.workflows[0].content += '\n      - uses: ' + legacy + '\n';
    assert.throws(() => check(fixture), /Deprecated Node20/);
  }
});

test('scans each workflow rather than trusting only the canonical ci.yml', async () => {
  const base = await baseline();
  base.workflows.push({ name: 'new-publish.yml',
    content: 'name: Bad\njobs:\n  publish:\n    steps:\n      - run: gh release create latest\n' });
  assert.throws(() => check(base), /Release\/publish/);
});
