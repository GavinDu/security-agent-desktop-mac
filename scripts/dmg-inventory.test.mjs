import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, symlink, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const inventory = (directory, pattern, type) =>
  spawnSync('bash', [
    '-c',
    'set -e; source "$1"; require_single_inventory_path "$2" "$3" "$4"; printf "%s" "$SINGLE_INVENTORY_PATH"',
    '--', 'scripts/dmg-inventory.sh', directory, pattern, type,
  ], { encoding: 'utf8', timeout: 5000 });

test('strict upload DMG inventory refuses zero, duplicates and symlinked candidates', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mac-bundle-inventory-'));
  try {
    assert.notEqual(inventory(dir, '*.dmg', 'file').status, 0);
    await writeFile(join(dir, 'one.dmg'), 'developer-fixture');
    assert.equal(inventory(dir, '*.dmg', 'file').stdout, join(dir, 'one.dmg'));
    assert.equal(inventory(dir, '*.dmg', 'file').status, 0);
    await writeFile(join(dir, 'stale.dmg'), 'stale');
    assert.notEqual(inventory(dir, '*.dmg', 'file').status, 0);
    await rm(join(dir, 'stale.dmg'));
    await symlink(join(dir, 'one.dmg'), join(dir, 'linked.dmg'));
    assert.notEqual(inventory(dir, '*.dmg', 'file').status, 0);
    await rm(join(dir, 'one.dmg'));
    assert.notEqual(inventory(dir, '*.dmg', 'file').status, 0,
      'single symlink cannot be verified as the only real DMG');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('inventory remains unambiguous with spaces and embedded newline filenames', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mac-bundle-inventory-'));
  try {
    const filename = 'signed-looking but untrusted\nname.dmg';
    const p = join(dir, filename);
    await writeFile(p, 'fixture');
    const result = inventory(dir, '*.dmg', 'file');
    assert.equal(result.status, 0);
    assert.equal(result.stdout, p);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('mounted app inventory refuses multiple bundles and symlink applications', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mac-app-inventory-'));
  try {
    await mkdir(join(dir, 'Security Agent.app'));
    assert.equal(inventory(dir, '*.app', 'directory').status, 0);
    await mkdir(join(dir, 'Stale Agent.app'));
    assert.notEqual(inventory(dir, '*.app', 'directory').status, 0);
    await rm(join(dir, 'Stale Agent.app'), { recursive: true });
    await symlink(join(dir, 'Security Agent.app'), join(dir, 'Fake Agent.app'));
    assert.notEqual(inventory(dir, '*.app', 'directory').status, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('inventory rejects wrong type, directory symlink and unavailable directory', async () => {
  const root = await mkdtemp(join(tmpdir(), 'mac-app-inventory-'));
  try {
    const path = join(root, 'real');
    await mkdir(path);
    await mkdir(join(path, 'wrong.dmg'));
    assert.notEqual(inventory(path, '*.dmg', 'file').status, 0);
    assert.notEqual(inventory(path, '*.dmg', 'unknown').status, 0);
    assert.notEqual(inventory(join(root, 'missing'), '*.dmg', 'file').status, 0);
    await symlink(path, join(root, 'linked-dir'));
    assert.notEqual(inventory(join(root, 'linked-dir'), '*.dmg', 'file').status, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('real macOS mounted verifier uses the same strict inventory as artifact upload', async () => {
  const verifier = await readFile('scripts/verify-macos-bundle.sh', 'utf8');
  assert.match(verifier, /source "\$\(dirname "\$\{BASH_SOURCE\[0\]\}"\)\/dmg-inventory\.sh"/);
  assert.match(verifier, /require_single_inventory_path "\$dmg_dir" '\*\.dmg' file/);
  assert.match(verifier, /require_single_inventory_path "\$mount_dir" '\*\.app' directory/);
  assert.doesNotMatch(verifier, /find[^\n]*-name '\\*\\.dmg'[^\n]*-print -quit/);
  assert.doesNotMatch(verifier, /find[^\n]*-name '\\*\\.app'[^\n]*-print -quit/);
  assert.match(verifier, /hdiutil attach -readonly/);
  assert.match(verifier, /codesign --verify --strict/);
  assert.match(verifier, /Cannot inspect ad-hoc signature entitlements/);
  assert.match(verifier, /trap cleanup EXIT/);
});


test('partial find failure after one real candidate cannot appear as a valid unique DMG', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mac-bundle-inventory-'));
  try {
    await writeFile(join(dir, 'one.dmg'), 'fixture');
    const script = String.raw`
      set -e
      source "$1"
      fixture="$2/one.dmg"
      find() { printf '%s\0' "$fixture"; return 9; }
      require_single_inventory_path "$2" '*.dmg' file
    `;
    const result = spawnSync('bash', [
      '-c', script, '--', 'scripts/dmg-inventory.sh', dir,
    ], { encoding: 'utf8', timeout: 5000 });
    assert.notEqual(result.status, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
