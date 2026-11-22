import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const compiled = ts.transpileModule(await readFile('webview/bridges/root-snapshot.ts', 'utf8'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
}).outputText;
const { RootSnapshotCoordinator } = await import('data:text/javascript;base64,' +
  Buffer.from(compiled).toString('base64'));
const ui = await readFile('webview/pages/app.ts', 'utf8');

test('delayed pre-clear read cannot overwrite newer confirmed empty roots (#158)', () => {
  const root = new RootSnapshotCoordinator();
  assert.equal(root.applyRefresh(root.beginRefresh(), ['/previous'], 'native-session:1'), true);
  const oldRefresh = root.beginRefresh();
  assert.equal(root.canWrite, false);
  assert.equal(root.startMutation(), false);
  assert.equal(root.startMutation(true), true);
  assert.equal(root.canWrite, false);
  root.finishMutation();
  const currentRefresh = root.beginRefresh();
  assert.equal(root.applyRefresh(currentRefresh, [], 'native-session:1'), true);
  assert.equal(root.applyRefresh(oldRefresh, ['/previous'], 'native-session:1'), false);
  assert.deepEqual(root.snapshot(), []);
  assert.equal(root.canWrite, true);
});

test('latest-read-wins and readback failure disable stale grant actions (#158)', () => {
  const root = new RootSnapshotCoordinator();
  const old = root.beginRefresh();
  const newest = root.beginRefresh();
  assert.equal(root.applyRefresh(newest, ['/verified'], 'native-session:1'), true);
  assert.equal(root.applyRefresh(old, ['/obsolete'], 'native-session:1'), false);
  assert.deepEqual(root.snapshot(), ['/verified']);
  const failed = root.beginRefresh();
  assert.equal(root.canWrite, false);
  assert.equal(root.failRefresh(failed), true);
  assert.equal(root.canWrite, false);
  assert.equal(root.startMutation(), false);
  // A fail-closed Grant must not prevent emergency revocation of all roots.
  assert.equal(root.canRevoke, true);
  assert.equal(root.startMutation(true), true);
  assert.equal(root.canRevoke, false);
  root.finishMutation();
  assert.deepEqual(root.snapshot(), []);
  assert.equal(root.applyRefresh(root.beginRefresh(), ['/restored'], 'native-session:1'), true);
  assert.equal(root.canWrite, true);
});

test('refresh invalidates stale additive root grant immediately, but Clear remains possible (#158)', () => {
  const root = new RootSnapshotCoordinator();
  assert.equal(root.applyRefresh(root.beginRefresh(), ['/old'], 'native-session:1'), true);
  const slowRefresh = root.beginRefresh();
  assert.equal(root.canWrite, false);
  assert.deepEqual(root.snapshot(), []);
  assert.equal(root.startMutation(), false);
  assert.equal(root.canRevoke, true);
  assert.equal(root.startMutation(true), true);
  root.finishMutation();
  assert.equal(root.applyRefresh(slowRefresh, ['/old'], 'native-session:1'), false);
  assert.equal(root.applyRefresh(root.beginRefresh(), [], 'native-session:1'), true);
  assert.equal(root.canWrite, true);
  assert.deepEqual(root.snapshot(), []);
});

test('readback begun during pending mutation cannot publish, failures can recover (#158)', () => {
  const root = new RootSnapshotCoordinator();
  assert.equal(root.applyRefresh(root.beginRefresh(), ['/initial'], 'native-session:1'), true);
  assert.equal(root.startMutation(), true);
  const duringWrite = root.beginRefresh();
  assert.equal(root.applyRefresh(duringWrite, ['/obsolete'], 'native-session:1'), false);
  root.finishMutation();
  assert.equal(root.applyRefresh(duringWrite, ['/obsolete'], 'native-session:1'), false);
  assert.equal(root.canWrite, false);
  assert.equal(root.applyRefresh(root.beginRefresh(), ['/initial'], 'native-session:1'), true);
  assert.equal(root.canWrite, true);
});

test('trusted UI only takes new Grant roots from currently acknowledged state (#158)', () => {
  const refresh = ui.slice(ui.indexOf('async function refresh()'), ui.indexOf('async function respond('));
  const update = ui.slice(ui.indexOf('async function updateRoots('), ui.indexOf("el('refresh').addEventListener"));
  assert.match(ui, /import \{ RootSnapshotCoordinator \} from '\.\.\/bridges\/root-snapshot';/);
  assert.match(refresh, /rootSnapshots.beginRefresh\(\)/);
  assert.match(refresh, /grantRootButton.disabled = true;[\s\S]*?clearRootsButton.disabled = !rootSnapshots.canRevoke;/);
  assert.match(refresh, /rootSnapshots.applyRefresh\(rootEpoch, settings.allowed_roots, settings.root_revision\)/);
  assert.match(refresh, /rootSnapshots.failRefresh\(rootEpoch\)/);
  assert.match(update, /if \(rootWrites.inFlight \|\| !rootSnapshots.startMutation\(roots.length === 0\)\) return;/);
  assert.match(update, /await rootWrites.tryWrite\(roots,/);
  assert.match(update, /clearRootsButton.disabled = !rootSnapshots.canRevoke;/);
  assert.match(refresh, /clearRootsButton.disabled = !rootSnapshots.canRevoke;/);
  assert.match(update, /finally \{\s*rootSnapshots.finishMutation\(\);[\s\S]*?await refresh\(\)/);
  assert.match(ui, /if \(root && rootSnapshots.canWrite\) void updateRoots\(\[\.\.\.configuredRoots, root\]\)/);
  assert.doesNotMatch(update, /String\(error\)|JSON.stringify\(error\)|console\./);
});

test('native revision is bound to only the latest authoritative UI root snapshot (#160)', () => {
  const root = new RootSnapshotCoordinator();
  const stale = root.beginRefresh();
  assert.equal(root.applyRefresh(stale, ['/old'], 'session-one:1'), true);
  assert.equal(root.snapshotRevision(), 'session-one:1');
  assert.equal(root.startMutation(), true);
  assert.equal(root.snapshotRevision(), null);
  root.finishMutation();
  const current = root.beginRefresh();
  assert.equal(root.applyRefresh(stale, ['/old'], 'session-one:1'), false);
  assert.equal(root.applyRefresh(current, [], 'session-one:2'), true);
  assert.equal(root.snapshotRevision(), 'session-one:2');
  const pending = root.beginRefresh();
  assert.equal(root.snapshotRevision(), null);
  assert.equal(root.applyRefresh(pending, ['/untrusted'], ''), false);
  assert.equal(root.canWrite, false);
  assert.equal(root.canRevoke, true);
});

test('root updates cannot send an additive set without native revision, and Clear is revoke-only (#160)', async () => {
  const connectors = await readFile('webview/bridges/connectors.ts', 'utf8');
  const native = await readFile('src-tauri/src/tools/commands.rs', 'utf8');
  const app = await readFile('src-tauri/src/app.rs', 'utf8');
  assert.match(ui, /const revision = roots.length === 0 \? null : rootSnapshots.snapshotRevision\(\)/);
  assert.match(ui, /roots.length > 0 && revision === null/);
  assert.match(ui, /connectorBridge.clearAllowedRoots\(\)/);
  assert.match(ui, /connectorBridge.setAllowedRoots\(nextRoots, revision\)/);
  assert.match(connectors, /setAllowedRoots: \(roots, expectedRootRevision\) => invoke\('set_allowed_roots', \{ roots, expectedRootRevision \}\)/);
  assert.match(connectors, /clearAllowedRoots: \(\) => invoke\('clear_allowed_roots'\)/);
  assert.match(native, /navigation::ensure_privileged_webview\(&window\)\?;[\s\S]*?commit_serialized_roots/);
  assert.match(native, /expected_root_revision: String/);
  assert.match(native, /revision.ensure_current\(/);
  assert.match(native, /revision.ensure_can_advance\(\)\?/);
  assert.match(app, /tools::commands::clear_allowed_roots/);
});
