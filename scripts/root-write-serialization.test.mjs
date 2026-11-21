import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

// Execute the actual source TypeScript coordinator, not a duplicated JS mock.
// TypeScript is an existing locked devDependency used by frontend CI.
const coordinatorSource = await readFile('webview/bridges/root-write.ts', 'utf8');
const compiled = ts.transpileModule(coordinatorSource, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
}).outputText;
const { RootWriteCoordinator } = await import('data:text/javascript;base64,' +
  Buffer.from(compiled).toString('base64'));
const ui = await readFile('webview/pages/app.ts', 'utf8');

test('root grants serialize and a newer revoke cannot overtake an unacknowledged write (#154)', async () => {
  const writes = [];
  let finish;
  const pending = new Promise((resolve) => { finish = resolve; });
  const roots = ['/first/grant'];
  const coordinator = new RootWriteCoordinator();
  const first = coordinator.tryWrite(roots, async (value) => {
    writes.push([...value]);
    await pending;
  });
  assert.equal(coordinator.inFlight, true);
  roots.push('/mutable-after-request');
  // A concurrent action is explicitly rejected, not submitted concurrently.
  const second = await coordinator.tryWrite([], async () => { writes.push([]); });
  assert.equal(second, false);
  assert.deepEqual(writes, [['/first/grant']]);
  finish();
  assert.equal(await first, true);
  assert.equal(coordinator.inFlight, false);
  const revoke = await coordinator.tryWrite([], async (value) => { writes.push(value); });
  assert.equal(revoke, true);
  assert.deepEqual(writes, [['/first/grant'], []]);
});

test('failed native persistence frees UI write gate without claiming success (#154)', async () => {
  const coordinator = new RootWriteCoordinator();
  await assert.rejects(
    coordinator.tryWrite(['/granted'], async () => { throw new Error('simulated disk failure'); }),
    /simulated disk failure/,
  );
  assert.equal(coordinator.inFlight, false);
  assert.equal(await coordinator.tryWrite([], async () => {}), true);
});

test('bad requested root collection cannot strand the single-flight lock (#154)', async () => {
  const coordinator = new RootWriteCoordinator();
  const impossible = new Proxy([], {
    get(target, key) {
      if (key === Symbol.iterator) throw new Error('snapshot failed');
      return Reflect.get(target, key);
    },
  });
  await assert.rejects(coordinator.tryWrite(impossible, async () => {}), /snapshot failed/);
  assert.equal(coordinator.inFlight, false);
  assert.equal(await coordinator.tryWrite([], async () => {}), true);
});

test('trusted desktop disables both controls before await and restores only after final acknowledgement (#154)', () => {
  const section = ui.slice(ui.indexOf('async function updateRoots('), ui.indexOf("el('refresh').addEventListener"));
  assert.match(ui, /import \{ RootWriteCoordinator \} from '\.\.\/bridges\/root-write';/);
  assert.match(ui, /const rootWrites = new RootWriteCoordinator\(\)/);
  const guard = section.indexOf('if (rootWrites.inFlight || !rootSnapshots.startMutation(roots.length === 0)) return;');
  const disableGrant = section.indexOf('grantRootButton.disabled = true;');
  const disableClear = section.indexOf('clearRootsButton.disabled = true;');
  const awaitWrite = section.indexOf('await rootWrites.tryWrite(roots,');
  assert.ok(guard >= 0 && disableGrant > guard && disableClear > guard && awaitWrite > disableClear);
  assert.match(section, /if \(!accepted\) return;/);
  assert.match(section, /if \(!accepted\) return;[\s\S]*?await refresh\(\)/);
  assert.match(section, /finally \{\s*rootSnapshots.finishMutation\(\);[\s\S]*?await refresh\(\);[\s\S]*?grantRootButton.disabled = !rootSnapshots.canWrite;[\s\S]*?clearRootsButton.disabled = !rootSnapshots.canWrite;/);
  assert.doesNotMatch(section, /String\(error\)|console\.|JSON\.stringify\(error\)/);
  assert.match(ui, /grantRootButton.addEventListener\('click'/);
  assert.match(ui, /clearRootsButton.addEventListener\('click'/);
});
