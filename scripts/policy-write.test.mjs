import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

async function loadCoordinator() {
  const source = await readFile('webview/bridges/policy-write.ts', 'utf8');
  const js = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
  }).outputText;
  return import('data:text/javascript;charset=utf-8,' + encodeURIComponent(js));
}

test('single-flight policy coordinator forbids overlapping contradictory writes (#125)', async () => {
  const { PolicyWriteCoordinator } = await loadCoordinator();
  const writer = new PolicyWriteCoordinator();
  const calls = [];
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const first = writer.tryWrite('disable', async (policy) => {
    calls.push(policy);
    await held;
  });
  assert.equal(writer.inFlight, true);
  const overlapping = await writer.tryWrite('auto', async (policy) => {
    calls.push(policy);
  });
  assert.equal(overlapping, false);
  assert.deepEqual(calls, ['disable']);
  release();
  assert.equal(await first, true);
  assert.equal(writer.inFlight, false);
  assert.equal(await writer.tryWrite('ask', async (policy) => calls.push(policy)), true);
  assert.deepEqual(calls, ['disable', 'ask']);
});

test('failed policy writes release single-flight guard without reporting success (#125)', async () => {
  const { PolicyWriteCoordinator } = await loadCoordinator();
  const writer = new PolicyWriteCoordinator();
  await assert.rejects(writer.tryWrite('disable', async () => {
    throw new Error('persistence failed');
  }), /persistence failed/);
  assert.equal(writer.inFlight, false);
  assert.equal(await writer.tryWrite('ask', async () => {}), true);
});

test('trusted desktop retains acknowledged selection during pending policy write (#125)', async () => {
  const app = await readFile('webview/pages/app.ts', 'utf8');
  assert.match(app, /let confirmedBashPolicy: ShellPolicy \| null = null/);
  assert.match(app, /if \(epoch === policyEpoch && !policyWrites\.inFlight\)/);
  assert.match(app, /if \(confirmedBashPolicy === null \|\| policyWrites\.inFlight\)/);
  assert.match(app, /bashPolicy\.disabled = true/);
  assert.match(app, /const saved = await policyWrites\.tryWrite/);
  assert.match(app, /confirmedBashPolicy = requested/);
  assert.match(app, /Shell policy update failed; previous confirmed setting retained/);
  assert.doesNotMatch(app, /\.catch\(\(error: unknown\) => \{ el\('settingsNotice'\)\.textContent = String\(error\)/);
});
