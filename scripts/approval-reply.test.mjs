import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

async function loadReplyCoordinator() {
  const source = await readFile('webview/bridges/approval-reply.ts', 'utf8');
  const js = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
  }).outputText;
  return import('data:text/javascript;charset=utf-8,' + encodeURIComponent(js));
}

test('approval response only shows success for explicit backend true (#135)', async () => {
  const { ApprovalReplyCoordinator } = await loadReplyCoordinator();
  const coordinator = new ApprovalReplyCoordinator();
  assert.equal(await coordinator.tryRespond('valid', true, async () => true), 'accepted');
  assert.equal(await coordinator.tryRespond('stale', true, async () => false), 'expired');
  assert.equal(await coordinator.tryRespond('missing', false, async () => undefined), 'expired');
  assert.equal(coordinator.inFlight, false);
});

test('second click never issues a second reply while first is pending (#135)', async () => {
  const { ApprovalReplyCoordinator } = await loadReplyCoordinator();
  const coordinator = new ApprovalReplyCoordinator();
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const calls = [];
  const first = coordinator.tryRespond('original', true, async (id, allow) => {
    calls.push([id, allow]);
    return held;
  });
  assert.equal(coordinator.inFlight, true);
  const concurrent = await coordinator.tryRespond('original', false, async (id) => {
    calls.push(['duplicate', id]);
    return true;
  });
  assert.equal(concurrent, 'busy');
  assert.deepEqual(calls, [['original', true]]);
  release(true);
  assert.equal(await first, 'accepted');
  assert.equal(coordinator.inFlight, false);
  assert.equal(await coordinator.tryRespond('next', false, async () => true), 'accepted');
});

test('throwing IPC reply does not lock approvals indefinitely (#135)', async () => {
  const { ApprovalReplyCoordinator } = await loadReplyCoordinator();
  const coordinator = new ApprovalReplyCoordinator();
  await assert.rejects(coordinator.tryRespond('id', false, async () => {
    throw new Error('unsafe native secret goes here');
  }), /unsafe native secret/);
  assert.equal(coordinator.inFlight, false);
  assert.equal(await coordinator.tryRespond('id', false, async () => true), 'accepted');
});

test('trusted UI never claims success on stale or thrown native approval (#135)', async () => {
  const source = await readFile('webview/pages/app.ts', 'utf8');
  assert.match(source, /const approvalReplies = new ApprovalReplyCoordinator\(\)/);
  assert.match(source, /if \(!current \|\| approvalReplies\.inFlight\) return/);
  assert.match(source, /await approvalReplies\.tryRespond\(/);
  assert.match(source, /if \(pending\?\.id !== current\.id\) return/);
  assert.match(source, /if \(result === 'accepted'\)/);
  assert.match(source, /else if \(result === 'expired'\)/);
  assert.match(source, /Approval expired or no longer pending\./);
  assert.match(source, /Approval response failed; retry or deny\./);
  assert.match(source, /allow\.disabled = !pending/);
  assert.match(source, /deny\.disabled = !pending/);
  assert.doesNotMatch(source, /Approval failed: ' \+ String\(error\)/);
  assert.match(source, /allow\.disabled = approvalReplies\.inFlight/);
});
