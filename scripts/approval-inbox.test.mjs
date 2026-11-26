import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile('webview/bridges/approval-inbox.ts', 'utf8');
const js = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
}).outputText;
const { ApprovalInbox } = await import('data:text/javascript;charset=utf-8,' + encodeURIComponent(js));
const a = { id: '00000000-0000-4000-8000-000000000001', tool: 'bash__run', preview: 'first' };
const b = { ...a, id: '00000000-0000-4000-8000-000000000002', preview: 'second' };

test('concurrent inbox never auto-selects or advances after response', () => {
  const inbox = new ApprovalInbox();
  assert.equal(inbox.applyRead(inbox.beginRead(), [a, b]), true);
  assert.equal(inbox.current, null);
  inbox.select(a.id);
  assert.deepEqual(inbox.current, a);
  assert.deepEqual(inbox.beginResponse(), a);
  assert.equal(inbox.beginResponse(), null);
  assert.equal(inbox.applyRead(inbox.beginRead(), [b]), false);
  inbox.finishResponse();
  assert.equal(inbox.applyRead(inbox.beginRead(), [b]), true);
  assert.equal(inbox.current, null);
  inbox.select(b.id);
  assert.deepEqual(inbox.current, b);
});

test('invalidation fences a stale reply and changed preview clears selection', () => {
  const inbox = new ApprovalInbox();
  inbox.applyRead(inbox.beginRead(), [a]);
  inbox.select(a.id);
  const stale = inbox.beginRead();
  inbox.invalidate();
  assert.equal(inbox.current, null);
  assert.equal(inbox.applyRead(stale, [a, b]), false);
  inbox.applyRead(inbox.beginRead(), [b, a]);
  assert.deepEqual(inbox.current, a);
  inbox.applyRead(inbox.beginRead(), [{ ...a, preview: 'changed' }, b]);
  assert.equal(inbox.current, null);
  inbox.select(b.id);
  inbox.applyRead(inbox.beginRead(), [a]);
  assert.equal(inbox.current, null);
});

test('malformed, oversized or expired snapshot cannot authorize', () => {
  for (const malformed of [
    null, [a, a], [{ ...a, id: a.id + '\n' }], [{ ...a, tool: 'bash__run\n' }],
    [{ ...a, preview: 'first\n' }], [{ ...a, preview: 'x'.repeat(8193) }],
    Array.from({ length: 33 }, () => a),
  ]) {
    const inbox = new ApprovalInbox();
    inbox.applyRead(inbox.beginRead(), [a]);
    inbox.select(a.id);
    assert.equal(inbox.applyRead(inbox.beginRead(), malformed), false);
    assert.equal(inbox.available, false);
    assert.equal(inbox.current, null);
  }
  const inbox = new ApprovalInbox();
  const version = inbox.beginRead();
  inbox.failRead(version);
  assert.equal(inbox.applyRead(version, [a]), false);
});

test('UI polls authoritative readback, ignores event payload and preserves literal preview', async () => {
  const ui = await readFile('webview/pages/approval-inbox.ts', 'utf8');
  const page = await readFile('webview/pages/app.ts', 'utf8');
  assert.match(ui, /invoke<unknown>\('list_pending_approvals'\)/);
  assert.match(ui, /if \(reading \|\| inbox.busy\) return/);
  assert.match(ui, /window.setTimeout\(/);
  assert.match(ui, /window.setInterval\(\(\) => void refresh\(\), 2000\)/);
  assert.match(ui, /listen\('security-agent:\/\/tool-approval', \(\) =>/);
  assert.doesNotMatch(ui, /event.payload|innerHTML/);
  assert.match(page, /mountApprovalInbox\(\)/);
});
