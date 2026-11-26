import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('pending approval snapshot is native-only and checks trusted origin', async () => {
  const commands = await readFile('src-tauri/src/tools/commands.rs', 'utf8');
  const app = await readFile('src-tauri/src/app.rs', 'utf8');
  const server = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const start = commands.indexOf('pub fn list_pending_approvals(');
  const guard = commands.indexOf('navigation::ensure_privileged_webview(&window)?', start);
  const read = commands.indexOf('state.gate.pending_snapshot()', guard);
  assert.ok(start > 0 && guard > start && read > guard);
  assert.match(app, /tools::commands::list_pending_approvals,/);
  assert.doesNotMatch(server, /pending_snapshot|list_pending_approvals/);
});

test('snapshot is from the same pending sender map, with no poison recovery', async () => {
  const gate = await readFile('src-tauri/src/tools/approvals.rs', 'utf8');
  const snapshot = gate.slice(gate.indexOf('fn pending_snapshot('), gate.indexOf('pub fn policy('));
  assert.match(snapshot, /\.pending\s*\.lock\(\)/);
  assert.match(snapshot, /shutting_down\.load/);
  assert.match(snapshot, /!entry\.sender\.is_closed\(\)/);
  assert.match(snapshot, /entry\.request\.clone\(\)/);
  assert.doesNotMatch(snapshot, /into_inner|send\(true\)/);
});
