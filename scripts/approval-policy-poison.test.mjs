import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('persisted policy cannot advance after poisoned live approval writer (#197)', async () => {
  const gate = await readFile('src-tauri/src/tools/approvals.rs', 'utf8');
  const commands = await readFile('src-tauri/src/tools/commands.rs', 'utf8');
  assert.match(gate, /fn commit_policy_transaction\(/);
  const tx = gate.slice(gate.indexOf('pub(crate) fn commit_policy_transaction('), gate.indexOf('// Test-only hooks'));
  assert.match(tx, /\.policies\s*\.write\(\)\s*\.map_err\(\|_\| "Approval policy registry unavailable"\.to_owned\(\)\)/);
  assert.ok(tx.indexOf('.write()') < tx.indexOf('persist()?'));
  assert.ok(tx.indexOf('persist()?') < tx.indexOf('current.insert('));
  const fnStart = commands.indexOf('fn persist_tool_policy(');
  const fnEnd = commands.indexOf('#[tauri::command]', fnStart);
  const persist = commands.slice(fnStart, fnEnd);
  assert.match(persist, /gate\.commit_policy_transaction\(tool, policy, \|\|/);
  assert.match(persist, /persist\(&staged\)\.map_err\(\|_\| "Cannot persist tool policy"\.to_owned\(\)\)/);
  assert.ok(persist.indexOf('commit_policy_transaction') < persist.indexOf('*settings = staged'));
  assert.doesNotMatch(persist, /gate\.set_policy\(/);
});

test('poisoned policy reads disable Auto and native tests cover no-save failure (#197)', async () => {
  const gate = await readFile('src-tauri/src/tools/approvals.rs', 'utf8');
  const commands = await readFile('src-tauri/src/tools/commands.rs', 'utf8');
  const readBlock = gate.slice(gate.indexOf('pub fn policy('), gate.indexOf('pub(crate) fn commit_policy_transaction('));
  assert.match(readBlock, /let Ok\(policies\) = self\.policies\.read\(\) else/);
  assert.match(readBlock, /return Policy::Disable;/);
  assert.match(gate, /fn poisoned_policy_writer_disables_discovery_and_denies_invocation/);
  assert.match(gate, /fn accepted_policy_save_precedes_live_publish_and_failure_preserves_old_value/);
  assert.match(commands, /fn poisoned_live_policy_writer_cannot_persist_or_claim_success/);
  assert.match(commands, /assert!\(!durable_save_called\)/);
});
