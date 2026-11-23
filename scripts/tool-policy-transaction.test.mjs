import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('tool-policy persistence publishes only after a successful staged save (#123)', async () => {
  const source = await readFile('src-tauri/src/tools/commands.rs', 'utf8');
  assert.match(source, /fn persist_tool_policy\(/);
  assert.match(source, /let mut staged = settings\.clone\(\)/);
  assert.match(source, /staged\.policies\.insert\(tool\.to_owned\(\), policy\)/);
  // The root-grant helper in the same module also stages and publishes.
  // Inspect this specific helper so the test validates policy ordering only.
  const policyStart = source.indexOf('fn persist_tool_policy(');
  const policyEnd = source.indexOf('#[tauri::command]\npub async fn set_tool_policy(', policyStart);
  assert.ok(policyStart > 0 && policyEnd > policyStart);
  const policyHelper = source.slice(policyStart, policyEnd);
  const stage = policyHelper.indexOf('let mut staged = settings.clone()');
  const reserve = policyHelper.indexOf('gate.commit_policy_transaction(tool, policy');
  const write = policyHelper.indexOf('persist(&staged).map_err');
  const memory = policyHelper.indexOf('*settings = staged');
  assert.ok(stage > 0 && reserve > stage && write > reserve && memory > write);
  // The live writer is held across durable save; do not confuse an early
  // write callback with publication of a policy before persistence.
  const gateSource = await readFile('src-tauri/src/tools/approvals.rs', 'utf8');
  const txn = gateSource.slice(gateSource.indexOf('pub(crate) fn commit_policy_transaction('),
    gateSource.indexOf('// Test-only hooks'));
  assert.ok(txn.indexOf('.write()') >= 0);
  assert.ok(txn.indexOf('persist()?') > txn.indexOf('.write()'));
  assert.ok(txn.indexOf('current.insert(') > txn.indexOf('persist()?'));
  assert.match(source, /Cannot persist tool policy/);
  assert.match(source, /persist_tool_policy\(\s*&mut settings,\s*&state\.gate,\s*&tool,\s*policy,\s*AgentSettings::save,\s*\)/);
  assert.match(source, /fn failed_policy_persistence_keeps_ui_memory_and_live_gate_in_sync/);
  assert.match(source, /fn successful_policy_persistence_updates_both_gate_and_ui_memory/);
});
