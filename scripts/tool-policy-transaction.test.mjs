import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('tool-policy persistence publishes only after a successful staged save (#123)', async () => {
  const source = await readFile('src-tauri/src/tools/commands.rs', 'utf8');
  assert.match(source, /fn persist_tool_policy\(/);
  assert.match(source, /let mut staged = settings\.clone\(\)/);
  assert.match(source, /staged\.policies\.insert\(tool\.to_owned\(\), policy\)/);
  const stage = source.indexOf('let mut staged = settings.clone()');
  const write = source.indexOf('persist(&staged).map_err');
  const publish = source.indexOf('gate.set_policy(tool, policy)');
  const memory = source.indexOf('*settings = staged');
  assert.ok(stage > 0 && write > stage && publish > write && memory > publish);
  assert.match(source, /Cannot persist tool policy/);
  assert.match(source, /persist_tool_policy\(&mut settings, &state\.gate, &tool, policy, AgentSettings::save\)/);
  assert.match(source, /fn failed_policy_persistence_keeps_ui_memory_and_live_gate_in_sync/);
  assert.match(source, /fn successful_policy_persistence_updates_both_gate_and_ui_memory/);
});
