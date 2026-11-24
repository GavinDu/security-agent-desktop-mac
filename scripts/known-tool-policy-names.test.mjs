import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('persisted tool policies reject dormant names through the shared registry predicate (#201)', async () => {
  const settings = await readFile('src-tauri/src/settings.rs', 'utf8');
  const registry = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  assert.match(registry, /pub fn is_known\(tool: &str\) -> bool/);
  assert.match(settings, /registry::ToolRegistry/);
  assert.match(settings, /fn only_known_tool_policies\(&self\) -> bool/);
  assert.match(settings, /self\.policies\s*\.keys\(\)\s*\.all\(\|tool\| ToolRegistry::is_known\(tool\)\)/);
  const load = settings.slice(settings.indexOf('fn load_at('), settings.indexOf('pub fn save('));
  assert.match(load, /if !settings\.only_known_tool_policies\(\)/);
  assert.match(load, /return Err\("Invalid settings\.json"\.into\(\)\)/);
  assert.ok(load.indexOf('serde_json::from_slice') < load.indexOf('only_known_tool_policies()'));
});

test('unknown tool policies cannot be saved or silently activated (#201)', async () => {
  const settings = await readFile('src-tauri/src/settings.rs', 'utf8');
  const save = settings.slice(settings.indexOf('fn save_at('), settings.indexOf('#[cfg(test)]'));
  assert.match(save, /if !self\.only_known_tool_policies\(\)/);
  assert.match(save, /return Err\("Invalid tool policy configuration"\.into\(\)\)/);
  assert.ok(save.indexOf('only_known_tool_policies()') < save.indexOf('fs::create_dir_all('));
  assert.match(settings, /fn unknown_persisted_tool_policy_names_fail_closed_without_echoing_key/);
  assert.match(settings, /fn saving_unknown_tool_policy_does_not_replace_prior_secure_settings/);
  assert.match(settings, /future__sensitive_tool/);
  assert.match(settings, /assert_eq!\(fs::read\(&path\)\.unwrap\(\), original\)/);
});
