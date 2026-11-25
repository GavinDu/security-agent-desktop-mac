import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const registry = readFileSync('src-tauri/src/tools/registry.rs', 'utf8');
const server = readFileSync('src-tauri/src/agent/server.rs', 'utf8');
const commands = readFileSync('src-tauri/src/tools/commands.rs', 'utf8');
const ui = readFileSync('webview/pages/app.ts', 'utf8');

test('one live approval policy controls shared Tauri and HTTP catalog visibility (#150)', () => {
  assert.match(registry, /pub fn list\(&self\) -> Vec<Value> \{/);
  assert.match(registry, /\.filter\(\|tool\| \{[\s\S]*?self\.gate\.policy\(name\) != Policy::Disable/);
  assert.match(commands, /pub async fn list_tools\([\s\S]*?native_tool_catalog\(&state\.registry\)/);
  const nativeCatalog = commands.slice(commands.indexOf('fn native_tool_catalog('), commands.indexOf('async fn invoke_native_tool('));
  assert.match(nativeCatalog, /registry\.list\(\)/);
  assert.match(nativeCatalog, /tools\.retain\(\|tool\|[\s\S]*?native_tool_allowed\(name\)/);
  assert.match(server, /async fn list_tools\([\s\S]*?state\.registry\.list\(\)/);
  assert.match(server, /tools\.retain\(\|tool\|/);
});

test('catalog is not treated as authorization; Disabled still gates invoke (#150)', () => {
  assert.match(registry, /fn disabled_tools_are_hidden_and_remain_denied_at_invocation\(\)/);
  assert.match(server, /fn shared_http_catalog_tracks_live_disabled_policy_without_restart\(\)/);
  assert.match(registry, /self\.gate\s*\.require\("filesystem__read_file"/);
  assert.match(registry, /self\.gate\s*\.require\([\s\S]*?"bash__run"/);
  assert.match(server, /request\.uri\(\)\.path\(\) != "\/health"/);
  assert.match(commands, /navigation::ensure_privileged_webview\(&window\)\?;/);
  assert.match(server, /ConnectInfo\(source\)/);
});

test('trusted desktop refreshes committed tool catalog, never publishes stale disabled policy (#150)', () => {
  const refresh = ui.slice(ui.indexOf('async function refresh()'), ui.indexOf('async function respond('));
  assert.match(refresh, /if \(epoch === policyEpoch && !policyWrites\.inFlight\) \{\s*el\('tools'\)\.textContent/);
  const save = ui.slice(ui.indexOf('async function saveBashPolicy()'), ui.indexOf("bashPolicy.addEventListener('change'"));
  assert.match(save, /let persisted = false;/);
  assert.match(save, /if \(!saved\) throw new Error\('Policy write in progress'\);/);
  assert.match(save, /el\('settingsNotice'\)\.textContent = 'Shell policy updated\.';\s*persisted = true;/);
  assert.match(save, /finally \{\s*policyEpoch \+= 1;\s*bashPolicy\.disabled = false;\s*\}\s*(?:\/\/[^\n]*\n\s*)*if \(persisted\) await refresh\(\);/);
});
