import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('one strict ToolCall envelope guards Tauri IPC and HTTP routes (#141)', async () => {
  const registry = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  const commands = await readFile('src-tauri/src/tools/commands.rs', 'utf8');
  const server = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  assert.match(registry, /#\[derive\(Debug, Clone, Serialize, Deserialize\)\]\s*#\[serde\(deny_unknown_fields\)\]\s*pub struct ToolCall/);
  assert.match(registry, /pub name: String/);
  assert.match(registry, /#\[serde\(default\)\]\s*pub arguments: Value/);
  assert.match(registry, /struct ReadInput/);
  assert.match(registry, /struct RunInput/);
  assert.match(registry, /fn tool_call_envelope_requires_exact_fields_on_both_http_and_tauri_paths/);
  assert.match(commands, /pub async fn invoke_tool\([\s\S]*?call: ToolCall,/);
  assert.match(server, /async fn invoke_tool\([\s\S]*?Json\(call\): Json<ToolCall>/);
  assert.match(server, /tool_call: Option<ToolCall>/);
  assert.match(server, /state\.registry\.invoke\(call\)\.await/);
});

test('trusted frontend only sends the documented tool name plus arguments (#141)', async () => {
  const source = await readFile('webview/bridges/connectors.ts', 'utf8');
  assert.match(source, /interface ToolCall \{ name: string; arguments: Record<string, unknown> \}/);
  assert.match(source, /invoke: \(call\) => invoke\('invoke_tool', \{ call \}\)/);
  assert.doesNotMatch(source, /approvalToken|bearerToken|adminPrivileges/);
});
