import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('tunnel HTTP disallows escaped-process shell regardless of spoofed forwarding headers (#111)', async () => {
  const source = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  assert.match(source, /fn tunnel_shell_forbidden\(source: SocketAddr, tool_name: &str\) -> bool/);
  assert.match(source, /tool_name == "bash__run" && !source\.ip\(\)\.is_loopback\(\)/);
  assert.match(source, /async fn list_tools\([\s\S]*ConnectInfo\(source\)/);
  assert.match(source, /tools\.retain\(\|tool\|/);
  assert.match(source, /async fn invoke_tool\([\s\S]*if tunnel_shell_forbidden\(source, &call\.name\)/);
  assert.match(source, /async fn chat\([\s\S]*if tunnel_shell_forbidden\(source, &call\.name\)/);
  assert.match(source, /fn tunnel_http_never_advertises_or_invokes_uncontained_shell/);
  assert.match(source, /fn loopback_http_keeps_operator_approved_shell_catalog/);
  assert.match(source, /StatusCode::FORBIDDEN/);
  assert.match(source, /StatusCode::UNAUTHORIZED/);
  assert.doesNotMatch(source, /headers\(\)\.get\("x-forwarded-for"\)/i);
});
