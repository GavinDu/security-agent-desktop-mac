import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('tunnel HTTP rejects unfenced filesystem reads before registry invocation (#191)', async () => {
  const source = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const catalog = source.slice(source.indexOf('async fn list_tools('), source.indexOf('async fn invoke_tool('));
  const invoke = source.slice(source.indexOf('async fn invoke_tool('), source.indexOf('#[derive(Deserialize)]', source.indexOf('async fn invoke_tool(')));
  const chat = source.slice(source.indexOf('async fn chat('), source.indexOf('async fn pairing()'));
  assert.match(source, /fn tunnel_file_read_forbidden\(source: SocketAddr, tool_name: &str\) -> bool/);
  assert.match(source, /tool_name == "filesystem__read_file" && !source\.ip\(\)\.is_loopback\(\)/);
  assert.match(catalog, /!tunnel_shell_forbidden\(source, name\) && !tunnel_file_read_forbidden\(source, name\)/);
  for (const handler of [invoke, chat]) {
    const guard = handler.indexOf('if tunnel_file_read_forbidden(source, &call.name)');
    const execution = handler.indexOf('state.registry.invoke(call).await');
    assert.ok(guard > 0 && execution > guard, 'remote read must be rejected before ToolRegistry invokes');
    assert.match(handler, /return remote_file_read_denied\(\);/);
  }
  const deny = source.slice(source.indexOf('fn remote_file_read_denied()'), source.indexOf('async fn list_tools('));
  assert.match(deny, /StatusCode::FORBIDDEN/);
  assert.match(deny, /Remote file read awaits a verified revocation response fence/);
  assert.doesNotMatch(deny, /\.display\(\)|file_content|allowed_roots|SECRET|Keychain/);
  assert.doesNotMatch(source, /headers\(\)\.get\("x-forwarded-for"\)/i);
});

test('native HTTP integration proves tunnel catalogue, both routes and local control (#191)', async () => {
  const source = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const remote = source.slice(source.indexOf('async fn tunnel_http_never_advertises_or_invokes_uncontained_shell()'), source.indexOf('async fn loopback_http_keeps_operator_approved_shell_catalog()'));
  assert.match(remote, /assert!\(!names.contains\(&"filesystem__read_file"\)\)/);
  assert.match(remote, /assert!\(!names.contains\(&"bash__run"\)\)/);
  assert.match(remote, /"name":"filesystem__read_file"/);
  assert.match(remote, /"tool_call":\{"name":"filesystem__read_file"/);
  assert.match(remote, /"x-forwarded-for", "127\.0\.0\.1"/);
  assert.match(remote, /StatusCode::FORBIDDEN/);
  assert.match(remote, /StatusCode::UNAUTHORIZED/);
  const local = source.slice(source.indexOf('async fn loopback_http_keeps_operator_approved_shell_catalog()'), source.indexOf('async fn oversized_authenticated_json_is_rejected_before_tool_dispatch()'));
  assert.match(local, /"filesystem__read_file"/);
  assert.match(local, /"bash__run"/);
  assert.match(source, /fn tunnel_file_read_is_restricted_only_to_remote_http_peers\(\)/);
});

test('remote filesystem mitigation documentation keeps complete response fence open (#191)', async () => {
  const doc = await readFile('docs/REMOTE_FILE_READ_POLICY.md', 'utf8');
  assert.match(doc, /#176/);
  assert.match(doc, /#191/);
  assert.match(doc, /physical Mac/i);
  assert.match(doc, /HTTP|Axum/);
});
