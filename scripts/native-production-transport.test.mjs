import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = path => readFileSync(path, 'utf8');
const commands = read('src-tauri/src/tools/commands.rs');
const app = read('src-tauri/src/app.rs');
const transport = read('src-tauri/src/tools/native_transport.rs');
const bridge = read('webview/bridges/connectors.ts');
const csp = JSON.parse(read('src-tauri/tauri.conf.json')).app.security.csp;

test('native file command is opaque-only and the original unfenced invoke remains denied', () => {
  assert.match(commands, /pub async fn prepare_native_file\(window: WebviewWindow, call: ToolCall\) -> Result<String, String>/);
  assert.match(commands, /super::native_transport::prepare\(&window, call\).await/);
  assert.match(commands, /name != "filesystem__read_file"/);
  assert.match(transport, /session\.prepare\(window.label\(\), true, call\).await\?/);
  assert.match(transport, /Ok\(ticket.to_string\(\)\)/);
});

test('native response uses the host-owned session and real synchronous responder', () => {
  assert.match(app, /register_asynchronous_uri_scheme_protocol\(\s*"security-agent-file"/);
  assert.match(app, /native_transport::redeem\(ctx, request, \|response\| responder.respond\(response\)\)/);
  assert.match(transport, /ensure_privileged_webview\(window\)/);
  assert.match(transport, /session.redeem\(label, true, &request, respond\)/);
  assert.match(transport, /native_route::dispatch\(label, false/);
});

test('desktop bridge uses only the fenced path and CSP does not open remote frames', () => {
  assert.match(bridge, /call.name === 'filesystem__read_file'\s*\? redeemNativeFile\(\(\) => invoke\('prepare_native_file', \{ call \}\)\)\s*: invoke\('invoke_tool'/);
  assert.match(csp, /connect-src ipc: http:\/\/ipc.localhost security-agent-file:;/);
  assert.match(csp, /frame-src 'none'/);
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /worker-src 'none'/);
});
