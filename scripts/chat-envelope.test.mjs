import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('internal ChatRequest rejects unrecognized top-level JSON keys (#145)', async () => {
  const server = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  assert.match(server, /#\[derive\(Deserialize\)\]\s*#\[serde\(deny_unknown_fields\)\]\s*struct ChatRequest/);
  assert.match(server, /#\[serde\(default\)\]\s*message: String/);
  assert.match(server, /tool_call: Option<ToolCall>/);
  assert.match(server, /async fn chat\([\s\S]*?Json\(request\): Json<ChatRequest>/);
  assert.match(server, /fn chat_request_accepts_only_documented_internal_top_level_fields/);
  assert.match(server, /fn chat_json_extractor_denies_unknown_claims_after_source_and_bearer_checks/);
});

test('strict chat parsing preserves auth, request bounds and admission before dispatch (#145)', async () => {
  const source = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  assert.match(source, /\.layer\(DefaultBodyLimit::max\(64 \* 1024\)\)/);
  const router = source.slice(source.indexOf('pub fn router('), source.indexOf('pub async fn serve('));
  const limits = router.indexOf('limit_tool_dispatch,');
  const auth = router.indexOf('authorize))');
  assert.ok(limits >= 0 && auth > limits, 'Axum reverses nesting: authenticate first');
  assert.match(source, /ConnectInfo\(source\): ConnectInfo<SocketAddr>/);
  assert.match(source, /request\.uri\(\)\.path\(\) != "\/health"/);
  assert.match(source, /Source IP not in allowed tunnel network/);
  assert.match(source, /Bearer token required/);
  assert.match(source, /Source request rate limit reached/);
  assert.match(source, /Concurrent tool request limit reached/);
  assert.match(source, /StatusCode::UNPROCESSABLE_ENTITY/);
  assert.match(source, /StatusCode::UNAUTHORIZED/);
  assert.match(source, /StatusCode::FORBIDDEN/);
  assert.match(source, /StatusCode::NOT_IMPLEMENTED/);
});
