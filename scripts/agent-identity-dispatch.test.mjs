import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('authenticated tool/chat router shares bounded fail-fast permits (#100)', async () => {
  const agent = await readFile('src-tauri/src/agent/mod.rs', 'utf8');
  const api = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  assert.match(agent, /pub const MAX_CONCURRENT_TOOL_REQUESTS: usize = 16/);
  assert.match(agent, /dispatch_permits: Arc<Semaphore>/);
  assert.match(agent, /Arc::new\(Semaphore::new\(MAX_CONCURRENT_TOOL_REQUESTS\)\)/);
  const limitLayer = api.indexOf('limit_tool_dispatch,');
  const authLayer = api.indexOf('state.clone(), authorize');
  assert.ok(limitLayer > 0 && authLayer > limitLayer,
    'authorization is the outermost and first-entered middleware');
  assert.match(api, /request\.method\(\) == Method::POST/);
  assert.match(api, /matches!\(request\.uri\(\)\.path\(\), "\/tools" \| "\/chat"\)/);
  assert.match(api, /dispatch_permits\.clone\(\)\.try_acquire_owned\(\)/);
  assert.match(api, /StatusCode::TOO_MANY_REQUESTS/);
  assert.match(api, /fn authenticated_post_routes_share_fail_fast_dispatch_permits/);
  assert.match(api, /StatusCode::UNAUTHORIZED/);
  assert.match(api, /StatusCode::FORBIDDEN/);
  assert.match(api, /StatusCode::NOT_IMPLEMENTED/);
});

test('empty bearer token cannot reach the Axum router (#102)', async () => {
  const agent = await readFile('src-tauri/src/agent/mod.rs', 'utf8');
  const server = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const start = agent.indexOf('pub fn new(');
  const registry = agent.indexOf('ToolRegistry::canonical_roots', start);
  const validation = agent.indexOf('token.trim().is_empty()', start);
  assert.ok(start >= 0 && validation > start && registry > validation,
    'credential validation must happen before constructing the registry or listener');
  assert.match(agent, /return Err\("Agent authentication token is unavailable"\.into\(\)\)/);
  assert.match(agent, /fn unavailable_bearer_credentials_fail_closed_before_agent_setup/);
  assert.match(server, /strip_prefix\("Bearer "\)/);
  assert.match(server, /unwrap_or_default\(\)/);
  assert.match(server, /StatusCode::UNAUTHORIZED/);
  assert.match(server, /async fn health_is_loopback_only_and_tools_need_token/);
});

test('AgentState construction and startup share the same strict bind allowlist (#104)', async () => {
  const agent = await readFile('src-tauri/src/agent/mod.rs', 'utf8');
  assert.match(agent, /fn allowed_agent_bind\(bind: SocketAddr\) -> bool/);
  assert.match(agent, /bind\.port\(\) == 8080/);
  assert.match(agent, /ip == Ipv4Addr::LOCALHOST \|\| ip == Ipv4Addr::new\(10, 8, 0, 1\)/);
  const constructorStart = agent.indexOf('pub fn new(');
  const predicate = agent.indexOf('if !allowed_agent_bind(bind)', constructorStart);
  const registrySetup = agent.indexOf('ToolRegistry::canonical_roots', constructorStart);
  assert.ok(constructorStart >= 0 && predicate > constructorStart && predicate < registrySetup,
    'constructor must reject untrusted bind before any registry/privileged setup');
  const parserStart = agent.indexOf('pub fn bind_address()');
  assert.ok(parserStart >= 0 && agent.indexOf('if !allowed_agent_bind(bind)', parserStart) > parserStart,
    'environment config and direct state constructors must share one predicate');
  assert.match(agent, /fn constructor_enforces_shared_loopback_and_tunnel_bind_allowlist/);
  assert.doesNotMatch(agent, /IpAddr::V6\(_\) => true/);
});
