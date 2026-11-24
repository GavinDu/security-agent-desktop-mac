import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('router fallback goes through outer source/Host/bearer and inner rate gates (#212)', async () => {
  const server = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const router = server.slice(server.indexOf('pub fn router('), server.indexOf('pub async fn serve('));
  const fallback = router.indexOf('.fallback(unknown_route)');
  const admit = router.indexOf('limit_tool_dispatch,');
  const auth = router.indexOf('.layer(middleware::from_fn_with_state(state.clone(), authorize))');
  assert.ok(fallback > 0 && admit > fallback && auth > admit,
    'route fallback must be present before both reverse-order Axum security layers');

  const unknown = server.slice(server.indexOf('async fn unknown_route('), server.indexOf('async fn health('));
  assert.match(unknown, /StatusCode::NOT_FOUND/);
  assert.match(unknown, /"error":"Unknown route"/);
  assert.doesNotMatch(unknown, /request|uri|headers|authorization|token|source/);
});

test('all authenticated non-health methods and fallback responses spend peer budget (#212)', async () => {
  const server = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const auth = server.slice(server.indexOf('async fn authorize('), server.indexOf('async fn limit_tool_dispatch('));
  assert.match(auth, /state\.source_allowed\(source\.ip\(\)\)/);
  assert.match(auth, /host_authority_allowed\(request\.headers\(\), request\.uri\(\), state\.bind\)/);
  assert.match(auth, /request\.method\(\) != Method::GET \|\| request\.uri\(\)\.path\(\) != "\/health"/);
  assert.match(auth, /\.ct_eq\(provided\.as_bytes\(\)\)/);

  const middleware = server.slice(server.indexOf('async fn limit_tool_dispatch('), server.indexOf('async fn unknown_route('));
  const health = middleware.indexOf('if request.uri().path() == "/health"');
  const healthRate = middleware.indexOf('health_rate_limiter.allow(source.ip())');
  const tools = middleware.indexOf('let is_tool_post');
  const sourceRate = middleware.indexOf('source_rate_limiter.allow(source.ip())');
  const permit = middleware.indexOf('dispatch_permits.clone().try_acquire_owned()');
  assert.ok(health >= 0 && healthRate > health && tools > healthRate && sourceRate > tools && permit > sourceRate);
  assert.doesNotMatch(middleware.slice(tools, sourceRate), /return next\.run\(request\)\.await;/,
    'unknown paths and unsupported methods must not bypass the authenticated quota');
  assert.match(middleware, /if !is_tool_post \{/);
  assert.match(server, /fn unknown_routes_and_unsupported_methods_share_authenticated_real_peer_budget/);
  assert.match(server, /REQUESTS_PER_WINDOW/);
  assert.match(server, /StatusCode::METHOD_NOT_ALLOWED/);
  assert.match(server, /StatusCode::TOO_MANY_REQUESTS/);
});
