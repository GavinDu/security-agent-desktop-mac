import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('authenticated POST source budget precedes dispatch and ignores spoofed headers (#133)', async () => {
  const server = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const state = await readFile('src-tauri/src/agent/mod.rs', 'utf8');
  const limiter = await readFile('src-tauri/src/agent/rate_limit.rs', 'utf8');

  const authorize = server.indexOf('.layer(middleware::from_fn_with_state(state.clone(), authorize))');
  const dispatch = server.indexOf('limit_tool_dispatch,');
  assert.ok(dispatch > 0 && authorize > dispatch,
    'Axum layers are applied in reverse order: authenticate before rate/dispatch');

  const begin = server.indexOf('async fn limit_tool_dispatch(');
  const end = server.indexOf('async fn health(', begin);
  assert.ok(begin > 0 && end > begin);
  const middleware = server.slice(begin, end);
  assert.match(middleware, /ConnectInfo\(source\): ConnectInfo<SocketAddr>/);
  assert.match(middleware, /state\.source_rate_limiter\.allow\(source\.ip\(\)\)/);
  assert.doesNotMatch(middleware, /x-forwarded-for|forwarded-for|HeaderMap/i);
  const rate = middleware.indexOf('source_rate_limiter.allow(source.ip())');
  const semaphore = middleware.indexOf('dispatch_permits.clone().try_acquire_owned()');
  assert.ok(rate > 0 && semaphore > rate, 'rate limit must precede shared concurrency admission');
  assert.match(middleware, /StatusCode::TOO_MANY_REQUESTS/);
  assert.match(middleware, /Source request rate limit reached/);

  assert.match(state, /source_rate_limiter: rate_limit::SourceRateLimiter/);
  assert.match(limiter, /pub const REQUESTS_PER_WINDOW: u32 = 60/);
  assert.match(limiter, /pub const WINDOW: Duration = Duration::from_secs\(60\)/);
  assert.match(limiter, /const MAX_TRACKED_SOURCES: usize = 256/);
  assert.match(limiter, /now\.saturating_duration_since\(window\.started\) >= WINDOW/);
  assert.match(limiter, /windows\.retain\(/);
  assert.match(server, /async fn per_tcp_source_authenticated_post_rate_limit_is_shared_and_not_spoofable/);
});

test('authenticated read-only catalog and pairing GETs use the real-peer rate budget without tool permits (#169)', async () => {
  const server = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const middleware = server.slice(server.indexOf('async fn limit_tool_dispatch('),
    server.indexOf('async fn health('));
  assert.match(middleware, /let is_tool_post\s*=/);
  assert.match(middleware, /request\.method\(\) == Method::POST/);
  assert.match(middleware, /matches!\(request\.uri\(\)\.path\(\), "\/tools" \| "\/chat"\)/);
  assert.match(middleware, /let is_catalog_get\s*=/);
  assert.match(middleware, /request\.method\(\) == Method::GET/);
  assert.match(middleware, /matches!\(request\.uri\(\)\.path\(\), "\/tools" \| "\/pairing"\)/);
  assert.match(middleware, /if !is_tool_post && !is_catalog_get/);
  const admit = middleware.indexOf('source_rate_limiter.allow(source.ip())');
  const avoidPermit = middleware.indexOf('if !is_tool_post {', admit);
  const costlyPermit = middleware.indexOf('dispatch_permits.clone().try_acquire_owned()', admit);
  assert.ok(admit > 0 && avoidPermit > admit && costlyPermit > avoidPermit,
    'rate admission must precede the GET-only bypass of POST expensive permits');
  assert.match(server, /async fn catalog_and_pairing_reads_share_post_rate_budget_without_consuming_dispatch_permits/);
  assert.match(server, /assert_eq!\(state\.dispatch_permits\.available_permits\(\), 0\)/);
  assert.match(server, /StatusCode::TOO_MANY_REQUESTS/);
});
