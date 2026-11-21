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
