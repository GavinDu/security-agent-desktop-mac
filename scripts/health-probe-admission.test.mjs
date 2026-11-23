import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('outer source and Host authorize precede a separate health admission (#203)', async () => {
  const source = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const agent = await readFile('src-tauri/src/agent/mod.rs', 'utf8');
  const rates = await readFile('src-tauri/src/agent/rate_limit.rs', 'utf8');
  assert.match(rates, /pub const HEALTH_REQUESTS_PER_WINDOW: u32 = 300;/);
  assert.match(rates, /pub const REQUESTS_PER_WINDOW: u32 = 60;/);
  assert.match(agent, /health_rate_limiter: rate_limit::SourceRateLimiter/);
  assert.match(agent, /SourceRateLimiter::with_limit\(\s*rate_limit::HEALTH_REQUESTS_PER_WINDOW/);
  const route = source.slice(source.indexOf('pub fn router('), source.indexOf('pub async fn serve('));
  assert.ok(route.indexOf('limit_tool_dispatch') < route.indexOf('authorize'));
  const authorize = source.slice(source.indexOf('async fn authorize('), source.indexOf('async fn limit_tool_dispatch('));
  assert.match(authorize, /state\.source_allowed\(source\.ip\(\)\)/);
  assert.match(authorize, /host_authority_allowed\(request\.headers\(\), request\.uri\(\), state\.bind\)/);
  const inner = source.slice(source.indexOf('async fn limit_tool_dispatch('), source.indexOf('async fn health('));
  assert.match(inner, /request\.method\(\) == Method::GET && request\.uri\(\)\.path\(\) == "\/health"/);
  assert.match(inner, /state\.health_rate_limiter\.allow\(source\.ip\(\)\)/);
  assert.match(inner, /Health request rate limit reached/);
  assert.ok(inner.indexOf('health_rate_limiter.allow') < inner.indexOf('source_rate_limiter.allow'));
  assert.ok(inner.indexOf('return next.run(request).await;') < inner.indexOf('dispatch_permits'));
});

test('native health negative tests and distinct budget remain wired into Foundation (#203)', async () => {
  const source = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const rates = await readFile('src-tauri/src/agent/rate_limit.rs', 'utf8');
  assert.match(source, /fn unauthenticated_health_has_separate_real_peer_budget_and_no_dispatch_cost/);
  assert.match(source, /x-forwarded-for/);
  assert.match(source, /attacker\.test:8080/);
  assert.match(source, /HEALTH_REQUESTS_PER_WINDOW/);
  assert.match(rates, /fn independent_health_budget_is_bounded_and_does_not_spend_tool_allowance/);
  assert.match(rates, /now \+ WINDOW/);
  assert.match(rates, /MAX_TRACKED_SOURCES/);
  assert.match(rates, /if self\.max_per_window == 0/);
});
