import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('only exact GET health bypasses bearer after actual source and Host checks (#210)', async () => {
  const server = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const auth = server.slice(server.indexOf('async fn authorize('), server.indexOf('async fn limit_tool_dispatch('));
  const sourceGate = auth.indexOf('state.source_allowed(source.ip())');
  const hostGate = auth.indexOf('host_authority_allowed(request.headers(), request.uri(), state.bind)');
  const methodGate = auth.indexOf('request.method() != Method::GET || request.uri().path() != "/health"');
  const bearer = auth.indexOf('header::AUTHORIZATION');
  assert.ok(sourceGate >= 0 && hostGate > sourceGate && methodGate > hostGate && bearer > methodGate);
  assert.match(auth, /\.ct_eq\(provided\.as_bytes\(\)\)/);
  assert.doesNotMatch(auth, /if request\.uri\(\)\.path\(\) != "\/health"/);
});

test('all health methods consume the separate real-peer bucket, not tool permits (#210)', async () => {
  const server = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const inner = server.slice(server.indexOf('async fn limit_tool_dispatch('), server.indexOf('async fn health('));
  const path = inner.indexOf('if request.uri().path() == "/health"');
  const budget = inner.indexOf('state.health_rate_limiter.allow(source.ip())');
  const forward = inner.indexOf('return next.run(request).await;');
  const toolBudget = inner.indexOf('state.source_rate_limiter.allow(source.ip())');
  const permit = inner.indexOf('dispatch_permits.clone().try_acquire_owned()');
  assert.ok(path >= 0 && budget > path && forward > budget && toolBudget > forward && permit > toolBudget);
  assert.doesNotMatch(inner.slice(path, toolBudget), /x-forwarded-for/);
  assert.match(server, /fn only_get_health_is_bearer_free_and_every_health_method_spends_probe_budget/);
  assert.match(server, /StatusCode::METHOD_NOT_ALLOWED/);
  assert.match(server, /StatusCode::TOO_MANY_REQUESTS/);
  assert.match(server, /HEALTH_REQUESTS_PER_WINDOW - 2/);
});
