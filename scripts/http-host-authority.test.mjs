import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('outermost HTTP authorization rejects forged Host without using forwarded identity (#193)', async () => {
  const source = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const outer = source.indexOf('.layer(middleware::from_fn_with_state(state.clone(), authorize))');
  const dispatch = source.indexOf('async fn limit_tool_dispatch(');
  const auth = source.indexOf('async fn authorize(');
  assert.ok(outer >= 0 && dispatch >= 0 && auth >= 0);
  const body = source.slice(auth, dispatch);
  assert.match(body, /if !state\.source_allowed\(source\.ip\(\)\)/);
  assert.match(body, /if !host_authority_allowed\(request\.headers\(\), request\.uri\(\), state\.bind\)/);
  assert.match(body, /StatusCode::FORBIDDEN/);
  assert.match(body, /HTTP Host authority not permitted/);
  assert.ok(body.indexOf('host_authority_allowed') < body.indexOf('header::AUTHORIZATION'));
  assert.match(body, /ct_eq\(provided\.as_bytes\(\)\)/);
});

test('Host policy pins configured bind authority and rejects duplicate/absolute authority tricks (#193)', async () => {
  const source = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const policy = source.slice(source.indexOf('fn host_authority_allowed('), source.indexOf('/// ConnectInfo is set by axum'));
  assert.match(policy, /headers\.get_all\(header::HOST\)\.iter\(\)/);
  assert.match(policy, /hosts\.next\(\)\.is_some\(\)/);
  assert.match(policy, /requested\.authority\(\)/);
  assert.match(policy, /value == bind\.to_string\(\)/);
  assert.match(policy, /bind\.ip\(\)\.is_loopback\(\)/);
  assert.match(policy, /localhost:\{\}/);
  assert.doesNotMatch(policy, /x-forwarded|lookup_host|dns_lookup|\.ends_with\(/i);
  const tests = source.slice(source.indexOf('#[cfg(test)]'));
  assert.match(tests, /fn literal_host_policy_rejects_foreign_duplicate_and_absolute_authorities/);
  assert.match(tests, /fn host_rebinding_denied_before_bearer_and_dispatch_but_valid_host_works/);
  assert.match(tests, /evil\.example:8080/);
  assert.match(tests, /x-forwarded-for/);
  assert.match(tests, /x-forwarded-host/);
});
