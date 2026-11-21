import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync('src-tauri/src/agent/server.rs', 'utf8');

test('both retry-path listener logs use fixed error classes rather than OS error text', () => {
  const block = source.match(/async fn serve_with_retry_interval\([\s\S]*?\/\/\/ ConnectInfo/s)?.[0];
  assert.ok(block, 'retry path and trusted TCP source comment must exist');
  assert.equal((block.match(/safe_listener_log_reason\(error\.kind\(\)\)/g) ?? []).length, 2);
  assert.match(block, /eprintln!\(\s*"Local agent listener stopped unexpectedly: \{\}"/);
  assert.match(block, /eprintln!\(\s*"Local agent listener failed to bind: \{\}"/);
  assert.doesNotMatch(block, /\{error(?::[^}]+)?\}/);
});

test('log reason mapping is fixed and provides a safe unknown-error fallback', () => {
  assert.match(source, /fn safe_listener_log_reason\(kind: std::io::ErrorKind\) -> &'static str/);
  assert.match(source, /std::io::ErrorKind::AddrInUse => "address in use"/);
  assert.match(source, /std::io::ErrorKind::AddrNotAvailable => "interface unavailable"/);
  assert.match(source, /std::io::ErrorKind::PermissionDenied => "permission denied"/);
  assert.match(source, /_ => "I\/O failure"/);
  assert.match(source, /fn listener_diagnostics_ignore_os_error_messages\(\)/);
});
