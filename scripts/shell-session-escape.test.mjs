import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('native negative test proves setsid escape without orphaning either child (#181)', async () => {
  const fixture = await readFile('src-tauri/tests/shell_session_escape.rs', 'utf8');
  const tunnelPolicy = await readFile('docs/TUNNEL_SHELL_POLICY.md', 'utf8');
  assert.match(fixture, /fn process_group_kill_does_not_contain_a_setsid_descendant\(/);
  assert.match(fixture, /fn escaped_session_fixture_child\(/);
  assert.match(fixture, /libc::setsid\(\)/);
  assert.match(fixture, /let self_expiry = Instant::now\(\) \+ Duration::from_secs\(15\)/);
  assert.match(fixture, /\.process_group\(0\)/);
  assert.match(fixture, /\.process_group\(group_id\)/);
  assert.match(fixture, /libc::kill\(-group_id, libc::SIGKILL\)/);
  assert.match(fixture, /libc::getsid\(escaped_id\)/);
  assert.match(fixture, /struct OwnedSessionFixture/);
  assert.match(fixture, /impl Drop for OwnedSessionFixture/);
  assert.match(fixture, /let _ = escaped\.wait\(\)/);
  assert.match(fixture, /let _ = self\.leader\.wait\(\)/);
  assert.doesNotMatch(fixture, /pkill|killall/);
  assert.match(tunnelPolicy, /shell/i);
});
