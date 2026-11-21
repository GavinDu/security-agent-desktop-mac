import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('macOS desktop refuses root/setuid context before home path or Keychain startup (#129)', async () => {
  const guard = await readFile('src-tauri/src/single_instance.rs', 'utf8');
  const app = await readFile('src-tauri/src/app.rs', 'utf8');
  const acquireStart = guard.indexOf('pub fn acquire() -> Result<Self, String>');
  const acquireEnd = guard.indexOf('fn acquire_at(', acquireStart);
  const acquire = guard.slice(acquireStart, acquireEnd);
  assert.ok(acquireStart > 0 && acquireEnd > acquireStart);
  assert.match(guard, /fn validate_unprivileged_user\(/);
  assert.match(guard, /real_uid == 0 \|\| effective_uid == 0 \|\| real_uid != effective_uid/);
  assert.match(guard, /Desktop requires an unprivileged macOS user identity/);
  assert.match(acquire, /#\[cfg\(target_os = "macos"\)\]/);
  const policy = acquire.indexOf('Self::validate_unprivileged_user(');
  const home = acquire.indexOf('dirs::home_dir()');
  assert.ok(policy > 0 && home > policy, 'real/effective UID check must precede any home access');
  assert.match(acquire, /libc::getuid\(\)/);
  assert.match(acquire, /libc::geteuid\(\)/);

  const lock = app.indexOf('InstanceGuard::acquire()');
  const keychain = app.indexOf('secrets::get_or_create_api_token()');
  const agent = app.indexOf('AgentState::new(token, bind, settings)');
  assert.ok(lock > 0 && keychain > lock && agent > keychain);
  assert.match(guard, /fn desktop_rejects_root_setuid_and_mismatched_macos_identity/);
});

test('strict singleton FD lock guarantees survive non-root desktop guard (#129)', async () => {
  const source = await readFile('src-tauri/src/single_instance.rs', 'utf8');
  assert.match(source, /open_lock_in_pinned_directory\(parent, path\)/);
  assert.match(source, /libc::openat\(/);
  assert.match(source, /libc::O_NOFOLLOW/);
  assert.match(source, /metadata\.uid\(\) != unsafe \{ libc::geteuid\(\) \}/);
  assert.match(source, /file\.try_lock\(\)/);
  assert.match(source, /Unsafe hard-linked desktop instance lock/);
});
