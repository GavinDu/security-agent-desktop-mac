import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('pending-approval resolution denies poisoned locks instead of panicking (#205)', async () => {
  const source = await readFile('src-tauri/src/tools/approvals.rs', 'utf8');
  const resolver = source.slice(
    source.indexOf('pub async fn resolve('),
    source.indexOf('#[cfg(test)]\nmod tests')
  );
  // Poison must deny before a sender can be used, whether the resolver
  // sends within a mutex guard (for shutdown ordering) or after extraction.
  assert.match(resolver, /let Ok\(mut pending\) = self\.pending\.lock\(\) else \{\s*return false;/);
  assert.match(resolver, /match pending\.entries\.remove\(&id\)/);
  assert.match(resolver, /Some\(entry\) => entry\.sender\.send\(allow\)\.is_ok\(\)/);
  assert.match(resolver, /self\.shutting_down\.load\(Ordering::SeqCst\)/);
  assert.doesNotMatch(resolver, /expect\("approval lock poisoned"\)/);
  assert.match(source, /fn poisoned_pending_registry_never_resolves_or_broadcasts_a_grant/);
  assert.match(source, /assert!\(!gate\.resolve\(id, true\)\.await\)/);
  assert.match(source, /assert!\(!gate\.resolve\(id, false\)\.await\)/);
});

test('poison cleanup can remove abandoned UUID but never grant (#205)', async () => {
  const source = await readFile('src-tauri/src/tools/approvals.rs', 'utf8');
  const guard = source.slice(source.indexOf('impl Drop for PendingApprovalGuard'), source.indexOf('impl ApprovalGate'));
  assert.match(guard, /unwrap_or_else\(\|poisoned\| poisoned\.into_inner\(\)\)/);
  assert.match(guard, /pending\.entries\.remove\(&self\.id\)/);
  assert.doesNotMatch(guard, /send\(true\)/);
  const approval = source.slice(source.indexOf('pub async fn require('), source.indexOf('pub async fn resolve('));
  assert.match(approval, /\.lock\(\)\s*\.map_err\(\|_\| "Approval system unavailable"\)/);
  const tests = source.slice(source.indexOf('fn poisoned_pending_registry_never_resolves_or_broadcasts_a_grant'));
  assert.match(tests, /waiting\.abort\(\)/);
  assert.match(tests, /assert!\(pending\.entries\.is_empty\(\)\)/);
  assert.match(tests, /TryRecvError::Empty/);
});
