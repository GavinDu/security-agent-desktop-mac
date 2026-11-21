import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('canceled ask/approval futures revoke their pending ID through synchronous Drop (#113)', async () => {
  const source = await readFile('src-tauri/src/tools/approvals.rs', 'utf8');
  assert.match(source, /struct PendingApprovalGuard<'a>/);
  assert.match(source, /impl Drop for PendingApprovalGuard<'_>/);
  assert.match(source, /pending\.remove\(&self\.id\)/);
  assert.match(source, /let _pending_guard = PendingApprovalGuard \{ gate: self, id \}/);
  assert.match(source, /sync::\{Arc, Mutex, RwLock\}/);
  assert.doesNotMatch(source, /tokio::sync::\{broadcast, oneshot, Mutex\}/);
  assert.match(source, /fn cancelled_approval_future_drops_pending_id_without_waiting_for_timeout/);
  assert.match(source, /fn unavailable_desktop_approval_listener_cleans_pending_id/);
  assert.match(source, /assert!\(!gate\.resolve\(id, true\)\.await/);
});
