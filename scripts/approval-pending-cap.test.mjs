import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('Ask admission has a bounded pending-ID cap before notification (#139)', async () => {
  const source = await readFile('src-tauri/src/tools/approvals.rs', 'utf8');
  assert.match(source, /const MAX_PENDING_APPROVALS: usize = 32/);
  assert.match(source, /if pending\.len\(\) >= MAX_PENDING_APPROVALS/);
  assert.match(source, /Too many pending tool approvals/);
  const start = source.indexOf('pub async fn require(');
  const end = source.indexOf('pub async fn resolve(', start);
  assert.ok(start > 0 && end > start);
  const require = source.slice(start, end);
  const cap = require.indexOf('pending.len() >= MAX_PENDING_APPROVALS');
  const insert = require.indexOf('pending.insert(');
  const guard = require.indexOf('PendingApprovalGuard { gate: self, id }');
  const broadcast = require.indexOf('.send(request)');
  assert.ok(cap > 0 && insert > cap && broadcast > insert && guard > broadcast,
    'excess Ask must deny before registration, and serialized publish must precede RAII after lock release');
  // A delayed preview after a completed Exit would be misleading; the
  // synchronous publish must occur inside the same pending lock as insertion.
  assert.ok(require.indexOf('.send(request)') < require.indexOf('let _pending_guard'));
  assert.match(require, /pending\.insert\(\s*id,\s*PendingApproval\s*\{\s*request: request\.clone\(\),\s*sender,\s*\}/);
  assert.match(require, /if !delivered \{[\s\S]*?pending\.remove\(&id\)/);
  assert.match(require, /map_err\(\|_\| "Approval system unavailable"\)/);
  assert.match(require, /tokio::time::timeout\(Duration::from_secs\(60\), receiver\)/);
  assert.match(source, /fn pending_approval_capacity_fails_closed_and_cancellation_releases_one_slot/);
  assert.match(source, /impl Drop for PendingApprovalGuard/);
});

test('bounded approval admission preserves authoritative desktop and UUID response semantics (#139)', async () => {
  const source = await readFile('src-tauri/src/tools/approvals.rs', 'utf8');
  assert.match(source, /self\.events\s*\.send\(request\)/);
  assert.match(source, /No desktop approval listener is connected/);
  assert.match(source, /Some\(entry\) => entry\.sender\.send\(allow\)\.is_ok\(\)/);
  assert.match(source, /None => false/);
  assert.match(source, /Policy::Auto => Ok\(\(\)\)/);
  assert.match(source, /Policy::Disable => Err\("Tool disabled by policy"\.into\(\)\)/);
});
