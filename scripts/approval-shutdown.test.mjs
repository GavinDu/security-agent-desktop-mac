import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('trusted process Exit, not WebView CloseRequested, cancels pending Ask (#208)', async () => {
  const app = await readFile('src-tauri/src/app.rs', 'utf8');
  assert.match(app, /matches!\(&event, tauri::RunEvent::Exit\)/);
  assert.match(app, /app\.try_state::<Arc<AgentState>>\(\)/);
  assert.match(app, /state\.gate\.cancel_pending_for_shutdown\(\)/);
  assert.match(app, /WindowEvent::CloseRequested \{ api, \.\. \}/);
  assert.match(app, /api\.prevent_close\(\)/);
  assert.match(app, /window\.hide\(\)/);
  const invokes = app.slice(app.indexOf('.invoke_handler('), app.indexOf('.on_window_event('));
  assert.doesNotMatch(invokes, /cancel_pending_for_shutdown/);
  const server = await readFile('src-tauri/src/agent/server.rs', 'utf8');
  const routes = server.slice(server.indexOf('pub fn router('), server.indexOf('pub async fn serve('));
  assert.doesNotMatch(routes, /shutdown|cancel_pending/);
});

test('shutdown and late approval cannot resurrect an old UUID (#208)', async () => {
  const src = await readFile('src-tauri/src/tools/approvals.rs', 'utf8');
  assert.match(src, /shutting_down: AtomicBool/);
  assert.match(src, /fn cancel_pending_for_shutdown\(&self\) -> Result<usize, String>/);
  assert.match(src, /self\.shutting_down\.store\(true, Ordering::SeqCst\)/);
  const close = src.slice(src.indexOf('fn cancel_pending_for_shutdown('), src.indexOf('pub async fn resolve('));
  assert.match(close, /std::mem::take\(&mut \*pending\)/);
  assert.match(close, /drop\(senders\)/);
  assert.doesNotMatch(close, /send\(true\)/);
  const resolve = src.slice(src.indexOf('pub async fn resolve('), src.indexOf('#[cfg(test)]\nmod tests'));
  assert.match(resolve, /if self\.shutting_down\.load\(Ordering::SeqCst\)/);
  assert.match(resolve, /return false/);
  assert.match(resolve, /pending\.remove\(&id\)/);
  const require = src.slice(src.indexOf('pub async fn require('), src.indexOf('fn cancel_pending_for_shutdown('));
  assert.match(require, /Approval system shutting down/);
  assert.match(require, /pending\.insert\(id, sender\)/);
  assert.match(src, /fn trusted_exit_cancels_thirty_two_pending_asks_and_rejects_late_replies/);
  assert.match(src, /fn poisoned_pending_shutdown_fails_closed_without_recovery_to_approve/);
  assert.match(src, /MAX_PENDING_APPROVALS/);
});
