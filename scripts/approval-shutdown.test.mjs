import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('trusted process Exit, not WebView CloseRequested, cancels pending Ask (#208)', async () => {
  const app = await readFile('src-tauri/src/app.rs', 'utf8');
  assert.match(app, /matches!\(&event, tauri::RunEvent::Exit\)/);
  assert.match(app, /app\.try_state::<Arc<AgentState>>\(\)/);
  assert.match(app, /state\.begin_shutdown\(\)/);
  const state = await readFile('src-tauri/src/agent/mod.rs', 'utf8');
  const terminal = state.slice(state.indexOf('fn begin_shutdown('), state.indexOf('fn ensure_running('));
  assert.match(terminal, /self\.registry\.begin_shutdown\(\)/);
  assert.match(terminal, /self\.gate\.cancel_pending_for_shutdown\(\)/);
  assert.match(app, /WindowEvent::CloseRequested \{ api, \.\. \}/);
  assert.match(app, /api\.prevent_close\(\)/);
  assert.match(app, /window\.hide\(\)/);
  const invokes = app.slice(app.indexOf('.invoke_handler('), app.indexOf('.on_window_event('));
  assert.doesNotMatch(invokes, /begin_shutdown|cancel_pending_for_shutdown/);
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
  assert.match(close, /std::mem::take\(&mut pending\.entries\)/);
  assert.match(close, /drop\(senders\)/);
  assert.doesNotMatch(close, /send\(true\)/);
  const resolve = src.slice(src.indexOf('pub async fn resolve('), src.indexOf('#[cfg(test)]\nmod tests'));
  assert.match(resolve, /if self\.shutting_down\.load\(Ordering::SeqCst\)/);
  assert.match(resolve, /return false/);
  assert.match(resolve, /pending\.entries\.remove\(&id\)/);
  const require = src.slice(src.indexOf('pub async fn require('), src.indexOf('fn cancel_pending_for_shutdown('));
  assert.match(require, /Approval system shutting down/);
  assert.match(require, /pending\.entries\.insert\(\s*id,\s*PendingApproval\s*\{[\s\S]*?sender,/);
  assert.match(src, /fn trusted_exit_cancels_thirty_two_pending_asks_and_rejects_late_replies/);
  assert.match(src, /fn poisoned_pending_shutdown_fails_closed_without_recovery_to_approve/);
  assert.match(src, /MAX_PENDING_APPROVALS/);
});


test('dormant workspace worker belongs only to trusted native lifecycle (#322)', async () => {
  const app = await readFile('src-tauri/src/app.rs', 'utf8');
  const invokes = app.slice(app.indexOf('.invoke_handler('), app.indexOf('.on_window_event('));
  assert.doesNotMatch(invokes, /workspace|enroll|activate/i);
  const setup = app.slice(app.indexOf('.setup('), app.indexOf('.build(tauri::generate_context'));
  assert.ok(setup.indexOf('app.manage(instance)') < setup.indexOf('WorkspaceWorker::start('));
  assert.ok(setup.indexOf('AgentState::new_with_local_model(') < setup.indexOf('WorkspaceWorker::start('));
  assert.match(setup, /app\.manage\(WorkspaceHost::new\(worker\)\)/);
  assert.doesNotMatch(setup, /worker\.(enroll|activate)\(/);
  const events = app.slice(app.indexOf('.on_window_event('), app.indexOf('.setup('));
  const destroyed = events.indexOf('if is_trusted_main_destroyed');
  assert.ok(destroyed >= 0);
  assert.doesNotMatch(events.slice(0, destroyed), /stop_workspace/);
  assert.match(events.slice(destroyed), /stop_workspace\(window\.app_handle\(\)\)/);
  const exit = app.slice(app.indexOf('if matches!(&event, tauri::RunEvent::Exit)'));
  assert.match(exit, /stop_workspace\(app\)/);
});
