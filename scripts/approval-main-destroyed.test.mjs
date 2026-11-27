import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('only real native main window destruction latches approval shutdown (#215)', async () => {
  const app = await readFile('src-tauri/src/app.rs', 'utf8');
  const pred = app.slice(app.indexOf('fn is_trusted_main_destroyed('), app.indexOf('pub fn run()'));
  assert.match(pred, /label == "main" && matches!\(event, WindowEvent::Destroyed\)/);

  const events = app.slice(app.indexOf('.on_window_event('), app.indexOf('.setup('));
  assert.match(events, /if window\.label\(\) == "main" \{/);
  assert.match(events, /WindowEvent::CloseRequested \{ api, \.\. \}/);
  assert.match(events, /api\.prevent_close\(\)/);
  assert.match(events, /window\.hide\(\)/);
  assert.match(events, /if is_trusted_main_destroyed\(window\.label\(\), event\) \{/);
  assert.match(events, /window\.app_handle\(\)\.try_state::<Arc<AgentState>>\(\)/);
  assert.match(events, /state\.gate\.cancel_pending_for_shutdown\(\)/);

  const invokes = app.slice(app.indexOf('.invoke_handler('), app.indexOf('.on_window_event('));
  assert.doesNotMatch(invokes, /cancel_pending_for_shutdown|is_trusted_main_destroyed/);
  assert.match(app, /matches!\(&event, tauri::RunEvent::Exit\)/);
  assert.match(app, /\.emit_to\("main", "security-agent:\/\/tool-approval", event\)/);
});

test('main-only predicate is tested for Destroyed, Focused, and foreign window (#215)', async () => {
  const app = await readFile('src-tauri/src/app.rs', 'utf8');
  assert.match(app, /fn only_real_main_window_destruction_closes_approval_inbox\(\)/);
  assert.match(app, /is_trusted_main_destroyed\("main", &WindowEvent::Destroyed\)/);
  assert.match(app, /is_trusted_main_destroyed\(\s*"second",\s*&WindowEvent::Destroyed\s*\)/);
  assert.match(app, /is_trusted_main_destroyed\(\s*"main",\s*&WindowEvent::Focused\(true\)\s*\)/);
  assert.match(app, /is_trusted_main_destroyed\(\s*"main",\s*&WindowEvent::Focused\(false\)\s*\)/);
  const gate = await readFile('src-tauri/src/tools/approvals.rs', 'utf8');
  assert.match(gate, /fn cancel_pending_for_shutdown\(&self\) -> Result<usize, String>/);
  assert.match(gate, /self\.shutting_down\.store\(true, Ordering::SeqCst\)/);
  assert.match(gate, /std::mem::take\(&mut pending\.entries\)/);
  assert.match(gate, /fn trusted_exit_cancels_thirty_two_pending_asks_and_rejects_late_replies\(\)/);
});
