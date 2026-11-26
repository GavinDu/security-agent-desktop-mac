import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('native chat checks trusted origin and reuses optional bounded provider', async () => {
  const model = await readFile('src-tauri/src/agent/local_model.rs', 'utf8');
  const app = await readFile('src-tauri/src/app.rs', 'utf8');
  const command = model.indexOf('async fn chat_text(');
  const guard = model.indexOf('navigation::ensure_privileged_webview(&window)?', command);
  const dispatch = model.indexOf('complete_native_text(state.local_model.as_ref(), &message)', guard);
  assert.ok(command > 0 && guard > command && dispatch > guard);
  assert.match(model, /provider\s*\.complete\(message\)/);
  assert.match(app, /agent::local_model::chat_text,/);
});

test('local chat sends only explicit prompt and displays literal output', async () => {
  const ui = await readFile('webview/pages/local-chat.ts', 'utf8');
  const page = await readFile('webview/pages/app.ts', 'utf8');
  assert.match(ui, /send\.addEventListener\('click'/);
  assert.match(ui, /if \(active\) return/);
  assert.match(ui, /invoke<Completion>\('chat_text', \{ message \}\)/);
  assert.match(ui, /answer\.textContent = completion\.message/);
  assert.match(ui, /completion\.finish_reason === 'length'/);
  assert.doesNotMatch(ui, /innerHTML|respond_approval|invoke_tool/);
  assert.match(page, /mountLocalChat\(\)/);
});
