import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('native macOS reopen only focuses the already trusted main WebView (#72)', async () => {
  const app = await readFile('src-tauri/src/app.rs', 'utf8');
  const tray = await readFile('src-tauri/src/tray.rs', 'utf8');
  assert.match(app, /\.build\(tauri::generate_context!\(\)\)[\s\S]*\.run\(\|app, event\|/);
  assert.match(app, /#\[cfg\(target_os = "macos"\)\][\s\S]*RunEvent::Reopen \{ \.\. \} = event \{[\s\S]*tray::show_main\(app\)/);
  assert.match(tray, /"show" => show_main\(app\)/);
  const helper = tray.slice(tray.indexOf('pub(crate) fn show_main('));
  assert.match(helper, /get_webview_window\("main"\)/);
  assert.match(helper, /window\.show\(\)/);
  assert.match(helper, /window\.set_focus\(\)/);
  assert.doesNotMatch(helper, /WebviewWindowBuilder|\.invoke\(|AgentState|TcpListener|secrets::/);
  assert.equal((app.match(/WebviewWindowBuilder::from_config/g) || []).length, 1);
  const lock = app.indexOf('InstanceGuard::acquire()');
  const token = app.indexOf('secrets::get_or_create_api_token()');
  assert.ok(lock > 0 && token > lock, 'no Keychain or agent setup before instance guard');
});
